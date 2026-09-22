import glob
import json
import os
import sys
import tempfile
import time
import subprocess
from collections import deque
from typing import Dict, Any, Optional

import joblib
import numpy as np
import pandas as pd
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Depends, Response, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse

from utils import auth

# ============================================================
# PATHS & GLOBALS
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE_DIR, "models")

MODEL_PATH = os.path.join(MODEL_DIR, "cicids2017_xgboost_multiclass.joblib")
LABEL_ENCODER_PATH = os.path.join(MODEL_DIR, "cicids2017_label_encoder.joblib")
FEATURE_COLUMNS_PATH = os.path.join(MODEL_DIR, "cicids2017_feature_columns.joblib")
MEDIANS_PATH = os.path.join(MODEL_DIR, "cicids2017_training_medians.joblib")

# Where live_ids.py archives threat PCAPs + JSON sidecars. Override with the
# IDS_EVIDENCE_DIR env var if your CICFlowMeter working directory lives
# elsewhere (see live_ids.py, which must point at the same folder).
EVIDENCE_DIR = os.environ.get(
    "IDS_EVIDENCE_DIR", os.path.join(BASE_DIR, "evidence")
)
os.makedirs(EVIDENCE_DIR, exist_ok=True)

live_ids_process: Optional[subprocess.Popen] = None

# ============================================================
# IN-MEMORY DASHBOARD STATE
# ============================================================
# /predict-csv is called from two different sources: live_ids.py's 10s
# capture loop, and manual uploads from the dashboard's UploadPanel. Each
# gets its OWN state bucket so live traffic stats and manual CSV stats never
# blend together. Reset on API restart -- this is a live-session view, not
# a persisted analytics store.

def _new_bucket():
    return {
        "total_flows": 0,
        "total_flagged": 0,
        "distribution_totals": {},   # label -> cumulative count
        "history": deque(maxlen=40), # [{ts, flows, flagged}] one entry per batch
        "recent_alerts": deque(maxlen=50),  # most recent individual alerts, newest first
    }

STATE = {
    "live": _new_bucket(),
    "csv": _new_bucket(),
}


def _record_batch(source: str, distribution: Dict[str, int], alerts: list[dict], rows: int):
    bucket = STATE.get(source, STATE["csv"])  # unknown source -> treat as manual CSV
    flagged = sum(c for lbl, c in distribution.items() if lbl != "BENIGN")
    bucket["total_flows"] += rows
    bucket["total_flagged"] += flagged
    for lbl, c in distribution.items():
        bucket["distribution_totals"][lbl] = bucket["distribution_totals"].get(lbl, 0) + c
    bucket["history"].append({"ts": time.time(), "flows": rows, "flagged": flagged})
    for a in reversed(alerts[:10]):  # cap how many individual alerts we retain per batch
        bucket["recent_alerts"].appendleft({**a, "ts": time.time()})

# ============================================================
# COLUMNS EXCLUDED FROM TRAINING
# ============================================================

EXCLUDED_COLUMNS = [
    "Flow ID",
    "Src IP",
    "Src Port",
    "Dst IP",
    "Source IP",
    "Destination IP",
    "Protocol",
    "Timestamp",
    "Fwd Header Length.1",
]

COLUMN_MAPPING = {
    "Dst Port": "Destination Port",
    "DstPort": "Destination Port",
    "Total Fwd Packet": "Total Fwd Packets",
    "Total Bwd packets": "Total Backward Packets",
    "Tot Fwd Pkts": "Total Fwd Packets",
    "Tot Bwd Pkts": "Total Backward Packets",
    "Total Length of Fwd Packet": "Total Length of Fwd Packets",
    "Total Length of Bwd Packet": "Total Length of Bwd Packets",
    "TotLen Fwd Pkts": "Total Length of Fwd Packets",
    "TotLen Bwd Pkts": "Total Length of Bwd Packets",
    "Packet Length Min": "Min Packet Length",
    "Packet Length Max": "Max Packet Length",
    "Pkt Len Min": "Min Packet Length",
    "Pkt Len Max": "Max Packet Length",
    "CWR Flag Count": "CWE Flag Count",
    "CWE Flag Cnt": "CWE Flag Count",
    "Fwd Segment Size Avg": "Avg Fwd Segment Size",
    "Bwd Segment Size Avg": "Avg Bwd Segment Size",
    "Fwd Seg Size Avg": "Avg Fwd Segment Size",
    "Bwd Seg Size Avg": "Avg Bwd Segment Size",
    "Fwd Bytes/Bulk Avg": "Fwd Avg Bytes/Bulk",
    "Fwd Packet/Bulk Avg": "Fwd Avg Packets/Bulk",
    "Fwd Bulk Rate Avg": "Fwd Avg Bulk Rate",
    "Bwd Bytes/Bulk Avg": "Bwd Avg Bytes/Bulk",
    "Bwd Packet/Bulk Avg": "Bwd Avg Packets/Bulk",
    "Bwd Bulk Rate Avg": "Bwd Avg Bulk Rate",
    "Fwd Byts/b Avg": "Fwd Avg Bytes/Bulk",
    "Fwd Pkts/b Avg": "Fwd Avg Packets/Bulk",
    "Fwd Blk Rate Avg": "Fwd Avg Bulk Rate",
    "Bwd Byts/b Avg": "Bwd Avg Bytes/Bulk",
    "Bwd Pkts/b Avg": "Bwd Avg Packets/Bulk",
    "Bwd Blk Rate Avg": "Bwd Avg Bulk Rate",
    "FWD Init Win Bytes": "Init_Win_bytes_forward",
    "Bwd Init Win Bytes": "Init_Win_bytes_backward",
    "Init Fwd Win Byts": "Init_Win_bytes_forward",
    "Init Bwd Win Byts": "Init_Win_bytes_backward",
    "Fwd Act Data Pkts": "act_data_pkt_fwd",
    "Fwd Seg Size Min": "min_seg_size_forward",
}

# ============================================================
# LOAD MODEL & ARTIFACTS
# ============================================================

try:
    model = joblib.load(MODEL_PATH)
    label_encoder = joblib.load(LABEL_ENCODER_PATH)
    raw_feature_columns = joblib.load(FEATURE_COLUMNS_PATH)
    feature_columns = [
        str(col).replace("\ufeff", "").strip() for col in raw_feature_columns
    ]
    training_medians = joblib.load(MEDIANS_PATH)
except Exception as e:
    raise RuntimeError(f"Failed to load model artifacts from {MODEL_DIR}: {e}") from e

# ============================================================
# FASTAPI APP
# ============================================================

app = FastAPI(
    title="CICIDS2017 AI Network Forensics & IDS API",
    description="XGBoost-based live traffic monitoring and forensic CSV evaluation.",
    version="1.1.0",
)

# Dashboard runs on a different origin.
# The allowed origin(s) are supplied through IDS_DASHBOARD_ORIGINS.
# Example:
# IDS_DASHBOARD_ORIGINS=https://ids.example.com
# Multiple origins can be comma-separated.

_raw_origins = os.environ.get("IDS_DASHBOARD_ORIGINS", "")

allowed_origins = [
    origin.strip()
    for origin in _raw_origins.split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
# HELPERS
# ============================================================

def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    df_clean = df.copy()
    df_clean.columns = [str(col).replace("\ufeff", "").strip() for col in df_clean.columns]
    df_clean.rename(columns=COLUMN_MAPPING, inplace=True)
    return df_clean


def prepare_features(df: pd.DataFrame) -> tuple[pd.DataFrame, Optional[pd.Series]]:
    df_norm = normalize_columns(df)
    
    y_true = None
    if "Label" in df_norm.columns:
        y_true = (
            df_norm["Label"]
            .astype(str)
            .str.replace("\ufeff", "", regex=False)
            .str.strip()
            .str.upper()
        )

    X = df_norm.drop(
        columns=[c for c in EXCLUDED_COLUMNS if c in df_norm.columns] + ["Label"],
        errors="ignore",
    ).copy()

    missing_features = [col for col in feature_columns if col not in X.columns]
    if missing_features:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Missing required model features",
                "missing_count": len(missing_features),
                "missing_features": missing_features,
            },
        )

    X = X[feature_columns].copy()

    for col in X.columns:
        X[col] = pd.to_numeric(X[col], errors="coerce")

    X.replace([np.inf, -np.inf], np.nan, inplace=True)

    if isinstance(training_medians, dict):
        for col in feature_columns:
            if col in training_medians:
                X[col] = X[col].fillna(training_medians[col])

    X.fillna(0, inplace=True)
    return X, y_true


def evaluate_predictions(y_true: pd.Series, predicted_labels: list[str]) -> Dict[str, Any]:
    from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, confusion_matrix, classification_report

    valid_labels = set(label_encoder.classes_)
    valid_mask = y_true.isin(valid_labels)

    if valid_mask.sum() == 0:
        return {"rows_with_valid_labels": 0, "message": "No matching evaluation labels found."}

    true_valid = y_true[valid_mask]
    pred_series = pd.Series(predicted_labels, index=y_true.index)
    pred_valid = pred_series[valid_mask]
    labels = label_encoder.classes_

    return {
        "rows_with_valid_labels": int(valid_mask.sum()),
        "accuracy": float(accuracy_score(true_valid, pred_valid)),
        "macro_precision": float(precision_score(true_valid, pred_valid, labels=labels, average="macro", zero_division=0)),
        "macro_recall": float(recall_score(true_valid, pred_valid, labels=labels, average="macro", zero_division=0)),
        "macro_f1": float(f1_score(true_valid, pred_valid, labels=labels, average="macro", zero_division=0)),
        "confusion_matrix": confusion_matrix(true_valid, pred_valid, labels=labels).tolist(),
        "classification_report": classification_report(true_valid, pred_valid, labels=labels, output_dict=True, zero_division=0),
    }

# ============================================================
# API ENDPOINTS
# ============================================================

@app.get("/")
def root():
    return {
        "status": "running",
        "service": "XGBoost Real-Time IDS API",
        "features": len(feature_columns),
        "classes": label_encoder.classes_.tolist(),
    }


# ============================================================
# AUTH ENDPOINTS
# ============================================================

@app.post("/auth/login")
def login(request: Request, response: Response, password: str = Form(...)):
    client_ip = request.client.host if request.client else "unknown"
    auth._check_lockout(client_ip)
    if not auth.verify_password(password):
        auth._record_failure(client_ip)
        raise HTTPException(status_code=401, detail="Incorrect password.")
    auth.issue_session_cookie(response)
    return {"status": "success"}


@app.post("/auth/logout")
def logout(response: Response):
    auth.clear_session_cookie(response)
    return {"status": "success"}


@app.get("/auth/status")
def auth_status(request: Request):
    return {"authenticated": auth._valid_session_cookie(request)}


@app.get("/auth/needs-setup")
def auth_needs_setup():
    return {"needs_setup": auth.needs_setup()}


@app.post("/auth/setup")
def auth_setup(response: Response, password: str = Form(...)):
    auth.set_password(password)
    # Log the person straight in after setup so they don't have to submit
    # the password twice in a row.
    auth.issue_session_cookie(response)
    return {"status": "success"}


@app.post("/predict-csv", dependencies=[Depends(auth.require_user_or_internal)])
async def predict_csv(file: UploadFile = File(...), source: str = Form("csv")):
    # "live" = live_ids.py's periodic capture batches, "csv" = manual dashboard
    # upload. Anything else is treated as "csv" (see _record_batch).
    if source not in ("live", "csv"):
        source = "csv"
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="A valid CSV file must be provided.")

    start_time = time.time()
    contents = await file.read()
    if not contents:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as temp_file:
            temp_file.write(contents)
            temp_path = temp_file.name

        df = pd.read_csv(temp_path)
        if df.empty:
            raise HTTPException(status_code=400, detail="CSV contains no data rows.")

        X, y_true = prepare_features(df)

        # Inference
        if hasattr(model, "predict_proba"):
            probs = model.predict_proba(X)
            preds_encoded = np.argmax(probs, axis=1)
            confidences = np.max(probs, axis=1)
        else:
            preds_encoded = model.predict(X)
            confidences = np.ones(len(preds_encoded))

        raw_labels = label_encoder.inverse_transform(preds_encoded.astype(int))

        # Open-set classification: Low confidence (<0.75) flagged as UNKNOWN_ATTACK
        final_labels = [
            label if (label == "BENIGN" or conf >= 0.75) else "UNKNOWN_ATTACK"
            for label, conf in zip(raw_labels, confidences)
        ]

        # Aggregate prediction distribution
        distribution: Dict[str, int] = {}
        for lbl in final_labels:
            distribution[lbl] = distribution.get(lbl, 0) + 1

        # Extract detailed alert structures for threats
        alerts = []
        df_norm = normalize_columns(df)
        for idx, (lbl, conf) in enumerate(zip(final_labels, confidences)):
            if lbl != "BENIGN":
                alert_item = {
                    "row_index": idx,
                    "prediction": lbl,
                    "confidence": round(float(conf), 4),
                }
                for meta_col in ["Src IP", "Dst IP", "Src Port", "Destination Port", "Protocol", "Timestamp"]:
                    if meta_col in df_norm.columns:
                        alert_item[meta_col.lower().replace(" ", "_")] = str(df_norm.iloc[idx][meta_col])
                alerts.append(alert_item)
                if len(alerts) >= 100:  # Cap alert response list payload size
                    break

        response_data = {
            "filename": file.filename,
            "rows_processed": int(len(X)),
            "prediction_distribution": distribution,
            "alerts_detected": int(
                sum(
                    count
                    for label, count in distribution.items()
                     if label != "BENIGN"
                 )
            ),
            "alerts": alerts,
            "processing_time_sec": round(time.time() - start_time, 3),
        }

        if y_true is not None:
            response_data["evaluation"] = evaluate_predictions(y_true, final_labels)

        response_data["source"] = source
        _record_batch(source, distribution, alerts, rows=int(len(X)))

        return JSONResponse(content=response_data)

    finally:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)


@app.post("/live/start", dependencies=[Depends(auth.require_user)])
def start_live_ids():
    global live_ids_process
    if live_ids_process is None or live_ids_process.poll() is not None:
        script_path = os.path.join(BASE_DIR, "utils", "live_ids.py")
        live_ids_process = subprocess.Popen([sys.executable, script_path])
        return {"status": "success", "message": "Live continuous capture worker started."}
    return {"status": "warning", "message": "Live IDS worker is already running."}


@app.post("/live/stop", dependencies=[Depends(auth.require_user)])
def stop_live_ids():
    global live_ids_process
    if live_ids_process and live_ids_process.poll() is None:
        live_ids_process.terminate()
        live_ids_process = None
        return {"status": "success", "message": "Live capture worker stopped."}
    return {"status": "warning", "message": "Live IDS worker is not active."}


@app.get("/live/status", dependencies=[Depends(auth.require_user)])
def get_live_status():
    is_running = live_ids_process is not None and live_ids_process.poll() is None
    return {"active": is_running}


# ============================================================
# DASHBOARD ENDPOINTS
# ============================================================

def _bucket_view(bucket: dict, classes: list) -> dict:
    return {
        "total_flows": bucket["total_flows"],
        "total_flagged": bucket["total_flagged"],
        "distribution_totals": {c: bucket["distribution_totals"].get(c, 0) for c in classes},
        "history": list(bucket["history"]),
        "recent_alerts": list(bucket["recent_alerts"]),
    }


@app.get("/stats", dependencies=[Depends(auth.require_user)])
def get_stats():
    """Session stats for live capture and manual CSV analysis, kept separate."""
    classes = label_encoder.classes_.tolist()
    return {
        "classes": classes,
        "live": _bucket_view(STATE["live"], classes),
        "csv": _bucket_view(STATE["csv"], classes),
        "live_active": live_ids_process is not None and live_ids_process.poll() is None,
    }


def _evidence_entries():
    """Scan EVIDENCE_DIR for archived PCAPs + their JSON sidecars (if any)."""
    entries = []
    for pcap_path in sorted(
        glob.glob(os.path.join(EVIDENCE_DIR, "*.pcap")), reverse=True
    ):
        filename = os.path.basename(pcap_path)
        sidecar_path = pcap_path + ".json"
        meta: Dict[str, Any] = {}
        if os.path.exists(sidecar_path):
            try:
                with open(sidecar_path, "r", encoding="utf-8") as f:
                    meta = json.load(f)
            except Exception:
                meta = {}

        stat = os.stat(pcap_path)
        top_alert = (meta.get("alerts") or [{}])[0]
        entries.append({
            "filename": filename,
            "size_bytes": stat.st_size,
            "modified": stat.st_mtime,
            "attack_type": top_alert.get("prediction", "UNKNOWN_ATTACK"),
            "confidence": top_alert.get("confidence"),
            "src_ip": top_alert.get("src_ip"),
            "dst_ip": top_alert.get("dst_ip"),
            "prediction_distribution": meta.get("prediction_distribution", {}),
        })
    return entries


@app.get("/evidence", dependencies=[Depends(auth.require_user)])
def list_evidence():
    return {"evidence_dir": EVIDENCE_DIR, "entries": _evidence_entries()}


@app.get("/evidence/download/{filename}", dependencies=[Depends(auth.require_user)])
def download_evidence(filename: str):
    safe_name = os.path.basename(filename)  # prevent path traversal
    path = os.path.join(EVIDENCE_DIR, safe_name)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Evidence file not found.")
    return FileResponse(path, filename=safe_name, media_type="application/vnd.tcpdump.pcap")


@app.get("/evidence/features/{filename}", dependencies=[Depends(auth.require_user)])
def evidence_features(filename: str):
    safe_name = os.path.basename(filename)
    sidecar_path = os.path.join(EVIDENCE_DIR, safe_name + ".json")
    if not os.path.exists(sidecar_path):
        raise HTTPException(status_code=404, detail="No feature metadata found for this file.")
    with open(sidecar_path, "r", encoding="utf-8") as f:
        return json.load(f)