import glob
import os
import joblib
import pandas as pd
import numpy as np

MODEL_DIR = "models"  # adjust to your actual models folder path
OUTPUT_DIR = r"C:\Full_ids_with_cic\CICFlowMeter-master\output"
THRESHOLD = 0.75

model = joblib.load(f"{MODEL_DIR}/cicids2017_xgboost_multiclass.joblib")
label_encoder = joblib.load(f"{MODEL_DIR}/cicids2017_label_encoder.joblib")
raw_feature_columns = joblib.load(f"{MODEL_DIR}/cicids2017_feature_columns.joblib")
feature_columns = [str(c).replace("\ufeff", "").strip() for c in raw_feature_columns]
training_medians = joblib.load(f"{MODEL_DIR}/cicids2017_training_medians.joblib")

COLUMN_MAPPING = {
    "Dst Port": "Destination Port", "DstPort": "Destination Port",
    "Total Fwd Packet": "Total Fwd Packets", "Total Bwd packets": "Total Backward Packets",
    "Tot Fwd Pkts": "Total Fwd Packets", "Tot Bwd Pkts": "Total Backward Packets",
    "Total Length of Fwd Packet": "Total Length of Fwd Packets",
    "Total Length of Bwd Packet": "Total Length of Bwd Packets",
    "TotLen Fwd Pkts": "Total Length of Fwd Packets", "TotLen Bwd Pkts": "Total Length of Bwd Packets",
    "Packet Length Min": "Min Packet Length", "Packet Length Max": "Max Packet Length",
    "Pkt Len Min": "Min Packet Length", "Pkt Len Max": "Max Packet Length",
    "CWR Flag Count": "CWE Flag Count", "CWE Flag Cnt": "CWE Flag Count",
    "Fwd Segment Size Avg": "Avg Fwd Segment Size", "Bwd Segment Size Avg": "Avg Bwd Segment Size",
    "Fwd Seg Size Avg": "Avg Fwd Segment Size", "Bwd Seg Size Avg": "Avg Bwd Segment Size",
    "Fwd Bytes/Bulk Avg": "Fwd Avg Bytes/Bulk", "Fwd Packet/Bulk Avg": "Fwd Avg Packets/Bulk",
    "Fwd Bulk Rate Avg": "Fwd Avg Bulk Rate", "Bwd Bytes/Bulk Avg": "Bwd Avg Bytes/Bulk",
    "Bwd Packet/Bulk Avg": "Bwd Avg Packets/Bulk", "Bwd Bulk Rate Avg": "Bwd Avg Bulk Rate",
    "Fwd Byts/b Avg": "Fwd Avg Bytes/Bulk", "Fwd Pkts/b Avg": "Fwd Avg Packets/Bulk",
    "Fwd Blk Rate Avg": "Fwd Avg Bulk Rate", "Bwd Byts/b Avg": "Bwd Avg Bytes/Bulk",
    "Bwd Pkts/b Avg": "Bwd Avg Packets/Bulk", "Bwd Blk Rate Avg": "Bwd Avg Bulk Rate",
    "FWD Init Win Bytes": "Init_Win_bytes_forward", "Bwd Init Win Bytes": "Init_Win_bytes_backward",
    "Init Fwd Win Byts": "Init_Win_bytes_forward", "Init Bwd Win Byts": "Init_Win_bytes_backward",
    "Fwd Act Data Pkts": "act_data_pkt_fwd", "Fwd Seg Size Min": "min_seg_size_forward",
}

csv_files = sorted(glob.glob(os.path.join(OUTPUT_DIR, "live_chunk_*.pcap_Flow.csv")),
                    key=os.path.getmtime, reverse=True)[:60]  # most recent 60 files
print(f"Scanning {len(csv_files)} recent CSV files for rows below {THRESHOLD} confidence...\n")

found_any = False

for CSV_PATH in csv_files:
    try:
        df = pd.read_csv(CSV_PATH)
    except Exception:
        continue
    if df.empty:
        continue

    df.columns = [str(c).replace("\ufeff", "").strip() for c in df.columns]
    df.rename(columns=COLUMN_MAPPING, inplace=True)

    if any(c not in df.columns for c in feature_columns):
        continue  # skip malformed/incompatible CSVs silently

    meta_cols = [c for c in ["Src IP", "Dst IP", "Destination Port", "Protocol"] if c in df.columns]

    X = df[feature_columns].copy()
    for col in X.columns:
        X[col] = pd.to_numeric(X[col], errors="coerce")
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    if isinstance(training_medians, dict):
        for col in feature_columns:
            if col in training_medians:
                X[col] = X[col].fillna(training_medians[col])
    X.fillna(0, inplace=True)

    probs = model.predict_proba(X)
    classes = label_encoder.classes_
    top_conf = probs.max(axis=1)

    low_conf_idx = np.where(top_conf < THRESHOLD)[0]
    for i in low_conf_idx:
        found_any = True
        top3_idx = np.argsort(probs[i])[::-1][:3]
        meta = " | ".join(f"{c}={df.iloc[i][c]}" for c in meta_cols)
        print(f"FILE: {os.path.basename(CSV_PATH)}  ROW: {i}")
        print(f"  {meta}")
        for idx in top3_idx:
            print(f"  {classes[idx]}: {probs[i][idx]:.4f}")
        print()

if not found_any:
    print("No rows below threshold found in the scanned files.")