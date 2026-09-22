import os
import sys
import glob
import subprocess
import joblib
import pandas as pd
import numpy as np

# Fixed Environment Paths
EDITCAP = r"D:\Wireshark\editcap.exe"
CFM_DIR = r"C:\CICFlowMeter-master\CICFlowMeter-master"
JNETPCAP_LIB = r"C:\CICFlowMeter-master\CICFlowMeter-master\jnetpcap\win\jnetpcap-1.4.r1425"
INPUT_DIR = os.path.join(CFM_DIR, "input")
OUTPUT_DIR = os.path.join(CFM_DIR, "output")
MODEL_DIR = os.path.join(CFM_DIR, "model")

# Open-Set Guardrail Settings
CONFIDENCE_THRESHOLD = 0.75  # Min probability required to accept XGBoost class label


def load_ml_artifacts():
    """Loads model artifacts and optional OOD/Anomaly model from MODEL_DIR."""
    model_path = os.path.join(MODEL_DIR, "cicids2017_xgboost_multiclass.joblib")
    encoder_path = os.path.join(MODEL_DIR, "cicids2017_label_encoder.joblib")
    features_path = os.path.join(MODEL_DIR, "cicids2017_feature_columns.joblib")
    medians_path = os.path.join(MODEL_DIR, "cicids2017_training_medians.joblib")
    iso_path = os.path.join(MODEL_DIR, "isolation_forest.joblib")

    required_files = [model_path, encoder_path, features_path, medians_path]
    if not all(os.path.exists(p) for p in required_files):
        print(f"[!] Warning: One or more required model artifacts are missing in {MODEL_DIR}")
        return None

    try:
        model = joblib.load(model_path)
        encoder = joblib.load(encoder_path)
        feature_cols = joblib.load(features_path)
        medians = joblib.load(medians_path)

        iso_model = None
        if os.path.exists(iso_path):
            try:
                iso_model = joblib.load(iso_path)
                print("[*] Isolation Forest (OOD Anomaly Detector) loaded successfully.")
            except Exception as e:
                print(f"[!] Warning: Could not load Isolation Forest: {e}")

        print("[*] Core Machine Learning model artifacts loaded successfully.")
        return model, encoder, feature_cols, medians, iso_model
    except Exception as e:
        print(f"[!] Error loading ML models: {e}")
        return None


def classify_flows(csv_path, ml_artifacts):
    """Processes extracted CSV features and attaches predicted attack labels with UNKNOWN guardrails."""
    model, encoder, feature_cols, medians, iso_model = ml_artifacts

    try:
        df = pd.read_csv(csv_path)
        if df.empty:
            print(f"[!] Extracted CSV is empty: {csv_path}")
            return

        df.columns = df.columns.str.strip()  # Strip leading/trailing spaces

        # Align features to training schema and impute missing/inf values
        X = df.reindex(columns=feature_cols)
        X = X.replace([np.inf, -np.inf], np.nan)
        X = X.fillna(medians)

        # Run XGBoost inference
        preds = model.predict(X)
        probs = model.predict_proba(X)

        raw_labels = encoder.inverse_transform(preds)
        confidence_scores = np.max(probs, axis=1)

        # Optional Isolation Forest evaluation (-1 = Anomaly, 1 = Normal)
        iso_scores = iso_model.predict(X) if iso_model is not None else None

        # Apply Open-Set Guardrail Logic
        final_labels = []
        for i in range(len(df)):
            raw_label = raw_labels[i]
            conf = confidence_scores[i]
            is_anomaly = (iso_scores[i] == -1) if iso_scores is not None else False

            # Guardrail 1: Low prediction confidence -> UNKNOWN_ATTACK
            if conf < CONFIDENCE_THRESHOLD:
                final_labels.append("UNKNOWN_ATTACK")
            # Guardrail 2: Classified as BENIGN but flagged as anomaly by Isolation Forest
            elif is_anomaly and raw_label == "BENIGN":
                final_labels.append("UNKNOWN_ATTACK")
            else:
                final_labels.append(raw_label)

        # Save metadata columns alongside final security decision
        df["Raw_Prediction"] = raw_labels
        df["Confidence_Score"] = confidence_scores
        df["Predicted_Label"] = final_labels

        # Save classified CSV output
        labeled_csv = csv_path.replace(".csv", "_labeled.csv")
        df.to_csv(labeled_csv, index=False)

        print(f"[SUCCESS] Labeled results saved to: {labeled_csv}")
        print("\n--- ATTACK DETECTION SUMMARY ---")
        print(df["Predicted_Label"].value_counts().to_string())
        print("--------------------------------\n")

    except Exception as e:
        print(f"[ERROR] Classification failed for {csv_path}: {e}")


def process_target(target_path):
    if not os.path.exists(target_path):
        print(f"[!] Path does not exist: {target_path}")
        return

    # Load ML Model Artifacts
    ml_artifacts = load_ml_artifacts()

    # Collect target files (supports single file OR entire directory)
    files = []
    if os.path.isfile(target_path):
        files.append(target_path)
    elif os.path.isdir(target_path):
        for ext in ("*.pcap", "*.anonymized*", "*.cap"):
            files.extend(glob.glob(os.path.join(target_path, ext)))

    if not files:
        print("[!] No supported capture files found.")
        return

    print(f"[*] Found {len(files)} file(s) to extract.")

    for file in files:
        base_name = os.path.basename(file)
        print(f"\n---> Processing: {base_name}")

        # Step 1: Wipe input directory clean
        for f in glob.glob(os.path.join(INPUT_DIR, "*")):
            try:
                os.remove(f)
            except Exception:
                pass

        # Step 2: Convert link-layer framing & output standard pcap
        staged_pcap = os.path.join(INPUT_DIR, f"{base_name}_ether.pcap")
        editcap_cmd = [EDITCAP, "-F", "pcap", "-T", "ether", file, staged_pcap]

        try:
            subprocess.run(
                editcap_cmd,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except subprocess.CalledProcessError:
            print(f"[ERROR] editcap failed to convert {base_name}")
            continue

        # Track existing CSVs in output folder to detect new output file
        pre_existing_csvs = set(glob.glob(os.path.join(OUTPUT_DIR, "*.csv")))

        # Step 3: Run Java engine for feature extraction
        java_cmd = [
            "java",
            f"-Djava.library.path={JNETPCAP_LIB}",
            "-cp",
            r"build\install\CICFlowMeter\lib\*",
            "cic.cs.unb.ca.ifm.Cmd",
            INPUT_DIR,
            OUTPUT_DIR,
        ]

        try:
            subprocess.run(java_cmd, cwd=CFM_DIR, check=True)
            print(f"[SUCCESS] Features extracted to {OUTPUT_DIR}")
        except subprocess.CalledProcessError:
            print(f"[ERROR] Extraction failed for {base_name}")
            continue

        # Step 4: Machine Learning Classification on Generated CSV
        if ml_artifacts:
            post_csvs = set(glob.glob(os.path.join(OUTPUT_DIR, "*.csv")))
            new_csvs = post_csvs - pre_existing_csvs

            # Process all newly generated flow CSV files
            for new_csv in new_csvs:
                if not new_csv.endswith("_labeled.csv"):
                    print(f"[*] Classifying extracted flows in {os.path.basename(new_csv)}...")
                    classify_flows(new_csv, ml_artifacts)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1].strip('"')
    else:
        target = input("Enter PCAP file path or directory: ").strip('"')

    process_target(target)