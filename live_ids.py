import glob
import json
import os
import shutil
import subprocess
import time
import requests

# ============================================================
# CONFIGURATION
# ============================================================

FASTAPI_URL = "http://127.0.0.1:8000/predict-csv"
INTERFACE_INDEX = "5"  # Network interface index from 'dumpcap -D'

EDITCAP = r"D:\Wireshark\editcap.exe"
DUMPCAP = r"D:\Wireshark\dumpcap.exe"
CFM_DIR = r"C:\Full_ids_with_cic\CICFlowMeter-master"
JNETPCAP_LIB = r"C:\Full_ids_with_cic\CICFlowMeter-master\jnetpcap\win\jnetpcap-1.4.r1425"

INPUT_DIR = os.path.join(CFM_DIR, "input")
OUTPUT_DIR = os.path.join(CFM_DIR, "output")
# Must match IDS_EVIDENCE_DIR / EVIDENCE_DIR used by main.py, so the dashboard
# reads the same folder this script writes to. Override both with the
# IDS_EVIDENCE_DIR env var if you don't want the default under CFM_DIR.
EVIDENCE_DIR = os.environ.get("IDS_EVIDENCE_DIR", os.path.join(CFM_DIR, "evidence"))


def clean_working_directories():
    """Clean leftover files from previous runs to prevent stale batch processing."""
    for folder in [INPUT_DIR, OUTPUT_DIR]:
        if os.path.exists(folder):
            for f in os.listdir(folder):
                file_p = os.path.join(folder, f)
                try:
                    if os.path.isfile(file_p):
                        os.remove(file_p)
                except Exception:
                    pass


def send_csv_to_fastapi(csv_path: str, source_pcap: str):
    """Sends flow CSV to API and preserves source PCAP if threats are detected."""
    try:
        if not os.path.exists(csv_path) or os.path.getsize(csv_path) == 0:
            print("ℹ️ [NO TRAFFIC] Capture window yielded empty CSV file.")
            return

        # Read CSV and check for actual network flow data rows beyond the header
        with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = [line.strip() for line in f if line.strip()]
            if len(lines) <= 1:
                print("ℹ️ [NO TRAFFIC] 0 network flows captured in this 10s window.")
                return

        with open(csv_path, "rb") as f:
            response = requests.post(
                FASTAPI_URL,
                files={"file": (os.path.basename(csv_path), f)},
                data={"source": "live"},
            )

        if response.status_code == 200:
            data = response.json()
            dist = data.get("prediction_distribution", {})
            rows = data.get("rows_processed", 0)
            threats = data.get("alerts_detected", 0)

            print(f"📊 [INFERENCE SUCCESS] Processed {rows} flows | Results: {dist}")

            # Archive PCAP evidence if non-benign traffic or unknown attacks are detected
            has_threat = any(label != "BENIGN" and count > 0 for label, count in dist.items())
            if has_threat and os.path.exists(source_pcap):
                timestamp = int(time.time())
                archived_filename = f"threat_{timestamp}_{os.path.basename(source_pcap)}"
                dest_path = os.path.join(EVIDENCE_DIR, archived_filename)
                shutil.copy(source_pcap, dest_path)

                # Sidecar JSON: lets the dashboard show attack type, confidence,
                # and IPs for this card without re-parsing the PCAP.
                sidecar = {
                    "timestamp": timestamp,
                    "source_pcap": os.path.basename(source_pcap),
                    "prediction_distribution": dist,
                    "alerts": data.get("alerts", []),
                }
                try:
                    with open(dest_path + ".json", "w", encoding="utf-8") as sf:
                        json.dump(sidecar, sf)
                except Exception as e:
                    print(f"⚠️ Could not write evidence sidecar: {e}")

                print(f"🚨 [FORENSICS ARCHIVED] Evidence PCAP saved: {dest_path} (Detected {threats} threats)")

        else:
            print(f"❌ [API ERROR {response.status_code}] {response.text}")

    except requests.exceptions.ConnectionError:
        print(f"🚨 Connection Error: FastAPI server unreachable at {FASTAPI_URL}")
    except Exception as e:
        print(f"❌ Error uploading CSV or archiving evidence: {e}")


def process_pcap_batch(pcap_path: str):
    """Converts PCAP, runs CICFlowMeter Java extraction, and posts CSV to API."""
    pcap_name = os.path.basename(pcap_path)
    print(f"\n⚙️ [PROCESSING CHUNK] Analyzing {pcap_name}...")

    staged_pcap = os.path.join(INPUT_DIR, f"stage_{pcap_name}")

    # Step 1: Normalize PCAP encapsulation using editcap
    editcap_cmd = [EDITCAP, "-F", "pcap", "-T", "ether", pcap_path, staged_pcap]
    try:
        subprocess.run(editcap_cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as err:
        print(f"❌ Editcap failed processing {pcap_path}: {err.stderr.decode('utf-8', errors='ignore')}")
        return

    pre_csvs = set(glob.glob(os.path.join(OUTPUT_DIR, "*.csv")))

    # Step 2: Extract flow features via Java CLI
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
        subprocess.run(java_cmd, cwd=CFM_DIR, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as err:
        print(f"❌ CICFlowMeter Java engine failed: {err.stderr.decode('utf-8', errors='ignore')}")
        return

    # Step 3: Forward generated CSV to API
    post_csvs = set(glob.glob(os.path.join(OUTPUT_DIR, "*.csv")))
    new_csvs = post_csvs - pre_csvs

    if not new_csvs:
        print("ℹ️ [NO TRAFFIC] No flow CSV generated for this window.")

    for csv_file in new_csvs:
        send_csv_to_fastapi(csv_file, pcap_path)
        #try:
            #os.remove(csv_file)
        #except OSError:
           # pass

    # Clean up temporary PCAP files
    for path in [pcap_path, staged_pcap]:
        if os.path.exists(path):
            try:
                os.remove(path)
            except OSError:
                pass


def start_live_ids():
    """Launches dumpcap background capture loop and processes continuous chunks."""
    os.makedirs(INPUT_DIR, exist_ok=True)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(EVIDENCE_DIR, exist_ok=True)

    clean_working_directories()

    capture_pattern = os.path.join(INPUT_DIR, "live_chunk.pcap")
    dumpcap_cmd = [
        DUMPCAP,
        "-i", INTERFACE_INDEX,
        "-b", "duration:10",
        "-w", capture_pattern,
    ]

    print(f"[*] Starting background packet capture on interface index {INTERFACE_INDEX}...")
    capture_process = subprocess.Popen(dumpcap_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("[*] Live Continuous IDS Active. Waiting for 10-second capture windows...\n")

    processed = set()
    try:
        while True:
            pcaps = sorted(glob.glob(os.path.join(INPUT_DIR, "live_chunk_*.pcap")))
            # Exclude active chunk currently being written to by dumpcap
            if len(pcaps) > 1:
                for pcap in pcaps[:-1]:
                    if pcap not in processed:
                        process_pcap_batch(pcap)
                        processed.add(pcap)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[*] Shutting down Live IDS Pipeline...")
        capture_process.terminate()


if __name__ == "__main__":
    start_live_ids()