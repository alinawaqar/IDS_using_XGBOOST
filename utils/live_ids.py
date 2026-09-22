import glob
import json
import os
import shutil
import subprocess
import sys
import time
import requests

# ============================================================
# CONFIGURATION
# ============================================================

FASTAPI_URL = os.environ.get(
    "FASTAPI_URL",
    "http://127.0.0.1:8000/predict-csv"
)

IS_WINDOWS = sys.platform.startswith("win")

# Default to "any" inside Docker/Linux
INTERFACE_INDEX = os.environ.get("INTERFACE_INDEX", "any")

INTERNAL_KEY = os.environ.get(
    "IDS_INTERNAL_KEY",
    "dev_secret_key"
)

if IS_WINDOWS:
    EDITCAP = os.environ.get(
        "EDITCAP_PATH",
        r"D:\Wireshark\editcap.exe"
    )
    DUMPCAP = os.environ.get(
        "DUMPCAP_PATH",
        r"D:\Wireshark\dumpcap.exe"
    )
else:
    EDITCAP = shutil.which("editcap") or "/usr/bin/editcap"
    DUMPCAP = shutil.which("dumpcap") or "/usr/bin/dumpcap"

# live_ids.py is inside utils/
# Therefore, going up two levels reaches the project root.
BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

CFM_DIR = os.path.join(
    BASE_DIR,
    "CICFlowMeter-master"
)

if IS_WINDOWS:
    JNETPCAP_LIB = os.path.join(
        CFM_DIR,
        "jnetpcap",
        "win",
        "jnetpcap-1.4.r1425"
    )

    CLASSPATH_LIB = r"build\install\CICFlowMeter\lib\*"

else:
    JNETPCAP_LIB = os.path.join(
        CFM_DIR,
        "jnetpcap",
        "linux",
        "jnetpcap-1.4.r1425"
    )

    CLASSPATH_LIB = os.path.join(
        CFM_DIR,
        "build",
        "install",
        "CICFlowMeter",
        "lib",
        "*"
    )

INPUT_DIR = os.path.join(
    CFM_DIR,
    "input"
)

OUTPUT_DIR = os.path.join(
    CFM_DIR,
    "output"
)

EVIDENCE_DIR = os.environ.get(
    "IDS_EVIDENCE_DIR",
    os.path.join(CFM_DIR, "evidence")
)


def clean_working_directories():
    """Clean leftover files from previous runs to prevent stale batch processing."""

    for folder in [INPUT_DIR, OUTPUT_DIR]:

        if os.path.exists(folder):

            for f in os.listdir(folder):

                file_p = os.path.join(
                    folder,
                    f
                )

                try:
                    if os.path.isfile(file_p):
                        os.remove(file_p)

                except Exception:
                    pass


def send_csv_to_fastapi(csv_path: str, source_pcap: str):
    """Sends flow CSV to API and preserves source PCAP if threats are detected."""

    try:

        if (
            not os.path.exists(csv_path)
            or os.path.getsize(csv_path) == 0
        ):
            print(
                "ℹ️ [NO TRAFFIC] Capture window yielded empty CSV file."
            )
            return

        with open(
            csv_path,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as f:

            lines = [
                line.strip()
                for line in f
                if line.strip()
            ]

            if len(lines) <= 1:
                print(
                    "ℹ️ [NO TRAFFIC] 0 network flows captured in this window."
                )
                return

        with open(csv_path, "rb") as f:

            response = requests.post(
                FASTAPI_URL,
                files={
                    "file": (
                        os.path.basename(csv_path),
                        f
                    )
                },
                data={
                    "source": "live"
                },
                headers={
                    "X-Internal-Key": INTERNAL_KEY
                },
            )

        if response.status_code == 200:

            data = response.json()

            dist = data.get(
                "prediction_distribution",
                {}
            )

            rows = data.get(
                "rows_processed",
                0
            )

            threats = data.get(
                "alerts_detected",
                0
            )

            print(
                f"📊 [INFERENCE SUCCESS] "
                f"Processed {rows} flows | "
                f"Results: {dist}"
            )

            has_threat = any(
                label != "BENIGN" and count > 0
                for label, count in dist.items()
            )

            if (
                has_threat
                and os.path.exists(source_pcap)
            ):

                timestamp = int(time.time())

                archived_filename = (
                    f"threat_{timestamp}_"
                    f"{os.path.basename(source_pcap)}"
                )

                dest_path = os.path.join(
                    EVIDENCE_DIR,
                    archived_filename
                )

                shutil.copy(
                    source_pcap,
                    dest_path
                )

                sidecar = {
                    "timestamp": timestamp,
                    "source_pcap": os.path.basename(source_pcap),
                    "prediction_distribution": dist,
                    "alerts": data.get(
                        "alerts",
                        []
                    ),
                }

                try:

                    with open(
                        dest_path + ".json",
                        "w",
                        encoding="utf-8"
                    ) as sf:

                        json.dump(
                            sidecar,
                            sf
                        )

                except Exception as e:

                    print(
                        f"⚠️ Could not write evidence sidecar: {e}"
                    )

                print(
                    f"🚨 [FORENSICS ARCHIVED] "
                    f"Evidence saved: {dest_path} "
                    f"(Threats: {threats})"
                )

        else:

            print(
                f"❌ [API ERROR {response.status_code}] "
                f"{response.text}"
            )

    except requests.exceptions.ConnectionError:

        print(
            f"🚨 Connection Error: "
            f"FastAPI server unreachable at {FASTAPI_URL}"
        )

    except Exception as e:

        print(
            f"❌ Error uploading CSV or archiving evidence: {e}"
        )


def process_pcap_batch(pcap_path: str):
    """Converts PCAP, runs CICFlowMeter Java extraction, and posts CSV to API."""

    pcap_name = os.path.basename(
        pcap_path
    )

    print(
        f"\n⚙️ [PROCESSING CHUNK] "
        f"Analyzing {pcap_name}..."
    )

    staged_pcap = os.path.join(
        INPUT_DIR,
        f"stage_{pcap_name}"
    )

    # ========================================================
    # STEP 1: Normalize PCAP using editcap
    # ========================================================

    editcap_cmd = [
        EDITCAP,
        "-F",
        "pcap",
        "-T",
        "ether",
        pcap_path,
        staged_pcap
    ]

    try:

        subprocess.run(
            editcap_cmd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

    except subprocess.CalledProcessError as err:

        print(
            f"❌ Editcap failed on {pcap_path}: "
            f"{err.stderr.decode('utf-8', errors='ignore')}"
        )

        return

    pre_csvs = set(
        glob.glob(
            os.path.join(
                OUTPUT_DIR,
                "*.csv"
            )
        )
    )

    # ========================================================
    # STEP 2: CICFlowMeter Java feature extraction
    # ========================================================

    java_cmd = [
        "java",
        f"-Djava.library.path={JNETPCAP_LIB}",
        "-cp",
        CLASSPATH_LIB,
        "cic.cs.unb.ca.ifm.Cmd",
        INPUT_DIR,
        OUTPUT_DIR,
    ]

    try:

        subprocess.run(
            java_cmd,
            cwd=CFM_DIR,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

    except subprocess.CalledProcessError as err:

        print(
            f"❌ CICFlowMeter Java engine failed: "
            f"{err.stderr.decode('utf-8', errors='ignore')}"
        )

        return

    # ========================================================
    # STEP 3: Send generated CSV to FastAPI
    # ========================================================

    post_csvs = set(
        glob.glob(
            os.path.join(
                OUTPUT_DIR,
                "*.csv"
            )
        )
    )

    new_csvs = post_csvs - pre_csvs

    if not new_csvs:

        print(
            "ℹ️ [NO TRAFFIC] "
            "No flow CSV generated for this window."
        )

    for csv_file in new_csvs:

        send_csv_to_fastapi(
            csv_file,
            pcap_path
        )

    # ========================================================
    # CLEANUP
    # ========================================================

    for path in [
        pcap_path,
        staged_pcap
    ]:

        if os.path.exists(path):

            try:
                os.remove(path)

            except OSError:
                pass


def start_live_ids():
    """Launches dumpcap background capture loop and processes continuous chunks."""

    os.makedirs(
        INPUT_DIR,
        exist_ok=True
    )

    os.makedirs(
        OUTPUT_DIR,
        exist_ok=True
    )

    os.makedirs(
        EVIDENCE_DIR,
        exist_ok=True
    )

    clean_working_directories()

    # Dumpcap creates files such as:
    # live_chunk_00001_2026...pcap

    capture_pattern = os.path.join(
        INPUT_DIR,
        "live_chunk.pcap"
    )

    dumpcap_cmd = [
        DUMPCAP,
        "-i",
        INTERFACE_INDEX,
        "-b",
        "duration:10",
        "-w",
        capture_pattern,
    ]

    print(
        f"[*] Starting background packet capture "
        f"with '{DUMPCAP}' "
        f"on interface '{INTERFACE_INDEX}'..."
    )

    # Capture stderr so dumpcap permission/interface
    # errors can be displayed.
    capture_process = subprocess.Popen(
        dumpcap_cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE
    )

    print(
        "[*] Live Continuous IDS Active. "
        "Waiting for 10-second capture windows...\n"
    )

    processed = set()

    try:

        while True:

            pcaps = sorted(
                glob.glob(
                    os.path.join(
                        INPUT_DIR,
                        "live_chunk_*.pcap"
                    )
                )
            )

            if len(pcaps) > 1:

                # Process all completed chunks except
                # the currently active one.

                for pcap in pcaps[:-1]:

                    if pcap not in processed:

                        process_pcap_batch(
                            pcap
                        )

                        processed.add(
                            pcap
                        )

            time.sleep(2)

    except KeyboardInterrupt:

        print(
            "\n[*] Shutting down Live IDS Pipeline..."
        )

        capture_process.terminate()


if __name__ == "__main__":
    start_live_ids()