# IDS Dashboard — AI Network Intrusion Detection System

An AI-powered Network Intrusion Detection System (IDS) that analyzes network traffic and identifies different types of attacks using **XGBoost, CICFlowMeter, FastAPI, React, and Docker**.

The project supports two types of detection:

1. **CSV Detection** — upload an existing network-flow CSV file and classify the traffic.
2. **Live Detection** — capture live network traffic on Windows, convert the captured packets into flow data, send the flows to the Dockerized backend, and display the results on the dashboard.

---

# 1. How the System Works

The project has two main parts:

### Windows Host

Windows handles the parts that need direct access to the computer's network interface:

```text
Windows Network Adapter
        ↓
     dumpcap
        ↓
      PCAP
        ↓
  CICFlowMeter
        ↓
    Flow CSV
```

### Docker

Docker handles the application and AI detection:

```text
Flow CSV
   ↓
FastAPI Backend
   ↓
XGBoost Model
   ↓
Prediction
   ↓
React Dashboard
```

So the complete system is:

```text
                  WINDOWS HOST
┌───────────────────────────────────────────┐
│                                           │
│  Wi-Fi / Network Adapter                  │
│             ↓                             │
│         dumpcap.exe                       │
│             ↓                             │
│          PCAP file                        │
│             ↓                             │
│       CICFlowMeter                       │
│             ↓                             │
│         Flow CSV                          │
│             ↓                             │
│      utils/live_ids.py                    │
│             │                             │
└─────────────┼─────────────────────────────┘
              │
              │ HTTP
              ▼
┌───────────────────────────────────────────┐
│              DOCKER                       │
│                                           │
│       FastAPI Backend                     │
│             ↓                             │
│       XGBoost Model                       │
│             ↓                             │
│        Prediction                         │
│             ↓                             │
│       React Dashboard                     │
│                                           │
└───────────────────────────────────────────┘
```

---

# 2. Why Are Windows Capture and Docker Separate?

This is an important part of the project.

Initially, the live packet-capture process was also tested inside Docker. However, Docker Desktop on Windows runs containers in a Linux environment through WSL2.

The physical Windows network adapter is not automatically available inside the Linux container in the same way it is available to Wireshark on Windows.

Even using:

```text
interface=any
```

does not mean "capture every network interface on the Windows computer."

Inside Docker, `any` refers to the interfaces available **inside the Linux environment/container**. It does not provide direct access to the physical Windows Wi-Fi adapter.

Because of this, the live capture was not reliably producing flow data that reached the Dockerized backend, and the dashboard showed no live flows.

The final architecture therefore keeps the packet-capture layer on Windows:

```text
Windows
dumpcap + CICFlowMeter
        ↓
     Flow CSV
        ↓
Docker
FastAPI + XGBoost + React
```

This allows:

* Windows to handle direct network-interface access.
* Docker to handle the backend, AI model, and dashboard.
* The two parts to communicate through the FastAPI API.

---

# 3. Main Features

* AI-based network traffic classification
* XGBoost multiclass classification
* CIC-IDS2017-based model
* CSV/manual traffic prediction
* Live network traffic detection
* PCAP capture using Wireshark/dumpcap
* Network-flow generation using CICFlowMeter
* Real-time dashboard statistics
* Attack-class distribution
* Alert/threat feed
* Forensic evidence archive
* PCAP evidence download
* Evidence feature information
* Login and initial setup
* FastAPI REST API
* React dashboard
* Dockerized backend and frontend
* Windows live-capture launcher
* Environment-variable configuration

---

# 4. Technologies Used

| Component                   | Technology              |
| --------------------------- | ----------------------- |
| Backend                     | FastAPI                 |
| API Server                  | Uvicorn                 |
| Frontend                    | React                   |
| Frontend Build Tool         | Vite                    |
| Frontend Web Server         | Nginx                   |
| Machine Learning            | XGBoost                 |
| Flow Generation             | CICFlowMeter            |
| Dataset                     | CIC-IDS2017             |
| Packet Capture              | Wireshark / dumpcap     |
| Containerization            | Docker / Docker Compose |
| Reverse Proxy Configuration | Caddy                   |
| Programming                 | Python, JavaScript      |

---

# 5. Project Structure

The important files and folders are:

```text
IDS_using_XGBOOST/
│
├── dashboard/                  # React frontend
│   ├── src/
│   ├── Dockerfile
│   ├── nginx.conf
│   ├── package.json
│   └── vite.config.js
│
├── CICFlowMeter-master/        # CICFlowMeter
│   ├── src/
│   ├── model/
│   ├── jnetpcap/
│   ├── gradle/
│   ├── bin/
│   └── build.gradle
│
├── scripts/                    # Testing/traffic scripts
│   ├── deb.py
│   └── flood.py
│
├── utils/                      # Supporting Python scripts
│   ├── __init__.py
│   ├── auth.py
│   ├── hash_pswd.py
│   └── live_ids.py
│
├── main.py                     # FastAPI backend
├── Dockerfile                  # Backend Docker image
├── docker-compose.yml          # Docker services
├── Caddyfile                   # Caddy configuration
├── requirements.txt            # Python dependencies
├── start_ids.ps1               # Windows live IDS launcher
├── .dockerignore
├── .gitignore
└── README.md
```

Generated PCAP files, temporary CSV files, logs, environment files, Python cache files, and build output are excluded from Git.

---

# 6. Requirements

Before running the project, install the following:

### Required

* Windows 10/11
* Docker Desktop
* Python 3.11 or compatible Python version
* Wireshark
* CICFlowMeter
* Git

### Docker

Docker Desktop should be running before starting the application.

Check Docker:

```powershell
docker --version
```

Check Docker Compose:

```powershell
docker compose version
```

---

# 7. Download the Project

Clone the repository:

```powershell
git clone https://github.com/alinawaqar/IDS_using_XGBOOST.git
```

Go into the project folder:

```powershell
cd IDS_using_XGBOOST
```

You should now be inside:

```text
IDS_using_XGBOOST
```

---

# 8. Configure the Environment

The project uses environment variables for settings that depend on the user's computer or contain sensitive information.

Do **not** put passwords, API keys, or secret values directly into GitHub.

The important variables are:

```text
IDS_INTERNAL_KEY
IDS_PASSWORD_HASH
IDS_SESSION_SECRET
IDS_EVIDENCE_DIR
IDS_DASHBOARD_ORIGINS
INTERFACE_INDEX
FASTAPI_URL
DUMPCAP_PATH
```

---

# 9. Windows Path Configuration

The live-capture part runs on Windows, so it needs to know where Wireshark/dumpcap and CICFlowMeter are located.

## Wireshark / dumpcap

If Wireshark is installed in:

```text
D:\Wireshark\
```

the project can use:

```text
D:\Wireshark\dumpcap.exe
```

If your Wireshark installation is somewhere else, set the path accordingly.

For example:

```powershell
$env:DUMPCAP_PATH = "C:\Program Files\Wireshark\dumpcap.exe"
```

The exact path depends on where Wireshark is installed on your computer.

---

# 10. Configure the Network Interface

The live IDS needs to know which network interface should be captured.

First, list the interfaces available to Wireshark/dumpcap:

```powershell
& "D:\Wireshark\dumpcap.exe" -D
```

You may see something similar to:

```text
1. Ethernet
2. Loopback
3. ...
5. Wi-Fi
```

The number depends on your computer.

If your Wi-Fi interface is number `5`, configure:

```powershell
$env:INTERFACE_INDEX = "5"
```

If your computer shows a different number, use that number instead.

For example:

```powershell
$env:INTERFACE_INDEX = "3"
```

Do not assume that interface `5` will be the same on another computer.

---

# 11. CICFlowMeter Configuration

CICFlowMeter is included in:

```text
CICFlowMeter-master/
```

It converts captured packets into network-flow features.

The live pipeline is:

```text
PCAP
 ↓
CICFlowMeter
 ↓
Flow CSV
```

The generated CSV contains the network-flow features required by the XGBoost model.

CICFlowMeter is primarily used from the Windows live-capture workflow.

---

# 12. Start the Application

There are two stages:

### Stage 1 — Start Docker

Open PowerShell in the project folder:

```powershell
cd "C:\path\to\IDS_using_XGBOOST"
```

Start Docker:

```powershell
docker compose up -d
```

Check the containers:

```powershell
docker compose ps
```

You should see the backend and frontend services running.

The services are:

| Service  | Purpose         | Port |
| -------- | --------------- | ---: |
| Backend  | FastAPI IDS API | 8000 |
| Frontend | React dashboard | 3000 |

---

# 13. Open the Dashboard

Once Docker is running, open:

```text
http://localhost:3000
```

The FastAPI backend can be accessed at:

```text
http://localhost:8000
```

The dashboard communicates with the backend through the API.

---

# 14. Start Live Detection

Once Docker is running and the Windows capture configuration is correct, start the live IDS.

The project includes:

```text
start_ids.ps1
```

From the project folder, run:

```powershell
.\start_ids.ps1
```

The launcher:

1. Starts Docker services.
2. Gets the required internal API configuration.
3. Sets the network interface.
4. Starts the Windows live IDS agent.
5. Allows the agent to capture traffic and send flow data to the Docker backend.

The live agent is:

```text
utils/live_ids.py
```

---

# 15. What Happens When Live Detection Starts?

The complete process is:

```text
1. Windows network interface
             ↓
2. dumpcap captures packets
             ↓
3. PCAP file is created
             ↓
4. CICFlowMeter processes the PCAP
             ↓
5. Flow CSV is generated
             ↓
6. live_ids.py sends the CSV to FastAPI
             ↓
7. XGBoost predicts the traffic class
             ↓
8. FastAPI updates the dashboard data
             ↓
9. React dashboard displays the results
```

The PowerShell window should show processing/inference messages while the system is running.

---

# 16. Testing Live Detection

After starting:

```powershell
.\start_ids.ps1
```

leave that PowerShell window running.

Open another PowerShell window and generate normal network traffic.

For example:

```powershell
ping google.com
```

You can also browse websites normally.

For a simple HTTP request:

```powershell
curl https://example.com
```

The live capture should detect the generated traffic, convert it into flow data, and send it to the backend.

Then open:

```text
http://localhost:3000
```

The dashboard should begin showing traffic/flow information.

---

# 17. CSV / Manual Detection

The system can also analyze an existing flow CSV without live packet capture.

The process is:

```text
CSV File
   ↓
FastAPI
   ↓
Feature Processing
   ↓
XGBoost Model
   ↓
Prediction
   ↓
Dashboard
```

This is useful when you already have a CIC-IDS2017-style flow CSV and want to test the model without capturing live traffic.

---

# 18. API

The FastAPI backend provides several endpoints.

Important endpoints include:

```text
POST /predict-csv
GET  /stats
GET  /evidence
GET  /evidence/download/{filename}
GET  /evidence/features/{filename}
```

### `/predict-csv`

Receives network-flow CSV data and performs IDS prediction.

### `/stats`

Returns information used by the dashboard, including:

* Total flows
* Flagged flows
* Attack-class distribution
* Recent traffic history
* Recent alerts

### `/evidence`

Returns available forensic evidence.

### `/evidence/download/{filename}`

Downloads an archived PCAP evidence file.

### `/evidence/features/{filename}`

Returns information associated with an evidence file.

---

# 19. Dashboard

The React dashboard provides a visual interface for monitoring network traffic.

It includes:

* Traffic statistics
* Traffic history
* Attack distribution
* Threat/alert feed
* Forensic evidence
* PCAP evidence information
* Login/setup interface

The dashboard gets its information from the FastAPI backend.

The dashboard currently uses periodic API polling to refresh information rather than WebSockets.

---

# 20. Machine Learning Model

The IDS uses an XGBoost multiclass classification model trained using CIC-IDS2017 network-flow data.

The model uses the following artifacts:

```text
cicids2017_feature_columns.joblib
cicids2017_label_encoder.joblib
cicids2017_training_medians.joblib
cicids2017_xgboost_multiclass.joblib
```

These files are used to:

1. Match incoming data to the expected model features.
2. Handle missing/preprocessed feature values.
3. Convert predicted class labels.
4. Generate the final traffic classification.

The model is used by the FastAPI backend during prediction.

---

# 21. Attack Classes

The trained model supports the following classes:

```text
Normal
DoS
Suspicious
Web Attack
PortScan
Bot
Brute Force
```

The predicted class depends on the features of the incoming network flow and the trained XGBoost model.

---

# 22. Evidence and Forensics

When suspicious traffic is detected, the live IDS workflow can save PCAP evidence.

Evidence information can include:

* Attack class
* Confidence
* Source IP
* Destination IP
* Attack information

The dashboard can display available evidence through the forensic section.

The evidence directory can be configured using:

```text
IDS_EVIDENCE_DIR
```

For example:

```powershell
$env:IDS_EVIDENCE_DIR = "C:\IDS\evidence"
```

The actual location can be changed according to the user's computer.

---

# 23. Authentication

The dashboard includes login and initial setup functionality.

Authentication-related code is located in:

```text
utils/
```

Sensitive authentication settings are supplied through environment variables.

Important:

**Never commit `.env` files, passwords, API keys, or session secrets to GitHub.**

The project `.gitignore` excludes:

```text
.env
```

---

# 24. Environment Variables

The following variables can be used to configure the application:

```text
IDS_INTERNAL_KEY
IDS_PASSWORD_HASH
IDS_SESSION_SECRET
IDS_EVIDENCE_DIR
IDS_DASHBOARD_ORIGINS
INTERFACE_INDEX
FASTAPI_URL
DUMPCAP_PATH
```

### Example

Network interface:

```powershell
$env:INTERFACE_INDEX = "5"
```

Wireshark:

```powershell
$env:DUMPCAP_PATH = "D:\Wireshark\dumpcap.exe"
```

Evidence directory:

```powershell
$env:IDS_EVIDENCE_DIR = "C:\IDS\evidence"
```

The values above are examples. Paths and interface numbers must be changed according to the computer being used.

---

# 25. Stopping the Application

To stop the Docker services:

```powershell
docker compose down
```

If the live IDS PowerShell window is still running, stop it first with:

```text
Ctrl + C
```

Then stop Docker:

```powershell
docker compose down
```

---

# 26. Restarting the Application

For a normal restart:

```powershell
docker compose up -d
```

Then:

```powershell
.\start_ids.ps1
```

There is normally **no need to rebuild the Docker images** unless the Dockerfiles, dependencies, or application image itself has changed.

---

# 27. Frontend Development

The normal project uses Docker for the frontend.

For frontend development without Docker:

```powershell
cd dashboard
npm install
npm run dev
```

The Vite development server normally runs at:

```text
http://localhost:5173
```

---

# 28. Production Frontend Build

To create a production frontend build:

```powershell
cd dashboard
npm run build
```

The generated files are placed in:

```text
dashboard/dist/
```

The Docker frontend uses Nginx to serve the production build.

---

# 29. Backend Development Without Docker

For local backend development:

```powershell
pip install -r requirements.txt
```

Then:

```powershell
uvicorn main:app --reload --port 8000
```

The backend will be available at:

```text
http://127.0.0.1:8000
```

Docker is recommended for the complete application because the Docker setup also provides the required system-level dependencies.

---

# 30. Testing Scripts

The project contains testing/traffic scripts:

```text
scripts/deb.py
scripts/flood.py
```

These are separate from the normal dashboard interface and are intended for traffic/testing purposes.

---

# 31. Important Limitations

### Dashboard statistics are stored in memory

The current dashboard statistics are maintained in memory.

If the backend restarts, the current statistics are reset.

A database would be required for permanent historical statistics.

### Dashboard uses polling

The dashboard periodically requests updated information from the API.

It does not currently use WebSockets.

### Live capture depends on the Windows host

Live detection requires:

* A working network interface
* Wireshark/dumpcap
* CICFlowMeter
* Python
* Docker
* Correct interface configuration

The Docker containers do not directly capture packets from the Windows physical network adapter.

### Model scope

The system is an AI-based network traffic classification project. It is not intended to replace a complete enterprise security monitoring platform.

### Public deployment

Before exposing the application to the public internet, additional security measures should be added, such as:

* HTTPS
* Strong authentication
* Secure secret management
* Persistent database storage
* Rate limiting
* Logging and monitoring
* Firewall configuration
* Proper network access controls

---

# 32. Security Notes

Never commit the following to GitHub:

```text
.env
Passwords
API keys
Session secrets
Private credentials
```

Generated PCAP files and temporary network-flow files should also remain outside version control.

The repository's `.gitignore` and `.dockerignore` are configured to exclude generated and sensitive files.

---

# 33. Quick Start — For Someone Using the Project for the First Time

If you are using this project for the first time, follow these steps in order.

### Step 1 — Clone the project

```powershell
git clone https://github.com/alinawaqar/IDS_using_XGBOOST.git
cd IDS_using_XGBOOST
```

### Step 2 — Make sure Docker Desktop is running

Check:

```powershell
docker --version
docker compose version
```

### Step 3 — Check Wireshark

Find `dumpcap.exe`.

For example:

```text
D:\Wireshark\dumpcap.exe
```

If it is somewhere else, configure:

```powershell
$env:DUMPCAP_PATH = "C:\path\to\dumpcap.exe"
```

### Step 4 — Find your network interface

Run:

```powershell
& "D:\Wireshark\dumpcap.exe" -D
```

Find your Wi-Fi or Ethernet interface.

For example:

```text
5. Wi-Fi
```

Then configure:

```powershell
$env:INTERFACE_INDEX = "5"
```

Use the number shown on your own computer.

### Step 5 — Start Docker

```powershell
docker compose up -d
```

Check:

```powershell
docker compose ps
```

### Step 6 — Open the dashboard

Go to:

```text
http://localhost:3000
```

### Step 7 — Start live detection

In the project folder:

```powershell
.\start_ids.ps1
```

### Step 8 — Generate some network traffic

For example:

```powershell
ping google.com
```

or browse websites normally.

### Step 9 — Check the dashboard

Return to:

```text
http://localhost:3000
```

The captured network flows should start appearing as the live pipeline processes them.

---

# 34. Simple Overview

If you only remember one thing about the project, remember this:

```text
WINDOWS
│
├── Captures packets
├── Creates PCAP
└── CICFlowMeter creates flow CSV
             │
             ▼
          DOCKER
             │
             ├── FastAPI
             ├── XGBoost
             └── React Dashboard
```

**Windows = packet capture**

**Docker = AI detection + API + dashboard**

This separation is intentional because the Windows host has direct access to the physical network interface, while the Dockerized application runs in a Linux environment.

---

# 35. Author

**Alina Waqar**

AI / Cybersecurity Project

**IDS Dashboard — AI Network Intrusion Detection System**
