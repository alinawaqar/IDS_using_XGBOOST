# IDS Dashboard — AI Network Intrusion Detection System

An AI-powered network intrusion detection dashboard built with **FastAPI, React, XGBoost, and CICFlowMeter**.

The system analyzes network-flow data and classifies traffic into multiple attack categories. It supports both **CSV-based detection** and **live network traffic detection**.

The application is Dockerized for the backend and frontend, while the Windows live-capture agent uses `dumpcap` and CICFlowMeter to capture network traffic and send generated flow data to the IDS API.

---

## Features

* AI-based network traffic classification using XGBoost
* CIC-IDS2017-based traffic classification
* CSV/manual traffic prediction
* Live network traffic capture
* CICFlowMeter flow generation
* Real-time dashboard statistics
* Attack distribution visualization
* Threat/alert feed
* Forensic evidence archive
* PCAP evidence download
* Evidence feature information
* Login and initial setup
* FastAPI REST API
* React dashboard
* Dockerized backend and frontend
* Windows live-capture launcher
* Environment-variable based configuration

---

## System Architecture

```text
                         Windows Host
                              │
                              │ Network Traffic
                              ▼
                         dumpcap.exe
                              │
                              │ PCAP
                              ▼
                        CICFlowMeter
                              │
                              │ Flow CSV
                              ▼
                    utils/live_ids.py
                              │
                              │ HTTP POST
                              ▼
              ┌─────────────────────────────┐
              │     Docker Backend          │
              │                             │
              │       FastAPI API           │
              │             │               │
              │             ▼               │
              │      XGBoost Model           │
              │             │               │
              │             ▼               │
              │       Predictions            │
              └─────────────┬───────────────┘
                            │
                            │ API
                            ▼
                  ┌────────────────────┐
                  │   React Dashboard  │
                  │                    │
                  │ Traffic Statistics │
                  │ Alerts             │
                  │ Attack Classes     │
                  │ Evidence           │
                  └────────────────────┘
```

### Detection flow

```text
Network Traffic
      ↓
dumpcap
      ↓
PCAP
      ↓
CICFlowMeter
      ↓
Flow CSV
      ↓
XGBoost IDS Model
      ↓
Prediction
      ↓
FastAPI
      ↓
React Dashboard
```

---

## Technologies

* Python
* FastAPI
* Uvicorn
* React
* Vite
* JavaScript
* HTML/CSS
* XGBoost
* CICFlowMeter
* CIC-IDS2017
* Docker
* Docker Compose
* Nginx
* Caddy

---

## Project Structure

```text
IDS_using_XGBOOST/
│
├── dashboard/
│   ├── src/
│   │   ├── components/
│   │   ├── App.jsx
│   │   ├── Login.jsx
│   │   ├── Setup.jsx
│   │   ├── api.js
│   │   └── styles.css
│   ├── Dockerfile
│   ├── nginx.conf
│   ├── index.html
│   ├── package.json
│   ├── package-lock.json
│   └── vite.config.js
│
├── CICFlowMeter-master/
│   ├── src/
│   ├── model/
│   ├── jnetpcap/
│   ├── gradle/
│   ├── bin/
│   ├── build.gradle
│   ├── pom.xml
│   └── ...
│
├── models/
│   └── ...
│
├── scripts/
│   ├── deb.py
│   └── flood.py
│
├── utils/
│   ├── __init__.py
│   ├── auth.py
│   ├── hash_pswd.py
│   └── live_ids.py
│
├── main.py
├── Dockerfile
├── docker-compose.yml
├── Caddyfile
├── requirements.txt
├── start_ids.ps1
├── .dockerignore
├── .gitignore
└── README.md
```

Generated PCAP files, CSV files, logs, Python cache files, environment files, and build output are excluded from Git through `.gitignore` and `.dockerignore`.

---

## Docker Setup

The application uses Docker Compose to run the main services.

### Services

| Service  | Purpose                         |   Port |
| -------- | ------------------------------- | -----: |
| Backend  | FastAPI IDS API                 | `8000` |
| Frontend | React dashboard served by Nginx | `3000` |

### Start the application

From the project folder:

```powershell
docker compose up -d
```

Check running containers:

```powershell
docker compose ps
```

The backend is available at:

```text
http://localhost:8000
```

The dashboard is available at:

```text
http://localhost:3000
```

### Stop the application

```powershell
docker compose down
```

---

## Authentication and Setup

The dashboard includes a login/setup flow.

Authentication-related functionality is handled by the files in:

```text
utils/
```

The project uses environment variables for sensitive configuration.

### Important

Do not commit `.env` files or passwords/secrets to GitHub.

The `.gitignore` file excludes:

```text
.env
```

---

## Live Network Detection

Live detection uses the Windows host to capture network traffic.

### Requirements

For live detection on Windows, the following components are required:

* Wireshark / `dumpcap`
* CICFlowMeter
* Python
* Running Docker backend
* Network interface available for capture

The live detection pipeline is:

```text
Windows Network Interface
          ↓
       dumpcap
          ↓
        PCAP
          ↓
     CICFlowMeter
          ↓
       Flow CSV
          ↓
   utils/live_ids.py
          ↓
 FastAPI /predict-csv
          ↓
     XGBoost Model
          ↓
      Dashboard
```

### Starting the system

The project includes:

```text
start_ids.ps1
```

This launcher starts the Docker services, obtains the required internal API configuration, selects the network interface, and starts the Windows live IDS agent.

Run PowerShell from the project folder:

```powershell
.\start_ids.ps1
```

The network interface can be configured through:

```text
INTERFACE_INDEX
```

For example:

```powershell
$env:INTERFACE_INDEX = "5"
```

The correct interface number depends on the user's computer.

---

## Wireshark / dumpcap

The live capture agent uses `dumpcap` to capture network traffic.

The default Windows paths used by the project can be configured through environment variables when necessary.

Example:

```powershell
$env:DUMPCAP_PATH = "D:\Wireshark\dumpcap.exe"
```

The exact path depends on the local Wireshark installation.

---

## CICFlowMeter

CICFlowMeter converts captured network packets into network-flow features used by the IDS model.

The project contains the CICFlowMeter source and required dependencies under:

```text
CICFlowMeter-master/
```

CICFlowMeter is used primarily by the Windows live-capture workflow.

The generated flow data is then sent to the FastAPI backend for prediction.

---

## CSV Detection

The backend also supports prediction from network-flow CSV files.

CSV detection follows:

```text
CSV Flow Data
      ↓
FastAPI
      ↓
Feature Processing
      ↓
XGBoost Model
      ↓
Traffic Class
      ↓
Dashboard
```

The model expects the CIC-IDS2017 feature format used during training.

---

## API

The FastAPI backend provides endpoints for prediction, statistics, evidence, and application functionality.

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

Returns dashboard statistics such as:

* total flows
* flagged flows
* attack-class distribution
* recent traffic history
* recent alerts

### `/evidence`

Returns available forensic evidence.

### `/evidence/download/{filename}`

Downloads an archived PCAP file.

### `/evidence/features/{filename}`

Returns information associated with an archived evidence file.

---

## Dashboard

The React dashboard provides a visual interface for monitoring network traffic.

It includes:

* Traffic statistics
* Traffic history
* Attack distribution
* Alert/threat feed
* Forensic evidence
* PCAP evidence information
* Login/setup interface

Dashboard data is retrieved from the FastAPI backend.

The dashboard uses polling to refresh live information.

---

## Model

The IDS uses an **XGBoost multiclass classification model** trained using CIC-IDS2017 network-flow data.

The model artifacts include:

```text
cicids2017_feature_columns.joblib
cicids2017_label_encoder.joblib
cicids2017_training_medians.joblib
cicids2017_xgboost_multiclass.joblib
```

These artifacts are used for:

1. Matching incoming features to the expected model features
2. Handling feature preprocessing
3. Encoding predicted classes
4. Generating multiclass traffic predictions

---

## Attack Classes

The trained model includes the following traffic classes:

* Normal
* DoS
* Suspicious
* Web Attack
* PortScan
* Bot
* Brute Force

The exact prediction depends on the trained model and the characteristics of the incoming network flow.

---

## Evidence and Forensics

When suspicious traffic is detected, the live IDS workflow can archive PCAP evidence.

Associated metadata can include:

* Attack class
* Confidence
* Source IP
* Destination IP
* Attack distribution

The dashboard can display this information through the forensic archive.

The evidence directory can be configured using:

```text
IDS_EVIDENCE_DIR
```

For example:

```powershell
$env:IDS_EVIDENCE_DIR = "C:\path\to\evidence"
```

---

## Environment Variables

Sensitive or machine-specific configuration should be supplied through environment variables.

Examples include:

```text
IDS_INTERNAL_KEY
IDS_PASSWORD_HASH
IDS_SESSION_SECRET
IDS_EVIDENCE_DIR
IDS_DASHBOARD_ORIGINS
INTERFACE_INDEX
FASTAPI_URL
```

Machine-specific paths such as Wireshark/CICFlowMeter locations should also be configured according to the local environment.

Never commit secrets or `.env` files to GitHub.

---

## Frontend Development

The production application uses Docker.

For frontend development outside Docker:

```powershell
cd dashboard
npm install
npm run dev
```

The Vite development server normally runs on:

```text
http://localhost:5173
```

---

## Production Frontend Build

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

## Backend Development Without Docker

For local backend development:

```powershell
pip install -r requirements.txt
```

Then:

```powershell
uvicorn main:app --reload --port 8000
```

The API will be available at:

```text
http://127.0.0.1:8000
```

Docker is recommended for the complete application because the production setup also includes the required backend system dependencies.

---

## Testing Scripts

The project contains separate traffic-testing scripts:

```text
scripts/deb.py
scripts/flood.py
```

These scripts are used for traffic/testing purposes and are not required for the normal dashboard interface.

---

## Important Limitations

### In-memory dashboard statistics

Dashboard statistics are maintained in memory.

They reset when the backend restarts.

For persistent historical analytics, a database would be required.

### Polling

The dashboard currently uses periodic API polling rather than WebSockets.

This provides near-real-time dashboard updates without requiring a persistent WebSocket connection.

### Live capture is host-dependent

Live capture depends on the Windows machine having:

* a working network interface
* Wireshark/dumpcap
* CICFlowMeter
* the correct interface configuration

The Docker containers process the generated flow data, while packet capture itself is performed on the Windows host.

### Model scope

The system is an AI-based network traffic classification system and should not be treated as a replacement for a complete enterprise security monitoring system.

### Deployment security

Before exposing the API or dashboard to the public internet, additional production security measures should be implemented, including:

* HTTPS
* stronger authentication and authorization
* secure secret management
* persistent database storage
* rate limiting
* logging and monitoring
* proper firewall/network configuration

---

## Security Notes

Never commit:

```text
.env
passwords
API keys
session secrets
private credentials
```

Generated network captures and temporary files should also remain outside version control.

---

## Quick Start

### 1. Clone the repository

```powershell
git clone https://github.com/alinawaqar/IDS_using_XGBOOST.git
cd IDS_using_XGBOOST
```

### 2. Start Docker

```powershell
docker compose up -d
```

### 3. Open the dashboard

```text
http://localhost:3000
```

### 4. For live detection

Configure the Windows capture environment and run:

```powershell
.\start_ids.ps1
```

Then use the dashboard's live detection functionality.

---

## Technologies Summary

| Component                   | Technology              |
| --------------------------- | ----------------------- |
| Backend                     | FastAPI                 |
| API Server                  | Uvicorn                 |
| Frontend                    | React                   |
| Frontend Build Tool         | Vite                    |
| Frontend Server             | Nginx                   |
| ML Model                    | XGBoost                 |
| Flow Generator              | CICFlowMeter            |
| Dataset                     | CIC-IDS2017             |
| Containerization            | Docker / Docker Compose |
| Packet Capture              | Wireshark / dumpcap     |
| Reverse Proxy Configuration | Caddy                   |

---

## Author

**Alina Waqar**

AI / Cybersecurity Project

**IDS Dashboard — AI Network Intrusion Detection System**
