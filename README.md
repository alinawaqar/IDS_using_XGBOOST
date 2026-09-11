# IDS Dashboard — setup

Two pieces: your existing FastAPI backend (`main.py`, `live_ids.py`), patched
to expose dashboard data, and a new React app in `dashboard/`.

## What changed in your existing files

**`main.py`**
- Added CORS so the dashboard (different port) can call it.
- Added in-memory `STATE` that accumulates as `/predict-csv` runs — total
  flows/flagged, cumulative distribution per class, a rolling history buffer
  (for the traffic chart), and the last 50 individual alerts.
- New endpoints:
  - `GET /stats` — everything above, for the dashboard to poll.
  - `GET /evidence` — lists archived PCAPs from `EVIDENCE_DIR`, enriched with
    attack type / confidence / IPs read from a JSON sidecar (see below).
  - `GET /evidence/download/{filename}` — streams the raw PCAP.
  - `GET /evidence/features/{filename}` — returns the sidecar JSON (the
    "VIEW FEATURES" button in the archive cards).
- `EVIDENCE_DIR` now defaults to `<project_ids_root>/evidence` but can be
  overridden with the `IDS_EVIDENCE_DIR` env var.

**`live_ids.py`**
- When it archives a threat PCAP, it now also writes `<pcap>.json` next to
  it — attack distribution, confidence, IPs — so the dashboard doesn't have
  to reparse anything.
- `EVIDENCE_DIR` reads the same `IDS_EVIDENCE_DIR` env var as `main.py`.
  **Set this env var (or edit both files) so they point at the same
  folder** — by default `live_ids.py` still uses your hardcoded
  `CFM_DIR\evidence` (Windows path), while `main.py` defaults to a local
  `./evidence` folder. If you run both on the same Windows machine, set:

  ```
  set IDS_EVIDENCE_DIR=C:\CICFlowMeter-master\CICFlowMeter-master\evidence
  ```

  before starting both `main.py` and `live_ids.py` (or just launch
  `live_ids.py` via `/live/start`, which inherits the API process's env).

Nothing else about your inference logic, column mapping, or CICFlowMeter
integration was touched.

## Running it

**Backend** (from `project_ids_root/`):
```bash
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

**Dashboard** (from `project_ids_root/dashboard/`):
```bash
npm install
npm run dev
```
Opens on `http://localhost:5173`. It proxies `/api/*` to `http://127.0.0.1:8000`
in dev (see `vite.config.js`) — change the proxy target if your API runs
elsewhere.

Click **START CAPTURE** in the top bar to call `/live/start` (which spawns
`live_ids.py` exactly as before). The traffic chart, threat feed, alert
donut, and forensic archive all poll `/stats` and `/evidence` every 4s —
no mock data anywhere.

## Production build

```bash
cd dashboard && npm run build
```
Outputs static files to `dashboard/dist/` — serve these from any static
host or behind the same reverse proxy as the FastAPI app. Set
`VITE_API_BASE` at build time if the API isn't reachable at `/api` in
production (e.g. `VITE_API_BASE=https://your-host/api npm run build`).

## Known gaps (see "is it production style" discussion)

- Stats are in-memory and reset on API restart — fine for a live session
  view, not for historical reporting. Swap in a DB if you need persistence.
- Polling, not WebSockets — 4s latency on the dashboard. Fine for a 10s
  capture cadence; upgrade to a WebSocket push from `main.py` if you want
  sub-second updates.
- No auth. Anyone who can reach the API can hit `/live/start`, download
  evidence PCAPs, etc. Add auth before exposing this beyond localhost.
- `flood.py` (your traffic-burst test script) wasn't touched or wired into
  the dashboard.
