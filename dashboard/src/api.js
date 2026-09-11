// Every call goes through /api/* which vite.config.js proxies to FastAPI
// in dev. In production, serve the built dashboard behind the same host
// as main.py (or set VITE_API_BASE at build time) so these paths resolve.
const BASE = import.meta.env.VITE_API_BASE || "/api";

async function req(path, options) {
  const res = await fetch(`${BASE}${path}`, options);
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`${res.status} ${res.statusText}: ${body}`);
  }
  return res.json();
}

export const api = {
  stats: () => req("/stats"),
  evidence: () => req("/evidence"),
  evidenceFeatures: (filename) =>
    req(`/evidence/features/${encodeURIComponent(filename)}`),
  evidenceDownloadUrl: (filename) =>
    `${BASE}/evidence/download/${encodeURIComponent(filename)}`,
  liveStatus: () => req("/live/status"),
  liveStart: () => req("/live/start", { method: "POST" }),
  liveStop: () => req("/live/stop", { method: "POST" }),
  predictCsv: (file) => {
    const form = new FormData();
    form.append("file", file);
    form.append("source", "csv");
    return req("/predict-csv", { method: "POST", body: form });
  },
};
