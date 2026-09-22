// Every call goes through /api/* which vite.config.js proxies to FastAPI
// in dev. In production, serve the built dashboard behind the same host
// as main.py (or set VITE_API_BASE at build time) so these paths resolve.
//
// credentials: "include" is required on every call now that the API uses
// a session cookie -- without it, the browser won't send the cookie and
// every request will come back 401 even right after logging in.
const BASE = import.meta.env.VITE_API_BASE || "/api";

async function req(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, { ...options, credentials: "include" });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    const err = new Error(`${res.status} ${res.statusText}: ${body}`);
    err.status = res.status;
    throw err;
  }
  return res.json();
}

export const api = {
  authStatus: () => req("/auth/status"),
  needsSetup: () => req("/auth/needs-setup"),
  setup: (password) => {
    const form = new FormData();
    form.append("password", password);
    return req("/auth/setup", { method: "POST", body: form });
  },
  login: (password) => {
    const form = new FormData();
    form.append("password", password);
    return req("/auth/login", { method: "POST", body: form });
  },
  logout: () => req("/auth/logout", { method: "POST" }),

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