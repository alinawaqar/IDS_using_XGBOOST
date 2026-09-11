import { useState } from "react";
import { api } from "../api";

export default function UploadPanel({ onAnalyzed }) {
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  async function handleFile(e) {
    const file = e.target.files[0];
    if (!file) return;
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const data = await api.predictCsv(file);
      setResult(data);
      onAnalyzed?.();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
      e.target.value = "";
    }
  }

  return (
    <div className="card">
      <h2>MANUAL CSV ANALYSIS</h2>
      <label className="upload-drop">
        <input type="file" accept=".csv" onChange={handleFile} disabled={busy} hidden />
        {busy ? "Analyzing…" : "Upload a CICFlowMeter CSV to run inference"}
      </label>
      {error && <div style={{ color: "var(--red)", fontSize: 11.5, marginTop: 8 }}>{error}</div>}
      {result && (
        <div className="stat-row" style={{ marginTop: 10 }}>
          <span>ROWS <b>{result.rows_processed}</b></span>
          <span>ALERTS <b style={{ color: "var(--red)" }}>{result.alerts_detected}</b></span>
        </div>
      )}
    </div>
  );
}
