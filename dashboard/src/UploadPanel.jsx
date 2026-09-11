import { useState } from "react";
import { api } from "../api";

export default function UploadPanel({ onAnalyzed }) {
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  async function handleFile(e) {
    const file = e.target.files?.[0];
    if (!file) return;

    setBusy(true);
    setError(null);
    setResult(null);

    try {
      const data = await api.predictCsv(file);

      console.log("MANUAL CSV RESULT:", data);

      setResult(data);
      onAnalyzed?.();
    } catch (err) {
      console.error(err);
      setError(err.message || "CSV analysis failed.");
    } finally {
      setBusy(false);
      e.target.value = "";
    }
  }

  const distribution = result?.prediction_distribution || {};

  const flaggedCount = Object.entries(distribution)
    .filter(([label]) => label !== "BENIGN")
    .reduce((total, [, count]) => total + Number(count), 0);

  return (
    <div className="card manual-csv-card">
      <h2>MANUAL CSV ANALYSIS</h2>

      <label className="upload-drop">
        <input
          type="file"
          accept=".csv"
          onChange={handleFile}
          disabled={busy}
          hidden
        />

        {busy
          ? "Analyzing…"
          : "Upload a CICFlowMeter CSV to run inference"}
      </label>

      {error && (
        <div className="csv-error">
          {error}
        </div>
      )}

      {result && (
        <div className="csv-results">

          <div className="stat-row">
            <span>
              ROWS{" "}
              <b>
                {Number(result.rows_processed).toLocaleString()}
              </b>
            </span>

            <span>
              ALERTS{" "}
              <b className="csv-alert-count">
                {flaggedCount.toLocaleString()}
              </b>
            </span>
          </div>

          <div className="csv-breakdown">
            <div className="csv-breakdown-title">
              PREDICTION BREAKDOWN
            </div>

            {Object.entries(distribution)
              .sort((a, b) => Number(b[1]) - Number(a[1]))
              .map(([label, count]) => (
                <div className="csv-breakdown-row" key={label}>
                  <span>{label}</span>

                  <b className={label === "BENIGN" ? "" : "attack-count"}>
                    {Number(count).toLocaleString()}
                  </b>
                </div>
              ))}
          </div>

        </div>
      )}
    </div>
  );
}