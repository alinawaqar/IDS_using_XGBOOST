import { useState, useEffect } from "react";
import { api } from "../api";

function headClass(attack) {
  const a = (attack || "").toLowerCase();
  if (a.includes("ddos")) return "ddos";
  if (a.includes("ssh") || a.includes("brute")) return "ssh";
  if (a.includes("scan")) return "scan";
  return "unk";
}

function fmtSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function fmtTimestamp(unixSeconds) {
  const d = new Date(unixSeconds * 1000);
  return d.toISOString().replace("T", "_").slice(0, 19).replace(/:/g, "-");
}

function FeaturesModal({ filename, onClose }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    api.evidenceFeatures(filename).then(setData).catch((e) => setError(e.message));
  }, [filename]);

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <span>{filename}</span>
          <button onClick={onClose}>✕</button>
        </div>
        <div className="modal-body">
          {error && <div style={{ color: "var(--red)" }}>{error}</div>}
          {!error && !data && <div style={{ color: "var(--text-dim)" }}>Loading…</div>}
          {data && (
            <pre>{JSON.stringify(data, null, 2)}</pre>
          )}
        </div>
      </div>
    </div>
  );
}

export default function ForensicArchive({ entries }) {
  const [viewing, setViewing] = useState(null);

  return (
    <>
      <div className="archive-header">
        <h2>FORENSIC ARCHIVE — SAVED EVIDENCE</h2>
        <span className="count">{entries.length} incidents</span>
      </div>
      <div className="masonry">
        {entries.length === 0 && (
          <div style={{ color: "var(--text-dim)", fontSize: 13 }}>
            No archived evidence yet — threats get saved here automatically once live capture flags non-benign flows.
          </div>
        )}
        {entries.map((e) => {
          const cls = headClass(e.attack_type);
          return (
            <div className="pin" key={e.filename}>
              <div className={`pin-head ${cls}`}>
                <div className="label">{e.attack_type}</div>
                <div className="time">{fmtTimestamp(e.modified)}</div>
              </div>
              <div className="pin-body">
                {e.src_ip && <>SRC <span className="ip-flow">{e.src_ip}</span><br /></>}
                {e.dst_ip && <>DST <span className="ip-flow">{e.dst_ip}</span><br /></>}
                SIZE {fmtSize(e.size_bytes)}
                {e.confidence != null && <> · conf {e.confidence.toFixed(2)}</>}
              </div>
              <div className="pin-actions">
                <a href={api.evidenceDownloadUrl(e.filename)} download>
                  <button>DOWNLOAD PCAP</button>
                </a>
                <button onClick={() => setViewing(e.filename)}>VIEW FEATURES</button>
              </div>
            </div>
          );
        })}
      </div>
      {viewing && <FeaturesModal filename={viewing} onClose={() => setViewing(null)} />}
    </>
  );
}
