function severityClass(label) {
  if (label === "DDoS Flood" || label?.toLowerCase().includes("ddos")) return "crit";
  if (label === "UNKNOWN_ATTACK") return "";
  return "warn";
}

function fmtTime(ts) {
  return new Date(ts * 1000).toLocaleTimeString([], { hour12: false });
}

export default function ThreatFeed({ alerts }) {
  return (
    <div className="card">
      <h2>
        THREAT ACTIVITY FEED{" "}
        <span className="tag" style={{ background: "rgba(239,91,91,0.12)", color: "var(--red)" }}>
          LIVE
        </span>
      </h2>
      <div className="feed">
        {alerts.length === 0 && (
          <div style={{ color: "var(--text-dim)", fontSize: 12 }}>
            No threats detected yet this session.
          </div>
        )}
        {alerts.slice(0, 8).map((a, i) => {
          const sev = severityClass(a.prediction);
          return (
            <div className={`feed-item ${sev}`} key={i}>
              <span className="feed-time">{fmtTime(a.ts)}</span>
              <div className="feed-detail">
                <span className={`attack ${sev}`}>{a.prediction}</span>
                <span className="ips">
                  {a.src_ip || "—"} → {a.dst_ip || "—"}
                </span>
              </div>
              <span className="feed-action">{Math.round((a.confidence || 0) * 100)}%</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
