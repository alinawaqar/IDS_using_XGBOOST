const STEPS = [
  { label: "live_ids.py", sub: "orchestrator", active: true },
  { label: "dumpcap", sub: "packet capture" },
  { label: "editcap", sub: "normalize" },
  { label: "CICFlowMeter", sub: "77 features" },
  { label: "main.py", sub: "XGBoost inference", active: true },
  { label: "Classification", sub: "≥ 0.75 conf." },
  { label: "Forensic Archive", sub: "if threat", danger: true },
];

export default function WorkflowStrip() {
  return (
    <div className="card flow">
      <h2>SYSTEM WORKFLOW</h2>
      <div className="flow-track">
        {STEPS.map((s, i) => (
          <div key={s.label} style={{ display: "flex", alignItems: "center" }}>
            <div
              className={`flow-node ${s.active ? "active" : ""}`}
              style={s.danger ? { borderColor: "var(--red)", color: "var(--red)" } : {}}
            >
              {s.label}
              <span className="sub">{s.sub}</span>
            </div>
            {i < STEPS.length - 1 && <span className="flow-arrow">→</span>}
          </div>
        ))}
      </div>
    </div>
  );
}
