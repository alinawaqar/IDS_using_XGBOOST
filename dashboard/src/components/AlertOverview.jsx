import { PieChart, Pie, Cell, ResponsiveContainer } from "recharts";

const PALETTE = [
  "var(--green)", "var(--red)", "var(--orange)", "var(--amber)",
  "var(--blue)", "#9b7ede", "#5fd0d6", "#e07bb0",
];

export default function AlertOverview({ classes, distribution, totalFlows }) {
  const data = classes
    .map((c) => ({ name: c, value: distribution[c] || 0 }))
    .filter((d) => d.value > 0);

  const hasData = data.length > 0;

  return (
    <div className="card">
      <h2>
        ALERT OVERVIEW{" "}
        <span className="tag" style={{ background: "rgba(91,155,213,0.12)", color: "var(--blue)" }}>
          {totalFlows.toLocaleString()} SCANNED
        </span>
      </h2>
      <div className="donut-wrap">
        <div style={{ width: 90, height: 90, flexShrink: 0 }}>
          {hasData ? (
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={data} dataKey="value" innerRadius={28} outerRadius={40} strokeWidth={0}>
                  {data.map((_, i) => (
                    <Cell key={i} fill={PALETTE[i % PALETTE.length]} />
                  ))}
                </Pie>
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div style={{
              width: 90, height: 90, borderRadius: "50%",
              border: "4px solid var(--line)",
            }} />
          )}
        </div>
        <div className="legend">
          {hasData ? (
            data.map((d, i) => (
              <div className="row" key={d.name}>
                <div className="sw" style={{ background: PALETTE[i % PALETTE.length] }} />
                {d.name}
                <span className="pct">{((d.value / totalFlows) * 100).toFixed(1)}%</span>
              </div>
            ))
          ) : (
            <span style={{ color: "var(--text-dim)", fontSize: 12 }}>Waiting for flow data…</span>
          )}
        </div>
      </div>
    </div>
  );
}
