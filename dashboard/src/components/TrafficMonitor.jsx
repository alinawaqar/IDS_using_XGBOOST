import { BarChart, Bar, ResponsiveContainer, Cell, YAxis, Tooltip } from "recharts";

// Custom light-theme hover tooltip
function CustomTooltip({ active, payload }) {
  if (active && payload && payload.length) {
    const data = payload[0].payload;
    return (
      <div
        style={{
          background: "var(--panel)",
          border: "1px solid var(--line)",
          borderRadius: "6px",
          padding: "6px 10px",
          boxShadow: "var(--shadow-card)",
          fontSize: "11px",
          fontFamily: "var(--mono)",
          color: "var(--text)",
        }}
      >
        <div>
          Total Flows: <b>{data.flows}</b>
        </div>
        {data.flagged > 0 && (
          <div style={{ color: "var(--red)", marginTop: "2px" }}>
            Flagged: <b>{data.flagged}</b>
          </div>
        )}
      </div>
    );
  }
  return null;
}

export default function TrafficMonitor({ history, totalFlows, totalFlagged, liveActive }) {
  const data = history.length
    ? history.map((h) => ({ flows: h.flows, flagged: h.flagged }))
    : [{ flows: 0, flagged: 0 }];

  return (
    <div className="card">
      <h2>
        <span>LIVE TRAFFIC MONITOR</span>
        <span
          className="tag"
          style={
            liveActive
              ? {}
              : {
                  background: "var(--panel-alt)",
                  color: "var(--text-dim)",
                  border: "1px solid var(--line)",
                }
          }
        >
          {liveActive ? "RUNNING" : "IDLE"}
        </span>
      </h2>

      <div style={{ height: 110, marginBottom: 12 }}>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} barGap={4}>
            <YAxis hide domain={[0, "dataMax"]} />
            <Tooltip content={<CustomTooltip />} cursor={{ fill: "rgba(0,0,0,0.03)" }} />
            <Bar dataKey="flows" radius={[3, 3, 0, 0]}>
              {data.map((d, i) => (
                <Cell
                  key={i}
                  fill={d.flagged > 0 ? "var(--red)" : "var(--primary)"}
                />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      <div className="stat-row">
        <span>
          FLOWS <b>{totalFlows.toLocaleString()}</b>
        </span>
        <span>
          FLAGGED <b style={{ color: "var(--red)" }}>{totalFlagged.toLocaleString()}</b>
        </span>
      </div>

      <div className={`status-line ${liveActive ? "active" : ""}`}>
        <div className="led" />
        <span>
          {liveActive
            ? "capture agent active · dumpcap → editcap"
            : "capture agent stopped"}
        </span>
      </div>
    </div>
  );
}