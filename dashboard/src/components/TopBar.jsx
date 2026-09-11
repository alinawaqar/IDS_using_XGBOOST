export default function TopBar({ liveActive, onToggleLive, toggling, apiOk }) {
  return (
    <div className="topbar">
      <div className="brand">
        <div className={`dot ${apiOk ? "" : "dot-off"}`} />
        <h1>
          LIVE IDS <span>AI Network Defender</span>
        </h1>
      </div>
      <div className="topbar-right">
        <div>
          API <b style={{ color: apiOk ? "var(--green)" : "var(--red)" }}>
            {apiOk ? "CONNECTED" : "UNREACHABLE"}
          </b>
        </div>
        <div>
          CAPTURE{" "}
          <b style={{ color: liveActive ? "var(--green)" : "var(--text-dim)" }}>
            {liveActive ? "RUNNING" : "STOPPED"}
          </b>
        </div>
        <button className="live-toggle" onClick={onToggleLive} disabled={toggling}>
          {toggling ? "..." : liveActive ? "STOP CAPTURE" : "START CAPTURE"}
        </button>
      </div>
    </div>
  );
}
