import { useEffect, useRef, useState } from "react";
import { api } from "./api";

import Login from "./Login.jsx";
import Setup from "./Setup.jsx";
import TopBar from "./components/TopBar.jsx";
import TrafficMonitor from "./components/TrafficMonitor.jsx";
import ThreatFeed from "./components/ThreatFeed.jsx";
import AlertOverview from "./components/AlertOverview.jsx";
import WorkflowStrip from "./components/WorkflowStrip.jsx";
import ForensicArchive from "./components/ForensicArchive.jsx";
import UploadPanel from "./components/UploadPanel.jsx";

import "./styles.css";

const POLL_MS = 4000;

export default function App() {
  // "checking" | "needsSetup" | "loggedOut" | "loggedIn" -- avoids flashing
  // the dashboard (or the wrong screen) before we know the real state.
  const [authState, setAuthState] = useState("checking");

  const emptyBucket = { total_flows: 0, total_flagged: 0, distribution_totals: {}, history: [], recent_alerts: [] };
  const [stats, setStats] = useState({
    classes: [], live: emptyBucket, csv: emptyBucket, live_active: false,
  });
  const [evidence, setEvidence] = useState([]);
  const [apiOk, setApiOk] = useState(true);
  const [toggling, setToggling] = useState(false);
  const intervalRef = useRef(null);

  useEffect(() => {
    api.needsSetup()
      .then((res) => {
        if (res.needs_setup) {
          setAuthState("needsSetup");
          return;
        }
        return api.authStatus().then((r) => setAuthState(r.authenticated ? "loggedIn" : "loggedOut"));
      })
      .catch(() => setAuthState("loggedOut"));
  }, []);

  async function refresh() {
    try {
      const [statsData, evidenceData] = await Promise.all([api.stats(), api.evidence()]);
      setStats(statsData);
      setEvidence(evidenceData.entries || []);
      setApiOk(true);
    } catch (e) {
      // A session that expired mid-use surfaces here as a 401 -- bounce
      // back to the login screen instead of just showing a dead dashboard.
      if (e.status === 401) {
        setAuthState("loggedOut");
        return;
      }
      console.error("Poll error", e);
      setApiOk(false);
    }
  }

  useEffect(() => {
    if (authState !== "loggedIn") return;
    refresh();
    intervalRef.current = setInterval(refresh, POLL_MS);
    return () => clearInterval(intervalRef.current);
  }, [authState]);

  async function handleSetup(password) {
    await api.setup(password);
    setAuthState("loggedIn");
  }

  async function handleLogin(password) {
    await api.login(password);
    setAuthState("loggedIn");
  }

  async function handleLogout() {
    try {
      await api.logout();
    } finally {
      setAuthState("loggedOut");
    }
  }

  async function handleToggleLive() {
    if (toggling) return;
    setToggling(true);
    try {
      if (stats.live_active) await api.liveStop();
      else await api.liveStart();
      await refresh();
    } catch (e) {
      console.error("Toggle error", e);
    } finally {
      setToggling(false);
    }
  }

  if (authState === "checking") return null; // avoid a login-screen flash on refresh
  if (authState === "needsSetup") return <Setup onSetup={handleSetup} />;
  if (authState === "loggedOut") return <Login onLogin={handleLogin} />;

  return (
    <div className="app-wrapper">
      <TopBar
        liveActive={stats.live_active}
        onToggleLive={handleToggleLive}
        toggling={toggling}
        apiOk={apiOk}
        onLogout={handleLogout}
      />

      <main className="main-content">
        <div className="dashboard-grid">
          <TrafficMonitor
            history={stats.live.history}
            totalFlows={stats.live.total_flows}
            totalFlagged={stats.live.total_flagged}
            liveActive={stats.live_active}
          />
          <ThreatFeed alerts={stats.live.recent_alerts} />
          <AlertOverview
            classes={stats.classes}
            distribution={stats.live.distribution_totals}
            totalFlows={stats.live.total_flows}
          />

          <div className="workflow-row">
            <WorkflowStrip />
            <UploadPanel onAnalyzed={refresh} />
          </div>
        </div>

        <div className="archive-section">
          <div className="archive-header-card">
            <h2>Forensic Evidence Archive</h2>
            <div className="count">{evidence.length} Entries Archived</div>
          </div>
          <ForensicArchive entries={evidence} />
        </div>
      </main>
    </div>
  );
}