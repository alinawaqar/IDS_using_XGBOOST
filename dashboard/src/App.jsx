import { useEffect, useRef, useState } from "react";
// Assuming api is configured in your project
import { api } from "./api"; 

// Placeholders for your existing components - ensure these exist in your project
import TopBar from "./components/TopBar.jsx";
import TrafficMonitor from "./components/TrafficMonitor.jsx";
import ThreatFeed from "./components/ThreatFeed.jsx";
import AlertOverview from "./components/AlertOverview.jsx";
import WorkflowStrip from "./components/WorkflowStrip.jsx";
import ForensicArchive from "./components/ForensicArchive.jsx";
import UploadPanel from "./components/UploadPanel.jsx";

// Import the CSS file (see below)
import "./styles.css"; 

const POLL_MS = 4000;

export default function App() {
  const emptyBucket = { total_flows: 0, total_flagged: 0, distribution_totals: {}, history: [], recent_alerts: [] };
  const [stats, setStats] = useState({
    classes: [], live: emptyBucket, csv: emptyBucket, live_active: false,
  });
  const [evidence, setEvidence] = useState([]);
  const [apiOk, setApiOk] = useState(true);
  const [toggling, setToggling] = useState(false);
  const intervalRef = useRef(null);

  async function refresh() {
    try {
      // NOTE: Assuming your api utils return data in this structure
      const [statsData, evidenceData] = await Promise.all([api.stats(), api.evidence()]);
      setStats(statsData);
      setEvidence(evidenceData.entries || []); // Ensure array
      setApiOk(true);
    } catch (e) {
      console.error("Poll error", e);
      setApiOk(false);
    }
  }

  useEffect(() => {
    refresh();
    intervalRef.current = setInterval(refresh, POLL_MS);
    return () => clearInterval(intervalRef.current);
  }, []);

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

  return (
    <div className="app-wrapper">
      <TopBar
        liveActive={stats.live_active}
        onToggleLive={handleToggleLive}
        toggling={toggling}
        apiOk={apiOk}
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

        {/* Masonry section requires a specific wrapper structure for aesthetic flow */}
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