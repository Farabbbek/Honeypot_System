import { useEffect, useState } from "react";
import Link from "next/link";
import Layout from "../components/Layout";
import ThreatFeed from "../components/ThreatFeed";
import { Activity, ArrowRight } from "lucide-react";

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

function SeverityBadge({ severity }) {
  const classes = {
    CRITICAL: "severity-critical",
    HIGH: "severity-high",
    MEDIUM: "severity-medium",
    LOW: "severity-low",
  };
  return <span className={`status-badge ${classes[severity] || "severity-low"}`}>{severity}</span>;
}

export default function LiveFeed() {
  const [sessions, setSessions] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(`${API}/api/sessions?limit=10`)
      .then((r) => r.json())
      .then((data) => {
        setSessions(data);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  return (
    <Layout>
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold text-white mb-1">Live Feed</h1>
          <p className="text-sm text-muted">Real-time attack monitoring and threat intelligence</p>
        </div>
        <Link href="/sessions">
          <button className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-accent-cyan/10 border border-accent-cyan/20 text-accent-cyan text-sm font-semibold hover:bg-accent-cyan/15 transition-all hover:scale-[1.02]">
            All Sessions
            <ArrowRight className="w-4 h-4" />
          </button>
        </Link>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Threat Feed */}
        <div className="xl:col-span-2">
          <ThreatFeed demoMode={sessions.length === 0} maxAlerts={40} />
        </div>

        {/* Side: Active Sessions */}
        <div className="space-y-4">
          <div className="glass rounded-2xl p-4 neon-glow">
            <div className="flex items-center gap-2 mb-4">
              <Activity className="w-4 h-4 text-accent-cyan" />
              <h2 className="text-sm font-bold text-white uppercase tracking-wider">Active Sessions</h2>
            </div>

            {loading ? (
              <div className="text-center py-6 text-muted text-sm">Loading...</div>
            ) : sessions.length === 0 ? (
              <div className="text-center py-6 text-muted text-sm">No active sessions</div>
            ) : (
              <div className="space-y-2">
                {sessions.map((s) => (
                  <Link key={s.session_id} href={`/sessions/${s.session_id}`}>
                    <div className="flex items-center gap-3 p-2.5 rounded-lg bg-surface/50 border border-border hover:border-accent-cyan/20 transition-all group">
                      <div
                        className="w-2 h-2 rounded-full shrink-0"
                        style={{
                          background:
                            s.severity === "CRITICAL" ? "#FF4D4D" :
                            s.severity === "HIGH" ? "#FFB800" : "#00E5FF",
                          boxShadow: `0 0 6px ${
                            s.severity === "CRITICAL" ? "rgba(255,77,77,0.5)" :
                            s.severity === "HIGH" ? "rgba(255,184,0,0.5)" : "rgba(0,229,255,0.5)"
                          }`,
                        }}
                      />
                      <div className="min-w-0 flex-1">
                        <div className="font-mono text-xs text-white group-hover:text-accent-cyan transition-colors truncate">
                          {s.attacker_ip}
                        </div>
                        <div className="text-[10px] text-muted mt-0.5">
                          {s.current_tactic || "UNKNOWN"} · Risk {s.risk_score}
                        </div>
                      </div>
                      <SeverityBadge severity={s.severity} />
                    </div>
                  </Link>
                ))}
              </div>
            )}
          </div>

          {/* Quick stats */}
          <div className="glass rounded-2xl p-4 neon-glow">
            <h2 className="text-sm font-bold text-white uppercase tracking-wider mb-3">Feed Stats</h2>
            <div className="space-y-2 text-xs font-mono">
              <div className="flex justify-between">
                <span className="text-muted">WebSocket</span>
                <span className="text-success">Connected</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted">Refresh Rate</span>
                <span className="text-white">Real-time</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted">Buffer Size</span>
                <span className="text-white">50 alerts</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted">Auto-scroll</span>
                <span className="text-accent-cyan">Enabled</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </Layout>
  );
}