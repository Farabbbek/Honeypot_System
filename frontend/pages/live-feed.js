import { useEffect, useState, useRef } from "react";
import Link from "next/link";
import Layout from "../components/Layout";
import ThreatFeed from "../components/ThreatFeed";
import useRealtimeData from "../hooks/useRealtimeData";
import { Activity, ArrowRight, RefreshCw } from "lucide-react";

function SeverityBadge({ severity }) {
  const classes = {
    CRITICAL: "severity-critical",
    HIGH: "severity-high",
    MEDIUM: "severity-medium",
    LOW: "severity-low",
  };
  return <span className={`status-badge ${classes[severity] || "severity-low"}`}>{severity}</span>;
}

const severityDotColor = (sev) => {
  switch (sev) {
    case "CRITICAL": return "#FF4D4D";
    case "HIGH": return "#FFB800";
    case "MEDIUM": return "#F59E0B";
    default: return "#00E5FF";
  }
};

const severityDotShadow = (sev) => {
  switch (sev) {
    case "CRITICAL": return "rgba(255,77,77,0.5)";
    case "HIGH": return "rgba(255,184,0,0.5)";
    case "MEDIUM": return "rgba(245,158,11,0.5)";
    default: return "rgba(0,229,255,0.5)";
  }
};

export default function LiveFeed() {
  const { events, sessions, connected, reconnecting } = useRealtimeData();
  const [alerts, setAlerts] = useState([]);
  const [eventsPerMin, setEventsPerMin] = useState(0);
  const timestampsRef = useRef([]);

  // Keep a fixed alerts array from events for the ThreatFeed display
  useEffect(() => {
    setAlerts(events);
  }, [events]);

  // Track event arrival times for Events/min
  useEffect(() => {
    if (events.length > 0) {
      timestampsRef.current.push(Date.now());
      // Keep last 200 entries
      if (timestampsRef.current.length > 200) {
        timestampsRef.current = timestampsRef.current.slice(-200);
      }
    }
  }, [events.length]);

  // Recalculate Events/min every 10 seconds
  useEffect(() => {
    const interval = setInterval(() => {
      const now = Date.now();
      timestampsRef.current = timestampsRef.current.filter(t => now - t < 60000);
      setEventsPerMin(timestampsRef.current.length);
    }, 10000);
    return () => clearInterval(interval);
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
          <ThreatFeed
            alerts={alerts}
            connected={connected}
            reconnecting={reconnecting}
            maxAlerts={200}
          />
        </div>

        {/* Side: Active Sessions */}
        <div className="space-y-4">
          <div className="glass rounded-2xl p-4 neon-glow">
            <div className="flex items-center gap-2 mb-4">
              <Activity className="w-4 h-4 text-accent-cyan" />
              <h2 className="text-sm font-bold text-white uppercase tracking-wider">Active Sessions</h2>
              {reconnecting && (
                <RefreshCw className="w-3 h-3 text-warning animate-spin ml-auto" />
              )}
            </div>

            {sessions.length === 0 ? (
              <div className="text-center py-6 text-muted text-sm">No active sessions</div>
            ) : (
              <div className="space-y-2">
                {sessions.map((s) => (
                  <Link key={s.session_id} href={`/sessions/${s.session_id}`}>
                    <div
                      className={`flex items-center gap-3 p-2.5 rounded-lg bg-surface/50 border border-border hover:border-accent-cyan/20 transition-all group ${
                        s._new ? "session-fade-in" : ""
                      } ${s._closing ? "session-fade-out" : ""}`}
                      style={{
                        opacity: s._closing ? 0 : undefined,
                        transform: s._closing ? 'translateY(-10px)' : undefined,
                      }}
                    >
                      <div
                        className="w-2 h-2 rounded-full shrink-0"
                        style={{
                          background: severityDotColor(s.severity),
                          boxShadow: `0 0 6px ${severityDotShadow(s.severity)}`,
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

          {/* Feed Stats */}
          <div className="glass rounded-2xl p-4 neon-glow">
            <h2 className="text-sm font-bold text-white uppercase tracking-wider mb-3">Feed Stats</h2>
            <div className="space-y-2 text-xs font-mono">
              <div className="flex justify-between">
                <span className="text-muted">WebSocket</span>
                <span className={`flex items-center gap-1 ${connected ? "text-success" : reconnecting ? "text-warning" : "text-danger"}`}>
                  {reconnecting && <RefreshCw className="w-3 h-3 animate-spin" />}
                  {connected ? "Connected" : reconnecting ? "Reconnecting..." : "Disconnected"}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted">Refresh Rate</span>
                <span className="text-white">Real-time</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted">Buffer Size</span>
                <span className="text-white">{alerts.length} alerts</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted">Events/min</span>
                <span className="text-accent-cyan">{eventsPerMin}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted">Auto-scroll</span>
                <span className="text-accent-cyan">Enabled</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Animations */}
      <style jsx>{`
        @keyframes fadeInSlide {
          from { opacity: 0; transform: translateY(-10px); }
          to { opacity: 1; transform: translateY(0); }
        }
        @keyframes fadeOutSlide {
          from { opacity: 1; transform: translateY(0); }
          to { opacity: 0; transform: translateY(-10px); }
        }
        :global(.session-fade-in) {
          animation: fadeInSlide 0.4s ease-out forwards;
        }
        :global(.session-fade-out) {
          animation: fadeOutSlide 0.35s ease-in forwards;
        }
      `}</style>
    </Layout>
  );
}