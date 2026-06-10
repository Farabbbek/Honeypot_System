import { useEffect, useRef, useState } from "react";
import {
  Wifi,
  WifiOff,
  Terminal,
  ShieldAlert,
  AlertTriangle,
  Info,
  Skull,
  ScanLine,
  Trash2,
  Pause,
  Play,
  ArrowDown,
  RefreshCw
} from "lucide-react";

const SEVERITY_CONFIG = {
  CRITICAL: {
    color: "#FF4D4D",
    bg: "rgba(255, 77, 77, 0.08)",
    border: "rgba(255, 77, 77, 0.2)",
    glow: "0 0 12px rgba(255, 77, 77, 0.15)",
    icon: Skull,
  },
  HIGH: {
    color: "#FFB800",
    bg: "rgba(255, 184, 0, 0.08)",
    border: "rgba(255, 184, 0, 0.2)",
    glow: "0 0 12px rgba(255, 184, 0, 0.15)",
    icon: ShieldAlert,
  },
  MEDIUM: {
    color: "#F59E0B",
    bg: "rgba(245, 158, 11, 0.08)",
    border: "rgba(245, 158, 11, 0.2)",
    glow: "0 0 12px rgba(245, 158, 11, 0.15)",
    icon: AlertTriangle,
  },
  LOW: {
    color: "#00E5FF",
    bg: "rgba(0, 229, 255, 0.08)",
    border: "rgba(0, 229, 255, 0.2)",
    glow: "0 0 12px rgba(0, 229, 255, 0.15)",
    icon: Info,
  },
};

const getEventColor = (type) => {
  if (!type) return "transparent";
  if (type.includes("login.failed")) return "rgba(255, 77, 77, 0.05)";
  if (type.includes("command.input")) return "rgba(0, 229, 255, 0.05)";
  if (type.includes("session.connect")) return "rgba(0, 255, 128, 0.05)";
  if (type.includes("file_download")) return "rgba(180, 0, 255, 0.05)";
  if (type.includes("session.closed")) return "rgba(255, 184, 0, 0.05)";
  return "transparent";
};

const getEventLabel = (type) => {
  if (!type) return "UNKNOWN";
  return type.replace("cowrie.", "").replace(/[._]/g, " ").toUpperCase();
};

function formatTime(date) {
  const d = new Date(date);
  return d.toLocaleTimeString("en-US", {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export default function ThreatFeed({ alerts = [], connected = false, reconnecting = false, maxAlerts = 200 }) {
  const [paused, setPaused] = useState(false);
  const [autoScrollPaused, setAutoScrollPaused] = useState(false);
  const [activeFilter, setActiveFilter] = useState("ALL");
  const [internalAlerts, setInternalAlerts] = useState([]);
  const feedRef = useRef(null);

  // Keep internal state in sync with prop alerts, respecting paused
  useEffect(() => {
    if (!paused) {
      setInternalAlerts(alerts.slice(-maxAlerts));
    }
  }, [alerts, paused, maxAlerts]);

  const severityCounts = internalAlerts.reduce((acc, a) => {
    acc[a.severity] = (acc[a.severity] || 0) + 1;
    return acc;
  }, {});

  const filteredAlerts = internalAlerts.filter(a => activeFilter === "ALL" || a.severity === activeFilter);
  const showEmptyState = internalAlerts.length === 0;

  // Auto-scroll logic
  useEffect(() => {
    if (!autoScrollPaused && feedRef.current) {
      feedRef.current.scrollTop = feedRef.current.scrollHeight;
    }
  }, [internalAlerts.length, autoScrollPaused]);

  const handleScroll = () => {
    if (!feedRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = feedRef.current;
    const isAtBottom = scrollHeight - scrollTop - clientHeight < 50;
    setAutoScrollPaused(!isAtBottom);
  };

  const jumpToLatest = () => {
    if (feedRef.current) {
      feedRef.current.scrollTop = feedRef.current.scrollHeight;
      setAutoScrollPaused(false);
    }
  };

  const clearFeed = () => {
    setInternalAlerts([]);
  };

  return (
    <div className="glass rounded-2xl overflow-hidden neon-glow flex flex-col">
      <div className="flex items-center justify-between px-4 py-3 border-b border-border bg-surface/30">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-accent-cyan/10 border border-accent-cyan/20 flex items-center justify-center">
            <Terminal className="w-4 h-4 text-accent-cyan" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-white tracking-wider">THREAT FEED</h2>
            <div className="flex items-center gap-2 mt-0.5">
              <div className={`w-1.5 h-1.5 rounded-full ${
                reconnecting ? "bg-warning" : connected ? "bg-success animate-pulse" : "bg-danger"
              }`} />
              <span className="text-[10px] text-muted font-mono uppercase">
                {reconnecting ? "Reconnecting..." : connected ? "Live Stream" : "Disconnected"}
              </span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2 flex-wrap justify-end">
          <button
            onClick={() => setActiveFilter("ALL")}
            className={`px-2 py-1 rounded-md text-[10px] font-mono font-bold transition-all ${
              activeFilter === "ALL" ? "bg-white/20 text-white shadow-md shadow-white/10" : "bg-white/5 text-muted hover:bg-white/10"
            }`}
          >
            ALL
          </button>
          
          {Object.entries(SEVERITY_CONFIG).map(([sev, cfg]) => (
            <button
              key={sev}
              onClick={() => setActiveFilter(sev)}
              className={`hidden sm:flex items-center gap-1.5 px-2 py-1 rounded-md text-[10px] font-mono font-bold transition-all ${
                activeFilter === sev ? "opacity-100 scale-105" : "opacity-60 hover:opacity-80"
              }`}
              style={{
                background: cfg.bg,
                color: cfg.color,
                border: `1px solid ${cfg.border}`,
                boxShadow: activeFilter === sev ? cfg.glow : "none",
              }}
            >
              <cfg.icon className="w-3 h-3" />
              {severityCounts[sev] || 0}
            </button>
          ))}

          <button
            onClick={() => setPaused(!paused)}
            className="p-1.5 rounded-lg hover:bg-white/5 text-muted transition-colors ml-2"
            title={paused ? "Resume" : "Pause"}
          >
            {paused ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}
          </button>

          <button
            onClick={clearFeed}
            className="p-1.5 rounded-lg hover:bg-white/5 text-muted transition-colors"
            title="Clear feed"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>

          <div className="ml-1 pl-2 border-l border-border/50">
            {reconnecting ? (
              <RefreshCw className="w-4 h-4 text-warning animate-spin" />
            ) : connected ? (
              <Wifi className="w-4 h-4 text-success" />
            ) : (
              <WifiOff className="w-4 h-4 text-danger" />
            )}
          </div>
        </div>
      </div>

      <div style={{ position: 'relative' }} className="flex-1 bg-[#0A101C]">
        <div
          ref={feedRef}
          onScroll={handleScroll}
          className="threat-feed-scroll overflow-y-scroll overflow-x-hidden scroll-smooth font-mono text-xs p-3 space-y-1"
          style={{ height: 'calc(100vh - 280px)' }}
        >
          {showEmptyState && (
            <div className="flex flex-col items-center justify-center h-full text-muted">
              <ScanLine className="w-8 h-8 mb-2 opacity-30" />
              <p className="text-sm">Waiting for threats...</p>
              <p className="text-[10px] mt-1 opacity-50">Alerts will appear here in real-time</p>
            </div>
          )}

          {filteredAlerts.map((alert) => {
            const sev = SEVERITY_CONFIG[alert.severity] || SEVERITY_CONFIG.LOW;
            const bgHint = getEventColor(alert.type);

            return (
              <div
                key={alert.id}
                className="group flex items-center gap-3 py-1.5 px-2 rounded hover:bg-white/[0.08] transition-colors"
                style={{ backgroundColor: bgHint }}
              >
                {/* [HH:MM:SS] */}
                <span className="text-[10px] text-muted/60 shrink-0 w-[60px]">
                  [{formatTime(alert.timestamp)}]
                </span>

                {/* [IP] */}
                <span className="text-[10px] text-white/50 w-[100px] truncate shrink-0">
                  [{alert.ip}]
                </span>

                {/* [event_type badge] */}
                <div
                  className="px-1.5 py-0.5 rounded border text-[9px] font-bold whitespace-nowrap shrink-0"
                  style={{
                    color: sev.color,
                    background: sev.bg,
                    borderColor: sev.border,
                  }}
                >
                  {getEventLabel(alert.type)}
                </div>

                {/* [command if present] */}
                <div className="min-w-0 flex-1 text-[11px] text-white/80 group-hover:text-white transition-colors">
                  {alert.command && (
                    <span className="text-accent-cyan/80 break-words">{'>'} {alert.command}</span>
                  )}
                </div>

                {/* [MITRE ID] */}
                {alert.mitreId && (
                  <div className="shrink-0 px-1.5 rounded bg-white/5 border border-white/10 text-[9px] font-bold text-muted/60">
                    {alert.mitreId}
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* Jump to latest button */}
        {autoScrollPaused && filteredAlerts.length > 0 && (
          <button
            onClick={jumpToLatest}
            className="absolute bottom-4 right-6 flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-black/80 border border-accent-cyan/50 text-accent-cyan text-xs cursor-pointer z-10 shadow-lg shadow-black hover:bg-black hover:border-accent-cyan transition-all animate-in fade-in"
          >
            <ArrowDown className="w-3.5 h-3.5" />
            Latest
          </button>
        )}
      </div>

      <div className="flex items-center justify-between px-4 py-2 border-t border-border bg-surface/20 text-[10px] text-muted font-mono">
        <span>Total: {internalAlerts.length} alerts</span>
        <span className="flex items-center gap-1">
          <span className={`w-1.5 h-1.5 rounded-full ${paused ? "bg-warning" : "bg-accent-cyan animate-pulse"}`} />
          {paused ? "PAUSED" : "LIVE"}
        </span>
      </div>
    </div>
  );
}