import { useEffect, useRef, useState, useCallback } from "react";
import {
  Wifi,
  WifiOff,
  Terminal,
  ShieldAlert,
  AlertTriangle,
  AlertCircle,
  Info,
  Skull,
  Bug,
  Shell,
  ScanLine,
  Database,
  Fingerprint,
  Activity,
  Trash2,
  Pause,
  Play,
} from "lucide-react";

const WS_URL = process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8000/ws/alerts";
const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

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

const ALERT_TYPES = {
  "SSH_BRUTE_FORCE": { label: "SSH BRUTE FORCE", icon: Activity },
  "MALWARE_UPLOAD": { label: "MALWARE UPLOAD", icon: Bug },
  "REVERSE_SHELL": { label: "REVERSE SHELL", icon: Shell },
  "PORT_SCAN": { label: "PORT SCAN", icon: ScanLine },
  "SQL_INJECTION": { label: "SQL INJECTION", icon: Database },
  "SUSPICIOUS_LOGIN": { label: "SUSPICIOUS LOGIN", icon: Fingerprint },
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

// Demo alert generator
function generateDemoAlert(id) {
  const types = Object.keys(ALERT_TYPES);
  const severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
  const ips = ["185.220.101.42", "91.219.236.166", "45.142.212.100", "103.253.145.28", "194.32.107.89", "77.73.133.51"];
  const type = types[Math.floor(Math.random() * types.length)];
  const severity = severities[Math.floor(Math.random() * severities.length)];
  const ip = ips[Math.floor(Math.random() * ips.length)];

  return {
    id: `demo-${id}`,
    timestamp: new Date().toISOString(),
    severity,
    type,
    ip,
    session_id: `sess-${Math.random().toString(36).slice(2, 10)}`,
    message: `${ALERT_TYPES[type].label} detected from ${ip}`,
  };
}

export default function ThreatFeed({ maxAlerts = 50, demoMode = false }) {
  const [alerts, setAlerts] = useState([]);
  const [connected, setConnected] = useState(false);
  const [paused, setPaused] = useState(false);
  const feedRef = useRef(null);
  const shouldScrollRef = useRef(true);
  const demoIntervalRef = useRef(null);

  const addAlert = useCallback((alert) => {
    if (paused) return;
    setAlerts((prev) => {
      const next = [alert, ...prev].slice(0, maxAlerts);
      return next;
    });
  }, [paused, maxAlerts]);

  // WebSocket connection
  useEffect(() => {
    if (demoMode) return;

    const socket = new WebSocket(WS_URL);
    socket.onopen = () => setConnected(true);
    socket.onclose = () => setConnected(false);
    socket.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        addAlert({
          id: data.session_id || `ws-${Date.now()}`,
          timestamp: new Date().toISOString(),
          severity: data.severity || "INFO",
          type: data.type || "SUSPICIOUS_LOGIN",
          ip: data.ioc?.ip || "unknown",
          session_id: data.session_id,
          message: data.message || `Threat detected: ${data.severity}`,
        });
      } catch {}
    };

    return () => socket.close();
  }, [addAlert, demoMode]);

  // Demo mode — auto-generate alerts
  useEffect(() => {
    if (!demoMode) return;
    let counter = 0;
    demoIntervalRef.current = setInterval(() => {
      counter++;
      addAlert(generateDemoAlert(counter));
    }, 2000 + Math.random() * 3000);
    return () => clearInterval(demoIntervalRef.current);
  }, [addAlert, demoMode]);

  // Auto-scroll to top (newest)
  useEffect(() => {
    if (feedRef.current && shouldScrollRef.current && !paused) {
      feedRef.current.scrollTop = 0;
    }
  }, [alerts, paused]);

  const handleScroll = () => {
    if (!feedRef.current) return;
    const { scrollTop } = feedRef.current;
    shouldScrollRef.current = scrollTop < 10;
  };

  const severityCounts = alerts.reduce((acc, a) => {
    acc[a.severity] = (acc[a.severity] || 0) + 1;
    return acc;
  }, {});

  const clearFeed = () => setAlerts([]);

  return (
    <div className="glass rounded-2xl overflow-hidden neon-glow flex flex-col h-full min-h-[500px]">
      {/* Terminal header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-border bg-surface/30">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-accent-cyan/10 border border-accent-cyan/20 flex items-center justify-center">
            <Terminal className="w-4 h-4 text-accent-cyan" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-white tracking-wider">THREAT FEED</h2>
            <div className="flex items-center gap-2 mt-0.5">
              <div className={`w-1.5 h-1.5 rounded-full ${connected || demoMode ? "bg-success animate-pulse" : "bg-danger"}`} />
              <span className="text-[10px] text-muted font-mono uppercase">
                {connected ? "Live Stream" : demoMode ? "Demo Mode" : "Disconnected"}
              </span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {/* Severity counters */}
          {Object.entries(SEVERITY_CONFIG).map(([sev, cfg]) => (
            <div
              key={sev}
              className="hidden sm:flex items-center gap-1.5 px-2 py-1 rounded-md text-[10px] font-mono font-bold"
              style={{
                background: cfg.bg,
                color: cfg.color,
                border: `1px solid ${cfg.border}`,
              }}
            >
              <cfg.icon className="w-3 h-3" />
              {severityCounts[sev] || 0}
            </div>
          ))}

          <button
            onClick={() => setPaused(!paused)}
            className="p-1.5 rounded-lg hover:bg-white/5 text-muted transition-colors"
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

          {connected || demoMode ? (
            <Wifi className="w-4 h-4 text-success" />
          ) : (
            <WifiOff className="w-4 h-4 text-danger" />
          )}
        </div>
      </div>

      {/* Feed */}
      <div
        ref={feedRef}
        onScroll={handleScroll}
        className="flex-1 overflow-y-auto font-mono text-xs p-3 space-y-1"
        style={{ scrollbarWidth: "thin" }}
      >
        {alerts.length === 0 && (
          <div className="flex flex-col items-center justify-center h-full text-muted">
            <ScanLine className="w-8 h-8 mb-2 opacity-30" />
            <p className="text-sm">Waiting for threats...</p>
            <p className="text-[10px] mt-1 opacity-50">Alerts will appear here in real-time</p>
          </div>
        )}

        {alerts.map((alert, index) => {
          const sev = SEVERITY_CONFIG[alert.severity] || SEVERITY_CONFIG.LOW;
          const typeInfo = ALERT_TYPES[alert.type] || { label: alert.type, icon: AlertCircle };
          const TypeIcon = typeInfo.icon;

          return (
            <div
              key={alert.id}
              className="group flex items-start gap-3 p-2.5 rounded-lg transition-all duration-300 hover:bg-white/[0.03] animate-in slide-in-from-right-4 fade-in"
              style={{
                animationDelay: `${index === 0 ? 0 : 0}ms`,
                animationDuration: "300ms",
              }}
            >
              {/* Timestamp */}
              <span className="text-[10px] text-muted/60 shrink-0 pt-0.5 w-16">
                {formatTime(alert.timestamp)}
              </span>

              {/* Severity indicator */}
              <div
                className="w-1 shrink-0 rounded-full self-stretch mt-0.5"
                style={{ background: sev.color, boxShadow: sev.glow }}
              />

              {/* Icon */}
              <div
                className="w-5 h-5 rounded flex items-center justify-center shrink-0 mt-px"
                style={{ background: sev.bg, border: `1px solid ${sev.border}` }}
              >
                <TypeIcon className="w-3 h-3" style={{ color: sev.color }} />
              </div>

              {/* Content */}
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <span
                    className="text-[10px] font-bold px-1.5 py-0.5 rounded border"
                    style={{
                      color: sev.color,
                      background: sev.bg,
                      borderColor: sev.border,
                    }}
                  >
                    {alert.severity}
                  </span>
                  <span className="text-[10px] font-bold text-accent-cyan/80 tracking-wider">
                    {typeInfo.label}
                  </span>
                  <span className="text-[10px] text-muted/40">|</span>
                  <span className="text-[10px] text-white/50 font-mono">{alert.ip}</span>
                </div>
                <p className="text-xs text-white/70 mt-1 truncate group-hover:text-white/90 transition-colors">
                  {alert.message}
                </p>
                {alert.session_id && (
                  <p className="text-[10px] text-muted/40 mt-0.5 font-mono">
                    session: {alert.session_id}
                  </p>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Footer status bar */}
      <div className="flex items-center justify-between px-4 py-2 border-t border-border bg-surface/20 text-[10px] text-muted font-mono">
        <span>Total: {alerts.length} alerts</span>
        <span className="flex items-center gap-1">
          <span className="w-1.5 h-1.5 rounded-full bg-accent-cyan animate-pulse" />
          {paused ? "PAUSED" : "LIVE"}
        </span>
      </div>
    </div>
  );
}