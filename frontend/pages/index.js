import { useEffect, useState, useRef, useMemo, useCallback } from "react";
import Link from "next/link";
import Layout from "../components/Layout";
import KpiCard from "../components/KpiCard";
import TimelineChart from "../components/TimelineChart";
import HoneypotNodeCard from "../components/HoneypotNodeCard";
import useRealtimeData from "../hooks/useRealtimeData";
import {
  Activity,
  Globe,
  ShieldAlert,
  Server,
  ArrowRight,
} from "lucide-react";

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

function AnimatedNumber({ value, onFlash }) {
  const [flash, setFlash] = useState(false);
  const prevRef = useRef(value);

  useEffect(() => {
    if (prevRef.current !== value) {
      setFlash(true);
      if (onFlash) onFlash();
      const t = setTimeout(() => setFlash(false), 500);
      prevRef.current = value;
      return () => clearTimeout(t);
    }
  }, [value, onFlash]);

  return (
    <span className={`transition-all duration-300 ${flash ? "text-accent-cyan" : ""}`}>
      {value}
    </span>
  );
}

function KpiCardWithFlash({ title, value, subtitle, color, icon, children }) {
  const [flashBorder, setFlashBorder] = useState(false);

  const handleFlash = useCallback(() => {
    setFlashBorder(true);
    setTimeout(() => setFlashBorder(false), 500);
  }, []);

  return (
    <div
      className={`relative group overflow-hidden rounded-2xl
        bg-surface/40 backdrop-blur-xl border transition-all duration-500 ease-out
        hover:scale-[1.02] hover:-translate-y-0.5 cursor-default
        ${flashBorder ? "border-accent-cyan/60 shadow-[0_0_20px_rgba(0,229,255,0.2)]" : "border-border"}
      `}
    >
      <KpiCard title={title} value={<AnimatedNumber value={value} onFlash={handleFlash} />} subtitle={subtitle} color={color} icon={icon}>
        {children}
      </KpiCard>
    </div>
  );
}

export default function Overview() {
  const { sessions: wsSessions, events, connected } = useRealtimeData();
  const [uptime, setUptime] = useState(0);
  const [stats, setStats] = useState(null);
  const [restSessions, setRestSessions] = useState([]);

  // Uptime counter
  useEffect(() => {
    const t = setInterval(() => setUptime(p => p + 1), 1000);
    return () => clearInterval(t);
  }, []);

  // Fetch /api/stats and /api/sessions on mount
  const fetchStats = useCallback(() => {
    fetch(`${API}/api/stats`)
      .then(r => r.json())
      .then(data => {
        console.log("stats payload", data);
        setStats(data);
      })
      .catch(() => {});
  }, []);

  const fetchSessions = useCallback(() => {
    fetch(`${API}/api/sessions?limit=50`)
      .then(r => r.json())
      .then(data => {
        console.log("sessions payload", data);
        if (Array.isArray(data)) setRestSessions(data);
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    fetchStats();
    fetchSessions();
  }, [fetchStats, fetchSessions]);

  // Debounced re-fetch /api/stats on any WebSocket event (1s debounce)
  const debounceRef = useRef(null);
  useEffect(() => {
    if (events.length > 0) {
      clearTimeout(debounceRef.current);
      debounceRef.current = setTimeout(() => {
        fetchStats();
        fetchSessions();
      }, 1000);
      return () => clearTimeout(debounceRef.current);
    }
  }, [events, fetchStats, fetchSessions]);

  // Merge WS sessions (real-time) with REST sessions (history)
  const allSessions = useMemo(() => {
    if (restSessions.length > 0) return restSessions;
    return wsSessions;
  }, [restSessions, wsSessions]);

  // KPI values: prefer /api/stats, fallback to live sessions
  const totalAttacks = stats?.total_attacks ?? allSessions.length;
  const uniqueIPs = useMemo(() => {
    if (stats?.top_ips) return stats.top_ips.length;
    return new Set(allSessions.map(s => s.attacker_ip)).size;
  }, [stats, allSessions]);
  const highSeverity = useMemo(
    () => allSessions.filter(s => s.severity === "CRITICAL" || s.severity === "HIGH").length,
    [allSessions]
  );
  const activeAttackers = allSessions.filter(s => !s._closing).length;

  // Top attackers from stats.top_ips, fallback to sessions
  const topAttackers = useMemo(() => {
    if (stats?.top_ips && stats.top_ips.length > 0) {
      return stats.top_ips.slice(0, 5);
    }
    const counts = {};
    allSessions.forEach(s => {
      if (s.attacker_ip) counts[s.attacker_ip] = (counts[s.attacker_ip] || 0) + 1;
    });
    return Object.entries(counts)
      .map(([ip, count]) => ({ ip, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);
  }, [stats, allSessions]);

  // Top tactics from stats.top_tactics, fallback to sessions
  const topTactics = useMemo(() => {
    if (stats?.top_tactics && stats.top_tactics.length > 0) {
      return stats.top_tactics.slice(0, 5);
    }
    const counts = {};
    allSessions.forEach(s => {
      const t = s.current_tactic || "UNKNOWN";
      counts[t] = (counts[t] || 0) + 1;
    });
    return Object.entries(counts)
      .map(([tactic, count]) => ({ tactic, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);
  }, [stats, allSessions]);

  const maxTacticCount = topTactics[0]?.count || 1;

  // Keep max 10 rows in the table
  const tableSessions = useMemo(() => allSessions.slice(0, 10), [allSessions]);

  return (
    <Layout>
      {/* Page header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold text-white mb-1">Overview</h1>
          <p className="text-sm text-muted">Real-time threat monitoring and session analytics</p>
        </div>
        <Link href="/sessions">
          <button className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-accent-cyan/10 border border-accent-cyan/20 text-accent-cyan text-sm font-semibold hover:bg-accent-cyan/15 transition-all hover:scale-[1.02]">
            View All Sessions
            <ArrowRight className="w-4 h-4" />
          </button>
        </Link>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        <KpiCardWithFlash
          title="Total Attacks"
          value={totalAttacks}
          subtitle="All recorded sessions"
          color="danger"
          icon={Activity}
        />
        <KpiCardWithFlash
          title="Unique IPs"
          value={uniqueIPs}
          subtitle="Distinct attacker addresses"
          color="cyan"
          icon={Globe}
        />
        <KpiCardWithFlash
          title="High Severity"
          value={highSeverity}
          subtitle="Critical + High threats"
          color="danger"
          icon={ShieldAlert}
        />
        <KpiCard
          title="Active Nodes"
          value="1"
          subtitle="SSH Cowrie honeypot"
          color="success"
          icon={Server}
        />
      </div>

      {/* Honeypot Nodes */}
      <div className="mb-8">
        <h2 className="text-sm font-bold text-white uppercase tracking-wider mb-4">Honeypot Infrastructure</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <HoneypotNodeCard
            name="SSH Honeypot (Cowrie)"
            service="ssh"
            status="online"
            attackers={activeAttackers}
            port={2222}
            location="Astana, KZ"
            uptime={uptime}
          />
        </div>
      </div>

      {/* Timeline Chart */}
      <div className="mb-8">
        <TimelineChart sessions={allSessions} height={280} />
      </div>

      {/* Main content grid */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Recent Sessions */}
        <div className="xl:col-span-2 glass rounded-2xl overflow-hidden neon-glow">
          <div className="flex items-center justify-between px-6 py-4 border-b border-border">
            <h2 className="text-sm font-bold text-white uppercase tracking-wider">Recent Sessions</h2>
            <Link href="/sessions" className="text-xs text-accent-cyan hover:underline">View all</Link>
          </div>
          <div className="overflow-x-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Attacker IP</th>
                  <th>Session ID</th>
                  <th>Tactic</th>
                  <th>Severity</th>
                  <th>Risk</th>
                  <th>Duration</th>
                </tr>
              </thead>
              <tbody>
                {allSessions.length === 0 ? (
                  <tr><td colSpan={6} className="text-center py-8 text-muted">No sessions yet</td></tr>
                ) : (
                  tableSessions.map((s) => (
                    <tr
                      key={s.session_id}
                      className={`cursor-pointer group transition-colors ${
                        s._new ? "animate-[fadeInRow_0.4s_ease-out]" : ""
                      }`}
                    >
                      <td>
                        <Link href={`/sessions/${s.session_id}`} className="flex items-center gap-2">
                          <div className="w-2 h-2 rounded-full bg-accent-cyan/50 group-hover:bg-accent-cyan transition-colors" />
                          <span className="font-mono text-sm text-white group-hover:text-accent-cyan transition-colors">
                            {s.attacker_ip}
                          </span>
                        </Link>
                      </td>
                      <td className="font-mono text-xs text-muted">{s.session_id?.slice(0, 16)}...</td>
                      <td className={`text-sm text-white/80 ${s._updated ? "bg-yellow-500/10" : ""}`}>{s.current_tactic || "UNKNOWN"}</td>
                      <td>{s._updated ? <SeverityBadge severity={s.severity} /> : <SeverityBadge severity={s.severity} />}</td>
                      <td className={`font-mono text-sm text-white ${s._updated ? "bg-yellow-500/10" : ""}`}>{s.risk_score}</td>
                      <td className="text-sm text-muted">{s.duration_seconds ? `${s.duration_seconds}s` : "—"}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Side panels */}
        <div className="space-y-6">
          {/* Top IPs */}
          <div className="glass rounded-2xl p-5 neon-glow">
            <h2 className="text-sm font-bold text-white uppercase tracking-wider mb-4">Top Attackers</h2>
            <div className="space-y-3">
              {topAttackers.length > 0 ? (
                topAttackers.map((item, i) => (
                  <div key={item.ip} className="flex items-center gap-3">
                    <span className="w-5 h-5 rounded-md bg-surface border border-border flex items-center justify-center text-[10px] font-bold text-muted">
                      {i + 1}
                    </span>
                    <span className="font-mono text-sm text-white flex-1 truncate">{item.ip}</span>
                    <span className="text-xs font-semibold text-accent-cyan">{item.count}</span>
                  </div>
                ))
              ) : (
                <p className="text-muted text-sm">No data</p>
              )}
            </div>
          </div>

          {/* Top Tactics */}
          <div className="glass rounded-2xl p-5 neon-glow">
            <h2 className="text-sm font-bold text-white uppercase tracking-wider mb-4">Top Tactics</h2>
            <div className="space-y-3">
              {topTactics.length > 0 ? (
                topTactics.map((item) => (
                  <div key={item.tactic} className="flex items-center gap-3">
                    <div className="w-8 h-1.5 rounded-full bg-surface overflow-hidden">
                      <div
                        className="h-full rounded-full bg-accent-cyan"
                        style={{ width: `${Math.min(100, (item.count / maxTacticCount) * 100)}%` }}
                      />
                    </div>
                    <span className="text-sm text-white flex-1">{item.tactic}</span>
                    <span className="text-xs font-semibold text-muted">{item.count}</span>
                  </div>
                ))
              ) : (
                <p className="text-muted text-sm">No data</p>
              )}
            </div>
          </div>
        </div>
      </div>

      <style jsx>{`
        @keyframes fadeInRow {
          from { opacity: 0; background: rgba(0, 229, 255, 0.05); }
          to { opacity: 1; background: transparent; }
        }
      `}</style>
    </Layout>
  );
}