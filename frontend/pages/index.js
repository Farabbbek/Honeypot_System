import { useEffect, useState } from "react";
import Link from "next/link";
import Layout from "../components/Layout";
import KpiCard from "../components/KpiCard";
import TimelineChart from "../components/TimelineChart";
import HoneypotNodeCard from "../components/HoneypotNodeCard";
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

export default function Overview() {
  const [stats, setStats] = useState(null);
  const [sessions, setSessions] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(`${API}/api/stats`)
      .then((r) => r.json())
      .then(setStats)
      .catch(() => setStats(null));

    fetch(`${API}/api/sessions?limit=8`)
      .then((r) => r.json())
      .then((data) => {
        setSessions(data);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  const criticalCount = sessions.filter((s) => s.severity === "CRITICAL" || s.severity === "HIGH").length;

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

      {/* KPI Cards — all real data, no fake trends */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        <KpiCard
          title="Total Attacks"
          value={stats?.total_attacks?.toLocaleString() || "0"}
          subtitle="All recorded sessions"
          color="danger"
          icon={Activity}
        />
        <KpiCard
          title="Unique IPs"
          value={stats?.top_ips?.length || "0"}
          subtitle="Distinct attacker addresses"
          color="cyan"
          icon={Globe}
        />
        <KpiCard
          title="High Severity"
          value={criticalCount}
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
            attackers={sessions.length}
            port={2222}
            location="Astana, KZ"
          />
        </div>
      </div>

      {/* Timeline Chart */}
      <div className="mb-8">
        <TimelineChart sessions={sessions} height={280} />
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
                {loading ? (
                  <tr><td colSpan={6} className="text-center py-8 text-muted">Loading...</td></tr>
                ) : sessions.length === 0 ? (
                  <tr><td colSpan={6} className="text-center py-8 text-muted">No sessions yet</td></tr>
                ) : (
                  sessions.map((s) => (
                    <tr key={s.session_id} className="cursor-pointer group">
                      <td>
                        <Link href={`/sessions/${s.session_id}`} className="flex items-center gap-2">
                          <div className="w-2 h-2 rounded-full bg-accent-cyan/50 group-hover:bg-accent-cyan transition-colors" />
                          <span className="font-mono text-sm text-white group-hover:text-accent-cyan transition-colors">
                            {s.attacker_ip}
                          </span>
                        </Link>
                      </td>
                      <td className="font-mono text-xs text-muted">{s.session_id?.slice(0, 16)}...</td>
                      <td className="text-sm text-white/80">{s.current_tactic || "UNKNOWN"}</td>
                      <td><SeverityBadge severity={s.severity} /></td>
                      <td className="font-mono text-sm text-white">{s.risk_score}</td>
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
              {stats?.top_ips?.slice(0, 5).map((item, i) => (
                <div key={item.ip} className="flex items-center gap-3">
                  <span className="w-5 h-5 rounded-md bg-surface border border-border flex items-center justify-center text-[10px] font-bold text-muted">
                    {i + 1}
                  </span>
                  <span className="font-mono text-sm text-white flex-1">{item.ip}</span>
                  <span className="text-xs font-semibold text-accent-cyan">{item.count}</span>
                </div>
              )) || <p className="text-muted text-sm">No data</p>}
            </div>
          </div>

          {/* Top Tactics */}
          <div className="glass rounded-2xl p-5 neon-glow">
            <h2 className="text-sm font-bold text-white uppercase tracking-wider mb-4">Top Tactics</h2>
            <div className="space-y-3">
              {stats?.top_tactics?.slice(0, 5).map((item) => (
                <div key={item.tactic} className="flex items-center gap-3">
                  <div className="w-8 h-1.5 rounded-full bg-surface overflow-hidden">
                    <div
                      className="h-full rounded-full bg-accent-cyan"
                      style={{ width: `${Math.min(100, (item.count / (stats.top_tactics[0]?.count || 1)) * 100)}%` }}
                    />
                  </div>
                  <span className="text-sm text-white flex-1">{item.tactic}</span>
                  <span className="text-xs font-semibold text-muted">{item.count}</span>
                </div>
              )) || <p className="text-muted text-sm">No data</p>}
            </div>
          </div>
        </div>
      </div>
    </Layout>
  );
}