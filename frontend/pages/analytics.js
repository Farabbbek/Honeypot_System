import { useEffect, useState } from "react";
import Layout from "../components/Layout";
import { BarChart3, Activity, Globe, Lock, Terminal } from "lucide-react";

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

function StatCard({ title, value, icon: Icon, color = "cyan" }) {
  const colorMap = {
    cyan: "text-accent-cyan bg-accent-cyan/10 border-accent-cyan/20",
    danger: "text-danger bg-danger/10 border-danger/20",
    success: "text-success bg-success/10 border-success/20",
    warning: "text-warning bg-warning/10 border-warning/20",
  };

  return (
    <div className="metric-card">
      <div className="flex items-center gap-3 mb-3">
        <div className={`w-9 h-9 rounded-xl border flex items-center justify-center ${colorMap[color]}`}>
          <Icon className="w-4 h-4" />
        </div>
        <span className="text-xs font-semibold text-muted uppercase tracking-wider">{title}</span>
      </div>
      <div className="metric-value text-white">{value}</div>
    </div>
  );
}

function Panel({ title, items, label, icon: Icon }) {
  const max = items[0]?.count || 1;

  return (
    <div className="glass rounded-2xl p-5 neon-glow">
      <h2 className="text-sm font-bold text-white uppercase tracking-wider mb-4 flex items-center gap-2">
        {Icon && <Icon className="w-4 h-4 text-accent-cyan" />}
        {title}
      </h2>
      <div className="space-y-3">
        {items.length === 0 && <p className="text-muted text-sm">No data</p>}
        {items.slice(0, 10).map((item, i) => {
          const pct = max > 0 ? (item.count / max) * 100 : 0;
          return (
            <div key={item[label] || i} className="flex items-center gap-3">
              <div className="w-8 h-1.5 rounded-full bg-surface overflow-hidden">
                <div className="h-full rounded-full bg-accent-cyan" style={{ width: `${pct}%` }} />
              </div>
              <span className="text-sm text-white flex-1 truncate">{item[label] || "unknown"}</span>
              <span className="text-xs font-semibold text-accent-cyan font-mono">{item.count}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default function Analytics() {
  const [stats, setStats] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(`${API}/api/stats`)
      .then((r) => {
        if (!r.ok) throw new Error(`API returned ${r.status}`);
        return r.json();
      })
      .then((data) => {
        setStats(data);
        setError("");
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  return (
    <Layout>
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold text-white mb-1">Analytics</h1>
          <p className="text-sm text-muted">Statistical analysis of threat activity</p>
        </div>
      </div>

      {/* Top metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        <StatCard title="Total Attacks" value={stats?.total_attacks?.toLocaleString() || "0"} icon={Activity} color="danger" />
        <StatCard title="Unique IPs" value={stats?.top_ips?.length || "0"} icon={Globe} color="cyan" />
        <StatCard title="Unique Tactics" value={stats?.top_tactics?.length || "0"} icon={Terminal} color="warning" />
        <StatCard title="Passwords" value={stats?.top_passwords?.length || "0"} icon={Lock} color="success" />
      </div>

      {/* Panels grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Panel title="Top Attackers" items={stats?.top_ips || []} label="ip" icon={Globe} />
        <Panel title="Top Countries" items={stats?.top_countries || []} label="country" icon={Globe} />
        <Panel title="Top Tactics" items={stats?.top_tactics || []} label="tactic" icon={Terminal} />
        <Panel title="Top Passwords" items={stats?.top_passwords || []} label="password" icon={Lock} />
      </div>
    </Layout>
  );
}