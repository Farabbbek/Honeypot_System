import { useEffect, useState } from "react";
import Link from "next/link";
import Layout from "../components/Layout";
import { Terminal, Filter, RefreshCw } from "lucide-react";

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

export default function Sessions() {
  const [sessions, setSessions] = useState([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState("");

  const load = () => {
    setLoading(true);
    fetch(`${API}/api/sessions?limit=100`)
      .then((r) => r.json())
      .then((data) => {
        setSessions(data);
        setError("");
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    load();
    const interval = setInterval(load, 10000);
    return () => clearInterval(interval);
  }, []);

  const filtered = sessions.filter((s) => {
    if (!filter) return true;
    const q = filter.toLowerCase();
    return (
      s.attacker_ip?.toLowerCase().includes(q) ||
      s.session_id?.toLowerCase().includes(q) ||
      s.current_tactic?.toLowerCase().includes(q) ||
      s.severity?.toLowerCase().includes(q)
    );
  });

  return (
    <Layout>
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold text-white mb-1">Sessions</h1>
          <p className="text-sm text-muted">All attacker sessions and activity logs</p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={load}
            className="p-2.5 rounded-xl glass border border-border text-muted hover:text-white transition-colors"
            disabled={loading}
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
          </button>
        </div>
      </div>

      {/* Filter */}
      <div className="glass rounded-xl px-4 py-3 flex items-center gap-3 mb-6 border border-border">
        <Filter className="w-4 h-4 text-muted shrink-0" />
        <input
          type="text"
          placeholder="Filter by IP, tactic, severity..."
          className="bg-transparent border-none outline-none text-sm text-white placeholder:text-muted w-full"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
        <span className="text-xs text-muted font-mono">{filtered.length} / {sessions.length}</span>
      </div>

      <div className="glass rounded-2xl overflow-hidden neon-glow">
        <div className="overflow-x-auto">
          <table className="data-table">
            <thead>
              <tr>
                <th>Attacker IP</th>
                <th>Session ID</th>
                <th>Tactic</th>
                <th>Severity</th>
                <th>Risk</th>
                <th>Logins</th>
                <th>Duration</th>
                <th>Adaptation</th>
              </tr>
            </thead>
            <tbody>
              {loading && sessions.length === 0 ? (
                <tr><td colSpan={8} className="text-center py-8 text-muted">Loading sessions...</td></tr>
              ) : filtered.length === 0 ? (
                <tr><td colSpan={8} className="text-center py-8 text-muted">No sessions found</td></tr>
              ) : (
                filtered.map((s) => (
                  <tr key={s.session_id} className="cursor-pointer group">
                    <td>
                      <Link href={`/sessions/${s.session_id}`} className="flex items-center gap-2">
                        <Terminal className="w-3.5 h-3.5 text-accent-cyan/50 group-hover:text-accent-cyan" />
                        <span className="font-mono text-sm text-white group-hover:text-accent-cyan transition-colors">
                          {s.attacker_ip}
                        </span>
                      </Link>
                    </td>
                    <td className="font-mono text-xs text-muted">{s.session_id?.slice(0, 20)}...</td>
                    <td className="text-sm text-white/80">{s.current_tactic || "—"}</td>
                    <td><SeverityBadge severity={s.severity} /></td>
                    <td className="font-mono text-sm text-white">{s.risk_score}</td>
                    <td className="text-sm text-muted">{s.login_attempts}</td>
                    <td className="text-sm text-muted">{s.duration_seconds ? `${s.duration_seconds}s` : "—"}</td>
                    <td className="text-sm text-muted">{s.adaptation_applied || "—"}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </Layout>
  );
}