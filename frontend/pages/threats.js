import { useEffect, useState } from "react";
import Link from "next/link";
import Layout from "../components/Layout";
import { ShieldAlert, FileText, ExternalLink } from "lucide-react";

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

export default function Threats() {
  const [reports, setReports] = useState([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(`${API}/api/threats`)
      .then((r) => {
        if (!r.ok) throw new Error(`API returned ${r.status}`);
        return r.json();
      })
      .then((data) => {
        setReports(data);
        setError("");
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  const sorted = [...reports].sort(
    (a, b) => (severityOrder[a.severity] ?? 99) - (severityOrder[b.severity] ?? 99)
  );

  return (
    <Layout>
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold text-white mb-1">Threats</h1>
          <p className="text-sm text-muted">LLM-generated threat intelligence reports</p>
        </div>
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-surface border border-border">
          <ShieldAlert className="w-4 h-4 text-danger" />
          <span className="text-xs text-muted font-medium">{reports.length} reports</span>
        </div>
      </div>

      {loading ? (
        <div className="glass rounded-2xl p-8 text-center text-muted">Loading threats...</div>
      ) : error ? (
        <div className="glass rounded-2xl p-8 text-center text-danger">{error}</div>
      ) : sorted.length === 0 ? (
        <div className="glass rounded-2xl p-8 text-center">
          <p className="text-muted mb-2">No threat reports yet</p>
          <p className="text-muted text-sm">Analyze a session to generate a report</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {sorted.map((r) => (
            <div key={r.id} className="glass rounded-2xl p-5 neon-glow group hover:border-accent-cyan/20 transition-all">
              <div className="flex items-start justify-between mb-3">
                <div>
                  <h3 className="text-sm font-bold text-white group-hover:text-accent-cyan transition-colors">
                    {r.attack_type || "Threat Report"}
                  </h3>
                  <p className="text-xs text-muted font-mono mt-1">{r.session_id?.slice(0, 24)}...</p>
                </div>
                <SeverityBadge severity={r.severity} />
              </div>

              {r.mitre_techniques?.length > 0 && (
                <div className="flex flex-wrap gap-1 mb-3">
                  {r.mitre_techniques.slice(0, 3).map((t, i) => (
                    <span key={i} className="px-1.5 py-0.5 rounded bg-accent-cyan/10 text-accent-cyan text-[10px] font-mono border border-accent-cyan/20">
                      {t.id || t.name || t}
                    </span>
                  ))}
                  {r.mitre_techniques.length > 3 && (
                    <span className="px-1.5 py-0.5 rounded bg-surface text-muted text-[10px] font-mono border border-border">
                      +{r.mitre_techniques.length - 3}
                    </span>
                  )}
                </div>
              )}

              {r.recommendation && (
                <p className="text-xs text-white/60 mb-3 line-clamp-2">{r.recommendation}</p>
              )}

              <div className="flex items-center justify-between pt-3 border-t border-border">
                <span className="text-[10px] text-muted">
                  {r.created_at ? new Date(r.created_at).toLocaleDateString() : "?"}
                </span>
                <div className="flex items-center gap-2">
                  <Link href={`/sessions/${r.session_id}`} className="text-xs text-accent-cyan hover:underline flex items-center gap-1">
                    Session <ExternalLink className="w-3 h-3" />
                  </Link>
                  {r.id && (
                    <a
                      href={`${API}/api/threats/${r.id}/export`}
                      className="text-xs text-muted hover:text-white flex items-center gap-1 transition-colors"
                    >
                      <FileText className="w-3 h-3" />
                    </a>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </Layout>
  );
}