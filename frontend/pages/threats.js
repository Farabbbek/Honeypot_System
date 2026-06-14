import { useEffect, useState, useMemo } from "react";
import Link from "next/link";
import Layout from "../components/Layout";
import {
  ShieldAlert,
  FileText,
  ExternalLink,
  Terminal,
  Bot,
  Skull,
  AlertTriangle,
  Info,
  Filter,
} from "lucide-react";

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

const SEVERITY_CONFIG = {
  CRITICAL: { color: "#FF4D4D", bg: "rgba(255, 77, 77, 0.08)", border: "rgba(255, 77, 77, 0.2)", icon: Skull },
  HIGH: { color: "#FFB800", bg: "rgba(255, 184, 0, 0.08)", border: "rgba(255, 184, 0, 0.2)", icon: ShieldAlert },
  MEDIUM: { color: "#F59E0B", bg: "rgba(245, 158, 11, 0.08)", border: "rgba(245, 158, 11, 0.2)", icon: AlertTriangle },
  LOW: { color: "#00E5FF", bg: "rgba(0, 229, 255, 0.08)", border: "rgba(0, 229, 255, 0.2)", icon: Info },
};

function SeverityBadge({ severity }) {
  const classes = {
    CRITICAL: "severity-critical",
    HIGH: "severity-high",
    MEDIUM: "severity-medium",
    LOW: "severity-low",
  };
  return <span className={`status-badge ${classes[severity] || "severity-low"}`}>{severity}</span>;
}

function TacticBadge({ tactic }) {
  const colors = {
    EXECUTION: { bg: "rgba(0, 229, 255, 0.15)", text: "#00E5FF", border: "rgba(0, 229, 255, 0.3)" },
    CREDENTIAL_ACCESS: { bg: "rgba(255, 77, 77, 0.15)", text: "#FF4D4D", border: "rgba(255, 77, 77, 0.3)" },
    RECONNAISSANCE: { bg: "rgba(139, 92, 246, 0.15)", text: "#8B5CF6", border: "rgba(139, 92, 246, 0.3)" },
    INITIAL_ACCESS: { bg: "rgba(52, 211, 153, 0.15)", text: "#34D399", border: "rgba(52, 211, 153, 0.3)" },
    PERSISTENCE: { bg: "rgba(251, 191, 36, 0.15)", text: "#FBBF24", border: "rgba(251, 191, 36, 0.3)" },
    DEFENSE_EVASION: { bg: "rgba(168, 85, 247, 0.15)", text: "#A855F7", border: "rgba(168, 85, 247, 0.3)" },
  };
  const c = colors[tactic] || { bg: "rgba(255,255,255,0.05)", text: "#888", border: "rgba(255,255,255,0.1)" };
  return (
    <span
      className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold"
      style={{ background: c.bg, color: c.text, border: `1px solid ${c.border}` }}
    >
      {tactic}
    </span>
  );
}

export default function Threats() {
  const [reports, setReports] = useState([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  // Filters
  const [typeFilter, setTypeFilter] = useState("ALL"); // ALL | INTERACTIVE | BOT
  const [severityFilter, setSeverityFilter] = useState(null); // null | CRITICAL | HIGH | MEDIUM | LOW

  useEffect(() => {
    setLoading(true);
    // Build query params
    const params = new URLSearchParams({ limit: "200" });
    if (typeFilter === "INTERACTIVE") params.set("type", "interactive");
    else if (typeFilter === "BOT") params.set("type", "bot");
    if (severityFilter) params.set("severity", severityFilter);

    fetch(`${API}/api/threats?${params.toString()}`)
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
  }, [typeFilter, severityFilter]);

  // Compute counts for each category (from latest full fetch, or estimate)
  const severityCounts = useMemo(() => {
    const counts = {};
    for (const r of reports) {
      const s = r.severity || "LOW";
      counts[s] = (counts[s] || 0) + 1;
    }
    return counts;
  }, [reports]);

  const interactiveCount = useMemo(
    () => reports.filter((r) => r.attack_type && !r.attack_type.includes("Scanner")).length,
    [reports]
  );

  const sorted = [...reports].sort((a, b) => {
    const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
    return (order[a.severity] ?? 99) - (order[b.severity] ?? 99);
  });

  return (
    <Layout>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-white mb-1">Threats</h1>
          <p className="text-sm text-muted">LLM-generated threat intelligence reports</p>
        </div>
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-surface border border-border">
          <ShieldAlert className="w-4 h-4 text-danger" />
          <span className="text-xs text-muted font-medium">{reports.length} reports</span>
        </div>
      </div>

      {/* ── Filter Bar ── */}
      <div className="glass rounded-2xl p-3 mb-6 flex flex-wrap items-center gap-3 neon-glow">
        <Filter className="w-4 h-4 text-muted shrink-0" />

        {/* Type filter */}
        <div className="flex items-center gap-1.5">
          {[
            { key: "ALL", label: "All", icon: null },
            { key: "INTERACTIVE", label: "Interactive", icon: Terminal },
            { key: "BOT", label: "Bot", icon: Bot },
          ].map(({ key, label, icon: Icon }) => (
            <button
              key={key}
              onClick={() => setTypeFilter(key)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold font-mono transition-all ${
                typeFilter === key
                  ? "bg-white/20 text-white shadow-md shadow-white/10"
                  : "bg-white/5 text-muted hover:bg-white/10"
              }`}
            >
              {Icon && <Icon className="w-3.5 h-3.5" />}
              {label}
            </button>
          ))}
        </div>

        <div className="w-px h-6 bg-border/50 mx-1" />

        {/* Severity filter */}
        <div className="flex items-center gap-1.5 flex-wrap">
          {[{ key: null, label: "All" }, ...Object.entries(SEVERITY_CONFIG).map(([k, v]) => ({ key: k, ...v }))].map(
            (item) => (
              <button
                key={item.key || "all-sev"}
                onClick={() => setSeverityFilter(item.key)}
                className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[11px] font-bold font-mono transition-all ${
                  severityFilter === item.key
                    ? "opacity-100 scale-105 shadow-md"
                    : "opacity-60 hover:opacity-90"
                }`}
                style={
                  item.key
                    ? {
                        background: item.bg,
                        color: item.color,
                        border: `1px solid ${item.border}`,
                        boxShadow: severityFilter === item.key ? `0 0 12px ${item.color}22` : "none",
                      }
                    : {
                        background: severityFilter === null ? "rgba(255,255,255,0.15)" : "rgba(255,255,255,0.05)",
                        color: severityFilter === null ? "#fff" : "#888",
                        border: `1px solid ${severityFilter === null ? "rgba(255,255,255,0.2)" : "rgba(255,255,255,0.08)"}`,
                      }
                }
              >
                {item.icon && <item.icon className="w-3 h-3" />}
                {item.label}
                {item.key && severityCounts[item.key] ? ` ${severityCounts[item.key]}` : ""}
              </button>
            )
          )}
        </div>

        <div className="flex-1" />

        {/* Active filter indicator */}
        {(typeFilter !== "ALL" || severityFilter) && (
          <button
            onClick={() => {
              setTypeFilter("ALL");
              setSeverityFilter(null);
            }}
            className="text-[10px] text-accent-cyan hover:underline"
          >
            Clear filters
          </button>
        )}
      </div>

      {/* ── Content ── */}
      {loading ? (
        <div className="glass rounded-2xl p-8 text-center text-muted">Loading threats...</div>
      ) : error ? (
        <div className="glass rounded-2xl p-8 text-center text-danger">{error}</div>
      ) : sorted.length === 0 ? (
        <div className="glass rounded-2xl p-8 text-center">
          <p className="text-muted mb-2">No threat reports found</p>
          <p className="text-muted text-sm">
            {typeFilter !== "ALL" || severityFilter
              ? "Try changing the filters"
              : "Analyze a session to generate a report"}
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {sorted.map((r) => {
            const hasCommands = r.attack_type && !r.attack_type.includes("Scanner");
            const sev = SEVERITY_CONFIG[r.severity] || SEVERITY_CONFIG.LOW;

            return (
              <div
                key={r.id}
                className="glass rounded-2xl p-5 neon-glow group hover:border-accent-cyan/20 transition-all relative overflow-hidden"
              >
                {/* Interactive / Bot indicator bar at top */}
                <div
                  className="absolute top-0 left-0 right-0 h-0.5"
                  style={{
                    background: hasCommands
                      ? "linear-gradient(90deg, #00E5FF, #8B5CF6)"
                      : "linear-gradient(90deg, rgba(255,255,255,0.08), rgba(255,255,255,0.02))",
                  }}
                />

                <div className="flex items-start justify-between mb-3">
                  <div className="flex items-center gap-2 min-w-0">
                    {hasCommands ? (
                      <div className="w-7 h-7 rounded-lg bg-accent-cyan/10 border border-accent-cyan/20 flex items-center justify-center shrink-0">
                        <Terminal className="w-3.5 h-3.5 text-accent-cyan" />
                      </div>
                    ) : (
                      <div className="w-7 h-7 rounded-lg bg-white/5 border border-white/10 flex items-center justify-center shrink-0">
                        <Bot className="w-3.5 h-3.5 text-muted" />
                      </div>
                    )}
                    <div className="min-w-0">
                      <h3 className="text-sm font-bold text-white group-hover:text-accent-cyan transition-colors truncate">
                        {r.attack_type || "Threat Report"}
                      </h3>
                      <p className="text-[10px] text-muted font-mono mt-0.5 truncate">{r.session_id?.slice(0, 24)}...</p>
                    </div>
                  </div>
                  <SeverityBadge severity={r.severity} />
                </div>

                {/* Tactic badge */}
                {r.mitre_techniques?.length > 0 && (
                  <div className="flex flex-wrap gap-1 mb-3">
                    {r.mitre_techniques.slice(0, 3).map((t, i) => (
                      <span
                        key={i}
                        className="px-1.5 py-0.5 rounded bg-accent-cyan/10 text-accent-cyan text-[10px] font-mono border border-accent-cyan/20"
                      >
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

                {/* Interactive label */}
                {hasCommands && (
                  <div className="flex items-center gap-1.5 mb-2">
                    <span className="px-1.5 py-0.5 rounded bg-accent-cyan/10 text-accent-cyan text-[9px] font-mono font-bold border border-accent-cyan/20">
                      INTERACTIVE
                    </span>
                  </div>
                )}

                {r.recommendation && (
                  <p className="text-xs text-white/60 mb-3 line-clamp-2">{r.recommendation}</p>
                )}

                <div className="flex items-center justify-between pt-3 border-t border-border">
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] text-muted">
                      {r.created_at ? new Date(r.created_at).toLocaleDateString() : "?"}
                    </span>
                    {/* Severity dot */}
                    <div
                      className="w-1.5 h-1.5 rounded-full"
                      style={{ background: sev.color, boxShadow: `0 0 6px ${sev.color}` }}
                    />
                  </div>
                  <div className="flex items-center gap-2">
                    <Link
                      href={`/sessions/${r.session_id}`}
                      className="text-xs text-accent-cyan hover:underline flex items-center gap-1"
                    >
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
            );
          })}
        </div>
      )}
    </Layout>
  );
}