import { useEffect, useState } from "react";
import { useRouter } from "next/router";
import Link from "next/link";
import Layout from "../../components/Layout";
import { ArrowLeft, Shield, FileText, AlertTriangle, Loader2 } from "lucide-react";

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

export default function SessionDetail() {
  const router = useRouter();
  const { id } = router.query;
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [analyzing, setAnalyzing] = useState(false);

  useEffect(() => {
    if (!id) return;
    setLoading(true);
    fetch(`${API}/api/sessions/${encodeURIComponent(id)}`)
      .then((r) => {
        if (!r.ok) throw new Error(`API returned ${r.status}`);
        return r.json();
      })
      .then(setData)
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, [id]);

  const analyze = async () => {
    setAnalyzing(true);
    try {
      const r = await fetch(`${API}/api/threats/${encodeURIComponent(id)}/analyze`, { method: "POST" });
      if (!r.ok) throw new Error(`API returned ${r.status}`);
      const report = await r.json();
      setData((prev) => ({ ...prev, report }));
      setError("");
    } catch (err) {
      setError("Analysis failed: " + err.message);
    } finally {
      setAnalyzing(false);
    }
  };

  if (!id || loading) {
    return (
      <Layout>
        <div className="flex items-center justify-center h-96">
          <div className="w-6 h-6 rounded-full border-2 border-accent-cyan/30 border-t-accent-cyan animate-spin" />
        </div>
      </Layout>
    );
  }

  if (error && !data) {
    return (
      <Layout>
        <div className="glass rounded-2xl p-8 text-center">
          <AlertTriangle className="w-8 h-8 text-danger mx-auto mb-3" />
          <p className="text-danger mb-4">{error}</p>
          <Link href="/sessions" className="text-accent-cyan hover:underline text-sm">← Back to sessions</Link>
        </div>
      </Layout>
    );
  }

  const session = data?.session;
  const events = data?.events || [];
  const report = data?.report;
  const intel = data?.ip_intel;

  return (
    <Layout>
      <Link href="/sessions" className="inline-flex items-center gap-2 text-sm text-muted hover:text-white transition-colors mb-6">
        <ArrowLeft className="w-4 h-4" />
        Back to sessions
      </Link>

      <div className="flex items-start justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-white mb-1">Session Detail</h1>
          <p className="font-mono text-xs text-muted">{id}</p>
        </div>
        {session?.severity && <SeverityBadge severity={session.severity} />}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
        {/* Overview */}
        <div className="glass rounded-2xl p-5 neon-glow">
          <h2 className="text-sm font-bold text-white uppercase tracking-wider mb-4 flex items-center gap-2">
            <Shield className="w-4 h-4 text-accent-cyan" />
            Overview
          </h2>
          <div className="space-y-3 text-sm">
            <div className="flex justify-between"><span className="text-muted">Attacker IP</span><span className="font-mono text-white">{session?.attacker_ip}</span></div>
            <div className="flex justify-between"><span className="text-muted">Risk Score</span><span className="font-mono text-white">{session?.risk_score}/100</span></div>
            <div className="flex justify-between"><span className="text-muted">Tactic</span><span className="text-white">{session?.current_tactic || "—"}</span></div>
            <div className="flex justify-between"><span className="text-muted">Login Attempts</span><span className="text-white">{session?.login_attempts}</span></div>
            <div className="flex justify-between"><span className="text-muted">Successful</span><span className="text-white">{session?.successful_login ? "Yes" : "No"}</span></div>
            <div className="flex justify-between"><span className="text-muted">Duration</span><span className="text-white">{session?.duration_seconds ? `${session?.duration_seconds}s` : "—"}</span></div>
            <div className="flex justify-between"><span className="text-muted">Adaptation</span><span className="text-white">{session?.adaptation_applied || "—"}</span></div>
          </div>
        </div>

        {/* IP Intel */}
        <div className="glass rounded-2xl p-5 neon-glow">
          <h2 className="text-sm font-bold text-white uppercase tracking-wider mb-4 flex items-center gap-2">
            <Shield className="w-4 h-4 text-success" />
            IP Intelligence
          </h2>
          {intel ? (
            <div className="space-y-3 text-sm">
              <div className="flex justify-between"><span className="text-muted">Country</span><span className="text-white">{intel.country_name || "?"}</span></div>
              <div className="flex justify-between"><span className="text-muted">City</span><span className="text-white">{intel.city || "?"}</span></div>
              <div className="flex justify-between"><span className="text-muted">ASN</span><span className="font-mono text-white">{intel.asn || "?"}</span></div>
              <div className="flex justify-between"><span className="text-muted">Org</span><span className="text-white">{intel.org_name || "?"}</span></div>
              <div className="flex justify-between"><span className="text-muted">Abuse Score</span><span className="text-white">{intel.abuse_confidence_score != null ? `${intel.abuse_confidence_score}%` : "N/A"}</span></div>
              <div className="flex justify-between"><span className="text-muted">VPN</span><span className="text-white">{intel.is_vpn ? "Yes" : "No"}</span></div>
              <div className="flex justify-between"><span className="text-muted">Tor</span><span className="text-white">{intel.is_tor ? "Yes" : "No"}</span></div>
            </div>
          ) : (
            <p className="text-muted text-sm">No IP intel available</p>
          )}
        </div>

        {/* Threat Report */}
        <div className="glass rounded-2xl p-5 neon-glow">
          <h2 className="text-sm font-bold text-white uppercase tracking-wider mb-4 flex items-center gap-2">
            <FileText className="w-4 h-4 text-warning" />
            Threat Report
          </h2>
          {report ? (
            <div className="space-y-3 text-sm">
              <div className="flex items-center gap-2 mb-2">
                <SeverityBadge severity={report.severity} />
              </div>
              <div className="flex justify-between"><span className="text-muted">Attack Type</span><span className="text-white">{report.attack_type || "—"}</span></div>
              <div className="flex justify-between"><span className="text-muted">Kill Chain</span><span className="text-white">{report.kill_chain_phase || "—"}</span></div>
              <div className="flex justify-between"><span className="text-muted">Goal</span><span className="text-white">{report.attacker_goal || "—"}</span></div>
              <div className="flex justify-between"><span className="text-muted">Profile</span><span className="text-white">{report.attacker_profile || "—"}</span></div>
              <div className="flex justify-between"><span className="text-muted">Confidence</span><span className="text-white">{report.confidence != null ? `${(report.confidence * 100).toFixed(0)}%` : "—"}</span></div>
              {report.mitre_techniques?.length > 0 && (
                <div className="pt-2">
                  <span className="text-muted block mb-1">MITRE:</span>
                  <div className="flex flex-wrap gap-1">
                    {report.mitre_techniques.map((t, i) => (
                      <span key={i} className="px-2 py-0.5 rounded-md bg-accent-cyan/10 text-accent-cyan text-xs font-mono border border-accent-cyan/20">
                        {t.id || t.name || t}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {report.id && (
                <a href={`${API}/api/threats/${report.id}/export`} className="inline-flex items-center gap-2 mt-3 px-3 py-1.5 rounded-lg bg-accent-cyan/10 border border-accent-cyan/20 text-accent-cyan text-xs font-semibold hover:bg-accent-cyan/15 transition-colors">
                  <FileText className="w-3 h-3" />
                  Download PDF
                </a>
              )}
            </div>
          ) : (
            <div className="text-center py-4">
              <p className="text-muted text-sm mb-3">No threat report generated yet</p>
              <button
                onClick={analyze}
                disabled={analyzing}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-accent-cyan/10 border border-accent-cyan/20 text-accent-cyan text-sm font-semibold hover:bg-accent-cyan/15 transition-colors disabled:opacity-50"
              >
                {analyzing && <Loader2 className="w-4 h-4 animate-spin" />}
                {analyzing ? "Analyzing..." : "Generate Report"}
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Events */}
      <div className="glass rounded-2xl overflow-hidden neon-glow">
        <div className="px-6 py-4 border-b border-border flex items-center justify-between">
          <h2 className="text-sm font-bold text-white uppercase tracking-wider">Events ({events.length})</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="data-table">
            <thead>
              <tr><th>Time</th><th>Type</th><th>Command</th><th>MITRE</th></tr>
            </thead>
            <tbody>
              {events.length === 0 ? (
                <tr><td colSpan={4} className="text-center py-8 text-muted">No events</td></tr>
              ) : (
                events.map((e, i) => (
                  <tr key={i}>
                    <td className="font-mono text-xs text-muted whitespace-nowrap">
                      {e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : "?"}
                    </td>
                    <td className="text-sm text-white/80">{e.event_type}</td>
                    <td className="font-mono text-xs text-white/60">{e.raw_command || "—"}</td>
                    <td className="font-mono text-xs text-accent-cyan">{e.mitre_technique || "—"}</td>
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