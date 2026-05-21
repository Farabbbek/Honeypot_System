import { useEffect, useState } from "react";
import Layout from "../components/Layout";
import Globe3D from "../components/Globe3D";
import { Globe } from "lucide-react";

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

export default function MapPage() {
  const [points, setPoints] = useState([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState(null);

  useEffect(() => {
    let cancelled = false;

    const load = () => {
      fetch(`${API}/api/map`)
        .then((res) => {
          if (!res.ok) throw new Error(`API returned ${res.status}`);
          return res.json();
        })
        .then((data) => {
          if (cancelled) return;
          setPoints(data);
          setLastUpdated(new Date());
          setLoading(false);
          setError("");
        })
        .catch((err) => {
          if (cancelled) return;
          setError(err.message || "Could not load map data");
          setLoading(false);
        });
    };

    load();
    const interval = setInterval(load, 10000);

    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  return (
    <Layout>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-white mb-1">World Map</h1>
          <p className="text-sm text-muted">3D geospatial threat intelligence — attack origins and arcs</p>
        </div>
        <div className="flex items-center gap-3">
          {lastUpdated && (
            <span className="text-[11px] text-muted font-mono">
              Updated {lastUpdated.toLocaleTimeString()} · auto-refresh 10s
            </span>
          )}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-surface border border-border">
            <Globe className="w-4 h-4 text-accent-cyan" />
            <span className="text-xs text-muted font-medium">{points.length} points</span>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-4 gap-6">
        {/* 3D Globe */}
        <div className="xl:col-span-3">
          <div className="glass rounded-2xl overflow-hidden neon-glow" style={{ height: "680px" }}>
            {error ? (
              <div className="h-full flex items-center justify-center">
                <p className="text-danger">{error}</p>
              </div>
            ) : (
              <Globe3D points={points} className="w-full h-full" />
            )}
          </div>
          <p className="text-xs text-muted mt-2 text-center">
            Drag to rotate • Arcs show attack paths to honeypot node in Astana
          </p>
        </div>

        {/* Attack list sidebar */}
        <div className="space-y-4">
          <div className="glass rounded-2xl p-4 neon-glow">
            <h2 className="text-sm font-bold text-white uppercase tracking-wider mb-3">Recent Attacks</h2>
            <div className="space-y-2 max-h-[500px] overflow-y-auto">
              {points.slice(0, 20).map((p) => (
                <div key={p.session_id} className="flex items-center gap-2 p-2 rounded-lg bg-surface/50 border border-border hover:border-accent-cyan/20 transition-colors">
                  <div
                    className="w-2 h-2 rounded-full shrink-0"
                    style={{
                      background:
                        p.severity === "CRITICAL"
                          ? "#FF4D4D"
                          : p.severity === "HIGH"
                          ? "#FFB800"
                          : "#00E5FF",
                      boxShadow: `0 0 6px ${
                        p.severity === "CRITICAL"
                          ? "rgba(255,77,77,0.5)"
                          : p.severity === "HIGH"
                          ? "rgba(255,184,0,0.5)"
                          : "rgba(0,229,255,0.5)"
                      }`,
                    }}
                  />
                  <div className="min-w-0">
                    <div className="font-mono text-xs text-white truncate">{p.ip}</div>
                    <div className="text-[10px] text-muted truncate">{p.country}</div>
                  </div>
                  <div className="ml-auto">
                    <SeverityBadge severity={p.severity} />
                  </div>
                </div>
              ))}
              {points.length === 0 && !loading && (
                <p className="text-muted text-xs text-center py-4">No attack data</p>
              )}
            </div>
          </div>

          {/* Legend */}
          <div className="glass rounded-2xl p-4">
            <h2 className="text-sm font-bold text-white uppercase tracking-wider mb-3">Legend</h2>
            <div className="space-y-2 text-xs">
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-[#00E5FF]" style={{ boxShadow: "0 0 6px rgba(0,229,255,0.5)" }} />
                <span className="text-muted">LOW / MEDIUM attack</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-[#FFB800]" style={{ boxShadow: "0 0 6px rgba(255,184,0,0.5)" }} />
                <span className="text-muted">HIGH severity</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-[#FF4D4D]" style={{ boxShadow: "0 0 6px rgba(255,77,77,0.5)" }} />
                <span className="text-muted">CRITICAL threat</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-8 h-0.5 bg-gradient-to-r from-[#00E5FF] to-transparent" />
                <span className="text-muted">Arc — LOW / MEDIUM</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-8 h-0.5 bg-gradient-to-r from-[#FFB800] to-transparent" />
                <span className="text-muted">Arc — HIGH</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-8 h-0.5 bg-gradient-to-r from-[#FF4D4D] to-transparent" />
                <span className="text-muted">Arc — CRITICAL</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-[#7CFF6B]" style={{ boxShadow: "0 0 6px rgba(124,255,107,0.5)" }} />
                <span className="text-muted">Honeypot node</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </Layout>
  );
}
