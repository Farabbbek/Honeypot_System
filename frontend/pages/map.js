import { useEffect, useState, useCallback } from "react";
import Layout from "../components/Layout";
import Globe3D from "../components/Globe3D";
import { Globe } from "lucide-react";

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

// Fallback honeypot location (Astana, Kazakhstan) — used if API returns no honeypot object
const FALLBACK_HONEYPOT = { lat: 51.17, lon: 71.45, city: "Astana", country: "Kazakhstan" };

/**
 * Normalize a map attack point from the backend API shape to the shape
 * Globe3D component expects:
 *   { latitude, longitude, ip, severity, risk_score, session_id, country, city, asn, org, current_tactic }
 */
function normalizeMapPoint(raw) {
  const lat = raw.lat ?? raw.latitude ?? null;
  const lon = raw.lon ?? raw.longitude ?? null;
  const ip = raw.source_ip ?? raw.ip ?? "Unknown";

  // Skip invalid coordinates
  if (lat == null || lon == null || typeof lat !== "number" || typeof lon !== "number" || (lat === 0 && lon === 0)) {
    return null;
  }
  if (isNaN(lat) || isNaN(lon)) return null;

  return {
    latitude:        lat,
    longitude:       lon,
    ip,
    country:         raw.country || "",
    city:            raw.city || "",
    severity:        raw.severity || "LOW",
    risk_score:      raw.risk_score ?? 0,
    session_id:      raw.session_id || null,
    asn:             raw.asn || "",
    org:             raw.org || "",
    current_tactic:  raw.current_tactic || "",
    tactics:         raw.tactics || [],
    timestamp:       raw.timestamp || null,
  };
}

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
  const [honeypot, setHoneypot] = useState(FALLBACK_HONEYPOT);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState(null);

  const load = useCallback(() => {
    setLoading(true);
    setError("");

    fetch(`${API}/api/map`)
      .then((res) => {
        if (!res.ok) {
          console.error("map api error", res.status, res.statusText);
          throw new Error("Failed to load map data");
        }
        return res.json();
      })
      .then(async (data) => {
        console.log("map payload", data);
        // New API shape: { attacks: [...], honeypot: {...} }
        // Old API shape (fallback): flat array [...]
        let attackPoints = [];
        let honeypot = null;

        if (data && typeof data === "object" && !Array.isArray(data)) {
          // New shape
          attackPoints = Array.isArray(data.attacks) ? data.attacks : [];
          if (data.honeypot && typeof data.honeypot === "object") {
            honeypot = data.honeypot;
          }
        } else if (Array.isArray(data)) {
          // Old shape fallback: flat array
          attackPoints = data;
        }

        // Fallback: if map is empty but sessions exist, use sessions + geoip
        if (attackPoints.length === 0) {
          try {
            const sessRes = await fetch(`${API}/api/sessions?limit=50`);
            const sessions = await sessRes.json();
            if (Array.isArray(sessions) && sessions.length > 0) {
              const uniqueIPs = [...new Set(sessions.map(s => s.attacker_ip).filter(Boolean))];
              const geoPoints = await Promise.all(
                uniqueIPs.map(async (ip) => {
                  try {
                    const geoRes = await fetch(`${API}/api/geoip/${ip}`);
                    const geo = await geoRes.json();
                    const session = sessions.find(s => s.attacker_ip === ip);
                    return {
                      session_id: session?.session_id || `geo-${ip}`,
                      ip,
                      latitude: geo.latitude,
                      longitude: geo.longitude,
                      country: geo.country_name || geo.country || "",
                      city: geo.city || "",
                      severity: session?.severity || "LOW",
                      risk_score: session?.risk_score || 0,
                      asn: geo.asn || "",
                      org: geo.org_name || geo.org || "",
                    };
                  } catch {
                    return null;
                  }
                })
              );
              attackPoints = geoPoints.filter(Boolean);
            }
          } catch {
            // Keep empty — friendly empty state, not an error
          }
        }

        // Use honeypot from API response, or fallback
        const finalHoneypot = honeypot || FALLBACK_HONEYPOT;
        if (!honeypot) {
          console.log("map: using fallback honeypot location");
        }

        setHoneypot(finalHoneypot);
        setPoints(attackPoints);
        setLastUpdated(new Date());
        setLoading(false);
        setError("");  // clear any previous error
      })
      .catch((err) => {
        console.error("map api error", err);
        setError("Failed to load map data");
        setLoading(false);
      });
  }, []);

  useEffect(() => {
    load();
    const interval = setInterval(load, 30000); // Auto-refresh every 30 seconds
    return () => clearInterval(interval);
  }, [load]);

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
              Updated {lastUpdated.toLocaleTimeString()} · auto-refresh 30s
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
              <Globe3D points={points} honeypot={honeypot} className="w-full h-full" />
            )}
          </div>
          <p className="text-xs text-muted mt-2 text-center">
            Drag to rotate · Arcs show attack paths to honeypot node in Astana
          </p>
        </div>

        {/* Attack list sidebar */}
        <div className="space-y-4">
          <div className="glass rounded-2xl p-4 neon-glow">
            <h2 className="text-sm font-bold text-white uppercase tracking-wider mb-3">Recent Attacks</h2>
            <div className="space-y-2 max-h-[500px] overflow-y-auto">
              {points.slice(0, 20).map((p, i) => (
                <div key={p.session_id || i} className="flex items-center gap-2 p-2 rounded-lg bg-surface/50 border border-border hover:border-accent-cyan/20 transition-colors">
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
                    <div className="text-[10px] text-muted truncate">{p.country || p.city}</div>
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