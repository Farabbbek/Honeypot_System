import { useEffect, useState, useRef } from "react";
import { MapContainer, TileLayer, Marker, Popup, Tooltip, Polyline, useMap } from "react-leaflet";
import L from "leaflet";
import "leaflet/dist/leaflet.css";

// Fix default Leaflet icon paths
delete L.Icon.Default.prototype._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: "https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon-2x.png",
  iconUrl: "https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon.png",
  shadowUrl: "https://unpkg.com/leaflet@1.9.4/dist/images/marker-shadow.png",
});

// Dark tile layer — CartoDB dark
const TILE_URL = "https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png";
const ATTRIBUTION = '&copy; <a href="https://carto.com/">CARTO</a>';

const SERVER_POS = [51.17, 71.45]; // Astana

// Custom icons
const serverIcon = L.divIcon({
  className: "",
  html: '<div style="width:16px;height:16px;background:#7CFF6B;border-radius:50%;border:2px solid #fff;box-shadow:0 0 12px rgba(124,255,107,0.6);" />',
  iconSize: [16, 16],
  iconAnchor: [8, 8],
});

function createAttackerIcon(severity) {
  const color = severity === "CRITICAL" ? "#FF4D4D" : severity === "HIGH" ? "#FFB800" : "#00E5FF";
  const glow = severity === "CRITICAL" ? "rgba(255,77,77,0.6)" : severity === "HIGH" ? "rgba(255,184,0,0.5)" : "rgba(0,229,255,0.5)";
  return L.divIcon({
    className: "",
    html: `<div style="width:12px;height:12px;background:${color};border-radius:50%;border:2px solid rgba(255,255,255,0.9);box-shadow:0 0 10px ${glow};" />`,
    iconSize: [12, 12],
    iconAnchor: [6, 6],
  });
}

// Map controller to set view on load
function MapController() {
  const map = useMap();
  useEffect(() => {
    map.setView(SERVER_POS, 4, { animate: true });
  }, [map]);
  return null;
}

export default function AttackMap({ points = [], height = "500px" }) {
  if (typeof window === "undefined") {
    return <div style={{ height, background: "#0a1628" }} />;
  }

  const validPoints = points.filter((p) => p.latitude && p.longitude);

  return (
    <div style={{ height, borderRadius: "1rem", overflow: "hidden" }} className="neon-glow">
      <MapContainer
        center={SERVER_POS}
        zoom={3}
        style={{ height: "100%", width: "100%", background: "#0a1628" }}
        zoomControl={false}
        attributionControl={false}
        scrollWheelZoom={true}
        dragging={true}
      >
        <MapController />
        <TileLayer url={TILE_URL} attribution={ATTRIBUTION} />

        {/* Server marker */}
        <Marker position={SERVER_POS} icon={serverIcon}>
          <Tooltip permanent direction="top" offset={[0, -10]}>
            <div style={{ fontSize: "11px", fontWeight: 700, color: "#7CFF6B" }}>
              ADAPTIVEPOT Node
            </div>
            <div style={{ fontSize: "10px", color: "#94a3b8" }}>
              Astana, KZ · 51.17°N 71.45°E
            </div>
          </Tooltip>
        </Marker>

        {/* Attacker markers + arcs */}
        {validPoints.map((p, i) => (
          <div key={p.session_id || i}>
            <Marker
              position={[p.latitude, p.longitude]}
              icon={createAttackerIcon(p.severity)}
            >
              <Tooltip direction="top" offset={[0, -8]}>
                <div style={{ fontSize: "11px", fontWeight: 700, color: "#fff", fontFamily: "monospace" }}>
                  {p.ip}
                </div>
                <div style={{ fontSize: "10px", color: "#94a3b8" }}>
                  {[p.city, p.country].filter(Boolean).join(", ") || "Unknown location"}
                </div>
                <div style={{ fontSize: "9px", marginTop: 2 }}>
                  <span
                    style={{
                      color:
                        p.severity === "CRITICAL"
                          ? "#FF4D4D"
                          : p.severity === "HIGH"
                          ? "#FFB800"
                          : "#00E5FF",
                      fontWeight: 700,
                    }}
                  >
                    {p.severity}
                  </span>
                </div>
              </Tooltip>
            </Marker>
            <Polyline
              positions={[[p.latitude, p.longitude], SERVER_POS]}
              pathOptions={{
                color:
                  p.severity === "CRITICAL" || p.severity === "HIGH"
                    ? "rgba(255,77,77,0.35)"
                    : "rgba(0,229,255,0.25)",
                weight: 1.5,
                dashArray: "4 4",
              }}
            />
          </div>
        ))}
      </MapContainer>

      {/* Stats overlay */}
      <div style={{ position: "absolute", bottom: 12, left: 12, display: "flex", gap: 8 }}>
        <div className="glass rounded-lg px-3 py-1.5 text-xs">
          <span className="text-white font-mono">{validPoints.length} attackers</span>
        </div>
        <div className="glass rounded-lg px-3 py-1.5 text-xs">
          <span className="text-danger font-mono">
            {validPoints.filter((p) => p.severity === "CRITICAL" || p.severity === "HIGH").length} critical
          </span>
        </div>
      </div>
    </div>
  );
}