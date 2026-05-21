import { useEffect, useState } from "react";
import {
  Terminal,
  Globe,
  Database,
  Shield,
  Activity,
  Clock,
  Users,
  Server,
  Wifi,
  WifiOff,
} from "lucide-react";

const SERVICE_ICONS = {
  ssh: Terminal,
  http: Globe,
  database: Database,
  default: Server,
};

const STATUS_CONFIG = {
  online: {
    color: "#7CFF6B",
    bg: "rgba(124, 255, 107, 0.08)",
    border: "rgba(124, 255, 107, 0.2)",
    glow: "0 0 20px rgba(124, 255, 107, 0.1)",
    iconBg: "bg-success/10",
    iconBorder: "border-success/20",
    label: "ONLINE",
  },
  degraded: {
    color: "#FFB800",
    bg: "rgba(255, 184, 0, 0.08)",
    border: "rgba(255, 184, 0, 0.2)",
    glow: "0 0 20px rgba(255, 184, 0, 0.1)",
    iconBg: "bg-warning/10",
    iconBorder: "border-warning/20",
    label: "DEGRADED",
  },
  offline: {
    color: "#FF4D4D",
    bg: "rgba(255, 77, 77, 0.08)",
    border: "rgba(255, 77, 77, 0.2)",
    glow: "0 0 20px rgba(255, 77, 77, 0.1)",
    iconBg: "bg-danger/10",
    iconBorder: "border-danger/20",
    label: "OFFLINE",
  },
};

function formatUptime(seconds) {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${mins}m`;
  return `${mins}m`;
}

export default function HoneypotNodeCard({
  name,
  service = "ssh",
  status = "online",
  uptime = 3600,
  attackers = 0,
  port = 2222,
  location = "Almaty, KZ",
  onClick,
}) {
  const Icon = SERVICE_ICONS[service] || SERVICE_ICONS.default;
  const cfg = STATUS_CONFIG[status] || STATUS_CONFIG.online;

  return (
    <div
      onClick={onClick}
      className={`
        relative group overflow-hidden rounded-2xl
        bg-surface/40 backdrop-blur-xl
        border border-border
        transition-all duration-500 ease-out
        hover:scale-[1.02] hover:-translate-y-0.5
        ${onClick ? "cursor-pointer" : "cursor-default"}
      `}
      style={{ boxShadow: cfg.glow }}
    >
      {/* Top gradient border */}
      <div
        className="absolute top-0 left-0 right-0 h-px opacity-60 transition-opacity group-hover:opacity-100"
        style={{
          background: `linear-gradient(90deg, transparent, ${cfg.color}, transparent)`,
        }}
      />

      {/* Radial glow on hover */}
      <div
        className="absolute -top-16 -right-16 w-32 h-32 rounded-full opacity-0 group-hover:opacity-15 transition-opacity duration-700 blur-2xl pointer-events-none"
        style={{ background: cfg.color }}
      />

      <div className="relative p-5">
        {/* Header */}
        <div className="flex items-start justify-between mb-4">
          <div className={`w-10 h-10 rounded-xl ${cfg.iconBg} border ${cfg.iconBorder} flex items-center justify-center transition-transform duration-300 group-hover:scale-110`}>
            <Icon className="w-5 h-5" style={{ color: cfg.color }} />
          </div>

          <div
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-bold tracking-wider border"
            style={{
              background: cfg.bg,
              color: cfg.color,
              borderColor: cfg.border,
            }}
          >
            <div
              className={`w-1.5 h-1.5 rounded-full ${status === "online" ? "animate-pulse" : ""}`}
              style={{ background: cfg.color, boxShadow: `0 0 4px ${cfg.color}` }}
            />
            {cfg.label}
          </div>
        </div>

        {/* Name & service */}
        <h3 className="text-sm font-bold text-white mb-0.5 group-hover:text-white transition-colors">
          {name}
        </h3>
        <p className="text-[10px] text-muted uppercase tracking-wider mb-4">
          {service} · Port {port}
        </p>

        {/* Metrics */}
        <div className="space-y-2.5">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs text-muted">
              <Clock className="w-3.5 h-3.5" />
              Uptime
            </div>
            <span className="text-xs font-mono font-bold text-white">{formatUptime(uptime)}</span>
          </div>

          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs text-muted">
              <Users className="w-3.5 h-3.5" />
              Active Attackers
            </div>
            <span
              className="text-xs font-mono font-bold"
              style={{ color: attackers > 0 ? "#FF4D4D" : "#7CFF6B" }}
            >
              {attackers}
            </span>
          </div>

          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs text-muted">
              <Shield className="w-3.5 h-3.5" />
              Location
            </div>
            <span className="text-xs font-mono text-white/70">{location}</span>
          </div>
        </div>

        {/* Bottom bar */}
        <div className="mt-4 pt-3 border-t border-border flex items-center justify-between">
          <div className="flex items-center gap-1.5">
            <Activity className="w-3 h-3 text-muted" />
            <span className="text-[10px] text-muted">Health Check</span>
          </div>
          <span className="text-[10px] font-mono" style={{ color: cfg.color }}>
            {status === "online" ? "PASSING" : status === "degraded" ? "WARNING" : "FAILING"}
          </span>
        </div>
      </div>
    </div>
  );
}