import Sparkline from "./Sparkline";
import { TrendingUp, TrendingDown, Minus } from "lucide-react";

export default function KpiCard({
  title,
  value,
  subtitle,
  sparkData,
    trend,
    trendValue,
  color = "cyan",
  icon: Icon,
  delay = 0,
}) {
  const colorMap = {
    cyan: {
      border: "border-accent-cyan/20",
      borderHover: "hover:border-accent-cyan/40",
      glow: "neon-glow",
      iconBg: "bg-accent-cyan/10",
      iconBorder: "border-accent-cyan/20",
      iconText: "text-accent-cyan",
      sparkColor: "#00E5FF",
      trendUp: "text-success",
      trendDown: "text-danger",
    },
    danger: {
      border: "border-danger/20",
      borderHover: "hover:border-danger/40",
      glow: "neon-glow-danger",
      iconBg: "bg-danger/10",
      iconBorder: "border-danger/20",
      iconText: "text-danger",
      sparkColor: "#FF4D4D",
      trendUp: "text-danger",
      trendDown: "text-success",
    },
    success: {
      border: "border-success/20",
      borderHover: "hover:border-success/40",
      glow: "neon-glow-success",
      iconBg: "bg-success/10",
      iconBorder: "border-success/20",
      iconText: "text-success",
      sparkColor: "#7CFF6B",
      trendUp: "text-success",
      trendDown: "text-danger",
    },
    warning: {
      border: "border-warning/20",
      borderHover: "hover:border-warning/40",
      glow: "neon-glow",
      iconBg: "bg-warning/10",
      iconBorder: "border-warning/20",
      iconText: "text-warning",
      sparkColor: "#FFB800",
      trendUp: "text-warning",
      trendDown: "text-danger",
    },
  };

  const c = colorMap[color] || colorMap.cyan;

  const TrendIcon = trend === "up" ? TrendingUp : trend === "down" ? TrendingDown : Minus;
  const trendColor = trend === "up" ? c.trendUp : trend === "down" ? c.trendDown : "text-muted";

  return (
    <div
      className={`
        relative group overflow-hidden rounded-2xl
        bg-surface/40 backdrop-blur-xl
        border ${c.border} ${c.borderHover}
        ${c.glow}
        transition-all duration-500 ease-out
        hover:scale-[1.02] hover:-translate-y-0.5
        cursor-default
      `}
      style={{ animationDelay: `${delay}ms` }}
    >
      {/* Gradient border top */}
      <div
        className="absolute top-0 left-0 right-0 h-px opacity-60 transition-opacity group-hover:opacity-100"
        style={{
          background: `linear-gradient(90deg, transparent, ${c.sparkColor}, transparent)`,
        }}
      />

      {/* Subtle radial glow on hover */}
      <div
        className="absolute -top-20 -right-20 w-40 h-40 rounded-full opacity-0 group-hover:opacity-20 transition-opacity duration-700 blur-3xl pointer-events-none"
        style={{ background: c.sparkColor }}
      />

      <div className="relative p-6">
        {/* Header */}
        <div className="flex items-start justify-between mb-4">
          <div className={`w-11 h-11 rounded-xl ${c.iconBg} border ${c.iconBorder} flex items-center justify-center transition-transform duration-300 group-hover:scale-110`}>
            <Icon className={`w-5 h-5 ${c.iconText}`} />
          </div>

          {trendValue !== 0 && (
            <div className={`flex items-center gap-1 px-2 py-1 rounded-full bg-white/5 border border-border text-xs font-semibold ${trendColor}`}>
              <TrendIcon className="w-3 h-3" />
              <span>{trendValue > 0 ? "+" : ""}{trendValue}%</span>
            </div>
          )}
        </div>

        {/* Value */}
        <div className="mb-1">
          <span className="text-3xl font-bold text-white tracking-tight group-hover:text-white transition-colors">
            {value}
          </span>
        </div>

        {/* Title */}
        <div className="text-sm font-medium text-muted mb-1">{title}</div>

        {/* Subtitle */}
        {subtitle && <div className="text-xs text-muted/60 mb-4">{subtitle}</div>}

        {/* Sparkline */}
        {sparkData && (
          <div className="mt-3 -mx-2">
            <Sparkline data={sparkData} color={c.sparkColor} height={36} />
          </div>
        )}

        {/* Bottom indicator bar */}
        <div className="mt-4 flex items-center gap-2">
          <div className="flex-1 h-1 rounded-full bg-white/5 overflow-hidden">
            <div
              className="h-full rounded-full transition-all duration-1000 ease-out"
              style={{
                width: `${Math.min(100, Math.max(20, (parseFloat(value?.toString().replace(/,/g, "")) || 0) % 100))}%`,
                background: `linear-gradient(90deg, ${c.sparkColor}40, ${c.sparkColor})`,
              }}
            />
          </div>
          <div
            className="w-1.5 h-1.5 rounded-full animate-pulse"
            style={{ background: c.sparkColor, boxShadow: `0 0 6px ${c.sparkColor}` }}
          />
        </div>
      </div>
    </div>
  );
}