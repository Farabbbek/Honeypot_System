import { useMemo, useEffect, useState } from "react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

function CustomTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="glass rounded-xl px-4 py-3 border border-border shadow-xl">
      <p className="text-xs text-muted font-mono mb-2">{label}</p>
      {payload.map((entry, i) => (
        <div key={i} className="flex items-center gap-2 text-xs">
          <div className="w-2 h-2 rounded-full" style={{ background: entry.color, boxShadow: `0 0 6px ${entry.color}` }} />
          <span className="text-white font-medium">{entry.name}:</span>
          <span className="font-mono font-bold" style={{ color: entry.color }}>{entry.value}</span>
        </div>
      ))}
    </div>
  );
}

export default function TimelineChart({ sessions = [], height = 320 }) {
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);

  const data = useMemo(() => {
    // Group sessions by hour for last 24h
    const now = new Date();
    const buckets = {};
    for (let i = 23; i >= 0; i--) {
      const d = new Date(now);
      d.setHours(d.getHours() - i, 0, 0, 0);
      const key = `${d.getHours().toString().padStart(2, "0")}:00`;
      buckets[key] = { time: key, attacks: 0, critical: 0, adaptive: 0 };
    }

    sessions.forEach((s) => {
      if (!s.start_time) return;
      const d = new Date(s.start_time);
      // find closest hour bucket
      const hour = d.getHours();
      const diff = now - d;
      if (diff > 24 * 60 * 60 * 1000) return; // ignore older than 24h

      // map to bucket key
      const keys = Object.keys(buckets);
      // find if it matches any bucket (within its hour)
      for (const key of keys) {
        const bucketHour = parseInt(key.split(":")[0]);
        if (bucketHour === hour) {
          buckets[key].attacks++;
          if (s.severity === "CRITICAL" || s.severity === "HIGH") {
            buckets[key].critical++;
          }
          if (s.adaptation_applied && s.adaptation_applied !== "__pending_analysis") {
            buckets[key].adaptive++;
          }
          break;
        }
      }
    });

    return Object.values(buckets);
  }, [sessions]);

  if (!mounted) {
    return <div className="glass rounded-2xl" style={{ height }}><div className="flex items-center justify-center h-full text-muted"><div className="w-5 h-5 rounded-full border-2 border-accent-cyan/30 border-t-accent-cyan animate-spin" /></div></div>;
  }

  return (
    <div className="glass rounded-2xl p-5 neon-glow overflow-hidden">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-sm font-bold text-white uppercase tracking-wider">24h Attack Timeline</h3>
          <p className="text-[10px] text-muted mt-0.5">Incoming attacks, critical incidents, adaptive responses</p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5">
            <div className="w-2 h-2 rounded-full bg-accent-cyan" style={{ boxShadow: "0 0 6px rgba(0,229,255,0.4)" }} />
            <span className="text-[10px] text-muted">Attacks</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="w-2 h-2 rounded-full bg-danger" style={{ boxShadow: "0 0 6px rgba(255,77,77,0.4)" }} />
            <span className="text-[10px] text-muted">Critical</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="w-2 h-2 rounded-full bg-success" style={{ boxShadow: "0 0 6px rgba(124,255,107,0.4)" }} />
            <span className="text-[10px] text-muted">Adaptive</span>
          </div>
        </div>
      </div>
      {data.every((d) => d.attacks === 0) ? (
        <div className="flex items-center justify-center" style={{ height }}>
          <p className="text-xs text-muted">No session data in the last 24 hours. Start Cowrie to see attacks here.</p>
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={height}>
          <AreaChart data={data} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
            <defs>
              <linearGradient id="gradAttacks" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#00E5FF" stopOpacity={0.15} /><stop offset="100%" stopColor="#00E5FF" stopOpacity={0} /></linearGradient>
              <linearGradient id="gradCritical" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#FF4D4D" stopOpacity={0.15} /><stop offset="100%" stopColor="#FF4D4D" stopOpacity={0} /></linearGradient>
              <linearGradient id="gradAdaptive" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#7CFF6B" stopOpacity={0.15} /><stop offset="100%" stopColor="#7CFF6B" stopOpacity={0} /></linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.06)" vertical={false} />
            <XAxis dataKey="time" tick={{ fill: "#64748b", fontSize: 10, fontFamily: "JetBrains Mono, monospace" }} tickLine={false} axisLine={{ stroke: "rgba(148,163,184,0.1)" }} />
            <YAxis tick={{ fill: "#64748b", fontSize: 10, fontFamily: "JetBrains Mono, monospace" }} tickLine={false} axisLine={false} />
            <Tooltip content={<CustomTooltip />} cursor={{ stroke: "rgba(148,163,184,0.15)", strokeWidth: 1 }} />
            <Area type="monotone" dataKey="attacks" stroke="#00E5FF" strokeWidth={2} fill="url(#gradAttacks)" dot={false} activeDot={{ r: 4, fill: "#00E5FF", stroke: "#07111f", strokeWidth: 2 }} />
            <Area type="monotone" dataKey="critical" stroke="#FF4D4D" strokeWidth={2} fill="url(#gradCritical)" dot={false} activeDot={{ r: 4, fill: "#FF4D4D", stroke: "#07111f", strokeWidth: 2 }} />
            <Area type="monotone" dataKey="adaptive" stroke="#7CFF6B" strokeWidth={2} fill="url(#gradAdaptive)" dot={false} activeDot={{ r: 4, fill: "#7CFF6B", stroke: "#07111f", strokeWidth: 2 }} />
          </AreaChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}