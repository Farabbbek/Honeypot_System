import { useMemo } from "react";

export default function Sparkline({ data, color = "#00E5FF", height = 40, strokeWidth = 2 }) {
  const width = 120;

  const { path, areaPath } = useMemo(() => {
    if (!data || data.length < 2) return { path: "", areaPath: "" };

    const max = Math.max(...data, 1);
    const min = Math.min(...data, 0);
    const range = max - min || 1;

    const points = data.map((val, i) => {
      const x = (i / (data.length - 1)) * width;
      const y = height - ((val - min) / range) * (height - 4) - 2;
      return `${x},${y}`;
    });

    const pathD = `M ${points.join(" L ")}`;

    const areaD = `${pathD} L ${width},${height} L 0,${height} Z`;

    return { path: pathD, areaPath: areaD };
  }, [data, height, width]);

  if (!data || data.length < 2) {
    return <div style={{ height, width }} className="opacity-30" />;
  }

  return (
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} className="overflow-visible">
      <defs>
        <linearGradient id={`spark-gradient-${color.replace("#", "")}`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.25" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      <path
        d={areaPath}
        fill={`url(#spark-gradient-${color.replace("#", "")})`}
        stroke="none"
      />
      <path
        d={path}
        fill="none"
        stroke={color}
        strokeWidth={strokeWidth}
        strokeLinecap="round"
        strokeLinejoin="round"
        className="drop-shadow-[0_0_4px_rgba(0,229,255,0.4)]"
      />
      {/* End dot */}
      <circle
        cx={width}
        cy={height - ((data[data.length - 1] - Math.min(...data, 0)) / (Math.max(...data, 1) - Math.min(...data, 0) || 1)) * (height - 4) - 2}
        r="3"
        fill={color}
        className="drop-shadow-[0_0_6px_rgba(0,229,255,0.6)]"
      />
    </svg>
  );
}