"use client"

import { useEffect, useRef, useCallback, useState, useMemo } from "react"
import createGlobe from "cobe"

const HONEYPOT = { lat: 51.17, lng: 71.45 }

// ── helpers ──────────────────────────────────────────────────────────────────
function latLngToVec3(lat, lng) {
  const phi   = (90 - lat) * (Math.PI / 180)
  const theta = lng       * (Math.PI / 180)
  return {
    x: Math.sin(phi) * Math.cos(theta),
    y: Math.cos(phi),
    z: Math.sin(phi) * Math.sin(theta),
  }
}

function rotateVec(v, rPhi, rTheta) {
  const cp = Math.cos(rPhi), sp = Math.sin(rPhi)
  const ct = Math.cos(rTheta), st = Math.sin(rTheta)
  const x1 =  v.x * cp - v.z * sp
  const z1 =  v.x * sp + v.z * cp
  const y2 =  v.y * ct - z1 * st
  const z2 =  v.y * st + z1 * ct
  return { x: x1, y: y2, z: z2 }
}

function projectOnCanvas(v, w, h) {
  if (v.z < -0.05) return null
  return {
    x: w / 2 + v.x * (w / 2) * 1.18,
    y: h / 2 - v.y * (h / 2) * 1.18,
  }
}

function sevColor(sev) {
  if (sev === "CRITICAL") return "#FF4D4D"
  if (sev === "HIGH")     return "#FFB800"
  if (sev === "SERVER")   return "#7CFF6B"
  return "#00E5FF"
}

function sevArcColor(sev) {
  if (sev === "CRITICAL") return [1, 0.2, 0.2]
  if (sev === "HIGH")     return [1, 0.72, 0]
  return [0, 0.9, 1]
}

// ── component ─────────────────────────────────────────────────────────────────
export default function Globe3D({ points = [], className = "" }) {
  const canvasRef    = useRef(null)
  const containerRef = useRef(null)
  const globeRef     = useRef(null)

  // Rotation state — all refs to avoid re-renders
  const phiRef          = useRef(0)
  const phiOffsetRef    = useRef(0)
  const thetaOffsetRef  = useRef(0.2)
  const dragStartRef    = useRef(null)
  const isDraggingRef   = useRef(false)

  const [tooltip, setTooltip] = useState(null) // { x, y, marker }
  const [clicked, setClicked] = useState(null) // sticky marker

  // ── memoised data (stable references → no globe destroy on every render) ──
  const validPoints = useMemo(
    () => points.filter((p) => p.latitude != null && p.longitude != null),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [JSON.stringify(points)]
  )

  const markers = useMemo(() => [
    ...validPoints.map((p, i) => ({
      id:       p.session_id || `atk-${i}`,
      location: [p.latitude, p.longitude],
      size:     p.severity === "CRITICAL" ? 0.048 : p.severity === "HIGH" ? 0.036 : 0.026,
      ip:       p.ip           || "Unknown",
      country:  p.country      || "Unknown",
      city:     p.city         || "",
      severity: p.severity     || "LOW",
      risk:     p.risk_score   ?? null,
      asn:      p.asn          || "",
      org:      p.org          || "",
      tactic:   p.current_tactic || "",
      tactics:  Array.isArray(p.tactics) ? p.tactics : [],
    })),
    {
      id:       "honeypot",
      location: [HONEYPOT.lat, HONEYPOT.lng],
      size:     0.06,
      ip:       "Honeypot Node",
      country:  "Kazakhstan",
      city:     "Astana",
      severity: "SERVER",
      risk: null, asn: "", org: "", tactic: "", tactics: [],
    },
  // eslint-disable-next-line react-hooks/exhaustive-deps
  ], [validPoints])

  const cobeMarkers = useMemo(
    () => markers.map((m) => ({ location: m.location, size: m.size })),
    [markers]
  )

  const cobeArcs = useMemo(
    () => validPoints.map((p) => ({
      startLat: p.latitude,
      startLng: p.longitude,
      endLat:   HONEYPOT.lat,
      endLng:   HONEYPOT.lng,
      color:    sevArcColor(p.severity),
    })),
    [validPoints]
  )

  const hasCritical = useMemo(
    () => validPoints.some((p) => p.severity === "CRITICAL" || p.severity === "HIGH"),
    [validPoints]
  )
  const glowColor = useMemo(
    () => hasCritical ? [0.15, 0.05, 0.05] : [0.05, 0.1, 0.16],
    [hasCritical]
  )

  // ── pointer / drag ────────────────────────────────────────────────────────
  const handlePointerDown = useCallback((e) => {
    e.preventDefault()
    isDraggingRef.current = true
    dragStartRef.current  = {
      x:     e.clientX,
      y:     e.clientY,
      phi:   phiOffsetRef.current,
      theta: thetaOffsetRef.current,
    }
    if (canvasRef.current) canvasRef.current.style.cursor = "grabbing"
  }, [])

  useEffect(() => {
    const onMove = (e) => {
      if (!isDraggingRef.current || !dragStartRef.current) return
      const dx = e.clientX - dragStartRef.current.x
      const dy = e.clientY - dragStartRef.current.y
      phiOffsetRef.current   = dragStartRef.current.phi   + dx / 200
      thetaOffsetRef.current = Math.max(-0.65, Math.min(0.65,
        dragStartRef.current.theta + dy / 500))
    }
    const onUp = () => {
      isDraggingRef.current = false
      dragStartRef.current  = null
      if (canvasRef.current) canvasRef.current.style.cursor = "grab"
    }
    window.addEventListener("pointermove", onMove, { passive: true })
    window.addEventListener("pointerup",   onUp,   { passive: true })
    return () => {
      window.removeEventListener("pointermove", onMove)
      window.removeEventListener("pointerup",   onUp)
    }
  }, [])

  // ── hit test (uses CANVAS bounding rect, not container) ───────────────────
  const hitTest = useCallback((clientX, clientY) => {
    const canvas = canvasRef.current
    if (!canvas) return null
    const r = canvas.getBoundingClientRect()
    const mx = clientX - r.left
    const my = clientY - r.top
    const w  = r.width
    const h  = r.height
    const curPhi   = phiRef.current + phiOffsetRef.current
    const curTheta = thetaOffsetRef.current
    let bestDist   = 30
    let best       = null
    for (const m of markers) {
      const v  = latLngToVec3(m.location[0], m.location[1])
      const rv = rotateVec(v, curPhi, curTheta)
      const s  = projectOnCanvas(rv, w, h)
      if (!s) continue
      const d = Math.hypot(s.x - mx, s.y - my)
      if (d < bestDist) { bestDist = d; best = m }
    }
    return best
  }, [markers])

  const handleMouseMove = useCallback((e) => {
    const m = hitTest(e.clientX, e.clientY)
    setTooltip(m ? { x: e.clientX, y: e.clientY, marker: m } : null)
  }, [hitTest])

  const handleMouseLeave = useCallback(() => setTooltip(null), [])

  const handleClick = useCallback((e) => {
    const m = hitTest(e.clientX, e.clientY)
    if (m) {
      setClicked((prev) => (prev?.id === m.id ? null : m))
    } else {
      setClicked(null)
    }
  }, [hitTest])

  // ── globe creation ────────────────────────────────────────────────────────
  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return

    let raf = null

    const create = () => {
      if (globeRef.current) return // already created

      // Use the container div for size measurement (not canvas itself)
      const container = containerRef.current
      if (!container) return
      const pw   = container.clientWidth
      const ph   = container.clientHeight
      const size = Math.min(pw, ph)
      if (size < 50) return // layout not ready yet

      // Size the canvas
      const dpr = Math.min(window.devicePixelRatio || 1, 2)
      canvas.width  = size * dpr
      canvas.height = size * dpr
      canvas.style.width  = size + "px"
      canvas.style.height = size + "px"

      globeRef.current = createGlobe(canvas, {
        devicePixelRatio: dpr,
        width:  size * dpr,
        height: size * dpr,
        phi:    0,
        theta:  0.2,
        dark:   1,
        diffuse: 1.4,
        mapSamples:    28000,
        mapBrightness: 8,
        baseColor:    [0.12, 0.15, 0.23],
        markerColor:  [0, 0.9, 1],
        glowColor,
        markers: cobeMarkers,
        markerElevation: 0,
        arcs:    cobeArcs,
        arcAltitude:  0.35,
        arcColor:     (arc) => arc.color || [0, 0.9, 1],
        arcWidth:     1.0,
        arcDashLength: 0.9,
        arcDashGap:   2,
        arcDashAnimateTime: 2000,
        opacity: 0.92,
        scale:   1.14,
        onRender: (state) => {
          if (!isDraggingRef.current) phiRef.current += 0.003
          state.phi   = phiRef.current + phiOffsetRef.current
          state.theta = thetaOffsetRef.current
        },
      })

      canvas.style.opacity = "1"
    }

    // Defer first creation one frame to ensure layout is stable
    raf = requestAnimationFrame(() => {
      create()

      const ro = new ResizeObserver(() => {
        if (globeRef.current) {
          globeRef.current.destroy()
          globeRef.current = null
          canvas.style.opacity = "0"
        }
        create()
      })
      if (containerRef.current) ro.observe(containerRef.current)

      // store ro for cleanup
      canvas._ro = ro
    })

    return () => {
      if (raf) cancelAnimationFrame(raf)
      if (canvas._ro) { canvas._ro.disconnect(); delete canvas._ro }
      if (globeRef.current) {
        globeRef.current.destroy()
        globeRef.current = null
      }
    }
  // Only recreate when actual data changes (markers, arcs, glowColor are memoised)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [cobeMarkers, cobeArcs, glowColor])

  // ── popup position ────────────────────────────────────────────────────────
  const activeMarker = clicked || tooltip?.marker
  const isSticky     = !!clicked

  let popupLeft = 0, popupTop = 0
  if (activeMarker) {
    if (isSticky && canvasRef.current) {
      const r   = canvasRef.current.getBoundingClientRect()
      const v   = latLngToVec3(activeMarker.location[0], activeMarker.location[1])
      const rv  = rotateVec(v, phiRef.current + phiOffsetRef.current, thetaOffsetRef.current)
      const s   = projectOnCanvas(rv, r.width, r.height)
      if (s) {
        popupLeft = r.left + s.x + 16
        popupTop  = r.top  + s.y - 16
      } else {
        popupLeft = r.left + r.width  / 2 + 16
        popupTop  = r.top  + r.height / 2 - 16
      }
    } else if (tooltip) {
      popupLeft = tooltip.x + 16
      popupTop  = tooltip.y - 16
    }
  }

  // ── render ────────────────────────────────────────────────────────────────
  return (
    <div
      ref={containerRef}
      className={`relative w-full h-full flex items-center justify-center select-none overflow-hidden ${className}`}
      onMouseMove={handleMouseMove}
      onMouseLeave={handleMouseLeave}
      onClick={handleClick}
    >
      <canvas
        ref={canvasRef}
        onPointerDown={handlePointerDown}
        style={{
          cursor:     "grab",
          opacity:    0,
          transition: "opacity 1.0s ease",
          touchAction: "none",
          display:    "block",
          flexShrink: 0,
        }}
      />

      {/* ── Popup ─────────────────────────────────────────────────────────── */}
      {activeMarker && (
        <div
          className="fixed z-50 pointer-events-none"
          style={{ left: popupLeft, top: popupTop }}
        >
          <div
            className="rounded-xl px-4 py-3 shadow-2xl border backdrop-blur-md min-w-[210px] max-w-[270px]"
            style={{
              background:  "rgba(7,17,31,0.97)",
              borderColor: sevColor(activeMarker.severity) + "40",
            }}
          >
            {/* IP row */}
            <div className="flex items-center gap-2 mb-2">
              <div
                className="w-2.5 h-2.5 rounded-full shrink-0 animate-pulse"
                style={{
                  background: sevColor(activeMarker.severity),
                  boxShadow:  `0 0 8px ${sevColor(activeMarker.severity)}80`,
                }}
              />
              <span
                className="font-mono text-xs font-bold truncate"
                style={{ color: sevColor(activeMarker.severity) }}
              >
                {activeMarker.ip}
              </span>
            </div>

            {/* Location */}
            <div className="text-[10px] text-slate-400 mb-2">
              {[activeMarker.city, activeMarker.country].filter(Boolean).join(", ") || "Unknown Location"}
            </div>

            {activeMarker.severity === "SERVER" ? (
              <div className="text-[10px] text-slate-500">
                Honeypot node · 51.17°N 71.45°E
              </div>
            ) : (
              <>
                {/* Severity + Risk */}
                <div className="flex items-center justify-between mb-2">
                  <span
                    className="text-[10px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded"
                    style={{
                      color:      sevColor(activeMarker.severity),
                      background: sevColor(activeMarker.severity) + "20",
                      border:    `1px solid ${sevColor(activeMarker.severity)}40`,
                    }}
                  >
                    {activeMarker.severity}
                  </span>
                  {activeMarker.risk != null && (
                    <span className="text-[10px] text-slate-400">
                      Risk: <span className="text-white font-mono font-bold">{activeMarker.risk}</span>
                    </span>
                  )}
                </div>

                {/* ASN / Org */}
                {(activeMarker.asn || activeMarker.org) && (
                  <div className="space-y-0.5 mb-2">
                    {activeMarker.asn && (
                      <div className="text-[10px]">
                        <span className="text-slate-500">ASN: </span>
                        <span className="font-mono text-slate-300">{activeMarker.asn}</span>
                      </div>
                    )}
                    {activeMarker.org && (
                      <div className="text-[10px] truncate">
                        <span className="text-slate-500">Org: </span>
                        <span className="text-slate-300">{activeMarker.org}</span>
                      </div>
                    )}
                  </div>
                )}

                {/* Current tactic */}
                {activeMarker.tactic && (
                  <div className="text-[10px] mb-2">
                    <span className="text-slate-500">Tactic: </span>
                    <span className="text-cyan-300 font-mono">{activeMarker.tactic}</span>
                  </div>
                )}

                {/* Tactics chain */}
                {activeMarker.tactics.length > 0 && (
                  <div className="mb-1">
                    <div className="text-[9px] text-slate-500 uppercase tracking-wider mb-1">Attack Chain</div>
                    <div className="flex flex-wrap gap-1">
                      {activeMarker.tactics.slice(0, 5).map((t, i) => (
                        <span
                          key={i}
                          className="text-[9px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700"
                        >
                          {t}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {isSticky && (
                  <div className="text-[9px] text-slate-600 mt-2 text-center">
                    click anywhere to close
                  </div>
                )}
              </>
            )}
          </div>
        </div>
      )}

      {/* ── Bottom-left badge ─────────────────────────────────────────────── */}
      <div className="absolute bottom-4 left-4 glass rounded-lg px-3 py-2 text-xs pointer-events-none z-10">
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          <span className="text-white font-mono">Honeypot Node</span>
        </div>
        <div className="text-slate-400 mt-0.5">Astana, KZ · 51.17°N 71.45°E</div>
      </div>

      {/* ── Top-right counter ─────────────────────────────────────────────── */}
      <div className="absolute top-4 right-4 glass rounded-lg px-3 py-2 text-xs text-right pointer-events-none z-10">
        <div className="text-white font-mono">{validPoints.length} attacks</div>
        <div className="text-slate-400 mt-0.5">
          {validPoints.filter((p) => p.severity === "CRITICAL" || p.severity === "HIGH").length} high / critical
        </div>
      </div>
    </div>
  )
}
