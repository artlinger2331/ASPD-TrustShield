import React, { useEffect, useState, useRef } from "react";
import { motion } from "framer-motion";
import { cn } from "@/utils/cn";

export function RiskGauge({ score = 0, size = 200, className }) {
  const containerRef = useRef(null);
  const [percent, setPercent] = useState(0);
  const [tilt, setTilt] = useState({ x: 10, y: -5 });

  // Smooth ease-out animated count-up
  useEffect(() => {
    let start = 0;
    const end = Math.max(0, Math.min(100, Number(score) || 0));
    const dur = 900;
    const startTime = performance.now();
    function frame(now) {
      const t = Math.min(1, (now - startTime) / dur);
      // Ease-out cubic
      const ease = 1 - Math.pow(1 - t, 3);
      const cur = start + (end - start) * ease;
      setPercent(cur);
      if (t < 1) requestAnimationFrame(frame);
    }
    requestAnimationFrame(frame);
  }, [score]);

  // Interactive mouse tilt physics
  const handleMouseMove = (e) => {
    if (!containerRef.current) return;
    const rect = containerRef.current.getBoundingClientRect();
    const x = (e.clientX - rect.left) / rect.width - 0.5;
    const y = (e.clientY - rect.top) / rect.height - 0.5;
    setTilt({
      x: -y * 22 + 8,
      y: x * 22 - 4,
    });
  };

  const handleMouseLeave = () => {
    setTilt({ x: 10, y: -5 });
  };

  // Color & severity config by score
  const getTheme = (val) => {
    if (val <= 30) {
      return {
        main: "#10b981",
        gradientStart: "#34d399",
        gradientEnd: "#059669",
        label: "SAFE",
        subLabel: "VERIFIED",
        glow: "rgba(16, 185, 129, 0.4)",
        badgeBg: "bg-emerald-500/15 text-emerald-300 border-emerald-500/40",
      };
    }
    if (val <= 50) {
      return {
        main: "#06b6d4",
        gradientStart: "#22d3ee",
        gradientEnd: "#0891b2",
        label: "SUSPICIOUS",
        subLabel: "ELEVATED",
        glow: "rgba(6, 182, 212, 0.4)",
        badgeBg: "bg-cyan-500/15 text-cyan-300 border-cyan-500/40",
      };
    }
    if (val <= 75) {
      return {
        main: "#f59e0b",
        gradientStart: "#fbbf24",
        gradientEnd: "#d97706",
        label: "HIGH RISK",
        subLabel: "WARNING",
        glow: "rgba(245, 158, 11, 0.45)",
        badgeBg: "bg-amber-500/15 text-amber-300 border-amber-500/40",
      };
    }
    return {
      main: "#ef4444",
      gradientStart: "#f87171",
      gradientEnd: "#dc2626",
      label: "DANGEROUS",
      subLabel: "CRITICAL",
      glow: "rgba(239, 68, 68, 0.5)",
      badgeBg: "bg-red-500/15 text-red-300 border-red-500/40",
    };
  };

  const theme = getTheme(score);

  // Geometry configuration: mathematically aligned to prevent any overlap
  const cx = size / 2;
  const cy = size / 2;
  const radius = size * 0.38;
  const strokeWidth = Math.max(6, size * 0.075);

  // Arc range: 140° to 400° (260° sweep, open at bottom)
  const startAngle = 140;
  const endAngle = 400;
  const totalSweep = endAngle - startAngle;
  const currentAngle = startAngle + (Math.min(100, Math.max(0, percent)) / 100) * totalSweep;

  const polarToCartesian = (centerX, centerY, r, angleInDeg) => {
    const rad = ((angleInDeg - 90) * Math.PI) / 180.0;
    return {
      x: centerX + r * Math.cos(rad),
      y: centerY + r * Math.sin(rad),
    };
  };

  const describeArc = (centerX, centerY, r, startA, endA) => {
    const start = polarToCartesian(centerX, centerY, r, endA);
    const end = polarToCartesian(centerX, centerY, r, startA);
    const largeArc = endA - startA <= 180 ? "0" : "1";
    return `M ${start.x} ${start.y} A ${r} ${r} 0 ${largeArc} 0 ${end.x} ${end.y}`;
  };

  // Paths
  const bgTrackPath = describeArc(cx, cy, radius, startAngle, endAngle);
  const bevelShadowPath = describeArc(cx, cy + 3.5, radius, startAngle, endAngle);
  const activeArcPath =
    percent > 0.5 ? describeArc(cx, cy, radius, startAngle, currentAngle) : "";

  // Tip of the active beam (laser beacon dot)
  const tipPos = polarToCartesian(cx, cy, radius, currentAngle);

  // Graduated Cyber Ticks (11 ticks along the arc)
  const TICKS_COUNT = 11;
  const ticks = Array.from({ length: TICKS_COUNT }).map((_, i) => {
    const tickVal = i * 10;
    const tickAngle = startAngle + (i / (TICKS_COUNT - 1)) * totalSweep;
    const pInner = polarToCartesian(cx, cy, radius - strokeWidth * 0.75, tickAngle);
    const pOuter = polarToCartesian(cx, cy, radius - strokeWidth * 0.35, tickAngle);
    const isActive = tickVal <= percent;
    return { tickVal, tickAngle, pInner, pOuter, isActive };
  });

  // Dynamic proportional font sizes based on size
  const scoreFontSize = Math.max(18, Math.round(size * 0.16));
  const maxFontSize = Math.max(9, Math.round(size * 0.065));
  const labelFontSize = Math.max(7, Math.round(size * 0.05));
  const badgeFontSize = Math.max(7, Math.round(size * 0.048));
  const hubSize = size * 0.52;

  // Endpoint labels positioned outside arc terminals with clean clearance
  const startP = polarToCartesian(cx, cy, radius + strokeWidth * 0.9, startAngle);
  const endP = polarToCartesian(cx, cy, radius + strokeWidth * 0.9, endAngle);

  return (
    <div
      ref={containerRef}
      onMouseMove={handleMouseMove}
      onMouseLeave={handleMouseLeave}
      className={cn(
        "relative flex flex-col items-center justify-center select-none cursor-pointer perspective-[1000px]",
        className
      )}
      style={{ width: size, height: size }}
    >
      {/* 3D Isometric Motion Wrapper */}
      <motion.div
        animate={{
          rotateX: tilt.x,
          rotateY: tilt.y,
        }}
        transition={{ type: "spring", stiffness: 220, damping: 24, mass: 0.6 }}
        style={{
          width: size,
          height: size,
          transformStyle: "preserve-3d",
        }}
        className="relative flex items-center justify-center"
      >
        {/* Layer -1: Ambient Floor Glow (Deep in Z) */}
        <div
          className="absolute rounded-full pointer-events-none blur-2xl"
          style={{
            width: size * 0.7,
            height: size * 0.7,
            transform: "translateZ(-30px)",
            background: `radial-gradient(circle, ${theme.glow} 0%, transparent 70%)`,
            transition: "background 0.5s ease",
          }}
        />

        {/* Layer 0 & 1: 3D Volumetric SVG Dial */}
        <svg
          width={size}
          height={size}
          className="block overflow-visible"
          style={{ transform: "translateZ(0px)" }}
        >
          <defs>
            {/* Dynamic Active Energy Gradient */}
            <linearGradient id={`gaugeGrad_${size}`} x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor={theme.gradientStart} />
              <stop offset="100%" stopColor={theme.gradientEnd} />
            </linearGradient>

            {/* Neon Glow Filter */}
            <filter id={`gaugeGlow_${size}`} x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="2.5" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>

            {/* Inset Depth Shadow */}
            <filter id={`depthShadow_${size}`} x="-10%" y="-10%" width="120%" height="120%">
              <feDropShadow dx="0" dy="2" stdDeviation="1.5" floodColor="#000000" floodOpacity="0.8" />
            </filter>
          </defs>

          {/* Extruded Bevel Base (gives real 3D physical thickness) */}
          <path
            d={bevelShadowPath}
            fill="none"
            stroke="#070c18"
            strokeWidth={strokeWidth + 2.5}
            strokeLinecap="round"
            opacity="0.9"
          />

          {/* Recessed Track Base (Metallic Slot) */}
          <path
            d={bgTrackPath}
            fill="none"
            stroke="#131d31"
            strokeWidth={strokeWidth}
            strokeLinecap="round"
            filter={`url(#depthShadow_${size})`}
          />

          {/* Subtle Outer Cyber Track Edge Ring */}
          <path
            d={describeArc(cx, cy, radius + strokeWidth * 0.65, startAngle, endAngle)}
            fill="none"
            stroke="rgba(255, 255, 255, 0.08)"
            strokeWidth="1"
            strokeDasharray="2 3"
          />

          {/* Graduated Cyber Tick Marks */}
          {ticks.map((t, idx) => (
            <line
              key={idx}
              x1={t.pInner.x}
              y1={t.pInner.y}
              x2={t.pOuter.x}
              y2={t.pOuter.y}
              stroke={t.isActive ? theme.main : "rgba(255, 255, 255, 0.15)"}
              strokeWidth={idx === 0 || idx === 5 || idx === 10 ? "2" : "1"}
              strokeLinecap="round"
              className="transition-colors duration-300"
            />
          ))}

          {/* Active Energy Beam (Filled glowing arc) */}
          {percent > 0.5 && (
            <path
              d={activeArcPath}
              fill="none"
              stroke={`url(#gaugeGrad_${size})`}
              strokeWidth={strokeWidth}
              strokeLinecap="round"
              filter={`url(#gaugeGlow_${size})`}
              style={{
                filter: `drop-shadow(0 0 5px ${theme.main})`,
              }}
            />
          )}

          {/* Inner Specular Highlight Ridge */}
          {percent > 0.5 && (
            <path
              d={describeArc(cx, cy, radius - strokeWidth * 0.28, startAngle, currentAngle)}
              fill="none"
              stroke="rgba(255, 255, 255, 0.45)"
              strokeWidth="1"
              strokeLinecap="round"
            />
          )}

          {/* Pulsing Laser Beacon Dot at Beam Tip */}
          {percent > 0.5 && (
            <g transform={`translate(${tipPos.x}, ${tipPos.y})`}>
              <circle r={strokeWidth * 0.5} fill={theme.main} opacity="0.3" className="animate-ping" />
              <circle r={strokeWidth * 0.38} fill="#ffffff" filter={`url(#gaugeGlow_${size})`} />
              <circle r={strokeWidth * 0.22} fill={theme.main} />
            </g>
          )}

          {/* Scale Endpoint Labels: positioned outside the arc with zero overlap */}
          <text
            x={startP.x - 2}
            y={startP.y + 7}
            fill="#64748b"
            fontSize={Math.max(7, Math.round(size * 0.046))}
            fontFamily="monospace"
            textAnchor="end"
          >
            0
          </text>
          <text
            x={endP.x + 2}
            y={endP.y + 7}
            fill="#64748b"
            fontSize={Math.max(7, Math.round(size * 0.046))}
            fontFamily="monospace"
            textAnchor="start"
          >
            100
          </text>
        </svg>

        {/* Layer 2: Floating 3D Holographic Center Hub (Exactly Concentric at cx, cy) */}
        <div
          className="absolute flex flex-col items-center justify-center pointer-events-none"
          style={{
            left: cx,
            top: cy,
            transform: "translate(-50%, -50%) translateZ(24px)",
            width: hubSize,
            height: hubSize,
          }}
        >
          {/* Glass Pedestal Disc */}
          <div
            className="w-full h-full rounded-full flex flex-col items-center justify-center border border-white/10 backdrop-blur-md shadow-2xl relative"
            style={{
              backgroundColor: "rgba(8, 14, 28, 0.82)",
              boxShadow: `0 6px 20px -3px ${theme.glow}, inset 0 1px 2px rgba(255, 255, 255, 0.18)`,
            }}
          >
            {/* Inner Cyber Glow Ring */}
            <div
              className="absolute inset-1 rounded-full border border-white/5 pointer-events-none"
              style={{
                boxShadow: `inset 0 0 10px ${theme.glow}`,
              }}
            />

            {/* Score Number with 3D Emboss & Dynamic Glow */}
            <div className="flex items-baseline justify-center leading-none">
              <span
                className="font-extrabold tracking-tight font-mono text-white transition-all duration-300"
                style={{
                  fontSize: `${scoreFontSize}px`,
                  textShadow: `0 0 14px ${theme.main}, 0 2px 4px rgba(0,0,0,0.9)`,
                }}
              >
                {Math.round(percent)}
              </span>
              <span
                className="font-mono text-slate-400 font-bold ml-0.5"
                style={{ fontSize: `${maxFontSize}px` }}
              >
                /100
              </span>
            </div>

            {/* "RISK SCORE" Label */}
            <span
              className="font-mono tracking-widest uppercase text-slate-400 font-semibold mt-0.5"
              style={{ fontSize: `${labelFontSize}px` }}
            >
              Risk Score
            </span>

            {/* Severity Status Pill */}
            <div
              className={cn(
                "rounded-full border font-mono font-bold tracking-wider uppercase transition-colors duration-300 mt-1 px-1.5 py-0.5 leading-none",
                theme.badgeBg
              )}
              style={{ fontSize: `${badgeFontSize}px` }}
            >
              {theme.label}
            </div>
          </div>
        </div>
      </motion.div>
    </div>
  );
}