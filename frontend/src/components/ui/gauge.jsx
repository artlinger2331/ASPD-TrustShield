import React, { useEffect, useState, useRef } from "react";
import { motion } from "framer-motion";
import { cn } from "@/utils/cn";

export function RiskGauge({ score = 0, size = 220, className }) {
  const containerRef = useRef(null);
  const [percent, setPercent] = useState(0);
  const [tilt, setTilt] = useState({ x: 12, y: -6 });

  // Smooth animated count-up
  useEffect(() => {
    let start = 0;
    const end = Math.max(0, Math.min(100, score));
    const dur = 950;
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

  // Mouse tilt physics
  const handleMouseMove = (e) => {
    if (!containerRef.current) return;
    const rect = containerRef.current.getBoundingClientRect();
    const x = (e.clientX - rect.left) / rect.width - 0.5;
    const y = (e.clientY - rect.top) / rect.height - 0.5;
    setTilt({
      x: -y * 24 + 10,
      y: x * 24 - 4,
    });
  };

  const handleMouseLeave = () => {
    setTilt({ x: 12, y: -6 });
  };

  // Color & severity config by score
  const getTheme = (val) => {
    if (val <= 30) {
      return {
        main: "#10b981",
        gradientStart: "#34d399",
        gradientEnd: "#059669",
        label: "SAFE // VERIFIED",
        glow: "rgba(16, 185, 129, 0.4)",
        badgeBg: "bg-emerald-500/10 text-emerald-300 border-emerald-500/30",
      };
    }
    if (val <= 50) {
      return {
        main: "#06b6d4",
        gradientStart: "#22d3ee",
        gradientEnd: "#0891b2",
        label: "SUSPICIOUS",
        glow: "rgba(6, 182, 212, 0.4)",
        badgeBg: "bg-cyan-500/10 text-cyan-300 border-cyan-500/30",
      };
    }
    if (val <= 75) {
      return {
        main: "#f59e0b",
        gradientStart: "#fbbf24",
        gradientEnd: "#d97706",
        label: "HIGH RISK",
        glow: "rgba(245, 158, 11, 0.45)",
        badgeBg: "bg-amber-500/10 text-amber-300 border-amber-500/30",
      };
    }
    return {
      main: "#ef4444",
      gradientStart: "#f87171",
      gradientEnd: "#dc2626",
      label: "CRITICAL DANGER",
      glow: "rgba(239, 68, 68, 0.5)",
      badgeBg: "bg-red-500/10 text-red-300 border-red-500/30",
    };
  };

  const theme = getTheme(score);

  // SVG Gauge Geometry
  const cx = size / 2;
  const cy = size / 2 + 10;
  const radius = size * 0.38;
  const strokeWidth = size * 0.085;

  // Arc range: 140° to 400° (260° sweep, open at bottom)
  const startAngle = 140;
  const endAngle = 400;
  const totalSweep = endAngle - startAngle;
  const currentAngle = startAngle + (Math.min(100, percent) / 100) * totalSweep;

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

  const bgTrackPath = describeArc(cx, cy, radius, startAngle, endAngle);
  const bevelShadowPath = describeArc(cx, cy + 5, radius, startAngle, endAngle);
  const activeArcPath =
    percent > 0.5 ? describeArc(cx, cy, radius, startAngle, currentAngle) : "";

  // Tip of the active beam (for laser beacon dot)
  const tipPos = polarToCartesian(cx, cy, radius, currentAngle);

  // Generate graduated tick marks (11 primary ticks: 0, 10, ..., 100)
  const TICKS_COUNT = 11;
  const ticks = Array.from({ length: TICKS_COUNT }).map((_, i) => {
    const tickVal = i * 10;
    const tickAngle = startAngle + (i / (TICKS_COUNT - 1)) * totalSweep;
    const pInner = polarToCartesian(cx, cy, radius - strokeWidth * 0.65, tickAngle);
    const pOuter = polarToCartesian(cx, cy, radius - strokeWidth * 0.3, tickAngle);
    const isActive = tickVal <= percent;
    return { tickVal, tickAngle, pInner, pOuter, isActive };
  });

  return (
    <div
      ref={containerRef}
      onMouseMove={handleMouseMove}
      onMouseLeave={handleMouseLeave}
      className={cn(
        "relative flex flex-col items-center select-none cursor-pointer perspective-[1000px]",
        className
      )}
      style={{ width: size, height: size * 0.88 }}
    >
      {/* 3D Motion Wrapper */}
      <motion.div
        animate={{
          rotateX: tilt.x,
          rotateY: tilt.y,
        }}
        transition={{ type: "spring", stiffness: 220, damping: 24, mass: 0.6 }}
        style={{
          width: size,
          height: size * 0.88,
          transformStyle: "preserve-3d",
        }}
        className="relative flex items-center justify-center"
      >
        {/* Layer -1: Ambient Floor Glow (Deep in Z) */}
        <div
          className="absolute rounded-full pointer-events-none blur-2xl"
          style={{
            width: size * 0.72,
            height: size * 0.72,
            transform: "translateZ(-35px)",
            background: `radial-gradient(circle, ${theme.glow} 0%, transparent 70%)`,
            transition: "background 0.5s ease",
          }}
        />

        {/* Layer 0 & 1: 3D Multi-Layer Volumetric SVG Dial */}
        <svg
          width={size}
          height={size * 0.88}
          className="block overflow-visible"
          style={{ transform: "translateZ(0px)" }}
        >
          <defs>
            {/* Dynamic Active Energy Gradient */}
            <linearGradient id="riskDialGradient" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor={theme.gradientStart} />
              <stop offset="100%" stopColor={theme.gradientEnd} />
            </linearGradient>

            {/* Neon Glow Filter */}
            <filter id="gaugeNeonGlow" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="3.5" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>

            {/* Inset Shadow Bevel Filter */}
            <filter id="innerDepthShadow" x="-10%" y="-10%" width="120%" height="120%">
              <feDropShadow dx="0" dy="2" stdDeviation="2" floodColor="#000000" floodOpacity="0.7" />
            </filter>
          </defs>

          {/* Extruded Bevel Under-Layer (gives physical thickness) */}
          <path
            d={bevelShadowPath}
            fill="none"
            stroke="#0b1120"
            strokeWidth={strokeWidth + 3}
            strokeLinecap="round"
            opacity="0.85"
          />

          {/* Recessed Track Base (Metallic Slot) */}
          <path
            d={bgTrackPath}
            fill="none"
            stroke="#1e293b"
            strokeWidth={strokeWidth}
            strokeLinecap="round"
            filter="url(#innerDepthShadow)"
          />

          {/* Subtle Outer Cyber Track Edge Ring */}
          <path
            d={describeArc(cx, cy, radius + strokeWidth * 0.6, startAngle, endAngle)}
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
              stroke="url(#riskDialGradient)"
              strokeWidth={strokeWidth}
              strokeLinecap="round"
              filter="url(#gaugeNeonGlow)"
              style={{
                filter: `drop-shadow(0 0 6px ${theme.main})`,
              }}
            />
          )}

          {/* Inner Specular Light Ridge */}
          {percent > 0.5 && (
            <path
              d={describeArc(cx, cy, radius - strokeWidth * 0.28, startAngle, currentAngle)}
              fill="none"
              stroke="rgba(255, 255, 255, 0.4)"
              strokeWidth="1.2"
              strokeLinecap="round"
            />
          )}

          {/* Pulsing Laser Beacon Dot at Beam Tip */}
          {percent > 0.5 && (
            <g transform={`translate(${tipPos.x}, ${tipPos.y})`}>
              <circle r={strokeWidth * 0.55} fill={theme.main} opacity="0.3" className="animate-ping" />
              <circle r={strokeWidth * 0.42} fill="#ffffff" filter="url(#gaugeNeonGlow)" />
              <circle r={strokeWidth * 0.25} fill={theme.main} />
            </g>
          )}

          {/* Scale Endpoint Labels */}
          <text
            x={polarToCartesian(cx, cy, radius + strokeWidth * 0.7, startAngle).x - 4}
            y={polarToCartesian(cx, cy, radius + strokeWidth * 0.7, startAngle).y + 6}
            fill="#64748b"
            fontSize="9"
            fontFamily="monospace"
            textAnchor="end"
          >
            0 SAFE
          </text>
          <text
            x={polarToCartesian(cx, cy, radius + strokeWidth * 0.7, endAngle).x + 4}
            y={polarToCartesian(cx, cy, radius + strokeWidth * 0.7, endAngle).y + 6}
            fill="#64748b"
            fontSize="9"
            fontFamily="monospace"
            textAnchor="start"
          >
            100 CRIT
          </text>
        </svg>

        {/* Layer 2: Floating Holographic Center Hub (Elevated in 3D Space) */}
        <div
          className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none"
          style={{
            transform: "translateZ(26px)",
            paddingTop: size * 0.06,
          }}
        >
          {/* Circular Glass Pedestal behind the score */}
          <div
            className="rounded-full flex flex-col items-center justify-center border border-white/10 backdrop-blur-md shadow-2xl"
            style={{
              width: size * 0.48,
              height: size * 0.48,
              backgroundColor: "rgba(10, 16, 30, 0.8)",
              boxShadow: `0 8px 24px -4px ${theme.glow}, inset 0 1px 2px rgba(255, 255, 255, 0.2)`,
            }}
          >
            {/* Cyber Hub Glow Ring */}
            <div
              className="absolute inset-1 rounded-full border border-white/5 pointer-events-none"
              style={{
                boxShadow: `inset 0 0 12px ${theme.glow}`,
              }}
            />

            {/* Score Number with 3D Emboss & Dynamic Glow */}
            <div className="flex items-baseline gap-0.5 mt-1">
              <span
                className="text-3xl sm:text-4xl font-extrabold tracking-tight font-mono text-white transition-all duration-300"
                style={{
                  textShadow: `0 0 18px ${theme.main}, 0 2px 4px rgba(0,0,0,0.8)`,
                }}
              >
                {Math.round(percent)}
              </span>
              <span className="text-[11px] font-mono text-slate-400 font-bold">/100</span>
            </div>

            {/* "RISK SCORE" Monospace Label */}
            <span className="text-[9px] font-mono tracking-widest uppercase text-slate-400 mt-0.5">
              Risk Score
            </span>

            {/* Severity Pill */}
            <div
              className={cn(
                "mt-1.5 px-2 py-0.5 rounded-full border text-[9px] font-mono font-bold tracking-wider uppercase transition-colors duration-300",
                theme.badgeBg
              )}
            >
              {theme.label}
            </div>
          </div>
        </div>
      </motion.div>
    </div>
  );
}