import { useState, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";

export function ThreeDDonut({
  data = [],
  title = "",
  totalLabel = "Total",
  size = 280,
  colors = ["#3b82f6", "#06b6d4", "#f59e0b", "#ef4444", "#10b981"],
}) {
  const containerRef = useRef(null);
  const [tilt, setTilt] = useState({ x: 12, y: -8 });
  const [hoveredIndex, setHoveredIndex] = useState(null);
  const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0 });

  const total = data.reduce((acc, curr) => acc + curr.value, 0);

  // SVG Donut geometry
  const radius = 64;
  const strokeWidth = 24;
  const circumference = 2 * Math.PI * radius; // ~402.12
  const center = size / 2;

  const handleMouseMove = (e) => {
    if (!containerRef.current) return;
    const rect = containerRef.current.getBoundingClientRect();
    const x = (e.clientX - rect.left) / rect.width - 0.5;
    const y = (e.clientY - rect.top) / rect.height - 0.5;
    // Interactive 3D tilt angles
    setTilt({ x: -y * 28 + 10, y: x * 28 - 6 });
    setTooltipPos({
      x: e.clientX - rect.left,
      y: e.clientY - rect.top,
    });
  };

  const handleMouseLeave = () => {
    setTilt({ x: 14, y: -6 });
    setHoveredIndex(null);
  };

  // Pre-calculate cumulative offsets for slices
  let accumulated = 0;
  const slices = data.map((item, idx) => {
    const fraction = total > 0 ? item.value / total : 0;
    const sliceLen = fraction * circumference;
    const gap = data.length > 1 ? 4 : 0;
    const visibleLen = Math.max(0, sliceLen - gap);
    const offset = accumulated;
    accumulated += sliceLen;

    const color = item.color || colors[idx % colors.length];
    const percent = Math.round(fraction * 100);

    return {
      ...item,
      color,
      fraction,
      percent,
      strokeDasharray: `${visibleLen} ${circumference - visibleLen}`,
      strokeDashoffset: -offset,
      idx,
    };
  });

  const activeSlice = hoveredIndex !== null ? slices[hoveredIndex] : null;

  return (
    <div className="flex flex-col items-center w-full select-none">
      {/* 3D Perspective Canvas Container */}
      <div
        ref={containerRef}
        onMouseMove={handleMouseMove}
        onMouseLeave={handleMouseLeave}
        className="relative flex items-center justify-center cursor-pointer"
        style={{
          width: size,
          height: size,
          perspective: 1000,
        }}
      >
        {/* Floating Cyber Tooltip */}
        <AnimatePresence>
          {activeSlice && (
            <motion.div
              initial={{ opacity: 0, scale: 0.85, y: -10 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.85 }}
              transition={{ duration: 0.15 }}
              className="absolute z-50 pointer-events-none px-3 py-2 rounded-xl liquid-glass border shadow-2xl backdrop-blur-xl"
              style={{
                left: Math.min(Math.max(tooltipPos.x + 12, 10), size - 140),
                top: Math.max(tooltipPos.y - 48, 10),
                borderColor: `${activeSlice.color}88`,
                boxShadow: `0 8px 25px -4px ${activeSlice.color}40`,
              }}
            >
              <div className="flex items-center gap-1.5 mb-0.5">
                <span
                  className="w-2 h-2 rounded-full animate-pulse"
                  style={{ backgroundColor: activeSlice.color }}
                />
                <span className="text-xs font-bold text-slate-100">{activeSlice.name}</span>
              </div>
              <div className="flex items-center justify-between gap-3 text-[11px] font-mono">
                <span className="text-slate-400">Count: <strong className="text-white">{activeSlice.value}</strong></span>
                <span className="font-bold px-1.5 py-0.2 rounded text-[10px]" style={{ backgroundColor: `${activeSlice.color}25`, color: activeSlice.color }}>
                  {activeSlice.percent}%
                </span>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* 3D Isometric Transform Wrapper */}
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
          {/* Ambient Deep Glow Underneath */}
          <div
            className="absolute rounded-full pointer-events-none blur-3xl opacity-35"
            style={{
              width: size * 0.75,
              height: size * 0.75,
              transform: "translateZ(-45px)",
              background: `radial-gradient(circle, ${activeSlice ? activeSlice.color : "#06b6d4"} 0%, transparent 70%)`,
              transition: "background 0.3s ease",
            }}
          />

          {/* LAYER 1: Deep Floor Shadow */}
          <svg
            width={size}
            height={size}
            className="absolute inset-0 pointer-events-none opacity-40 blur-md"
            style={{ transform: "translateZ(-30px) scale(0.92)" }}
          >
            <circle
              cx={center}
              cy={center}
              r={radius}
              fill="none"
              stroke="#000000"
              strokeWidth={strokeWidth + 8}
            />
          </svg>

          {/* LAYER 2: Extruded Cylinder Depth Base (Bottom Rim) */}
          <svg
            width={size}
            height={size}
            className="absolute inset-0 pointer-events-none"
            style={{ transform: "translateZ(-14px)" }}
          >
            {slices.map((slice) => (
              <circle
                key={`base-${slice.idx}`}
                cx={center}
                cy={center}
                r={radius}
                fill="none"
                stroke={slice.color}
                strokeWidth={strokeWidth}
                strokeDasharray={slice.strokeDasharray}
                strokeDashoffset={slice.strokeDashoffset}
                strokeLinecap="round"
                className="opacity-30 brightness-50"
              />
            ))}
          </svg>

          {/* LAYER 3: Mid Cylinder Bevel Layer */}
          <svg
            width={size}
            height={size}
            className="absolute inset-0 pointer-events-none"
            style={{ transform: "translateZ(-4px)" }}
          >
            {slices.map((slice) => (
              <circle
                key={`mid-${slice.idx}`}
                cx={center}
                cy={center}
                r={radius}
                fill="none"
                stroke={slice.color}
                strokeWidth={strokeWidth}
                strokeDasharray={slice.strokeDasharray}
                strokeDashoffset={slice.strokeDashoffset}
                strokeLinecap="round"
                className="opacity-60 brightness-75"
              />
            ))}
          </svg>

          {/* LAYER 4: Primary Top Glowing 3D Donut Ring */}
          <svg
            width={size}
            height={size}
            className="absolute inset-0 overflow-visible"
            style={{ transform: "translateZ(18px)" }}
          >
            <defs>
              <filter id="neon-glow" x="-20%" y="-20%" width="140%" height="140%">
                <feGaussianBlur stdDeviation="3" result="blur" />
                <feComposite in="SourceGraphic" in2="blur" operator="over" />
              </filter>
            </defs>

            {slices.map((slice) => {
              const isHovered = hoveredIndex === slice.idx;
              return (
                <circle
                  key={`top-${slice.idx}`}
                  cx={center}
                  cy={center}
                  r={radius}
                  fill="none"
                  stroke={slice.color}
                  strokeWidth={isHovered ? strokeWidth + 4 : strokeWidth}
                  strokeDasharray={slice.strokeDasharray}
                  strokeDashoffset={slice.strokeDashoffset}
                  strokeLinecap="round"
                  onMouseEnter={() => setHoveredIndex(slice.idx)}
                  className="transition-all duration-200 cursor-pointer"
                  style={{
                    filter: isHovered
                      ? `drop-shadow(0 0 10px ${slice.color}) brightness(1.25)`
                      : `drop-shadow(0 0 3px ${slice.color}88)`,
                    opacity: hoveredIndex !== null && !isHovered ? 0.45 : 1,
                  }}
                />
              );
            })}
          </svg>

          {/* LAYER 5: Elevated Hollow Core Telemetry Display */}
          <div
            className="absolute rounded-full border border-white/10 bg-[#080d1c]/90 backdrop-blur-md flex flex-col items-center justify-center pointer-events-none shadow-2xl"
            style={{
              width: (radius - strokeWidth / 2) * 2 - 8,
              height: (radius - strokeWidth / 2) * 2 - 8,
              transform: "translateZ(30px)",
              borderColor: activeSlice ? `${activeSlice.color}66` : "rgba(255, 255, 255, 0.12)",
              boxShadow: activeSlice ? `0 0 20px -3px ${activeSlice.color}33, inset 0 0 15px rgba(0,0,0,0.8)` : "inset 0 0 15px rgba(0,0,0,0.8)",
            }}
          >
            {/* Concentric subtle radar line */}
            <div className="absolute inset-2 rounded-full border border-cyan-500/15 border-dashed animate-spin" style={{ animationDuration: "40s" }} />

            <span className="text-[10px] font-mono font-semibold uppercase tracking-wider text-slate-400 text-center px-1 truncate max-w-[80px]">
              {activeSlice ? activeSlice.name : totalLabel}
            </span>
            <span
              className="text-lg font-black font-mono transition-colors"
              style={{ color: activeSlice ? activeSlice.color : "#ffffff" }}
            >
              {activeSlice ? `${activeSlice.percent}%` : total}
            </span>
            <span className="text-[9px] font-mono text-slate-500">
              {activeSlice ? `${activeSlice.value} items` : "Total"}
            </span>
          </div>
        </motion.div>
      </div>

      {/* COMPACT MINI-SUMMARY PILL BAR BELOW CHART */}
      <div className="flex flex-wrap items-center justify-center gap-1.5 mt-3 pt-3 border-t border-white/5 w-full">
        {slices.map((slice) => {
          const isHovered = hoveredIndex === slice.idx;
          return (
            <button
              key={slice.idx}
              onMouseEnter={() => setHoveredIndex(slice.idx)}
              onMouseLeave={() => setHoveredIndex(null)}
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[11px] font-mono transition-all cursor-pointer border ${
                isHovered
                  ? "bg-white/10 border-cyan-400/50 shadow-[0_0_12px_rgba(6,182,212,0.3)] scale-105"
                  : "bg-white/[0.02] border-white/5 text-slate-400 hover:text-slate-200 hover:bg-white/5"
              }`}
            >
              <span
                className="w-2 h-2 rounded-full shrink-0"
                style={{ backgroundColor: slice.color, boxShadow: isHovered ? `0 0 8px ${slice.color}` : "none" }}
              />
              <span className="truncate max-w-[100px]">{slice.name}</span>
              <span className="font-bold text-slate-300">{slice.percent}%</span>
            </button>
          );
        })}
      </div>
    </div>
  );
}
