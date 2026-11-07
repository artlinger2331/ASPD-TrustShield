import { useState, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";

export function ThreeDBarChart({
  data = [],
  title = "Risk-Score Distribution",
  subtitle = "Target URLs categorized by heuristic risk range",
  height = 280,
}) {
  const containerRef = useRef(null);
  const [tilt, setTilt] = useState({ x: 10, y: -6 });
  const [hoveredIdx, setHoveredIdx] = useState(null);
  const [mousePos, setMousePos] = useState({ x: 0, y: 0 });

  const total = data.reduce((acc, curr) => acc + curr.count, 0);
  const maxCount = Math.max(...data.map((d) => d.count), 1);

  const handleMouseMove = (e) => {
    if (!containerRef.current) return;
    const rect = containerRef.current.getBoundingClientRect();
    const x = (e.clientX - rect.left) / rect.width - 0.5;
    const y = (e.clientY - rect.top) / rect.height - 0.5;
    setTilt({ x: -y * 22 + 8, y: x * 22 - 4 });
    setMousePos({ x: e.clientX - rect.left, y: e.clientY - rect.top });
  };

  const handleMouseLeave = () => {
    setTilt({ x: 10, y: -6 });
    setHoveredIdx(null);
  };

  const BUCKET_THEMES = [
    {
      label: "Safe",
      range: "0-30",
      color: "#10b981",
      topColor: "#34d399",
      sideColor: "#059669",
      glowColor: "rgba(16, 185, 129, 0.45)",
      bgGradient: "from-emerald-500/20 to-emerald-950/40",
      description: "Verified legitimate domains with trusted SSL chains & zero threat signals.",
    },
    {
      label: "Suspicious",
      range: "31-50",
      color: "#06b6d4",
      topColor: "#67e8f9",
      sideColor: "#0891b2",
      glowColor: "rgba(6, 182, 212, 0.45)",
      bgGradient: "from-cyan-500/20 to-cyan-950/40",
      description: "Low-reputation domains with missing security headers or redirect hops.",
    },
    {
      label: "High Risk",
      range: "51-75",
      color: "#f59e0b",
      topColor: "#fbbf24",
      sideColor: "#d97706",
      glowColor: "rgba(245, 158, 11, 0.45)",
      bgGradient: "from-amber-500/20 to-amber-950/40",
      description: "Anomalous patterns, short-lived certs (<24h), and credential harvest traps.",
    },
    {
      label: "Dangerous",
      range: "76-100",
      color: "#ef4444",
      topColor: "#f87171",
      sideColor: "#b91c1c",
      glowColor: "rgba(239, 68, 68, 0.5)",
      bgGradient: "from-red-500/20 to-red-950/40",
      description: "Confirmed zero-day homograph phishing clones, credential drainers & malware.",
    },
  ];

  // SVG dimensions for 3D Isometric Projection
  const svgWidth = 460;
  const svgHeight = 220;
  const baseY = 180;
  const barWidth = 62;
  const depthX = 18;
  const depthY = 12;
  const maxBarH = 125;
  const gap = 38;
  const startX = 36;

  const activeItem = hoveredIdx !== null ? data[hoveredIdx] : null;
  const activeTheme = hoveredIdx !== null ? BUCKET_THEMES[hoveredIdx] : null;

  return (
    <div className="flex flex-col w-full select-none">
      {/* 3D Perspective Stage Container */}
      <div
        ref={containerRef}
        onMouseMove={handleMouseMove}
        onMouseLeave={handleMouseLeave}
        className="relative w-full flex items-center justify-center cursor-pointer overflow-visible"
        style={{ height, perspective: 1000 }}
      >
        {/* Floating Cyber Tooltip */}
        <AnimatePresence>
          {activeItem && activeTheme && (
            <motion.div
              initial={{ opacity: 0, scale: 0.88, y: -8 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.88 }}
              transition={{ duration: 0.15 }}
              className="absolute z-50 pointer-events-none p-3.5 rounded-2xl liquid-glass border shadow-2xl backdrop-blur-2xl max-w-xs"
              style={{
                left: Math.min(Math.max(mousePos.x - 70, 16), 310),
                top: Math.max(mousePos.y - 100, 10),
                borderColor: `${activeTheme.color}88`,
                boxShadow: `0 12px 30px -4px ${activeTheme.glowColor}`,
              }}
            >
              <div className="flex items-center justify-between gap-3 mb-1">
                <div className="flex items-center gap-2">
                  <span
                    className="w-2.5 h-2.5 rounded-full animate-pulse"
                    style={{ backgroundColor: activeTheme.color }}
                  />
                  <span className="text-xs font-bold text-slate-100 font-mono">
                    {activeItem.range}
                  </span>
                </div>
                <span
                  className="text-[10px] font-mono font-bold px-2 py-0.5 rounded uppercase"
                  style={{ backgroundColor: `${activeTheme.color}25`, color: activeTheme.color }}
                >
                  {activeTheme.label}
                </span>
              </div>

              <div className="flex items-baseline justify-between gap-4 my-1.5 font-mono">
                <span className="text-lg font-black text-white">{activeItem.count} URLs</span>
                <span className="text-xs font-bold" style={{ color: activeTheme.color }}>
                  {total > 0 ? ((activeItem.count / total) * 100).toFixed(1) : 0}% of scans
                </span>
              </div>

              <p className="text-[10px] text-slate-300 leading-relaxed border-t border-white/10 pt-1.5">
                {activeTheme.description}
              </p>
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
            transformStyle: "preserve-3d",
            width: "100%",
            maxWidth: svgWidth,
          }}
          className="relative flex items-center justify-center"
        >
          {/* Isometric Ground Cyber Grid Platform */}
          <svg
            viewBox={`0 0 ${svgWidth} ${svgHeight}`}
            className="w-full h-auto overflow-visible"
            style={{ transform: "translateZ(-15px)" }}
          >
            <defs>
              {/* Floor ambient radial glow */}
              <radialGradient id="floorGlow" cx="50%" cy="50%" r="50%">
                <stop offset="0%" stopColor="#06b6d4" stopOpacity="0.18" />
                <stop offset="100%" stopColor="#06b6d4" stopOpacity="0" />
              </radialGradient>

              {/* Individual Pillar Gradients */}
              {BUCKET_THEMES.map((theme, idx) => (
                <linearGradient key={`grad-front-${idx}`} id={`grad-front-${idx}`} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={theme.topColor} stopOpacity="0.95" />
                  <stop offset="100%" stopColor={theme.color} stopOpacity="0.8" />
                </linearGradient>
              ))}

              {BUCKET_THEMES.map((theme, idx) => (
                <linearGradient key={`grad-side-${idx}`} id={`grad-side-${idx}`} x1="0" y1="0" x2="1" y2="1">
                  <stop offset="0%" stopColor={theme.sideColor} stopOpacity="0.95" />
                  <stop offset="100%" stopColor="#040813" stopOpacity="0.9" />
                </linearGradient>
              ))}
            </defs>

            {/* Base Grid Lines */}
            <line x1="20" y1={baseY} x2={svgWidth - 20} y2={baseY} stroke="rgba(255,255,255,0.08)" strokeDasharray="3 3" />
            <line x1="20 + depthX" y1={baseY - depthY} x2={svgWidth - 20 + depthX} y2={baseY - depthY} stroke="rgba(255,255,255,0.04)" strokeDasharray="3 3" />

            {/* 3D Isometric Pillars */}
            {data.map((item, idx) => {
              const theme = BUCKET_THEMES[idx % BUCKET_THEMES.length];
              const isHovered = hoveredIdx === idx;
              const x = startX + idx * (barWidth + gap);

              // Calculate volumetric height
              const rawH = (item.count / maxCount) * maxBarH;
              const h = Math.max(22, rawH);
              const topY = baseY - h;

              return (
                <g
                  key={idx}
                  onMouseEnter={() => setHoveredIdx(idx)}
                  className="cursor-pointer transition-all duration-200"
                  style={{
                    filter: isHovered
                      ? `drop-shadow(0 0 15px ${theme.color}) brightness(1.2)`
                      : `drop-shadow(0 0 4px ${theme.color}66)`,
                    opacity: hoveredIdx !== null && !isHovered ? 0.45 : 1,
                  }}
                >
                  {/* Floor Ambient Glow Shadow */}
                  <ellipse
                    cx={x + barWidth / 2 + depthX / 2}
                    cy={baseY + 4}
                    rx={barWidth / 2 + 8}
                    ry={depthY + 4}
                    fill={theme.glowColor}
                    className="opacity-70 blur-[3px]"
                  />

                  {/* 1. FRONT FACE */}
                  <polygon
                    points={`
                      ${x},${topY}
                      ${x + barWidth},${topY}
                      ${x + barWidth},${baseY}
                      ${x},${baseY}
                    `}
                    fill={`url(#grad-front-${idx})`}
                    stroke={theme.topColor}
                    strokeWidth={isHovered ? 1.5 : 0.8}
                    strokeOpacity="0.6"
                  />

                  {/* 2. TOP FACE (Isometric Diamond Cap) */}
                  <polygon
                    points={`
                      ${x},${topY}
                      ${x + depthX},${topY - depthY}
                      ${x + barWidth + depthX},${topY - depthY}
                      ${x + barWidth},${topY}
                    `}
                    fill={theme.topColor}
                    stroke="#ffffff"
                    strokeWidth={isHovered ? 1.5 : 0.8}
                    strokeOpacity="0.8"
                  />

                  {/* 3. RIGHT SIDE FACE (Depth/Shadow extrusion) */}
                  <polygon
                    points={`
                      ${x + barWidth},${topY}
                      ${x + barWidth + depthX},${topY - depthY}
                      ${x + barWidth + depthX},${baseY - depthY}
                      ${x + barWidth},${baseY}
                    `}
                    fill={`url(#grad-side-${idx})`}
                    stroke={theme.sideColor}
                    strokeWidth={0.8}
                    strokeOpacity="0.6"
                  />

                  {/* Subtle Inner Highlight Lines for Metallic 3D Edge */}
                  <line
                    x1={x}
                    y1={topY}
                    x2={x + barWidth}
                    y2={topY}
                    stroke="#ffffff"
                    strokeWidth="1.2"
                    strokeOpacity="0.9"
                  />
                  <line
                    x1={x + barWidth}
                    y1={topY}
                    x2={x + barWidth}
                    y2={baseY}
                    stroke="#ffffff"
                    strokeWidth="0.8"
                    strokeOpacity="0.5"
                  />

                  {/* Floating Metric Badge Above Pillar */}
                  <g style={{ transform: isHovered ? "translateY(-6px)" : "translateY(0)", transition: "transform 0.2s" }}>
                    <rect
                      x={x + barWidth / 2 - 20}
                      y={topY - depthY - 24}
                      width="40"
                      height="18"
                      rx="6"
                      fill="#070c18"
                      stroke={isHovered ? theme.topColor : "rgba(255,255,255,0.15)"}
                      strokeWidth="1"
                    />
                    <text
                      x={x + barWidth / 2}
                      y={topY - depthY - 12}
                      textAnchor="middle"
                      fill="#ffffff"
                      fontSize="10"
                      fontWeight="bold"
                      fontFamily="monospace"
                    >
                      {item.count}
                    </text>
                  </g>

                  {/* X-Axis Range Label Below */}
                  <text
                    x={x + barWidth / 2}
                    y={baseY + 22}
                    textAnchor="middle"
                    fill={isHovered ? theme.topColor : "#94a3b8"}
                    fontSize="10"
                    fontFamily="monospace"
                    fontWeight={isHovered ? "bold" : "normal"}
                  >
                    {theme.range}
                  </text>
                  <text
                    x={x + barWidth / 2}
                    y={baseY + 34}
                    textAnchor="middle"
                    fill={isHovered ? "#ffffff" : "#64748b"}
                    fontSize="9"
                    fontFamily="monospace"
                  >
                    ({theme.label})
                  </text>
                </g>
              );
            })}
          </svg>
        </motion.div>
      </div>

      {/* COMPACT MINI-SUMMARY PILL BAR BELOW */}
      <div className="flex flex-wrap items-center justify-center gap-1.5 mt-2 pt-3 border-t border-white/5 w-full">
        {data.map((item, idx) => {
          const theme = BUCKET_THEMES[idx % BUCKET_THEMES.length];
          const isHovered = hoveredIdx === idx;
          const percent = total > 0 ? Math.round((item.count / total) * 100) : 0;

          return (
            <button
              key={idx}
              onMouseEnter={() => setHoveredIdx(idx)}
              onMouseLeave={() => setHoveredIdx(null)}
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[11px] font-mono transition-all cursor-pointer border ${
                isHovered
                  ? "bg-white/10 border-cyan-400/50 shadow-[0_0_12px_rgba(6,182,212,0.3)] scale-105"
                  : "bg-white/[0.02] border-white/5 text-slate-400 hover:text-slate-200 hover:bg-white/5"
              }`}
            >
              <span
                className="w-2 h-2 rounded-full shrink-0"
                style={{ backgroundColor: theme.color, boxShadow: isHovered ? `0 0 8px ${theme.color}` : "none" }}
              />
              <span className="font-semibold text-slate-200">{theme.label}</span>
              <span className="text-slate-400 font-bold">{item.count}</span>
              <span className="text-[10px] text-slate-500">({percent}%)</span>
            </button>
          );
        })}
      </div>
    </div>
  );
}
