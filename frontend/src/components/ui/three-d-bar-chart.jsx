import { useState, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Percent, Hash, Info, CheckCircle2, AlertTriangle, ShieldAlert } from "lucide-react";

export function ThreeDBarChart({
  data = [],
  title = "Risk-Score Distribution",
  subtitle = "Target URLs categorized by heuristic risk range",
  height = 300,
}) {
  const containerRef = useRef(null);
  const [tilt, setTilt] = useState({ x: 12, y: -6 });
  const [hoveredIdx, setHoveredIdx] = useState(null);
  const [selectedIdx, setSelectedIdx] = useState(0); // Default to first (Safe) so HUD is always filled
  const [viewMode, setViewMode] = useState("count"); // "count" | "percent"

  const total = data.reduce((acc, curr) => acc + curr.count, 0) || 1;
  const maxCount = Math.max(...data.map((d) => d.count), 1);

  const handleMouseMove = (e) => {
    if (!containerRef.current) return;
    const rect = containerRef.current.getBoundingClientRect();
    const x = (e.clientX - rect.left) / rect.width - 0.5;
    const y = (e.clientY - rect.top) / rect.height - 0.5;
    setTilt({ x: -y * 20 + 8, y: x * 20 - 4 });
  };

  const handleMouseLeave = () => {
    setTilt({ x: 12, y: -6 });
    setHoveredIdx(null);
  };

  const BUCKET_THEMES = [
    {
      label: "Safe",
      range: "0-30",
      color: "#10b981",
      topColor: "#34d399",
      sideColor: "#059669",
      glowColor: "rgba(16, 185, 129, 0.5)",
      bgGradient: "from-emerald-500/20 to-emerald-950/40",
      status: "VERIFIED SECURE",
      description: "Legitimate canonical targets with trusted EV SSL chains and zero deceptive homoglyphs.",
    },
    {
      label: "Suspicious",
      range: "31-50",
      color: "#06b6d4",
      topColor: "#67e8f9",
      sideColor: "#0891b2",
      glowColor: "rgba(6, 182, 212, 0.5)",
      bgGradient: "from-cyan-500/20 to-cyan-950/40",
      status: "LOW REPUTATION",
      description: "Anomalous targets with missing HSTS/CSP headers, recent DNS changes, or open redirects.",
    },
    {
      label: "High Risk",
      range: "51-75",
      color: "#f59e0b",
      topColor: "#fbbf24",
      sideColor: "#d97706",
      glowColor: "rgba(245, 158, 11, 0.5)",
      bgGradient: "from-amber-500/20 to-amber-950/40",
      status: "POTENTIAL PHISH",
      description: "Disposable SSL certificates (<24h old), keyword spoofing, or obfuscated login forms.",
    },
    {
      label: "Dangerous",
      range: "76-100",
      color: "#ef4444",
      topColor: "#f87171",
      sideColor: "#b91c1c",
      glowColor: "rgba(239, 68, 68, 0.55)",
      bgGradient: "from-red-500/20 to-red-950/40",
      status: "CRITICAL THREAT",
      description: "Active homograph phishing, weaponized credential drainers, or malicious payload hosts.",
    },
  ];

  // Active item determined by hover or selection
  const activeIdx = hoveredIdx !== null ? hoveredIdx : selectedIdx !== null ? selectedIdx : 0;
  const activeItem = data[activeIdx] || data[0];
  const activeTheme = BUCKET_THEMES[activeIdx] || BUCKET_THEMES[0];
  const activePercent = total > 0 ? ((activeItem.count / total) * 100).toFixed(1) : "0";

  // SVG dimensions for 3D Isometric Projection
  const svgWidth = 460;
  const svgHeight = 210;
  const baseY = 168;
  const barWidth = 62;
  const depthX = 16;
  const depthY = 10;
  const maxBarH = 115;
  const gap = 38;
  const startX = 36;

  const handlePillClick = (idx) => {
    setSelectedIdx(idx);
    setHoveredIdx(idx);
  };

  const toggleViewMode = (mode) => {
    setViewMode(mode);
  };

  return (
    <div className="flex flex-col w-full select-none">
      
      {/* Top Interactive Mode Toggle Strip */}
      <div className="flex items-center justify-between w-full px-2 mb-2 pb-2 border-b border-white/5">
        <div className="flex items-center gap-2">
          <span className="text-[11px] font-mono text-slate-400">Display Metric:</span>
          <div className="flex items-center p-0.5 rounded-lg bg-black/40 border border-white/10">
            <button
              onClick={() => toggleViewMode("count")}
              className={`flex items-center gap-1 px-2.5 py-1 rounded-md text-[10px] font-mono font-bold transition-all cursor-pointer ${
                viewMode === "count"
                  ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-[0_0_10px_rgba(6,182,212,0.3)]"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              <Hash className="w-3 h-3" />
              <span>Counts</span>
            </button>
            <button
              onClick={() => toggleViewMode("percent")}
              className={`flex items-center gap-1 px-2.5 py-1 rounded-md text-[10px] font-mono font-bold transition-all cursor-pointer ${
                viewMode === "percent"
                  ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-[0_0_10px_rgba(6,182,212,0.3)]"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              <Percent className="w-3 h-3" />
              <span>Percentage (%)</span>
            </button>
          </div>
        </div>

        <span className="text-[10px] font-mono text-slate-500">
          Click any bar or pill to isolate
        </span>
      </div>

      {/* 3D Perspective Stage Container - completely clear, no tooltip overlay blocking bars! */}
      <div
        ref={containerRef}
        onMouseMove={handleMouseMove}
        onMouseLeave={handleMouseLeave}
        className="relative w-full flex items-center justify-center cursor-pointer overflow-visible py-2"
        style={{ perspective: 1000 }}
      >
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
          <svg
            viewBox={`0 0 ${svgWidth} ${svgHeight}`}
            className="w-full h-auto overflow-visible"
            style={{ transform: "translateZ(-10px)" }}
          >
            <defs>
              {/* Gradients for Front Faces */}
              {BUCKET_THEMES.map((theme, idx) => (
                <linearGradient key={`bar-front-${idx}`} id={`bar-front-${idx}`} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={theme.topColor} stopOpacity="1" />
                  <stop offset="100%" stopColor={theme.color} stopOpacity="0.85" />
                </linearGradient>
              ))}

              {/* Gradients for Right Side Shadow Extrusions */}
              {BUCKET_THEMES.map((theme, idx) => (
                <linearGradient key={`bar-side-${idx}`} id={`bar-side-${idx}`} x1="0" y1="0" x2="1" y2="1">
                  <stop offset="0%" stopColor={theme.sideColor} stopOpacity="0.95" />
                  <stop offset="100%" stopColor="#040711" stopOpacity="0.95" />
                </linearGradient>
              ))}
            </defs>

            {/* Base Grid Guidelines */}
            <line x1="20" y1={baseY} x2={svgWidth - 20} y2={baseY} stroke="rgba(255,255,255,0.08)" strokeDasharray="3 3" />
            <line x1={20 + depthX} y1={baseY - depthY} x2={svgWidth - 20 + depthX} y2={baseY - depthY} stroke="rgba(255,255,255,0.04)" strokeDasharray="3 3" />

            {/* Render Each 3D Isometric Pillar */}
            {data.map((item, idx) => {
              const theme = BUCKET_THEMES[idx % BUCKET_THEMES.length];
              const isSelected = selectedIdx === idx;
              const isHovered = hoveredIdx === idx;
              const isActive = isSelected || isHovered;

              const x = startX + idx * (barWidth + gap);

              // Calculate volumetric height based on current viewMode
              const fraction = item.count / maxCount;
              const rawH = fraction * maxBarH;
              const h = Math.max(26, rawH);

              // Elevation shift when selected/hovered (bounces up in 3D!)
              const elevation = isActive ? 12 : 0;
              const currentBaseY = baseY - elevation;
              const topY = currentBaseY - h;

              // Display string based on viewMode
              const percentVal = total > 0 ? ((item.count / total) * 100).toFixed(1) : 0;
              const displayVal = viewMode === "percent" ? `${percentVal}%` : item.count;

              return (
                <g
                  key={idx}
                  onClick={() => handlePillClick(idx)}
                  onMouseEnter={() => setHoveredIdx(idx)}
                  className="cursor-pointer transition-all duration-300"
                  style={{
                    filter: isActive
                      ? `drop-shadow(0 0 16px ${theme.color}) brightness(1.25)`
                      : `drop-shadow(0 0 4px ${theme.color}55)`,
                    opacity: activeIdx !== null && activeIdx !== idx ? 0.45 : 1,
                  }}
                >
                  {/* Floor Pedestal Glow & Ring */}
                  <ellipse
                    cx={x + barWidth / 2 + depthX / 2}
                    cy={baseY + 4}
                    rx={barWidth / 2 + (isActive ? 12 : 6)}
                    ry={depthY + (isActive ? 6 : 3)}
                    fill={theme.glowColor}
                    className={isActive ? "opacity-90 blur-[4px]" : "opacity-40 blur-[2px]"}
                  />

                  {/* Active Pillar Pedestal Ring */}
                  {isActive && (
                    <ellipse
                      cx={x + barWidth / 2 + depthX / 2}
                      cy={baseY + 4}
                      rx={barWidth / 2 + 10}
                      ry={depthY + 4}
                      fill="none"
                      stroke={theme.topColor}
                      strokeWidth="1.5"
                      strokeDasharray="4 2"
                    />
                  )}

                  {/* 1. FRONT FACE */}
                  <polygon
                    points={`
                      ${x},${topY}
                      ${x + barWidth},${topY}
                      ${x + barWidth},${currentBaseY}
                      ${x},${currentBaseY}
                    `}
                    fill={`url(#bar-front-${idx})`}
                    stroke={theme.topColor}
                    strokeWidth={isActive ? 1.5 : 0.8}
                    strokeOpacity="0.8"
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
                    strokeWidth={isActive ? 1.8 : 1}
                    strokeOpacity="0.9"
                  />

                  {/* 3. RIGHT SIDE FACE (Depth Extrusion) */}
                  <polygon
                    points={`
                      ${x + barWidth},${topY}
                      ${x + barWidth + depthX},${topY - depthY}
                      ${x + barWidth + depthX},${currentBaseY - depthY}
                      ${x + barWidth},${currentBaseY}
                    `}
                    fill={`url(#bar-side-${idx})`}
                    stroke={theme.sideColor}
                    strokeWidth={0.8}
                    strokeOpacity="0.6"
                  />

                  {/* Specular Edge Highlights */}
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
                    y2={currentBaseY}
                    stroke="#ffffff"
                    strokeWidth="1"
                    strokeOpacity="0.6"
                  />

                  {/* Floating Metric Badge Above Pillar (Smoothly displays Count or %) */}
                  <g style={{ transform: isActive ? "translateY(-8px)" : "translateY(0)", transition: "transform 0.25s ease-out" }}>
                    <rect
                      x={x + barWidth / 2 - 24}
                      y={topY - depthY - 26}
                      width="48"
                      height="20"
                      rx="7"
                      fill="#060b17"
                      stroke={isActive ? theme.topColor : "rgba(255,255,255,0.2)"}
                      strokeWidth={isActive ? "1.5" : "1"}
                    />
                    <text
                      x={x + barWidth / 2}
                      y={topY - depthY - 12}
                      textAnchor="middle"
                      fill={isActive ? "#ffffff" : theme.topColor}
                      fontSize="10.5"
                      fontWeight="bold"
                      fontFamily="monospace"
                    >
                      {displayVal}
                    </text>
                  </g>

                  {/* X-Axis Range Label Below Ground */}
                  <text
                    x={x + barWidth / 2}
                    y={baseY + 22}
                    textAnchor="middle"
                    fill={isActive ? theme.topColor : "#94a3b8"}
                    fontSize="10"
                    fontFamily="monospace"
                    fontWeight={isActive ? "bold" : "normal"}
                  >
                    {theme.range}
                  </text>
                  <text
                    x={x + barWidth / 2}
                    y={baseY + 34}
                    textAnchor="middle"
                    fill={isActive ? "#ffffff" : "#64748b"}
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

      {/* ========================================================================= */}
      {/* DEDICATED TELEMETRY HUD (Guaranteed to NEVER block the 3D bars)            */}
      {/* ========================================================================= */}
      <div className="w-full mt-2 p-3 rounded-2xl bg-black/40 border border-white/10 backdrop-blur-md">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-white/5 pb-2 mb-2">
          <div className="flex items-center gap-2">
            <span
              className="w-3 h-3 rounded-full animate-pulse"
              style={{ backgroundColor: activeTheme.color }}
            />
            <span className="text-xs font-bold font-mono text-white">
              {activeTheme.range} Risk Score: {activeTheme.label}
            </span>
            <span
              className="text-[9px] font-mono font-bold px-2 py-0.5 rounded uppercase"
              style={{ backgroundColor: `${activeTheme.color}25`, color: activeTheme.color }}
            >
              {activeTheme.status}
            </span>
          </div>

          <div className="flex items-center gap-3 font-mono text-xs">
            <span className="text-slate-400">
              Total Count: <strong className="text-white">{activeItem.count} URLs</strong>
            </span>
            <span className="text-slate-600">|</span>
            <span className="font-bold" style={{ color: activeTheme.color }}>
              Share: {activePercent}%
            </span>
          </div>
        </div>

        <p className="text-[11px] text-slate-300 leading-relaxed font-mono">
          {activeTheme.description}
        </p>
      </div>

      {/* ========================================================================= */}
      {/* INTERACTIVE PILL BAR (Clicking updates selected bar & switches view)      */}
      {/* ========================================================================= */}
      <div className="flex flex-wrap items-center justify-center gap-1.5 mt-2 pt-2 border-t border-white/5 w-full">
        {data.map((item, idx) => {
          const theme = BUCKET_THEMES[idx % BUCKET_THEMES.length];
          const isSelected = selectedIdx === idx;
          const percentVal = total > 0 ? ((item.count / total) * 100).toFixed(0) : 0;

          return (
            <button
              key={idx}
              onClick={() => handlePillClick(idx)}
              onMouseEnter={() => setHoveredIdx(idx)}
              onMouseLeave={() => setHoveredIdx(null)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-[11px] font-mono transition-all cursor-pointer border ${
                isSelected
                  ? "bg-white/15 border-cyan-400 text-white shadow-[0_0_15px_rgba(6,182,212,0.4)] scale-105"
                  : "bg-white/[0.03] border-white/10 text-slate-400 hover:text-slate-200 hover:bg-white/5"
              }`}
            >
              <span
                className="w-2 h-2 rounded-full shrink-0"
                style={{ backgroundColor: theme.color, boxShadow: isSelected ? `0 0 10px ${theme.color}` : "none" }}
              />
              <span className="font-semibold text-slate-200">{theme.label}</span>
              <span className="text-slate-400 font-bold">{item.count}</span>
              <span
                onClick={(e) => {
                  e.stopPropagation();
                  setViewMode("percent");
                  handlePillClick(idx);
                }}
                className={`text-[10px] px-1 py-0.2 rounded font-bold transition-colors hover:text-cyan-300 ${
                  viewMode === "percent" ? "text-cyan-300 bg-cyan-500/20" : "text-slate-400"
                }`}
                title="Click to view percentages"
              >
                ({percentVal}%)
              </span>
            </button>
          );
        })}
      </div>

    </div>
  );
}