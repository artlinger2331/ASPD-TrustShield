import React, { useState } from "react";
import { motion } from "framer-motion";
import { Shield, Globe, Lock, Cpu, AlertTriangle, CheckCircle, Flame } from "lucide-react";
import { cn } from "@/utils/cn";

const LAYERS = [
  {
    id: "heuristics",
    name: "Layer 4: Heuristics & Homographs",
    shortName: "Heuristics",
    icon: Cpu,
    category: "Neural Inspection",
    standbyDesc: "Punycode & Cyrillic lookalike detector",
    activeDesc: "Deconstructing unicode characters & phishing signatures...",
    dangerDesc: "Hostile brand spoofing & high-confidence phishing clone detected",
    safeDesc: "No obfuscated glyphs or known impersonation patterns found",
    weight: "Risk Weight: High (40%)",
  },
  {
    id: "content",
    name: "Layer 3: DOM & Form Harvesters",
    shortName: "DOM Content",
    icon: AlertTriangle,
    category: "Payload Analysis",
    standbyDesc: "Hidden form action & script tracer",
    activeDesc: "Scanning input targets, obfuscated iframes & credential drainers...",
    dangerDesc: "Unsafe form actions exfiltrating credentials to unverified host",
    safeDesc: "Clean DOM architecture with verified submit targets",
    weight: "Risk Weight: Medium (25%)",
  },
  {
    id: "ssl",
    name: "Layer 2: X.509 SSL & Encryption",
    shortName: "SSL / TLS",
    icon: Lock,
    category: "Cryptographic Audit",
    standbyDesc: "Certificate Authority & SAN chain validator",
    activeDesc: "Verifying CA trust root, cipher suites & certificate age...",
    dangerDesc: "Short-lived domain-validated cert with missing revocation status",
    safeDesc: "DigiCert High Assurance EV Certificate, strict HSTS enforced",
    weight: "Risk Weight: Medium (20%)",
  },
  {
    id: "dns",
    name: "Layer 1: DNS & Autonomous System",
    shortName: "DNS & IP",
    icon: Globe,
    category: "Network Infrastructure",
    standbyDesc: "Fast-flux DNS & ASN reputation matrix",
    activeDesc: "Resolving recursive records, geo-location & registrar age...",
    dangerDesc: "Domain registered <72h ago via bulletproof offshore hosting ASN",
    safeDesc: "Established ASN reputation with zero historical blacklists",
    weight: "Risk Weight: Standard (15%)",
  },
];

export function ThreeDLayerStack({
  activeStep = 0,
  isScanning = false,
  isCompleted = false,
  result = null,
}) {
  const [hoveredLayer, setHoveredLayer] = useState(null);
  const [selectedLayer, setSelectedLayer] = useState("heuristics");

  // Determine status of each layer based on current scan stage
  // ActiveStep ranges 0 to 6 in progress
  const getLayerStatus = (index) => {
    // LAYERS is index 0 (top/heuristics) to index 3 (bottom/dns)
    // Scan steps logically progress from DNS (0-1), SSL (2-3), Content (4), Heuristics (5-6)
    const reversedIndex = 3 - index; // 0 for dns, 1 for ssl, 2 for content, 3 for heuristics
    
    if (isCompleted) {
      if (result?.verdict === "dangerous" || result?.verdict === "high-risk") {
        if (index === 0 || index === 1) return "danger"; // Heuristics & content flagged
        return "warning";
      }
      return "safe";
    }

    if (isScanning) {
      const targetStepThreshold = reversedIndex * 1.8;
      if (activeStep > targetStepThreshold) return "done";
      if (activeStep >= targetStepThreshold - 1) return "analyzing";
      return "idle";
    }

    return "standby";
  };

  const activeLayerData = LAYERS.find((l) => l.id === selectedLayer) || LAYERS[0];

  return (
    <div className="relative w-full rounded-2xl border border-white/10 bg-gradient-to-b from-navy-800/80 to-navy-900/90 backdrop-blur-xl p-5 sm:p-6 shadow-2xl overflow-hidden flex flex-col justify-between">
      {/* Background cyber ambient grid */}
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-cyan-500/10 via-transparent to-transparent pointer-events-none" />
      <div className="absolute -top-24 -right-24 w-60 h-60 bg-blue-500/10 rounded-full blur-3xl pointer-events-none" />

      {/* Header telemetry pill */}
      <div className="relative z-10 flex items-center justify-between mb-4 pb-3 border-b border-white/5">
        <div className="flex items-center gap-2">
          <div className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-pulse shadow-[0_0_8px_#22d3ee]" />
          <span className="text-xs font-mono uppercase tracking-wider text-cyan-300">
            3D Security Layer Stack
          </span>
        </div>
        <span className="text-[11px] font-mono px-2 py-0.5 rounded-full border border-cyan-500/30 bg-cyan-500/10 text-cyan-400">
          {isScanning ? "LAYER INSPECTION ACTIVE" : isCompleted ? "FORENSIC DECONSTRUCTION COMPLETE" : "STANDBY // PERSPECTIVE HUD"}
        </span>
      </div>

      {/* 3D Isometric Viewport Container */}
      <div className="relative z-10 my-3 h-[280px] sm:h-[310px] flex items-center justify-center perspective-[1000px] select-none">
        <div
          className="relative w-[280px] sm:w-[320px] h-[190px] transition-transform duration-500 ease-out"
          style={{
            transform: "rotateX(58deg) rotateZ(-26deg)",
            transformStyle: "preserve-3d",
          }}
        >
          {/* Base holographic floor grid */}
          <div
            className="absolute -inset-6 rounded-2xl border border-cyan-500/20 bg-cyan-500/[0.02] pointer-events-none"
            style={{
              transform: "translateZ(-35px)",
              backgroundImage: "linear-gradient(to right, rgba(34, 211, 238, 0.08) 1px, transparent 1px), linear-gradient(to bottom, rgba(34, 211, 238, 0.08) 1px, transparent 1px)",
              backgroundSize: "20px 20px",
            }}
          />

          {/* Render 4 Isometric Plates */}
          {LAYERS.map((layer, index) => {
            const status = getLayerStatus(index);
            const isHovered = hoveredLayer === layer.id;
            const isSelected = selectedLayer === layer.id;

            // Z-spacing for stack elevation: calibrated to prevent any overlapping
            const zElev = (3 - index) * 58;
            const lift = isHovered || isSelected ? 12 : 0;
            const finalZ = zElev + lift;

            // Color palette by status
            let plateBorder = "border-cyan-500/30";
            let plateBg = "bg-slate-900/80";
            let glowColor = "rgba(34, 211, 238, 0.25)";
            let badgeBg = "bg-cyan-500/20 text-cyan-300";

            if (status === "danger") {
              plateBorder = "border-red-500/70";
              plateBg = "bg-red-950/80";
              glowColor = "rgba(239, 68, 68, 0.4)";
              badgeBg = "bg-red-500/20 text-red-300";
            } else if (status === "safe") {
              plateBorder = "border-emerald-500/60";
              plateBg = "bg-emerald-950/80";
              glowColor = "rgba(16, 185, 129, 0.35)";
              badgeBg = "bg-emerald-500/20 text-emerald-300";
            } else if (status === "analyzing") {
              plateBorder = "border-blue-400";
              plateBg = "bg-blue-950/90";
              glowColor = "rgba(59, 130, 246, 0.5)";
              badgeBg = "bg-blue-500/20 text-blue-300";
            } else if (status === "warning") {
              plateBorder = "border-amber-500/60";
              plateBg = "bg-amber-950/80";
              glowColor = "rgba(245, 158, 11, 0.35)";
              badgeBg = "bg-amber-500/20 text-amber-300";
            }

            const LayerIcon = layer.icon;

            return (
              <div
                key={layer.id}
                onClick={() => setSelectedLayer(layer.id)}
                onMouseEnter={() => setHoveredLayer(layer.id)}
                onMouseLeave={() => setHoveredLayer(null)}
                className={cn(
                  "absolute left-0 right-0 h-[56px] rounded-xl border cursor-pointer transition-all duration-300 ease-out backdrop-blur-md flex items-center justify-between px-4 py-2 select-none shadow-xl",
                  plateBorder,
                  plateBg,
                  isSelected && "ring-2 ring-cyan-400/80",
                  status === "analyzing" && "animate-pulse"
                )}
                style={{
                  top: "calc(50% - 28px)",
                  transform: `translateZ(${finalZ}px)`,
                  boxShadow: `0 10px 25px -5px ${glowColor}, inset 0 1px 2px rgba(255, 255, 255, 0.15)`,
                }}
              >
                {/* Plate Surface Decor */}
                <div className="flex items-center gap-2.5">
                  <div
                    className={cn(
                      "w-7 h-7 rounded-lg flex items-center justify-center border border-white/10 shadow-inner",
                      badgeBg
                    )}
                  >
                    <LayerIcon className="w-3.5 h-3.5" />
                  </div>
                  <div>
                    <div className="text-xs font-semibold text-white tracking-wide">
                      {layer.shortName}
                    </div>
                    <div className="text-[10px] font-mono text-slate-400">
                      {layer.category}
                    </div>
                  </div>
                </div>

                {/* Right Status Indicator */}
                <div className="flex items-center gap-1.5">
                  {status === "danger" && (
                    <span className="flex items-center gap-1 text-[10px] font-mono font-bold text-red-400 bg-red-500/10 px-2 py-0.5 rounded border border-red-500/30">
                      <Flame className="w-3 h-3" /> THREAT
                    </span>
                  )}
                  {status === "safe" && (
                    <span className="flex items-center gap-1 text-[10px] font-mono font-bold text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/30">
                      <CheckCircle className="w-3 h-3" /> CLEAN
                    </span>
                  )}
                  {status === "analyzing" && (
                    <span className="flex items-center gap-1 text-[10px] font-mono font-bold text-blue-400 bg-blue-500/10 px-2 py-0.5 rounded border border-blue-500/30">
                      SCANNING
                    </span>
                  )}
                  {status === "standby" && (
                    <span className="text-[10px] font-mono text-cyan-400/80 bg-cyan-500/10 px-1.5 py-0.5 rounded">
                      STANDBY
                    </span>
                  )}
                  {status === "done" && (
                    <span className="text-[10px] font-mono text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded">
                      VERIFIED
                    </span>
                  )}
                </div>

                {/* Cyber corner marks */}
                <div className="absolute top-1 left-1 w-1.5 h-1.5 border-t border-l border-white/30" />
                <div className="absolute bottom-1 right-1 w-1.5 h-1.5 border-b border-r border-white/30" />
              </div>
            );
          })}
        </div>
      </div>

      {/* Interactive Layer Detail HUD Bar */}
      <div className="relative z-10 pt-3 border-t border-white/5">
        <div className="flex items-center justify-between text-xs mb-1.5">
          <span className="font-semibold text-white flex items-center gap-1.5">
            <activeLayerData.icon className="w-3.5 h-3.5 text-cyan-400" />
            {activeLayerData.name}
          </span>
          <span className="font-mono text-[11px] text-cyan-400/80">
            {activeLayerData.weight}
          </span>
        </div>
        <p className="text-xs text-slate-300 leading-relaxed font-sans">
          {isCompleted && (result?.verdict === "dangerous" || result?.verdict === "high-risk")
            ? (activeLayerData.id === "heuristics" || activeLayerData.id === "content" ? activeLayerData.dangerDesc : activeLayerData.safeDesc)
            : isCompleted
            ? activeLayerData.safeDesc
            : isScanning
            ? activeLayerData.activeDesc
            : activeLayerData.standbyDesc}
        </p>
      </div>
    </div>
  );
}
