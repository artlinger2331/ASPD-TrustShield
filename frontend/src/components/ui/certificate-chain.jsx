import React from "react";
import { ArrowRight, ShieldCheck, Lock, Globe } from "lucide-react";

export function CertificateChain({ chain = [] }) {
  const getNodeMeta = (i, status) => {
    if (i === 0) {
      return {
        letter: "R",
        role: "Root CA",
        color: "text-emerald-400 border-emerald-500/50 bg-emerald-500/10 shadow-[0_0_14px_rgba(16,185,129,0.35)]",
        icon: ShieldCheck,
      };
    }
    if (i === 1) {
      return {
        letter: "I",
        role: "Intermediate CA",
        color: "text-cyan-400 border-cyan-500/50 bg-cyan-500/10 shadow-[0_0_14px_rgba(34,211,238,0.35)]",
        icon: Lock,
      };
    }
    return {
      letter: "W",
      role: "Leaf Cert",
      color: "text-amber-400 border-amber-500/50 bg-amber-500/10 shadow-[0_0_14px_rgba(245,158,11,0.35)]",
      icon: Globe,
    };
  };

  return (
    <div className="relative rounded-xl border border-white/10 hover:border-cyan-500/40 bg-gradient-to-b from-white/[0.06] via-slate-900/80 to-slate-950/90 backdrop-blur-md p-4 sm:p-5 shadow-[0_6px_20px_-2px_rgba(0,0,0,0.5),inset_0_1px_0_rgba(255,255,255,0.15),inset_0_-1px_2px_rgba(0,0,0,0.4)] transition-all overflow-hidden group">
      {/* 3D Top Bevel Specular Reflection */}
      <div className="absolute top-0 left-4 right-4 h-[1px] bg-gradient-to-r from-transparent via-cyan-400/30 to-transparent pointer-events-none" />
      <div className="absolute top-2 right-2 w-1.5 h-1.5 border-t border-r border-white/20 group-hover:border-cyan-400 transition-colors pointer-events-none" />

      {/* Header bar */}
      <div className="flex items-center justify-between mb-4 pb-2 border-b border-white/5">
        <span className="text-xs font-bold font-mono text-slate-200 tracking-wider uppercase flex items-center gap-1.5">
          <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
          Certificate Chain
        </span>
        <span className="text-[10px] font-mono text-cyan-400/80 px-2 py-0.5 rounded border border-cyan-500/20 bg-cyan-500/10">
          ROOT &rarr; INTERMEDIATE &rarr; LEAF
        </span>
      </div>

      {/* Chain flow nodes */}
      <div className="relative flex flex-wrap sm:flex-nowrap items-center justify-between gap-2 sm:gap-4 py-2">
        {chain.map((node, i) => {
          const isLast = i === chain.length - 1;
          const meta = getNodeMeta(i, node.status);
          const NodeIcon = meta.icon;

          return (
            <React.Fragment key={node.name || i}>
              <div className="flex-1 flex flex-col items-center text-center min-w-[90px] relative z-10 group/node">
                {/* 3D Glowing Node Hub */}
                <div
                  className={`w-11 h-11 rounded-xl flex items-center justify-center border font-mono text-sm font-bold transition-all duration-300 group-hover/node:scale-105 ${meta.color}`}
                >
                  <NodeIcon className="w-5 h-5" />
                </div>

                {/* Node details */}
                <div className="mt-2 text-xs font-semibold text-slate-200 text-center max-w-[130px] leading-tight truncate" title={node.name}>
                  {node.name}
                </div>
                <div className="text-[10px] font-mono text-slate-400 mt-0.5 uppercase tracking-wide">
                  {meta.role}
                </div>
              </div>

              {/* Connecting laser arrow */}
              {!isLast && (
                <div className="hidden sm:flex items-center justify-center px-1 text-cyan-400/60 shrink-0">
                  <div className="h-[2px] w-6 bg-gradient-to-r from-cyan-500/40 via-cyan-400 to-cyan-500/40 relative">
                    <span className="absolute -top-1 right-0 w-2 h-2 border-t-2 border-r-2 border-cyan-400 rotate-45" />
                  </div>
                </div>
              )}
            </React.Fragment>
          );
        })}
      </div>
    </div>
  );
}