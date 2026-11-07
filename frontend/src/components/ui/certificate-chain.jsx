export function CertificateChain({ chain }) {
  return (
    <div className="glass rounded-xl p-5">
      <div className="flex items-center justify-between mb-4">
        <span className="text-sm font-medium text-slate-300">Certificate Chain</span>
        <span className="text-xs text-slate-500">Root → Intermediate → Leaf</span>
      </div>
      <div className="relative flex items-center gap-4">
        {chain.map((node, i) => {
          const isLast = i === chain.length - 1;
          const statusColor =
            node.status === "trusted" || node.status === "valid"
              ? "text-emerald-400 border-emerald-500/30"
              : "text-amber-400 border-amber-500/30";
          return (
            <div key={node.name} className="flex flex-col items-center relative z-10">
              <div
                className={`w-10 h-10 rounded-full flex items-center justify-center border text-xs font-medium shadow-lg ${statusColor} bg-white/5`}
              >
                {i === 0 ? "R" : i === 1 ? "I" : "W"}
              </div>
              <div className="mt-2 text-xs text-slate-400 text-center max-w-[140px] leading-tight">
                {node.name}
              </div>
              <div className="text-[10px] text-slate-600 mt-0.5 capitalize">{node.type}</div>
              {!isLast && (
                <div className="absolute -top-6 left-1/2 -translate-x-1/2 w-1 h-2 bg-cyan-500/60 rounded-t" />
              )}
              {!isLast && i < chain.length - 1 && (
                <div
                  className="absolute top-10 left-1/2 -translate-x-1/2 w-px h-8 bg-white/10"
                />
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
