export function RedirectFlow({ hops }) {
  return (
    <div className="glass rounded-xl p-5">
      <div className="mb-4 flex items-center justify-between">
        <span className="text-sm font-medium text-slate-300">Redirect Chain</span>
        <span className="text-xs text-slate-500">{hops.length} hops</span>
      </div>
      <div className="space-y-3">
        {hops.map((hop, i) => (
          <div key={i} className="flex items-center gap-3 relative">
            <div
              className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold border shadow ${i === 0 ? "bg-blue-600/20 border-blue-500/50 text-blue-400" : i === hops.length - 1 ? "bg-red-600/20 border-red-500/50 text-red-400" : "bg-white/5 border-white/10 text-slate-400"}`}
            >
              {i + 1}
            </div>
            <div className="flex-1">
              <div className="text-sm text-slate-200 truncate" title={hop.url}>{hop.url}</div>
              <div className="text-[10px] text-slate-600 mt-0.5">HTTP {hop.status}</div>
            </div>
            {i < hops.length - 1 && (
              <svg className="w-4 h-4 text-slate-600 flex-shrink-0" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 5l7 7-7 7" />
              </svg>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
