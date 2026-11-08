import { useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  ShieldAlert,
  Search,
  Filter,
  Plus,
  Eye,
  Copy,
  Users,
  Link as LinkIcon,
  ExternalLink,
  Zap,
  Radio,
  ArrowRight,
  ShieldCheck,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { StatusBadge, SeverityBadge } from "@/components/ui/badge";
import { cn } from "@/utils/cn";
import { COMMUNITY_REPORTS } from "@/data/mockData";

const FILTERS = [
  "All",
  "Phishing",
  "Scam",
  "Malware",
  "Fake Recruitment",
  "Impersonation",
  "Payment Fraud",
];

export default function CommunityReports() {
  const navigate = useNavigate();
  const [filter, setFilter] = useState("All");
  const [search, setSearch] = useState("");

  const filtered = COMMUNITY_REPORTS.filter(
    (r) =>
      (filter === "All" || r.type === filter) &&
      r.url.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="w-full max-w-6xl mx-auto space-y-6 pb-12">
      {/* Page Title & Cyber Status Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-white/5">
        <div>
          <div className="flex items-center gap-2 mb-1.5">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse shadow-[0_0_8px_#22d3ee]" />
            <span className="text-xs font-mono tracking-widest uppercase text-cyan-400">
              Decentralized Threat Intelligence
            </span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
            Community Threat Reports
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Crowdsourced indicators of compromise verified by distributed SOC sensor nodes.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <Button
            onClick={() => navigate("/report")}
            className="bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white text-xs font-semibold shadow-lg shadow-cyan-500/25 transition-all cursor-pointer px-4 py-2.5 rounded-xl border border-cyan-400/30"
          >
            <Plus className="w-4 h-4 mr-2" /> Submit Report
          </Button>
        </div>
      </div>

      {/* 3D Filter Pills */}
      <div className="flex flex-wrap items-center gap-2">
        {FILTERS.map((f) => {
          const isActive = filter === f;
          return (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={cn(
                "px-3.5 py-1.5 rounded-xl text-xs font-mono font-medium border transition-all duration-200 cursor-pointer",
                isActive
                  ? "border-cyan-500/50 bg-gradient-to-r from-cyan-500/20 to-blue-600/20 text-cyan-300 shadow-[0_0_12px_rgba(34,211,238,0.25),inset_0_1px_0_rgba(255,255,255,0.2)] font-semibold"
                  : "border-white/10 bg-slate-900/60 hover:border-cyan-500/30 hover:bg-slate-800/80 text-slate-400 hover:text-slate-200"
              )}
            >
              {f}
            </button>
          );
        })}
      </div>

      {/* 3D Cyber Terminal Search Box */}
      <div className="relative rounded-xl border border-white/10 focus-within:border-cyan-400/60 focus-within:shadow-[0_0_20px_rgba(34,211,238,0.15)] bg-slate-950/70 p-1.5 transition-all">
        <div className="flex items-center px-2 py-1">
          <Search className="w-4 h-4 text-cyan-400 shrink-0 mr-2.5" />
          <input
            type="text"
            placeholder="Search reports by URL (e.g. sbi, verify-account, paypal)..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-transparent text-sm text-slate-100 placeholder-slate-500 focus:outline-none font-mono py-1"
          />
          {search && (
            <button
              onClick={() => setSearch("")}
              className="text-xs font-mono text-slate-400 hover:text-white px-2 py-0.5 rounded bg-white/5"
            >
              Clear
            </button>
          )}
        </div>
      </div>

      {/* Threat Report Cards with 3D Cyber Borders */}
      <div className="space-y-4">
        {filtered.length === 0 ? (
          <div className="relative rounded-2xl border border-white/10 bg-gradient-to-b from-slate-900/90 to-navy-950/90 backdrop-blur-xl p-12 text-center shadow-xl">
            <Users className="w-12 h-12 mx-auto mb-3 text-cyan-500/40 animate-pulse" />
            <h3 className="text-base font-bold text-white font-mono">No matching threat reports found</h3>
            <p className="text-xs text-slate-400 mt-1 font-sans">
              Try selecting a different filter category or clearing your search term.
            </p>
          </div>
        ) : (
          filtered.map((report) => {
            const isCritical = report.risk === "Critical";
            const isHigh = report.risk === "High";
            const isMedium = report.risk === "Medium";

            const cardBorderStyles = isCritical
              ? "border-red-500/40 hover:border-red-400 bg-gradient-to-b from-red-950/20 via-slate-900/90 to-navy-950/95 shadow-[0_8px_24px_-4px_rgba(239,68,68,0.25),inset_0_1px_1px_rgba(255,255,255,0.15),inset_0_-2px_4px_rgba(0,0,0,0.6)]"
              : isHigh
              ? "border-orange-500/40 hover:border-orange-400 bg-gradient-to-b from-orange-950/20 via-slate-900/90 to-navy-950/95 shadow-[0_8px_24px_-4px_rgba(249,115,22,0.25),inset_0_1px_1px_rgba(255,255,255,0.15)]"
              : isMedium
              ? "border-amber-500/35 hover:border-amber-400 bg-gradient-to-b from-amber-950/15 via-slate-900/90 to-navy-950/95 shadow-[0_8px_24px_-4px_rgba(245,158,11,0.2),inset_0_1px_1px_rgba(255,255,255,0.15)]"
              : "border-cyan-500/35 hover:border-cyan-400 bg-gradient-to-b from-cyan-950/15 via-slate-900/90 to-navy-950/95 shadow-[0_8px_24px_-4px_rgba(6,182,212,0.2),inset_0_1px_1px_rgba(255,255,255,0.15)]";

            const pillarGlow = isCritical
              ? "bg-red-500 shadow-[0_0_10px_#ef4444]"
              : isHigh
              ? "bg-orange-500 shadow-[0_0_10px_#f97316]"
              : isMedium
              ? "bg-amber-500 shadow-[0_0_10px_#f59e0b]"
              : "bg-cyan-400 shadow-[0_0_10px_#22d3ee]";

            return (
              <div
                key={report.id}
                className={cn(
                  "relative rounded-2xl border transition-all duration-300 hover:-translate-y-1 hover:scale-[1.008] p-4 sm:p-5 overflow-hidden group select-text",
                  cardBorderStyles
                )}
              >
                {/* 3D Vertical Neon Edge Pillar */}
                <div className={cn("absolute left-0 top-0 bottom-0 w-1", pillarGlow)} />

                {/* 3D Top Specular Light Line */}
                <div className="absolute top-0 left-6 right-6 h-[1px] bg-gradient-to-r from-transparent via-white/20 to-transparent pointer-events-none" />

                {/* Cyber Corner Marks */}
                <div className="absolute top-2.5 right-2.5 w-1.5 h-1.5 border-t border-r border-white/25 pointer-events-none" />

                <div className="flex flex-col sm:flex-row items-start gap-4 pl-1.5">
                  {/* Screenshot Thumbnail with Cyber Rim */}
                  <div className="relative shrink-0 w-full sm:w-28 h-24 sm:h-20 rounded-xl overflow-hidden border border-white/10 shadow-lg bg-black/40">
                    <img
                      src={report.screenshot}
                      alt="Report screenshot"
                      className="w-full h-full object-cover grayscale group-hover:grayscale-0 transition-all duration-300"
                    />
                    <div className="absolute inset-0 bg-gradient-to-t from-black/80 via-transparent to-transparent pointer-events-none" />
                    <span className="absolute bottom-1 left-1.5 text-[9px] font-mono text-cyan-300 bg-black/60 px-1 py-0.2 rounded border border-white/10">
                      EVIDENCE
                    </span>
                  </div>

                  {/* Body Info */}
                  <div className="flex-1 min-w-0">
                    {/* Title & Badges */}
                    <div className="flex flex-wrap items-center gap-2 mb-1.5">
                      <span className="text-sm font-bold text-white font-mono tracking-tight truncate max-w-md" title={report.url}>
                        {report.url}
                      </span>
                      <StatusBadge status={report.status} />
                    </div>

                    <div className="flex items-center gap-2 mb-2">
                      <SeverityBadge severity={report.risk}>{report.risk}</SeverityBadge>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-white/10 bg-white/5 text-slate-300 uppercase tracking-wider">
                        {report.type}
                      </span>
                    </div>

                    {/* Threat Narrative */}
                    <p className="text-xs text-slate-300 leading-relaxed font-sans line-clamp-2 mb-3">
                      {report.description}
                    </p>

                    {/* Footer Telemetry & Metadata */}
                    <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-white/5 text-xs text-slate-400 font-mono">
                      <div className="flex items-center gap-3">
                        <span className="flex items-center gap-1.5 text-[11px] text-cyan-400">
                          <Users className="w-3.5 h-3.5" />
                          <strong className="text-white">{report.confirmations}</strong> SOC confirmations
                        </span>
                        <span className="text-slate-600 hidden sm:inline">&bull;</span>
                        <span className="text-[11px] text-slate-400">
                          Submitted by: <span className="text-slate-300 font-semibold">{report.reporter}</span>
                        </span>
                      </div>

                      {/* Quick Inspect CTA */}
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => navigate(`/scan?url=${encodeURIComponent(report.url)}`)}
                          className="px-2.5 py-1 rounded-lg border border-cyan-500/30 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 text-[11px] font-mono transition-all flex items-center gap-1 cursor-pointer"
                        >
                          <Zap className="w-3 h-3 text-cyan-400 fill-current" />
                          <span>Inspect Target</span>
                          <ArrowRight className="w-3 h-3 ml-0.5" />
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* Cyber Security Banner Footer */}
      <div className="mt-8 pt-4 border-t border-white/5 text-center text-xs font-mono text-slate-500 flex items-center justify-center gap-2">
        <ShieldCheck className="w-4 h-4 text-emerald-400" />
        <span>Community threat intelligence synchronizing across 80+ distributed consensus validator nodes.</span>
      </div>
    </div>
  );
}