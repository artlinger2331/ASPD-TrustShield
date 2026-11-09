<<<<<<< .merge_file_PB9NNZ
import { useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { cn } from "@/utils/cn";
import {
  FileText,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Copy,
  Download,
  Eye,
  Code,
  Link as LinkIcon,
  ChevronDown,
  ShieldCheck,
  Lock,
  Terminal,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from "@/components/ui/card";
import {
  Badge,
  SeverityBadge,
  StatusBadge,
  HeaderCheck,
  VerdictBadge,
} from "@/components/ui/badge";
import { RiskGauge } from "@/components/ui/gauge";
import { CertificateChain } from "@/components/ui/certificate-chain";
import { RedirectFlow } from "@/components/ui/redirect-flow";
import { Modal } from "@/components/ui/modal";
import { useToast } from "@/hooks/useAuth";
import {
  formatDate,
  formatDateTime,
  daysUntil,
  riskColor,
  verdictLabel,
} from "@/utils/formatters";
import {
  MOCK_SCAN_RESULT,
  MOCK_PHISHING_ANALYSIS,
  MOCK_CERT_ANALYSIS,
  MOCK_SECURITY_HEADERS,
  MOCK_THREAT_INTEL,
  MOCK_EVIDENCE,
} from "@/data/mockData";

export default function ScanReport() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { toast } = useToast();
  const [modalOpen, setModalOpen] = useState(false);
  const [expanded, setExpanded] = useState(new Set());

  const scan = MOCK_SCAN_RESULT;
  const scoreColor = riskColor(scan.score);

  const toggleSection = (key) => {
    const next = new Set(expanded);
    if (next.has(key)) next.delete(key);
    else next.add(key);
    setExpanded(next);
  };
  const isExpanded = (key) => expanded.has(key);

  return (
    <div className="min-h-screen flex flex-col">
      <Modal open={modalOpen} onClose={() => setModalOpen(false)} title="Export Report">
        <div className="space-y-4">
          <p className="text-sm text-slate-400">
            Export the full technical report for this scan. PDF includes all sections,
            evidence, and raw findings.
          </p>
          <div className="flex gap-2 pt-4">
            <Button onClick={() => { setModalOpen(false); toast({ title: "PDF exported", type: "success" }); }}>
              <Download className="w-4 h-4 mr-2" /> Download PDF
            </Button>
            <Button variant="outline" onClick={() => setModalOpen(false)}>
              Cancel
            </Button>
          </div>
        </div>
      </Modal>

      <div className="flex-1 overflow-y-auto py-6 px-4 sm:px-6 lg:px-8 max-w-6xl mx-auto">
        {/* Header */}
        <div className="mb-8 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <div className="px-2.5 py-0.5 rounded-full border border-cyan-500/30 bg-cyan-500/10 text-cyan-300 font-mono text-[11px] font-semibold flex items-center gap-1.5 shadow-[0_0_10px_rgba(34,211,238,0.2)]">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse shadow-[0_0_6px_#22d3ee]" />
                SCAN REPORT
              </div>
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight break-all">
              {scan.url}
            </h1>
            <p className="text-sm font-mono text-slate-400 mt-1">
              Scan ID: <span className="text-slate-300">{scan.id}</span> &nbsp;•&nbsp; Scanned {formatDateTime(scan.scannedAt)}
            </p>
          </div>
          <div className="flex items-center gap-2.5 self-start md:self-center">
            <button
              onClick={() => setModalOpen(true)}
              className="px-3.5 py-2 rounded-xl border border-white/10 hover:border-cyan-400/50 bg-gradient-to-b from-white/[0.08] to-white/[0.02] hover:bg-cyan-500/10 text-xs font-mono font-medium text-slate-200 hover:text-white shadow-[0_4px_12px_-2px_rgba(0,0,0,0.5),inset_0_1px_0_rgba(255,255,255,0.18)] transition-all flex items-center cursor-pointer"
            >
              <Download className="w-3.5 h-3.5 mr-1.5 text-cyan-400" /> Export PDF
            </button>
            <button
              onClick={() => {
                navigator.clipboard.writeText(JSON.stringify(scan, null, 2));
                toast({ title: "JSON copied to clipboard", type: "success" });
              }}
              className="px-3.5 py-2 rounded-xl border border-white/10 hover:border-cyan-400/50 bg-gradient-to-b from-white/[0.08] to-white/[0.02] hover:bg-cyan-500/10 text-xs font-mono font-medium text-slate-200 hover:text-white shadow-[0_4px_12px_-2px_rgba(0,0,0,0.5),inset_0_1px_0_rgba(255,255,255,0.18)] transition-all flex items-center cursor-pointer"
            >
              <Copy className="w-3.5 h-3.5 mr-1.5 text-cyan-400" /> JSON
            </button>
          </div>
        </div>

        {/* A. Summary Card with 3D Cyber Border Styling */}
        <div className="relative rounded-2xl border border-cyan-500/30 bg-gradient-to-b from-slate-900/95 via-navy-900/90 to-navy-950/95 backdrop-blur-2xl shadow-[0_12px_40px_-8px_rgba(0,0,0,0.7),inset_0_1px_1px_rgba(255,255,255,0.15)] mb-6 p-5 sm:p-6 overflow-hidden">
          {/* Top Specular Edge Highlight */}
          <div className="absolute top-0 left-6 right-6 h-[1px] bg-gradient-to-r from-transparent via-cyan-400/40 to-transparent pointer-events-none" />

          {/* Cyber Corner Marks */}
          <div className="absolute top-2.5 left-2.5 w-2 h-2 border-t border-l border-cyan-400/40 pointer-events-none" />
          <div className="absolute top-2.5 right-2.5 w-2 h-2 border-t border-r border-cyan-400/40 pointer-events-none" />
          <div className="absolute bottom-2.5 left-2.5 w-2 h-2 border-b border-l border-cyan-400/30 pointer-events-none" />
          <div className="absolute bottom-2.5 right-2.5 w-2 h-2 border-b border-r border-cyan-400/30 pointer-events-none" />

          {/* Section Header */}
          <div className="mb-5 pb-3 border-b border-white/5 flex items-center justify-between">
            <div>
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse shadow-[0_0_8px_#22d3ee]" />
                <h3 className="text-sm font-bold text-white tracking-wide uppercase font-mono">A. Summary</h3>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">High-level verdict and risk assessment.</p>
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-cyan-500/20 bg-cyan-500/10 text-cyan-400 hidden sm:inline-block">
              DIAGNOSTIC SUMMARY
            </span>
          </div>

          {/* 6 Metric Pods with 3D Beveled Borders */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5">
            {/* Scanned URL */}
            <div className="relative rounded-xl border border-white/10 hover:border-cyan-500/40 bg-gradient-to-b from-white/[0.06] via-slate-900/80 to-slate-950/90 backdrop-blur-md p-3.5 shadow-[0_6px_16px_-2px_rgba(0,0,0,0.5),inset_0_1px_0_rgba(255,255,255,0.12),inset_0_-1px_2px_rgba(0,0,0,0.4)] transition-all duration-300 hover:-translate-y-0.5 group overflow-hidden">
              <div className="absolute top-1.5 right-1.5 w-1 h-1 border-t border-r border-white/20 group-hover:border-cyan-400 transition-colors" />
              <div className="text-[10px] font-mono uppercase text-slate-400 tracking-wider mb-1 flex items-center gap-1.5">
                <span className="w-1 h-1 rounded-full bg-cyan-400/70" />
                Scanned URL
              </div>
              <div className="text-sm font-medium text-slate-100 font-mono truncate" title={scan.url}>
                {scan.url}
              </div>
            </div>

            {/* Final URL */}
            <div className="relative rounded-xl border border-white/10 hover:border-cyan-500/40 bg-gradient-to-b from-white/[0.06] via-slate-900/80 to-slate-950/90 backdrop-blur-md p-3.5 shadow-[0_6px_16px_-2px_rgba(0,0,0,0.5),inset_0_1px_0_rgba(255,255,255,0.12),inset_0_-1px_2px_rgba(0,0,0,0.4)] transition-all duration-300 hover:-translate-y-0.5 group overflow-hidden">
              <div className="absolute top-1.5 right-1.5 w-1 h-1 border-t border-r border-white/20 group-hover:border-cyan-400 transition-colors" />
              <div className="text-[10px] font-mono uppercase text-slate-400 tracking-wider mb-1 flex items-center gap-1.5">
                <span className="w-1 h-1 rounded-full bg-cyan-400/70" />
                Final URL
              </div>
              <div className="text-sm font-medium text-slate-100 font-mono truncate" title={scan.finalUrl}>
                {scan.finalUrl}
              </div>
            </div>

            {/* Scan Time */}
            <div className="relative rounded-xl border border-white/10 hover:border-cyan-500/40 bg-gradient-to-b from-white/[0.06] via-slate-900/80 to-slate-950/90 backdrop-blur-md p-3.5 shadow-[0_6px_16px_-2px_rgba(0,0,0,0.5),inset_0_1px_0_rgba(255,255,255,0.12),inset_0_-1px_2px_rgba(0,0,0,0.4)] transition-all duration-300 hover:-translate-y-0.5 group overflow-hidden">
              <div className="absolute top-1.5 right-1.5 w-1 h-1 border-t border-r border-white/20 group-hover:border-cyan-400 transition-colors" />
              <div className="text-[10px] font-mono uppercase text-slate-400 tracking-wider mb-1 flex items-center gap-1.5">
                <span className="w-1 h-1 rounded-full bg-cyan-400/70" />
                Scan Time
              </div>
              <div className="text-sm font-medium text-slate-200">
                {formatDateTime(scan.scannedAt)}
              </div>
            </div>

            {/* Overall Verdict */}
            <div className="relative rounded-xl border border-red-500/40 bg-gradient-to-b from-red-950/25 via-slate-900/80 to-slate-950/90 backdrop-blur-md p-3.5 shadow-[0_6px_18px_-2px_rgba(239,68,68,0.25),inset_0_1px_0_rgba(255,255,255,0.15)] transition-all duration-300 hover:-translate-y-0.5 group overflow-hidden">
              <div className="absolute top-0 left-0 bottom-0 w-1 bg-red-500 shadow-[0_0_8px_#ef4444]" />
              <div className="pl-1.5">
                <div className="text-[10px] font-mono uppercase text-slate-400 tracking-wider mb-1.5 flex items-center gap-1.5">
                  <span className="w-1 h-1 rounded-full bg-red-400" />
                  Overall Verdict
                </div>
                <VerdictBadge verdict={scan.verdict} />
              </div>
            </div>

            {/* Risk Score */}
            <div className="relative rounded-xl border border-orange-500/40 bg-gradient-to-b from-orange-950/25 via-slate-900/80 to-slate-950/90 backdrop-blur-md p-3.5 shadow-[0_6px_18px_-2px_rgba(249,115,22,0.25),inset_0_1px_0_rgba(255,255,255,0.15)] transition-all duration-300 hover:-translate-y-0.5 group overflow-hidden">
              <div className="absolute top-0 left-0 bottom-0 w-1 bg-orange-500 shadow-[0_0_8px_#f97316]" />
              <div className="pl-1.5">
                <div className="text-[10px] font-mono uppercase text-slate-400 tracking-wider mb-1 flex items-center gap-1.5">
                  <span className="w-1 h-1 rounded-full bg-orange-400" />
                  Risk Score
                </div>
                <div className="text-base font-extrabold font-mono text-white">
                  {scan.score} <span className="text-slate-400 text-xs font-normal">/ 100</span>
                </div>
              </div>
            </div>

            {/* Confidence */}
            <div className="relative rounded-xl border border-white/10 hover:border-cyan-500/40 bg-gradient-to-b from-white/[0.06] via-slate-900/80 to-slate-950/90 backdrop-blur-md p-3.5 shadow-[0_6px_16px_-2px_rgba(0,0,0,0.5),inset_0_1px_0_rgba(255,255,255,0.12),inset_0_-1px_2px_rgba(0,0,0,0.4)] transition-all duration-300 hover:-translate-y-0.5 group overflow-hidden">
              <div className="absolute top-1.5 right-1.5 w-1 h-1 border-t border-r border-white/20 group-hover:border-cyan-400 transition-colors" />
              <div className="text-[10px] font-mono uppercase text-slate-400 tracking-wider mb-1 flex items-center gap-1.5">
                <span className="w-1 h-1 rounded-full bg-cyan-400/70" />
                Confidence
              </div>
              <div className="text-sm font-semibold text-emerald-400 font-mono">
                {scan.confidence}
              </div>
            </div>
          </div>

          {/* Main Reason & Recommended Action with 3D Beveled Borders */}
          <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-3.5">
            {/* Main Reason */}
            <div className="relative rounded-xl border border-red-500/35 bg-gradient-to-b from-red-950/20 via-slate-900/80 to-slate-950/90 backdrop-blur-md p-4 shadow-[0_8px_20px_-3px_rgba(239,68,68,0.2),inset_0_1px_0_rgba(255,255,255,0.15),inset_0_-2px_4px_rgba(0,0,0,0.5)] overflow-hidden">
              <div className="absolute left-0 top-0 bottom-0 w-1 bg-red-500 shadow-[0_0_10px_#ef4444]" />
              <div className="pl-1.5">
                <div className="text-[10px] font-mono uppercase text-red-300 tracking-wider mb-1.5 font-bold flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-red-400" />
                  Main Threat Driver
                </div>
                <p className="text-sm text-slate-200 leading-relaxed">{scan.mainReason}</p>
              </div>
            </div>

            {/* Recommended Action */}
            <div className="relative rounded-xl border border-cyan-500/35 bg-gradient-to-b from-cyan-950/20 via-slate-900/80 to-slate-950/90 backdrop-blur-md p-4 shadow-[0_8px_20px_-3px_rgba(6,182,212,0.2),inset_0_1px_0_rgba(255,255,255,0.15),inset_0_-2px_4px_rgba(0,0,0,0.5)] overflow-hidden">
              <div className="absolute left-0 top-0 bottom-0 w-1 bg-cyan-400 shadow-[0_0_10px_#22d3ee]" />
              <div className="pl-1.5">
                <div className="text-[10px] font-mono uppercase text-cyan-300 tracking-wider mb-1.5 font-bold flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
                  Recommended Action
                </div>
                <p className="text-sm text-slate-200 leading-relaxed">{scan.recommendedAction}</p>
              </div>
            </div>
          </div>

          {/* 3D Risk Gauge Footer with Ambient Slot */}
          <div className="w-full pt-5 mt-4 border-t border-white/5 flex flex-col items-center justify-center">
            <RiskGauge score={scan.score} size={160} className="mx-auto" />
          </div>
        </div>

        {/* B. Phishing Analysis */}
        <Card className="mb-6">
          <CardHeader className="flex items-center justify-between">
            <div>
              <CardTitle className="text-sm">B. Phishing Analysis</CardTitle>
              <CardDescription>Indicators of phishing, brand impersonation, and credential harvesting.</CardDescription>
            </div>
            <div className="flex gap-2">
              <Button variant="ghost" size="sm" onClick={() => toggleSection("all")}>
                {isExpanded("all") ? "Collapse all" : "Expand all"}
              </Button>
            </div>
          </CardHeader>
          <CardContent className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {Object.entries(MOCK_PHISHING_ANALYSIS).map(([key, finding]) => {
              const sev = finding.severity;
              const borderStyles =
                sev === "Critical"
                  ? "border-red-500/50 hover:border-red-400 bg-gradient-to-b from-red-950/30 via-slate-900/90 to-navy-950/90 shadow-[0_8px_24px_-4px_rgba(239,68,68,0.3),inset_0_1px_1px_rgba(255,255,255,0.2),inset_0_-2px_4px_rgba(0,0,0,0.6)]"
                  : sev === "High"
                    ? "border-orange-500/50 hover:border-orange-400 bg-gradient-to-b from-orange-950/25 via-slate-900/90 to-navy-950/90 shadow-[0_8px_24px_-4px_rgba(249,115,22,0.3),inset_0_1px_1px_rgba(255,255,255,0.2),inset_0_-2px_4px_rgba(0,0,0,0.6)]"
                    : sev === "Medium"
                      ? "border-amber-500/40 hover:border-amber-400 bg-gradient-to-b from-amber-950/20 via-slate-900/90 to-navy-950/90 shadow-[0_8px_24px_-4px_rgba(245,158,11,0.25),inset_0_1px_1px_rgba(255,255,255,0.18),inset_0_-2px_4px_rgba(0,0,0,0.6)]"
                      : "border-cyan-500/40 hover:border-cyan-400 bg-gradient-to-b from-cyan-950/20 via-slate-900/90 to-navy-950/90 shadow-[0_8px_24px_-4px_rgba(6,182,212,0.25),inset_0_1px_1px_rgba(255,255,255,0.18),inset_0_-2px_4px_rgba(0,0,0,0.6)]";

              const pillarGlow =
                sev === "Critical"
                  ? "bg-red-500 shadow-[0_0_12px_#ef4444]"
                  : sev === "High"
                    ? "bg-orange-500 shadow-[0_0_12px_#f97316]"
                    : sev === "Medium"
                      ? "bg-amber-500 shadow-[0_0_12px_#f59e0b]"
                      : "bg-cyan-500 shadow-[0_0_12px_#06b6d4]";

              return (
                <div
                  key={key}
                  className={cn(
                    "relative p-4 rounded-2xl border transition-all duration-300 hover:-translate-y-1 hover:scale-[1.01] overflow-hidden group",
                    borderStyles
                  )}
                >
                  {/* 3D Vertical Neon Edge Pillar */}
                  <div className={cn("absolute left-0 top-0 bottom-0 w-1", pillarGlow)} />

                  {/* 3D Top Bevel Specular Reflection */}
                  <div className="absolute top-0 left-3 right-3 h-[1px] bg-gradient-to-r from-transparent via-white/25 to-transparent pointer-events-none" />

                  {/* Cyber Corner Reticle */}
                  <div className="absolute top-2 right-2 w-1.5 h-1.5 border-t border-r border-white/20 pointer-events-none" />

                  <div className="flex items-center justify-between mb-2 pl-1.5">
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={finding.severity}>{finding.severity}</SeverityBadge>
                      <span className="text-xs font-semibold text-slate-200 tracking-wide">{finding.label}</span>
                    </div>
                    <button
                      onClick={() => toggleSection(key)}
                      className="p-1 text-slate-500 hover:text-white transition-colors"
                      aria-label={isExpanded(key) ? "Collapse" : "Expand"}
                    >
                      <ChevronDown className={cn("w-3 h-3 transition-transform", isExpanded(key) && "rotate-180")} />
                    </button>
                  </div>
                  <p className="text-sm text-slate-300 leading-relaxed pl-1.5">{finding.detail}</p>
                  {finding.hops && isExpanded(key) && (
                    <div className="mt-3 ml-1.5 p-3 rounded-xl bg-black/40 border border-white/10 shadow-inner">
                      <div className="text-xs font-semibold text-slate-400 mb-2 uppercase font-mono">Redirect path</div>
                      <RedirectFlow hops={finding.hops} />
                    </div>
                  )}
                </div>
              );
            })}
          </CardContent>
        </Card>

        {/* C. Certificate & Trust with 3D Cyber Border Styling */}
        <div className="relative rounded-2xl border border-cyan-500/30 bg-gradient-to-b from-slate-900/95 via-navy-900/90 to-navy-950/95 backdrop-blur-2xl shadow-[0_12px_40px_-8px_rgba(0,0,0,0.7),inset_0_1px_1px_rgba(255,255,255,0.15)] mb-6 p-5 sm:p-6 overflow-hidden">
          {/* Top Specular Edge Highlight */}
          <div className="absolute top-0 left-6 right-6 h-[1px] bg-gradient-to-r from-transparent via-cyan-400/40 to-transparent pointer-events-none" />
          
          {/* Cyber Corner Marks */}
          <div className="absolute top-2.5 left-2.5 w-2 h-2 border-t border-l border-cyan-400/40 pointer-events-none" />
          <div className="absolute top-2.5 right-2.5 w-2 h-2 border-t border-r border-cyan-400/40 pointer-events-none" />
          <div className="absolute bottom-2.5 left-2.5 w-2 h-2 border-b border-l border-cyan-400/30 pointer-events-none" />
          <div className="absolute bottom-2.5 right-2.5 w-2 h-2 border-b border-r border-cyan-400/30 pointer-events-none" />

          {/* Section Header */}
          <div className="mb-5 pb-3 border-b border-white/5 flex items-center justify-between">
            <div>
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse shadow-[0_0_8px_#22d3ee]" />
                <h3 className="text-sm font-bold text-white tracking-wide uppercase font-mono">
                  C. Certificate &amp; Trust Analysis
                </h3>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">HTTPS status, certificate chain, and cryptographic trust signals.</p>
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-cyan-500/20 bg-cyan-500/10 text-cyan-400 hidden sm:inline-block">
              X.509 CRYPTOGRAPHIC AUDIT
            </span>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Left 2 Columns: Certificate Chain & HTTPS Technical Grid */}
            <div className="lg:col-span-2 space-y-4">
              <CertificateChain chain={MOCK_CERT_ANALYSIS.chain} />

              {/* 3D Beveled Certificate Specs Pod */}
              <div className="relative rounded-xl border border-white/10 hover:border-cyan-500/40 bg-gradient-to-b from-white/[0.05] via-slate-900/80 to-slate-950/90 backdrop-blur-md p-4 shadow-[0_6px_20px_-2px_rgba(0,0,0,0.5),inset_0_1px_0_rgba(255,255,255,0.12),inset_0_-1px_2px_rgba(0,0,0,0.4)] transition-all overflow-hidden group">
                <div className="absolute top-1.5 right-1.5 w-1 h-1 border-t border-r border-white/20 group-hover:border-cyan-400 transition-colors pointer-events-none" />
                
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-3.5 text-sm">
                  <div className="p-2.5 rounded-lg bg-black/20 border border-white/5">
                    <div className="text-[10px] font-mono text-slate-400 uppercase tracking-wider mb-1">HTTPS status</div>
                    <div className="text-emerald-400 font-semibold font-mono text-xs flex items-center gap-1.5">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                      Secure (TLS 1.3)
                    </div>
                  </div>
                  <div className="p-2.5 rounded-lg bg-black/20 border border-white/5">
                    <div className="text-[10px] font-mono text-slate-400 uppercase tracking-wider mb-1">Issuer CA</div>
                    <div className="text-slate-100 font-medium text-xs font-mono truncate" title={MOCK_CERT_ANALYSIS.issuer}>
                      {MOCK_CERT_ANALYSIS.issuer}
                    </div>
                  </div>
                  <div className="p-2.5 rounded-lg bg-black/20 border border-white/5">
                    <div className="text-[10px] font-mono text-slate-400 uppercase tracking-wider mb-1">Valid from</div>
                    <div className="text-slate-200 font-medium text-xs font-mono">{MOCK_CERT_ANALYSIS.validFrom}</div>
                  </div>
                  <div className="p-2.5 rounded-lg bg-black/20 border border-white/5">
                    <div className="text-[10px] font-mono text-slate-400 uppercase tracking-wider mb-1">Expires on</div>
                    <div className="text-slate-200 font-medium text-xs font-mono">{MOCK_CERT_ANALYSIS.validTo}</div>
                  </div>
                  <div className="p-2.5 rounded-lg bg-black/20 border border-white/5">
                    <div className="text-[10px] font-mono text-slate-400 uppercase tracking-wider mb-1">Days to expiry</div>
                    <div className="text-cyan-300 font-bold text-xs font-mono">{MOCK_CERT_ANALYSIS.daysUntilExpiry} days</div>
                  </div>
                  <div className="p-2.5 rounded-lg bg-black/20 border border-white/5">
                    <div className="text-[10px] font-mono text-slate-400 uppercase tracking-wider mb-1">Root CA trust</div>
                    <div className="text-emerald-400 font-semibold text-xs font-mono">{MOCK_CERT_ANALYSIS.caTrust}</div>
                  </div>
                </div>

                {/* 3D Warning Box */}
                <div className="mt-3.5 relative rounded-xl border border-amber-500/40 bg-gradient-to-b from-amber-950/25 via-slate-900/80 to-slate-950/90 p-3.5 shadow-[0_4px_16px_-2px_rgba(245,158,11,0.25),inset_0_1px_0_rgba(255,255,255,0.15)] overflow-hidden">
                  <div className="absolute left-0 top-0 bottom-0 w-1 bg-amber-400 shadow-[0_0_8px_#f59e0b]" />
                  <div className="flex items-start gap-2.5 pl-1.5">
                    <AlertTriangle className="w-4 h-4 text-amber-400 mt-0.5 shrink-0" />
                    <p className="text-xs text-amber-200/90 leading-relaxed font-sans">
                      {MOCK_CERT_ANALYSIS.warning}
                    </p>
                  </div>
                </div>
              </div>
            </div>

            {/* Right Column: 3 Dedicated 3D Cyber Metric Pods */}
            <div className="space-y-3.5">
              {/* Revocation Pod */}
              <div className="relative rounded-xl border border-white/10 hover:border-emerald-500/40 bg-gradient-to-b from-white/[0.06] via-slate-900/80 to-slate-950/90 backdrop-blur-md p-4 shadow-[0_6px_18px_-2px_rgba(0,0,0,0.5),inset_0_1px_0_rgba(255,255,255,0.12),inset_0_-1px_2px_rgba(0,0,0,0.4)] transition-all duration-300 hover:-translate-y-0.5 group overflow-hidden">
                <div className="absolute top-1.5 right-1.5 w-1 h-1 border-t border-r border-white/20 group-hover:border-emerald-400 transition-colors pointer-events-none" />
                <div className="text-[10px] font-mono uppercase text-slate-400 tracking-wider mb-1.5 flex items-center gap-1.5">
                  <span className="w-1 h-1 rounded-full bg-emerald-400" />
                  Revocation Status (OCSP)
                </div>
                <div className="text-xs font-semibold font-mono text-slate-100 flex items-center justify-between">
                  <span>{MOCK_CERT_ANALYSIS.revocation}</span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                    PASS
                  </span>
                </div>
              </div>

              {/* Transparency Log Pod */}
              <div className="relative rounded-xl border border-white/10 hover:border-cyan-500/40 bg-gradient-to-b from-white/[0.06] via-slate-900/80 to-slate-950/90 backdrop-blur-md p-4 shadow-[0_6px_18px_-2px_rgba(0,0,0,0.5),inset_0_1px_0_rgba(255,255,255,0.12),inset_0_-1px_2px_rgba(0,0,0,0.4)] transition-all duration-300 hover:-translate-y-0.5 group overflow-hidden">
                <div className="absolute top-1.5 right-1.5 w-1 h-1 border-t border-r border-white/20 group-hover:border-cyan-400 transition-colors pointer-events-none" />
                <div className="text-[10px] font-mono uppercase text-slate-400 tracking-wider mb-1.5 flex items-center gap-1.5">
                  <span className="w-1 h-1 rounded-full bg-cyan-400" />
                  Transparency Log (CT)
                </div>
                <div className="text-xs font-semibold font-mono text-slate-100 flex items-center justify-between">
                  <span className="truncate pr-2">{MOCK_CERT_ANALYSIS.ctLog}</span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shrink-0">
                    VERIFIED
                  </span>
                </div>
              </div>

              {/* Weak Algorithm Pod */}
              <div className="relative rounded-xl border border-white/10 hover:border-emerald-500/40 bg-gradient-to-b from-white/[0.06] via-slate-900/80 to-slate-950/90 backdrop-blur-md p-4 shadow-[0_6px_18px_-2px_rgba(0,0,0,0.5),inset_0_1px_0_rgba(255,255,255,0.12),inset_0_-1px_2px_rgba(0,0,0,0.4)] transition-all duration-300 hover:-translate-y-0.5 group overflow-hidden">
                <div className="absolute top-1.5 right-1.5 w-1 h-1 border-t border-r border-white/20 group-hover:border-emerald-400 transition-colors pointer-events-none" />
                <div className="text-[10px] font-mono uppercase text-slate-400 tracking-wider mb-1.5 flex items-center gap-1.5">
                  <span className="w-1 h-1 rounded-full bg-emerald-400" />
                  Weak Cipher / Algorithm
                </div>
                <div className="text-xs font-semibold font-mono text-emerald-400 flex items-center justify-between">
                  <span>None detected</span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                    SHA-256
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* D. Security Assessment with 3D Cyber Border Styling */}
        <div className="relative rounded-2xl border border-cyan-500/30 bg-gradient-to-b from-slate-900/95 via-navy-900/90 to-navy-950/95 backdrop-blur-2xl shadow-[0_12px_40px_-8px_rgba(0,0,0,0.7),inset_0_1px_1px_rgba(255,255,255,0.15)] mb-6 p-5 sm:p-6 overflow-hidden">
          {/* Top Specular Edge Highlight */}
          <div className="absolute top-0 left-6 right-6 h-[1px] bg-gradient-to-r from-transparent via-cyan-400/40 to-transparent pointer-events-none" />
          
          {/* Cyber Corner Marks */}
          <div className="absolute top-2.5 left-2.5 w-2 h-2 border-t border-l border-cyan-400/40 pointer-events-none" />
          <div className="absolute top-2.5 right-2.5 w-2 h-2 border-t border-r border-cyan-400/40 pointer-events-none" />
          <div className="absolute bottom-2.5 left-2.5 w-2 h-2 border-b border-l border-cyan-400/30 pointer-events-none" />
          <div className="absolute bottom-2.5 right-2.5 w-2 h-2 border-b border-r border-cyan-400/30 pointer-events-none" />

          {/* Section Header */}
          <div className="mb-5 pb-3 border-b border-white/5 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse shadow-[0_0_8px_#22d3ee]" />
                <h3 className="text-sm font-bold text-white tracking-wide uppercase font-mono">
                  D. Website Security Assessment
                </h3>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">HTTP security headers and client protection policy checks.</p>
            </div>
            
            {/* Quick telemetry count pills */}
            <div className="flex items-center gap-2 self-start sm:self-center font-mono text-[10px]">
              <span className="px-2.5 py-1 rounded-lg border border-emerald-500/30 bg-emerald-500/10 text-emerald-400 font-bold flex items-center gap-1.5 shadow-[0_0_8px_rgba(16,185,129,0.2)]">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                PASS: 2
              </span>
              <span className="px-2.5 py-1 rounded-lg border border-amber-500/30 bg-amber-500/10 text-amber-400 font-bold flex items-center gap-1.5 shadow-[0_0_8px_rgba(245,158,11,0.2)]">
                <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
                WARN: 2
              </span>
              <span className="px-2.5 py-1 rounded-lg border border-red-500/30 bg-red-500/10 text-red-400 font-bold flex items-center gap-1.5 shadow-[0_0_8px_rgba(239,68,68,0.2)]">
                <span className="w-1.5 h-1.5 rounded-full bg-red-400" />
                FAIL: 6
              </span>
            </div>
          </div>

          {/* 3D Cyber Diagnostics Grid Table */}
          <div className="relative rounded-xl border border-white/10 bg-slate-950/70 backdrop-blur-md shadow-[0_6px_24px_-4px_rgba(0,0,0,0.6),inset_0_1px_0_rgba(255,255,255,0.12),inset_0_-1px_2px_rgba(0,0,0,0.4)] overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-cyan-500/20 bg-slate-900/90 text-cyan-300 font-mono text-[11px] uppercase tracking-wider">
                    <th className="px-4 py-3 font-semibold">Security Policy / Header</th>
                    <th className="px-4 py-3 font-semibold text-center w-28">Status</th>
                    <th className="px-4 py-3 font-semibold">Telemetry &amp; Findings</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5 font-mono text-xs">
                  {MOCK_SECURITY_HEADERS.map((h, i) => {
                    const isPass = h.status === "pass";
                    const isWarn = h.status === "warning";
                    const isFail = h.status === "fail";

                    const rowGlow = isPass
                      ? "hover:bg-emerald-500/[0.04]"
                      : isWarn
                      ? "hover:bg-amber-500/[0.04]"
                      : "hover:bg-red-500/[0.04]";

                    const pillarColor = isPass
                      ? "bg-emerald-500/80 shadow-[0_0_6px_#10b981]"
                      : isWarn
                      ? "bg-amber-500/80 shadow-[0_0_6px_#f59e0b]"
                      : "bg-red-500/80 shadow-[0_0_6px_#ef4444]";

                    return (
                      <tr key={i} className={cn("transition-colors relative group", rowGlow)}>
                        {/* Policy Name with 3D edge notch */}
                        <td className="px-4 py-3 font-medium text-slate-100 relative">
                          <div className={cn("absolute left-0 top-1 bottom-1 w-0.5 rounded-r", pillarColor)} />
                          <div className="flex items-center gap-2 pl-1">
                            {isPass ? (
                              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                            ) : isWarn ? (
                              <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                            ) : (
                              <ShieldAlert className="w-3.5 h-3.5 text-red-400 shrink-0" />
                            )}
                            <span className="font-semibold text-slate-100 font-sans">{h.name}</span>
                          </div>
                        </td>

                        {/* Status Badge */}
                        <td className="px-4 py-3 text-center">
                          <span
                            className={cn(
                              "inline-flex items-center justify-center px-2.5 py-0.5 rounded-full text-[10px] font-bold font-mono tracking-wider border shadow-sm",
                              isPass
                                ? "bg-emerald-500/15 text-emerald-300 border-emerald-500/40 shadow-[0_0_8px_rgba(16,185,129,0.25)]"
                                : isWarn
                                ? "bg-amber-500/15 text-amber-300 border-amber-500/40 shadow-[0_0_8px_rgba(245,158,11,0.25)]"
                                : "bg-red-500/15 text-red-300 border-red-500/40 shadow-[0_0_8px_rgba(239,68,68,0.25)]"
                            )}
                          >
                            {h.status.toUpperCase()}
                          </span>
                        </td>

                        {/* Details */}
                        <td className="px-4 py-3 text-slate-300 font-sans text-xs leading-relaxed">
                          {h.detail}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

          {/* Cyber Legend Bar */}
          <div className="mt-3.5 pt-3 border-t border-white/5 flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono text-slate-400">
            <div className="flex items-center gap-4">
              <span className="flex items-center gap-1.5 text-emerald-400">
                <span className="w-2 h-2 rounded-full bg-emerald-400" /> Pass = Zero issue found
              </span>
              <span className="flex items-center gap-1.5 text-amber-400">
                <span className="w-2 h-2 rounded-full bg-amber-400" /> Warning = Policy concern
              </span>
              <span className="flex items-center gap-1.5 text-red-400">
                <span className="w-2 h-2 rounded-full bg-red-400" /> Fail = Strict violation
              </span>
            </div>
            <span className="text-slate-500 text-[10px] hidden sm:inline">
              Security Policy Standard: OWASP ASVS v4.0
            </span>
          </div>
        </div>

        {/* E. Threat Intelligence with 3D Cyber Border Styling */}
        <div className="relative rounded-2xl border border-cyan-500/30 bg-gradient-to-b from-slate-900/95 via-navy-900/90 to-navy-950/95 backdrop-blur-2xl shadow-[0_12px_40px_-8px_rgba(0,0,0,0.7),inset_0_1px_1px_rgba(255,255,255,0.15)] mb-6 p-5 sm:p-6 overflow-hidden">
          {/* Top Specular Edge Highlight */}
          <div className="absolute top-0 left-6 right-6 h-[1px] bg-gradient-to-r from-transparent via-cyan-400/40 to-transparent pointer-events-none" />
          
          {/* Cyber Corner Marks */}
          <div className="absolute top-2.5 left-2.5 w-2 h-2 border-t border-l border-cyan-400/40 pointer-events-none" />
          <div className="absolute top-2.5 right-2.5 w-2 h-2 border-t border-r border-cyan-400/40 pointer-events-none" />
          <div className="absolute bottom-2.5 left-2.5 w-2 h-2 border-b border-l border-cyan-400/30 pointer-events-none" />
          <div className="absolute bottom-2.5 right-2.5 w-2 h-2 border-b border-r border-cyan-400/30 pointer-events-none" />

          {/* Section Header */}
          <div className="mb-5 pb-3 border-b border-white/5 flex items-center justify-between">
            <div>
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse shadow-[0_0_8px_#22d3ee]" />
                <h3 className="text-sm font-bold text-white tracking-wide uppercase font-mono">
                  E. Threat Intelligence
                </h3>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">Global feeds, autonomous ASN reputation, and crowdsourced telemetry.</p>
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-cyan-500/20 bg-cyan-500/10 text-cyan-400 hidden sm:inline-block">
              DECENTRALIZED IOC NETWORK
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5">
            {/* Feed Matches Pod */}
            <div className="relative rounded-xl border border-white/10 hover:border-cyan-500/40 bg-gradient-to-b from-white/[0.06] via-slate-900/80 to-slate-950/90 backdrop-blur-md p-4 shadow-[0_6px_18px_-2px_rgba(0,0,0,0.5),inset_0_1px_0_rgba(255,255,255,0.12),inset_0_-1px_2px_rgba(0,0,0,0.4)] transition-all overflow-hidden group">
              <div className="absolute top-1.5 right-1.5 w-1 h-1 border-t border-r border-white/20 group-hover:border-cyan-400 transition-colors pointer-events-none" />
              <div className="text-[10px] font-mono uppercase text-slate-400 tracking-wider mb-2.5 flex items-center gap-1.5">
                <span className="w-1 h-1 rounded-full bg-cyan-400" />
                Feed matches
              </div>
              {MOCK_THREAT_INTEL.feedMatches.map((m, i) => (
                <div key={i} className="flex items-center justify-between mb-2 p-1.5 rounded-lg bg-black/20 border border-white/5">
                  <span className="text-xs font-mono text-slate-300">{m.source}</span>
                  <Badge variant={m.confidence === "High" ? "high" : "medium"}>{m.confidence}</Badge>
                </div>
              ))}
            </div>

            {/* Domain Age Pod */}
            <div className="relative rounded-xl border border-white/10 hover:border-cyan-500/40 bg-gradient-to-b from-white/[0.06] via-slate-900/80 to-slate-950/90 backdrop-blur-md p-4 shadow-[0_6px_18px_-2px_rgba(0,0,0,0.5),inset_0_1px_0_rgba(255,255,255,0.12),inset_0_-1px_2px_rgba(0,0,0,0.4)] transition-all overflow-hidden group">
              <div className="absolute top-1.5 right-1.5 w-1 h-1 border-t border-r border-white/20 group-hover:border-cyan-400 transition-colors pointer-events-none" />
              <div className="text-[10px] font-mono uppercase text-slate-400 tracking-wider mb-2.5 flex items-center gap-1.5">
                <span className="w-1 h-1 rounded-full bg-cyan-400" />
                Domain age
              </div>
              <div className="text-xl font-bold font-mono text-slate-100 mt-2">
                {MOCK_THREAT_INTEL.domainAge}
              </div>
              <p className="text-[11px] text-amber-400 font-mono mt-1">EPHEMERAL TARGET // RECENT REGISTRATION</p>
            </div>

            {/* Community Reports Pod */}
            <div className="relative rounded-xl border border-white/10 hover:border-cyan-500/40 bg-gradient-to-b from-white/[0.06] via-slate-900/80 to-slate-950/90 backdrop-blur-md p-4 shadow-[0_6px_18px_-2px_rgba(0,0,0,0.5),inset_0_1px_0_rgba(255,255,255,0.12),inset_0_-1px_2px_rgba(0,0,0,0.4)] transition-all overflow-hidden group">
              <div className="absolute top-1.5 right-1.5 w-1 h-1 border-t border-r border-white/20 group-hover:border-cyan-400 transition-colors pointer-events-none" />
              <div className="text-[10px] font-mono uppercase text-slate-400 tracking-wider mb-2.5 flex items-center gap-1.5">
                <span className="w-1 h-1 rounded-full bg-cyan-400" />
                Community reports
              </div>
              <div className="text-xl font-bold font-mono text-red-400 mt-2">
                {MOCK_THREAT_INTEL.communityReports} reports
              </div>
              <p className="text-[11px] text-red-400/80 font-mono mt-1">CONFIRMED HOSTILE INCIDENTS</p>
            </div>

            {/* Hosting / IP reputation */}
            <div className="md:col-span-3 relative rounded-xl border border-red-500/35 bg-gradient-to-b from-red-950/20 via-slate-900/80 to-slate-950/90 backdrop-blur-md p-4 shadow-[0_6px_18px_-2px_rgba(239,68,68,0.2),inset_0_1px_0_rgba(255,255,255,0.12)] overflow-hidden">
              <div className="absolute left-0 top-0 bottom-0 w-1 bg-red-500 shadow-[0_0_8px_#ef4444]" />
              <div className="pl-1.5 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div>
                  <div className="text-[10px] font-mono uppercase text-slate-400 tracking-wider mb-1">Hosting / ASN Provider</div>
                  <p className="text-xs font-mono text-slate-200">{MOCK_THREAT_INTEL.hosting.provider}</p>
                </div>
                <span className="px-2.5 py-1 rounded-full font-mono text-[10px] font-bold bg-red-500/10 text-red-400 border border-red-500/30 self-start sm:self-center">
                  REPUTATION: POOR
                </span>
              </div>
            </div>

            {/* DNS records */}
            <div className="md:col-span-3 relative rounded-xl border border-white/10 hover:border-cyan-500/40 bg-gradient-to-b from-white/[0.05] via-slate-900/80 to-slate-950/90 backdrop-blur-md p-4 shadow-[0_6px_18px_-2px_rgba(0,0,0,0.5),inset_0_1px_0_rgba(255,255,255,0.12)] overflow-hidden">
              <div className="text-[10px] font-mono uppercase text-slate-400 tracking-wider mb-2 flex items-center gap-1.5">
                <span className="w-1 h-1 rounded-full bg-cyan-400" />
                DNS Records Telemetry
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs font-mono">
                <div className="p-2 rounded-lg bg-black/20 border border-white/5">
                  <span className="text-cyan-400 font-bold">A:</span> <span className="text-slate-300">{MOCK_THREAT_INTEL.dns.a}</span>
                </div>
                <div className="p-2 rounded-lg bg-black/20 border border-white/5">
                  <span className="text-cyan-400 font-bold">NS:</span> <span className="text-slate-300">{MOCK_THREAT_INTEL.dns.ns}</span>
                </div>
                <div className="p-2 rounded-lg bg-black/20 border border-white/5">
                  <span className="text-cyan-400 font-bold">MX:</span> <span className="text-slate-300">{MOCK_THREAT_INTEL.dns.mx}</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* F. Evidence with 3D Cyber Border Styling */}
        <div className="relative rounded-2xl border border-cyan-500/30 bg-gradient-to-b from-slate-900/95 via-navy-900/90 to-navy-950/95 backdrop-blur-2xl shadow-[0_12px_40px_-8px_rgba(0,0,0,0.7),inset_0_1px_1px_rgba(255,255,255,0.15)] mb-6 p-5 sm:p-6 overflow-hidden">
          {/* Top Specular Edge Highlight */}
          <div className="absolute top-0 left-6 right-6 h-[1px] bg-gradient-to-r from-transparent via-cyan-400/40 to-transparent pointer-events-none" />
          
          {/* Cyber Corner Marks */}
          <div className="absolute top-2.5 left-2.5 w-2 h-2 border-t border-l border-cyan-400/40 pointer-events-none" />
          <div className="absolute top-2.5 right-2.5 w-2 h-2 border-t border-r border-cyan-400/40 pointer-events-none" />

          {/* Section Header */}
          <div className="mb-5 pb-3 border-b border-white/5 flex items-center justify-between">
            <div>
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse shadow-[0_0_8px_#22d3ee]" />
                <h3 className="text-sm font-bold text-white tracking-wide uppercase font-mono">
                  F. Evidence &amp; Technical Findings
                </h3>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">Rendered viewport screenshot, credential harvest targets, and raw payload data.</p>
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-cyan-500/20 bg-cyan-500/10 text-cyan-400 hidden sm:inline-block">
              FORENSIC DOSSIER
            </span>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="space-y-4">
              <div className="aspect-video rounded-xl overflow-hidden border border-white/10 bg-slate-950 relative shadow-2xl">
                <img src={MOCK_EVIDENCE.screenshot} alt="Page screenshot" className="w-full h-full object-cover" />
                <div className="absolute bottom-0 left-0 right-0 p-2.5 bg-gradient-to-t from-black/90 via-black/50 to-transparent text-xs font-mono text-cyan-300 flex items-center justify-between">
                  <span>Rendered Viewport Capture</span>
                  <span className="text-[10px] text-slate-400 font-sans">1920x1080 Headless DOM</span>
                </div>
              </div>
              <div className="relative rounded-xl border border-white/10 bg-slate-950/70 p-3.5">
                <div className="text-[10px] font-mono text-slate-400 uppercase mb-1">Page Title Tag</div>
                <div className="text-sm font-semibold text-slate-100 font-mono">{MOCK_EVIDENCE.pageTitle}</div>
              </div>
            </div>

            <div className="space-y-4">
              {/* Detected Forms */}
              <div className="relative rounded-xl border border-red-500/30 bg-gradient-to-b from-red-950/20 to-slate-950/80 p-3.5 shadow-md">
                <div className="text-[10px] font-mono text-red-300 uppercase mb-2 font-bold flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-red-400" />
                  Detected Input Targets &amp; Forms
                </div>
                {MOCK_EVIDENCE.forms.map((f, i) => (
                  <div key={i} className="text-xs font-mono text-slate-300 p-2 rounded-lg bg-black/40 border border-white/5">
                    <span className="text-amber-400 font-bold">{f.method.toUpperCase()}</span> &rarr; {f.action}
                    <div className="text-[10px] text-slate-400 mt-1">Captured fields: {f.fields.join(", ")}</div>
                  </div>
                ))}
              </div>

              {/* External Scripts */}
              <div className="relative rounded-xl border border-white/10 bg-slate-950/70 p-3.5">
                <div className="text-[10px] font-mono text-slate-400 uppercase mb-2">External Scripts &amp; CDN Assets</div>
                <ul className="text-xs font-mono text-slate-300 space-y-1 list-disc list-inside">
                  {MOCK_EVIDENCE.externalScripts.map((s, i) => (
                    <li key={i} className="truncate">{s}</li>
                  ))}
                </ul>
              </div>

              {/* Redirect Path */}
              <div className="relative rounded-xl border border-white/10 bg-slate-950/70 p-3.5">
                <div className="text-[10px] font-mono text-slate-400 uppercase mb-2">Redirect Path Hops</div>
                <div className="text-xs text-slate-300 space-y-1 font-mono">
                  {MOCK_EVIDENCE.redirectPath.map((p, i) => (
                    <div key={i} className="flex items-center gap-1.5">
                      <span className="text-cyan-400 font-bold">[{i + 1}]</span> {p}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* Raw findings expandable */}
          <div className="mt-5 border-t border-white/5 pt-4">
            <details className="group">
              <summary className="flex items-center gap-2 cursor-pointer text-xs font-mono font-medium text-slate-400 hover:text-cyan-300 transition-colors">
                <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                Raw Machine-Readable Findings (JSON)
              </summary>
              <div className="mt-3 p-3.5 rounded-xl bg-slate-950 border border-white/10 overflow-x-auto shadow-inner">
                <pre className="text-xs text-cyan-300 font-mono overflow-x-auto whitespace-pre-wrap">
                  {JSON.stringify(
                    {
                      url: scan.url,
                      score: scan.score,
                      verdict: scan.verdict,
                      phishing: MOCK_PHISHING_ANALYSIS,
                      certificate: MOCK_CERT_ANALYSIS,
                      headers: MOCK_SECURITY_HEADERS,
                      threatIntel: MOCK_THREAT_INTEL,
                    },
                    null,
                    2
                  )}
                </pre>
              </div>
            </details>
          </div>

          {/* Footer CTAs */}
          <div className="mt-5 pt-4 border-t border-white/5 flex gap-3">
            <Button
              onClick={() => toast({ title: "Report Shared", description: "Telemetry dossier link saved to clipboard.", type: "success" })}
              className="bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white shadow-lg shadow-cyan-500/20"
            >
              <LinkIcon className="w-4 h-4 mr-2" /> Share Telemetry Dossier
            </Button>
            <Button variant="outline" onClick={() => navigate("/scan")}>
              Scan Another URL
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}
=======
import { useState, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { cn } from "@/utils/cn";
import {
  FileText,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Copy,
  Download,
  Eye,
  Code,
  Link as LinkIcon,
  ChevronDown,
  ShieldCheck,
  Lock,
  Terminal,
  Loader2,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from "@/components/ui/card";
import {
  Badge,
  SeverityBadge,
  StatusBadge,
  HeaderCheck,
  VerdictBadge,
} from "@/components/ui/badge";
import { RiskGauge } from "@/components/ui/gauge";
import { CertificateChain } from "@/components/ui/certificate-chain";
import { RedirectFlow } from "@/components/ui/redirect-flow";
import { ThreatIntelGraph } from "@/components/ui/threat-intel-graph";
import { Modal } from "@/components/ui/modal";
import { EmptyState } from "@/components/ui/empty-state";
import { Skeleton } from "@/components/ui/skeleton";
import { useToast } from "@/hooks/useAuth";
import { useScanReport } from "@/hooks/useScans";
import {
  formatDate,
  formatDateTime,
  daysUntil,
  riskColor,
  verdictLabel,
} from "@/utils/formatters";
import { scanApi } from "@/utils/api";
import {
  MOCK_SCAN_RESULT,
  MOCK_PHISHING_ANALYSIS,
  MOCK_CERT_ANALYSIS,
  MOCK_SECURITY_HEADERS,
  MOCK_THREAT_INTEL,
  MOCK_EVIDENCE,
} from "@/data/mockData";

export default function ScanReport() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { toast } = useToast();
  const [modalOpen, setModalOpen] = useState(false);
  const [expanded, setExpanded] = useState(new Set());

  // TanStack Query for detailed technical scan report
  const {
    data: report,
    isLoading: loading,
    isError,
    error,
    refetch,
  } = useScanReport(id);

  // Consolidate real data or fallback to mockData
  const scan = report
    ? {
        id: report.id,
        url: report.normalized_url || report.input_url,
        finalUrl: report.final_url || report.normalized_url || report.input_url,
        scannedAt: report.completed_at || report.started_at || new Date().toISOString(),
        score: report.risk_score ?? 0,
        verdict: report.verdict || "safe",
        verdictLabel: report.verdict_label || verdictLabel(report.verdict || "safe"),
        confidence:
          (report.confidence || 0) >= 0.85
            ? "High"
            : (report.confidence || 0) >= 0.65
            ? "Medium"
            : "Low",
        mainReason: report.summary || "Scan complete.",
        recommendedAction: report.recommendation || "Safe to browse.",
      }
    : MOCK_SCAN_RESULT;

  const scoreColor = riskColor(scan.score);

  // Split findings
  const realFindings = report?.findings || [];
  const phishingFindings = realFindings.filter((f) => f.category !== "security_headers");
  const headerFindings = realFindings.filter((f) => f.category === "security_headers");

  // Certificate data
  const certData = report?.certificate
    ? {
        https: true,
        issuer: report.certificate.issuer || "Trusted CA",
        validFrom: report.certificate.valid_from ? formatDate(report.certificate.valid_from) : "N/A",
        validTo: report.certificate.valid_to ? formatDate(report.certificate.valid_to) : "N/A",
        daysUntilExpiry: report.certificate.days_until_expiry ?? 90,
        chain: [
          { name: "Root CA", type: "Root CA", status: "trusted" },
          { name: report.certificate.issuer || "Intermediate CA", type: "Intermediate CA", status: "trusted" },
          { name: scan.url, type: "Website Certificate", status: report.certificate.is_valid ? "valid" : "invalid" },
        ],
        revocation: report.certificate.is_revoked ? "Revoked" : "Not revoked (OCSP)",
        ctLog: report.certificate.ct_log_present ? "Logged in Certificate Transparency" : "Missing CT Log",
        caTrust: report.certificate.ca_trust_status || "Trusted",
        weakAlgo: false,
        warning: report.certificate.is_valid
          ? "TLS certificate is valid and encrypted."
          : "Certificate has trust validation errors or has expired.",
      }
    : MOCK_CERT_ANALYSIS;

  // Security headers table
  const securityHeaders =
    headerFindings.length > 0
      ? headerFindings.map((f) => ({
          name: f.title,
          status: f.severity === "critical" || f.severity === "high" ? "fail" : f.severity === "medium" ? "warning" : "pass",
          detail: f.description,
        }))
      : MOCK_SECURITY_HEADERS;

  // Threat intel feeds
  const threatIntelMatches =
    report?.threat_intel && report.threat_intel.length > 0
      ? report.threat_intel.map((t) => ({
          source: t.source,
          match: t.match_type && t.match_type !== "CLEAN",
          confidence: (t.confidence || 0) >= 0.8 ? "High" : "Medium",
          detail: t.match_type || "Clean",
        }))
      : MOCK_THREAT_INTEL.feedMatches;

  const toggleSection = (key) => {
    const next = new Set(expanded);
    if (next.has(key)) next.delete(key);
    else next.add(key);
    setExpanded(next);
  };
  const isExpanded = (key) => expanded.has(key);

  if (loading) {
    return (
      <div className="min-h-screen py-8 px-4 sm:px-6 lg:px-8 max-w-6xl mx-auto space-y-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-white/5">
          <div className="space-y-2">
            <Skeleton className="h-4 w-32 rounded bg-cyan-500/10" />
            <Skeleton className="h-8 w-72 rounded-lg bg-white/5" />
            <Skeleton className="h-3 w-48 rounded bg-white/5" />
          </div>
          <div className="flex gap-2">
            <Skeleton className="h-8 w-24 rounded-xl bg-white/5" />
            <Skeleton className="h-8 w-20 rounded-xl bg-white/5" />
          </div>
        </div>

        {/* Summary skeleton */}
        <div className="p-6 rounded-2xl border border-white/5 bg-navy-800/40 space-y-4">
          <Skeleton className="h-4 w-40 rounded bg-cyan-500/10" />
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Skeleton className="h-16 w-full rounded-xl bg-white/5" />
            <Skeleton className="h-16 w-full rounded-xl bg-white/5" />
            <Skeleton className="h-16 w-full rounded-xl bg-white/5" />
          </div>
        </div>

        {/* Findings skeleton */}
        <div className="p-6 rounded-2xl border border-white/5 bg-navy-800/40 space-y-4">
          <Skeleton className="h-4 w-52 rounded bg-cyan-500/10" />
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Skeleton className="h-28 w-full rounded-xl bg-white/5" />
            <Skeleton className="h-28 w-full rounded-xl bg-white/5" />
          </div>
        </div>
      </div>
    );
  }

  if (isError || (!report && id && id !== "scan" && id !== "1")) {
    return (
      <div className="min-h-screen flex items-center justify-center p-4 max-w-xl mx-auto">
        <EmptyState
          title="Security Report Not Found"
          description={
            error?.message ||
            `Scan report #${id} was not found on the backend server or has expired.`
          }
          action={() => navigate("/scan")}
          actionLabel="Run New Security Scan"
        />
      </div>
    );
  }

  return (
    <div className="min-h-screen flex flex-col">
      <Modal open={modalOpen} onClose={() => setModalOpen(false)} title="Export Report">
        <div className="space-y-4">
          <p className="text-sm text-slate-400">
            Export the full technical report for this scan. PDF includes all sections,
            evidence, and raw findings.
          </p>
          <div className="flex gap-2 pt-4">
            <Button onClick={() => { setModalOpen(false); toast({ title: "PDF exported", type: "success" }); }}>
              <Download className="w-4 h-4 mr-2" /> Download PDF
            </Button>
            <Button variant="outline" onClick={() => setModalOpen(false)}>
              Cancel
            </Button>
          </div>
        </div>
      </Modal>

      <div className="flex-1 overflow-y-auto py-6 px-4 sm:px-6 lg:px-8 max-w-6xl mx-auto">
        {/* Header */}
        <div className="mb-8 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <ShieldAlert className="w-5 h-5 text-blue-400" />
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Scan Report</span>
            </div>
            <h1 className="text-2xl font-bold text-slate-100">{scan.url}</h1>
            <p className="text-sm text-slate-500">
              Scan ID: {scan.id} &nbsp;•&nbsp; Scanned {formatDateTime(scan.scannedAt)}
            </p>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={() => setModalOpen(true)}
              className="px-3 py-2 rounded-xl border border-white/10 bg-white/5 text-xs font-medium text-slate-300 hover:bg-white/10 transition-colors"
            >
              <Download className="w-4 h-4 mr-1.5" /> Export PDF
            </button>
            <button
              onClick={() => {
                navigator.clipboard.writeText(JSON.stringify(report || scan, null, 2));
                toast({ title: "JSON copied to clipboard", type: "success" });
              }}
              className="px-3 py-2 rounded-xl border border-white/10 bg-white/5 text-xs font-medium text-slate-300 hover:bg-white/10 transition-colors"
            >
              <Copy className="w-4 h-4 mr-1.5" /> JSON
            </button>
          </div>
        </div>

        {/* A. Summary Card */}
        <Card className="mb-6">
          <CardHeader>
            <CardTitle className="text-sm">A. Summary</CardTitle>
            <CardDescription>High-level verdict and risk assessment.</CardDescription>
          </CardHeader>
          <CardContent className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-white/3 rounded-xl p-3 border border-white/5">
              <div className="text-xs text-slate-500 uppercase mb-1">Scanned URL</div>
              <div className="text-sm font-medium text-slate-200 truncate" title={scan.url}>{scan.url}</div>
            </div>
            <div className="bg-white/3 rounded-xl p-3 border border-white/5">
              <div className="text-xs text-slate-500 uppercase mb-1">Final URL</div>
              <div className="text-sm font-medium text-slate-200 truncate" title={scan.finalUrl}>{scan.finalUrl}</div>
            </div>
            <div className="bg-white/3 rounded-xl p-3 border border-white/5">
              <div className="text-xs text-slate-500 uppercase mb-1">Scan time</div>
              <div className="text-sm font-medium text-slate-200">{formatDateTime(scan.scannedAt)}</div>
            </div>
            <div className="bg-white/3 rounded-xl p-3 border border-white/5">
              <div className="text-xs text-slate-500 uppercase mb-1">Overall verdict</div>
              <VerdictBadge verdict={scan.verdict} />
            </div>
            <div className="bg-white/3 rounded-xl p-3 border border-white/5">
              <div className="text-xs text-slate-500 uppercase mb-1">Risk score</div>
              <div className="text-sm font-bold text-slate-200">{scan.score} / 100</div>
            </div>
            <div className="bg-white/3 rounded-xl p-3 border border-white/5">
              <div className="text-xs text-slate-500 uppercase mb-1">Confidence</div>
              <div className="text-sm font-medium text-slate-200">{scan.confidence}</div>
            </div>
          </CardContent>
          <CardContent className="mt-5 grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-white/3 rounded-xl p-3 border border-white/5">
              <div className="text-xs text-slate-500 uppercase mb-1">Main reason</div>
              <p className="text-sm text-slate-300 leading-relaxed">{scan.mainReason}</p>
            </div>
            <div className="bg-white/3 rounded-xl p-3 border border-white/5">
              <div className="text-xs text-slate-500 uppercase mb-1">Recommended action</div>
              <p className="text-sm text-slate-300 leading-relaxed">{scan.recommendedAction}</p>
            </div>
          </CardContent>
          <CardFooter>
            <RiskGauge score={scan.score} size={140} className="mx-auto" />
          </CardFooter>
        </Card>

        {/* B. Phishing & Content Analysis */}
        <Card className="mb-6">
          <CardHeader className="flex items-center justify-between">
            <div>
              <CardTitle className="text-sm">B. Phishing &amp; Indicator Analysis</CardTitle>
              <CardDescription>Evidence of credential harvesting, brand impersonation, and deceptive content.</CardDescription>
            </div>
            <div className="flex gap-2">
              <Button variant="ghost" size="sm" onClick={() => toggleSection("all")}>
                {isExpanded("all") ? "Collapse all" : "Expand all"}
              </Button>
            </div>
          </CardHeader>
          <CardContent className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {report && phishingFindings.length > 0 ? (
              phishingFindings.map((finding) => (
                <Card key={finding.id} className="p-4 border-l-2">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={finding.severity}>{finding.severity}</SeverityBadge>
                      <span className="text-xs font-medium text-slate-300">{finding.title}</span>
                    </div>
                    <button
                      onClick={() => toggleSection(finding.id)}
                      className="p-1 text-slate-500 hover:text-white transition-colors"
                      aria-label={isExpanded(finding.id) ? "Collapse" : "Expand"}
                    >
                      <ChevronDown className={cn("w-3 h-3 transition-transform", (isExpanded(finding.id) || isExpanded("all")) && "rotate-180")} />
                    </button>
                  </div>
                  <p className="text-sm text-slate-300 leading-relaxed">{finding.description}</p>
                  {(isExpanded(finding.id) || isExpanded("all")) && (
                    <div className="mt-3 space-y-2">
                      {finding.evidence && Object.keys(finding.evidence).length > 0 && (
                        <div className="p-3 rounded-lg bg-black/40 border border-white/5 font-mono text-xs">
                          <div className="text-[10px] font-semibold text-cyan-400 mb-1.5 uppercase tracking-wider">
                            Captured Forensic Evidence
                          </div>
                          {finding.evidence.input_fields && (
                            <div className="mb-1 text-slate-300">
                              <span className="text-slate-500">Harvested Fields: </span>
                              <span className="text-amber-300 font-semibold">{finding.evidence.input_fields.join(", ")}</span>
                            </div>
                          )}
                          {finding.evidence.claimed_brand && (
                            <div className="mb-1 text-slate-300">
                              <span className="text-slate-500">Impersonated Brand: </span>
                              <span className="text-red-400 font-bold">{finding.evidence.claimed_brand}</span>
                              <span className="text-slate-500"> (Actual Host: {finding.evidence.actual_domain})</span>
                            </div>
                          )}
                          {finding.evidence.matched_phrase && (
                            <div className="mb-1 text-slate-300">
                              <span className="text-slate-500">Social Engineering Phrase: </span>
                              <span className="text-red-300 italic">"{finding.evidence.matched_phrase}"</span>
                            </div>
                          )}
                          {finding.evidence.button_text && (
                            <div className="mb-1 text-slate-300">
                              <span className="text-slate-500">Deceptive Action Button: </span>
                              <span className="text-orange-300 font-bold">"{finding.evidence.button_text}"</span>
                            </div>
                          )}
                          {finding.evidence.script_src && (
                            <div className="mb-1 text-slate-300 break-all">
                              <span className="text-slate-500">Suspicious Script Source: </span>
                              <span className="text-red-400">{finding.evidence.script_src}</span>
                            </div>
                          )}
                          {finding.evidence.detector_type && (
                            <div className="text-[10px] text-slate-500 mt-1 border-t border-white/5 pt-1">
                              Vector Type: {finding.evidence.detector_type} &bull; Risk Points: +{finding.risk_points || 0} pts
                            </div>
                          )}
                        </div>
                      )}
                      {finding.recommendation && (
                        <div className="p-3 rounded-lg bg-white/5 border border-white/5">
                          <div className="text-xs font-semibold text-slate-400 mb-1 uppercase">Remediation</div>
                          <p className="text-xs text-slate-300">{finding.recommendation}</p>
                        </div>
                      )}
                    </div>
                  )}
                </Card>
              ))
            ) : (
              Object.entries(MOCK_PHISHING_ANALYSIS).map(([key, finding]) => (
                <Card key={key} className="p-4 border-l-2">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={finding.severity}>{finding.severity}</SeverityBadge>
                      <span className="text-xs font-medium text-slate-300">{finding.label}</span>
                    </div>
                    <button
                      onClick={() => toggleSection(key)}
                      className="p-1 text-slate-500 hover:text-white transition-colors"
                      aria-label={isExpanded(key) ? "Collapse" : "Expand"}
                    >
                      <ChevronDown className={cn("w-3 h-3 transition-transform", (isExpanded(key) || isExpanded("all")) && "rotate-180")} />
                    </button>
                  </div>
                  <p className="text-sm text-slate-300 leading-relaxed">{finding.detail}</p>
                  {finding.hops && (isExpanded(key) || isExpanded("all")) && (
                    <div className="mt-3 p-3 rounded-lg bg-white/5 border border-white/5">
                      <div className="text-xs font-semibold text-slate-400 mb-2 uppercase">Redirect path</div>
                      <RedirectFlow hops={finding.hops} />
                    </div>
                  )}
                </Card>
              ))
            )}
          </CardContent>
        </Card>

        {/* C. Certificate & Trust */}
        <Card className="mb-6">
          <CardHeader>
            <CardTitle className="text-sm">C. Certificate &amp; Trust Analysis</CardTitle>
            <CardDescription>HTTPS status, certificate chain, and trust signals.</CardDescription>
          </CardHeader>
          <CardContent className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="lg:col-span-2 space-y-4">
              <CertificateChain chain={certData.chain} />
              <div className="bg-white/3 rounded-xl p-4 border border-white/5">
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <div className="text-xs text-slate-500 uppercase mb-1">HTTPS status</div>
                    <div className="text-slate-200 font-medium">Secure (TLS 1.3)</div>
                  </div>
                  <div>
                    <div className="text-xs text-slate-500 uppercase mb-1">Issuer</div>
                    <div className="text-slate-200 font-medium truncate">{certData.issuer}</div>
                  </div>
                  <div>
                    <div className="text-xs text-slate-500 uppercase mb-1">Valid from</div>
                    <div className="text-slate-200 font-medium">{certData.validFrom}</div>
                  </div>
                  <div>
                    <div className="text-xs text-slate-500 uppercase mb-1">Expires</div>
                    <div className="text-slate-200 font-medium">{certData.validTo}</div>
                  </div>
                  <div>
                    <div className="text-xs text-slate-500 uppercase mb-1">Days until expiry</div>
                    <div className="text-slate-200 font-medium">{certData.daysUntilExpiry} days</div>
                  </div>
                  <div>
                    <div className="text-xs text-slate-500 uppercase mb-1">CA trust</div>
                    <div className="text-slate-200 font-medium">{certData.caTrust}</div>
                  </div>
                </div>
                {certData.warning && (
                  <div className="mt-3 p-3 rounded-lg bg-amber-500/5 border border-amber-500/20">
                    <div className="flex items-start gap-2">
                      <AlertTriangle className="w-4 h-4 text-amber-400 mt-0.5 shrink-0" />
                      <p className="text-sm text-slate-300 leading-relaxed">
                        {certData.warning}
                      </p>
                    </div>
                  </div>
                )}
              </div>
            </div>
            <div className="space-y-4">
              <div className="bg-white/3 rounded-xl p-4 border border-white/5">
                <div className="text-xs text-slate-500 uppercase mb-2">Revocation</div>
                <div className="text-sm text-slate-200">{certData.revocation}</div>
              </div>
              <div className="bg-white/3 rounded-xl p-4 border border-white/5">
                <div className="text-xs text-slate-500 uppercase mb-2">Transparency log</div>
                <div className="text-sm text-slate-200">{certData.ctLog}</div>
              </div>
              <div className="bg-white/3 rounded-xl p-4 border border-white/5">
                <div className="text-xs text-slate-500 uppercase mb-2">Weak algorithm</div>
                <div className="text-sm text-emerald-400">None detected</div>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* D. Security Assessment */}
        <Card className="mb-6">
          <CardHeader>
            <CardTitle className="text-sm">D. Website Security Assessment</CardTitle>
            <CardDescription>HTTP security headers and configuration checks.</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse divide-y divide-white/5">
                <thead>
                  <tr className="border-b border-white/5 bg-white/3">
                    <th className="px-4 py-3 text-xs font-semibold text-slate-400 uppercase">Check</th>
                    <th className="px-4 py-3 text-xs font-semibold text-slate-400 uppercase">Status</th>
                    <th className="px-4 py-3 text-xs font-semibold text-slate-400 uppercase">Details</th>
                  </tr>
                </thead>
                <tbody>
                  {securityHeaders.map((h, i) => (
                    <tr key={i} className="hover:bg-white/3 transition-colors">
                      <td className="px-4 py-3 text-sm text-slate-200">{h.name}</td>
                      <td className="px-4 py-3">
                        <HeaderCheck status={h.status} />
                      </td>
                      <td className="px-4 py-3 text-sm text-slate-400">{h.detail}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="mt-4 text-xs text-slate-500">
              Pass = hardened defense &nbsp;•&nbsp; Warning = minor advisory &nbsp;•&nbsp; Fail = missing security control
            </p>
          </CardContent>
        </Card>

        {/* E. Threat Intelligence */}
        <Card className="mb-6">
          <CardHeader>
            <CardTitle className="text-sm">E. Threat Intelligence Feeds</CardTitle>
            <CardDescription>Telemetry from Google Safe Browsing, URLhaus, and VirusTotal.</CardDescription>
          </CardHeader>
          <CardContent className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-white/3 rounded-xl p-4 border border-white/5">
              <div className="text-xs text-slate-500 uppercase mb-2">Feed matches</div>
              {threatIntelMatches.map((m, i) => (
                <div key={i} className="flex items-center justify-between mb-2">
                  <span className="text-xs text-slate-400 capitalize">{m.source?.replace(/_/g, " ")}</span>
                  <Badge variant={m.match ? "danger" : "safe"}>
                    {m.match ? m.detail || "Flagged" : "Clean"}
                  </Badge>
                </div>
              ))}
            </div>
            <div className="bg-white/3 rounded-xl p-4 border border-white/5">
              <div className="text-xs text-slate-500 uppercase mb-2">Domain status</div>
              <div className="text-lg font-bold text-slate-200">{report ? "Active" : MOCK_THREAT_INTEL.domainAge}</div>
            </div>
            <div className="bg-white/3 rounded-xl p-4 border border-white/5">
              <div className="text-xs text-slate-500 uppercase mb-2">Feed consensus</div>
              <div className="text-lg font-bold text-slate-200">
                {scan.score >= 70 ? "Malicious Consensus" : "Clean / Low Risk"}
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Threat Intelligence Topology Graph */}
        <ThreatIntelGraph scanData={scan} className="mb-6" />

        {/* F. Evidence */}
        <Card className="mb-6">
          <CardHeader className="flex items-center justify-between">
            <div>
              <CardTitle className="text-sm">F. Evidence &amp; Raw Telemetry</CardTitle>
              <CardDescription>Structured findings and telemetry logs.</CardDescription>
            </div>
          </CardHeader>
          <CardContent className="mt-2 border-t border-white/5 pt-4">
            <details className="group">
              <summary className="flex items-center gap-2 cursor-pointer text-xs font-medium text-slate-400 hover:text-white">
                <Terminal className="w-3 h-3" /> Raw JSON findings and evidence payload
              </summary>
              <div className="mt-3 p-3 rounded-lg bg-white/5 border border-white/5 overflow-x-auto">
                <pre className="text-xs text-slate-400 font-mono overflow-x-auto whitespace-pre-wrap">
                  {JSON.stringify(report || scan, null, 2)}
                </pre>
              </div>
            </details>
          </CardContent>
          <CardFooter>
            <div className="flex gap-3">
              <Button onClick={() => {
                navigator.clipboard.writeText(window.location.href);
                toast({ title: "Report URL copied to clipboard", type: "success" });
              }}>
                <LinkIcon className="w-4 h-4 mr-2" /> Share report
              </Button>
              <Button variant="outline" onClick={() => navigate("/scan")}>
                Scan another website
              </Button>
            </div>
          </CardFooter>
        </Card>
      </div>
    </div>
  );
}
>>>>>>> .merge_file_lh3uhn
