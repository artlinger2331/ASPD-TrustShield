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

        {/* C. Certificate & Trust */}
        <Card className="mb-6">
          <CardHeader>
            <CardTitle className="text-sm">C. Certificate &amp; Trust Analysis</CardTitle>
            <CardDescription>HTTPS status, certificate chain, and trust signals.</CardDescription>
          </CardHeader>
          <CardContent className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="lg:col-span-2 space-y-4">
              <CertificateChain chain={MOCK_CERT_ANALYSIS.chain} />
              <div className="bg-white/3 rounded-xl p-4 border border-white/5">
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <div className="text-xs text-slate-500 uppercase mb-1">HTTPS status</div>
                    <div className="text-slate-200 font-medium">Secure (TLS 1.3)</div>
                  </div>
                  <div>
                    <div className="text-xs text-slate-500 uppercase mb-1">Issuer</div>
                    <div className="text-slate-200 font-medium truncate">{MOCK_CERT_ANALYSIS.issuer}</div>
                  </div>
                  <div>
                    <div className="text-xs text-slate-500 uppercase mb-1">Valid from</div>
                    <div className="text-slate-200 font-medium">{MOCK_CERT_ANALYSIS.validFrom}</div>
                  </div>
                  <div>
                    <div className="text-xs text-slate-500 uppercase mb-1">Expires</div>
                    <div className="text-slate-200 font-medium">{MOCK_CERT_ANALYSIS.validTo}</div>
                  </div>
                  <div>
                    <div className="text-xs text-slate-500 uppercase mb-1">Days until expiry</div>
                    <div className="text-slate-200 font-medium">{MOCK_CERT_ANALYSIS.daysUntilExpiry} days</div>
                  </div>
                  <div>
                    <div className="text-xs text-slate-500 uppercase mb-1">CA trust</div>
                    <div className="text-slate-200 font-medium">{MOCK_CERT_ANALYSIS.caTrust}</div>
                  </div>
                </div>
                <div className="mt-3 p-3 rounded-lg bg-amber-500/5 border border-amber-500/20">
                  <div className="flex items-start gap-2">
                    <AlertTriangle className="w-4 h-4 text-amber-400 mt-0.5 shrink-0" />
                    <p className="text-sm text-slate-300 leading-relaxed">
                      {MOCK_CERT_ANALYSIS.warning}
                    </p>
                  </div>
                </div>
              </div>
            </div>
            <div className="space-y-4">
              <div className="bg-white/3 rounded-xl p-4 border border-white/5">
                <div className="text-xs text-slate-500 uppercase mb-2">Revocation</div>
                <div className="text-sm text-slate-200">{MOCK_CERT_ANALYSIS.revocation}</div>
              </div>
              <div className="bg-white/3 rounded-xl p-4 border border-white/5">
                <div className="text-xs text-slate-500 uppercase mb-2">Transparency log</div>
                <div className="text-sm text-slate-200">{MOCK_CERT_ANALYSIS.ctLog}</div>
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
                  {MOCK_SECURITY_HEADERS.map((h, i) => (
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
              Pass = no issue found &nbsp;•&nbsp; Warning = minor concern &nbsp;•&nbsp; Fail = action needed
            </p>
          </CardContent>
        </Card>

        {/* E. Threat Intelligence */}
        <Card className="mb-6">
          <CardHeader>
            <CardTitle className="text-sm">E. Threat Intelligence</CardTitle>
            <CardDescription>Matches from public threat feeds and community data.</CardDescription>
          </CardHeader>
          <CardContent className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-white/3 rounded-xl p-4 border border-white/5">
              <div className="text-xs text-slate-500 uppercase mb-2">Feed matches</div>
              {MOCK_THREAT_INTEL.feedMatches.map((m, i) => (
                <div key={i} className="flex items-center justify-between mb-2">
                  <span className="text-xs text-slate-400">{m.source}</span>
                  <Badge variant={m.confidence === "High" ? "high" : "medium"}>{m.confidence}</Badge>
                </div>
              ))}
            </div>
            <div className="bg-white/3 rounded-xl p-4 border border-white/5">
              <div className="text-xs text-slate-500 uppercase mb-2">Domain age</div>
              <div className="text-lg font-bold text-slate-200">{MOCK_THREAT_INTEL.domainAge}</div>
            </div>
            <div className="bg-white/3 rounded-xl p-4 border border-white/5">
              <div className="text-xs text-slate-500 uppercase mb-2">Community reports</div>
              <div className="text-lg font-bold text-slate-200">{MOCK_THREAT_INTEL.communityReports}</div>
            </div>
            <div className="md:col-span-3 bg-white/3 rounded-xl p-4 border border-white/5">
              <div className="flex justify-between mb-2">
                <span className="text-xs text-slate-500 uppercase">Hosting / IP reputation</span>
                <span className="text-xs text-red-400 font-medium">Poor</span>
              </div>
              <p className="text-xs text-slate-400">{MOCK_THREAT_INTEL.hosting.provider}</p>
            </div>
            <div className="md:col-span-3 bg-white/3 rounded-xl p-4 border border-white/5">
              <div className="flex justify-between mb-2">
                <span className="text-xs text-slate-500 uppercase">DNS records</span>
              </div>
              <div className="text-xs font-mono text-slate-400 space-y-1">
                <div>A: {MOCK_THREAT_INTEL.dns.a}</div>
                <div>NS: {MOCK_THREAT_INTEL.dns.ns}</div>
                <div>MX: {MOCK_THREAT_INTEL.dns.mx}</div>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* F. Evidence */}
        <Card className="mb-6">
          <CardHeader className="flex items-center justify-between">
            <div>
              <CardTitle className="text-sm">F. Evidence &amp; Technical Findings</CardTitle>
              <CardDescription>Screenshot, detected forms, scripts, and raw data.</CardDescription>
            </div>
          </CardHeader>
          <CardContent className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="space-y-4">
              <div className="aspect-video rounded-xl overflow-hidden border border-white/10 bg-white/5 relative">
                <img src={MOCK_EVIDENCE.screenshot} alt="Page screenshot" className="w-full h-full object-cover" />
                <div className="absolute bottom-0 left-0 right-0 p-2 bg-gradient-to-t from-black/80 via-transparent text-xs text-slate-300">
                  Page screenshot (placeholder)
                </div>
              </div>
              <div className="bg-white/3 rounded-xl p-4 border border-white/5">
                <div className="text-xs text-slate-500 uppercase mb-2">Page title</div>
                <div className="text-sm text-slate-200 font-mono">{MOCK_EVIDENCE.pageTitle}</div>
              </div>
            </div>
            <div className="space-y-4">
              <div className="bg-white/3 rounded-xl p-4 border border-white/5">
                <div className="text-xs text-slate-500 uppercase mb-2">Detected forms</div>
                {MOCK_EVIDENCE.forms.map((f, i) => (
                  <div key={i} className="text-xs font-mono text-slate-400 mb-1">
                    <form action={f.action} method={f.method}>{f.fields.join(", ")}</form>
                  </div>
                ))}
              </div>
              <div className="bg-white/3 rounded-xl p-4 border border-white/5">
                <div className="text-xs text-slate-500 uppercase mb-2">External scripts / domains</div>
                <ul className="text-xs text-slate-400 space-y-1 list-disc list-inside">
                  {MOCK_EVIDENCE.externalScripts.map((s, i) => (
                    <li key={i} className="truncate">{s}</li>
                  ))}
                </ul>
              </div>
              <div className="bg-white/3 rounded-xl p-4 border border-white/5">
                <div className="text-xs text-slate-500 uppercase mb-2">Redirect path</div>
                <div className="text-xs text-slate-400 space-y-1 font-mono">
                  {MOCK_EVIDENCE.redirectPath.map((p, i) => (
                    <div key={i} className="flex items-center gap-1">
                      <span className="text-slate-600">{i + 1}.</span> {p}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </CardContent>
          <CardContent className="mt-4 border-t border-white/5 pt-4">
            <details className="group">
              <summary className="flex items-center gap-2 cursor-pointer text-xs font-medium text-slate-400 hover:text-white">
                <Terminal className="w-3 h-3" /> Raw technical findings
              </summary>
              <div className="mt-3 p-3 rounded-lg bg-white/5 border border-white/5 overflow-x-auto">
                <pre className="text-xs text-slate-400 font-mono overflow-x-auto whitespace-pre-wrap">
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
          </CardContent>
          <CardFooter>
            <div className="flex gap-3">
              <Button onClick={() => toast({ title: "Report shared", type: "success" })}>
                <LinkIcon className="w-4 h-4 mr-2" /> Share report
              </Button>
              <Button variant="outline">Close</Button>
            </div>
          </CardFooter>
        </Card>
      </div>
    </div>
  );
}
