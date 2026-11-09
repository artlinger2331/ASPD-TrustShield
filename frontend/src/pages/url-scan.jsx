import React, { useState, useEffect, useRef } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import {
  Search,
  Clipboard,
  Copy,
  AlertTriangle,
  ShieldAlert,
  ShieldCheck,
  CheckCircle,
  ExternalLink,
  Zap,
  Terminal,
  RotateCw,
  X,
  Radio,
  FileText,
  Activity,
  ArrowRight,
} from "lucide-react";
import { ThreeDLayerStack } from "@/components/ui/three-d-layer-stack";
import { RiskGauge } from "@/components/ui/gauge";
import { VerdictBadge } from "@/components/ui/badge";
import { useToast } from "@/hooks/useAuth";
import { cn } from "@/utils/cn";
import { verdictLabel, riskColor, shortenUrl } from "@/utils/formatters";
import { scanApi } from "@/utils/api";
import { useCreateScan, useScanStatus } from "@/hooks/useScans";
import { Skeleton } from "@/components/ui/skeleton";

const QUICK_PRESETS = [
  {
    label: "Suspicious Bank Portal",
    url: "https://paypa1-security-verification.com/login",
    risk: "High Phish",
    color: "border-red-500/30 bg-red-500/10 text-red-300 hover:border-red-500/50",
  },
  {
    label: "Unicode Lookalike",
    url: "https://xn--pple-43d.com/support/id",
    risk: "Homoglyph",
    color: "border-amber-500/30 bg-amber-500/10 text-amber-300 hover:border-amber-500/50",
  },
  {
    label: "Safe Verified Tech",
    url: "https://github.com",
    risk: "Safe",
    color: "border-emerald-500/30 bg-emerald-500/10 text-emerald-300 hover:border-emerald-500/50",
  },
];

export default function UrlScan() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { toast } = useToast();

  const [url, setUrl] = useState(searchParams.get("url") || "");
  const [scanId, setScanId] = useState(searchParams.get("id") || null);
  const [scanning, setScanning] = useState(Boolean(searchParams.get("id")));
  const [activeStep, setActiveStep] = useState(0);
  const [logs, setLogs] = useState([]);
  const [result, setResult] = useState(null);
  const [completed, setCompleted] = useState(false);
  const terminalBottomRef = useRef(null);
  const lastLoggedActionRef = useRef(null);
  const lastLoggedStepRef = useRef(0);
  const autoStartedRef = useRef(false);

  // TanStack Query hooks for scan creation and polling status
  const createScanMutation = useCreateScan();
  const {
    data: statusData,
    isLoading: isStatusLoading,
    isError: isStatusError,
    error: statusQueryError,
  } = useScanStatus(scanId);

  useEffect(() => {
    const paramUrl = searchParams.get("url");
    const paramId = searchParams.get("id");
    if (paramUrl && !url) {
      setUrl(paramUrl);
    }
    if (paramId && paramId !== scanId) {
      setScanId(paramId);
      setScanning(true);
    }
  }, [searchParams]);

  useEffect(() => {
    if (terminalBottomRef.current) {
      terminalBottomRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [logs]);

  const addLog = (tag, text, level = "info") => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs((prev) => [...prev, { timestamp, tag, text, level }]);
  };

  const STEP_LOG_MSGS = {
    1: { tag: "DNS_PROBE", text: "Resolving A, AAAA, MX, NS records and BGP Autonomous System..." },
    2: { tag: "SSL_AUDIT", text: "Inspecting X.509 certificate chain, SAN domains & TLS cipher suites..." },
    3: { tag: "HTTP_RECON", text: "Tracing redirects, canonical headers, and HSTS/CSP configurations..." },
    4: { tag: "DOM_PARSER", text: "Safely parsing DOM, checking login forms, password inputs, and script tags..." },
    5: { tag: "HEURISTICS", text: "Executing homoglyph detection, Punycode transforms, and brand impersonation..." },
    6: { tag: "THREAT_INTEL", text: "Cross-referencing Google Safe Browsing, URLhaus, and VirusTotal IOCs..." },
  };

  // Reactively handle status updates from TanStack Query polling
  useEffect(() => {
    if (!statusData) return;

<<<<<<< HEAD
    // Guard against processing status of a different scan
    if (statusData.id && scanId && String(statusData.id) !== String(scanId)) {
      return;
    }

=======
>>>>>>> 9b735eb99fcfab11611f7f8da03c77f43357eb91
    const currentStep = Math.max(1, statusData.step || 1);
    setActiveStep(currentStep);

    // Incrementally log stage transitions
    if (currentStep > lastLoggedStepRef.current) {
      for (let s = Math.max(1, lastLoggedStepRef.current + 1); s <= currentStep; s++) {
        if (STEP_LOG_MSGS[s]) {
          addLog(STEP_LOG_MSGS[s].tag, STEP_LOG_MSGS[s].text);
        }
      }
      lastLoggedStepRef.current = currentStep;
    }

    // Log live server telemetry action
    if (
      statusData.current_action &&
      statusData.current_action !== lastLoggedActionRef.current
    ) {
      lastLoggedActionRef.current = statusData.current_action;
      addLog(
        STEP_LOG_MSGS[currentStep]?.tag || "TELEMETRY",
        statusData.current_action,
        "info"
      );
    }

    // Handle completed scan
    if (statusData.status === "completed" && !completed) {
      setScanning(false);
      setCompleted(true);
      setResult({
        id: statusData.id || scanId,
        score: statusData.risk_score ?? 0,
        verdict: statusData.verdict || "safe",
        verdictLabel: statusData.summary || "Scan complete",
        confidence: statusData.confidence
          ? `${Math.round(statusData.confidence * 100)}%`
          : "High",
        mainReason: statusData.summary || "Consolidated security checks verified.",
        recommendedAction:
          statusData.recommendation || "View full report for detailed telemetry.",
      });
      addLog(
        "SCORE_SYNTHESIS",
        `Analysis finalized. Score: ${statusData.risk_score ?? 0}/100 [Verdict: ${(statusData.verdict || "SAFE").toUpperCase()}]`,
        (statusData.risk_score ?? 0) >= 50 ? "warn" : "info"
      );
      toast({
        title: "Scan complete",
        description: `Verdict: ${statusData.verdict?.toUpperCase() || "SAFE"} (Score: ${statusData.risk_score ?? 0}/100)`,
        type:
          (statusData.risk_score ?? 0) >= 70
            ? "error"
            : (statusData.risk_score ?? 0) >= 50
            ? "warning"
            : "success",
      });
    } else if (statusData.status === "failed") {
      setScanning(false);
      addLog(
        "ERROR",
        statusData.error_message || "The scanner encountered an unrecoverable error.",
        "error"
      );
      toast({
        title: "Scan Failed",
        description: statusData.error_message || "The scanner was unable to analyze this URL.",
        type: "error",
      });
    }
  }, [statusData, completed, scanId]);

  // Handle manual or automated scan submission
  const handleScan = async (overrideUrl) => {
<<<<<<< HEAD
    const rawTarget = typeof overrideUrl === "string" ? overrideUrl : url;
    let targetUrl = (rawTarget || "").trim();
    if (!targetUrl) return;

    if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
      targetUrl = `https://${targetUrl}`;
      setUrl(targetUrl);
    }

=======
    const targetUrl = (overrideUrl || url).trim();
    if (!targetUrl) return;

>>>>>>> 9b735eb99fcfab11611f7f8da03c77f43357eb91
    setScanning(true);
    setCompleted(false);
    setResult(null);
    setActiveStep(1);
    setLogs([]);
    lastLoggedActionRef.current = null;
    lastLoggedStepRef.current = 1;

    addLog("DISPATCH", `Dispatching forensic probe for ${targetUrl}`);
    addLog("DNS_PROBE", "Resolving authoritative name servers and DNS records...");

    try {
      const initRes = await createScanMutation.mutateAsync(targetUrl);
      const newScanId = initRes.id;
      setScanId(newScanId);
      navigate(`/scan?id=${newScanId}&url=${encodeURIComponent(targetUrl)}`, {
        replace: true,
      });
      addLog("QUEUE", `Job accepted by pipeline: ID #${newScanId}`);
    } catch (err) {
      setScanning(false);
      addLog("ERROR", err.message || "Failed to initiate scan", "error");
      toast({
        title: "Scan Failed",
        description: err.message || "Failed to initiate scan",
        type: "error",
      });
    }
  };

  // Auto-initiate if user navigated to /scan?url=... directly without an id
  useEffect(() => {
    const paramUrl = searchParams.get("url");
    const paramId = searchParams.get("id");
    if (paramUrl && !paramId && !autoStartedRef.current && !scanning) {
      autoStartedRef.current = true;
      handleScan(paramUrl);
    }
  }, [searchParams]);

  const handleClipboard = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) {
        setUrl(text);
        toast({ title: "Pasted from clipboard", description: text, type: "info" });
      }
    } catch {
      toast({ title: "Clipboard access denied", type: "error" });
    }
  };

  const handleClear = () => {
    setUrl("");
    setLogs([]);
    setResult(null);
    setCompleted(false);
    setActiveStep(0);
  };

  return (
    <div className="w-full space-y-6 max-w-7xl mx-auto pb-12">
      {/* Page Title & Status Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-white/5">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse shadow-[0_0_8px_#22d3ee]" />
            <span className="text-xs font-mono tracking-widest uppercase text-cyan-400">
              Autonomous Threat Interceptor
            </span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
            Deep URL Forensics Console
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Inspect hostile homographs, evasive redirects, short-lived SSL certs, and DOM credential harvesters.
          </p>
        </div>

        <div className="flex items-center gap-2 self-start sm:self-center font-mono text-xs">
          <div className="px-3 py-1.5 rounded-xl border border-cyan-500/20 bg-cyan-500/10 text-cyan-300 flex items-center gap-2">
            <Radio className="w-3.5 h-3.5 animate-pulse text-cyan-400" />
            <span>RADAR: ONLINE</span>
          </div>
          <div className="px-3 py-1.5 rounded-xl border border-white/10 bg-white/5 text-slate-300 flex items-center gap-1.5">
            <Activity className="w-3.5 h-3.5 text-emerald-400" />
            <span>0-DAY ENGINE</span>
          </div>
        </div>
      </div>

      {/* Main Grid: Left Column (Command Deck & Terminal) | Right Column (3D Layer Stack & Risk HUD) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* LEFT COLUMN: URL Inspector & Real-time Terminal (7 cols) */}
        <div className="lg:col-span-7 space-y-5">
          {/* High-Tech Cyber URL Bar Card */}
          <div className="relative rounded-2xl border border-cyan-500/30 bg-navy-800/80 backdrop-blur-xl p-4 sm:p-5 shadow-2xl overflow-hidden">
            <div className="absolute top-0 right-0 w-48 h-48 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />

            {/* Terminal Window Header Bar */}
            <div className="flex items-center justify-between mb-3 pb-2 border-b border-white/5 text-xs text-slate-400 font-mono">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-red-500/80 inline-block" />
                <span className="w-2.5 h-2.5 rounded-full bg-amber-500/80 inline-block" />
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/80 inline-block" />
                <span className="ml-2 text-slate-300 font-medium">INSPECTION_TARGET // SEC_INPUT</span>
              </div>
              <span className="text-[11px] text-cyan-400 hidden sm:inline-block">
                TLS 1.3 / HTTP 2.0 PROTOCOL
              </span>
            </div>

            {/* Input Element with Form Wrapper and Responsive Wrapped Buttons */}
            <form
              onSubmit={(e) => {
                e.preventDefault();
                if (!scanning && url.trim()) {
                  handleScan();
                }
              }}
              className="relative flex flex-col sm:flex-row items-stretch sm:items-center gap-2 p-1.5 sm:p-2 rounded-xl bg-slate-950/70 border border-white/10 focus-within:border-cyan-400 focus-within:shadow-[0_0_20px_rgba(34,211,238,0.2)] transition-all"
            >
              <div className="flex items-center flex-1 min-w-0 px-2 py-1">
                <Search className="w-4 h-4 text-cyan-400 shrink-0 mr-2.5" />
                <input
                  type="text"
                  placeholder="https://domain-to-inspect.com/path"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  disabled={scanning}
                  className="w-full bg-transparent text-sm text-slate-100 placeholder-slate-500 focus:outline-none font-mono py-1.5"
                />
                {url && !scanning && (
                  <button
                    type="button"
                    onClick={handleClear}
                    className="p-1 text-slate-400 hover:text-slate-200 transition-colors ml-1"
                    title="Clear input"
                  >
                    <X className="w-4 h-4" />
                  </button>
                )}
              </div>

              {/* Action Buttons: Cleanly integrated without any text clipping */}
              <div className="flex items-center gap-1.5 shrink-0 pt-1 sm:pt-0 border-t sm:border-t-0 border-white/5">
                <button
                  type="button"
                  onClick={handleClipboard}
                  disabled={scanning}
                  className="flex-1 sm:flex-none flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 text-xs font-mono font-medium border border-white/10 transition-colors disabled:opacity-50"
                  title="Paste from clipboard"
                >
                  <Clipboard className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Paste</span>
                </button>

                <button
                  type="submit"
                  disabled={scanning || !url || !url.trim()}
                  className="flex-1 sm:flex-none flex items-center justify-center gap-2 px-4 py-2 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white text-xs font-semibold shadow-lg shadow-cyan-500/25 transition-all disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
                >
                  {scanning ? (
                    <>
                      <RotateCw className="w-3.5 h-3.5 animate-spin" />
                      <span>Inspecting...</span>
                    </>
                  ) : (
                    <>
                      <Zap className="w-3.5 h-3.5 fill-current" />
                      <span>Inspect Target</span>
                    </>
                  )}
                </button>
              </div>
            </form>

            {/* Preset Target Quick-Pills */}
            <div className="mt-3.5 pt-3 border-t border-white/5">
              <div className="flex items-center justify-between mb-2">
                <span className="text-[11px] font-mono uppercase text-slate-400">
                  Quick Attack Vectors:
                </span>
                <span className="text-[10px] text-slate-500">Click to autofill</span>
              </div>
              <div className="flex flex-wrap gap-2">
                {QUICK_PRESETS.map((p, idx) => (
                  <button
                    key={idx}
                    type="button"
                    onClick={() => {
                      setUrl(p.url);
                    }}
                    disabled={scanning}
                    className={cn(
                      "px-2.5 py-1 rounded-lg text-xs font-mono border transition-all text-left flex items-center gap-1.5 hover:scale-[1.02]",
                      p.color
                    )}
                  >
                    <span>{p.label}</span>
                    <span className="text-[10px] opacity-70">({p.risk})</span>
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Real-Time Cyber Terminal Output Stream */}
          <div className="rounded-2xl border border-white/10 bg-slate-950/90 backdrop-blur-xl shadow-2xl overflow-hidden flex flex-col font-mono text-xs">
            {/* Terminal Top Bar */}
            <div className="bg-slate-900/90 px-4 py-2.5 border-b border-white/10 flex items-center justify-between text-slate-400">
              <div className="flex items-center gap-2">
                <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                <span className="text-slate-200 font-semibold text-[11px] tracking-wide">
                  LIVE TELEMETRY STREAM
                </span>
                <span className="text-[10px] text-slate-500 hidden sm:inline">
                  (/dev/sec_telemetry.sock)
                </span>
              </div>

              <div className="flex items-center gap-2">
                {scanning && (
                  <span className="flex items-center gap-1 text-[10px] text-cyan-400 animate-pulse">
                    <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
                    STREAMING
                  </span>
                )}
                {completed && (
                  <span className="flex items-center gap-1 text-[10px] text-emerald-400">
                    <CheckCircle className="w-3 h-3" /> PIPELINE_DONE
                  </span>
                )}
                {!scanning && !completed && (
                  <span className="text-[10px] text-slate-500">IDLE</span>
                )}
              </div>
            </div>

            {/* Terminal Console Body */}
            <div className="p-4 h-[240px] sm:h-[260px] overflow-y-auto space-y-2 select-text scrollbar-thin scrollbar-thumb-white/10">
              {logs.length === 0 ? (
                <div className="h-full flex flex-col items-center justify-center text-center text-slate-600 space-y-2">
                  <Terminal className="w-8 h-8 opacity-40 text-cyan-500" />
                  <p className="text-xs text-slate-400">
                    Waiting for target URL to initialize diagnostic probe.
                  </p>
                  <p className="text-[11px] text-slate-600">
                    Paste a link above or select a quick attack vector to begin telemetry capture.
                  </p>
                </div>
              ) : (
                <>
                  {logs.map((log, i) => (
                    <div
                      key={i}
                      className={cn(
                        "leading-relaxed flex items-start gap-2",
                        log.level === "warn"
                          ? "text-amber-300"
                          : log.level === "error"
                          ? "text-red-400"
                          : "text-slate-300"
                      )}
                    >
                      <span className="text-slate-600 shrink-0 select-none">[{log.timestamp}]</span>
                      <span
                        className={cn(
                          "px-1.5 py-0.2 rounded text-[10px] font-bold shrink-0",
                          log.tag === "SCORE_SYNTHESIS"
                            ? "bg-red-500/20 text-red-400 border border-red-500/30"
                            : "bg-cyan-500/10 text-cyan-300 border border-cyan-500/20"
                        )}
                      >
                        {log.tag}
                      </span>
                      <span className="flex-1 break-all">{log.text}</span>
                    </div>
                  ))}
                  {scanning && (
                    <div className="flex items-center gap-1 text-cyan-400 text-xs animate-pulse">
                      <span>&gt; Processing next neural layer</span>
                      <span className="w-2 h-3 bg-cyan-400 inline-block ml-1" />
                    </div>
                  )}
                  <div ref={terminalBottomRef} />
                </>
              )}
            </div>

            {/* Terminal Footer */}
            <div className="bg-slate-900/60 px-4 py-2 border-t border-white/5 flex items-center justify-between text-[11px] text-slate-500">
              <span>Encrypted pipe // Zero data persistence</span>
              <span>7 Diagnostic Stages</span>
            </div>
          </div>
        </div>

        {/* RIGHT COLUMN: 3D Isometric Layer Stack & Risk Assessment (5 cols) */}
        <div className="lg:col-span-5 space-y-5">
          {/* 3D Isometric Layer Stack Component */}
          <ThreeDLayerStack
            activeStep={activeStep}
            isScanning={scanning}
            isCompleted={completed}
            result={result}
          />

          {/* Assessment / Score HUD Card */}
          {result ? (
            <div
              className={cn(
                "rounded-2xl border p-5 sm:p-6 backdrop-blur-xl shadow-2xl transition-all duration-300",
                result.verdict === "dangerous"
                  ? "bg-red-950/40 border-red-500/40 shadow-red-500/10"
                  : result.verdict === "high-risk"
                  ? "bg-orange-950/40 border-orange-500/40 shadow-orange-500/10"
                  : result.verdict === "suspicious"
                  ? "bg-amber-950/40 border-amber-500/40 shadow-amber-500/10"
                  : "bg-emerald-950/40 border-emerald-500/40 shadow-emerald-500/10"
              )}
            >
              {/* Verdict Header */}
              <div className="flex items-start justify-between gap-3 mb-4 pb-3 border-b border-white/10">
                <div className="flex items-center gap-3">
                  <div
                    className={cn(
                      "w-10 h-10 rounded-xl flex items-center justify-center border shadow-inner",
                      result.verdict === "dangerous"
                        ? "bg-red-500/20 text-red-400 border-red-500/40"
                        : "bg-emerald-500/20 text-emerald-400 border-emerald-500/40"
                    )}
                  >
                    {result.verdict === "dangerous" ? (
                      <ShieldAlert className="w-5 h-5" />
                    ) : (
                      <ShieldCheck className="w-5 h-5" />
                    )}
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <VerdictBadge verdict={result.verdict} />
                      <span className="text-[11px] font-mono text-slate-400">
                        Confidence: {result.confidence}
                      </span>
                    </div>
                    <h3 className="text-base font-bold text-white mt-1">
                      {result.verdictLabel}
                    </h3>
                  </div>
                </div>
              </div>

              {/* Risk Gauge Visual */}
              <div className="my-2 flex justify-center">
                <RiskGauge score={result.score} size={190} />
              </div>

              {/* Primary Reason / Recommendation */}
              <div className="space-y-3 mt-4 pt-3 border-t border-white/10 text-xs">
                <div>
                  <span className="font-mono uppercase text-slate-400 text-[11px] block mb-1">
                    Threat Breakdown:
                  </span>
                  <p className="text-slate-200 leading-relaxed bg-black/20 p-2.5 rounded-xl border border-white/5">
                    {result.mainReason}
                  </p>
                </div>

                <div>
                  <span className="font-mono uppercase text-slate-400 text-[11px] block mb-1">
                    Recommended Action:
                  </span>
                  <p
                    className={cn(
                      "font-medium leading-relaxed p-2.5 rounded-xl border",
                      result.verdict === "dangerous"
                        ? "bg-red-500/10 border-red-500/30 text-red-200"
                        : "bg-emerald-500/10 border-emerald-500/30 text-emerald-200"
                    )}
                  >
                    {result.recommendedAction}
                  </p>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="mt-5 pt-3 border-t border-white/10 flex flex-col sm:flex-row gap-2">
                <button
                  type="button"
                  onClick={() => navigate(result?.id ? `/reports/${result.id}` : `/reports`)}
                  className="flex-1 flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white text-xs font-semibold shadow-lg shadow-cyan-500/20 transition-all cursor-pointer"
                >
                  <FileText className="w-3.5 h-3.5" />
                  <span>View Full Forensics Report</span>
                  <ArrowRight className="w-3 h-3" />
                </button>

                <button
                  type="button"
                  onClick={() => {
                    navigator.clipboard.writeText(window.location.href);
                    toast({ title: "Report Link Copied", description: "Shareable dossier link saved to clipboard.", type: "success" });
                  }}
                  className="px-3 py-2.5 rounded-xl bg-white/5 hover:bg-white/10 text-slate-300 text-xs font-medium border border-white/10 transition-colors flex items-center justify-center gap-1.5"
                  title="Copy report link"
                >
                  <Copy className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Share</span>
                </button>
              </div>
            </div>
          ) : scanning ? (
            /* Active Analysis Skeletons & Probe Progress Card */
            <div className="rounded-2xl border border-cyan-500/30 bg-navy-800/80 backdrop-blur-xl p-5 sm:p-6 shadow-2xl space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-white/10 text-xs">
                <span className="font-mono text-cyan-300 font-semibold uppercase flex items-center gap-2">
                  <RotateCw className="w-3.5 h-3.5 animate-spin text-cyan-400" />
                  <span>Pipeline Active (Step {activeStep}/6)</span>
                </span>
                <span className="text-[11px] font-mono text-cyan-400 bg-cyan-500/10 border border-cyan-500/30 px-2 py-0.5 rounded">
                  POLLING BACKEND
                </span>
              </div>
              <div className="space-y-3">
                <Skeleton className="h-6 w-3/4 rounded-lg bg-cyan-500/10" />
                <Skeleton className="h-28 w-full rounded-xl bg-white/5" />
                <div className="space-y-2 pt-2">
                  <Skeleton className="h-4 w-5/6 rounded bg-white/5" />
                  <Skeleton className="h-4 w-4/6 rounded bg-white/5" />
                </div>
              </div>
            </div>
          ) : (
            /* Standby Sensors Card */
            <div className="rounded-2xl border border-white/10 bg-navy-800/60 backdrop-blur-xl p-5 shadow-xl space-y-3">
              <div className="flex items-center justify-between text-xs pb-2 border-b border-white/5">
                <span className="font-mono text-slate-400 uppercase">Sensory Array Telemetry</span>
                <span className="text-[11px] font-mono text-emerald-400 flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" /> ACTIVE
                </span>
              </div>

              <div className="space-y-2 text-xs">
                <div className="flex items-center justify-between p-2 rounded-lg bg-white/[0.03] border border-white/5">
                  <span className="text-slate-300">Punycode & Homoglyph Engine</span>
                  <span className="font-mono text-[10px] text-cyan-400">READY</span>
                </div>
                <div className="flex items-center justify-between p-2 rounded-lg bg-white/[0.03] border border-white/5">
                  <span className="text-slate-300">X.509 SSL Certificate Chain Auditor</span>
                  <span className="font-mono text-[10px] text-cyan-400">READY</span>
                </div>
                <div className="flex items-center justify-between p-2 rounded-lg bg-white/[0.03] border border-white/5">
                  <span className="text-slate-300">Evasive Redirect & HSTS Tracer</span>
                  <span className="font-mono text-[10px] text-cyan-400">READY</span>
                </div>
                <div className="flex items-center justify-between p-2 rounded-lg bg-white/[0.03] border border-white/5">
                  <span className="text-slate-300">Decentralized Threat Intelligence Sync</span>
                  <span className="font-mono text-[10px] text-emerald-400">LIVE (80+ NODES)</span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}