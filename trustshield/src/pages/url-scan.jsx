import { useState, useEffect } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Search, Clipboard, Copy, AlertTriangle, ShieldAlert, Link as LinkIcon, RefreshCw } from "lucide-react";
import { ProgressStepper } from "@/components/ui/progress-stepper";
import { RiskGauge } from "@/components/ui/gauge";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from "@/components/ui/card";
import { VerdictBadge, SeverityBadge } from "@/components/ui/badge";
import { useToast } from "@/hooks/useAuth";
import { cn } from "@/utils/cn";
import { verdictLabel, riskColor, shortenUrl } from "@/utils/formatters";

export default function UrlScan() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { toast } = useToast();

  const [url, setUrl] = useState(searchParams.get("url") || "");
  const [scanning, setScanning] = useState(false);
  const [activeStep, setActiveStep] = useState(0);
  const [result, setResult] = useState(null);
  const [completed, setCompleted] = useState(false);

  const STEPS = 7;

  const handleScan = () => {
    if (!url) return;
    setScanning(true);
    setCompleted(false);
    setResult(null);
    let step = 0;
    const interval = setInterval(() => {
      setActiveStep((s) => {
        if (s >= STEPS - 1) {
          clearInterval(interval);
          setScanning(false);
          setCompleted(true);
          setResult({
            score: 87,
            verdict: "dangerous",
            verdictLabel: "Dangerous / Likely Phishing",
            confidence: "High",
            mainReason: "Domain mimics a major banking brand; login form requests password + OTP; newly registered domain; missing security headers.",
            recommendedAction: "Do not enter passwords, OTPs, or banking details on this website.",
          });
          toast({
            title: "Scan complete",
            description: "The website has been analyzed. View the full report.",
            type: "error",
          });
          return s;
        }
        return s + 1;
      });
    }, 700);
  };

  const handleClipboard = async () => {
    try {
      const text = await navigator.clipboard.readText();
      setUrl(text);
      toast({ title: "Pasted from clipboard", description: "URL ready to scan", type: "info" });
    } catch {
      toast({ title: "Clipboard access denied", type: "error" });
    }
  };

  const scoreColor = result ? riskColor(result.score) : "text-slate-500";

  return (
    <div className="min-h-screen flex flex-col">
      <div className="flex-1 overflow-y-auto py-8 px-4 sm:px-6 lg:px-8 max-w-4xl mx-auto">
        <div className="max-w-2xl mx-auto mb-8">
          <div className="flex items-center gap-2 mb-2">
            <div className="w-2 h-2 rounded-full bg-blue-500" />
            <h2 className="text-lg font-semibold text-slate-200">URL Scanner</h2>
          </div>
          <p className="text-sm text-slate-500">Paste a website address to check if it's safe.</p>
        </div>

        <Card className="mx-auto max-w-xl">
          <CardContent className="pt-0">
            <div className="relative">
              <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
              <input
                type="url"
                placeholder="https://example.com"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                disabled={scanning}
                className="w-full rounded-xl border border-white/10 bg-white/5 pl-10 pr-10 py-3.5 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50 disabled:opacity-50"
              />
              <div className="absolute right-2 top-1/2 -translate-y-1/2 flex gap-1">
                <button
                  onClick={handleClipboard}
                  disabled={scanning}
                  className="p-2 rounded-lg text-slate-400 hover:bg-white/10 hover:text-slate-300 transition-colors disabled:opacity-50"
                  aria-label="Paste from clipboard"
                  title="Paste from clipboard"
                >
                  <Clipboard className="w-4 h-4" />
                </button>
                <button
                  onClick={handleScan}
                  disabled={scanning || !url}
                  className="ml-1 px-3.5 py-2.5 rounded-xl bg-blue-600 text-white text-sm font-semibold hover:bg-blue-500 disabled:opacity-60 disabled:cursor-not-allowed transition-colors"
                >
                  {scanning ? "Scanning…" : "Scan website"}
                </button>
              </div>
            </div>
          </CardContent>
        </Card>

        {scanning || completed ? (
          <div className="mt-8 max-w-lg mx-auto">
            {scanning ? (
              <ProgressStepper activeStep={activeStep} />
            ) : (
              <div className="flex items-center gap-2 text-emerald-400 text-sm font-medium mb-4">
                <svg className="w-4 h-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" />
                </svg>
                Scan complete — view results below
              </div>
            )}
          </div>
        ) : null}

        {result && (
          <div className="mt-8 max-w-lg mx-auto space-y-4">
            <div
              className={cn(
                "rounded-2xl p-6 border flex items-start gap-4",
                result.verdict === "dangerous"
                  ? "bg-red-500/5 border-red-500/20"
                  : result.verdict === "high-risk"
                  ? "bg-orange-500/5 border-orange-500/20"
                  : result.verdict === "suspicious"
                  ? "bg-amber-500/5 border-amber-500/20"
                  : "bg-emerald-500/5 border-emerald-500/20"
              )}
            >
              <div className="flex-shrink-0 w-10 h-10 rounded-xl flex items-center justify-center">
                {result.verdict === "dangerous" ? (
                  <ShieldAlert className="w-5 h-5 text-red-400 bg-red-500/10" />
                ) : result.verdict === "high-risk" ? (
                  <AlertTriangle className="w-5 h-5 text-orange-400 bg-orange-500/10" />
                ) : result.verdict === "suspicious" ? (
                  <AlertTriangle className="w-5 h-5 text-amber-400 bg-amber-500/10" />
                ) : (
                  <ShieldAlert className="w-5 h-5 text-emerald-400 bg-emerald-500/10" />
                )}
              </div>
              <div className="flex-1">
                <div className="flex items-center gap-2 mb-1">
                  <VerdictBadge verdict={result.verdict} />
                  <span className="text-xs text-slate-500">Confidence: {result.confidence}</span>
                </div>
                <p className="text-sm font-semibold text-slate-200">{result.verdictLabel}</p>
              </div>
            </div>

            <RiskGauge score={result.score} size={200} className="mx-auto" />

            <Card className="mt-6">
              <CardHeader>
                <CardTitle className="text-sm">Recommendation</CardTitle>
                <CardDescription>
                  Plain-language guidance for non-technical users.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-slate-200">{result.recommendedAction}</p>
              </CardContent>
              <CardContent className="mt-4 flex gap-2">
                <Button
                  variant="outline"
                  onClick={() => navigate(`/report/${result.id || "scan"}`)}
                  className="flex-1"
                >
                  View full report
                </Button>
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(window.location.href);
                    toast({ title: "Report link copied", type: "success" });
                  }}
                  className="flex-1 bg-white/5 text-slate-300 hover:bg-white/10 text-sm font-semibold px-4 py-2.5 rounded-xl transition-colors"
                >
                  <Copy className="w-4 h-4 mr-2" /> Copy report link
                </button>
              </CardContent>
            </Card>
          </div>
        )}

        {!scanning && !completed && result === null && (
          <div className="mt-12 text-center text-slate-500 text-sm">
            Enter a URL above to begin scanning.
          </div>
        )}
      </div>
    </div>
  );
}
