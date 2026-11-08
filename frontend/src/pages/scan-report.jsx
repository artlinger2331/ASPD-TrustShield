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
                navigator.clipboard.writeText(JSON.stringify(scan, null, 2));
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
          <CardFooter className="flex justify-center pt-2">
            <RiskGauge score={scan.score} size={160} className="mx-auto" />
          </CardFooter>
        </Card>

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
            {Object.entries(MOCK_PHISHING_ANALYSIS).map(([key, finding]) => (
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
                    <ChevronDown className={cn("w-3 h-3 transition-transform", isExpanded(key) && "rotate-180")} />
                  </button>
                </div>
                <p className="text-sm text-slate-300 leading-relaxed">{finding.detail}</p>
                {finding.hops && isExpanded(key) && (
                  <div className="mt-3 p-3 rounded-lg bg-white/5 border border-white/5">
                    <div className="text-xs font-semibold text-slate-400 mb-2 uppercase">Redirect path</div>
                    <RedirectFlow hops={finding.hops} />
                  </div>
                )}
              </Card>
            ))}
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
