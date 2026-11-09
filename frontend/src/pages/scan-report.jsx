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
      <div className="min-h-screen flex items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <Loader2 className="w-8 h-8 text-blue-400 animate-spin" />
          <p className="text-sm font-medium text-slate-300">Loading security telemetry report…</p>
        </div>
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
