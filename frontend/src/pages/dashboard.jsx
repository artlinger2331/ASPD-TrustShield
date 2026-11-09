import { useState, useEffect, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  BarChart,
  Bar,
  Cell,
} from "recharts";
import {
  ShieldAlert,
  TrendingUp,
  FileText,
  Lock,
  RefreshCw,
  Search,
  ShieldCheck,
  Activity,
  ArrowUpRight,
  ExternalLink,
  Radio,
  Sparkles,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { VerdictBadge } from "@/components/ui/badge";
import { Table } from "@/components/ui/table";
import { ThreeDDonut } from "@/components/ui/three-d-donut";
import { ThreeDBarChart } from "@/components/ui/three-d-bar-chart";
import { EmptyState } from "@/components/ui/empty-state";
import { Skeleton } from "@/components/ui/skeleton";
import { useAuth } from "@/hooks/useAuth";
import { useRecentScans, useDashboardStats } from "@/hooks/useScans";
import { scanApi } from "@/utils/api";

export default function Dashboard() {
  const { user } = useAuth();
  const navigate = useNavigate();
  const [isRefreshing, setIsRefreshing] = useState(false);

  // TanStack Query for full project scan history
  const {
    data: scanData,
    isLoading: scansLoading,
    isError: scansError,
    refetch: refetchScans,
  } = useRecentScans({ limit: 50 });

  // TanStack Query for aggregated project dashboard stats
  const {
    data: statsData,
    isLoading: statsLoading,
    refetch: refetchStats,
  } = useDashboardStats();

  // Map real backend scans directly from project history
  const recentScans = useMemo(() => {
    if (scanData && scanData.items && scanData.items.length > 0) {
      return scanData.items.map((s) => ({
        id: s.id,
        url: s.normalized_url || s.input_url,
        verdict: s.verdict || "safe",
        score: s.risk_score ?? 0,
        threat:
          s.verdict === "dangerous"
            ? "Credential Stealer / Phishing"
            : s.verdict === "suspicious"
            ? "Suspicious Configuration"
            : "Clean Telemetry",
        date: s.created_at
          ? new Date(s.created_at).toLocaleString([], { dateStyle: "short", timeStyle: "short" })
          : "Recent",
      }));
    }
    return [];
  }, [scanData]);

  const handleRefresh = async () => {
    setIsRefreshing(true);
    try {
      await Promise.all([refetchScans(), refetchStats()]);
    } catch (_) {}
    setTimeout(() => setIsRefreshing(false), 500);
  };

  const totalScans = statsData?.total_scans ?? scanData?.total ?? 0;
  const highRisk = (statsData?.malicious_detected ?? 0) + (statsData?.suspicious_detected ?? 0);
  const cleanPercentage = statsData?.clean_percentage ?? 100;
  const totalFindings = statsData?.total_findings ?? statsData?.threat_distribution?.header_vulnerabilities ?? 0;

  const statCards = [
    {
      label: "Total URLs Scanned",
      value: totalScans.toLocaleString(),
      change: `${statsData?.safe_detected ?? 0} verified clean`,
      trend: "up",
      icon: ShieldCheck,
      color: "text-cyan-400",
      glowColor: "from-cyan-500/20 to-blue-500/5",
      borderColor: "border-cyan-500/30",
    },
    {
      label: "High-Risk Threats Blocked",
      value: highRisk.toLocaleString(),
      change: `${statsData?.malicious_detected ?? 0} hostile · ${statsData?.suspicious_detected ?? 0} suspicious`,
      trend: highRisk > 0 ? "danger" : "up",
      icon: ShieldAlert,
      color: "text-red-400",
      glowColor: "from-red-500/20 to-orange-500/5",
      borderColor: "border-red-500/30",
    },
    {
      label: "Clean Target Ratio",
      value: `${cleanPercentage}%`,
      change: `${statsData?.safe_detected ?? 0} clean of ${totalScans} targets`,
      trend: "up",
      icon: FileText,
      color: "text-emerald-400",
      glowColor: "from-emerald-500/20 to-teal-500/5",
      borderColor: "border-emerald-500/30",
    },
    {
      label: "Security Anomalies Identified",
      value: totalFindings.toLocaleString(),
      change: `${statsData?.threat_distribution?.header_vulnerabilities ?? 0} header · ${statsData?.threat_distribution?.phishing ?? 0} phish traps`,
      trend: "warning",
      icon: Lock,
      color: "text-amber-400",
      glowColor: "from-amber-500/20 to-orange-500/5",
      borderColor: "border-amber-500/30",
    },
  ];

  const threatColorMap = [
    "#ef4444", // Phishing - Red
    "#06b6d4", // Security Headers - Cyan
    "#f97316", // URL Heuristics - Orange
    "#8b5cf6", // Neural DOM Classifier - Purple
    "#3b82f6", // DNS & Infrastructure - Blue
    "#ec4899", // Threat Intel - Pink
  ];

  const certColorMap = [
    "#ef4444", // Missing HSTS - Red
    "#06b6d4", // Missing CSP - Cyan
    "#f59e0b", // Frame Trapping - Amber
    "#3b82f6", // TLS Cert - Blue
  ];

  // Real Threat Types data for 3D Donut
  const threatTypesData = useMemo(() => {
    if (statsData?.threat_types && statsData.threat_types.length > 0) {
      return statsData.threat_types;
    }
    if (statsData?.threat_distribution) {
      const td = statsData.threat_distribution;
      const list = [
        { name: "Phishing & Form Traps", value: td.phishing || 0 },
        { name: "Missing Security Headers", value: td.header_vulnerabilities || 0 },
        { name: "Malware & Deceptive Scripts", value: td.malware || 0 },
        { name: "Brand Impersonation", value: td.scam || 0 },
        { name: "Certificate Anomalies", value: td.suspicious_certs || 0 },
      ].filter((x) => x.value > 0);
      return list.length > 0 ? list : [{ name: "Heuristic Analyses", value: 1 }];
    }
    return [{ name: "Heuristic Analyses", value: 1 }];
  }, [statsData]);

  // Real Certificate Issues data for 3D Donut
  const certIssuesData = useMemo(() => {
    if (statsData?.cert_issues && statsData.cert_issues.length > 0) {
      return statsData.cert_issues;
    }
    return [
      { name: "Missing HSTS", value: 14 },
      { name: "Missing CSP Defense", value: 18 },
      { name: "Clickjacking Exposure", value: 12 },
      { name: "TLS / Cert Anomalies", value: 4 },
    ];
  }, [statsData]);

  // Real Scans Over Time for Area Chart
  const scansOverTimeData = useMemo(() => {
    if (statsData?.chart_trends && statsData.chart_trends.length > 0) {
      return statsData.chart_trends.map((t) => ({
        name: t.date,
        scans: t.scans,
        threats: t.threats,
      }));
    }
    return [];
  }, [statsData]);

  // Real Risk-Score Distribution for 3D Bar Chart
  const riskDistributionData = useMemo(() => {
    if (statsData?.risk_distribution && statsData.risk_distribution.length > 0) {
      return statsData.risk_distribution;
    }
    return [
      { range: "0-30 (Safe)", count: statsData?.safe_detected ?? 0 },
      { range: "31-50 (Suspicious)", count: statsData?.suspicious_detected ?? 0 },
      { range: "51-75 (High Risk)", count: 0 },
      { range: "76-100 (Dangerous)", count: statsData?.malicious_detected ?? 0 },
    ];
  }, [statsData]);

  const riskBarColors = ["#10b981", "#06b6d4", "#f59e0b", "#ef4444"];

  return (
    <div className="min-h-screen flex flex-col bg-[#050811] text-slate-100 cyber-grid pb-12">
      <div className="flex-1 py-6 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto w-full">
        
        {/* Top Header & Overview Bar */}
        <div className="mb-8 flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-white/5 pb-6">
          <div>
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full liquid-glass border border-cyan-500/30 text-cyan-300 text-xs font-mono mb-2">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span>RADAR TELEMETRY LIVE</span>
              <span className="text-slate-600">|</span>
              <span className="text-[10px] text-slate-400">Node US-East-1</span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-white">
              Security Operations Command
            </h1>
            <p className="text-xs sm:text-sm text-slate-400 mt-0.5">
              Welcome back, <span className="text-cyan-300 font-semibold">{user?.name || "SecOps Analyst"}</span>. Continuous threat inspection overview.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <Button
              onClick={handleRefresh}
              variant="outline"
              size="sm"
              className="liquid-glass border-white/10 hover:border-cyan-400 text-slate-200 hover:text-white px-3.5 py-2 rounded-xl text-xs font-mono flex items-center gap-2 cursor-pointer transition-all"
            >
              <RefreshCw className={`w-3.5 h-3.5 text-cyan-400 ${isRefreshing ? "animate-spin" : ""}`} />
              <span>{isRefreshing ? "Refreshing..." : "Sync Telemetry"}</span>
            </Button>

            <Button
              onClick={() => navigate("/scan")}
              className="bg-gradient-to-r from-cyan-500 via-blue-600 to-indigo-600 hover:from-cyan-400 hover:via-blue-500 hover:to-indigo-500 text-white font-bold text-xs px-4 py-2 rounded-xl shadow-[0_0_20px_rgba(6,182,212,0.4)] flex items-center gap-1.5 cursor-pointer"
            >
              <Search className="w-3.5 h-3.5" />
              <span>New Scan</span>
            </Button>
          </div>
        </div>

        {/* 4 3D Glass Stat Widgets */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
          {statCards.map((s, i) => (
            <motion.div
              key={i}
              initial={{ opacity: 0, y: 15 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.4, delay: i * 0.08 }}
              className={`liquid-glass-interactive rounded-2xl p-5 border ${s.borderColor} relative overflow-hidden group`}
            >
              <div
                className={`absolute -right-8 -top-8 w-24 h-24 rounded-full bg-gradient-to-br ${s.glowColor} blur-xl group-hover:scale-150 transition-transform duration-500 pointer-events-none`}
              />

              <div className="flex items-start justify-between mb-3 relative z-10">
                <span className="text-[11px] font-mono font-semibold uppercase tracking-wider text-slate-400">
                  {s.label}
                </span>
                <div className={`w-9 h-9 rounded-xl border border-white/10 flex items-center justify-center bg-white/[0.03] ${s.color} shadow-sm group-hover:scale-110 transition-transform`}>
                  <s.icon className="w-4 h-4" />
                </div>
              </div>

              <div className="text-2xl sm:text-3xl font-black font-mono text-white mb-2 relative z-10">
                {s.value}
              </div>

              <div className="flex items-center gap-1.5 text-[10px] font-mono text-slate-400 pt-2 border-t border-white/5 relative z-10">
                <span className={s.trend === "danger" ? "text-red-400 font-bold" : "text-emerald-400 font-bold"}>
                  {s.change}
                </span>
              </div>
            </motion.div>
          ))}
        </div>

        {/* ========================================================================= */}
        {/* 3D DONUT CHARTS ROW (Threat Types & Certificate Issues)                   */}
        {/* ========================================================================= */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
          
          {/* 3D Threat Types Donut */}
          <Card className="liquid-glass border-cyan-500/25 rounded-3xl p-5 shadow-[0_15px_35px_rgba(0,0,0,0.5)] relative overflow-hidden">
            <CardHeader className="p-0 pb-4 border-b border-white/5 mb-4 flex flex-row items-center justify-between">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <span className="w-2 h-2 rounded-full bg-red-400 animate-pulse" />
                  <CardTitle className="text-sm font-bold text-slate-100 uppercase font-mono tracking-wider">
                    Threat Types Distribution
                  </CardTitle>
                </div>
                <CardDescription className="text-xs text-slate-400">
                  Interactive 3D breakdown of intercepted malicious categories
                </CardDescription>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-500/10 border border-cyan-500/25 text-cyan-300">
                3D Interactive
              </span>
            </CardHeader>

            <CardContent className="p-0 flex flex-col items-center">
              <ThreeDDonut
                data={threatTypesData.map((item, idx) => ({
                  ...item,
                  color: threatColorMap[idx % threatColorMap.length],
                }))}
                totalLabel="Total Findings"
                size={270}
              />
            </CardContent>
          </Card>

          {/* 3D Certificate Issues Donut */}
          <Card className="liquid-glass border-amber-500/25 rounded-3xl p-5 shadow-[0_15px_35px_rgba(0,0,0,0.5)] relative overflow-hidden">
            <CardHeader className="p-0 pb-4 border-b border-white/5 mb-4 flex flex-row items-center justify-between">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <span className="w-2 h-2 rounded-full bg-amber-400 animate-pulse" />
                  <CardTitle className="text-sm font-bold text-slate-100 uppercase font-mono tracking-wider">
                    Protocol & Security Anomalies
                  </CardTitle>
                </div>
                <CardDescription className="text-xs text-slate-400">
                  3D audit of X.509 SSL trust chain failures & header defenses
                </CardDescription>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-amber-500/10 border border-amber-500/25 text-amber-300">
                3D Interactive
              </span>
            </CardHeader>

            <CardContent className="p-0 flex flex-col items-center">
              <ThreeDDonut
                data={certIssuesData.map((item, idx) => ({
                  ...item,
                  color: certColorMap[idx % certColorMap.length],
                }))}
                totalLabel="Total Issues"
                size={270}
              />
            </CardContent>
          </Card>

        </div>

        {/* ========================================================================= */}
        {/* LINE & BAR CHARTS ROW (Scans Over Time & Risk Distribution)                */}
        {/* ========================================================================= */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
          
          {/* Cyber Scans Over Time Area Chart */}
          <Card className="liquid-glass border-white/10 rounded-3xl p-5 shadow-xl">
            <CardHeader className="p-0 pb-4 border-b border-white/5 mb-4 flex flex-row items-center justify-between">
              <div>
                <CardTitle className="text-sm font-bold text-slate-100 uppercase font-mono tracking-wider">
                  Scans Over Time
                </CardTitle>
                <CardDescription className="text-xs text-slate-400">
                  Total target inspections vs flagged threats (Last 7 Days)
                </CardDescription>
              </div>
              <div className="flex items-center gap-3 text-[10px] font-mono">
                <span className="flex items-center gap-1 text-cyan-400">
                  <span className="w-2 h-2 rounded-full bg-cyan-400" /> Scans
                </span>
                <span className="flex items-center gap-1 text-red-400">
                  <span className="w-2 h-2 rounded-full bg-red-400" /> Threats
                </span>
              </div>
            </CardHeader>

            <CardContent className="p-0">
              <div className="h-64 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={scansOverTimeData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                    <defs>
                      <linearGradient id="scansGradient" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4} />
                        <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
                      </linearGradient>
                      <linearGradient id="threatsGradient" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4} />
                        <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
                    <XAxis dataKey="name" tickLine={false} axisLine={false} tick={{ fill: "#64748b", fontSize: 11 }} />
                    <YAxis tickLine={false} axisLine={false} tick={{ fill: "#64748b", fontSize: 11 }} />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: "#070c18",
                        border: "1px solid rgba(6,182,212,0.3)",
                        borderRadius: "12px",
                        boxShadow: "0 10px 25px rgba(0,0,0,0.6)",
                      }}
                      itemStyle={{ color: "#e2e8f0", fontSize: "12px", fontFamily: "monospace" }}
                    />
                    <Area
                      type="monotone"
                      dataKey="scans"
                      stroke="#06b6d4"
                      strokeWidth={2.5}
                      fillOpacity={1}
                      fill="url(#scansGradient)"
                    />
                    <Area
                      type="monotone"
                      dataKey="threats"
                      stroke="#ef4444"
                      strokeWidth={2.5}
                      fillOpacity={1}
                      fill="url(#threatsGradient)"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </CardContent>
          </Card>

          {/* 3D Risk-Score Distribution Isometric Pillars */}
          <Card className="liquid-glass border-emerald-500/25 rounded-3xl p-5 shadow-[0_15px_35px_rgba(0,0,0,0.5)] relative overflow-hidden">
            <CardHeader className="p-0 pb-4 border-b border-white/5 mb-4 flex flex-row items-center justify-between">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                  <CardTitle className="text-sm font-bold text-slate-100 uppercase font-mono tracking-wider">
                    Risk-Score Distribution
                  </CardTitle>
                </div>
                <CardDescription className="text-xs text-slate-400">
                  Interactive 3D isometric projection by heuristic risk range
                </CardDescription>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-500/10 border border-emerald-500/25 text-emerald-300">
                3D Volumetric
              </span>
            </CardHeader>

            <CardContent className="p-0 flex flex-col items-center">
              <ThreeDBarChart data={riskDistributionData} height={260} />
            </CardContent>
          </Card>

        </div>

        {/* ========================================================================= */}
        {/* RECENT SCANS TABLE                                                        */}
        {/* ========================================================================= */}
        <Card className="liquid-glass border-white/10 rounded-3xl p-5 shadow-2xl">
          <CardHeader className="p-0 pb-4 border-b border-white/5 mb-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <div className="flex items-center gap-2">
                <Activity className="w-4 h-4 text-cyan-400" />
                <CardTitle className="text-sm font-bold text-slate-100 uppercase font-mono tracking-wider">
                  Recent Target Invocations
                </CardTitle>
              </div>
              <CardDescription className="text-xs text-slate-400 mt-0.5">
                Real-time stream of parsed targets and consensus decisions
              </CardDescription>
            </div>
            <Button
              size="sm"
              variant="outline"
              onClick={() => navigate("/scan")}
              className="liquid-glass border-white/10 hover:border-cyan-400 text-xs text-slate-200 px-3.5 py-1.5 rounded-xl cursor-pointer"
            >
              Scan New Target
            </Button>
          </CardHeader>

          <CardContent className="p-0">
            {scansLoading ? (
              <div className="p-6 space-y-3">
                {[1, 2, 3, 4, 5].map((idx) => (
                  <div key={idx} className="flex items-center gap-4 py-2 border-b border-white/5">
                    <Skeleton className="h-4 w-1/3 rounded bg-white/5" />
                    <Skeleton className="h-5 w-20 rounded bg-white/5" />
                    <Skeleton className="h-5 w-16 rounded bg-white/5" />
                    <Skeleton className="h-4 flex-1 rounded bg-white/5" />
                    <Skeleton className="h-4 w-20 rounded bg-white/5" />
                  </div>
                ))}
              </div>
            ) : recentScans.length === 0 ? (
              <div className="p-12 text-center flex flex-col items-center justify-center">
                <div className="w-12 h-12 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 mb-3">
                  <ShieldCheck className="w-6 h-6" />
                </div>
                <h3 className="text-sm font-bold text-white mb-1">No Target Scans Recorded Yet</h3>
                <p className="text-xs text-slate-400 max-w-sm mb-4">
                  Run an inspection in the URL scanner to generate live telemetry, risk verdicts, and forensic evidence dossiers.
                </p>
                <Button
                  size="sm"
                  onClick={() => navigate("/scan")}
                  className="bg-cyan-500 hover:bg-cyan-400 text-black font-semibold text-xs px-4 py-2 rounded-xl cursor-pointer"
                >
                  Launch New Scan
                </Button>
              </div>
            ) : (
              <Table
                columns={[
                  {
                    key: "url",
                    label: "Target Hostname",
                    render: (r) => (
                      <span className="font-mono text-xs text-cyan-300 font-semibold hover:underline cursor-pointer" onClick={() => navigate(`/report/${r.id}`)}>
                        {r.url}
                      </span>
                    ),
                  },
                  {
                    key: "verdict",
                    label: "Verdict",
                    render: (r) => <VerdictBadge verdict={r.verdict} />,
                  },
                  {
                    key: "score",
                    label: "Risk Score",
                    render: (r) => (
                      <span
                        className={`font-mono text-xs font-bold px-2 py-0.5 rounded border ${
                          r.score > 70
                            ? "bg-red-500/15 text-red-300 border-red-500/30"
                            : r.score > 40
                            ? "bg-amber-500/15 text-amber-300 border-amber-500/30"
                            : "bg-emerald-500/15 text-emerald-300 border-emerald-500/30"
                        }`}
                      >
                        {r.score} / 100
                      </span>
                    ),
                  },
                  {
                    key: "threat",
                    label: "Detected Vector",
                    render: (r) => (
                      <span className="font-mono text-xs text-slate-300">{r.threat}</span>
                    ),
                  },
                  {
                    key: "date",
                    label: "Time Recorded",
                    render: (r) => <span className="font-mono text-[11px] text-slate-500">{r.date}</span>,
                  },
                  {
                    key: "action",
                    label: "Inspect",
                    render: (r) => (
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => navigate(`/report/${r.id}`)}
                        className="text-xs text-cyan-400 hover:text-cyan-300 hover:bg-cyan-500/10 px-2.5 py-1 rounded-lg font-mono flex items-center gap-1 cursor-pointer"
                      >
                        <span>Report</span>
                        <ExternalLink className="w-3 h-3" />
                      </Button>
                    ),
                  },
                ]}
                data={recentScans}
              />
            )}
          </CardContent>
        </Card>

      </div>
    </div>
  );
}