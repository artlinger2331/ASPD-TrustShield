import { useState, useEffect } from "react";
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
import { useRecentScans } from "@/hooks/useScans";
import { scanApi } from "@/utils/api";
import { DASHBOARD_STATS, RECENT_SCANS, CHART_DATA } from "@/data/mockData";

export default function Dashboard() {
  const { user } = useAuth();
  const navigate = useNavigate();
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [recentScans, setRecentScans] = useState(RECENT_SCANS);

  useEffect(() => {
    async function loadScans() {
      try {
        const data = await scanApi.getRecentScans(10);
        if (data && data.items && data.items.length > 0) {
          const mapped = data.items.map((s) => ({
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
            date: new Date(s.created_at).toLocaleDateString(),
          }));
          setRecentScans([...mapped, ...RECENT_SCANS.slice(mapped.length)]);
        }
      } catch (err) {
        console.warn("Could not fetch recent scans from backend:", err);
      }
    }
    loadScans();
  }, []);

  const handleRefresh = async () => {
    setIsRefreshing(true);
    try {
      const data = await scanApi.getRecentScans(10);
      if (data && data.items && data.items.length > 0) {
        const mapped = data.items.map((s) => ({
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
          date: new Date(s.created_at).toLocaleDateString(),
        }));
        setRecentScans([...mapped, ...RECENT_SCANS.slice(mapped.length)]);
      }
    } catch (_) {}
    setTimeout(() => setIsRefreshing(false), 600);
  };

  const statCards = [
    {
      label: "Total URLs Scanned",
      value: DASHBOARD_STATS.totalScans.toLocaleString(),
      change: "+18.4% this week",
      trend: "up",
      icon: ShieldCheck,
      color: "text-cyan-400",
      glowColor: "from-cyan-500/20 to-blue-500/5",
      borderColor: "border-cyan-500/30",
    },
    {
      label: "High-Risk Threats Blocked",
      value: DASHBOARD_STATS.highRisk.toLocaleString(),
      change: "+7 zero-day intercepts",
      trend: "danger",
      icon: ShieldAlert,
      color: "text-red-400",
      glowColor: "from-red-500/20 to-orange-500/5",
      borderColor: "border-red-500/30",
    },
    {
      label: "Community Intel Reports",
      value: DASHBOARD_STATS.reportsSubmitted.toLocaleString(),
      change: "+12 verified submissions",
      trend: "up",
      icon: FileText,
      color: "text-emerald-400",
      glowColor: "from-emerald-500/20 to-teal-500/5",
      borderColor: "border-emerald-500/30",
    },
    {
      label: "Certificate Anomalies",
      value: DASHBOARD_STATS.certIssues.toLocaleString(),
      change: "4 expired · 3 weak algos",
      trend: "warning",
      icon: Lock,
      color: "text-amber-400",
      glowColor: "from-amber-500/20 to-orange-500/5",
      borderColor: "border-amber-500/30",
    },
  ];

  const threatColorMap = [
    "#ef4444", // Phishing - Red
    "#f97316", // Scam - Orange
    "#8b5cf6", // Malware - Purple
    "#06b6d4", // Fake Recruitment - Cyan
    "#3b82f6", // Payment Fraud - Blue
  ];

  const certColorMap = [
    "#ef4444", // Expired - Red
    "#f59e0b", // Weak Algorithm - Amber
    "#06b6d4", // Self-Signed - Cyan
    "#3b82f6", // Chain Issue - Blue
  ];

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
                data={CHART_DATA.threatTypes.map((item, idx) => ({
                  ...item,
                  color: threatColorMap[idx % threatColorMap.length],
                }))}
                totalLabel="Total Threats"
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
                    Certificate Anomalies
                  </CardTitle>
                </div>
                <CardDescription className="text-xs text-slate-400">
                  3D audit of X.509 SSL trust chain failures & warnings
                </CardDescription>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-amber-500/10 border border-amber-500/25 text-amber-300">
                3D Interactive
              </span>
            </CardHeader>

            <CardContent className="p-0 flex flex-col items-center">
              <ThreeDDonut
                data={CHART_DATA.certIssues.map((item, idx) => ({
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
                  <AreaChart data={CHART_DATA.scansOverTime} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
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
              <ThreeDBarChart data={CHART_DATA.riskDistribution} height={260} />
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
            <Table
              columns={[
                {
                  key: "url",
                  label: "Target Hostname",
                  render: (r) => (
                    <span className="font-mono text-xs text-cyan-300 font-semibold hover:underline cursor-pointer" onClick={() => navigate(`/report/${r.id || "1"}`)}>
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
                  label: "Time Elapsed",
                  render: (r) => <span className="font-mono text-[11px] text-slate-500">{r.date}</span>,
                },
                {
                  key: "action",
                  label: "Inspect",
                  render: (r) => (
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => navigate(`/report/${r.id || "1"}`)}
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
          </CardContent>
        </Card>

      </div>
    </div>
  );
}