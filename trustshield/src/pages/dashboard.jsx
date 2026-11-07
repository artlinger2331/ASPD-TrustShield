import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
} from "recharts";
import {
  ShieldAlert,
  TrendingUp,
  FileText,
  Lock,
  RefreshCw,
  Search,
  ShieldCheck,
  ChevronRight,
  BarChart as BarChartIcon,
  PieChart as PieChartIcon,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { Badge, VerdictBadge } from "@/components/ui/badge";
import { Table } from "@/components/ui/table";
import { useAuth } from "@/hooks/useAuth";
import { DASHBOARD_STATS, RECENT_SCANS, CHART_DATA } from "@/data/mockData";

const COLORS = ["#3b82f6", "#22d3ee", "#f59e0b", "#ef4444", "#10b981"];

export default function Dashboard() {
  const { user } = useAuth();

  const statCards = [
    { label: "Total URLs scanned", value: DASHBOARD_STATS.totalScans, icon: ShieldAlert, color: "text-blue-400" },
    { label: "High-risk detected", value: DASHBOARD_STATS.highRisk, icon: TrendingUp, color: "text-red-400" },
    { label: "Reports submitted", value: DASHBOARD_STATS.reportsSubmitted, icon: FileText, color: "text-blue-400" },
    { label: "Certificate issues", value: DASHBOARD_STATS.certIssues, icon: Lock, color: "text-amber-400" },
  ];

  return (
    <div className="min-h-screen flex flex-col">
      <div className="flex-1 overflow-y-auto py-6 px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="mb-8 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold text-slate-100">Dashboard</h1>
            <p className="text-sm text-slate-500">
              Welcome back, {user?.name}. Here's your security overview.
            </p>
          </div>
          <div className="flex items-center gap-3">
            <Button onClick={() => {}}>
              <RefreshCw className="w-4 h-4 mr-2" /> Refresh
            </Button>
          </div>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
          {statCards.map((s, i) => (
            <Card key={i} className="p-5">
              <div className="flex items-center justify-between">
                <div>
                  <div className="text-xs text-slate-500 uppercase mb-1">{s.label}</div>
                  <div className="text-2xl font-bold text-slate-100">{s.value}</div>
                </div>
                <div className="w-10 h-10 rounded-xl flex items-center justify-center bg-white/5 border border-white/5">
                  <s.icon className="w-5 h-5" style={{ color: "currentColor" }} />
                </div>
              </div>
            </Card>
          ))}
        </div>

        {/* Charts row */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
          <Card className="lg:col-span-1">
            <CardHeader>
              <CardTitle className="text-sm">Scans over time</CardTitle>
              <CardDescription>Last 7 days</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={CHART_DATA.scansOverTime}>
                    <CartesianGrid strokeDasharray="3 3" stroke="white/5" vertical={false} />
                    <XAxis dataKey="name" tickLine={false} axisLine={false} textStyle={{ fill: "#64748b", fontSize: 11 }} />
                    <YAxis tickLine={false} axisLine={false} hide textStyle={{ fill: "#64748b", fontSize: 11 }} />
                    <Tooltip
                      contentStyle={{ backgroundColor: "#1a263f", border: "1px solid rgba(255,255,255,0.08)" }}
                      itemStyle={{ color: "#e2e8f0" }}
                    />
                    <Legend />
                    <Line type="monotone" dataKey="scans" stroke="#3b82f6" strokeWidth={2} dot={{ fill: "#3b82f6" }} />
                    <Line type="monotone" dataKey="threats" stroke="#ef4444" strokeWidth={2} dot={{ fill: "#ef4444" }} />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Threat types</CardTitle>
              <CardDescription>Distribution by category</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={CHART_DATA.threatTypes}
                      dataKey="value"
                      nameKey="name"
                      cx="50%"
                      cy="50%"
                      outerRadius={90}
                      fill="#8884d8"
                      labelLine={false}
                    >
                      {CHART_DATA.threatTypes.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                      ))}
                    </Pie>
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </CardContent>
          </Card>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Risk-score distribution</CardTitle>
              <CardDescription>Scans by risk bucket</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={CHART_DATA.riskDistribution}>
                    <CartesianGrid strokeDasharray="3 3" stroke="white/5" vertical={false} />
                    <XAxis dataKey="range" tickLine={false} axisLine={false} textStyle={{ fill: "#64748b", fontSize: 11 }} />
                    <YAxis tickLine={false} axisLine={false} hide textStyle={{ fill: "#64748b", fontSize: 11 }} />
                    <Tooltip />
                    <Bar dataKey="count" fill="#22d3ee" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Certificate issues</CardTitle>
              <CardDescription>Breakdown by issue type</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={CHART_DATA.certIssues}
                      dataKey="value"
                      nameKey="name"
                      cx="50%"
                      cy="50%"
                      outerRadius={90}
                      labelLine={false}
                    >
                      {CHART_DATA.certIssues.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                      ))}
                    </Pie>
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Recent scans */}
        <Card className="mt-8">
          <CardHeader className="flex items-center justify-between">
            <div>
              <CardTitle className="text-sm">Recent scans</CardTitle>
              <CardDescription>Latest URL scan activity.</CardDescription>
            </div>
            <Button size="sm" variant="outline">
              View all scans
            </Button>
          </CardHeader>
          <CardContent>
            <Table
              columns={[
                { key: "url", label: "URL", render: (r) => r.url },
                { key: "verdict", label: "Verdict", render: (r) => <VerdictBadge verdict={r.verdict} /> },
                { key: "score", label: "Risk score", render: (r) => r.score + "/100" },
                { key: "date", label: "Date", render: (r) => r.date },
                { key: "threat", label: "Threat type", render: (r) => r.threat },
                { key: "action", label: "Action", render: () => <Button size="sm" variant="ghost">View</Button> },
              ]}
              data={RECENT_SCANS}
            />
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
