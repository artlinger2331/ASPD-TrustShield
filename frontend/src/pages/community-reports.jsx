import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { ShieldAlert, Search, Filter, Plus, Eye, Copy, Users, Link as LinkIcon, ThumbsUp } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { StatusBadge, SeverityBadge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { communityApi } from "@/utils/api";
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
  const [reports, setReports] = useState(COMMUNITY_REPORTS);

  useEffect(() => {
    async function loadReports() {
      try {
        const data = await communityApi.getReports(filter);
        if (data && data.items && data.items.length > 0) {
          const mapped = data.items.map((r) => ({
            id: r.id,
            url: r.url,
            type: r.threat_type.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase()),
            risk: r.status === "verified" ? "Critical" : "High",
            description: r.description,
            status: r.status,
            confirmations: r.confirmations,
            reporter: "Security Researcher",
            screenshot: r.screenshot_url || "https://images.unsplash.com/photo-1563986768609-322da13575f3?w=300&q=80",
          }));
          setReports([...mapped, ...COMMUNITY_REPORTS.slice(mapped.length)]);
        }
      } catch (err) {
        console.warn("Could not fetch reports from backend, using mock data:", err);
      }
    }
    loadReports();
  }, [filter]);

  const handleVote = async (reportId) => {
    try {
      await communityApi.voteReport(reportId, "confirm");
      setReports((prev) =>
        prev.map((r) => (r.id === reportId ? { ...r, confirmations: r.confirmations + 1 } : r))
      );
    } catch (_) {}
  };

  const filtered = reports.filter(
    (r) =>
      (filter === "All" || r.type.toLowerCase().includes(filter.toLowerCase())) &&
      r.url.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="min-h-screen flex flex-col">
      <div className="flex-1 overflow-y-auto py-6 px-4 sm:px-6 lg:px-8">
        <div className="mb-6 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold text-slate-100">Community Reports</h1>
            <p className="text-sm text-slate-500">
              Recently reported suspicious websites and threat intelligence.
            </p>
          </div>
          <Button onClick={() => navigate("/report")}>
            <Plus className="w-4 h-4 mr-2" /> Submit Report
          </Button>
        </div>

        <div className="flex flex-wrap gap-3 mb-6">
          {FILTERS.map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`px-4 py-1.5 rounded-xl text-xs font-medium border transition-colors ${
                filter === f
                  ? "bg-blue-600 text-white border-blue-600"
                  : "bg-white/5 border-white/10 text-slate-400 hover:bg-white/10 hover:text-slate-300"
              }`}
            >
              {f}
            </button>
          ))}
        </div>

        <div className="mb-6">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
            <Input
              placeholder="Search reports by URL..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-10"
            />
          </div>
        </div>

        <div className="space-y-3">
          {filtered.length === 0 ? (
            <Card className="p-12 text-center">
              <Users className="w-12 h-12 mx-auto mb-3 text-slate-600" />
              <h3 className="text-sm font-semibold text-slate-200">No reports found</h3>
              <p className="text-xs text-slate-500 mt-1">Try adjusting your filters or search.</p>
            </Card>
          ) : (
            filtered.map((report) => (
              <Card key={report.id} className="group cursor-pointer hover:border-white/10 transition-colors">
                <div className="flex items-center gap-3">
                  <img
                    src={report.screenshot}
                    alt="Report screenshot"
                    className="w-16 h-16 rounded-lg object-cover grayscale group-hover:grayscale-0 transition-all"
                  />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-xs font-semibold text-slate-200 truncate">{report.url}</span>
                      <StatusBadge status={report.status} />
                    </div>
                    <div className="flex items-center gap-2 mb-2">
                      <SeverityBadge severity={report.risk}>{report.risk}</SeverityBadge>
                      <span className="text-[10px] text-slate-500 uppercase tracking-wider">{report.type}</span>
                    </div>
                    <p className="text-xs text-slate-400 line-clamp-2 mb-3">
                      {report.description}
                    </p>
                    <div className="flex items-center justify-between">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleVote(report.id);
                        }}
                        className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-blue-500/10 hover:bg-blue-500/20 text-blue-400 text-[11px] transition-colors"
                      >
                        <ThumbsUp className="w-3 h-3" />
                        <span>Confirm ({report.confirmations})</span>
                      </button>
                      <span className="text-[10px] text-slate-600">by {report.reporter}</span>
                    </div>
                  </div>
                  <div className="text-right hidden sm:block">
                    <button className="p-2 text-slate-500 hover:text-white transition-colors" title="View screenshot">
                      <Eye className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              </Card>
            ))
          )}
        </div>

        <div className="mt-8 text-center text-xs text-slate-600">
          Community-driven threat intelligence. Reports are reviewed and verified by the TrustShield team.
        </div>
      </div>
    </div>
  );
}
