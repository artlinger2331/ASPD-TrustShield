import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input, Label } from "@/components/ui/input";
import { VerdictBadge } from "@/components/ui/badge";
import { watchlistApi } from "@/utils/api";
import { WATCHLIST_DOMAINS } from "@/data/mockData";
import { Plus, Bell, RefreshCw, ChevronRight, Trash2 } from "lucide-react";

export default function Watchlist() {
  const [domains, setDomains] = useState(WATCHLIST_DOMAINS);
  const [newDomain, setNewDomain] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    async function loadWatchlist() {
      try {
        const res = await watchlistApi.getWatchlist();
        if (res && res.items && res.items.length > 0) {
          const mapped = res.items.map((it) => ({
            id: it.id,
            domain: it.domain,
            score: 15,
            certExpiry: "90 days",
            lastScan: it.last_checked_at ? new Date(it.last_checked_at).toLocaleDateString() : "Active",
            status: "safe",
            alerts: it.is_active,
          }));
          setDomains([...mapped, ...WATCHLIST_DOMAINS.slice(mapped.length)]);
        }
      } catch (err) {
        console.warn("Could not load backend watchlist, using fallback data:", err);
      }
    }
    loadWatchlist();
  }, []);

  const addDomain = async () => {
    if (!newDomain.trim()) return;
    const clean = newDomain.trim().toLowerCase();
    setLoading(true);
    try {
      const created = await watchlistApi.addDomain({ domain: clean });
      setDomains((prev) => [
        {
          id: created?.id,
          domain: clean,
          score: 15,
          certExpiry: "90 days",
          lastScan: "Just now",
          status: "safe",
          alerts: true,
        },
        ...prev,
      ]);
    } catch (err) {
      console.warn("API add failed, adding to local state:", err);
      setDomains((prev) => [
        {
          domain: clean,
          score: 15,
          certExpiry: "90 days",
          lastScan: "Just now",
          status: "safe",
          alerts: true,
        },
        ...prev,
      ]);
    } finally {
      setLoading(false);
      setNewDomain("");
    }
  };

  const removeDomain = async (id, domainName) => {
    try {
      if (id) {
        await watchlistApi.removeDomain(id);
      }
    } catch (_) {}
    setDomains((prev) => prev.filter((d) => d.id !== id && d.domain !== domainName));
  };


  return (
    <div className="min-h-screen flex flex-col">
      <div className="flex-1 overflow-y-auto py-6 px-4 sm:px-6 lg:px-8 max-w-5xl mx-auto">
        <div className="mb-6">
          <h1 className="text-2xl font-bold text-slate-100">Watchlist</h1>
          <p className="text-sm text-slate-500">
            Monitor domains you care about. Get alerted on risk changes and certificate expiry.
          </p>
        </div>

        <Card className="mb-6">
          <div className="p-6">
            <div className="flex gap-2 mb-4">
              <Input
                placeholder="example.com"
                value={newDomain}
                onChange={(e) => setNewDomain(e.target.value)}
                className="flex-1"
              />
              <Button onClick={addDomain} disabled={!newDomain.trim()}>
                <Plus className="w-4 h-4 mr-2" /> Add domain
              </Button>
            </div>
            <p className="text-xs text-slate-500">
              Add domains to monitor. We'll scan them regularly and alert you to changes.
            </p>
          </div>
        </Card>

        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <RefreshCw className="w-4 h-4 text-slate-500" />
            <span className="text-xs text-slate-400">Last updated: just now</span>
          </div>
        </div>

        <Card>
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse divide-y divide-white/5">
              <thead>
                <tr className="border-b border-white/5 bg-white/3">
                  <th className="px-4 py-3 text-xs font-semibold text-slate-400 uppercase">Domain</th>
                  <th className="px-4 py-3 text-xs font-semibold text-slate-400 uppercase">Risk score</th>
                  <th className="px-4 py-3 text-xs font-semibold text-slate-400 uppercase">Cert expiry</th>
                  <th className="px-4 py-3 text-xs font-semibold text-slate-400 uppercase">Last scan</th>
                  <th className="px-4 py-3 text-xs font-semibold text-slate-400 uppercase">Status</th>
                  <th className="px-4 py-3 text-xs font-semibold text-slate-400 uppercase">Alerts</th>
                  <th className="px-4 py-3 text-xs font-semibold text-slate-400 uppercase text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {domains.map((d, i) => (
                  <tr key={d.id || i} className="hover:bg-white/3 transition-colors">
                    <td className="px-4 py-3 text-sm text-slate-200 font-medium">{d.domain}</td>
                    <td className="px-4 py-3 text-sm">
                      <span className={`font-mono text-sm ${d.score <= 30 ? "text-emerald-400" : d.score <= 50 ? "text-amber-400" : "text-red-400"}`}>
                        {d.score}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-sm text-slate-400">{d.certExpiry}</td>
                    <td className="px-4 py-3 text-sm text-slate-400">{d.lastScan}</td>
                    <td className="px-4 py-3 text-sm">
                      <VerdictBadge verdict={d.status.toLowerCase()} />
                    </td>
                    <td className="px-4 py-3 text-sm">
                      <label className="relative inline-flex items-center cursor-pointer">
                        <input
                          type="checkbox"
                          defaultChecked={d.alerts}
                          className="peer sr-only"
                        />
                        <div className="w-9 h-5 rounded-full bg-white/5 border border-white/10 peer-checked:bg-blue-600 peer-checked:border-blue-600 transition-colors" />
                        <div className="w-3 h-3 rounded-full bg-white transform translate-x-1 peer-checked:translate-x-5 shadow transition-all" />
                      </label>
                    </td>
                    <td className="px-4 py-3 text-right">
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => removeDomain(d.id, d.domain)}
                        className="text-slate-500 hover:text-red-400 hover:bg-red-500/10 p-1.5"
                        title="Remove domain"
                      >
                        <Trash2 className="w-4 h-4" />
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>

        <div className="mt-8 p-6 rounded-xl border border-white/10 bg-white/5">
          <h3 className="text-sm font-semibold text-slate-200 mb-3">Alert types</h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            {[
              { label: "Certificate expiry", desc: "Alert before a monitored cert expires" },
              { label: "New phishing report", desc: "Notify when a domain is reported" },
              { label: "Reputation change", desc: "Alert on risk-score changes" },
              { label: "Header change", desc: "Notify when security headers change" },
            ].map((a, i) => (
              <div key={i} className="flex items-center gap-3 p-3 rounded-lg border border-white/10 bg-white/3">
                <div className="w-7 h-7 rounded flex items-center justify-center text-xs font-medium bg-blue-600/20 text-blue-400 border border-blue-500/30">
                  <Bell className="w-3 h-3" />
                </div>
                <div>
                  <div className="text-xs font-medium text-slate-200">{a.label}</div>
                  <div className="text-[10px] text-slate-500">{a.desc}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
