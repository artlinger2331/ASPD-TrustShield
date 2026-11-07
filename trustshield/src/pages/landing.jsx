import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Search, ArrowRight, ShieldCheck, Mail, Link as LinkIcon, Lock, Zap, Info } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

export default function Landing() {
  const navigate = useNavigate();
  const [url, setUrl] = useState("https://example-bank-login.com");

  const badges = [
    { label: "Phishing Detection", desc: "Spot fake login pages & brand impersonation" },
    { label: "Certificate Validation", desc: "Verify HTTPS & trust-chain integrity" },
    { label: "Security Assessment", desc: "Check headers, cookies & server config" },
    { label: "Community Reports", desc: "Real-time threat intel from users" },
  ];

  const steps = [
    { num: "01", title: "Enter a URL", desc: "Paste any website address into the scanner." },
    { num: "02", title: "Deep analysis", desc: "We check reputation, content, redirects & certificates." },
    { num: "03", title: "Get a verdict", desc: "See a clear risk score and plain-language advice." },
    { num: "04", title: "Stay safe", desc: "Decide whether to proceed or report the site." },
  ];

  return (
    <div className="min-h-screen flex flex-col relative overflow-hidden">
      <div className="absolute inset-0 z-0 opacity-30 pointer-events-none">
        <div className="absolute top-[-10%] left-[-10%] w-72 h-72 rounded-full bg-blue-600/20 blur-[120px]" />
        <div className="absolute bottom-[-10%] right-[-10%] w-96 h-96 rounded-full bg-cyan-500/15 blur-[120px]" />
      </div>

      <nav className="relative z-10 flex items-center justify-between px-6 py-4 md:px-8 lg:px-12">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 rounded-lg bg-blue-600 flex items-center justify-center text-white font-bold">TS</div>
          <span className="text-xl font-bold text-slate-100 tracking-tight">TrustShield</span>
        </div>
        <div className="hidden md:flex items-center gap-6 text-sm text-slate-400">
          <a href="#" className="hover:text-white transition-colors">Features</a>
          <a href="#" className="hover:text-white transition-colors">Report a Site</a>
          <a href="#" className="hover:text-white transition-colors">API</a>
        </div>
        <Button className="bg-white text-navy-900 hover:bg-slate-200 text-sm font-semibold px-5 py-2.5">
          Log in
        </Button>
      </nav>

      <main className="relative z-10 flex-1 px-6 pb-12 md:px-8 lg:px-12 max-w-6xl mx-auto w-full">
        <section className="max-w-3xl text-center mb-20">
          <span className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 text-xs font-semibold mb-6">
            <span className="w-2 h-2 rounded-full bg-blue-400 animate-pulse" /> Active threat monitoring
          </span>
          <h1 className="text-5xl md:text-7xl font-bold text-slate-100 tracking-tight mb-6 text-balance">
            Check before you trust.
          </h1>
          <p className="text-lg md:text-xl text-slate-400 mb-8 max-w-xl mx-auto leading-relaxed">
            Analyze phishing risks, website security, HTTPS certificates, and community threat reports in one
            place — before you enter personal, financial, or login information.
          </p>
          <div className="flex flex-col sm:flex-row gap-3 justify-center items-center">
            <div className="relative flex-1 sm:w-[420px]">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
              <input
                type="url"
                placeholder="https://example-bank-login.com"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                className="w-full rounded-xl border border-white/10 bg-white/5 pl-10 pr-4 py-3.5 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50"
              />
            </div>
            <Button size="lg" onClick={() => navigate(`/scan?url=${encodeURIComponent(url)}`)} className="w-full sm:w-auto">
              Scan website <ArrowRight className="ml-2 w-4 h-4" />
            </Button>
          </div>
        </section>

        <section className="mb-16">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {badges.map((b, i) => (
              <Card key={i} className="p-4">
                <div className="w-10 h-10 rounded-xl bg-blue-500/10 flex items-center justify-center text-blue-400 mb-3">
                  {i === 0 ? <ShieldCheck /> : i === 1 ? <Lock /> : i === 2 ? <Zap /> : <Info />}
                </div>
                <CardTitle className="text-sm">{b.label}</CardTitle>
                <CardDescription>{b.desc}</CardDescription>
              </Card>
            ))}
          </div>
        </section>

        <section className="mb-16">
          <div className="flex flex-col md:flex-row gap-8 items-center">
            <div className="flex-1">
              <h2 className="text-2xl font-bold text-slate-100 mb-4">How it works</h2>
              <div className="space-y-5">
                {steps.map((s) => (
                  <div key={s.num} className="flex gap-4">
                    <div className="flex-shrink-0 w-8 h-8 rounded-full bg-blue-600/20 flex items-center justify-center text-blue-400 text-xs font-bold border border-blue-500/30">
                      {s.num}
                    </div>
                    <div>
                      <h3 className="text-sm font-semibold text-slate-200">{s.title}</h3>
                      <p className="text-xs text-slate-500 mt-0.5">{s.desc}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
            <div className="hidden md:block w-1/2">
              <div className="glass rounded-2xl p-6 border border-white/5">
                <div className="text-xs text-slate-500 uppercase tracking-wider mb-3">Example scan</div>
                <div className="mb-4 p-3 rounded-xl bg-white/5 border border-white/5 font-mono text-xs text-slate-400">
                  secure-sbi-login.verify-account.top
                </div>
                <div className="flex items-center gap-3 mb-6">
                  <div className="w-2 h-2 rounded-full bg-red-500" />
                  <span className="text-sm font-medium text-red-400">Dangerous — Likely phishing</span>
                </div>
                <div className="flex items-center gap-3">
                  <div className="w-2 h-2 rounded-full bg-orange-500" />
                  <span className="text-sm font-medium text-orange-400">Risk score: 87 / 100</span>
                </div>
              </div>
            </div>
          </div>
        </section>

        <section className="mb-16 bg-white/5 rounded-2xl p-8 md:p-12 border border-white/5">
          <div className="max-w-2xl mx-auto text-center">
            <h2 className="text-2xl font-bold text-slate-100 mb-4">Why HTTPS alone isn't enough</h2>
            <p className="text-slate-400 text-sm mb-8 leading-relaxed max-w-lg mx-auto">
              A padlock only means the connection is encrypted — not that the website is trustworthy. Phishing
              sites can have valid HTTPS certificates. TrustShield checks domain reputation, content, redirects,
              security headers, and community reports to give you the full picture.
            </p>
            <Button onClick={() => navigate("/report")} className="w-full md:w-auto bg-blue-600 text-white px-8 py-3 text-sm font-semibold">
              Report a suspicious website <ArrowRight className="ml-2 w-4 h-4" />
            </Button>
          </div>
        </section>
      </main>

      <footer className="relative z-10 border-t border-white/10 bg-white/3 backdrop-blur pt-12 pb-8 px-6 md:px-8 lg:px-12">
        <div className="max-w-6xl mx-auto">
          <div className="flex flex-col md:flex-row justify-between items-center gap-6 mb-10">
            <div className="flex items-center gap-2">
              <div className="w-6 h-6 rounded bg-blue-600 flex items-center justify-center text-white text-[10px] font-bold">TS</div>
              <span className="font-bold text-slate-200">TrustShield</span>
            </div>
            <p className="text-xs text-slate-500">© 2026 TrustShield. Community-powered threat intelligence.</p>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8 text-sm">
            <div>
              <h4 className="text-slate-100 font-semibold mb-4">Product</h4>
              <ul className="space-y-2 text-slate-500 text-xs">
                <li><a href="#" className="hover:text-white transition-colors">About</a></li>
                <li><a href="#" className="hover:text-white transition-colors">Features</a></li>
                <li><a href="#" className="hover:text-white transition-colors">Report a Site</a></li>
                <li><a href="#" className="hover:text-white transition-colors">API</a></li>
              </ul>
            </div>
            <div>
              <h4 className="text-slate-100 font-semibold mb-4">Legal</h4>
              <ul className="space-y-2 text-slate-500 text-xs">
                <li><a href="#" className="hover:text-white transition-colors">Privacy</a></li>
                <li><a href="#" className="hover:text-white transition-colors">Contact</a></li>
              </ul>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}
