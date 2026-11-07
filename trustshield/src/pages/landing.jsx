import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  Search,
  ArrowRight,
  ShieldCheck,
  Lock,
  Zap,
  Info,
  Terminal,
  Globe,
  Network,
  RefreshCw,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

const BADGES = [
  {
    icon: <ShieldCheck className="w-5 h-5" />,
    label: "Phishing Detection",
    desc: "Spot fake login pages & brand impersonation",
    glow: "shadow-[0_0_20px_rgba(59,130,246,0.3)]",
  },
  {
    icon: <Lock className="w-5 h-5" />,
    label: "Certificate Validation",
    desc: "Verify HTTPS & trust-chain integrity",
    glow: "shadow-[0_0_20px_rgba(34,211,238,0.3)]",
  },
  {
    icon: <Zap className="w-5 h-5" />,
    label: "Security Assessment",
    desc: "Check headers, cookies & server config",
    glow: "shadow-[0_0_20px_rgba(245,158,11,0.3)]",
  },
  {
    icon: <Network className="w-5 h-5" />,
    label: "Community Reports",
    desc: "Real-time threat intel from users",
    glow: "shadow-[0_0_20px_rgba(239,68,68,0.3)]",
  },
];

const STEPS = [
  { num: "01", title: "Enter a URL", desc: "Paste any website address into the scanner." },
  { num: "02", title: "Deep analysis", desc: "We check reputation, content, redirects & certificates." },
  { num: "03", title: "Get a verdict", desc: "See a clear risk score and plain-language advice." },
  { num: "04", title: "Stay safe", desc: "Decide whether to proceed or report the site." },
];

export default function Landing() {
  const navigate = useNavigate();
  const [url, setUrl] = useState("https://example-bank-login.com");
  const [float, setFloat] = useState(0);

  return (
    <div className="min-h-screen relative overflow-hidden bg-[radial-gradient(circle_at_top_left,#13203b,#0b1120)]">
      {/* Background mesh/liquid effects */}
      <div className="fixed inset-0 z-0 pointer-events-none overflow-hidden">
        <div
          className="absolute top-[-10%] left-[-10%] w-[600px] h-[600px] rounded-full bg-blue-600/20 blur-[140px] animate-pulse"
          style={{ animationDuration: "10s" }}
        />
        <div
          className="absolute bottom-[-10%] right-[-10%] w-[700px] h-[700px] rounded-full bg-cyan-500/10 blur-[140px] animate-pulse"
          style={{ animationDuration: "14s", animationDelay: "-4s" }}
        />
        <div
          className="absolute top-[20%] left-[60%] w-[400px] h-[400px] rounded-full bg-purple-600/10 blur-[120px] animate-pulse"
          style={{ animationDuration: "12s", animationDelay: "-2s" }}
        />
      </div>

      {/* Subtle grid pattern */}
      <div className="fixed inset-0 z-0 pointer-events-none opacity-10" style={{ backgroundImage: "linear-gradient(#233054 1px, transparent 1px), linear-gradient(90deg, #233054 1px, transparent 1px)", backgroundSize: "40px 40px" }} />

      {/* Nav */}
      <nav className="relative z-10 flex items-center justify-between px-6 py-4 md:px-8 lg:px-12">
        <div className="flex items-center gap-2">
          <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-blue-500 to-cyan-500 flex items-center justify-center text-white font-bold shadow-[0_0_20px_rgba(59,130,246,0.6)]">
            TS
          </div>
          <span className="text-xl font-bold text-slate-100 tracking-tight">TrustShield</span>
        </div>
        <div className="hidden md:flex items-center gap-6 text-sm text-slate-400 font-medium">
          <a href="#" className="hover:text-white transition-colors">Features</a>
          <a href="#" className="hover:text-white transition-colors">Report a Site</a>
          <a href="#" className="hover:text-white transition-colors">API</a>
        </div>
        <Button className="bg-white text-navy-900 hover:bg-slate-200 text-sm font-semibold px-5 py-2.5 shadow-lg">
          Log in
        </Button>
      </nav>

      <main className="relative z-10 flex-1 px-6 pb-16 md:px-8 lg:px-12 max-w-7xl mx-auto w-full">
        <section className="max-w-4xl text-center mb-20">
          <span className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-500/10 border border-blue-500/30 text-blue-400 text-xs font-semibold mb-6 backdrop-blur-sm">
            <span className="w-2 h-2 rounded-full bg-blue-400 animate-pulse" /> Live threat monitoring
          </span>
          <h1 className="text-5xl md:text-8xl font-extrabold text-slate-100 tracking-tight mb-6 leading-[1.05]">
            Check before you trust.
          </h1>
          <p className="text-lg md:text-xl text-slate-400 mb-10 max-w-2xl mx-auto leading-relaxed">
            Analyze phishing risks, website security, HTTPS certificates, and community threat
            reports in one place — before you enter personal, financial, or login information.
          </p>
          <div className="flex flex-col sm:flex-row gap-3 justify-center items-center">
            <div className="relative flex-1 sm:w-[460px] group">
              <div className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500 group-focus-within:text-blue-400 transition-colors">
                <Search />
              </div>
              <input
                type="url"
                placeholder="https://example-bank-login.com"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                className="w-full rounded-2xl border border-white/10 bg-white/5 pl-12 pr-10 py-4 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500/60 focus:border-blue-500/50 backdrop-blur-md transition-all"
              />
            </div>
            <Button
              size="lg"
              onClick={() => navigate(`/scan?url=${encodeURIComponent(url)}`)}
              className="w-full sm:w-auto bg-gradient-to-r from-blue-600 to-cyan-600 text-white text-sm font-semibold px-8 py-4 shadow-[0_0_30px_rgba(59,130,246,0.5)] hover:from-blue-500 hover:to-cyan-500 hover:shadow-[0_0_40px_rgba(59,130,246,0.7)] transition-all"
            >
              Scan website <ArrowRight className="ml-2 w-4 h-4" />
            </Button>
          </div>
        </section>

        {/* Quick badges */}
        <section className="mb-16">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {BADGES.map((b, i) => (
              <Card
                key={i}
                className="p-5 group hover:border-blue-500/50 transition-colors"
              >
                <div
                  className={`w-12 h-12 rounded-2xl flex items-center justify-center mb-3 border border-white/10 ${b.glow}`}
                >
                  {b.icon}
                </div>
                <h3 className="text-sm font-semibold text-slate-100 mb-1">{b.label}</h3>
                <p className="text-xs text-slate-500 leading-relaxed">{b.desc}</p>
              </Card>
            ))}
          </div>
        </section>

        {/* How it works */}
        <section className="mb-16">
          <div className="flex flex-col md:flex-row gap-8 items-start">
            <div className="flex-1">
              <h2 className="text-2xl font-bold text-slate-100 mb-6">How it works</h2>
              <div className="space-y-5">
                {STEPS.map((s) => (
                  <div key={s.num} className="flex gap-4">
                    <div className="flex-shrink-0 w-10 h-10 rounded-xl bg-blue-600/20 flex items-center justify-center text-blue-400 text-xs font-bold border border-blue-500/30 shadow-[0_0_15px_rgba(59,130,246,0.3)]">
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
              <Card className="p-6 border border-white/10">
                <div className="flex items-center gap-2 mb-4">
                  <Terminal className="w-5 h-5 text-blue-400" />
                  <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Live example scan</span>
                </div>
                <div className="mb-4 p-3 rounded-xl bg-white/5 border border-white/5 font-mono text-xs text-slate-400">
                  secure-sbi-login.verify-account.top
                </div>
                <div className="flex items-center gap-3 mb-6">
                  <div className="w-2 h-2 rounded-full bg-red-500 shadow-[0_0_10px_rgba(239,68,68,0.6)]" />
                  <span className="text-sm font-medium text-red-400">Dangerous — Likely phishing</span>
                </div>
                <div className="flex items-center gap-3">
                  <div className="w-2 h-2 rounded-full bg-orange-500 shadow-[0_0_10px_rgba(245,158,11,0.6)]" />
                  <span className="text-sm font-medium text-orange-400">Risk score: 87 / 100</span>
                </div>
              </Card>
            </div>
          </div>
        </section>

        {/* Why HTTPS isn't enough */}
        <section className="relative overflow-hidden">
          <div className="absolute inset-0 bg-gradient-to-r from-blue-600/10 to-transparent -z-10" />
          <Card className="p-8 md:p-12 border border-white/10 text-center">
            <h2 className="text-2xl font-bold text-slate-100 mb-4">Why HTTPS alone isn't enough</h2>
            <p className="text-slate-400 text-sm mb-8 leading-relaxed max-w-lg mx-auto">
              A padlock only means the connection is encrypted — not that the website is trustworthy.
              Phishing sites can have valid HTTPS certificates. TrustShield checks domain reputation,
              content, redirects, security headers, and community reports to give you the full picture.
            </p>
            <div className="flex flex-col sm:flex-row gap-3 justify-center items-center">
              <Button
                onClick={() => navigate("/report")}
                className="w-full sm:w-auto bg-white text-slate-900 font-semibold px-8 py-3 text-sm shadow-xl hover:bg-slate-100 transition-colors"
              >
                Report a suspicious website <ArrowRight className="ml-2 w-4 h-4" />
              </Button>
              <Button variant="outline" className="w-full sm:w-auto px-8 py-3 text-sm font-semibold">
                Learn more
              </Button>
            </div>
          </Card>
        </section>
      </main>

      <footer className="relative z-10 border-t border-white/10 bg-white/3 backdrop-blur-md pt-12 pb-8 px-6 md:px-8 lg:px-12">
        <div className="max-w-6xl mx-auto">
          <div className="flex flex-col md:flex-row justify-between items-center gap-6 mb-10">
            <div className="flex items-center gap-2">
              <div className="w-6 h-6 rounded-lg bg-blue-600 flex items-center justify-center text-white text-[10px] font-bold">TS</div>
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
