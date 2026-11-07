import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  ShieldCheck,
  ShieldAlert,
  Lock,
  Zap,
  Search,
  ArrowRight,
  ExternalLink,
  Activity,
  Terminal,
  AlertTriangle,
  CheckCircle2,
  Copy,
  Sparkles,
  Globe,
  Cpu,
  Layers,
  Radio,
  FileText,
  Users,
} from "lucide-react";
import { Button } from "@/components/ui/button";

const SAMPLE_TARGETS = [
  { label: "Phishing Bank Clone", url: "https://secure-chase-update.bank-verify.xyz/login", type: "threat" },
  { label: "Fake PayPal Portal", url: "https://paypa1-account-resolution.top/auth", type: "threat" },
  { label: "Crypto Seed Drainer", url: "https://metamask-claim-airdrop.online/connect", type: "threat" },
  { label: "Official Google Auth", url: "https://accounts.google.com/signin", type: "safe" },
];

const CAPABILITIES = [
  {
    icon: ShieldAlert,
    tag: "Neural Heuristics",
    tagColor: "text-red-400 border-red-500/30 bg-red-500/10",
    title: "Zero-Day Phishing Detection",
    desc: "Identifies lookalike homograph domains, deceptive login forms, and obfuscated credential harvesters in real time.",
    metric: "99.8% Catch Rate",
    accentGlow: "from-red-500/20 to-orange-500/5",
    iconColor: "text-red-400 bg-red-500/15 border-red-500/30",
  },
  {
    icon: Lock,
    tag: "X.509 Cryptography",
    tagColor: "text-cyan-400 border-cyan-500/30 bg-cyan-500/10",
    title: "Certificate Chain Validation",
    desc: "Examines Certificate Authority trust paths, short-lived domain-validated certs, and suspicious SNI mismatches.",
    metric: "Deep Chain Audit",
    accentGlow: "from-cyan-500/20 to-blue-500/5",
    iconColor: "text-cyan-400 bg-cyan-500/15 border-cyan-500/30",
  },
  {
    icon: Cpu,
    tag: "RFC Header Audit",
    tagColor: "text-blue-400 border-blue-500/30 bg-blue-500/10",
    title: "Security Header Forensics",
    desc: "Detects missing Content-Security-Policy (CSP), HSTS enforcement gaps, open redirect chains, and clickjacking risks.",
    metric: "14 Checks / Scan",
    accentGlow: "from-blue-500/20 to-indigo-500/5",
    iconColor: "text-blue-400 bg-blue-500/15 border-blue-500/30",
  },
  {
    icon: Radio,
    tag: "Decentralized Intel",
    tagColor: "text-emerald-400 border-emerald-500/30 bg-emerald-500/10",
    title: "Community Threat Feeds",
    desc: "Crowdsourced indicators of compromise updated continuously by security researchers and verified analysts globally.",
    metric: "Live Consensus",
    accentGlow: "from-emerald-500/20 to-cyan-500/5",
    iconColor: "text-emerald-400 bg-emerald-500/15 border-emerald-500/30",
  },
];

const TELEMETRY_STATS = [
  { value: "<45ms", label: "Real-time Telemetry Latency", detail: "Edge inspection pipeline" },
  { value: "99.8%", label: "Phishing Detection Precision", detail: "Zero false-negative target" },
  { value: "1.8M+", label: "Quarantined Hostile URLs", detail: "Global blocklist sync" },
  { value: "256-bit", label: "Cryptographic Integrity", detail: "X.509 cert validation" },
];

export default function Landing() {
  const navigate = useNavigate();
  const [url, setUrl] = useState("https://secure-chase-update.bank-verify.xyz/login");
  const [copied, setCopied] = useState(false);

  const handleScanSubmit = (e) => {
    e.preventDefault();
    if (!url.trim()) return;
    navigate(`/scan?url=${encodeURIComponent(url.trim())}`);
  };

  const handleCopyTarget = (sampleUrl) => {
    setUrl(sampleUrl);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="min-h-screen relative overflow-hidden bg-[#070b14] text-slate-100 cyber-grid flex flex-col selection:bg-cyan-500/30 selection:text-white">
      {/* Dynamic Fluid Liquid Glow Orbs */}
      <div className="fixed inset-0 pointer-events-none overflow-hidden z-0">
        {/* Liquid Cyan Orb */}
        <div className="absolute top-[-10%] left-[15%] w-[650px] h-[650px] rounded-full bg-cyan-500/15 blur-[140px] animate-pulse-slow" />
        {/* Liquid Royal Blue Orb */}
        <div className="absolute top-[25%] right-[-5%] w-[600px] h-[600px] rounded-full bg-blue-600/15 blur-[160px] animate-float-fluid" />
        {/* Liquid Indigo/Purple Orb */}
        <div className="absolute bottom-[-10%] left-[25%] w-[700px] h-[700px] rounded-full bg-indigo-600/10 blur-[150px] animate-pulse-slow" />
      </div>

      {/* Cyber Radial Ambient Vignette */}
      <div className="fixed inset-0 pointer-events-none z-0 bg-[radial-gradient(ellipse_80%_80%_at_50%_-20%,rgba(14,165,233,0.15),rgba(255,255,255,0))]" />

      {/* Top Floating Liquid Glass Navigation Bar */}
      <header className="relative z-20 w-full px-4 sm:px-6 lg:px-8 pt-4 pb-2">
        <nav className="max-w-6xl mx-auto liquid-glass rounded-full px-5 py-3 border border-white/10 shadow-[0_8px_32px_rgba(0,0,0,0.5)] flex items-center justify-between transition-all">
          {/* Logo with Cyber Shield Accent */}
          <Link to="/" className="flex items-center gap-2.5 group">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 p-[1px] shadow-[0_0_20px_rgba(6,182,212,0.5)] group-hover:shadow-[0_0_28px_rgba(6,182,212,0.8)] transition-all">
              <div className="w-full h-full bg-[#0b1222] rounded-[11px] flex items-center justify-center">
                <ShieldCheck className="w-5 h-5 text-cyan-400 group-hover:scale-110 transition-transform" />
              </div>
            </div>
            <div className="flex flex-col">
              <span className="font-bold text-base sm:text-lg tracking-tight bg-gradient-to-r from-white via-slate-100 to-cyan-300 bg-clip-text text-transparent">
                TrustShield
              </span>
              <span className="text-[9px] font-mono tracking-wider text-cyan-400/80 uppercase font-semibold">
                SecOps Matrix
              </span>
            </div>
          </Link>

          {/* Centered Navigation Links with subtle cyber pills */}
          <div className="hidden md:flex items-center gap-1.5 px-3 py-1 rounded-full bg-white/[0.03] border border-white/5">
            <Link
              to="/dashboard"
              className="text-xs font-medium text-slate-300 hover:text-cyan-300 px-3.5 py-1.5 rounded-full hover:bg-white/5 transition-all"
            >
              Dashboard
            </Link>
            <Link
              to="/scan"
              className="text-xs font-medium text-slate-300 hover:text-cyan-300 px-3.5 py-1.5 rounded-full hover:bg-white/5 transition-all"
            >
              URL Scanner
            </Link>
            <Link
              to="/community"
              className="text-xs font-medium text-slate-300 hover:text-cyan-300 px-3.5 py-1.5 rounded-full hover:bg-white/5 transition-all"
            >
              Community Intel
            </Link>
            <Link
              to="/report"
              className="text-xs font-medium text-slate-300 hover:text-cyan-300 px-3.5 py-1.5 rounded-full hover:bg-white/5 transition-all"
            >
              Report Threat
            </Link>
          </div>

          {/* Action Button & Live Security Status */}
          <div className="flex items-center gap-3">
            <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-[10px] font-mono font-medium">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              RADAR ACTIVE
            </div>
            <Button
              onClick={() => navigate("/dashboard")}
              className="bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-navy-950 font-bold text-xs px-4 py-2 rounded-full shadow-[0_0_20px_rgba(6,182,212,0.4)] transition-all hover:shadow-[0_0_30px_rgba(6,182,212,0.7)]"
            >
              Launch Console
            </Button>
          </div>
        </nav>
      </header>

      {/* Main Content Area */}
      <main className="relative z-10 flex-1 flex flex-col max-w-6xl mx-auto w-full px-4 sm:px-6 lg:px-8 pt-8 pb-16">
        {/* HERO SECTION */}
        <section className="flex flex-col items-center text-center pt-6 pb-12">
          {/* Cyber Status Pill Badge */}
          <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full liquid-glass border border-cyan-500/30 text-cyan-300 text-xs font-medium mb-6 shadow-[0_0_20px_rgba(6,182,212,0.15)] animate-in fade-in slide-in-from-top-2 duration-500">
            <Radio className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
            <span className="tracking-wide">Zero-Trust Web Verification Engine</span>
            <span className="text-slate-500">|</span>
            <span className="text-[11px] font-mono text-cyan-400/90">v2.4 SEC-OPS</span>
          </div>

          {/* Primary Punchy Cyber Title */}
          <h1 className="text-4xl sm:text-6xl lg:text-7xl font-extrabold tracking-tight text-white max-w-4xl leading-[1.1] mb-6">
            Check Before You Trust.{" "}
            <span className="block mt-1 bg-gradient-to-r from-cyan-400 via-teal-300 to-blue-500 bg-clip-text text-transparent drop-shadow-[0_0_35px_rgba(6,182,212,0.4)]">
              Neutralize Phishing Links.
            </span>
          </h1>

          {/* Subtitle with High-Tech Context */}
          <p className="text-sm sm:text-base md:text-lg text-slate-300 max-w-2xl mx-auto leading-relaxed mb-10">
            Autonomous threat inspection analyzing brand impersonation, deceptive homographs,
            rogue SSL certificates, and weaponized redirects before you enter sensitive credentials.
          </p>

          {/* THE LIQUID GLASS SCANNER TERMINAL CONSOLE */}
          <div className="w-full max-w-3xl mx-auto mb-6">
            <div className="liquid-glass-glow rounded-3xl p-3 sm:p-4 shadow-[0_20px_50px_rgba(0,0,0,0.6)] border border-cyan-500/30 transition-all">
              {/* Terminal Title Bar */}
              <div className="flex items-center justify-between px-3 pb-3 border-b border-white/5 mb-3 text-xs text-slate-400 font-mono">
                <div className="flex items-center gap-1.5">
                  <div className="w-2.5 h-2.5 rounded-full bg-red-500/80" />
                  <div className="w-2.5 h-2.5 rounded-full bg-amber-500/80" />
                  <div className="w-2.5 h-2.5 rounded-full bg-emerald-500/80" />
                  <span className="ml-2 text-slate-400 hidden sm:inline">SEC-CORE // DEEP_URL_INSPECTOR</span>
                </div>
                <div className="flex items-center gap-2 text-[11px] text-cyan-400/80">
                  <Activity className="w-3 h-3 animate-spin" style={{ animationDuration: "6s" }} />
                  <span>HEURISTIC ENGINE READY</span>
                </div>
              </div>

              {/* Input & Scan Button Row */}
              <form onSubmit={handleScanSubmit} className="flex flex-col sm:flex-row gap-2.5">
                <div className="relative flex-1 group">
                  <div className="absolute left-4 top-1/2 -translate-y-1/2 text-cyan-400/70 group-focus-within:text-cyan-300 transition-colors">
                    <Terminal className="w-4 h-4" />
                  </div>
                  <input
                    type="url"
                    placeholder="Enter URL to inspect (e.g. https://suspect-domain.top/login)..."
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    className="w-full bg-[#0a101f]/90 text-slate-100 placeholder-slate-500 text-sm rounded-2xl pl-11 pr-4 py-4 border border-cyan-500/20 focus:border-cyan-400 focus:outline-none focus:ring-2 focus:ring-cyan-500/30 transition-all font-mono"
                    required
                  />
                </div>

                <Button
                  type="submit"
                  size="lg"
                  className="bg-gradient-to-r from-cyan-500 via-blue-600 to-indigo-600 hover:from-cyan-400 hover:via-blue-500 hover:to-indigo-500 text-white font-bold text-sm px-7 py-4 rounded-2xl shadow-[0_0_25px_rgba(6,182,212,0.4)] hover:shadow-[0_0_35px_rgba(6,182,212,0.7)] transition-all flex items-center justify-center gap-2 group cursor-pointer"
                >
                  <span>Scan Target</span>
                  <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
                </Button>
              </form>

              {/* Sample Target Attack Payloads for 1-Click Testing */}
              <div className="pt-4 mt-3 border-t border-white/5 flex flex-wrap items-center justify-between gap-2 px-1 text-xs">
                <span className="text-slate-400 font-mono text-[11px] flex items-center gap-1.5">
                  <Sparkles className="w-3.5 h-3.5 text-cyan-400" /> Test with threat samples:
                </span>
                <div className="flex flex-wrap gap-1.5">
                  {SAMPLE_TARGETS.map((sample, idx) => (
                    <button
                      key={idx}
                      type="button"
                      onClick={() => handleCopyTarget(sample.url)}
                      className={`text-[11px] font-mono px-2.5 py-1 rounded-lg border transition-all cursor-pointer ${
                        sample.type === "threat"
                          ? "bg-red-500/10 text-red-300 border-red-500/20 hover:bg-red-500/20 hover:border-red-500/40"
                          : "bg-emerald-500/10 text-emerald-300 border-emerald-500/20 hover:bg-emerald-500/20 hover:border-emerald-500/40"
                      }`}
                      title={sample.url}
                    >
                      {sample.label}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* TELEMETRY METRIC STRIP (Liquid Glass Bar) */}
          <div className="w-full max-w-4xl mx-auto grid grid-cols-2 md:grid-cols-4 gap-3 pt-4">
            {TELEMETRY_STATS.map((stat, i) => (
              <div
                key={i}
                className="liquid-glass rounded-2xl p-4 text-center border border-white/5 hover:border-cyan-500/30 transition-all group"
              >
                <div className="text-xl sm:text-2xl font-extrabold font-mono text-cyan-300 group-hover:text-cyan-200 transition-colors">
                  {stat.value}
                </div>
                <div className="text-xs font-semibold text-slate-200 mt-1">{stat.label}</div>
                <div className="text-[10px] text-slate-500 font-mono mt-0.5">{stat.detail}</div>
              </div>
            ))}
          </div>
        </section>

        {/* 4 CORE DEFENSE CAPABILITY CARDS (Liquid Glass Interactive) */}
        <section className="py-12">
          <div className="text-center mb-10">
            <div className="inline-flex items-center gap-2 text-xs font-mono font-semibold uppercase text-cyan-400 tracking-widest px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/20 mb-3">
              Comprehensive Protection Matrix
            </div>
            <h2 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
              Multi-Layered Threat Inspection
            </h2>
            <p className="text-sm text-slate-400 max-w-xl mx-auto mt-2">
              Beyond simple URL blocklists. TrustShield actively deconstructs domain telemetry, certificates,
              HTTP responses, and form handlers.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5">
            {CAPABILITIES.map((cap, i) => (
              <div
                key={i}
                className="liquid-glass-interactive rounded-2xl p-6 flex flex-col justify-between group cursor-default relative overflow-hidden"
              >
                {/* Background ambient gradient glow on hover */}
                <div
                  className={`absolute -right-12 -top-12 w-36 h-36 rounded-full bg-gradient-to-br ${cap.accentGlow} blur-2xl group-hover:scale-150 transition-transform duration-700 pointer-events-none`}
                />

                <div>
                  <div className="flex items-center justify-between mb-4">
                    <div className={`w-12 h-12 rounded-2xl border flex items-center justify-center ${cap.iconColor} shadow-lg transition-transform group-hover:scale-110 duration-300`}>
                      <cap.icon className="w-6 h-6" />
                    </div>
                    <span className={`text-[10px] font-mono font-bold px-2.5 py-1 rounded-full border ${cap.tagColor}`}>
                      {cap.tag}
                    </span>
                  </div>

                  <h3 className="text-base font-bold text-slate-100 group-hover:text-cyan-300 transition-colors mb-2">
                    {cap.title}
                  </h3>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    {cap.desc}
                  </p>
                </div>

                <div className="pt-4 mt-6 border-t border-white/5 flex items-center justify-between text-xs font-mono text-slate-400">
                  <span className="text-[11px] text-slate-500">BENCHMARK</span>
                  <span className="text-cyan-400 font-semibold">{cap.metric}</span>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* ANATOMY OF A THREAT - LIVE COMPARISON CARD */}
        <section className="py-8">
          <div className="liquid-glass rounded-3xl p-6 sm:p-8 border border-white/10 shadow-[0_20px_50px_rgba(0,0,0,0.5)]">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-6 pb-6 border-b border-white/5">
              <div>
                <span className="text-xs font-mono text-cyan-400 uppercase tracking-widest font-semibold">
                  Visual Threat Diagnostic
                </span>
                <h3 className="text-xl sm:text-2xl font-bold text-white mt-1">
                  Why A Simple "Green Padlock" Is No Longer Enough
                </h3>
              </div>
              <p className="text-xs text-slate-400 max-w-md">
                Over 82% of active phishing websites now display a valid HTTPS padlock. TrustShield uncovers
                the hidden deception signals normal browsers ignore.
              </p>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Spoofed Attack Vector Card */}
              <div className="rounded-2xl p-5 border border-red-500/30 bg-red-950/20 backdrop-blur-xl relative overflow-hidden">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <div className="w-2.5 h-2.5 rounded-full bg-red-500 animate-pulse" />
                    <span className="text-xs font-mono font-bold text-red-400 uppercase tracking-wide">
                      Hostile Phishing Vector
                    </span>
                  </div>
                  <span className="text-xs font-mono bg-red-500/20 text-red-300 px-2 py-0.5 rounded border border-red-500/30">
                    RISK 92/100
                  </span>
                </div>

                <div className="p-3 rounded-xl bg-black/40 border border-red-500/20 font-mono text-xs text-red-200 mb-4 break-all">
                  https://<span className="text-amber-300 font-bold underline">secure-login.paypa1</span>-verify.<span className="text-red-400 font-bold">top</span>/auth
                </div>

                <ul className="space-y-2 text-xs text-slate-300">
                  <li className="flex items-start gap-2">
                    <span className="text-red-400 mt-0.5 font-bold">✕</span>
                    <span><strong>Homograph spoof:</strong> Substitutes numeral <code className="text-amber-300 bg-white/5 px-1 rounded">'1'</code> for letter <code className="text-cyan-300 bg-white/5 px-1 rounded">'l'</code> in brand name.</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-red-400 mt-0.5 font-bold">✕</span>
                    <span><strong>Disposable cert:</strong> Free certificate issued 4 hours ago via Let's Encrypt abuse.</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-red-400 mt-0.5 font-bold">✕</span>
                    <span><strong>Credential harvest:</strong> Unobfuscated POST form sends password + OTP to Russian VPS endpoint.</span>
                  </li>
                </ul>
              </div>

              {/* Verified Domain Card */}
              <div className="rounded-2xl p-5 border border-emerald-500/30 bg-emerald-950/20 backdrop-blur-xl relative overflow-hidden">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <div className="w-2.5 h-2.5 rounded-full bg-emerald-400" />
                    <span className="text-xs font-mono font-bold text-emerald-400 uppercase tracking-wide">
                      Verified Canonical Target
                    </span>
                  </div>
                  <span className="text-xs font-mono bg-emerald-500/20 text-emerald-300 px-2 py-0.5 rounded border border-emerald-500/30">
                    RISK 04/100
                  </span>
                </div>

                <div className="p-3 rounded-xl bg-black/40 border border-emerald-500/20 font-mono text-xs text-emerald-200 mb-4 break-all">
                  https://www.paypal.com/signin
                </div>

                <ul className="space-y-2 text-xs text-slate-300">
                  <li className="flex items-start gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
                    <span><strong>Verified identity:</strong> PayPal, Inc. DigiCert High Assurance EV Root CA chain.</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
                    <span><strong>HSTS preload:</strong> Strict Transport Security enforced with max-age 31536000.</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
                    <span><strong>Hardened CSP:</strong> Strict Content-Security-Policy prohibits untrusted third-party scripts.</span>
                  </li>
                </ul>
              </div>
            </div>
          </div>
        </section>

        {/* 4-STAGE AUTONOMOUS PIPELINE */}
        <section className="py-12">
          <div className="text-center mb-10">
            <span className="text-xs font-mono text-cyan-400 uppercase tracking-widest font-semibold">
              Inspection Workflow
            </span>
            <h2 className="text-2xl sm:text-3xl font-bold text-white tracking-tight mt-1">
              How TrustShield Analyzes Any Target
            </h2>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {[
              {
                step: "01",
                title: "Canonicalization",
                desc: "Unwraps shorteners (bit.ly, t.co), follows redirect chains, and extracts target hostname & IP.",
              },
              {
                step: "02",
                title: "Neural Sandbox",
                desc: "Parses DOM content, brand keywords, logo assets, and password input fields for spoofing patterns.",
              },
              {
                step: "03",
                title: "Cryptographic Audit",
                desc: "Queries CRLs, OCSP stapling, certificate lifespan, and issuer hierarchy to catch rogue certs.",
              },
              {
                step: "04",
                title: "Consensus Verdict",
                desc: "Combines local heuristic scores with global threat feeds to deliver an actionable 0-100 risk score.",
              },
            ].map((p, i) => (
              <div key={i} className="liquid-glass rounded-2xl p-5 border border-white/5 relative group">
                <div className="text-2xl font-extrabold font-mono text-cyan-400/40 mb-3 group-hover:text-cyan-400 transition-colors">
                  {p.step}
                </div>
                <h4 className="text-sm font-bold text-slate-100 mb-1">{p.title}</h4>
                <p className="text-xs text-slate-400 leading-relaxed">{p.desc}</p>
              </div>
            ))}
          </div>
        </section>

        {/* CALL TO ACTION & REPORT BANNER */}
        <section className="py-6">
          <div className="liquid-glass-glow rounded-3xl p-8 md:p-10 text-center relative overflow-hidden border border-cyan-500/30">
            <div className="max-w-2xl mx-auto">
              <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-300 text-xs font-mono mb-4">
                <Users className="w-3.5 h-3.5" /> Community Defense Network
              </span>
              <h2 className="text-2xl sm:text-3xl font-bold text-white tracking-tight mb-3">
                Found a Suspicious Link in Email, SMS, or Discord?
              </h2>
              <p className="text-sm text-slate-300 mb-8 leading-relaxed">
                Submit a confidential threat report. Your submission automatically alerts thousands
                of users and initiates automated quarantine testing across our global network.
              </p>
              <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
                <Button
                  onClick={() => navigate("/report")}
                  size="lg"
                  className="w-full sm:w-auto bg-gradient-to-r from-red-500 to-orange-500 hover:from-red-400 hover:to-orange-400 text-white font-bold text-sm px-8 py-3.5 rounded-2xl shadow-[0_0_25px_rgba(239,68,68,0.4)] cursor-pointer"
                >
                  <ShieldAlert className="w-4 h-4 mr-2" /> Report Malicious URL
                </Button>
                <Button
                  onClick={() => navigate("/dashboard")}
                  variant="outline"
                  size="lg"
                  className="w-full sm:w-auto border-white/10 text-slate-200 hover:bg-white/5 font-semibold text-sm px-8 py-3.5 rounded-2xl cursor-pointer"
                >
                  Open Threat Dashboard
                </Button>
              </div>
            </div>
          </div>
        </section>
      </main>

      {/* Sleek Cyber Footer */}
      <footer className="relative z-10 border-t border-white/5 bg-[#050811]/80 backdrop-blur-xl py-10 px-4 sm:px-6 lg:px-8 mt-auto">
        <div className="max-w-6xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-6 text-xs text-slate-400">
          <div className="flex items-center gap-3">
            <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center text-navy-950 font-bold">
              <ShieldCheck className="w-4 h-4 text-navy-950" />
            </div>
            <div>
              <span className="font-bold text-slate-200 text-sm">TrustShield</span>
              <span className="text-[10px] text-cyan-400/80 font-mono ml-2">Zero-Trust Telemetry</span>
            </div>
          </div>

          <div className="flex flex-wrap items-center justify-center gap-6 text-slate-400 font-medium">
            <Link to="/dashboard" className="hover:text-cyan-300 transition-colors">Dashboard</Link>
            <Link to="/scan" className="hover:text-cyan-300 transition-colors">Scanner</Link>
            <Link to="/community" className="hover:text-cyan-300 transition-colors">Community</Link>
            <Link to="/watchlist" className="hover:text-cyan-300 transition-colors">Watchlist</Link>
            <Link to="/report" className="hover:text-cyan-300 transition-colors">Report Threat</Link>
          </div>

          <div className="text-slate-500 font-mono text-[11px] text-center sm:text-right">
            © 2026 TrustShield · Community-Powered SecOps
          </div>
        </div>
      </footer>
    </div>
  );
}
