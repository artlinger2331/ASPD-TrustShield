import { useState, useEffect } from "react";
import { Link, useNavigate } from "react-router-dom";
import { motion, useScroll, useSpring, AnimatePresence } from "framer-motion";
import {
  ShieldCheck,
  ShieldAlert,
  Shield,
  Lock,
  Unlock,
  ArrowRight,
  Activity,
  Terminal,
  CheckCircle2,
  Sparkles,
  Cpu,
  Radio,
  Users,
  Eye,
  Zap,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  Copy,
  Check,
  ExternalLink,
  Globe,
  Layers,
  ArrowUp,
  RefreshCw,
  BarChart3,
  Database,
  KeyRound,
  Search,
  AlertOctagon,
} from "lucide-react";
import { Button } from "@/components/ui/button";

const SAMPLE_TARGETS = [
  { label: "Phishing Bank Clone", url: "https://secure-chase-update.bank-verify.xyz/login", type: "threat" },
  { label: "Fake PayPal Portal", url: "https://paypa1-account-resolution.top/auth", type: "threat" },
  { label: "Crypto Seed Drainer", url: "https://metamask-claim-airdrop.online/connect", type: "threat" },
  { label: "Official Google Auth", url: "https://accounts.google.com/signin", type: "safe" },
];

const LIVE_THREAT_FEED = [
  { domain: "chase-update-verify.xyz", threat: "Homograph Phishing", risk: 96, time: "Just now", status: "Quarantined" },
  { domain: "paypa1-account-alert.top", threat: "Credential Harvester", risk: 94, time: "1m ago", status: "Blocked" },
  { domain: "metamask-airdrop-pool.site", threat: "Crypto Drainer", risk: 98, time: "3m ago", status: "Neutralized" },
  { domain: "wellsfargo-secure-login.cc", threat: "Brand Impersonation", risk: 91, time: "4m ago", status: "Quarantined" },
  { domain: "binance-token-claim.online", threat: "Zero-Day Exploit", risk: 99, time: "6m ago", status: "Blocked" },
  { domain: "microsoft-365-verify.biz", threat: "OAuth Hijack", risk: 89, time: "8m ago", status: "Quarantined" },
];

const CAPABILITIES = [
  {
    icon: ShieldAlert,
    tag: "Neural Engine",
    tagColor: "text-red-400 border-red-500/30 bg-red-500/10",
    title: "Zero-Day Phishing Detection",
    desc: "Autonomous heuristics uncover deceptive homoglyph characters, visually cloned login portals, and obfuscated credential fields.",
    metric: "99.8% Precision",
    accentGlow: "from-red-500/20 to-orange-500/5",
    iconColor: "text-red-400 bg-red-500/15 border-red-500/30",
    colSpan: "lg:col-span-2",
  },
  {
    icon: Lock,
    tag: "X.509 Forensics",
    tagColor: "text-cyan-400 border-cyan-500/30 bg-cyan-500/10",
    title: "SSL Certificate Validation",
    desc: "Audits Certificate Authority trust paths, short-lived domain-validated certs, and rogue SNI mismatches commonly abused by attackers.",
    metric: "Deep Chain Audit",
    accentGlow: "from-cyan-500/20 to-blue-500/5",
    iconColor: "text-cyan-400 bg-cyan-500/15 border-cyan-500/30",
    colSpan: "lg:col-span-1",
  },
  {
    icon: Cpu,
    tag: "HTTP Diagnostics",
    tagColor: "text-blue-400 border-blue-500/30 bg-blue-500/10",
    title: "Security Header Forensics",
    desc: "Inspects CSP policies, HSTS enforcement, open redirect loops, and clickjacking permissions in real time.",
    metric: "14 Strict Checks",
    accentGlow: "from-blue-500/20 to-indigo-500/5",
    iconColor: "text-blue-400 bg-blue-500/15 border-blue-500/30",
    colSpan: "lg:col-span-1",
  },
  {
    icon: Radio,
    tag: "Decentralized Intel",
    tagColor: "text-emerald-400 border-emerald-500/30 bg-emerald-500/10",
    title: "Global Threat Consensus",
    desc: "Crowdsourced indicators of compromise updated continuously by security researchers and verified SOC teams across 80+ countries.",
    metric: "Live Telemetry",
    accentGlow: "from-emerald-500/20 to-cyan-500/5",
    iconColor: "text-emerald-400 bg-emerald-500/15 border-emerald-500/30",
    colSpan: "lg:col-span-2",
  },
];

const TELEMETRY_STATS = [
  { value: "<28ms", label: "Edge Inspection Speed", detail: "Real-time telemetry pipeline" },
  { value: "99.8%", label: "Zero-Day Detection Precision", detail: "Zero false-negative target" },
  { value: "1.8M+", label: "Quarantined Hostile URLs", detail: "Global blocklist sync" },
  { value: "256-bit", label: "Cryptographic Integrity", detail: "X.509 cert validation" },
];

const WORKFLOW_STEPS = [
  {
    step: "01",
    title: "URL Canonicalization",
    desc: "Unwraps obfuscated shortlinks (bit.ly, tinyurl), traverses deep redirect chains, and extracts canonical host IP and DNS records.",
    badge: "Edge Parsing",
  },
  {
    step: "02",
    title: "Neural DOM & Form Sandbox",
    desc: "Renders page structure in an isolated sandbox, extracting input targets, password traps, homoglyphs, and logo asset hashes.",
    badge: "Heuristic AI",
  },
  {
    step: "03",
    title: "X.509 Certificate Chain Audit",
    desc: "Verifies CA root of trust, checks OCSP stapling status, flags ephemeral certs issued within hours, and examines wildcard SANs.",
    badge: "Cryptographic",
  },
  {
    step: "04",
    title: "Threat Consensus Verdict",
    desc: "Synthesizes multi-engine heuristics, IP reputation, and community telemetry into an actionable 0-100 risk score with quarantine advice.",
    badge: "Instant Decision",
  },
];

const FAQS = [
  {
    q: "How does TrustShield detect zero-day phishing before traditional blocklists?",
    a: "Traditional blocklists rely on reactive reports after users have already been victimized. TrustShield utilizes real-time neural heuristics to inspect visual brand impersonation, character homoglyphs (such as Cyrillic lookalikes), DOM credential forms, and newly minted SSL certificates on the fly.",
  },
  {
    q: "Is it safe to scan malicious URLs? Does TrustShield execute malware locally?",
    a: "Scanning is 100% safe. All inspections take place inside an isolated edge sandbox. No scripts, binaries, or malicious payloads are ever executed on your local machine or browser.",
  },
  {
    q: "Why isn't a valid SSL certificate (green padlock) enough to verify security?",
    a: "Over 82% of modern phishing websites now possess valid SSL certificates obtained through free, automated certificate authorities. The padlock only indicates encryption in transit, not the authenticity or trustworthiness of the party receiving your data.",
  },
  {
    q: "Can I integrate TrustShield into my enterprise SOC or browser workflow?",
    a: "Yes! TrustShield offers seamless API webhooks, automated SIEM data feeds, and community threat exports for enterprise incident response and proactive URL filtering.",
  },
];

export default function Landing() {
  const navigate = useNavigate();
  const [url, setUrl] = useState("https://secure-chase-update.bank-verify.xyz/login");
  const [copiedUrl, setCopiedUrl] = useState(false);
  const [activeConsoleTab, setActiveConsoleTab] = useState("homograph");
  const [activeFaq, setActiveFaq] = useState(null);
  const [scrolled, setScrolled] = useState(false);

  // Framer Motion scroll progress indicator
  const { scrollYProgress } = useScroll();
  const scaleX = useSpring(scrollYProgress, {
    stiffness: 100,
    damping: 30,
    restDelta: 0.001,
  });

  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 40);
    };
    window.addEventListener("scroll", handleScroll);
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  const handleScanSubmit = (e) => {
    e.preventDefault();
    if (!url.trim()) return;
    navigate(`/scan?url=${encodeURIComponent(url.trim())}`);
  };

  const handleCopyTarget = (sampleUrl) => {
    setUrl(sampleUrl);
    setCopiedUrl(true);
    setTimeout(() => setCopiedUrl(false), 2000);
  };

  const scrollToSection = (id) => {
    const element = document.getElementById(id);
    if (element) {
      element.scrollIntoView({ behavior: "smooth" });
    }
  };

  const scrollToTop = () => {
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  return (
    <div className="min-h-screen relative overflow-hidden bg-[#060913] text-slate-100 cyber-grid flex flex-col selection:bg-cyan-500/30 selection:text-white">
      {/* Scroll Progress Bar at very top */}
      <motion.div
        style={{ scaleX }}
        className="fixed top-0 left-0 right-0 h-[3px] bg-gradient-to-r from-cyan-400 via-blue-500 to-indigo-500 origin-left z-50 shadow-[0_0_12px_rgba(6,182,212,0.8)]"
      />

      {/* Dynamic Fluid Liquid Glow Orbs */}
      <div className="fixed inset-0 pointer-events-none overflow-hidden z-0">
        <div className="absolute top-[-8%] left-[10%] w-[680px] h-[680px] rounded-full bg-cyan-500/12 blur-[150px] animate-pulse-slow" />
        <div className="absolute top-[28%] right-[-5%] w-[620px] h-[620px] rounded-full bg-blue-600/15 blur-[160px] animate-float-fluid" />
        <div className="absolute bottom-[5%] left-[20%] w-[720px] h-[720px] rounded-full bg-indigo-600/10 blur-[160px] animate-pulse-slow" />
        <div className="absolute top-[60%] left-[-10%] w-[500px] h-[500px] rounded-full bg-emerald-500/10 blur-[140px] animate-float-fluid" />
      </div>

      {/* Cyber Ambient Radial Vignette */}
      <div className="fixed inset-0 pointer-events-none z-0 bg-[radial-gradient(ellipse_80%_80%_at_50%_-15%,rgba(14,165,233,0.18),rgba(255,255,255,0))]" />

      {/* Floating Cyber Glass Sticky Header */}
      <header
        className={`fixed top-0 left-0 right-0 z-40 transition-all duration-300 px-4 sm:px-6 lg:px-8 ${
          scrolled ? "py-2.5 bg-[#060913]/85 backdrop-blur-xl border-b border-white/10 shadow-[0_10px_30px_rgba(0,0,0,0.6)]" : "py-4 bg-transparent"
        }`}
      >
        <nav className="max-w-7xl mx-auto flex items-center justify-between">
          {/* Brand Logo with Cyber Glow */}
          <Link to="/" className="flex items-center gap-3 group">
            <div className="w-10 h-10 rounded-2xl bg-gradient-to-br from-cyan-400 to-blue-600 p-[1.5px] shadow-[0_0_25px_rgba(6,182,212,0.5)] group-hover:shadow-[0_0_35px_rgba(6,182,212,0.8)] transition-all">
              <div className="w-full h-full bg-[#0b1222] rounded-[14px] flex items-center justify-center">
                <ShieldCheck className="w-5 h-5 text-cyan-400 group-hover:scale-110 transition-transform" />
              </div>
            </div>
            <div className="flex flex-col">
              <div className="flex items-center gap-2">
                <span className="font-extrabold text-base sm:text-lg tracking-tight bg-gradient-to-r from-white via-slate-100 to-cyan-300 bg-clip-text text-transparent">
                  TrustShield
                </span>
                <span className="hidden sm:inline text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 font-semibold">
                  v2.5
                </span>
              </div>
              <span className="text-[10px] font-mono tracking-wider text-cyan-400/80 uppercase font-semibold">
                Autonomous SecOps Defense
              </span>
            </div>
          </Link>

          {/* Centered Navigation Pills */}
          <div className="hidden lg:flex items-center gap-1.5 px-4 py-1.5 rounded-full bg-white/[0.04] border border-white/10 backdrop-blur-md shadow-inner">
            <button
              onClick={() => scrollToSection("scanner")}
              className="text-xs font-medium text-slate-300 hover:text-cyan-300 px-3.5 py-1.5 rounded-full hover:bg-white/5 transition-all cursor-pointer"
            >
              URL Scanner
            </button>
            <button
              onClick={() => scrollToSection("features")}
              className="text-xs font-medium text-slate-300 hover:text-cyan-300 px-3.5 py-1.5 rounded-full hover:bg-white/5 transition-all cursor-pointer"
            >
              Capabilities
            </button>
            <button
              onClick={() => scrollToSection("console-demo")}
              className="text-xs font-medium text-slate-300 hover:text-cyan-300 px-3.5 py-1.5 rounded-full hover:bg-white/5 transition-all cursor-pointer"
            >
              Command Console
            </button>
            <button
              onClick={() => scrollToSection("workflow")}
              className="text-xs font-medium text-slate-300 hover:text-cyan-300 px-3.5 py-1.5 rounded-full hover:bg-white/5 transition-all cursor-pointer"
            >
              Architecture
            </button>
            <Link
              to="/community"
              className="text-xs font-medium text-slate-300 hover:text-cyan-300 px-3.5 py-1.5 rounded-full hover:bg-white/5 transition-all"
            >
              Community Intel
            </Link>
          </div>

          {/* Action Header Button & Live Radar Status */}
          <div className="flex items-center gap-3">
            <div className="hidden sm:flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/25 text-emerald-400 text-[11px] font-mono font-medium">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span>RADAR ONLINE</span>
            </div>

            <Button
              onClick={() => navigate("/dashboard")}
              className="bg-gradient-to-r from-cyan-500 via-blue-600 to-indigo-600 hover:from-cyan-400 hover:to-blue-500 text-white font-bold text-xs px-4 sm:px-5 py-2 sm:py-2.5 rounded-xl shadow-[0_0_20px_rgba(6,182,212,0.4)] transition-all hover:shadow-[0_0_30px_rgba(6,182,212,0.7)] flex items-center gap-1.5 cursor-pointer"
            >
              <span>Launch Console</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </Button>
          </div>
        </nav>
      </header>

      {/* Main Content Area */}
      <main className="relative z-10 flex-1 flex flex-col w-full pt-24 sm:pt-28">
        
        {/* HERO SECTION WITH FLOATING CYBER ELEMENTS */}
        <section id="scanner" className="relative px-4 sm:px-6 lg:px-8 pt-8 sm:pt-14 pb-16 max-w-7xl mx-auto w-full">
          
          {/* Floating Security Badges (CyberSafe Behance signature design) */}
          <div className="hidden xl:block absolute left-4 top-24 pointer-events-none">
            <motion.div
              initial={{ opacity: 0, x: -40 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.8, delay: 0.2 }}
              className="animate-cyber-float liquid-glass rounded-2xl p-4 border border-red-500/30 shadow-[0_15px_35px_rgba(239,68,68,0.25)] max-w-xs"
            >
              <div className="flex items-center gap-2 mb-2">
                <span className="w-2.5 h-2.5 rounded-full bg-red-500 animate-pulse" />
                <span className="text-[11px] font-mono font-bold text-red-400 uppercase tracking-wide">
                  Live Threat Intercepted
                </span>
              </div>
              <p className="font-mono text-xs text-slate-200 truncate">chase-online.bank-auth.xyz</p>
              <div className="mt-2 flex items-center justify-between text-[10px] font-mono text-slate-400 border-t border-white/5 pt-2">
                <span>Homograph Spoof</span>
                <span className="text-red-400 font-bold">RISK 98/100</span>
              </div>
            </motion.div>
          </div>

          <div className="hidden xl:block absolute right-4 top-28 pointer-events-none">
            <motion.div
              initial={{ opacity: 0, x: 40 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.8, delay: 0.3 }}
              className="animate-cyber-float liquid-glass rounded-2xl p-4 border border-emerald-500/30 shadow-[0_15px_35px_rgba(16,185,129,0.25)] max-w-xs"
              style={{ animationDelay: "2.5s" }}
            >
              <div className="flex items-center gap-2 mb-2">
                <div className="w-5 h-5 rounded-full bg-emerald-500/20 flex items-center justify-center text-emerald-400">
                  <Lock className="w-3 h-3" />
                </div>
                <span className="text-[11px] font-mono font-bold text-emerald-400 uppercase tracking-wide">
                  X.509 Cryptography
                </span>
              </div>
              <p className="font-mono text-xs text-slate-200">DigiCert High Assurance EV</p>
              <div className="mt-2 flex items-center justify-between text-[10px] font-mono text-slate-400 border-t border-white/5 pt-2">
                <span>Chain Verified</span>
                <span className="text-emerald-400 font-bold">GRADE A+</span>
              </div>
            </motion.div>
          </div>

          {/* Central Hero Headline & Description */}
          <div className="flex flex-col items-center text-center max-w-4xl mx-auto">
            {/* Top Security Status Pill */}
            <motion.div
              initial={{ opacity: 0, y: -20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6 }}
              className="inline-flex items-center gap-2.5 px-4 py-2 rounded-full liquid-glass border border-cyan-500/30 text-cyan-300 text-xs font-medium mb-6 shadow-[0_0_25px_rgba(6,182,212,0.2)]"
            >
              <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
              <span className="font-mono tracking-wider uppercase font-semibold text-[11px]">
                Autonomous Zero-Trust Web Shield
              </span>
              <span className="text-slate-600">|</span>
              <span className="text-slate-400 font-mono text-[11px]">Next-Gen URL Defense</span>
            </motion.div>

            {/* Hero Main Punch Headline */}
            <motion.h1
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.7, delay: 0.1 }}
              className="text-4xl sm:text-6xl lg:text-7xl font-black tracking-tight text-white leading-[1.08] mb-6"
            >
              Check Before You Trust.{" "}
              <span className="block mt-2 bg-gradient-to-r from-cyan-400 via-teal-300 to-blue-500 bg-clip-text text-transparent drop-shadow-[0_0_40px_rgba(6,182,212,0.45)]">
                Neutralize Phishing Links.
              </span>
            </motion.h1>

            {/* Subheading */}
            <motion.p
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.7, delay: 0.2 }}
              className="text-base sm:text-lg md:text-xl text-slate-300 max-w-2xl mx-auto leading-relaxed mb-10"
            >
              Real-time heuristic threat telemetry inspecting lookalike homographs, weaponized redirects,
              short-lived SSL certificates, and obfuscated credential harvesters.
            </motion.p>

            {/* CYBERSAFE TERMINAL SCANNER BOX */}
            <motion.div
              initial={{ opacity: 0, scale: 0.96 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.7, delay: 0.3 }}
              className="w-full max-w-3xl mx-auto mb-8"
            >
              <div className="liquid-glass-glow rounded-3xl p-3.5 sm:p-5 shadow-[0_25px_60px_rgba(0,0,0,0.7)] border border-cyan-500/30 transition-all relative overflow-hidden">
                {/* Cyber Scanline Overlay */}
                <div className="absolute inset-0 pointer-events-none opacity-20 bg-[linear-gradient(rgba(18,16,16,0)_50%,rgba(0,0,0,0.25)_50%)] bg-[length:100%_4px]" />

                {/* Terminal Header */}
                <div className="flex items-center justify-between px-3 pb-3 border-b border-white/10 mb-3 text-xs text-slate-400 font-mono">
                  <div className="flex items-center gap-2">
                    <div className="flex gap-1.5">
                      <div className="w-2.5 h-2.5 rounded-full bg-red-500/90" />
                      <div className="w-2.5 h-2.5 rounded-full bg-amber-500/90" />
                      <div className="w-2.5 h-2.5 rounded-full bg-emerald-500/90" />
                    </div>
                    <span className="text-slate-400 font-semibold tracking-wide ml-2 hidden sm:inline">
                      SEC-CORE // DEEP_URL_INSPECTOR
                    </span>
                  </div>
                  <div className="flex items-center gap-2 text-cyan-400 text-[11px]">
                    <Activity className="w-3.5 h-3.5 animate-spin" style={{ animationDuration: "5s" }} />
                    <span>EDGE RADAR READY</span>
                  </div>
                </div>

                {/* Scan Input & Action Button */}
                <form onSubmit={handleScanSubmit} className="flex flex-col sm:flex-row gap-3 relative z-10">
                  <div className="relative flex-1 group">
                    <div className="absolute left-4 top-1/2 -translate-y-1/2 text-cyan-400/80 group-focus-within:text-cyan-300 transition-colors">
                      <Terminal className="w-4 h-4" />
                    </div>
                    <input
                      type="url"
                      placeholder="Enter target URL to inspect (e.g. https://suspect-auth.top)..."
                      value={url}
                      onChange={(e) => setUrl(e.target.value)}
                      className="w-full bg-[#070d1b]/95 text-slate-100 placeholder-slate-500 text-sm rounded-2xl pl-11 pr-4 py-4 border border-cyan-500/25 focus:border-cyan-400 focus:outline-none focus:ring-2 focus:ring-cyan-500/40 transition-all font-mono shadow-inner"
                      required
                    />
                  </div>

                  <Button
                    type="submit"
                    size="lg"
                    className="bg-gradient-to-r from-cyan-500 via-blue-600 to-indigo-600 hover:from-cyan-400 hover:via-blue-500 hover:to-indigo-500 text-white font-extrabold text-sm px-8 py-4 rounded-2xl shadow-[0_0_30px_rgba(6,182,212,0.5)] hover:shadow-[0_0_40px_rgba(6,182,212,0.8)] transition-all flex items-center justify-center gap-2 group cursor-pointer"
                  >
                    <span>Inspect Target</span>
                    <ArrowRight className="w-4 h-4 group-hover:translate-x-1.5 transition-transform" />
                  </Button>
                </form>

                {/* Sample Attack Payloads for Instant 1-Click Verification */}
                <div className="pt-4 mt-3 border-t border-white/5 flex flex-wrap items-center justify-between gap-2 px-1 text-xs relative z-10">
                  <span className="text-slate-400 font-mono text-[11px] flex items-center gap-1.5">
                    <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Quick attack samples:</span>
                  </span>
                  <div className="flex flex-wrap gap-1.5">
                    {SAMPLE_TARGETS.map((sample, idx) => (
                      <button
                        key={idx}
                        type="button"
                        onClick={() => handleCopyTarget(sample.url)}
                        className={`text-[11px] font-mono px-3 py-1 rounded-xl border transition-all cursor-pointer flex items-center gap-1.5 ${
                          sample.type === "threat"
                            ? "bg-red-500/10 text-red-300 border-red-500/25 hover:bg-red-500/20 hover:border-red-500/50"
                            : "bg-emerald-500/10 text-emerald-300 border-emerald-500/25 hover:bg-emerald-500/20 hover:border-emerald-500/50"
                        }`}
                        title={sample.url}
                      >
                        <span>{sample.label}</span>
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            </motion.div>

            {/* Scroll-down cue button */}
            <motion.button
              onClick={() => scrollToSection("live-ticker")}
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.8 }}
              className="mt-2 text-slate-400 hover:text-cyan-300 text-xs font-mono flex flex-col items-center gap-1.5 transition-colors cursor-pointer group"
            >
              <span>Explore Live Telemetry</span>
              <ChevronDown className="w-4 h-4 animate-bounce text-cyan-400" />
            </motion.button>
          </div>
        </section>

        {/* INFINITE REAL-TIME THREAT MARQUEE TICKER (Scrolling Effect) */}
        <div id="live-ticker" className="w-full border-y border-white/10 bg-[#090e1c]/80 backdrop-blur-md py-3.5 overflow-hidden relative">
          <div className="flex items-center gap-3 absolute left-4 z-20 bg-[#090e1c]/90 px-3 py-1 rounded-lg border border-cyan-500/30 text-cyan-400 font-mono text-xs font-bold shadow-lg">
            <Radio className="w-3.5 h-3.5 text-red-400 animate-pulse" />
            <span className="hidden sm:inline">LIVE THREAT FEED:</span>
          </div>

          <div className="animate-marquee flex items-center gap-8 pl-44 sm:pl-48">
            {[...LIVE_THREAT_FEED, ...LIVE_THREAT_FEED].map((item, idx) => (
              <div
                key={idx}
                className="flex items-center gap-3 text-xs font-mono px-4 py-1.5 rounded-full bg-white/[0.03] border border-white/5 hover:border-cyan-500/30 transition-all shrink-0 cursor-default"
              >
                <span className="w-2 h-2 rounded-full bg-red-400 animate-ping" />
                <span className="text-slate-200 font-semibold">{item.domain}</span>
                <span className="text-slate-500">|</span>
                <span className="text-red-400">{item.threat}</span>
                <span className="text-xs bg-red-500/15 text-red-300 px-2 py-0.5 rounded font-bold border border-red-500/20">
                  RISK {item.risk}
                </span>
                <span className="text-[10px] text-slate-500">{item.time}</span>
              </div>
            ))}
          </div>
        </div>

        {/* TELEMETRY METRIC STRIP (Counter / Glass Bar) */}
        <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12 w-full">
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: "-50px" }}
            transition={{ duration: 0.6 }}
            className="grid grid-cols-2 lg:grid-cols-4 gap-4"
          >
            {TELEMETRY_STATS.map((stat, i) => (
              <div
                key={i}
                className="liquid-glass rounded-2xl p-5 text-center border border-white/10 hover:border-cyan-500/40 transition-all group relative overflow-hidden"
              >
                <div className="absolute -top-10 -right-10 w-24 h-24 bg-cyan-500/10 rounded-full blur-xl group-hover:scale-150 transition-transform" />
                <div className="text-2xl sm:text-3xl font-black font-mono text-cyan-300 group-hover:text-cyan-200 transition-colors">
                  {stat.value}
                </div>
                <div className="text-xs sm:text-sm font-semibold text-slate-200 mt-1">{stat.label}</div>
                <div className="text-[10px] text-slate-400 font-mono mt-0.5">{stat.detail}</div>
              </div>
            ))}
          </motion.div>
        </section>

        {/* INTERACTIVE THREAT COMMAND CONSOLE SHOWCASE */}
        <section id="console-demo" className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12 w-full">
          <div className="text-center mb-10">
            <div className="inline-flex items-center gap-2 text-xs font-mono font-semibold uppercase text-cyan-400 tracking-widest px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/20 mb-3">
              <Terminal className="w-3.5 h-3.5" /> Interactive Demonstration
            </div>
            <h2 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
              Live Threat Command Console
            </h2>
            <p className="text-sm text-slate-400 max-w-2xl mx-auto mt-2">
              Explore how TrustShield deconstructs attacker payloads layer-by-layer before any browser renders the page.
            </p>
          </div>

          <motion.div
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: "-50px" }}
            transition={{ duration: 0.6 }}
            className="liquid-glass rounded-3xl border border-white/10 shadow-[0_20px_50px_rgba(0,0,0,0.6)] overflow-hidden"
          >
            {/* Top Navigation Tabs */}
            <div className="flex flex-wrap items-center justify-between border-b border-white/10 p-3 sm:p-4 bg-black/30 gap-2">
              <div className="flex items-center gap-1.5 sm:gap-2">
                {[
                  { id: "homograph", label: "Homograph Inspector", icon: Eye },
                  { id: "ssl", label: "SSL Certificate Chain", icon: Lock },
                  { id: "redirects", label: "Redirect Trace", icon: Layers },
                  { id: "headers", label: "Security Headers", icon: Cpu },
                ].map((tab) => {
                  const Icon = tab.icon;
                  const isActive = activeConsoleTab === tab.id;
                  return (
                    <button
                      key={tab.id}
                      onClick={() => setActiveConsoleTab(tab.id)}
                      className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-mono font-semibold transition-all cursor-pointer ${
                        isActive
                          ? "bg-gradient-to-r from-cyan-500/20 to-blue-500/20 text-cyan-300 border border-cyan-500/40 shadow-[0_0_15px_rgba(6,182,212,0.3)]"
                          : "text-slate-400 hover:text-slate-200 hover:bg-white/5 border border-transparent"
                      }`}
                    >
                      <Icon className="w-3.5 h-3.5" />
                      <span>{tab.label}</span>
                    </button>
                  );
                })}
              </div>

              <div className="flex items-center gap-2 text-[11px] font-mono text-emerald-400">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                <span>CONSENSUS VERDICT: HIGH RISK</span>
              </div>
            </div>

            {/* Tab Content Display Area */}
            <div className="p-5 sm:p-8">
              <AnimatePresence mode="wait">
                {activeConsoleTab === "homograph" && (
                  <motion.div
                    key="homograph"
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -10 }}
                    transition={{ duration: 0.3 }}
                    className="grid grid-cols-1 lg:grid-cols-2 gap-6"
                  >
                    <div>
                      <div className="flex items-center justify-between mb-3">
                        <span className="text-xs font-mono text-red-400 uppercase font-bold flex items-center gap-2">
                          <AlertTriangle className="w-4 h-4" /> Punycode & Homoglyph Deception
                        </span>
                        <span className="text-xs font-mono bg-red-500/20 text-red-300 px-2.5 py-0.5 rounded border border-red-500/30">
                          98% MATCH TO BRAND
                        </span>
                      </div>

                      <div className="p-4 rounded-2xl bg-black/50 border border-white/10 font-mono text-xs space-y-2 mb-4">
                        <div className="text-slate-400">Target Hostname:</div>
                        <div className="text-sm font-bold text-red-300 break-all">
                          https://<span className="bg-red-500/30 text-amber-200 px-1 rounded">pаypal</span>.verify-account.top/signin
                        </div>
                        <div className="text-[11px] text-slate-500 pt-2 border-t border-white/5">
                          Unicode Deconstruction: Character <code className="text-amber-300 font-bold bg-white/10 px-1 py-0.5 rounded">'а'</code> is Cyrillic Small Letter A (U+0430), NOT Latin 'a' (U+0061).
                        </div>
                      </div>

                      <div className="space-y-2 text-xs text-slate-300">
                        <div className="flex items-center gap-2 p-2.5 rounded-xl bg-white/[0.02] border border-white/5">
                          <CheckCircle2 className="w-4 h-4 text-cyan-400" />
                          <span>Brand Impersonation Target: <strong>PayPal Inc.</strong></span>
                        </div>
                        <div className="flex items-center gap-2 p-2.5 rounded-xl bg-white/[0.02] border border-white/5">
                          <CheckCircle2 className="w-4 h-4 text-cyan-400" />
                          <span>Domain Registration Age: <strong>3 days ago (Ephemeral)</strong></span>
                        </div>
                        <div className="flex items-center gap-2 p-2.5 rounded-xl bg-white/[0.02] border border-white/5">
                          <CheckCircle2 className="w-4 h-4 text-cyan-400" />
                          <span>Punycode Translation: <code>xn--pypal-43a.verify-account.top</code></span>
                        </div>
                      </div>
                    </div>

                    <div className="rounded-2xl p-5 bg-gradient-to-br from-red-950/30 to-black/60 border border-red-500/30 flex flex-col justify-between">
                      <div>
                        <div className="flex items-center justify-between mb-4">
                          <span className="text-xs font-mono text-slate-300 font-bold">Neural Confidence Gauge</span>
                          <span className="text-xl font-mono font-black text-red-400">96 / 100</span>
                        </div>
                        {/* Gauge bar */}
                        <div className="w-full h-3 rounded-full bg-slate-800 overflow-hidden mb-4">
                          <div className="h-full bg-gradient-to-r from-amber-500 to-red-500 rounded-full w-[96%]" />
                        </div>
                        <p className="text-xs text-slate-300 leading-relaxed">
                          This domain has been flagged as a hostile homoglyph clone designed to steal user credentials.
                          TrustShield automatically alerts connected SOC nodes and adds this pattern to the decentralized threat matrix.
                        </p>
                      </div>

                      <div className="pt-4 border-t border-red-500/20 mt-4 flex items-center justify-between text-xs font-mono">
                        <span className="text-slate-400">Automated Action:</span>
                        <span className="text-red-400 font-bold uppercase tracking-wider">Zero-Trust Block Enforced</span>
                      </div>
                    </div>
                  </motion.div>
                )}

                {activeConsoleTab === "ssl" && (
                  <motion.div
                    key="ssl"
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -10 }}
                    transition={{ duration: 0.3 }}
                    className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-xs"
                  >
                    <div className="p-4 rounded-2xl bg-black/40 border border-white/10">
                      <div className="text-slate-500 text-[10px] mb-1">CERTIFICATE AUTHORITY</div>
                      <div className="text-sm font-bold text-slate-100">Let's Encrypt (R3)</div>
                      <div className="text-amber-400 text-[11px] mt-1">Domain Validated (DV) only</div>
                      <div className="text-[10px] text-slate-400 mt-3 pt-2 border-t border-white/5">
                        Free automated certificate commonly abused for lookalike sites.
                      </div>
                    </div>

                    <div className="p-4 rounded-2xl bg-black/40 border border-red-500/30">
                      <div className="text-red-400 text-[10px] mb-1">LIFESPAN & EXPIRATION</div>
                      <div className="text-sm font-bold text-red-300">Issued 4 hours ago</div>
                      <div className="text-slate-400 text-[11px] mt-1">Validity: 90 days</div>
                      <div className="text-[10px] text-red-400 mt-3 pt-2 border-t border-red-500/20">
                        High risk signal: Over 78% of phishing vectors use certs &lt;24h old.
                      </div>
                    </div>

                    <div className="p-4 rounded-2xl bg-black/40 border border-white/10">
                      <div className="text-slate-500 text-[10px] mb-1">SAN WILDCARD MATCH</div>
                      <div className="text-sm font-bold text-slate-100">Mismatch Detected</div>
                      <div className="text-cyan-400 text-[11px] mt-1">SNI doesn't match official org</div>
                      <div className="text-[10px] text-slate-400 mt-3 pt-2 border-t border-white/5">
                        Authentic bank cert is issued by DigiCert with Extended Validation.
                      </div>
                    </div>
                  </motion.div>
                )}

                {activeConsoleTab === "redirects" && (
                  <motion.div
                    key="redirects"
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -10 }}
                    transition={{ duration: 0.3 }}
                    className="space-y-3"
                  >
                    {[
                      { hop: 1, url: "https://bit.ly/3xSecAuth", code: 301, type: "Shortener Gateway", safe: true },
                      { hop: 2, url: "https://t.co/redirect-filter-pass", code: 302, type: "WAF Bypasser Hop", safe: false },
                      { hop: 3, url: "https://secure-chase-update.bank-verify.xyz/login", code: 200, type: "Hostile Credential Harvester", safe: false },
                    ].map((step, idx) => (
                      <div
                        key={idx}
                        className="flex flex-col sm:flex-row items-start sm:items-center justify-between p-3.5 rounded-2xl bg-black/40 border border-white/5 font-mono text-xs gap-2"
                      >
                        <div className="flex items-center gap-3">
                          <span className="w-6 h-6 rounded-lg bg-white/5 border border-white/10 flex items-center justify-center font-bold text-cyan-400">
                            {step.hop}
                          </span>
                          <span className="text-slate-200 font-semibold">{step.url}</span>
                        </div>
                        <div className="flex items-center gap-3">
                          <span className="text-[11px] text-slate-400">{step.type}</span>
                          <span
                            className={`px-2 py-0.5 rounded text-[11px] font-bold border ${
                              step.code === 200
                                ? "bg-red-500/20 text-red-300 border-red-500/30"
                                : "bg-cyan-500/20 text-cyan-300 border-cyan-500/30"
                            }`}
                          >
                            HTTP {step.code}
                          </span>
                        </div>
                      </div>
                    ))}
                  </motion.div>
                )}

                {activeConsoleTab === "headers" && (
                  <motion.div
                    key="headers"
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -10 }}
                    transition={{ duration: 0.3 }}
                    className="grid grid-cols-1 sm:grid-cols-2 gap-3 font-mono text-xs"
                  >
                    {[
                      { name: "Content-Security-Policy", status: "MISSING", detail: "Allows inline scripts & rogue credential posting", danger: true },
                      { name: "Strict-Transport-Security (HSTS)", status: "ABSENT", detail: "Leaves users open to SSL stripping attacks", danger: true },
                      { name: "X-Frame-Options", status: "NOT CONFIGURED", detail: "Vulnerable to iframe clickjacking exploits", danger: true },
                      { name: "X-Content-Type-Options", status: "nosniff (Present)", detail: "MIME sniffing disabled", danger: false },
                    ].map((hdr, idx) => (
                      <div
                        key={idx}
                        className={`p-3.5 rounded-2xl border ${
                          hdr.danger ? "bg-red-950/20 border-red-500/30" : "bg-emerald-950/20 border-emerald-500/30"
                        }`}
                      >
                        <div className="flex items-center justify-between mb-1">
                          <span className="font-bold text-slate-200">{hdr.name}</span>
                          <span
                            className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                              hdr.danger ? "bg-red-500/20 text-red-300" : "bg-emerald-500/20 text-emerald-300"
                            }`}
                          >
                            {hdr.status}
                          </span>
                        </div>
                        <div className="text-[11px] text-slate-400">{hdr.detail}</div>
                      </div>
                    ))}
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          </motion.div>
        </section>

        {/* BENTO GRID: 4 CORE DEFENSE CAPABILITY CARDS */}
        <section id="features" className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16 w-full">
          <div className="text-center mb-12">
            <div className="inline-flex items-center gap-2 text-xs font-mono font-semibold uppercase text-cyan-400 tracking-widest px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/20 mb-3">
              Multi-Layered Security Fabric
            </div>
            <h2 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
              Comprehensive Threat Detection Architecture
            </h2>
            <p className="text-sm text-slate-400 max-w-xl mx-auto mt-2">
              Beyond simple URL blocklists. TrustShield actively evaluates domain telemetry, certificates,
              HTTP responses, and form handlers in a unified pipeline.
            </p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
            {CAPABILITIES.map((cap, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0, y: 30 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, margin: "-50px" }}
                transition={{ duration: 0.5, delay: i * 0.1 }}
                className={`liquid-glass-interactive rounded-3xl p-6 sm:p-8 flex flex-col justify-between group relative overflow-hidden ${cap.colSpan}`}
              >
                {/* Background ambient gradient glow on hover */}
                <div
                  className={`absolute -right-16 -top-16 w-44 h-44 rounded-full bg-gradient-to-br ${cap.accentGlow} blur-3xl group-hover:scale-150 transition-transform duration-700 pointer-events-none`}
                />

                <div>
                  <div className="flex items-center justify-between mb-5">
                    <div
                      className={`w-14 h-14 rounded-2xl border flex items-center justify-center ${cap.iconColor} shadow-lg transition-transform group-hover:scale-110 duration-300`}
                    >
                      <cap.icon className="w-7 h-7" />
                    </div>
                    <span className={`text-[11px] font-mono font-bold px-3 py-1 rounded-full border ${cap.tagColor}`}>
                      {cap.tag}
                    </span>
                  </div>

                  <h3 className="text-xl font-bold text-slate-100 group-hover:text-cyan-300 transition-colors mb-2.5">
                    {cap.title}
                  </h3>
                  <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
                    {cap.desc}
                  </p>
                </div>

                <div className="pt-5 mt-6 border-t border-white/10 flex items-center justify-between text-xs font-mono text-slate-400">
                  <span className="text-[11px] text-slate-500">OPERATIONAL STANDARD</span>
                  <span className="text-cyan-400 font-bold">{cap.metric}</span>
                </div>
              </motion.div>
            ))}
          </div>
        </section>

        {/* ANATOMY OF A THREAT - LIVE COMPARISON CARD */}
        <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12 w-full">
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: "-50px" }}
            transition={{ duration: 0.6 }}
            className="liquid-glass rounded-3xl p-6 sm:p-10 border border-white/10 shadow-[0_20px_50px_rgba(0,0,0,0.5)]"
          >
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8 pb-6 border-b border-white/10">
              <div>
                <span className="text-xs font-mono text-cyan-400 uppercase tracking-widest font-semibold flex items-center gap-1.5">
                  <Eye className="w-3.5 h-3.5" /> Threat Anatomy Breakdown
                </span>
                <h3 className="text-2xl sm:text-3xl font-extrabold text-white mt-1">
                  Why A Standard "Padlock" Is No Longer Enough
                </h3>
              </div>
              <p className="text-xs sm:text-sm text-slate-400 max-w-md">
                Over 82% of active phishing websites now display a valid HTTPS padlock. TrustShield uncovers
                the hidden deception signals normal browsers ignore.
              </p>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Spoofed Attack Vector Card */}
              <div className="rounded-2xl p-6 border border-red-500/30 bg-red-950/20 backdrop-blur-xl relative overflow-hidden group">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-2">
                    <div className="w-2.5 h-2.5 rounded-full bg-red-500 animate-pulse" />
                    <span className="text-xs font-mono font-bold text-red-400 uppercase tracking-wide">
                      Hostile Phishing Vector
                    </span>
                  </div>
                  <span className="text-xs font-mono bg-red-500/20 text-red-300 px-2.5 py-1 rounded-lg border border-red-500/30 font-bold">
                    RISK 92 / 100
                  </span>
                </div>

                <div className="p-3.5 rounded-xl bg-black/50 border border-red-500/20 font-mono text-xs text-red-200 mb-5 break-all">
                  https://<span className="text-amber-300 font-bold underline">secure-login.paypa1</span>-verify.<span className="text-red-400 font-bold">top</span>/auth
                </div>

                <ul className="space-y-3 text-xs text-slate-300">
                  <li className="flex items-start gap-2.5">
                    <span className="text-red-400 mt-0.5 font-bold">✕</span>
                    <span><strong>Homograph spoof:</strong> Substitutes numeral <code className="text-amber-300 bg-white/5 px-1 rounded">'1'</code> for letter <code className="text-cyan-300 bg-white/5 px-1 rounded">'l'</code> in brand name.</span>
                  </li>
                  <li className="flex items-start gap-2.5">
                    <span className="text-red-400 mt-0.5 font-bold">✕</span>
                    <span><strong>Disposable cert:</strong> Free certificate issued 4 hours ago via Let's Encrypt abuse.</span>
                  </li>
                  <li className="flex items-start gap-2.5">
                    <span className="text-red-400 mt-0.5 font-bold">✕</span>
                    <span><strong>Credential harvest:</strong> Unobfuscated POST form sends password + OTP to Russian VPS endpoint.</span>
                  </li>
                </ul>
              </div>

              {/* Verified Domain Card */}
              <div className="rounded-2xl p-6 border border-emerald-500/30 bg-emerald-950/20 backdrop-blur-xl relative overflow-hidden group">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-2">
                    <div className="w-2.5 h-2.5 rounded-full bg-emerald-400" />
                    <span className="text-xs font-mono font-bold text-emerald-400 uppercase tracking-wide">
                      Verified Canonical Target
                    </span>
                  </div>
                  <span className="text-xs font-mono bg-emerald-500/20 text-emerald-300 px-2.5 py-1 rounded-lg border border-emerald-500/30 font-bold">
                    RISK 04 / 100
                  </span>
                </div>

                <div className="p-3.5 rounded-xl bg-black/50 border border-emerald-500/20 font-mono text-xs text-emerald-200 mb-5 break-all">
                  https://www.paypal.com/signin
                </div>

                <ul className="space-y-3 text-xs text-slate-300">
                  <li className="flex items-start gap-2.5">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
                    <span><strong>Verified identity:</strong> PayPal, Inc. DigiCert High Assurance EV Root CA chain.</span>
                  </li>
                  <li className="flex items-start gap-2.5">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
                    <span><strong>HSTS preload:</strong> Strict Transport Security enforced with max-age 31536000.</span>
                  </li>
                  <li className="flex items-start gap-2.5">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
                    <span><strong>Hardened CSP:</strong> Strict Content-Security-Policy prohibits untrusted third-party scripts.</span>
                  </li>
                </ul>
              </div>
            </div>
          </motion.div>
        </section>

        {/* 4-STAGE PIPELINE ARCHITECTURE (Timeline with Scroll Glow) */}
        <section id="workflow" className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16 w-full">
          <div className="text-center mb-12">
            <span className="text-xs font-mono text-cyan-400 uppercase tracking-widest font-semibold">
              Execution Architecture
            </span>
            <h2 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight mt-1">
              Autonomous 4-Stage Inspection Pipeline
            </h2>
            <p className="text-sm text-slate-400 max-w-xl mx-auto mt-2">
              How TrustShield evaluates any URL from raw submission to actionable verdict in under 30 milliseconds.
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 relative">
            {WORKFLOW_STEPS.map((p, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0, y: 30 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, margin: "-50px" }}
                transition={{ duration: 0.5, delay: i * 0.1 }}
                className="liquid-glass rounded-3xl p-6 border border-white/10 relative group hover:border-cyan-500/40 transition-all flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between mb-4">
                    <div className="text-3xl font-black font-mono text-cyan-400/30 group-hover:text-cyan-400 transition-colors">
                      {p.step}
                    </div>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-300">
                      {p.badge}
                    </span>
                  </div>

                  <h4 className="text-base font-bold text-slate-100 mb-2 group-hover:text-cyan-300 transition-colors">
                    {p.title}
                  </h4>
                  <p className="text-xs text-slate-400 leading-relaxed">{p.desc}</p>
                </div>

                <div className="mt-6 pt-3 border-t border-white/5 flex items-center justify-end text-cyan-400/60 group-hover:text-cyan-400 transition-colors">
                  <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
                </div>
              </motion.div>
            ))}
          </div>
        </section>

        {/* COMMUNITY REPORT & DEFENSE NETWORK BANNER */}
        <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10 w-full">
          <motion.div
            initial={{ opacity: 0, scale: 0.98 }}
            whileInView={{ opacity: 1, scale: 1 }}
            viewport={{ once: true, margin: "-50px" }}
            transition={{ duration: 0.6 }}
            className="liquid-glass-glow rounded-3xl p-8 sm:p-12 text-center relative overflow-hidden border border-cyan-500/30 shadow-[0_20px_60px_rgba(6,182,212,0.15)]"
          >
            <div className="max-w-2xl mx-auto relative z-10">
              <span className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-full bg-cyan-500/10 border border-cyan-500/25 text-cyan-300 text-xs font-mono mb-4">
                <Users className="w-3.5 h-3.5" /> Global Incident Response Network
              </span>
              <h2 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight mb-4">
                Encountered a Phishing Link in SMS, Email, or Chat?
              </h2>
              <p className="text-sm sm:text-base text-slate-300 mb-8 leading-relaxed">
                Submit a confidential threat report. Your submission automatically alerts thousands of security
                teams and initiates automated sandbox testing across our global cloud network.
              </p>
              <div className="flex flex-col sm:flex-row items-center justify-center gap-3.5">
                <Button
                  onClick={() => navigate("/report")}
                  size="lg"
                  className="w-full sm:w-auto bg-gradient-to-r from-red-500 to-orange-500 hover:from-red-400 hover:to-orange-400 text-white font-bold text-sm px-8 py-4 rounded-2xl shadow-[0_0_30px_rgba(239,68,68,0.4)] cursor-pointer"
                >
                  <ShieldAlert className="w-4 h-4 mr-2" /> Report Malicious URL
                </Button>
                <Button
                  onClick={() => navigate("/community")}
                  variant="outline"
                  size="lg"
                  className="w-full sm:w-auto border-white/10 text-slate-200 hover:bg-white/5 font-semibold text-sm px-8 py-4 rounded-2xl cursor-pointer"
                >
                  Explore Community Intel Feed
                </Button>
              </div>
            </div>
          </motion.div>
        </section>

        {/* FREQUENTLY ASKED QUESTIONS (Accordion with Scrolling Support) */}
        <section className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-16 w-full">
          <div className="text-center mb-10">
            <span className="text-xs font-mono text-cyan-400 uppercase tracking-widest font-semibold">
              Security Answers
            </span>
            <h2 className="text-3xl font-extrabold text-white tracking-tight mt-1">
              Frequently Asked Questions
            </h2>
          </div>

          <div className="space-y-3">
            {FAQS.map((faq, idx) => {
              const isOpen = activeFaq === idx;
              return (
                <div
                  key={idx}
                  className="liquid-glass rounded-2xl border border-white/10 overflow-hidden transition-all"
                >
                  <button
                    onClick={() => setActiveFaq(isOpen ? null : idx)}
                    className="w-full p-5 text-left flex items-center justify-between gap-4 cursor-pointer hover:bg-white/[0.02] transition-colors"
                  >
                    <span className="text-sm font-bold text-slate-200">{faq.q}</span>
                    {isOpen ? (
                      <ChevronUp className="w-4 h-4 text-cyan-400 shrink-0" />
                    ) : (
                      <ChevronDown className="w-4 h-4 text-slate-400 shrink-0" />
                    )}
                  </button>

                  <AnimatePresence>
                    {isOpen && (
                      <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: "auto", opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        transition={{ duration: 0.3 }}
                        className="px-5 pb-5 text-xs text-slate-300 leading-relaxed border-t border-white/5 pt-3"
                      >
                        {faq.a}
                      </motion.div>
                    )}
                  </AnimatePresence>
                </div>
              );
            })}
          </div>
        </section>
      </main>

      {/* Floating Back to Top Button */}
      {scrolled && (
        <motion.button
          onClick={scrollToTop}
          initial={{ opacity: 0, scale: 0.8 }}
          animate={{ opacity: 1, scale: 1 }}
          exit={{ opacity: 0, scale: 0.8 }}
          className="fixed bottom-6 right-6 z-40 w-11 h-11 rounded-full liquid-glass border border-cyan-500/40 text-cyan-400 flex items-center justify-center shadow-[0_0_20px_rgba(6,182,212,0.4)] hover:shadow-[0_0_30px_rgba(6,182,212,0.7)] transition-all cursor-pointer group"
          title="Scroll to top"
        >
          <ArrowUp className="w-4 h-4 group-hover:-translate-y-0.5 transition-transform" />
        </motion.button>
      )}

      {/* CyberSafe Footer with Live System Status */}
      <footer className="relative z-10 border-t border-white/10 bg-[#04070f]/90 backdrop-blur-2xl py-12 px-4 sm:px-6 lg:px-8 mt-auto">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-8 text-xs text-slate-400">
          <div className="flex items-center gap-3.5">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-cyan-400 to-blue-600 flex items-center justify-center text-navy-950 font-bold shadow-[0_0_20px_rgba(6,182,212,0.4)]">
              <ShieldCheck className="w-5 h-5 text-[#04070f]" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-slate-100 text-sm">TrustShield</span>
                <span className="text-[10px] text-cyan-400 font-mono px-2 py-0.5 rounded-full bg-cyan-500/10 border border-cyan-500/20">
                  SecOps Matrix
                </span>
              </div>
              <p className="text-[11px] text-slate-400 mt-0.5">
                Autonomous Zero-Trust Web & Phishing Defense Platform
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center justify-center gap-6 text-slate-300 font-medium">
            <Link to="/dashboard" className="hover:text-cyan-300 transition-colors">Dashboard</Link>
            <Link to="/scan" className="hover:text-cyan-300 transition-colors">Scanner</Link>
            <Link to="/community" className="hover:text-cyan-300 transition-colors">Community Intel</Link>
            <Link to="/watchlist" className="hover:text-cyan-300 transition-colors">Watchlist</Link>
            <Link to="/report" className="hover:text-cyan-300 transition-colors">Report Threat</Link>
          </div>

          <div className="flex flex-col items-center md:items-end gap-1.5 text-slate-400 font-mono text-[11px]">
            <div className="flex items-center gap-2 text-emerald-400">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span>ALL SECURITY CLUSTERS OPERATIONAL</span>
            </div>
            <span className="text-slate-500">Edge latency: 14ms · 99.99% Network Uptime</span>
          </div>
        </div>
      </footer>
    </div>
  );
}