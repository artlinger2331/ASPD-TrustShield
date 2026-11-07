import { useState } from "react";
import { ShieldAlert, Globe, Lock, Server, Database, AlertTriangle, Eye, Layers } from "lucide-react";
import { cn } from "@/utils/cn";

export function ThreatIntelGraph({ scanData, className }) {
  const [selectedNode, setSelectedNode] = useState(null);
  const [filter, setFilter] = useState("all");

  const domain = scanData?.url || "secure-sbi-login.verify-account.top";
  const isDangerous = (scanData?.score || 0) >= 70;

  // Nodes definition
  const nodes = [
    {
      id: "root",
      label: domain,
      type: "target",
      category: "target",
      x: 350,
      y: 200,
      color: isDangerous ? "#ef4444" : "#10b981",
      icon: Globe,
      details: `Target URL: ${domain}\nVerdict: ${scanData?.verdict || "dangerous"}\nRisk Score: ${scanData?.score || 87}/100`,
    },
    // Infrastructure
    {
      id: "dns_a",
      label: "185.220.101.42",
      type: "ip",
      category: "infra",
      x: 180,
      y: 110,
      color: "#38bdf8",
      icon: Server,
      details: "A Record: 185.220.101.42\nASN: AS203456 (Bulletproof Hosting)\nCountry: Seychelles",
    },
    {
      id: "dns_ns",
      label: "ns1.suspended-domain.net",
      type: "dns",
      category: "infra",
      x: 140,
      y: 200,
      color: "#38bdf8",
      icon: Server,
      details: "NameServer: ns1.suspended-domain.net\nReputation: Poor / Multiple Disclaimers",
    },
    {
      id: "tld_node",
      label: ".top TLD",
      type: "tld",
      category: "infra",
      x: 180,
      y: 290,
      color: "#f59e0b",
      icon: Database,
      details: "TLD: .top\nAbuse Rating: High (68% phishing prevalence in registrars)",
    },
    // PKI / SSL
    {
      id: "ca_leaf",
      label: "DV SSL (Let's Encrypt)",
      type: "cert",
      category: "pki",
      x: 350,
      y: 60,
      color: "#a855f7",
      icon: Lock,
      details: "Issuer: Let's Encrypt Authority R10\nDays to Expiry: 80 days\nStatus: Free Automated DV (Brand Mismatch)",
    },
    // Threat Feeds
    {
      id: "feed_urlhaus",
      label: "URLhaus: Malware Lure",
      type: "feed",
      category: "intel",
      x: 520,
      y: 110,
      color: "#ef4444",
      icon: ShieldAlert,
      details: "Source: abuse.ch URLhaus\nThreat: malware_download / credential_stealer\nStatus: Online",
    },
    {
      id: "feed_gsb",
      label: "Safe Browsing: Social Eng.",
      type: "feed",
      category: "intel",
      x: 560,
      y: 200,
      color: "#ef4444",
      icon: ShieldAlert,
      details: "Source: Google Safe Browsing\nThreatType: SOCIAL_ENGINEERING\nConfidence: 98%",
    },
    {
      id: "brand_target",
      label: "Impersonated: SBI Bank",
      type: "brand",
      category: "brand",
      x: 520,
      y: 290,
      color: "#f43f5e",
      icon: AlertTriangle,
      details: "Impersonation Victim: State Bank of India (sbi.co.in)\nTechnique: Combosquatting + Logo Spoofing",
    },
    // Vulnerability
    {
      id: "cred_form",
      label: "Credential Harvest Form",
      type: "vuln",
      category: "vuln",
      x: 350,
      y: 340,
      color: "#ef4444",
      icon: AlertTriangle,
      details: "Action: http://attacker-exfiltration.xyz/stealer.php\nInputs: Password, OTP, Debit Card PIN",
    },
  ];

  // Links connecting nodes
  const links = [
    { from: "root", to: "dns_a" },
    { from: "root", to: "dns_ns" },
    { from: "root", to: "tld_node" },
    { from: "root", to: "ca_leaf" },
    { from: "root", to: "feed_urlhaus" },
    { from: "root", to: "feed_gsb" },
    { from: "root", to: "brand_target" },
    { from: "root", to: "cred_form" },
  ];

  const filteredNodes = nodes.filter(
    (n) => filter === "all" || n.category === filter || n.id === "root"
  );

  return (
    <div className={cn("rounded-3xl glass border border-white/10 p-5 bg-slate-950/70", className)}>
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
        <div>
          <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
            <Layers className="w-4 h-4 text-cyan-400" />
            Interactive Threat Intelligence Graph
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Relational topology between domain infrastructure, certificates, threat feeds, and victim brands.
          </p>
        </div>
        <div className="flex gap-1.5 flex-wrap">
          {["all", "infra", "pki", "intel", "brand", "vuln"].map((cat) => (
            <button
              key={cat}
              onClick={() => setFilter(cat)}
              className={cn(
                "px-2.5 py-1 rounded-lg text-[10px] font-mono uppercase tracking-wider transition-colors",
                filter === cat
                  ? "bg-blue-600 text-white"
                  : "bg-white/5 text-slate-400 hover:text-slate-200"
              )}
            >
              {cat}
            </button>
          ))}
        </div>
      </div>

      <div className="relative border border-white/5 rounded-2xl bg-[#040812] overflow-hidden">
        <svg
          viewBox="0 0 700 400"
          className="w-full h-[360px] cursor-crosshair select-none"
        >
          <defs>
            <radialGradient id="target-glow" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor={isDangerous ? "#ef4444" : "#10b981"} stopOpacity="0.4" />
              <stop offset="100%" stopColor={isDangerous ? "#ef4444" : "#10b981"} stopOpacity="0" />
            </radialGradient>
            <filter id="glow">
              <feGaussianBlur stdDeviation="3" result="coloredBlur" />
              <feMerge>
                <feMergeNode in="coloredBlur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>

          {/* Lines */}
          {links.map((link, idx) => {
            const source = nodes.find((n) => n.id === link.from);
            const target = filteredNodes.find((n) => n.id === link.to);
            if (!source || !target) return null;

            return (
              <line
                key={idx}
                x1={source.x}
                y1={source.y}
                x2={target.x}
                y2={target.y}
                stroke={target.color}
                strokeWidth="1.5"
                strokeOpacity="0.4"
                strokeDasharray="4 3"
              />
            );
          })}

          {/* Central Target Pulsing Ring */}
          <circle
            cx="350"
            cy="200"
            r="46"
            fill="url(#target-glow)"
            className="animate-pulse"
          />

          {/* Nodes */}
          {filteredNodes.map((node) => {
            const isSelected = selectedNode?.id === node.id;
            const isCenter = node.id === "root";

            return (
              <g
                key={node.id}
                transform={`translate(${node.x}, ${node.y})`}
                onClick={() => setSelectedNode(node)}
                className="cursor-pointer transition-transform hover:scale-110"
              >
                <circle
                  r={isCenter ? 26 : 18}
                  fill="#0a0f1d"
                  stroke={node.color}
                  strokeWidth={isSelected ? 3 : 2}
                  filter={isSelected ? "url(#glow)" : undefined}
                />
                <circle
                  r={isCenter ? 20 : 13}
                  fill={node.color}
                  fillOpacity="0.25"
                />
                <text
                  textAnchor="middle"
                  dy={isCenter ? "38" : "30"}
                  fill="#e2e8f0"
                  fontSize={isCenter ? "11" : "9"}
                  fontWeight="600"
                  fontFamily="monospace"
                  className="pointer-events-none select-none"
                >
                  {node.label.length > 22 ? `${node.label.slice(0, 20)}…` : node.label}
                </text>
              </g>
            );
          })}
        </svg>

        {/* Selected Node Inspector Overlay */}
        {selectedNode && (
          <div className="absolute bottom-3 left-3 right-3 p-3.5 rounded-xl glass border border-white/10 bg-slate-900/90 backdrop-blur-md flex items-start justify-between gap-3 animate-in fade-in">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <span
                  className="w-2.5 h-2.5 rounded-full"
                  style={{ backgroundColor: selectedNode.color }}
                />
                <span className="text-xs font-bold text-slate-100 font-mono">
                  {selectedNode.label}
                </span>
                <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-white/5 text-slate-400">
                  {selectedNode.category}
                </span>
              </div>
              <p className="text-xs text-slate-300 font-mono whitespace-pre-wrap leading-relaxed">
                {selectedNode.details}
              </p>
            </div>
            <button
              onClick={() => setSelectedNode(null)}
              className="text-xs text-slate-400 hover:text-white px-2 py-1 rounded bg-white/5"
            >
              Close
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
