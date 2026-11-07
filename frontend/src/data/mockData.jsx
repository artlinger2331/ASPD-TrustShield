export const SCANNED_URL = "secure-sbi-login.verify-account.top";
export const FINAL_URL = "https://secure-sbi-login.verify-account.top/auth/login";

export const MOCK_SCAN_RESULT = {
  id: "scan_7f3a9c2e",
  url: SCANNED_URL,
  finalUrl: FINAL_URL,
  scannedAt: new Date(Date.now() - 2 * 60 * 1000).toISOString(),
  score: 87,
  verdict: "dangerous",
  verdictLabel: "Dangerous / Likely Phishing",
  confidence: "High",
  mainReason:
    "Domain mimics State Bank of India (SBI) banking brand; login form requests password and OTP; domain registered 4 days ago; missing critical security headers.",
  recommendedAction:
    "Do not enter any passwords, OTPs, or banking details on this website. Close the tab and report the link.",
};

export const MOCK_PHISHING_ANALYSIS = {
  domainSimilarity: {
    severity: "Critical",
    label: "Domain Similarity",
    detail:
      "The domain 'verify-account.top' uses a suspicious TLD and closely imitates 'sbi.co.in'. Levenshtein distance to sbi.co.in indicates intentional brand impersonation.",
  },
  suspiciousKeywords: {
    severity: "High",
    label: "Suspicious Keywords",
    detail:
      "Detected: 'secure', 'login', 'verify', 'account', 'sbi', 'banking', 'update', 'kyc'.",
  },
  brandImpersonation: {
    severity: "Critical",
    label: "Brand Impersonation",
    detail:
      "Visual and textual signals match State Bank of India (SBI) branding, including logo and color scheme.",
  },
  loginForm: {
    severity: "High",
    label: "Login Form Detection",
    detail:
      "A login form was detected requesting username and password over a non-EV certificate.",
  },
  credentialRequest: {
    severity: "Critical",
    label: "Credential / OTP / Card Request",
    detail:
      "Page requests password, OTP, and card details in a single form — a strong phishing indicator.",
  },
  redirectChain: {
    severity: "Medium",
    label: "Redirect Chain",
    detail:
      "secure-sbi-login.verify-account.top → https://verify-account.top/redirect → https://secure-sbi-login.verify-account.top/auth/login",
    hops: [
      { step: 1, url: "secure-sbi-login.verify-account.top", status: 302 },
      { step: 2, url: "https://verify-account.top/redirect", status: 301 },
      { step: 3, url: FINAL_URL, status: 200 },
    ],
  },
  newlyRegistered: {
    severity: "High",
    label: "Newly Registered Domain",
    detail:
      "Domain registered 4 days ago (2026-11-03). Phishing domains are often registered shortly before use.",
    registeredAt: "2026-11-03",
  },
  suspiciousTld: {
    severity: "Medium",
    label: "Suspicious TLD",
    detail:
      "The '.top' TLD is frequently abused for low-cost phishing and throwaway campaigns.",
  },
};

export const MOCK_CERT_ANALYSIS = {
  https: true,
  issuer: "R10 (Let's Encrypt)",
  validFrom: "2026-10-28",
  validTo: "2027-01-26",
  daysUntilExpiry: 80,
  chain: [
    { name: "ISRG Root X1", type: "Root CA", status: "trusted" },
    { name: "R10", type: "Intermediate CA", status: "trusted" },
    { name: "secure-sbi-login.verify-account.top", type: "Website Certificate", status: "valid" },
  ],
  revocation: "Not revoked (OCSP)",
  ctLog: "Logged in Certificate Transparency",
  caTrust: "Trusted",
  weakAlgo: false,
  warning:
    "Certificate is valid and issued by Let's Encrypt, but was issued only 4 days ago — consistent with a newly registered phishing domain. A valid certificate does NOT mean a site is safe.",
};

export const MOCK_SECURITY_HEADERS = [
  { name: "HTTPS Enforcement", status: "pass", detail: "Site loads over HTTPS." },
  { name: "HSTS", status: "fail", detail: "Strict-Transport-Security header is missing." },
  { name: "Content Security Policy", status: "fail", detail: "Content-Security-Policy header is missing." },
  { name: "X-Frame-Options", status: "fail", detail: "X-Frame-Options header is missing (clickjacking risk)." },
  { name: "X-Content-Type-Options", status: "fail", detail: "X-Content-Type-Options header is missing." },
  { name: "Referrer-Policy", status: "warning", detail: "Referrer-Policy header is not set." },
  { name: "Cookie Security Flags", status: "fail", detail: "Session cookies lack Secure/HttpOnly/SameSite flags." },
  { name: "Mixed Content", status: "pass", detail: "No mixed content detected." },
  { name: "Exposed Common Paths", status: "warning", detail: "/.env and /admin are accessible." },
  { name: "Server Version Disclosure", status: "fail", detail: "Server header reveals 'nginx/1.18.0'." },
];

export const MOCK_THREAT_INTEL = {
  feedMatches: [
    { source: "PhishTank", match: true, confidence: "High", detail: "Listed as confirmed phishing." },
    { source: "OpenPhish", match: true, confidence: "Medium", detail: "Suspicious URL pattern." },
    { source: "Google Safe Browsing", match: false, confidence: "High", detail: "Not listed." },
  ],
  domainAge: "4 days",
  dns: { a: "185.220.101.42", ns: "ns1.suspended-domain.net", mx: "None" },
  hosting: {
    provider: "Bulletproof Hosting (AS203456)",
    country: "Unknown",
    reputation: "Poor",
  },
  historicalReports: 3,
  communityReports: 7,
  sources: ["PhishTank", "OpenPhish", "URLhaus", "Community Reports"],
};

export const MOCK_EVIDENCE = {
  screenshot: "https://images.unsplash.com/photo-1550751827-4bd374c3f58b?q=80&w=1000&auto=format&fit=crop",
  pageTitle: "SBI Secure Login - Verify Your Account",
  forms: [
    { id: "loginForm", action: "/auth/submit", method: "POST", fields: ["username", "password", "otp", "cardNumber"] },
  ],
  externalScripts: [
    "https://cdn.jsdelivr.net/npm/jquery@3.6.0",
    "https://tracker.evil-domain.top/analytics.js",
  ],
  redirectPath: [
    "secure-sbi-login.verify-account.top",
    "verify-account.top/redirect",
    FINAL_URL,
  ],
};

export const DASHBOARD_STATS = {
  totalScans: 1247,
  highRisk: 89,
  reportsSubmitted: 34,
  certIssues: 12,
};

export const RECENT_SCANS = [
  { id: "1", url: "secure-sbi-login.verify-account.top", verdict: "dangerous", score: 87, date: "2m ago", threat: "Phishing" },
  { id: "2", url: "paypal-security-update.net", verdict: "suspicious", score: 54, date: "14m ago", threat: "Scam" },
  { id: "3", url: "microsoft365-renewal.com", verdict: "dangerous", score: 92, date: "1h ago", threat: "Credential Theft" },
  { id: "4", url: "github.com", verdict: "safe", score: 8, date: "2h ago", threat: "None" },
  { id: "5", url: "fake-recruitment-portal.org", verdict: "high-risk", score: 71, date: "4h ago", threat: "Fake Recruitment" },
];

export const COMMUNITY_REPORTS = [
  {
    id: "r1",
    url: "secure-sbi-login.verify-account.top",
    type: "Phishing",
    risk: "Critical",
    status: "Verified",
    description: "Received via SMS claiming my SBI account is blocked. Asks to login and enter OTP.",
    confirmations: 142,
    screenshot: "https://images.unsplash.com/photo-1550751827-4bd374c3f58b?q=80&w=400&auto=format&fit=crop",
    reporter: "Anonymous",
  },
  {
    id: "r2",
    url: "paypal-security-update.net",
    type: "Scam",
    risk: "High",
    status: "Pending",
    description: "Email claims PayPal account needs urgent verification.",
    confirmations: 23,
    screenshot: "https://images.unsplash.com/photo-1563013645-976908500316?q=80&w=400&auto=format&fit=crop",
    reporter: "user_9281",
  },
  {
    id: "r3",
    url: "microsoft365-renewal.com",
    type: "Impersonation",
    risk: "Critical",
    status: "Verified",
    description: "Fake Microsoft 365 renewal page harvesting credentials.",
    confirmations: 87,
    screenshot: "https://images.unsplash.com/photo-1551288049-b9e4e0a7f28d?q=80&w=400&auto=format&fit=crop",
    reporter: "sec_researcher",
  },
  {
    id: "r4",
    url: "fake-recruitment-portal.org",
    type: "Fake Recruitment",
    risk: "Medium",
    status: "False Positive",
    description: "Job offer asking for banking details upfront.",
    confirmations: 12,
    screenshot: "https://images.unsplash.com/photo-1507679799987-c7377956453c?q=80&w=400&auto=format&fit=crop",
    reporter: "jobseeker_44",
  },
];

export const WATCHLIST_DOMAINS = [
  { domain: "sbi.co.in", score: 12, certExpiry: "2027-05-10", lastScan: "2h ago", status: "Safe", alerts: true },
  { domain: "paypal.com", score: 8, certExpiry: "2027-02-14", lastScan: "5h ago", status: "Safe", alerts: true },
  { domain: "microsoft.com", score: 5, certExpiry: "2026-12-01", lastScan: "1d ago", status: "Safe", alerts: false },
];

export const CHART_DATA = {
  scansOverTime: [
    { name: "Mon", scans: 40, threats: 8 },
    { name: "Tue", scans: 55, threats: 12 },
    { name: "Wed", scans: 70, threats: 18 },
    { name: "Thu", scans: 62, threats: 14 },
    { name: "Fri", scans: 85, threats: 22 },
    { name: "Sat", scans: 48, threats: 10 },
    { name: "Sun", scans: 32, threats: 6 },
  ],
  threatTypes: [
    { name: "Phishing", value: 45 },
    { name: "Scam", value: 25 },
    { name: "Malware", value: 12 },
    { name: "Fake Recruitment", value: 10 },
    { name: "Payment Fraud", value: 8 },
  ],
  riskDistribution: [
    { range: "0-30 (Safe)", count: 820 },
    { range: "31-50 (Suspicious)", count: 210 },
    { range: "51-75 (High Risk)", count: 130 },
    { range: "76-100 (Dangerous)", count: 87 },
  ],
  certIssues: [
    { name: "Expired", value: 4 },
    { name: "Weak Algorithm", value: 3 },
    { name: "Self-Signed", value: 3 },
    { name: "Chain Issue", value: 2 },
  ],
};
