import re
import ipaddress
import socket
import uuid
from typing import List, Dict, Any, Optional, Tuple, Set
from urllib.parse import urlparse, urljoin
import httpx
from bs4 import BeautifulSoup
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan_finding import ScanFinding
from app.schemas.content_analysis import ContentFindingSchema, ContentAnalysisResult

# ---------------------------------------------------------------------------
# SSRF & SAFE FETCHING CONSTANTS
# ---------------------------------------------------------------------------

BLOCKED_IP_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),       # Link-local / Cloud metadata (AWS 169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),          # Multicast
    ipaddress.ip_network("240.0.0.0/4"),          # Reserved
    ipaddress.ip_network("255.255.255.255/32"),
    # IPv6
    ipaddress.ip_network("::1/128"),              # Loopback
    ipaddress.ip_network("fc00::/7"),             # Unique local
    ipaddress.ip_network("fe80::/10"),            # Link-local
    ipaddress.ip_network("ff00::/8"),             # Multicast
]

SAFE_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 (TrustShield-Scanner/1.0; +https://trustshield.local/bot)"
)

# ---------------------------------------------------------------------------
# BRAND INTELLIGENCE DICTIONARY
# Maps recognized brands to their legitimate canonical domains and regex patterns
# ---------------------------------------------------------------------------

KNOWN_BRANDS = {
    "paypal": {
        "name": "PayPal",
        "patterns": [r"\bpaypal\b"],
        "domains": ["paypal.com", "paypal.me", "paypal-community.com"],
        "keywords": ["send money", "wallet", "paypal balance", "dispute"],
    },
    "microsoft": {
        "name": "Microsoft",
        "patterns": [r"\bmicrosoft\b", r"\boffice\s*365\b", r"\bm365\b", r"\boutlook\b", r"\bone\s*drive\b", r"\bsharepoint\b"],
        "domains": ["microsoft.com", "live.com", "office.com", "office365.com", "outlook.com", "microsoftonline.com", "sharepoint.com", "azure.com"],
        "keywords": ["sign in to your account", "work or school account", "stay signed in"],
    },
    "google": {
        "name": "Google",
        "patterns": [r"\bgoogle\b", r"\bgmail\b", r"\bgoogle\s*drive\b", r"\bgoogle\s*docs\b"],
        "domains": ["google.com", "gmail.com", "google.co.in", "google.co.uk", "googleusercontent.com"],
        "keywords": ["sign in with google", "choose an account", "to continue to gmail"],
    },
    "apple": {
        "name": "Apple",
        "patterns": [r"\bapple\b", r"\bicloud\b", r"\bapple\s*id\b"],
        "domains": ["apple.com", "icloud.com"],
        "keywords": ["sign in with apple id", "find my iphone", "icloud drive"],
    },
    "amazon": {
        "name": "Amazon",
        "patterns": [r"\bamazon\b", r"\bprime\s*video\b", r"\bamazon\s*pay\b"],
        "domains": ["amazon.com", "amazon.co.uk", "amazon.in", "amazon.de", "primevideo.com", "media-amazon.com"],
        "keywords": ["order confirmation", "amazon prime", "delivery attempt"],
    },
    "netflix": {
        "name": "Netflix",
        "patterns": [r"\bnetflix\b"],
        "domains": ["netflix.com"],
        "keywords": ["update your payment method", "membership paused", "restart membership"],
    },
    "sbi": {
        "name": "State Bank of India (SBI)",
        "patterns": [r"\bstate\s*bank\s*of\s*india\b", r"\byono\b", r"\bonlinesbi\b"],
        "domains": ["onlinesbi.sbi", "sbi.co.in", "onlinesbi.com", "bank.sbi"],
        "keywords": ["internet banking", "yono sbi", "profile password"],
    },
    "hdfc": {
        "name": "HDFC Bank",
        "patterns": [r"\bhdfc\s*bank\b", r"\bhdfc\b"],
        "domains": ["hdfcbank.com", "hdfc.com"],
        "keywords": ["netbanking", "customer id", "ipassword"],
    },
    "icici": {
        "name": "ICICI Bank",
        "patterns": [r"\bicici\s*bank\b", r"\bicici\b", r"\bimobile\b"],
        "domains": ["icicibank.com"],
        "keywords": ["internet banking", "user id", "debit card grid"],
    },
    "meta": {
        "name": "Meta / Facebook / Instagram",
        "patterns": [r"\bfacebook\b", r"\binstagram\b", r"\bwhatsapp\b", r"\bmeta\b"],
        "domains": ["facebook.com", "instagram.com", "whatsapp.com", "meta.com", "fb.com"],
        "keywords": ["log in with facebook", "meta business suite", "copyright violation notice"],
    },
    "chase": {
        "name": "Chase Bank",
        "patterns": [r"\bchase\s*bank\b", r"\bjpmorgan\s*chase\b", r"\bchase\b"],
        "domains": ["chase.com", "jpmorganchase.com"],
        "keywords": ["sign in to chase", "routing number", "card ending in"],
    },
    "dhl": {
        "name": "DHL Express",
        "patterns": [r"\bdhl\b", r"\bdhl\s*express\b"],
        "domains": ["dhl.com", "dhl.de"],
        "keywords": ["package pending delivery", "customs fee", "unpaid shipping fee"],
    },
}

# ---------------------------------------------------------------------------
# PHISHING KEYWORD DICTIONARIES
# ---------------------------------------------------------------------------

DECEPTIVE_URGENCY_KEYWORDS = [
    (r"\baccount\s*(has\s*been)?\s*(suspended|locked|frozen|restricted|disabled)\b", "Account Suspension / Restriction Lure", 20),
    (r"\bimmediate\s*action\s*(is\s*)?required\b", "High-Pressure Urgency Claim", 15),
    (r"\bverify\s*your\s*(identity|account|credentials|card|details)\s*(within\s*\d+\s*(hours|minutes|days))?\b", "Mandatory Verification Under Threat of Action", 20),
    (r"\bunauthorized\s*(login|activity|transaction|access)\s*(detected|attempt)?\b", "Fabricated Security Alert / Breach Notice", 20),
    (r"\bkyc\s*(verification|update|suspended|mandatory|pending)\b", "Urgent KYC Verification Demand", 20),
    (r"\b(sim|pan|aadhaar)\s*(card)?\s*(will\s*be)?\s*(deactivated|blocked)\b", "Identity / Telecom Deactivation Threat", 20),
    (r"\b(claim|collect)\s*(your)?\s*(prize|lottery|reward|bonus|crypto\s*giveaway|refund)\b", "Fraudulent Lottery / Giveaway / Refund Enticement", 20),
    (r"\b(unpaid|pending)\s*(customs|delivery|shipping)\s*(fee|duty|charge)\b", "Fake Delivery / Parcel Impersonation Lure", 15),
    (r"\bclick\s*here\s*to\s*(restore|reactivate|unlock)\s*(your)?\s*account\b", "Call-to-Action to Circumvent Security", 15),
]

SUSPICIOUS_SCRIPT_PATTERNS = [
    (r"\beval\s*\(\s*(unescape|atob|String\.fromCharCode|decodeURIComponent)?\b", "JavaScript Obfuscation via eval() / String decoding", 20),
    (r"oncontextmenu\s*=\s*['\"]return\s+false;?['\"]", "Right-Click Context Menu Suppression (Anti-Analysis)", 10),
    (r"onselectstart\s*=\s*['\"]return\s+false;?['\"]", "Text Selection Suppression (Anti-Copy)", 5),
    (r"onkeydown\s*=.*(?:123|keyCode\s*==\s*123)", "DevTools / F12 Key Suppression (Anti-Debugging)", 15),
    (r"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){4,}", "High-Density Hex-Encoded Script Payload", 15),
]

CLICKFIX_PATTERNS = [
    (r"(?:press|hit)\s*(?:windows|win)\s*\+\s*r", "ClickFix / Fake CAPTCHA PowerShell Attack Vector", 30),
    (r"powershell\s+-(?:enc|encodedcommand|executionpolicy)", "PowerShell Command Execution Directive", 30),
    (r"curl\s+.*\|\s*(?:sh|bash|powershell)", "Pipe-to-Shell Remote Payload Directive", 30),
]


# ---------------------------------------------------------------------------
# SSRF PROTECTION HELPER
# ---------------------------------------------------------------------------

def is_safe_url(url: str, resolve_dns: bool = True) -> bool:
    """
    Validates if a URL is strictly safe for server-side outbound HTTP requests.
    Prevents Server-Side Request Forgery (SSRF) against internal metadata,
    private IPs, localhost, and non-HTTP protocols.
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme.lower() not in ("http", "https"):
            return False

        hostname = parsed.hostname
        if not hostname:
            return False

        hostname_lower = hostname.lower()

        # Block literal localhost keywords & internal cloud metadata
        if hostname_lower in ("localhost", "0.0.0.0", "127.0.0.1", "::1", "metadata.google.internal", "instance-data"):
            return False

        # Fast path 1: Check if hostname is an IP address directly (no DNS lookup needed)
        try:
            ip_obj = ipaddress.ip_address(hostname_lower)
            for net in BLOCKED_IP_NETWORKS:
                if ip_obj in net:
                    return False
            return True
        except ValueError:
            pass

        # Fast path 2: Check standard private domain suffixes
        if hostname_lower.endswith((".local", ".localhost", ".internal", ".lan", ".home")):
            return False

        # Optional DNS resolution for domain names
        if resolve_dns:
            try:
                addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
                for item in addr_info:
                    ip_str = item[4][0]
                    ip_obj = ipaddress.ip_address(ip_str)
                    for net in BLOCKED_IP_NETWORKS:
                        if ip_obj in net:
                            return False
            except (socket.gaierror, socket.herror, TimeoutError, OSError):
                pass

        return True
    except Exception:
        return False


def get_base_domain(url_or_host: str) -> str:
    """
    Extracts the root domain (e.g., 'example.com' from 'sub.example.com' or 'https://sub.example.com/path').
    """
    if "://" in url_or_host:
        host = urlparse(url_or_host).hostname or ""
    else:
        host = url_or_host.split(":")[0].split("/")[0]

    host = host.lower().strip()
    parts = host.split(".")
    if len(parts) >= 2:
        # Check for two-part TLDs (e.g., .co.uk, .com.au, .co.in)
        if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "gov", "ac", "edu") and len(parts[-1]) <= 3:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])
    return host


# ---------------------------------------------------------------------------
# SAFE FETCHING (No JS Execution, No File Downloads)
# ---------------------------------------------------------------------------

async def safe_fetch_html(
    url: str,
    timeout: float = 8.0,
    max_bytes: int = 2 * 1024 * 1024,  # 2 MB limit
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Safely retrieves HTML document without executing JavaScript or downloading arbitrary files.
    Enforces SSRF validation, size limits, redirect limits, and content-type verification.

    Returns:
        (html_content, final_url, error_message)
    """
    if not is_safe_url(url):
        return None, None, "URL violates SSRF security boundary (private IP, loopback, or cloud metadata target blocked)"

    headers = {
        "User-Agent": SAFE_USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
    }

    try:
        # Custom client with strictly safe redirect handling
        async with httpx.AsyncClient(
            headers=headers,
            timeout=timeout,
            follow_redirects=True,
            max_redirects=5,
            verify=False,  # Allow inspecting untrusted/self-signed cert phishing targets
        ) as client:
            response = await client.get(url)

            # Validate that the final redirected URL is still SSRF safe
            if not is_safe_url(str(response.url)):
                return None, str(response.url), "Redirected to forbidden private network / loopback address"

            # Check Content-Type to reject executable binaries, archives, and media
            content_type = response.headers.get("content-type", "").lower()
            allowed_types = ("text/html", "application/xhtml+xml", "text/plain", "application/xml")
            if content_type and not any(t in content_type for t in allowed_types):
                return None, str(response.url), f"Unsupported content type '{content_type}'. Binary and file downloads are prohibited."

            # Read content with hard upper bound
            content_bytes = response.content
            if len(content_bytes) > max_bytes:
                content_bytes = content_bytes[:max_bytes]

            html_text = content_bytes.decode("utf-8", errors="replace")
            return html_text, str(response.url), None

    except httpx.TimeoutException:
        return None, None, f"Connection timed out after {timeout} seconds"
    except httpx.ConnectError:
        return None, None, "Failed to establish TCP/TLS connection to host"
    except Exception as e:
        return None, None, f"HTTP fetch error: {str(e)}"


# ---------------------------------------------------------------------------
# HTML PARSER & PHISHING DETECTION ENGINE
# ---------------------------------------------------------------------------

def analyze_html(html: str, target_url: str) -> ContentAnalysisResult:
    """
    Parses static HTML without executing JavaScript.
    Analyzes forms, sensitive fields, brand claims, keywords, scripts, hidden fields, and evasion.
    """
    soup = BeautifulSoup(html or "", "html.parser")
    target_domain = get_base_domain(target_url)

    findings: List[ContentFindingSchema] = []
    detected_brands: Set[str] = set()
    brand_mismatches: List[str] = []
    sensitive_fields: Set[str] = set()
    suspicious_scripts: List[str] = []
    phishing_keywords_found: List[str] = []

    page_title = soup.title.string.strip() if soup.title and soup.title.string else ""

    # =========================================================================
    # 1. LOGIN & CREDENTIAL HARVESTING FORMS
    # =========================================================================
    forms = soup.find_all("form")
    has_login_form = False
    has_credential_harvesting = False

    for idx, form in enumerate(forms, start=1):
        inputs = form.find_all("input")
        input_types = [inp.get("type", "text").lower() for inp in inputs]
        input_names = [inp.get("name", "").lower() for inp in inputs if inp.get("name")]
        input_ids = [inp.get("id", "").lower() for inp in inputs if inp.get("id")]
        all_field_identifiers = input_names + input_ids

        has_password = "password" in input_types or any("password" in ident or "pwd" in ident for ident in all_field_identifiers)
        has_user_identifier = any(
            t in ("text", "email") for t in input_types
        ) and any(
            term in ident for ident in all_field_identifiers for term in ("user", "email", "login", "uname", "account", "phone")
        )

        if has_password:
            has_login_form = True

            action_raw = (form.get("action") or "").strip()
            form_method = (form.get("method") or "GET").upper()

            # Resolve relative action URL against base
            action_resolved = urljoin(target_url, action_raw) if action_raw else target_url
            action_domain = get_base_domain(action_resolved)

            # Check for suspicious / third-party / external action
            is_external_action = bool(action_domain and target_domain and action_domain != target_domain)
            is_insecure_http = action_resolved.startswith("http://") and target_url.startswith("https://")
            is_suspicious_endpoint = any(
                hook in action_resolved.lower()
                for hook in ("api.telegram.org", "discord.com/api/webhooks", "formspree.io", "google.com/forms", "mailto:")
            )

            evidence_data = {
                "form_index": idx,
                "method": form_method,
                "action": action_raw or "(empty/same-page)",
                "resolved_action": action_resolved,
                "input_fields": all_field_identifiers[:10],
                "has_username_field": has_user_identifier,
                "has_password_field": True,
            }

            if is_suspicious_endpoint or is_external_action:
                has_credential_harvesting = True
                findings.append(
                    ContentFindingSchema(
                        category="credential_harvesting",
                        title="Third-Party Credential Exfiltration Endpoint",
                        severity="critical",
                        confidence=0.95,
                        description=(
                            f"Form #{idx} captures authentication credentials and submits them directly to an external "
                            f"destination ('{action_domain or action_resolved}') that does not belong to the host site."
                        ),
                        evidence=evidence_data,
                        recommendation="Do NOT enter login credentials. The form forwards credentials to an unauthorized external server.",
                        risk_points=35,
                        raw_data={"form_html": str(form)[:500]},
                    )
                )
            elif is_insecure_http:
                findings.append(
                    ContentFindingSchema(
                        category="credential_harvesting",
                        title="Insecure HTTP Login Form Submission",
                        severity="high",
                        confidence=0.90,
                        description=f"Form #{idx} submits sensitive credentials over an unencrypted HTTP channel ('{action_resolved}').",
                        evidence=evidence_data,
                        recommendation="Never submit credentials over unencrypted HTTP.",
                        risk_points=20,
                        raw_data={"form_html": str(form)[:500]},
                    )
                )
            else:
                findings.append(
                    ContentFindingSchema(
                        category="login_form",
                        title="Credential Input Form Detected",
                        severity="medium",
                        confidence=0.85,
                        description=f"The page presents a user login form requesting credentials for authentication.",
                        evidence=evidence_data,
                        recommendation="Verify that the website domain matches the authentic service before entering credentials.",
                        risk_points=10,
                        raw_data={"form_html": str(form)[:500]},
                    )
                )

    # =========================================================================
    # 2. SENSITIVE INPUT FIELDS (OTP, CARD, UPI, GOV ID)
    # =========================================================================
    all_inputs = soup.find_all(["input", "select", "textarea"])
    hidden_inputs_count = 0

    otp_fields = []
    card_fields = []
    upi_fields = []
    govid_fields = []

    for inp in all_inputs:
        itype = inp.get("type", "text").lower()
        if itype == "hidden":
            hidden_inputs_count += 1

        name = inp.get("name", "").lower()
        iid = inp.get("id", "").lower()
        placeholder = inp.get("placeholder", "").lower()
        field_str = f"{name} {iid} {placeholder}"

        # OTP / 2FA check
        if any(term in field_str for term in ("otp", "2fa", "one-time", "passcode", "security_code", "verification_code", "totp", "mfa")):
            otp_fields.append(name or iid or "otp_field")
            sensitive_fields.add("OTP / 2FA")

        # Payment card check
        if any(term in field_str for term in ("card_number", "cardnumber", "card_no", "cc_num", "cvv", "cvc", "exp_date", "expiry", "cardholder")):
            card_fields.append(name or iid or "card_field")
            sensitive_fields.add("Payment Card (PAN/CVV)")

        # UPI / Digital Wallet check
        if any(term in field_str for term in ("upi", "vpa", "upi_pin", "mpin", "bhim", "gpay", "phonepe", "paytm")):
            upi_fields.append(name or iid or "upi_field")
            sensitive_fields.add("UPI ID / PIN")

        # Government ID check (Aadhaar, PAN, SSN)
        if any(term in field_str for term in ("aadhaar", "uidai", "pan_number", "pancard", "ssn", "social_security")):
            govid_fields.append(name or iid or "national_id_field")
            sensitive_fields.add("Government ID (Aadhaar/PAN/SSN)")

    if otp_fields:
        findings.append(
            ContentFindingSchema(
                category="sensitive_inputs",
                title="One-Time Password (OTP) Input Fields Detected",
                severity="high",
                confidence=0.90,
                description=f"The page contains input fields specifically designed to capture Second-Factor/OTP verification tokens.",
                evidence={"detected_fields": otp_fields},
                recommendation="Legitimate financial and security services will never ask for your OTP via suspicious or unverified portals.",
                risk_points=25,
            )
        )

    if card_fields:
        findings.append(
            ContentFindingSchema(
                category="sensitive_inputs",
                title="Payment Card Details Harvesting Fields Detected",
                severity="critical" if has_login_form else "high",
                confidence=0.92,
                description="The page requests credit/debit card numbers, expiration dates, or CVV security codes.",
                evidence={"detected_fields": card_fields},
                recommendation="Do not provide card information unless you independently verify the merchant/issuer.",
                risk_points=25,
            )
        )

    if upi_fields:
        findings.append(
            ContentFindingSchema(
                category="sensitive_inputs",
                title="UPI Financial PIN / VPA Harvesting Request Detected",
                severity="critical",
                confidence=0.90,
                description="Detected input fields soliciting UPI IDs, VPAs, or confidential UPI PINs.",
                evidence={"detected_fields": upi_fields},
                recommendation="Remember: UPI PIN is ONLY required to send money or debit your account, never to receive funds.",
                risk_points=25,
            )
        )

    if govid_fields:
        findings.append(
            ContentFindingSchema(
                category="sensitive_inputs",
                title="National Identity Number Solicitation (Aadhaar/PAN/SSN)",
                severity="high",
                confidence=0.90,
                description="Detected input fields collecting highly sensitive government identity numbers (Aadhaar, PAN, or SSN).",
                evidence={"detected_fields": govid_fields},
                recommendation="Never share sensitive national identification numbers on unverified web addresses.",
                risk_points=20,
            )
        )

    # =========================================================================
    # 3. BRAND IMPERSONATION & DOMAIN MISMATCH
    # =========================================================================
    page_text_lower = soup.get_text(" ", strip=True).lower()
    html_raw_lower = html.lower()

    for brand_key, brand_info in KNOWN_BRANDS.items():
        brand_name = brand_info["name"]
        patterns = brand_info["patterns"]
        legit_domains = [get_base_domain(d) for d in brand_info["domains"]]

        brand_detected_on_page = False
        evidence_snippets = []

        # Check title
        if any(re.search(pat, page_title.lower()) for pat in patterns):
            brand_detected_on_page = True
            evidence_snippets.append(f"Title contains '{page_title}'")

        # Check OpenGraph / Meta headers
        for meta in soup.find_all("meta"):
            content_val = (meta.get("content") or "").lower()
            if any(re.search(pat, content_val) for pat in patterns):
                brand_detected_on_page = True
                evidence_snippets.append(f"Meta tag: {content_val[:60]}")
                break

        # Check images alt/src or headings
        if not brand_detected_on_page:
            for img in soup.find_all("img"):
                alt_val = (img.get("alt") or "").lower()
                src_val = (img.get("src") or "").lower()
                if any(re.search(pat, f"{alt_val} {src_val}") for pat in patterns):
                    brand_detected_on_page = True
                    evidence_snippets.append(f"Logo/Image: {alt_val or src_val[:40]}")
                    break

        if brand_detected_on_page:
            detected_brands.add(brand_name)

            # Check domain mismatch: Is current domain in legitimate domain whitelist?
            is_legit_domain = any(target_domain == ld or target_domain.endswith(f".{ld}") for ld in legit_domains)

            if not is_legit_domain:
                brand_mismatches.append(brand_name)
                findings.append(
                    ContentFindingSchema(
                        category="brand_impersonation",
                        title=f"Brand Impersonation: {brand_name} Claimed on Unofficial Domain",
                        severity="critical",
                        confidence=0.95,
                        description=(
                            f"The page displays {brand_name} branding and design elements, but is hosted on '{target_domain}', "
                            f"which is NOT an authorized domain for {brand_name} (legitimate: {', '.join(brand_info['domains'][:3])})."
                        ),
                        evidence={
                            "claimed_brand": brand_name,
                            "actual_domain": target_domain,
                            "authorized_domains": brand_info["domains"],
                            "brand_indicators": evidence_snippets,
                        },
                        recommendation=f"Do NOT trust this website. This is an impersonation of {brand_name}.",
                        risk_points=30,
                    )
                )

    # =========================================================================
    # 4. DECEPTIVE PAGE CONTENT & PHISHING KEYWORDS
    # =========================================================================
    for pattern, title, pts in DECEPTIVE_URGENCY_KEYWORDS:
        match = re.search(pattern, page_text_lower, re.IGNORECASE)
        if match:
            matched_phrase = match.group(0)
            phishing_keywords_found.append(matched_phrase)
            findings.append(
                ContentFindingSchema(
                    category="deceptive_content",
                    title=f"Phishing Indicator: {title}",
                    severity="high" if pts >= 20 else "medium",
                    confidence=0.88,
                    description=f"Detected social engineering phrase: \"{matched_phrase}\", commonly used to manipulate victims into hasty compliance.",
                    evidence={"matched_phrase": matched_phrase, "pattern": pattern},
                    recommendation="Scammers frequently manufacture artificial urgency or panic. Verify requests through verified official channels.",
                    risk_points=pts,
                )
            )

    # ClickFix / Fake CAPTCHA check
    for pattern, title, pts in CLICKFIX_PATTERNS:
        match = re.search(pattern, page_text_lower, re.IGNORECASE) or re.search(pattern, html_raw_lower, re.IGNORECASE)
        if match:
            matched_text = match.group(0)
            findings.append(
                ContentFindingSchema(
                    category="malicious_lure",
                    title=f"Malicious Execution Lure: {title}",
                    severity="critical",
                    confidence=0.98,
                    description="The page attempts to deceive the user into executing a system terminal command or clipboard paste (ClickFix attack).",
                    evidence={"matched_directive": matched_text},
                    recommendation="CRITICAL: Do NOT press Windows+R or paste clipboard contents into your terminal. This directly runs malware on your machine.",
                    risk_points=pts,
                )
            )

    # =========================================================================
    # 5. SUSPICIOUS SCRIPTS, IFRAMES & HIDDEN ELEMENTS
    # =========================================================================
    # Script inspection for obfuscation and eval
    scripts = soup.find_all("script")
    for s_idx, script in enumerate(scripts, start=1):
        s_content = script.string or script.text or ""
        for pattern, s_title, pts in SUSPICIOUS_SCRIPT_PATTERNS:
            if "oncontextmenu" not in pattern and "onselectstart" not in pattern and "onkeydown" not in pattern:
                if re.search(pattern, s_content, re.IGNORECASE):
                    suspicious_scripts.append(s_title)
                    findings.append(
                        ContentFindingSchema(
                            category="suspicious_script",
                            title=s_title,
                            severity="medium",
                            confidence=0.85,
                            description=f"Script #{s_idx} contains code associated with anti-analysis evasion or payload obfuscation.",
                            evidence={"pattern": pattern, "snippet": s_content[:100].strip()},
                            recommendation="The presence of obfuscated client-side code is a frequent indicator of hostile or evasion behavior.",
                            risk_points=pts,
                        )
                    )

    # Anti-analysis event handlers across entire HTML (tag attributes or inline scripts)
    for pattern, s_title, pts in SUSPICIOUS_SCRIPT_PATTERNS:
        if "oncontextmenu" in pattern or "onselectstart" in pattern or "onkeydown" in pattern:
            if re.search(pattern, html_raw_lower):
                suspicious_scripts.append(s_title)
                findings.append(
                    ContentFindingSchema(
                        category="anti_analysis",
                        title=s_title,
                        severity="medium",
                        confidence=0.90,
                        description="Detected inline event handlers preventing user inspection, right-click, or DevTools shortcut keys.",
                        evidence={"pattern": pattern},
                        recommendation="Legitimate sites do not restrict browser inspect or text selection controls.",
                        risk_points=pts,
                    )
                )

    # Iframe inspection (invisible/overlay frames)
    iframes = soup.find_all("iframe")
    for if_idx, iframe in enumerate(iframes, start=1):
        width = iframe.get("width", "")
        height = iframe.get("height", "")
        style = (iframe.get("style") or "").lower()

        is_zero_dimension = width in ("0", "0px") or height in ("0", "0px") or "display:none" in style or "opacity:0" in style
        if is_zero_dimension:
            findings.append(
                ContentFindingSchema(
                    category="hidden_elements",
                    title="Hidden or Zero-Dimension Iframe Detected",
                    severity="high",
                    confidence=0.90,
                    description=f"Iframe #{if_idx} is concealed using zero-dimension dimensions or CSS visibility hiding, often used for stealth clickjacking or CSRF.",
                    evidence={"src": iframe.get("src", ""), "style": style, "width": width, "height": height},
                    recommendation="Concealed iframes indicate covert activity running in the background.",
                    risk_points=15,
                )
            )

    # Excessive hidden fields
    if hidden_inputs_count >= 5:
        findings.append(
            ContentFindingSchema(
                category="hidden_elements",
                title=f"Excessive Hidden Form Fields ({hidden_inputs_count} fields)",
                severity="low",
                confidence=0.75,
                description=f"The page embeds {hidden_inputs_count} hidden input tags, potentially passing tracking tokens or concealed parameters.",
                evidence={"hidden_count": hidden_inputs_count},
                recommendation="Monitor form submission targets for concealed exfiltration channels.",
                risk_points=5,
            )
        )

    # Calculate aggregate risk score & severity
    total_risk_points = min(100, sum(f.risk_points for f in findings))

    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    max_sev = "info"
    for f in findings:
        if severity_order.get(f.severity, 0) > severity_order.get(max_sev, 0):
            max_sev = f.severity

    # Construct descriptive summary
    if brand_mismatches and (has_login_form or sensitive_fields):
        summary = f"Dangerous Phishing Detected: Unauthorized site impersonating {', '.join(brand_mismatches)} to harvest sensitive user credentials."
    elif brand_mismatches:
        summary = f"High Risk: Suspected brand impersonation of {', '.join(brand_mismatches)} on unofficial domain."
    elif has_credential_harvesting:
        summary = "High Risk: Form exfiltrates user credentials to third-party endpoints."
    elif sensitive_fields:
        summary = f"Suspicious Content: Page solicits high-risk financial/identity fields ({', '.join(sensitive_fields)})."
    elif has_login_form:
        summary = "Informational: Standard login form detected."
    else:
        summary = "Content Analysis: No significant phishing forms or brand impersonations detected in page content."

    return ContentAnalysisResult(
        url=target_url,
        final_url=target_url,
        page_title=page_title,
        has_login_form=has_login_form,
        has_credential_harvesting=has_credential_harvesting,
        detected_brands=list(detected_brands),
        brand_mismatches=brand_mismatches,
        sensitive_fields=list(sensitive_fields),
        suspicious_scripts=suspicious_scripts,
        hidden_inputs_count=hidden_inputs_count,
        phishing_keywords_found=phishing_keywords_found,
        total_risk_points=total_risk_points,
        max_severity=max_sev,
        summary=summary,
        findings=findings,
    )


# ---------------------------------------------------------------------------
# DATABASE PERSISTENCE
# ---------------------------------------------------------------------------

def save_findings_to_db_sync(
    scan_id: uuid.UUID,
    findings: List[ContentFindingSchema],
    db: Any,
) -> List[ScanFinding]:
    """
    Synchronously persists structured content findings into the `scan_findings` table.
    """
    db_records: List[ScanFinding] = []

    for f in findings:
        record = ScanFinding(
            scan_id=scan_id,
            category=f.category,
            title=f.title,
            severity=f.severity,
            confidence=f.confidence,
            description=f.description,
            evidence=f.evidence,
            recommendation=f.recommendation,
            risk_points=f.risk_points,
            raw_data=f.raw_data or {},
        )
        db.add(record)
        db_records.append(record)

    db.commit()
    for record in db_records:
        db.refresh(record)

    return db_records


async def save_findings_to_db(
    scan_id: uuid.UUID,
    findings: List[ContentFindingSchema],
    db: AsyncSession,
) -> List[ScanFinding]:
    """
    Persists structured content findings into the PostgreSQL/SQLite `scan_findings` table.
    """
    db_records: List[ScanFinding] = []

    for f in findings:
        record = ScanFinding(
            scan_id=scan_id,
            category=f.category,
            title=f.title,
            severity=f.severity,
            confidence=f.confidence,
            description=f.description,
            evidence=f.evidence,
            recommendation=f.recommendation,
            risk_points=f.risk_points,
            raw_data=f.raw_data or {},
        )
        db.add(record)
        db_records.append(record)

    await db.commit()
    for record in db_records:
        await db.refresh(record)

    return db_records


# ---------------------------------------------------------------------------
# MAIN END-TO-END ANALYZER ENTRY POINT
# ---------------------------------------------------------------------------

def analyze_content_sync(
    url: str,
    scan_id: Optional[uuid.UUID] = None,
    html: Optional[str] = None,
    db: Optional[Any] = None,
) -> ContentAnalysisResult:
    """
    Synchronous content analysis using a pre-provided HTML fixture.
    """
    result = analyze_html(html or "", url)
    if scan_id and db and result.findings:
        save_findings_to_db_sync(scan_id=scan_id, findings=result.findings, db=db)
    return result

async def analyze_content(
    url: str,
    scan_id: Optional[uuid.UUID] = None,
    html: Optional[str] = None,
    db: Optional[AsyncSession] = None,
) -> ContentAnalysisResult:
    """
    End-to-end execution of Phishing Content Analysis:
    1. Safely fetches HTML (if not provided as a fixture).
    2. Parses HTML and extracts structured findings.
    3. Persists findings to database linked to `scan_id` (if db provided).
    4. Returns consolidated ContentAnalysisResult.
    """
    final_url = url
    if html is None:
        html_content, final_url, err = await safe_fetch_html(url)
        if err or html_content is None:
            return ContentAnalysisResult(
                url=url,
                final_url=final_url,
                error_message=err or "Failed to retrieve page content",
                summary=f"Content Analysis Incomplete: {err}",
            )
    else:
        html_content = html

    # Parse and generate findings
    result = analyze_html(html_content, final_url or url)

    # Persist findings to database if scan_id and db are provided
    if scan_id and db and result.findings:
        await save_findings_to_db(scan_id=scan_id, findings=result.findings, db=db)

    return result
