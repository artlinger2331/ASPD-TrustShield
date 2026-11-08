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
# COMPREHENSIVE BRAND INTELLIGENCE DICTIONARY
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
    "sbi": {
        "name": "State Bank of India (SBI)",
        "patterns": [r"\bstate\s*bank\s*of\s*india\b", r"\byono\b", r"\byono\s*sbi\b", r"\bonlinesbi\b"],
        "domains": ["onlinesbi.sbi", "sbi.co.in", "onlinesbi.com", "bank.sbi"],
        "keywords": ["internet banking", "yono sbi", "profile password", "customer id"],
    },
    "hdfc": {
        "name": "HDFC Bank",
        "patterns": [r"\bhdfc\s*bank\b", r"\bhdfc\b"],
        "domains": ["hdfcbank.com", "hdfc.com"],
        "keywords": ["netbanking", "customer id", "ipassword", "hdfc net banking"],
    },
    "icici": {
        "name": "ICICI Bank",
        "patterns": [r"\bicici\s*bank\b", r"\bicici\b", r"\bimobile\b"],
        "domains": ["icicibank.com"],
        "keywords": ["internet banking", "user id", "debit card grid"],
    },
    "axis": {
        "name": "Axis Bank",
        "patterns": [r"\baxis\s*bank\b", r"\baxis\b"],
        "domains": ["axisbank.com"],
        "keywords": ["internet banking", "login id", "m-pin"],
    },
    "kotak": {
        "name": "Kotak Mahindra Bank",
        "patterns": [r"\bkotak\s*mahindra\b", r"\bkotak\s*bank\b", r"\bkotak\b", r"\bkotak811\b"],
        "domains": ["kotak.com"],
        "keywords": ["net banking", "crn", "mpin"],
    },
    "pnb": {
        "name": "Punjab National Bank (PNB)",
        "patterns": [r"\bpunjab\s*national\s*bank\b", r"\bpnb\b", r"\bpnbone\b"],
        "domains": ["pnbindia.in", "netpnb.com"],
        "keywords": ["internet banking", "user id", "pnb one"],
    },
    "bob": {
        "name": "Bank of Baroda",
        "patterns": [r"\bbank\s*of\s*baroda\b", r"\bbob\s*world\b"],
        "domains": ["bankofbaroda.in", "bobworld.com"],
        "keywords": ["bob world", "baroda connect"],
    },
    "incometax": {
        "name": "Income Tax Department of India",
        "patterns": [r"\bincome\s*tax\s*(department)?\b", r"\be-filing\b", r"\bpan\s*card\s*portal\b"],
        "domains": ["incometax.gov.in", "incometaxindiaefiling.gov.in", "tin-nsdl.com"],
        "keywords": ["tax refund", "e-filing portal", "verify pan", "link aadhaar to pan"],
    },
    "uidai": {
        "name": "UIDAI / Aadhaar",
        "patterns": [r"\buidai\b", r"\bmyaadhaar\b", r"\baadhaar\b"],
        "domains": ["uidai.gov.in", "myaadhaar.uidai.gov.in"],
        "keywords": ["download aadhaar", "update aadhaar", "aadhaar kyc", "biometric lock"],
    },
    "paytm": {
        "name": "Paytm",
        "patterns": [r"\bpaytm\b"],
        "domains": ["paytm.com"],
        "keywords": ["paytm wallet", "paytm payments bank", "scan upi qr"],
    },
    "phonepe": {
        "name": "PhonePe",
        "patterns": [r"\bphonepe\b"],
        "domains": ["phonepe.com"],
        "keywords": ["upi id", "phonepe wallet", "rewards"],
    },
    "binance": {
        "name": "Binance",
        "patterns": [r"\bbinance\b"],
        "domains": ["binance.com"],
        "keywords": ["crypto deposit", "binance exchange", "claim token airdrop"],
    },
}

# ---------------------------------------------------------------------------
# PHISHING KEYWORD & DECEPTIVE LURE DICTIONARIES
# ---------------------------------------------------------------------------

DECEPTIVE_URGENCY_KEYWORDS = [
    (r"\baccount\s*(has\s*been)?\s*(suspended|locked|frozen|restricted|disabled|blocked)\b", "Account Suspension / Restriction Lure", 20),
    (r"\bimmediate\s*action\s*(is\s*)?required\b", "High-Pressure Urgency Claim", 15),
    (r"\bverify\s*your\s*(identity|account|credentials|card|details)\s*(within\s*\d+\s*(hours|minutes|days))?\b", "Mandatory Verification Under Threat of Action", 20),
    (r"\bunauthorized\s*(login|activity|transaction|access)\s*(detected|attempt)?\b", "Fabricated Security Alert / Breach Notice", 20),
    (r"\bkyc\s*(verification|update|suspended|mandatory|pending|expired)\b", "Urgent KYC Verification Demand", 20),
    (r"\b(sim|pan|aadhaar)\s*(card)?\s*(will\s*be)?\s*(deactivated|blocked|cancelled)\b", "Identity / Telecom Deactivation Threat", 25),
    (r"\b(claim|collect)\s*(your)?\s*(prize|lottery|reward|bonus|cashback|crypto\s*giveaway|refund)\b", "Fraudulent Lottery / Reward / Refund Enticement", 20),
    (r"\b(unpaid|pending)\s*(customs|delivery|shipping)\s*(fee|duty|charge)\b", "Fake Delivery / Parcel Impersonation Lure", 15),
    (r"\bclick\s*here\s*to\s*(restore|reactivate|unlock|verify)\s*(your)?\s*account\b", "Call-to-Action to Circumvent Security", 15),
    (r"\breactivate\s*your\s*netbanking\b", "Banking Deactivation Lure", 20),
    (r"\belectricity\s*bill\s*(unpaid|overdue|disconnection)\b", "Fake Utility Disconnection Threat", 20),
]

# Deceptive Buttons and Calls to Action (CTAs)
DECEPTIVE_CTA_PATTERNS = [
    (r"update\s*kyc(\s*now)?", "Update KYC Urgent Action", 15),
    (r"verify\s*(now|account|identity|identity\s*now)", "Verify Identity Call-to-Action", 15),
    (r"unlock\s*(my\s*)?account", "Unlock Account Action", 15),
    (r"claim\s*(reward|prize|cashback|refund|\d+)", "Claim Reward / Cashback Action", 15),
    (r"restore\s*access", "Restore Access Urgent Action", 15),
    (r"pay\s*(pending|customs|delivery|overdue)\s*fee", "Pay Overdue Fee Action", 15),
    (r"click\s*to\s*verify\s*(you\s*are\s*)?human", "Fake CAPTCHA / Human Verification Button", 20),
]

SUSPICIOUS_SCRIPT_PATTERNS = [
    (r"\beval\s*\(\s*(unescape|atob|String\.fromCharCode|decodeURIComponent)?\b", "JavaScript Obfuscation via eval() / String decoding", 20),
    (r"oncontextmenu\s*=\s*['\"]return\s+false;?['\"]", "Right-Click Context Menu Suppression (Anti-Analysis)", 10),
    (r"onselectstart\s*=\s*['\"]return\s+false;?['\"]", "Text Selection Suppression (Anti-Copy)", 5),
    (r"onkeydown\s*=.*(?:123|keyCode\s*==\s*123)", "DevTools / F12 Key Suppression (Anti-Debugging)", 15),
    (r"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){4,}", "High-Density Hex-Encoded Script Payload", 15),
    (r"\bfunction\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*d\s*\)", "Dean Edwards Packed JavaScript Obfuscation", 20),
]

SUSPICIOUS_EXTERNAL_SCRIPT_DOMAINS = [
    "pastebin.com",
    "raw.githubusercontent.com",
    "cdn.discordapp.com",
    "api.telegram.org",
    "ngrok.io",
    "ngrok-free.app",
    "localtunnel.me",
    "serveo.net",
    "duckdns.org",
    "formspree.io",
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
        # Check for two-part TLDs (e.g., .co.uk, .com.au, .co.in, .gov.in)
        if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "gov", "ac", "edu", "res") and len(parts[-1]) <= 3:
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
        current_target = url
        # Custom client with strictly safe per-hop redirect validation
        async with httpx.AsyncClient(
            headers=headers,
            timeout=timeout,
            follow_redirects=False,  # Enforce manual hop-by-hop SSRF validation
            verify=False,  # Allow inspecting untrusted/self-signed cert phishing targets
        ) as client:
            response = None
            for hop in range(5):
                if not is_safe_url(current_target):
                    return None, current_target, f"Redirect hop {hop + 1} violates SSRF security boundary"
                response = await client.get(current_target)
                if response.status_code in (301, 302, 303, 307, 308):
                    loc = response.headers.get("location")
                    if not loc:
                        break
                    current_target = urljoin(current_target, loc)
                else:
                    break

            if response is None:
                return None, current_target, "No response received"

            # Validate that the final redirected URL is still SSRF safe
            final_url = str(response.url)
            if not is_safe_url(final_url):
                return None, final_url, "Redirected to forbidden private network / loopback address"

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
# HTML PARSER & PHISHING DETECTION ENGINE (12 Detection Vectors)
# ---------------------------------------------------------------------------

def analyze_html(html: str, target_url: str) -> ContentAnalysisResult:
    """
    Parses static HTML without executing JavaScript.
    Analyzes forms, sensitive fields, brand claims, keywords, scripts, hidden fields, and evasion.
    Generates standardized ScanFindings with category='phishing' and granular detector_types in evidence.
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
    page_text_lower = soup.get_text(" ", strip=True).lower()
    html_raw_lower = html.lower()

    # Pre-check: Scan for brand indicators across title, meta, images, and headings
    brand_occurrences: Dict[str, Dict[str, Any]] = {}
    title_or_heading_brands: Set[str] = set()

    for brand_key, brand_info in KNOWN_BRANDS.items():
        brand_name = brand_info["name"]
        patterns = brand_info["patterns"]
        evidence_snippets = []
        is_logo_or_meta = False

        # Check title
        if any(re.search(pat, page_title.lower()) for pat in patterns):
            evidence_snippets.append(f"Title contains '{page_title}'")
            title_or_heading_brands.add(brand_name)

        # Check OpenGraph / Meta headers
        for meta in soup.find_all("meta"):
            content_val = (meta.get("content") or "").lower()
            prop_val = (meta.get("property") or meta.get("name") or "").lower()
            if any(re.search(pat, content_val) for pat in patterns):
                evidence_snippets.append(f"Meta tag: {content_val[:60]}")
                if "site_name" in prop_val or "title" in prop_val:
                    is_logo_or_meta = True
                break

        # Check images alt/src (Logos)
        for img in soup.find_all("img"):
            alt_val = (img.get("alt") or "").lower()
            src_val = (img.get("src") or "").lower()
            if any(re.search(pat, f"{alt_val} {src_val}") for pat in patterns):
                evidence_snippets.append(f"Logo/Image: {alt_val or src_val[:40]}")
                is_logo_or_meta = True
                break

        # Check main headings (h1, h2)
        for heading in soup.find_all(["h1", "h2"]):
            h_text = heading.get_text().lower()
            if any(re.search(pat, h_text) for pat in patterns):
                evidence_snippets.append(f"Heading: {h_text[:60]}")
                title_or_heading_brands.add(brand_name)
                break

        if evidence_snippets:
            brand_occurrences[brand_key] = {
                "name": brand_name,
                "info": brand_info,
                "evidence": evidence_snippets,
                "is_logo_or_meta": is_logo_or_meta,
            }

    # Identify if page is an editorial, news, or multi-brand discussion article
    is_editorial_discussion = (
        any(term in page_title.lower() for term in ("review", "analysis", "trends", "guide", "news", "blog", "article", "history", "vs", "comparing"))
        or len(title_or_heading_brands) >= 2  # Discusses multiple competing brands simultaneously
    )

    # Inspect forms first so we know if authentication/credentials exist on the page
    forms = soup.find_all("form")
    has_login_form = False
    has_credential_harvesting = False
    all_harvested_inputs: List[str] = []
    form_analysis_records = []

    for idx, form in enumerate(forms, start=1):
        inputs = form.find_all("input")
        input_types = [inp.get("type", "text").lower() for inp in inputs]
        input_names = [inp.get("name", "").lower() for inp in inputs if inp.get("name")]
        input_ids = [inp.get("id", "").lower() for inp in inputs if inp.get("id")]
        input_placeholders = [inp.get("placeholder", "").lower() for inp in inputs if inp.get("placeholder")]
        all_field_identifiers = input_names + input_ids

        has_password = (
            "password" in input_types
            or any("password" in ident or "pwd" in ident or "passcode" in ident for ident in all_field_identifiers)
            or any("password" in ph for ph in input_placeholders)
        )
        is_auth_action = any(
            term in f"{form.get('action', '')} {form.get('id', '')} {' '.join(form.get('class', []))}".lower()
            for term in ("login", "signin", "auth", "session", "authenticate", "verify", "netbanking")
        )
        has_user_identifier = any(
            t in ("text", "email", "tel") for t in input_types
        ) and any(
            term in ident for ident in all_field_identifiers for term in ("user", "email", "login", "uname", "account", "phone", "mobile", "cust_id")
        )

        # True login form requires a password field, OR username with explicit auth action/id
        is_login = has_password or (has_user_identifier and is_auth_action)
        if is_login:
            has_login_form = True

        action_raw = (form.get("action") or "").strip()
        form_method = (form.get("method") or "GET").upper()
        action_resolved = urljoin(target_url, action_raw) if action_raw else target_url
        action_domain = get_base_domain(action_resolved)

        is_external_action = bool(action_domain and target_domain and action_domain != target_domain)
        is_insecure_http = action_resolved.startswith("http://") and target_url.startswith("https://")
        is_suspicious_endpoint = any(
            hook in action_resolved.lower()
            for hook in ("api.telegram.org", "discord.com/api/webhooks", "formspree.io", "google.com/forms", "mailto:", "webhook.site", "pastebin.com")
        )

        form_analysis_records.append({
            "idx": idx,
            "form": form,
            "inputs": inputs,
            "is_login": is_login,
            "has_password": has_password,
            "has_user_identifier": has_user_identifier,
            "action_raw": action_raw,
            "form_method": form_method,
            "action_resolved": action_resolved,
            "action_domain": action_domain,
            "is_external_action": is_external_action,
            "is_insecure_http": is_insecure_http,
            "is_suspicious_endpoint": is_suspicious_endpoint,
        })

    # Evaluate Brand Mismatches
    for brand_key, b_data in brand_occurrences.items():
        brand_name = b_data["name"]
        brand_info = b_data["info"]
        legit_domains = [get_base_domain(d) for d in brand_info["domains"]]
        is_legit_domain = any(target_domain == ld or target_domain.endswith(f".{ld}") for ld in legit_domains)

        detected_brands.add(brand_name)

        if not is_legit_domain:
            # Check if this is an authentic brand claim or an ambiguous discussion
            # Flag mismatch if: has logo/site_name, or page has login form/lures, or not an editorial multi-brand review
            is_actionable_brand_claim = b_data["is_logo_or_meta"] or has_login_form or not is_editorial_discussion

            if is_actionable_brand_claim:
                brand_mismatches.append(brand_name)
                # Finding Vector 11: Brand Domain Mismatch
                findings.append(
                    ContentFindingSchema(
                        category="phishing",
                        title=f"Brand mismatch: {brand_name} claimed on unauthorized domain",
                        severity="critical",
                        confidence=0.95,
                        description=(
                            f"The page displays {brand_name} branding elements, but is hosted on '{target_domain}', "
                            f"which is NOT an authorized domain for {brand_name} (authorized: {', '.join(brand_info['domains'][:3])})."
                        ),
                        evidence={
                            "detector_type": "brand_mismatch",
                            "claimed_brand": brand_name,
                            "actual_domain": target_domain,
                            "authorized_domains": brand_info["domains"],
                            "brand_indicators": b_data["evidence"],
                        },
                        recommendation=f"Do NOT enter credentials or trust this website. It is an unauthorized impersonation of {brand_name}.",
                        risk_points=35,
                    )
                )

    has_brand_mismatch = len(brand_mismatches) > 0

    # =========================================================================
    # 1. PROCESS FORM FINDINGS
    # =========================================================================
    for rec in form_analysis_records:
        if not rec["is_login"]:
            continue

        idx = rec["idx"]
        form = rec["form"]
        inputs = rec["inputs"]
        input_field_summary = [inp.get("name") or inp.get("id") or inp.get("type", "text") for inp in inputs]
        all_harvested_inputs.extend(input_field_summary)

        evidence_data = {
            "detector_type": "credential_harvesting" if (has_brand_mismatch or rec["is_external_action"] or rec["is_suspicious_endpoint"]) else "login_form",
            "form_index": idx,
            "method": rec["form_method"],
            "action": rec["action_raw"] or "(empty/same-page)",
            "resolved_action": rec["action_resolved"],
            "input_fields": input_field_summary[:10],
            "has_username_field": rec["has_user_identifier"],
            "has_password_field": rec["has_password"],
            "is_external_action": rec["is_external_action"],
            "is_insecure_http": rec["is_insecure_http"],
        }

        # Vector 12: Credential-Harvesting Pattern (Brand mismatch + Login Form OR External Exfiltration)
        if rec["is_suspicious_endpoint"] or rec["is_external_action"] or has_brand_mismatch:
            has_credential_harvesting = True
            findings.append(
                ContentFindingSchema(
                    category="phishing",
                    title="Credential-harvesting form detected",
                    severity="critical" if (has_brand_mismatch or rec["is_suspicious_endpoint"]) else "high",
                    confidence=0.92,
                    description=(
                        f"The page contains an authentication form requesting credentials that either submits "
                        f"to an unauthorized external destination ('{rec['action_domain'] or rec['action_resolved']}') "
                        f"or is hosted on an unverified brand impersonation portal."
                    ),
                    evidence=evidence_data,
                    recommendation="Do not enter credentials on this website. The login form forwards authentication data to an untrusted endpoint.",
                    risk_points=35 if has_brand_mismatch else 25,
                    raw_data={"form_html": str(form)[:500]},
                )
            )
        elif rec["is_insecure_http"]:
            findings.append(
                ContentFindingSchema(
                    category="phishing",
                    title="Insecure HTTP credential submission detected",
                    severity="high",
                    confidence=0.90,
                    description=f"Form #{idx} submits login credentials over an unencrypted cleartext HTTP channel ('{rec['action_resolved']}').",
                    evidence=evidence_data,
                    recommendation="Never submit credentials over unencrypted HTTP. Interceptors can capture passwords in transit.",
                    risk_points=20,
                    raw_data={"form_html": str(form)[:500]},
                )
            )
        else:
            # Vector 1: Standard Login Form on legitimate/neutral domain
            findings.append(
                ContentFindingSchema(
                    category="phishing",
                    title="Login form detected",
                    severity="info",
                    confidence=0.85,
                    description="The page presents a user login form requesting authentication credentials.",
                    evidence=evidence_data,
                    recommendation="Verify that the address bar matches the authentic official domain before logging in.",
                    risk_points=5,
                    raw_data={"form_html": str(form)[:500]},
                )
            )

        # Vector 2: Standalone Password Field Finding (if password on suspicious page)
        if rec["has_password"] and (has_brand_mismatch or rec["is_external_action"]):
            findings.append(
                ContentFindingSchema(
                    category="phishing",
                    title="Password input field detected on suspicious page",
                    severity="high",
                    confidence=0.90,
                    description="The page solicits user account passwords on an unverified or mismatched domain.",
                    evidence={
                        "detector_type": "password_field",
                        "form_index": idx,
                        "fields": [inp.get("name") or inp.get("id") or "password" for inp in inputs if inp.get("type") == "password"],
                    },
                    recommendation="Do NOT enter passwords on unofficial or unrecognized web pages.",
                    risk_points=25,
                )
            )

    # =========================================================================
    # 3. OTP & 2FA FIELDS & 4. FINANCIAL & IDENTITY FIELDS (CARD, UPI, BANK, AADHAAR, PAN)
    # =========================================================================
    all_inputs = soup.find_all(["input", "select", "textarea"])
    hidden_inputs_count = 0
    hidden_field_names: List[str] = []

    otp_fields = []
    card_fields = []
    upi_fields = []
    bank_fields = []
    aadhaar_fields = []
    pan_fields = []

    for inp in all_inputs:
        itype = inp.get("type", "text").lower()
        name = inp.get("name", "").lower()
        iid = inp.get("id", "").lower()
        placeholder = inp.get("placeholder", "").lower()
        field_str = f"{name} {iid} {placeholder}"

        if itype == "hidden":
            hidden_inputs_count += 1
            if name or iid:
                hidden_field_names.append(name or iid)

        # OTP / 2FA check
        if any(term in field_str for term in ("otp", "2fa", "one-time", "passcode", "security_code", "verification_code", "totp", "mfa", "vcode")):
            otp_fields.append(name or iid or "otp_field")
            sensitive_fields.add("OTP / 2FA")

        # Payment card check
        if any(term in field_str for term in ("card_number", "cardnumber", "card_no", "cc_num", "cvv", "cvc", "exp_date", "expiry", "cardholder", "debit_card", "credit_card")):
            card_fields.append(name or iid or "card_field")
            sensitive_fields.add("Payment Card (PAN/CVV)")

        # UPI check
        if any(term in field_str for term in ("upi", "vpa", "upi_pin", "mpin", "bhim", "gpay", "phonepe", "paytm")):
            upi_fields.append(name or iid or "upi_field")
            sensitive_fields.add("UPI ID / PIN")

        # Bank Account & IFSC check
        if any(term in field_str for term in ("account_number", "account_no", "bank_account", "acc_no", "ifsc", "ifsc_code", "cif", "customer_id", "branch_code", "routing_number", "sort_code")):
            bank_fields.append(name or iid or "bank_account_field")
            sensitive_fields.add("Bank Account / IFSC")

        # Aadhaar check
        if any(term in field_str for term in ("aadhaar", "uidai", "aadhar", "adhar")):
            aadhaar_fields.append(name or iid or "aadhaar_field")
            sensitive_fields.add("Aadhaar Number")

        # PAN check
        if any(term in field_str for term in ("pan_number", "pancard", "pan_card", "permanent_account_number")):
            pan_fields.append(name or iid or "pan_field")
            sensitive_fields.add("PAN Number")

    # Vector 3: OTP Fields Finding
    if otp_fields:
        findings.append(
            ContentFindingSchema(
                category="phishing",
                title="One-Time Password (OTP) harvesting field detected",
                severity="high",
                confidence=0.90,
                description="The page contains input fields specifically designed to capture Second-Factor/OTP verification tokens.",
                evidence={
                    "detector_type": "otp_field",
                    "input_fields": otp_fields,
                },
                recommendation="Legitimate banks and services will never ask for your OTP via SMS links or unofficial portals.",
                risk_points=25,
            )
        )

    # Vector 4a: Payment Card Details
    if card_fields:
        findings.append(
            ContentFindingSchema(
                category="phishing",
                title="Payment card harvesting fields detected",
                severity="critical" if (has_brand_mismatch or has_login_form) else "high",
                confidence=0.92,
                description="The page requests confidential payment card numbers, expiration dates, or CVV security codes.",
                evidence={
                    "detector_type": "payment_card",
                    "input_fields": card_fields,
                },
                recommendation="Do not provide card information unless you independently verify the merchant/issuer URL.",
                risk_points=25,
            )
        )

    # Vector 4b: UPI / VPA / MPIN Details
    if upi_fields:
        findings.append(
            ContentFindingSchema(
                category="phishing",
                title="UPI PIN / VPA solicitation fields detected",
                severity="critical",
                confidence=0.92,
                description="Detected input fields soliciting UPI IDs, VPAs, or confidential UPI/MPIN credentials.",
                evidence={
                    "detector_type": "upi_field",
                    "input_fields": upi_fields,
                },
                recommendation="Remember: UPI PIN is ONLY required to send money or debit your account, never to receive rewards or payments.",
                risk_points=25,
            )
        )

    # Vector 4c: Bank Account & IFSC Details
    if bank_fields:
        findings.append(
            ContentFindingSchema(
                category="phishing",
                title="Bank account and IFSC code solicitation detected",
                severity="high",
                confidence=0.90,
                description="The page contains input fields requesting confidential bank account numbers, CIF tokens, or IFSC codes.",
                evidence={
                    "detector_type": "bank_account",
                    "input_fields": bank_fields,
                },
                recommendation="Verify your bank's official portal URL. Scammers use fake KYC portals to siphon account details.",
                risk_points=20,
            )
        )

    # Vector 4d: Aadhaar & PAN Government Identity Details
    if aadhaar_fields or pan_fields:
        combined_govid = aadhaar_fields + pan_fields
        findings.append(
            ContentFindingSchema(
                category="phishing",
                title="National identity number solicitation (Aadhaar / PAN)",
                severity="high",
                confidence=0.90,
                description="Detected input fields collecting sensitive Indian national identity numbers (Aadhaar and/or PAN).",
                evidence={
                    "detector_type": "government_id",
                    "input_fields": combined_govid,
                    "has_aadhaar": len(aadhaar_fields) > 0,
                    "has_pan": len(pan_fields) > 0,
                },
                recommendation="Never share Aadhaar or PAN details on unverified third-party websites.",
                risk_points=20,
            )
        )

    # Compound Decision 3: Aggregated Critical Finding if multiple sensitive categories coexist
    multi_vector_count = sum(1 for present in [bool(otp_fields), bool(card_fields), bool(upi_fields), bool(bank_fields), bool(aadhaar_fields or pan_fields)] if present)
    if multi_vector_count >= 2:
        findings.append(
            ContentFindingSchema(
                category="phishing",
                title="Multi-vector financial and identity credential harvesting detected",
                severity="critical",
                confidence=0.95,
                description=(
                    f"The page combines multiple high-risk credential harvesting mechanisms: "
                    f"{', '.join(sensitive_fields)}. This is a hallmark signature of an organized banking phishing attack."
                ),
                evidence={
                    "detector_type": "multi_vector_harvesting",
                    "sensitive_categories": list(sensitive_fields),
                    "total_sensitive_fields": len(otp_fields) + len(card_fields) + len(upi_fields) + len(bank_fields) + len(aadhaar_fields) + len(pan_fields),
                },
                recommendation="CRITICAL: Do NOT submit any data. This site is actively orchestrating identity theft and financial fraud.",
                risk_points=35,
            )
        )

    # =========================================================================
    # 5. PHISHING KEYWORDS & DECEPTIVE LURES
    # =========================================================================
    for pattern, title, pts in DECEPTIVE_URGENCY_KEYWORDS:
        match = re.search(pattern, page_text_lower, re.IGNORECASE)
        if match:
            matched_phrase = match.group(0)
            phishing_keywords_found.append(matched_phrase)
            findings.append(
                ContentFindingSchema(
                    category="phishing",
                    title=f"Phishing keyword detected: {title}",
                    severity="high" if pts >= 20 else "medium",
                    confidence=0.88,
                    description=f"Detected social engineering phrase: \"{matched_phrase}\", commonly deployed to manipulate victims into hasty compliance.",
                    evidence={
                        "detector_type": "phishing_keyword",
                        "matched_phrase": matched_phrase,
                        "pattern": pattern,
                    },
                    recommendation="Scammers frequently manufacture artificial urgency or panic. Verify requests through verified official channels.",
                    risk_points=pts,
                )
            )

    # Fake CAPTCHA / ClickFix Directive Check
    for pattern, title, pts in CLICKFIX_PATTERNS:
        match = re.search(pattern, page_text_lower, re.IGNORECASE) or re.search(pattern, html_raw_lower, re.IGNORECASE)
        if match:
            matched_text = match.group(0)
            findings.append(
                ContentFindingSchema(
                    category="phishing",
                    title=f"Malicious terminal lure detected: {title}",
                    severity="critical",
                    confidence=0.98,
                    description="The page attempts to deceive the user into executing a system terminal command or clipboard paste (ClickFix attack).",
                    evidence={
                        "detector_type": "clickfix_deception",
                        "matched_directive": matched_text,
                    },
                    recommendation="CRITICAL: Do NOT press Windows+R or paste clipboard contents into your terminal. This directly executes malware.",
                    risk_points=pts,
                )
            )

    # =========================================================================
    # 10. DECEPTIVE BUTTONS OR CALLS TO ACTION (CTAs)
    # =========================================================================
    interactive_elements = soup.find_all(["button", "a", "input"])
    for elem in interactive_elements:
        elem_text = ""
        if elem.name == "input" and elem.get("type") in ("submit", "button"):
            elem_text = elem.get("value", "")
        else:
            elem_text = elem.get_text()

        elem_text_clean = elem_text.strip().lower()
        if not elem_text_clean:
            continue

        for pattern, cta_title, pts in DECEPTIVE_CTA_PATTERNS:
            if re.search(pattern, elem_text_clean, re.IGNORECASE):
                # Escalate to 25 pts if on an unauthorized brand mismatch or page with forms
                elevated_pts = 25 if (has_brand_mismatch or has_login_form) else pts
                findings.append(
                    ContentFindingSchema(
                        category="phishing",
                        title=f"Deceptive call-to-action button detected: {cta_title}",
                        severity="high" if elevated_pts >= 25 else "medium",
                        confidence=0.88,
                        description=f"Detected high-urgency call-to-action button labeled \"{elem_text.strip()}\", typical of coercive phishing traps.",
                        evidence={
                            "detector_type": "deceptive_cta",
                            "button_text": elem_text.strip(),
                            "tag": elem.name,
                            "href_or_action": elem.get("href") or elem.get("action") or "(inline button)",
                        },
                        recommendation="Do not click deceptive action buttons. They often lead to malicious credential drains or download payloads.",
                        risk_points=elevated_pts,
                    )
                )
                break

    # =========================================================================
    # 7. SUSPICIOUS EXTERNAL SCRIPTS & IFRAMES
    # =========================================================================
    # External script inspection
    scripts = soup.find_all("script")
    for s_idx, script in enumerate(scripts, start=1):
        s_src = (script.get("src") or "").strip()
        if s_src:
            s_domain = get_base_domain(s_src)
            is_suspicious_script_host = any(s_domain.endswith(bad) or bad in s_src.lower() for bad in SUSPICIOUS_EXTERNAL_SCRIPT_DOMAINS)
            if is_suspicious_script_host:
                findings.append(
                    ContentFindingSchema(
                        category="phishing",
                        title="Suspicious external script source detected",
                        severity="high",
                        confidence=0.90,
                        description=f"Script #{s_idx} loads external code from an untrusted source or raw hosting service ('{s_src}').",
                        evidence={
                            "detector_type": "suspicious_script",
                            "script_src": s_src,
                            "script_domain": s_domain,
                        },
                        recommendation="External scripts from unauthorized CDNs or paste services can inject malicious form grabbers or stealers.",
                        risk_points=20,
                    )
                )

        # Vector 9: Obfuscated JavaScript Indicators
        s_content = script.string or script.text or ""
        for pattern, s_title, pts in SUSPICIOUS_SCRIPT_PATTERNS:
            if "oncontextmenu" not in pattern and "onselectstart" not in pattern and "onkeydown" not in pattern:
                if re.search(pattern, s_content, re.IGNORECASE):
                    suspicious_scripts.append(s_title)
                    findings.append(
                        ContentFindingSchema(
                            category="phishing",
                            title=f"Obfuscated JavaScript indicator: {s_title}",
                            severity="medium",
                            confidence=0.85,
                            description=f"Script #{s_idx} contains obfuscation techniques associated with dynamic payload unpacking or anti-analysis evasion.",
                            evidence={
                                "detector_type": "obfuscated_js",
                                "pattern": pattern,
                                "snippet": s_content[:120].strip(),
                            },
                            recommendation="Obfuscated client-side code is a frequent indicator of hostile or evasion behavior.",
                            risk_points=pts,
                        )
                    )

    # Anti-analysis event handlers (inline)
    for pattern, s_title, pts in SUSPICIOUS_SCRIPT_PATTERNS:
        if "oncontextmenu" in pattern or "onselectstart" in pattern or "onkeydown" in pattern:
            if re.search(pattern, html_raw_lower):
                suspicious_scripts.append(s_title)
                findings.append(
                    ContentFindingSchema(
                        category="phishing",
                        title=f"Anti-analysis evasion detected: {s_title}",
                        severity="medium",
                        confidence=0.90,
                        description="Detected inline event handlers preventing user inspection, right-click, or DevTools shortcut keys.",
                        evidence={
                            "detector_type": "obfuscated_js",
                            "pattern": pattern,
                        },
                        recommendation="Legitimate websites do not restrict browser inspect or text selection controls.",
                        risk_points=pts,
                    )
                )

    # Iframe inspection (zero dimension / clickjacking)
    iframes = soup.find_all("iframe")
    for if_idx, iframe in enumerate(iframes, start=1):
        width = iframe.get("width", "")
        height = iframe.get("height", "")
        style = (iframe.get("style") or "").lower()

        is_zero_dimension = width in ("0", "0px") or height in ("0", "0px") or "display:none" in style or "opacity:0" in style or "visibility:hidden" in style
        if is_zero_dimension:
            findings.append(
                ContentFindingSchema(
                    category="phishing",
                    title="Hidden or zero-dimension iframe detected",
                    severity="high",
                    confidence=0.90,
                    description=f"Iframe #{if_idx} is concealed using zero-dimension geometry or CSS visibility hiding, often used for stealth clickjacking or credential theft.",
                    evidence={
                        "detector_type": "suspicious_iframe",
                        "src": iframe.get("src", ""),
                        "style": style,
                        "width": width,
                        "height": height,
                    },
                    recommendation="Concealed iframes indicate covert activity running in the background.",
                    risk_points=20,
                )
            )

    # =========================================================================
    # 8. HIDDEN FORM FIELDS
    # =========================================================================
    if hidden_inputs_count >= 5:
        findings.append(
            ContentFindingSchema(
                category="phishing",
                title=f"Excessive hidden form fields detected ({hidden_inputs_count} fields)",
                severity="low" if hidden_inputs_count < 10 else "medium",
                confidence=0.80,
                description=f"The page embeds {hidden_inputs_count} hidden input tags, potentially passing tracking tokens or concealed parameters.",
                evidence={
                    "detector_type": "hidden_fields",
                    "hidden_count": hidden_inputs_count,
                    "field_names": hidden_field_names[:10],
                },
                recommendation="Monitor form submission targets for concealed exfiltration channels.",
                risk_points=10 if hidden_inputs_count >= 10 else 5,
            )
        )

    # =========================================================================
    # CALCULATE AGGREGATE RISK SCORE & SEVERITY
    # =========================================================================
    total_risk_points = min(100, sum(f.risk_points for f in findings))

    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    max_sev = "info"
    for f in findings:
        if severity_order.get(f.severity, 0) > severity_order.get(max_sev, 0):
            max_sev = f.severity

    # Construct descriptive summary
    if brand_mismatches and (has_login_form or sensitive_fields):
        summary = f"Dangerous Phishing Detected: Unauthorized website impersonating {', '.join(brand_mismatches)} to harvest sensitive user credentials."
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
