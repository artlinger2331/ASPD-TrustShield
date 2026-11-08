"""
TrustShield URL Normalization, Forensics & SSRF Defense Pipeline.

Provides production-grade sanitization, defang removal, canonicalization,
domain/TLD segmentation, homoglyph detection, heuristic threat extraction,
and strict SSRF blocking with hop-by-hop redirect tracing.
"""

from dataclasses import dataclass, field
from typing import Optional, Tuple, List, Set, Dict, Any
import ipaddress
import posixpath
import re
import socket
import time
from urllib.parse import urlsplit, urlunsplit, quote, unquote, parse_qs

# ---------------------------------------------------------------------------
# SSRF RESTRICTED IP NETWORKS
# ---------------------------------------------------------------------------

BLOCKED_IPV4_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # Current network ("this" host)
    ipaddress.ip_network("10.0.0.0/8"),         # RFC 1918 Private
    ipaddress.ip_network("100.64.0.0/10"),      # Shared Address Space (Carrier-Grade NAT)
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # Link-Local / Cloud Instance Metadata (AWS/GCP/Azure)
    ipaddress.ip_network("172.16.0.0/12"),      # RFC 1918 Private
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1 (RFC 5737)
    ipaddress.ip_network("192.168.0.0/16"),     # RFC 1918 Private
    ipaddress.ip_network("198.18.0.0/15"),      # Network Interconnect Device Benchmark
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2 (RFC 5737)
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3 (RFC 5737)
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved for future use
    ipaddress.ip_network("255.255.255.255/32"), # Limited Broadcast
]

BLOCKED_IPV6_NETWORKS = [
    ipaddress.ip_network("::/128"),             # Unspecified
    ipaddress.ip_network("::1/128"),           # Loopback
    ipaddress.ip_network("100::/64"),          # Discard prefix
    ipaddress.ip_network("2001:db8::/32"),     # Documentation
    ipaddress.ip_network("fc00::/7"),          # Unique Local Address (ULA / Private)
    ipaddress.ip_network("fe80::/10"),         # Link-Local Unicast
    ipaddress.ip_network("ff00::/8"),          # Multicast
]

BLOCKED_HOSTNAMES: Set[str] = {
    "localhost",
    "localhost.localdomain",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "metadata.google.internal",
    "instance-data",
}

# ---------------------------------------------------------------------------
# HEURISTIC KNOWLEDGE BASES
# ---------------------------------------------------------------------------

MULTI_PART_TLDS = {
    "co.uk", "org.uk", "me.uk", "gov.uk", "ac.uk", "ltd.uk",
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in", "gov.in", "edu.in", "ac.in", "res.in",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.za", "net.za", "org.za", "gov.za",
    "co.jp", "ne.jp", "or.jp", "go.jp", "ac.jp",
    "com.br", "net.br", "org.br", "gov.br",
    "com.cn", "net.cn", "org.cn", "gov.cn",
    "com.sg", "net.sg", "org.sg", "gov.sg",
    "com.mx", "org.mx", "gob.mx",
    "com.hk", "org.hk", "gov.hk",
    "com.tw", "org.tw", "gov.tw",
}

# Phishing and deceptive lure keywords
SUSPICIOUS_KEYWORDS = {
    "login", "verify", "secure", "update", "payment", "refund", "account",
    "recovery", "reward", "claim", "signin", "sign-in", "banking", "wallet",
    "kyc", "support", "confirm", "security", "authenticate", "credential",
    "passcode", "billing", "invoice", "auth", "validation", "unlock"
}

# Known URL shortener services
KNOWN_URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", "cutt.ly",
    "rb.gy", "shorturl.at", "rebrand.ly", "tiny.cc", "goo.gl", "bit.do",
    "adf.ly", "bc.vc", "shorte.st", "clck.ru", "s.id", "t.ly", "v.gd",
    "lnkd.in", "soo.gd", "qr.net", "1url.com", "hyperurl.co"
}

# High-abuse and suspicious top-level domains
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq",  # Legacy free domains frequently abused in phishing
    "top", "xyz", "work", "click", "loan", "buzz", "fit", "surf",
    "country", "kim", "stream", "gdn", "racing", "win", "bid", "vip",
    "men", "party", "date", "faith", "review", "accountant", "download",
    "quest", "live", "rest", "casa"
}

# Cyrillic / Greek characters commonly used in IDN homoglyph lookalike spoofing
HOMOGLYPH_CYRILLIC_MAP = {
    "а": "a", "с": "c", "е": "e", "о": "o", "р": "p", "х": "x", "у": "y",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ԛ": "q", "ԝ": "w",
    # Greek lookalikes
    "α": "a", "ο": "o", "ν": "v", "ρ": "p", "τ": "t", "υ": "u", "χ": "x",
}


# ---------------------------------------------------------------------------
# DATA STRUCTURES
# ---------------------------------------------------------------------------

@dataclass
class URLHeuristicFindings:
    """Detailed heuristic security indicators extracted from the URL."""
    is_ip: bool = False
    is_shortener: bool = False
    is_punycode: bool = False
    has_homoglyphs: bool = False
    has_excessive_subdomains: bool = False
    subdomain_count: int = 0
    has_suspicious_tld: bool = False
    has_embedded_credentials: bool = False
    is_overly_long: bool = False
    url_length: int = 0
    suspicious_keywords_found: List[str] = field(default_factory=list)
    heuristic_risk_score: int = 0
    findings_list: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class NormalizedURL:
    """Structured outcome of URL validation, normalization, and domain breakdown."""
    input_url: str
    normalized_url: str
    scheme: str
    host: str
    port: Optional[int]
    base_domain: str
    subdomain: Optional[str]
    tld: str
    path: str
    query: Optional[str]
    query_params: Dict[str, Any]
    fragment: Optional[str]
    is_ip: bool
    is_punycode: bool
    has_homoglyphs: bool
    unicode_host: str
    heuristics: URLHeuristicFindings = field(default_factory=URLHeuristicFindings)


@dataclass
class RedirectHopRecord:
    """Telemetry captured for a single redirect hop."""
    hop_number: int
    from_url: str
    to_url: str
    status_code: int
    latency_ms: Optional[float] = None


# ---------------------------------------------------------------------------
# DEFANGING & SANITIZATION HELPERS
# ---------------------------------------------------------------------------

def defang_url(url: str) -> str:
    """
    Reconstructs user-defanged or obfuscated URLs into standard syntax.
    Handles:
      - hxxp:// -> http://, hxxps:// -> https://
      - h**p:// -> http://, h**ps:// -> https://
      - [.] or (.) or {.} -> .
      - [:] -> :
      - Leading/trailing brackets, quotes, whitespace
    """
    cleaned = url.strip().strip("\"'<>[]()")

    # Normalize protocol defanging
    cleaned = re.sub(
        r"^hxxps?://",
        lambda m: "https://" if "s" in m.group(0).lower() else "http://",
        cleaned,
        flags=re.IGNORECASE,
    )
    cleaned = re.sub(
        r"^h\*\*ps?://",
        lambda m: "https://" if "s" in m.group(0).lower() else "http://",
        cleaned,
        flags=re.IGNORECASE,
    )
    cleaned = re.sub(r"^fxps?://", "ftp://", cleaned, flags=re.IGNORECASE)

    # Normalize dot defanging: [.] (.) {.} \. [dot]
    cleaned = re.sub(r"\[\.\]|\(\.\)|\{\.\}|\\\.|\s*\[dot\]\s*", ".", cleaned, flags=re.IGNORECASE)

    # Normalize colon defanging: [:] (:)
    cleaned = re.sub(r"\[\:\]|\(\:\)", ":", cleaned)

    return cleaned.strip()


def extract_domain_parts(host: str) -> Tuple[str, Optional[str], str]:
    """
    Segments a host into (base_domain, subdomain, tld).
    Handles multi-part suffixes like .co.uk, .gov.in, .com.au accurately.
    """
    # IP address: host is treated as base domain, no subdomain, tld is "ip"
    try:
        ipaddress.ip_address(host.strip("[]"))
        return host, None, "ip"
    except ValueError:
        pass

    labels = host.lower().split(".")
    if len(labels) == 1:
        return host, None, ""

    # Check for known multi-part TLD (e.g. co.uk, gov.in)
    if len(labels) >= 3:
        two_part_tld = f"{labels[-2]}.{labels[-1]}"
        if two_part_tld in MULTI_PART_TLDS:
            tld = two_part_tld
            base_domain = f"{labels[-3]}.{two_part_tld}"
            subdomain = ".".join(labels[:-3]) if len(labels) > 3 else None
            return base_domain, subdomain, tld

    # Standard single TLD
    tld = labels[-1]
    base_domain = f"{labels[-2]}.{labels[-1]}"
    subdomain = ".".join(labels[:-2]) if len(labels) > 2 else None
    return base_domain, subdomain, tld


def detect_homoglyphs(host: str) -> Tuple[bool, str]:
    """
    Detects if a domain uses mixed scripts or IDN homoglyphs to imitate known Latin words.
    Returns (has_homoglyphs, unicode_host).
    """
    unicode_host = host
    has_homoglyphs = False

    # Decode punycode if applicable
    if "xn--" in host.lower():
        try:
            unicode_host = host.encode("ascii").decode("idna")
        except Exception:
            unicode_host = host

    # Inspect for Cyrillic/Greek characters that mirror Latin characters
    for ch in unicode_host:
        if ch in HOMOGLYPH_CYRILLIC_MAP:
            has_homoglyphs = True
            break

    return has_homoglyphs, unicode_host


# ---------------------------------------------------------------------------
# SSRF VALIDATION
# ---------------------------------------------------------------------------

def is_blocked_ip(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> Tuple[bool, str]:
    """
    Checks if an IP address belongs to any RFC 1918, loopback, multicast, or metadata address.
    """
    # Handle IPv4-mapped IPv6 (e.g., ::ffff:127.0.0.1)
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
        ip_obj = ip_obj.ipv4_mapped

    if isinstance(ip_obj, ipaddress.IPv4Address):
        for net in BLOCKED_IPV4_NETWORKS:
            if ip_obj in net:
                return True, f"Blocked IPv4 range ({net}): {ip_obj}"
    elif isinstance(ip_obj, ipaddress.IPv6Address):
        for net in BLOCKED_IPV6_NETWORKS:
            if ip_obj in net:
                return True, f"Blocked IPv6 range ({net}): {ip_obj}"

    return False, ""


def check_ssrf_safety(host: str, resolve_dns: bool = True) -> Tuple[bool, Optional[str]]:
    """
    Verifies that a host is safe to scan and does not target internal services.
    Blocks:
      - Raw loopback / private IP addresses.
      - Cloud instance metadata addresses (e.g. 169.254.169.254).
      - Reserved domain aliases (localhost, *.local, internal).
      - Hostnames resolving to private/loopback IPs via DNS.
    """
    host_clean = host.strip("[]").lower()

    # 1. Check direct blocked hostnames
    if (
        host_clean in BLOCKED_HOSTNAMES
        or host_clean.endswith(".localhost")
        or host_clean.endswith(".local")
        or host_clean.endswith(".internal")
    ):
        return False, f"Prohibited local/internal hostname '{host}' blocked to protect infrastructure."

    # 2. Check if host is a literal IP address
    try:
        ip_obj = ipaddress.ip_address(host_clean)
        is_blocked, reason = is_blocked_ip(ip_obj)
        if is_blocked:
            return False, f"SSRF Protection: Direct scanning of private/restricted IP is blocked ({reason})."
        return True, None
    except ValueError:
        # Not a literal IP address, proceed to DNS validation if requested
        pass

    # 3. DNS resolution validation (DNS Rebinding & internal hostname resolution)
    if resolve_dns:
        try:
            socket.setdefaulttimeout(2.0)
            addr_info = socket.getaddrinfo(host_clean, None)
            for item in addr_info:
                sockaddr = item[4]
                ip_str = sockaddr[0]
                try:
                    ip_obj = ipaddress.ip_address(ip_str)
                    is_blocked, reason = is_blocked_ip(ip_obj)
                    if is_blocked:
                        return (
                            False,
                            f"SSRF Protection: Hostname '{host}' resolves to restricted internal IP {ip_str} ({reason}).",
                        )
                except ValueError:
                    continue
        except (socket.gaierror, socket.timeout):
            # Domain failed to resolve via DNS; allow validation to proceed
            pass
        except Exception:
            pass

    return True, None


# ---------------------------------------------------------------------------
# HEURISTIC FORENSIC DETECTOR
# ---------------------------------------------------------------------------

def detect_url_heuristics(
    raw_url: str,
    normalized_url: str,
    host: str,
    base_domain: str,
    subdomain: Optional[str],
    tld: str,
    path: str,
    query: Optional[str],
    is_ip: bool,
    is_punycode: bool,
    has_homoglyphs: bool,
    unicode_host: str,
    has_embedded_credentials: bool,
) -> URLHeuristicFindings:
    """
    Scans URL components for heuristic risk indicators, phishing keywords,
    deceptive formatting, shorteners, and suspicious TLDs.
    """
    findings_list: List[Dict[str, Any]] = []
    risk_score = 0
    url_length = len(raw_url)
    is_overly_long = url_length > 255

    # 1. IP-Based URL
    if is_ip:
        risk_score += 25
        findings_list.append({
            "category": "url_heuristics",
            "title": "IP-Based Target Authority",
            "severity": "high",
            "confidence": 0.95,
            "description": f"URL targets a direct IP address ({host}) rather than a registered domain name, commonly used in phishing campaigns to bypass domain reputation filters.",
            "evidence": {"host": host, "is_ip": True},
            "recommendation": "Legitimate business and banking services use branded domain names rather than raw IP addresses.",
            "risk_points": 25,
        })

    # 2. Known URL Shortener
    is_shortener = base_domain.lower() in KNOWN_URL_SHORTENERS
    if is_shortener:
        risk_score += 15
        findings_list.append({
            "category": "url_heuristics",
            "title": "Known URL Shortener Detected",
            "severity": "medium",
            "confidence": 0.90,
            "description": f"Domain '{base_domain}' is a URL redirection shortener, often used to obfuscate final destination URLs in malicious emails or messages.",
            "evidence": {"shortener_domain": base_domain},
            "recommendation": "Inspect the resolved destination URL before entering credentials or sensitive data.",
            "risk_points": 15,
        })

    # 3. Suspicious / High-Abuse TLD
    has_suspicious_tld = tld.lower() in SUSPICIOUS_TLDS
    if has_suspicious_tld:
        risk_score += 20
        findings_list.append({
            "category": "url_heuristics",
            "title": "Suspicious / High-Abuse Top-Level Domain",
            "severity": "medium",
            "confidence": 0.85,
            "description": f"Domain utilizes '.{tld}', a top-level domain frequently associated with automated throwaway domains and phishing kit hosting.",
            "evidence": {"tld": tld},
            "recommendation": "Exercise heightened scrutiny; verify the organization's official domain extension.",
            "risk_points": 20,
        })

    # 4. Punycode & Homoglyph Lookalike Spoofing
    if has_homoglyphs or is_punycode:
        risk_score += 35
        findings_list.append({
            "category": "url_heuristics",
            "title": "Internationalized Domain (IDN) Homoglyph Spoofing",
            "severity": "critical" if has_homoglyphs else "medium",
            "confidence": 0.95,
            "description": f"Domain uses Punycode ({host}) or lookalike characters ({unicode_host}) to visually mimic a legitimate Latin brand name.",
            "evidence": {
                "host": host,
                "unicode_host": unicode_host,
                "is_punycode": is_punycode,
                "has_homoglyphs": has_homoglyphs,
            },
            "recommendation": "Do not enter passwords or personal data; this URL exhibits deceptive visual mimicry.",
            "risk_points": 35,
        })

    # 5. Excessive Subdomains
    subdomain_labels = [s for s in (subdomain or "").split(".") if s]
    subdomain_count = len(subdomain_labels)
    has_excessive_subdomains = subdomain_count >= 3
    if has_excessive_subdomains:
        risk_score += 15
        findings_list.append({
            "category": "url_heuristics",
            "title": "Excessive Subdomain Stacking",
            "severity": "medium",
            "confidence": 0.85,
            "description": f"Domain contains {subdomain_count} nested subdomain labels ('{subdomain}'), a technique commonly used to display fake brand names while hosting on arbitrary domains.",
            "evidence": {"subdomain": subdomain, "label_count": subdomain_count},
            "recommendation": "Check the registered domain on the far right before the TLD.",
            "risk_points": 15,
        })

    # 6. Embedded Credentials / Userinfo Spoofing
    if has_embedded_credentials:
        risk_score += 30
        findings_list.append({
            "category": "url_heuristics",
            "title": "Deceptive Embedded Credentials in URL",
            "severity": "high",
            "confidence": 0.95,
            "description": "URL contains an '@' userinfo authority segment, used in phishing attacks to display a fake trusted domain before the '@' symbol while routing the browser to an attacker host.",
            "evidence": {"input_url": raw_url},
            "recommendation": "The domain displayed before the '@' symbol is disregarded by web browsers; you are being sent to the host after the '@'.",
            "risk_points": 30,
        })

    # 7. Overly Long URL
    if is_overly_long:
        risk_score += 10
        findings_list.append({
            "category": "url_heuristics",
            "title": "Abnormally Long URL Structure",
            "severity": "low",
            "confidence": 0.80,
            "description": f"URL length ({url_length} chars) exceeds standard web conventions (>255 chars), frequently observed in phishing links containing token exfiltration payloads or base64 parameters.",
            "evidence": {"url_length": url_length},
            "recommendation": "Inspect query parameters for suspicious redirects or encoded payload strings.",
            "risk_points": 10,
        })

    # 8. Phishing & Lure Keywords Detection
    # Inspect subdomains, path, and query strings
    text_to_search = f"{subdomain or ''} {path} {query or ''}".lower()
    # Normalize punctuation for clean tokenization
    tokens = set(re.findall(r"[a-z0-9_-]+", text_to_search))
    matched_keywords = sorted(list(tokens.intersection(SUSPICIOUS_KEYWORDS)))

    if matched_keywords:
        keyword_risk = min(30, len(matched_keywords) * 10)
        risk_score += keyword_risk
        findings_list.append({
            "category": "url_heuristics",
            "title": "Deceptive Phishing Keywords in URL",
            "severity": "high" if len(matched_keywords) >= 2 else "medium",
            "confidence": 0.85,
            "description": f"URL path or subdomain contains high-risk authentication lure keywords: {', '.join(matched_keywords)}.",
            "evidence": {"matched_keywords": matched_keywords, "matched_count": len(matched_keywords)},
            "recommendation": "Confirm you navigated to this login/verification portal directly from a trusted bookmark or app.",
            "risk_points": keyword_risk,
        })

    return URLHeuristicFindings(
        is_ip=is_ip,
        is_shortener=is_shortener,
        is_punycode=is_punycode,
        has_homoglyphs=has_homoglyphs,
        has_excessive_subdomains=has_excessive_subdomains,
        subdomain_count=subdomain_count,
        has_suspicious_tld=has_suspicious_tld,
        has_embedded_credentials=has_embedded_credentials,
        is_overly_long=is_overly_long,
        url_length=url_length,
        suspicious_keywords_found=matched_keywords,
        heuristic_risk_score=min(100, risk_score),
        findings_list=findings_list,
    )


# ---------------------------------------------------------------------------
# MAIN URL NORMALIZATION & VALIDATION ENGINE
# ---------------------------------------------------------------------------

def normalize_and_validate_url(
    raw_url: str,
    resolve_dns: bool = True,
) -> Tuple[Optional[NormalizedURL], Optional[str]]:
    """
    Validates, normalizes, inspects, and analyzes an input URL.
    Returns:
      (NormalizedURL, None) on success.
      (None, error_message) on validation or SSRF failure.
    """
    if not raw_url or not isinstance(raw_url, str) or not raw_url.strip():
        return None, "Empty or invalid URL provided."

    # Enforce maximum safe URL length limit (RFC 7230 / Web standards: 2048 chars)
    if len(raw_url.strip()) > 2048:
        return None, f"URL exceeds maximum permissible length of 2048 characters (received {len(raw_url.strip())} characters)."

    # 1. Defang input
    clean_input = defang_url(raw_url)

    # 2. Check for explicit URI scheme
    scheme_match = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*):", clean_input)
    if scheme_match:
        scheme_candidate = scheme_match.group(1).lower()
        if scheme_candidate in ("http", "https"):
            remainder = clean_input[len(scheme_candidate) + 1:].lstrip("/")
            clean_input = f"{scheme_candidate}://{remainder}"
        else:
            return None, (
                f"Unsupported URL scheme '{scheme_candidate}:'. "
                "TrustShield strictly analyzes web protocols ('http://' or 'https://'). "
                "File, FTP, Javascript, Data, and non-web schemes are blocked for security."
            )
    else:
        # No scheme specified at all; default to https://
        clean_input = f"https://{clean_input}"

    # 3. Parse with urlsplit
    try:
        parts = urlsplit(clean_input)
    except Exception as e:
        return None, f"Malformed URL syntax: {str(e)}"

    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        return None, (
            f"Unsupported URL scheme '{scheme}:'. "
            "TrustShield strictly analyzes web protocols ('http://' or 'https://'). "
            "File, FTP, Javascript, and Data schemes are blocked for security."
        )

    netloc = parts.netloc
    if not netloc:
        return None, "URL must contain a valid domain or host name."

    # 4. Extract userinfo if present (Embedded Credentials Detection)
    has_embedded_credentials = False
    if "@" in netloc:
        has_embedded_credentials = True
        # Strip userinfo for the safe normalized scanning target
        netloc = netloc.split("@")[-1]

    # Extract host and port
    host = netloc
    port: Optional[int] = None
    if ":" in netloc:
        if netloc.startswith("[") and "]" in netloc:
            closing_idx = netloc.rfind("]")
            host = netloc[:closing_idx + 1]
            port_str = netloc[closing_idx + 1:].lstrip(":")
            if port_str.isdigit():
                port = int(port_str)
        else:
            host_parts = netloc.split(":")
            host = host_parts[0]
            if len(host_parts) == 2 and host_parts[1].isdigit():
                port = int(host_parts[1])

    # Strip default ports
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        port = None

    # Canonicalize host
    host_clean = host.strip(".").lower()
    if not host_clean:
        return None, "Host name cannot be empty."

    # Validate host characters (must be valid domain or valid IP)
    is_ip = False
    try:
        ipaddress.ip_address(host_clean.strip("[]"))
        is_ip = True
    except ValueError:
        if not re.match(
            r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$|^[a-z0-9-]+$",
            host_clean,
        ):
            try:
                host_clean.encode("ascii").decode("idna")
            except Exception:
                return None, f"Invalid domain character format in '{host_clean}'."

    # 5. Enforce strict SSRF safety
    is_safe, ssrf_error = check_ssrf_safety(host_clean, resolve_dns=resolve_dns)
    if not is_safe:
        return None, ssrf_error

    # 6. Extract domain segments & homoglyphs
    base_domain, subdomain, tld = extract_domain_parts(host_clean)
    is_punycode = "xn--" in host_clean
    has_homoglyphs, unicode_host = detect_homoglyphs(host_clean)

    # 7. Normalize path
    raw_path = parts.path
    if not raw_path:
        norm_path = "/"
    else:
        norm_path = posixpath.normpath(unquote(raw_path))
        if raw_path.endswith("/") and not norm_path.endswith("/"):
            norm_path += "/"
        if not norm_path.startswith("/"):
            norm_path = f"/{norm_path}"
        norm_path = quote(norm_path, safe="/:@&=+$,-_.!~*'()")

    # Reconstruct canonical netloc
    canon_netloc = host_clean
    if port is not None:
        canon_netloc = f"{host_clean}:{port}"

    # 8. Query and Fragment parsing
    query_str = parts.query if parts.query else None
    fragment_str = parts.fragment if parts.fragment else None

    # Parse query parameters dictionary
    parsed_params: Dict[str, Any] = {}
    if query_str:
        raw_qs = parse_qs(query_str, keep_blank_values=True)
        for k, v in raw_qs.items():
            parsed_params[k] = v if len(v) > 1 else v[0]

    normalized_url = urlunsplit((
        scheme,
        canon_netloc,
        norm_path,
        query_str or "",
        "",  # Strip URL fragment from backend scanning target
    ))

    # 9. Extract deep heuristic threat findings
    heuristics = detect_url_heuristics(
        raw_url=raw_url,
        normalized_url=normalized_url,
        host=host_clean,
        base_domain=base_domain,
        subdomain=subdomain,
        tld=tld,
        path=norm_path,
        query=query_str,
        is_ip=is_ip,
        is_punycode=is_punycode,
        has_homoglyphs=has_homoglyphs,
        unicode_host=unicode_host,
        has_embedded_credentials=has_embedded_credentials,
    )

    result = NormalizedURL(
        input_url=raw_url,
        normalized_url=normalized_url,
        scheme=scheme,
        host=host_clean,
        port=port,
        base_domain=base_domain,
        subdomain=subdomain,
        tld=tld,
        path=norm_path,
        query=query_str,
        query_params=parsed_params,
        fragment=fragment_str,
        is_ip=is_ip,
        is_punycode=is_punycode,
        has_homoglyphs=has_homoglyphs,
        unicode_host=unicode_host,
        heuristics=heuristics,
    )

    return result, None


# ---------------------------------------------------------------------------
# SSRF-SAFE STEP-BY-STEP REDIRECT TRACER
# ---------------------------------------------------------------------------

async def trace_redirects_safely_async(
    start_url: str,
    max_hops: int = 5,
    timeout: float = 5.0,
) -> Tuple[str, List[RedirectHopRecord], Optional[str]]:
    """
    Safely follows and audits HTTP/HTTPS redirects one hop at a time.
    Validates each hop destination against SSRF rules before making the request.
    Returns:
      (final_url, list_of_hops, error_message)
    """
    import httpx
    from urllib.parse import urljoin

    current_url = start_url
    hops: List[RedirectHopRecord] = []

    # Safe inspection headers
    headers = {
        "User-Agent": "TrustShield-Security-Auditor/1.0 (+https://trustshield.local/bot)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    try:
        async with httpx.AsyncClient(
            headers=headers,
            timeout=timeout,
            follow_redirects=False,  # Enforce manual single-hop inspection
            verify=False,           # Inspect phishing targets with self-signed certs
        ) as client:
            for hop_idx in range(1, max_hops + 1):
                # Validate current URL before request
                norm, err = normalize_and_validate_url(current_url, resolve_dns=True)
                if err or norm is None:
                    return current_url, hops, f"Redirect hop {hop_idx} blocked: {err}"

                t_start = time.perf_counter()
                try:
                    resp = await client.get(current_url)
                except httpx.RequestError as exc:
                    return current_url, hops, f"Network error during hop {hop_idx}: {str(exc)}"

                latency_ms = round((time.perf_counter() - t_start) * 1000, 2)

                # Check if this response is a redirect
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("location")
                    if not location:
                        break  # Redirect without Location header

                    next_url = urljoin(current_url, location)
                    hops.append(RedirectHopRecord(
                        hop_number=hop_idx,
                        from_url=current_url,
                        to_url=next_url,
                        status_code=resp.status_code,
                        latency_ms=latency_ms,
                    ))
                    current_url = next_url
                else:
                    # Final landing page reached
                    break

            return current_url, hops, None
    except Exception as exc:
        return current_url, hops, f"Unexpected error during redirect tracing: {str(exc)}"


def trace_redirects_safely_sync(
    start_url: str,
    max_hops: int = 5,
    timeout: float = 5.0,
) -> Tuple[str, List[RedirectHopRecord], Optional[str]]:
    """
    Synchronous wrapper for safe step-by-step redirect tracing.
    """
    import asyncio
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                return pool.submit(
                    asyncio.run,
                    trace_redirects_safely_async(start_url, max_hops, timeout),
                ).result()
        else:
            return loop.run_until_complete(
                trace_redirects_safely_async(start_url, max_hops, timeout)
            )
    except RuntimeError:
        return asyncio.run(trace_redirects_safely_async(start_url, max_hops, timeout))


def save_url_heuristic_findings_to_db_sync(
    scan_id: Any,
    findings: List[Dict[str, Any]],
    db: Any,
) -> List[Any]:
    """
    Synchronously persists URL heuristic findings into the scan_findings table.
    """
    from app.models.scan_finding import ScanFinding
    db_records = []
    for f in findings:
        record = ScanFinding(
            scan_id=scan_id,
            category=f.get("category", "url_heuristics"),
            title=f.get("title", "URL Heuristic Alert"),
            severity=f.get("severity", "medium"),
            confidence=f.get("confidence", 0.85),
            description=f.get("description", ""),
            evidence=f.get("evidence") or {},
            recommendation=f.get("recommendation"),
            risk_points=f.get("risk_points", 15),
            raw_data=f.get("raw_data") or {},
        )
        db.add(record)
        db_records.append(record)
    if db_records:
        db.commit()
    return db_records

