"""
TrustShield URL Normalization & SSRF Defense Pipeline
Provides comprehensive sanitization, defang removal, canonicalization,
domain/TLD segmentation, homoglyph detection, and strict SSRF blocking.
"""

from dataclasses import dataclass
from typing import Optional, Tuple, List, Set
import ipaddress
import posixpath
import re
import socket
from urllib.parse import urlsplit, urlunsplit, quote, unquote

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

# Common multi-part ccTLDs and second-level suffixes
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

# Cyrillic / Greek characters commonly used in IDN homoglyph spoofing
HOMOGLYPH_CYRILLIC_MAP = {
    "а": "a", "с": "c", "е": "e", "о": "o", "р": "p", "х": "x", "у": "y",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ԛ": "q", "ԝ": "w",
}


@dataclass
class NormalizedURL:
    """
    Structured outcome of URL validation, normalization, and domain breakdown.
    """
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
    fragment: Optional[str]
    is_ip: bool
    is_punycode: bool
    has_homoglyphs: bool
    unicode_host: str


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
    cleaned = re.sub(r"^hxxps?://", lambda m: "https://" if "s" in m.group(0).lower() else "http://", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"^h\*\*ps?://", lambda m: "https://" if "s" in m.group(0).lower() else "http://", cleaned, flags=re.IGNORECASE)
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
        ipaddress.ip_address(host)
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

    # Inspect for Cyrillic characters that mirror Latin characters
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
    if host_clean in BLOCKED_HOSTNAMES or host_clean.endswith(".localhost") or host_clean.endswith(".local") or host_clean.endswith(".internal"):
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
            # Query IPv4 and IPv6 addresses with a short timeout
            socket.setdefaulttimeout(1.5)
            addr_info = socket.getaddrinfo(host_clean, None)
            for item in addr_info:
                sockaddr = item[4]
                ip_str = sockaddr[0]
                try:
                    ip_obj = ipaddress.ip_address(ip_str)
                    is_blocked, reason = is_blocked_ip(ip_obj)
                    if is_blocked:
                        return False, f"SSRF Protection: Hostname '{host}' resolves to restricted internal IP {ip_str} ({reason})."
                except ValueError:
                    continue
        except (socket.gaierror, socket.timeout):
            # Domain failed to resolve via DNS; allow validation to proceed (will fail gracefully during network phase)
            pass
        except Exception as e:
            # Catch unexpected socket errors cleanly
            pass

    return True, None


# ---------------------------------------------------------------------------
# MAIN URL NORMALIZATION & VALIDATION ENGINE
# ---------------------------------------------------------------------------

def normalize_and_validate_url(
    raw_url: str,
    resolve_dns: bool = True,
) -> Tuple[Optional[NormalizedURL], Optional[str]]:
    """
    Validates, normalizes, and inspects an input URL.
    Returns:
      (NormalizedURL, None) on success.
      (None, error_message) on validation or SSRF failure.
    """
    if not raw_url or not isinstance(raw_url, str) or not raw_url.strip():
        return None, "Empty or invalid URL provided."

    # 1. Defang input
    clean_input = defang_url(raw_url)

    # 2. Ensure scheme exists; default to https if absent
    if "://" not in clean_input:
        # Check if user typed "http://example.com" or just "example.com"
        clean_input = f"https://{clean_input}"

    # 3. Parse with urlsplit
    try:
        parts = urlsplit(clean_input)
    except Exception as e:
        return None, f"Malformed URL syntax: {str(e)}"

    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        return None, (
            f"Unsupported URL scheme '{scheme}://'. "
            "TrustShield strictly analyzes web protocols ('http://' or 'https://'). "
            "File, FTP, Javascript, and Data schemes are blocked for security."
        )

    # Extract and clean netloc
    netloc = parts.netloc
    if not netloc:
        return None, "URL must contain a valid domain or host name."

    # Extract userinfo if present and strip it for safety (credentials in URL)
    if "@" in netloc:
        netloc = netloc.split("@")[-1]

    # Extract host and port
    host = netloc
    port: Optional[int] = None
    if ":" in netloc:
        # Handle IPv6 brackets [::1]:8080 vs host:port
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
        # Validate domain name characters
        if not re.match(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$|^[a-z0-9-]+$", host_clean):
            # Check for internationalized domain names (Punycode / IDN)
            try:
                host_clean.encode("ascii").decode("idna")
            except Exception:
                return None, f"Invalid domain character format in '{host_clean}'."

    # 4. Enforce strict SSRF safety
    is_safe, ssrf_error = check_ssrf_safety(host_clean, resolve_dns=resolve_dns)
    if not is_safe:
        return None, ssrf_error

    # 5. Extract domain segments & homoglyphs
    base_domain, subdomain, tld = extract_domain_parts(host_clean)
    is_punycode = "xn--" in host_clean
    has_homoglyphs, unicode_host = detect_homoglyphs(host_clean)

    # 6. Normalize path
    raw_path = parts.path
    if not raw_path:
        norm_path = "/"
    else:
        # Resolve '.' and '..' cleanly
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

    # 7. Construct final normalized URL
    query_str = parts.query if parts.query else None
    fragment_str = parts.fragment if parts.fragment else None

    normalized_url = urlunsplit((
        scheme,
        canon_netloc,
        norm_path,
        query_str or "",
        "",  # Strip URL fragment from backend scanning target
    ))

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
        fragment=fragment_str,
        is_ip=is_ip,
        is_punycode=is_punycode,
        has_homoglyphs=has_homoglyphs,
        unicode_host=unicode_host,
    )

    return result, None
