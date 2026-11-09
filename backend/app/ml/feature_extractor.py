"""
<<<<<<< HEAD
Feature extraction service for URLs in TrustShield ML classification.
Converts a URL and optional scan metadata into:
1. A human-readable feature dictionary with explanatory descriptions and suspicious flags.
2. A fixed numerical feature vector aligned with a versioned feature schema (v1.0.0).
"""

from collections import Counter
from dataclasses import asdict, dataclass
import ipaddress
import json
import math
from pathlib import Path
=======
Feature extraction service for URLs in TrustShield.
Extracts 42 lexical, structural, keyword, domain/DNS, and redirect features
with a stable, versioned schema (v1.0.0).
"""

from collections import Counter
from dataclasses import dataclass
import ipaddress
import math
>>>>>>> 9b735eb99fcfab11611f7f8da03c77f43357eb91
import re
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import parse_qs, urlparse


@dataclass(frozen=True)
class FeatureDefinition:
    name: str
    feature_type: str  # "int" or "float"
    description: str
    default_value: Union[int, float]
<<<<<<< HEAD
    category: str  # "lexical", "structural", "keyword", "domain", "reputation"


@dataclass
class HumanReadableFeature:
    name: str
    value: Union[int, float]
    category: str
    description: str
    is_suspicious: bool

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ExtractedFeatureReport:
    url: str
    schema_version: str
    feature_count: int
    features: Dict[str, HumanReadableFeature]
    numerical_vector: List[float]
    summary_flags: Dict[str, bool]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "schema_version": self.schema_version,
            "feature_count": self.feature_count,
            "features": {k: v.to_dict() for k, v in self.features.items()},
            "numerical_vector": self.numerical_vector,
            "summary_flags": self.summary_flags,
        }


SUSPICIOUS_KEYWORDS = [
=======
    category: str  # "lexical", "structural", "keyword", "domain_dns", "redirect_http"


SENSITIVE_KEYWORDS = [
>>>>>>> 9b735eb99fcfab11611f7f8da03c77f43357eb91
    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "security",
    "account",
    "update",
    "banking",
    "bank",
    "password",
    "auth",
    "authenticate",
    "confirm",
    "confirmation",
    "service",
    "support",
    "wallet",
    "credential",
    "billing",
    "invoice",
<<<<<<< HEAD
    "recover",
    "recovery",
=======
>>>>>>> 9b735eb99fcfab11611f7f8da03c77f43357eb91
]

TARGETED_BRANDS = [
    "paypal",
    "google",
    "apple",
    "microsoft",
    "amazon",
    "facebook",
    "netflix",
    "wellsfargo",
    "chase",
    "bankofamerica",
    "binance",
    "coinbase",
    "metamask",
    "instagram",
    "twitter",
    "yahoo",
    "outlook",
<<<<<<< HEAD
    "steam",
    "dropbox",
=======
>>>>>>> 9b735eb99fcfab11611f7f8da03c77f43357eb91
]

SUSPICIOUS_TLDS = {
    ".xyz",
    ".top",
    ".buzz",
    ".club",
    ".work",
    ".loan",
    ".cam",
    ".cfd",
    ".sbs",
    ".quest",
    ".icu",
    ".gq",
    ".ml",
    ".cf",
    ".tk",
    ".ga",
    ".monster",
    ".fit",
    ".rest",
<<<<<<< HEAD
    ".country",
    ".stream",
=======
}

COMMON_TLDS = {
    ".com",
    ".net",
    ".org",
    ".info",
    ".biz",
    ".co",
    ".io",
    ".app",
    ".dev",
    ".me",
    ".cc",
    ".online",
    ".site",
>>>>>>> 9b735eb99fcfab11611f7f8da03c77f43357eb91
}

KNOWN_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "adf.ly",
    "bitly.com",
    "cutt.ly",
    "rb.gy",
    "shorturl.at",
}

<<<<<<< HEAD
SPECIAL_CHAR_REGEX = re.compile(r"[@_!$&*%+=?#~;,\^]")
REPEATING_CHAR_REGEX = re.compile(r"(.)\1*")


FEATURE_DEFINITIONS_V1: List[FeatureDefinition] = [
    FeatureDefinition("url_length", "int", "Total character length of the URL", 0, "lexical"),
    FeatureDefinition("domain_length", "int", "Character length of the domain/hostname", 0, "lexical"),
    FeatureDefinition("num_dots", "int", "Count of dots in URL", 0, "lexical"),
    FeatureDefinition("num_hyphens", "int", "Count of hyphens in URL", 0, "lexical"),
    FeatureDefinition("num_digits", "int", "Count of numeric digits in URL", 0, "lexical"),
    FeatureDefinition("num_special_chars", "int", "Count of special characters (@, _, %, =, ?, etc.)", 0, "lexical"),
    FeatureDefinition("num_subdomains", "int", "Number of subdomains excluding domain and TLD", 0, "structural"),
    FeatureDefinition("domain_age_days", "int", "Domain registration age in days from WHOIS, or -1 if unknown", -1, "domain"),
    FeatureDefinition("has_ip_address", "int", "1 if host is an IPv4 or IPv6 address literal else 0", 0, "structural"),
    FeatureDefinition("uses_https", "int", "1 if scheme is HTTPS else 0", 0, "structural"),
    FeatureDefinition("suspicious_keyword_count", "int", "Occurrences of phishing and credential keywords", 0, "keyword"),
    FeatureDefinition("brand_keyword_count", "int", "Count of high-target brand names in domain/subdomains", 0, "keyword"),
    FeatureDefinition("suspicious_tld", "int", "1 if domain extension is a high-abuse TLD else 0", 0, "reputation"),
    FeatureDefinition("is_url_shortener", "int", "1 if hostname is a known URL shortening service else 0", 0, "reputation"),
    FeatureDefinition("redirect_count", "int", "Number of HTTP redirection hops, or 0", 0, "structural"),
    FeatureDefinition("domain_entropy", "float", "Shannon entropy of the domain string", 0.0, "lexical"),
    FeatureDefinition("char_repetition_max", "int", "Maximum consecutive identical character run length", 1, "lexical"),
    FeatureDefinition("path_depth", "int", "Directory nesting depth in URL path", 0, "structural"),
    FeatureDefinition("query_param_count", "int", "Number of query parameters in query string", 0, "structural"),
    FeatureDefinition("has_embedded_credentials", "int", "1 if user:password@ credentials present in URL else 0", 0, "structural"),
=======

FEATURE_DEFINITIONS_V1: List[FeatureDefinition] = [
    # Lexical (1-16)
    FeatureDefinition("url_length", "int", "Total character length of the URL", 0, "lexical"),
    FeatureDefinition("hostname_length", "int", "Length of the hostname", 0, "lexical"),
    FeatureDefinition("path_length", "int", "Length of the path component", 0, "lexical"),
    FeatureDefinition("query_length", "int", "Length of the query string", 0, "lexical"),
    FeatureDefinition("num_dots", "int", "Number of dots in full URL", 0, "lexical"),
    FeatureDefinition("num_hyphens", "int", "Number of hyphens in full URL", 0, "lexical"),
    FeatureDefinition("num_underscores", "int", "Number of underscores in full URL", 0, "lexical"),
    FeatureDefinition("num_slashes", "int", "Number of forward slashes in full URL", 0, "lexical"),
    FeatureDefinition("num_question_marks", "int", "Number of question marks in full URL", 0, "lexical"),
    FeatureDefinition("num_equal_signs", "int", "Number of equal signs in full URL", 0, "lexical"),
    FeatureDefinition("num_at_symbols", "int", "Number of @ symbols in full URL", 0, "lexical"),
    FeatureDefinition("num_percent_signs", "int", "Number of % signs in full URL (hex obfuscation)", 0, "lexical"),
    FeatureDefinition("num_digits", "int", "Count of numeric digits in full URL", 0, "lexical"),
    FeatureDefinition("digit_ratio", "float", "Ratio of digits to URL length", 0.0, "lexical"),
    FeatureDefinition("uppercase_ratio", "float", "Ratio of uppercase letters to URL length", 0.0, "lexical"),
    FeatureDefinition("vowel_ratio", "float", "Ratio of vowels in hostname", 0.0, "lexical"),
    # Structural (17-26)
    FeatureDefinition("url_entropy", "float", "Shannon entropy of full URL", 0.0, "structural"),
    FeatureDefinition("hostname_entropy", "float", "Shannon entropy of hostname", 0.0, "structural"),
    FeatureDefinition("is_ip_address", "int", "1 if hostname is IPv4/IPv6 literal else 0", 0, "structural"),
    FeatureDefinition("has_custom_port", "int", "1 if custom port specified (not 80/443) else 0", 0, "structural"),
    FeatureDefinition("num_subdomains", "int", "Number of subdomains excluding domain & TLD", 0, "structural"),
    FeatureDefinition("num_query_params", "int", "Number of query parameters", 0, "structural"),
    FeatureDefinition("is_https", "int", "1 if protocol is HTTPS else 0", 0, "structural"),
    FeatureDefinition("path_depth", "int", "Directory depth in URL path", 0, "structural"),
    FeatureDefinition("has_double_slash_in_path", "int", "1 if path contains // else 0", 0, "structural"),
    FeatureDefinition("has_punycode", "int", "1 if hostname contains xn-- punycode else 0", 0, "structural"),
    # Keywords (27-30)
    FeatureDefinition("sensitive_word_count", "int", "Occurrences of phishing keywords in URL", 0, "keyword"),
    FeatureDefinition("brand_in_subdomain", "int", "1 if recognized brand appears in subdomain else 0", 0, "keyword"),
    FeatureDefinition("suspicious_tld", "int", "1 if domain uses a high-abuse TLD else 0", 0, "keyword"),
    FeatureDefinition("tld_in_path", "int", "1 if common TLD appears inside URL path else 0", 0, "keyword"),
    # Domain & DNS (31-37)
    FeatureDefinition("domain_age_days", "int", "Domain age in days from WHOIS, or -1 if unknown", -1, "domain_dns"),
    FeatureDefinition("days_to_expiry", "int", "Days remaining until domain expiration, or -1", -1, "domain_dns"),
    FeatureDefinition("is_private_whois", "int", "1 if WHOIS privacy guard detected else 0", 0, "domain_dns"),
    FeatureDefinition("num_dns_records", "int", "Total resolved DNS resource records", 0, "domain_dns"),
    FeatureDefinition("has_mx_records", "int", "1 if domain has MX records else 0", 0, "domain_dns"),
    FeatureDefinition("has_txt_records", "int", "1 if domain has TXT records else 0", 0, "domain_dns"),
    FeatureDefinition("ttl_value", "int", "DNS TTL in seconds, or -1 if unknown", -1, "domain_dns"),
    # Redirect & HTTP (38-42)
    FeatureDefinition("redirect_count", "int", "Number of HTTP redirects encountered", 0, "redirect_http"),
    FeatureDefinition("has_cross_domain_redirect", "int", "1 if redirects cross registered domains else 0", 0, "redirect_http"),
    FeatureDefinition("uses_shortener", "int", "1 if domain is a known URL shortener else 0", 0, "redirect_http"),
    FeatureDefinition("http_status_code", "int", "HTTP status code of final landing response", 200, "redirect_http"),
    FeatureDefinition("response_time_ms", "float", "Total HTTP response latency in ms, or -1.0", -1.0, "redirect_http"),
>>>>>>> 9b735eb99fcfab11611f7f8da03c77f43357eb91
]


class FeatureSchemaV1:
    """Versioned schema v1.0.0 for URL classification features."""

    VERSION = "v1.0.0"
    FEATURE_DEFINITIONS = FEATURE_DEFINITIONS_V1
    FEATURE_NAMES = [f.name for f in FEATURE_DEFINITIONS_V1]
    _MAP = {f.name: f for f in FEATURE_DEFINITIONS_V1}

    @classmethod
    def get_feature(cls, name: str) -> Optional[FeatureDefinition]:
        return cls._MAP.get(name)

    @classmethod
    def feature_count(cls) -> int:
        return len(cls.FEATURE_DEFINITIONS)

    @classmethod
    def feature_names(cls) -> List[str]:
        return list(cls.FEATURE_NAMES)

    @classmethod
    def validate_features_dict(cls, features: Dict[str, Any]) -> bool:
        """Verifies that all required features are present."""
        return all(name in features for name in cls.FEATURE_NAMES)

<<<<<<< HEAD
    @classmethod
    def to_dict(cls) -> Dict[str, Any]:
        return {
            "version": cls.VERSION,
            "feature_count": cls.feature_count(),
            "features": [asdict(f) for f in cls.FEATURE_DEFINITIONS],
        }

    @classmethod
    def export_schema_json(cls, path: Optional[Union[str, Path]] = None) -> str:
        data = cls.to_dict()
        json_str = json.dumps(data, indent=2)
        if path:
            out_path = Path(path)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(json_str)
        return json_str

=======
>>>>>>> 9b735eb99fcfab11611f7f8da03c77f43357eb91

def calculate_shannon_entropy(text: str) -> float:
    """Calculates the Shannon entropy (bits per symbol) of a string."""
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    return round(entropy, 4)


<<<<<<< HEAD
def extract_max_char_repetition(text: str) -> int:
    """Finds the maximum consecutive identical character run length in text."""
    if not text:
        return 0
    runs = [len(match.group(0)) for match in REPEATING_CHAR_REGEX.finditer(text)]
    return max(runs) if runs else 1


=======
>>>>>>> 9b735eb99fcfab11611f7f8da03c77f43357eb91
def is_ip_host(host: str) -> bool:
    """Checks whether the hostname is an IPv4 or IPv6 address literal."""
    if not host:
        return False
<<<<<<< HEAD
    clean_host = host.strip("[]")
    if ":" in clean_host and clean_host.count(":") == 1:
=======
    # Strip port if present or brackets for IPv6
    clean_host = host.strip("[]")
    if ":" in clean_host and not clean_host.count(":") > 1:
>>>>>>> 9b735eb99fcfab11611f7f8da03c77f43357eb91
        clean_host = clean_host.split(":")[0]
    try:
        ipaddress.ip_address(clean_host)
        return True
    except ValueError:
        return False


def parse_subdomain_parts(hostname: str) -> Tuple[List[str], str, str]:
    """
    Parses hostname into (subdomains, second_level_domain, top_level_domain).
<<<<<<< HEAD
=======
    Fallback heuristic when public suffix list is not loaded.
>>>>>>> 9b735eb99fcfab11611f7f8da03c77f43357eb91
    """
    if not hostname or is_ip_host(hostname):
        return [], hostname, ""

    parts = hostname.lower().split(".")
    if len(parts) <= 1:
        return [], hostname, ""
    if len(parts) == 2:
        return [], parts[0], "." + parts[1]

<<<<<<< HEAD
=======
    # Handle multi-part ccTLDs like .co.uk, .com.au, .gov.in
>>>>>>> 9b735eb99fcfab11611f7f8da03c77f43357eb91
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in {"co", "com", "gov", "org", "net", "edu", "ac"}:
        tld = f".{parts[-2]}.{parts[-1]}"
        sld = parts[-3]
        subdomains = parts[:-3]
    else:
        tld = "." + parts[-1]
        sld = parts[-2]
        subdomains = parts[:-2]

    return subdomains, sld, tld


def extract_features(
    url: str,
<<<<<<< HEAD
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Union[int, float]]:
    """
    Extracts the 20 numerical features from a URL and optional scan metadata.
    Provides safe, deterministic offline fallbacks for all values.
    """
    metadata = metadata or {}
    raw_url = str(url or "").strip()

    parse_target = raw_url
    if parse_target and not (parse_target.startswith("http://") or parse_target.startswith("https://") or "://" in parse_target):
=======
    context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Union[int, float]]:
    """
    Extracts 42 features from a URL string and optional scan context.
    All features have safe deterministic defaults when context is omitted.
    """
    context = context or {}
    raw_url = str(url or "").strip()

    # Prepend scheme if missing so urlparse behaves consistently
    parse_target = raw_url
    if parse_target and not (parse_target.startswith("http://") or parse_target.startswith("https://")):
>>>>>>> 9b735eb99fcfab11611f7f8da03c77f43357eb91
        parse_target = "http://" + parse_target

    parsed = urlparse(parse_target)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    scheme = parsed.scheme.lower() if parsed.scheme else ""

    url_len = len(raw_url)
<<<<<<< HEAD
    domain_len = len(hostname)

    num_dots = raw_url.count(".")
    num_hyphens = raw_url.count("-")
    num_digits = sum(c.isdigit() for c in raw_url)
    num_special_chars = len(SPECIAL_CHAR_REGEX.findall(raw_url))
=======
    host_len = len(hostname)
    path_len = len(path)
    query_len = len(query)

    # 1. Lexical features
    num_dots = raw_url.count(".")
    num_hyphens = raw_url.count("-")
    num_underscores = raw_url.count("_")
    num_slashes = raw_url.count("/")
    num_question_marks = raw_url.count("?")
    num_equal_signs = raw_url.count("=")
    num_at_symbols = raw_url.count("@")
    num_percent_signs = raw_url.count("%")
    num_digits = sum(c.isdigit() for c in raw_url)

    digit_ratio = round(num_digits / max(url_len, 1), 4)
    uppercase_ratio = round(sum(c.isupper() for c in raw_url) / max(url_len, 1), 4)

    vowel_count = sum(1 for c in hostname if c in "aeiou")
    vowel_ratio = round(vowel_count / max(host_len, 1), 4)

    # 2. Structural features
    url_entropy = calculate_shannon_entropy(raw_url)
    hostname_entropy = calculate_shannon_entropy(hostname)
    is_ip = 1 if is_ip_host(hostname) else 0

    has_custom_port = 0
    if parsed.port and parsed.port not in (80, 443):
        has_custom_port = 1
>>>>>>> 9b735eb99fcfab11611f7f8da03c77f43357eb91

    subdomains, sld, tld = parse_subdomain_parts(hostname)
    num_subdomains = len(subdomains)

<<<<<<< HEAD
    domain_age_days = int(metadata.get("domain_age_days", -1))
    has_ip = 1 if is_ip_host(hostname) else 0
    uses_https = 1 if scheme == "https" else 0

    lower_url = raw_url.lower()
    suspicious_keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in lower_url)
    brand_count = sum(1 for brand in TARGETED_BRANDS if brand in hostname)

    suspicious_tld_flag = 1 if any(hostname.endswith(stld) for stld in SUSPICIOUS_TLDS) else 0
    is_shortener = 1 if (hostname in KNOWN_SHORTENERS or metadata.get("is_shortener") or metadata.get("uses_shortener")) else 0

    redirect_count = int(metadata.get("redirect_count", 0))
    domain_entropy = calculate_shannon_entropy(hostname)
    char_repetition_max = extract_max_char_repetition(raw_url)

    clean_path_segments = [seg for seg in path.strip("/").split("/") if seg]
    path_depth = len(clean_path_segments)
    num_query_params = len(parse_qs(query))

    has_credentials = 0
    if parsed.username or parsed.password:
        has_credentials = 1
    elif "@" in parsed.netloc:
        has_credentials = 1
    elif "@" in raw_url.split("?")[0].split("#")[0]:
        has_credentials = 1

    features: Dict[str, Union[int, float]] = {
        "url_length": url_len,
        "domain_length": domain_len,
        "num_dots": num_dots,
        "num_hyphens": num_hyphens,
        "num_digits": num_digits,
        "num_special_chars": num_special_chars,
        "num_subdomains": num_subdomains,
        "domain_age_days": domain_age_days,
        "has_ip_address": has_ip,
        "uses_https": uses_https,
        "suspicious_keyword_count": suspicious_keyword_count,
        "brand_keyword_count": brand_count,
        "suspicious_tld": suspicious_tld_flag,
        "is_url_shortener": is_shortener,
        "redirect_count": redirect_count,
        "domain_entropy": domain_entropy,
        "char_repetition_max": char_repetition_max,
        "path_depth": path_depth,
        "query_param_count": num_query_params,
        "has_embedded_credentials": has_credentials,
=======
    parsed_qs = parse_qs(query)
    num_query_params = len(parsed_qs)

    is_https = 1 if scheme == "https" else 0
    clean_path_segments = [seg for seg in path.strip("/").split("/") if seg]
    path_depth = len(clean_path_segments)
    has_double_slash_in_path = 1 if "//" in path else 0
    has_punycode = 1 if "xn--" in hostname else 0

    # 3. Keyword and brand features
    lower_url = raw_url.lower()
    sensitive_word_count = sum(1 for kw in SENSITIVE_KEYWORDS if kw in lower_url)

    brand_in_sub = 0
    for brand in TARGETED_BRANDS:
        if any(brand in sub for sub in subdomains):
            brand_in_sub = 1
            break

    suspicious_tld_flag = 0
    for stld in SUSPICIOUS_TLDS:
        if hostname.endswith(stld):
            suspicious_tld_flag = 1
            break

    tld_in_path_flag = 0
    lower_path = path.lower()
    for tld_marker in (COMMON_TLDS | SUSPICIOUS_TLDS):
        if tld_marker in lower_path:
            tld_in_path_flag = 1
            break

    # Shortener detection
    is_shortener = 0
    if hostname in KNOWN_SHORTENERS or context.get("uses_shortener"):
        is_shortener = 1

    # 4. Domain & DNS features (with safe context fallbacks)
    domain_age_days = int(context.get("domain_age_days", -1))
    days_to_expiry = int(context.get("days_to_expiry", -1))
    is_private_whois = int(bool(context.get("is_private_whois", 0)))
    num_dns_records = int(context.get("num_dns_records", 0))
    has_mx_records = int(bool(context.get("has_mx_records", 0)))
    has_txt_records = int(bool(context.get("has_txt_records", 0)))
    ttl_value = int(context.get("ttl_value", -1))

    # 5. Redirect & HTTP features (with safe context fallbacks)
    redirect_count = int(context.get("redirect_count", 0))
    has_cross_domain_redirect = int(bool(context.get("has_cross_domain_redirect", 0)))
    http_status_code = int(context.get("http_status_code", 200))
    response_time_ms = float(context.get("response_time_ms", -1.0))

    features: Dict[str, Union[int, float]] = {
        # Lexical
        "url_length": url_len,
        "hostname_length": host_len,
        "path_length": path_len,
        "query_length": query_len,
        "num_dots": num_dots,
        "num_hyphens": num_hyphens,
        "num_underscores": num_underscores,
        "num_slashes": num_slashes,
        "num_question_marks": num_question_marks,
        "num_equal_signs": num_equal_signs,
        "num_at_symbols": num_at_symbols,
        "num_percent_signs": num_percent_signs,
        "num_digits": num_digits,
        "digit_ratio": digit_ratio,
        "uppercase_ratio": uppercase_ratio,
        "vowel_ratio": vowel_ratio,
        # Structural
        "url_entropy": url_entropy,
        "hostname_entropy": hostname_entropy,
        "is_ip_address": is_ip,
        "has_custom_port": has_custom_port,
        "num_subdomains": num_subdomains,
        "num_query_params": num_query_params,
        "is_https": is_https,
        "path_depth": path_depth,
        "has_double_slash_in_path": has_double_slash_in_path,
        "has_punycode": has_punycode,
        # Keywords
        "sensitive_word_count": sensitive_word_count,
        "brand_in_subdomain": brand_in_sub,
        "suspicious_tld": suspicious_tld_flag,
        "tld_in_path": tld_in_path_flag,
        # Domain & DNS
        "domain_age_days": domain_age_days,
        "days_to_expiry": days_to_expiry,
        "is_private_whois": is_private_whois,
        "num_dns_records": num_dns_records,
        "has_mx_records": has_mx_records,
        "has_txt_records": has_txt_records,
        "ttl_value": ttl_value,
        # Redirect & HTTP
        "redirect_count": redirect_count,
        "has_cross_domain_redirect": has_cross_domain_redirect,
        "uses_shortener": is_shortener,
        "http_status_code": http_status_code,
        "response_time_ms": response_time_ms,
>>>>>>> 9b735eb99fcfab11611f7f8da03c77f43357eb91
    }

    return features


def extract_features_vector(
    url: str,
<<<<<<< HEAD
    metadata: Optional[Dict[str, Any]] = None,
) -> List[float]:
    """
    Extracts features as a fixed numerical vector strictly ordered according
    to FeatureSchemaV1.FEATURE_NAMES.
    """
    feature_dict = extract_features(url, metadata=metadata)
    return [float(feature_dict[name]) for name in FeatureSchemaV1.FEATURE_NAMES]


def extract_feature_report(
    url: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> ExtractedFeatureReport:
    """
    Extracts a comprehensive human-readable report along with the numerical vector.
    """
    feature_dict = extract_features(url, metadata=metadata)
    vector = [float(feature_dict[name]) for name in FeatureSchemaV1.FEATURE_NAMES]

    readable_features: Dict[str, HumanReadableFeature] = {}
    for f_def in FEATURE_DEFINITIONS_V1:
        val = feature_dict[f_def.name]

        is_suspicious = False
        if f_def.name == "has_ip_address" and val == 1:
            is_suspicious = True
        elif f_def.name == "has_embedded_credentials" and val == 1:
            is_suspicious = True
        elif f_def.name == "suspicious_tld" and val == 1:
            is_suspicious = True
        elif f_def.name == "is_url_shortener" and val == 1:
            is_suspicious = True
        elif f_def.name == "uses_https" and val == 0:
            is_suspicious = True
        elif f_def.name == "suspicious_keyword_count" and val > 0:
            is_suspicious = True
        elif f_def.name == "brand_keyword_count" and val > 0 and feature_dict["num_subdomains"] > 0:
            is_suspicious = True
        elif f_def.name == "domain_entropy" and val > 4.2:
            is_suspicious = True
        elif f_def.name == "char_repetition_max" and val >= 5:
            is_suspicious = True
        elif f_def.name == "domain_age_days" and 0 <= val < 30:
            is_suspicious = True
        elif f_def.name == "redirect_count" and val >= 3:
            is_suspicious = True

        readable_features[f_def.name] = HumanReadableFeature(
            name=f_def.name,
            value=val,
            category=f_def.category,
            description=f_def.description,
            is_suspicious=is_suspicious,
        )

    summary_flags = {
        "is_ip_address": bool(feature_dict["has_ip_address"]),
        "uses_https": bool(feature_dict["uses_https"]),
        "is_url_shortener": bool(feature_dict["is_url_shortener"]),
        "has_embedded_credentials": bool(feature_dict["has_embedded_credentials"]),
        "has_credentials": bool(feature_dict["has_embedded_credentials"]),
        "has_suspicious_tld": bool(feature_dict["suspicious_tld"]),
        "has_suspicious_keywords": bool(feature_dict["suspicious_keyword_count"] > 0),
        "has_brand_in_domain": bool(feature_dict["brand_keyword_count"] > 0),
        "has_high_repetition": bool(feature_dict["char_repetition_max"] >= 5),
    }

    return ExtractedFeatureReport(
        url=url,
        schema_version=FeatureSchemaV1.VERSION,
        feature_count=len(FEATURE_DEFINITIONS_V1),
        features=readable_features,
        numerical_vector=vector,
        summary_flags=summary_flags,
    )
=======
    context: Optional[Dict[str, Any]] = None,
) -> List[Union[int, float]]:
    """
    Extracts features as a strict ordered list corresponding to FeatureSchemaV1.FEATURE_NAMES.
    """
    feature_dict = extract_features(url, context=context)
    return [feature_dict[name] for name in FeatureSchemaV1.FEATURE_NAMES]
>>>>>>> 9b735eb99fcfab11611f7f8da03c77f43357eb91
