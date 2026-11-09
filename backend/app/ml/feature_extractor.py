"""
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
import re
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import parse_qs, urlparse


@dataclass(frozen=True)
class FeatureDefinition:
    name: str
    feature_type: str  # "int" or "float"
    description: str
    default_value: Union[int, float]
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
    "recover",
    "recovery",
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
    "steam",
    "dropbox",
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
    ".country",
    ".stream",
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


def calculate_shannon_entropy(text: str) -> float:
    """Calculates the Shannon entropy (bits per symbol) of a string."""
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    return round(entropy, 4)


def extract_max_char_repetition(text: str) -> int:
    """Finds the maximum consecutive identical character run length in text."""
    if not text:
        return 0
    runs = [len(match.group(0)) for match in REPEATING_CHAR_REGEX.finditer(text)]
    return max(runs) if runs else 1


def is_ip_host(host: str) -> bool:
    """Checks whether the hostname is an IPv4 or IPv6 address literal."""
    if not host:
        return False
    clean_host = host.strip("[]")
    if ":" in clean_host and clean_host.count(":") == 1:
        clean_host = clean_host.split(":")[0]
    try:
        ipaddress.ip_address(clean_host)
        return True
    except ValueError:
        return False


def parse_subdomain_parts(hostname: str) -> Tuple[List[str], str, str]:
    """
    Parses hostname into (subdomains, second_level_domain, top_level_domain).
    """
    if not hostname or is_ip_host(hostname):
        return [], hostname, ""

    parts = hostname.lower().split(".")
    if len(parts) <= 1:
        return [], hostname, ""
    if len(parts) == 2:
        return [], parts[0], "." + parts[1]

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
        parse_target = "http://" + parse_target

    parsed = urlparse(parse_target)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    scheme = parsed.scheme.lower() if parsed.scheme else ""

    url_len = len(raw_url)
    domain_len = len(hostname)

    num_dots = raw_url.count(".")
    num_hyphens = raw_url.count("-")
    num_digits = sum(c.isdigit() for c in raw_url)
    num_special_chars = len(SPECIAL_CHAR_REGEX.findall(raw_url))

    subdomains, sld, tld = parse_subdomain_parts(hostname)
    num_subdomains = len(subdomains)

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
    }

    return features


def extract_features_vector(
    url: str,
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
