"""
Advanced Brand Impersonation, Homoglyph, and Typosquatting Detection Engine.

Implements:
1. Homoglyph mapping (Cyrillic, Greek, lookalikes)
2. Levenshtein edit distance and Jaro-Winkler string similarity
3. Combosquatting (brand + auth/security tokens)
4. Subdomain brand spoofing (e.g. brand.com.attacker.xyz)
5. Database persistence into `scan_findings`
"""

import uuid
from typing import Dict, Any, List, Optional, Tuple, Set
from urllib.parse import urlparse

from app.models.scan_finding import ScanFinding

# ---------------------------------------------------------------------------
# TARGETED BRAND CATALOG (Brand name -> Official domain / ccTLDs)
# ---------------------------------------------------------------------------

TARGETED_BRANDS: Dict[str, Dict[str, Any]] = {
    "paypal": {
        "domains": ["paypal.com", "paypal.me"],
        "category": "Fintech / Payment",
        "criticality": "critical",
    },
    "sbi": {
        "domains": ["onlinesbi.sbi", "sbi.co.in", "statebankofindia.com"],
        "category": "Banking",
        "criticality": "critical",
    },
    "hdfc": {
        "domains": ["hdfcbank.com", "hdfc.com"],
        "category": "Banking",
        "criticality": "critical",
    },
    "icici": {
        "domains": ["icicibank.com"],
        "category": "Banking",
        "criticality": "critical",
    },
    "chase": {
        "domains": ["chase.com"],
        "category": "Banking",
        "criticality": "critical",
    },
    "bankofamerica": {
        "domains": ["bankofamerica.com", "bofa.com"],
        "category": "Banking",
        "criticality": "critical",
    },
    "wellsfargo": {
        "domains": ["wellsfargo.com"],
        "category": "Banking",
        "criticality": "critical",
    },
    "binance": {
        "domains": ["binance.com"],
        "category": "Cryptocurrency",
        "criticality": "critical",
    },
    "apple": {
        "domains": ["apple.com", "icloud.com"],
        "category": "Tech / Identity",
        "criticality": "critical",
    },
    "google": {
        "domains": ["google.com", "accounts.google.com"],
        "category": "Tech / Identity",
        "criticality": "critical",
    },
    "microsoft": {
        "domains": ["microsoft.com", "live.com", "office.com", "outlook.com"],
        "category": "Tech / Identity",
        "criticality": "critical",
    },
    "netflix": {
        "domains": ["netflix.com"],
        "category": "Entertainment / Streaming",
        "criticality": "high",
    },
    "amazon": {
        "domains": ["amazon.com", "amazon.in", "amazon.co.uk", "amazon.de"],
        "category": "E-Commerce",
        "criticality": "critical",
    },
    "facebook": {
        "domains": ["facebook.com", "fb.com", "meta.com"],
        "category": "Social Media",
        "criticality": "high",
    },
    "instagram": {
        "domains": ["instagram.com"],
        "category": "Social Media",
        "criticality": "high",
    },
    "dhl": {
        "domains": ["dhl.com"],
        "category": "Logistics",
        "criticality": "high",
    },
    "fedex": {
        "domains": ["fedex.com"],
        "category": "Logistics",
        "criticality": "high",
    },
}

# Homoglyph character substitution map
HOMOGLYPH_MAP: Dict[str, str] = {
    # Cyrillic to Latin
    "а": "a", "с": "c", "е": "e", "о": "o", "р": "p", "ѕ": "s", "х": "x", "у": "y",
    "і": "i", "ј": "j", "ԁ": "d", "ԛ": "q", "ԝ": "w", "ո": "n", "һ": "h",
    # Digits used as letter replacements
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
}

SUSPICIOUS_AFFIXES = {
    "login", "signin", "verify", "secure", "security", "support", "account",
    "portal", "auth", "update", "service", "billing", "helpdesk", "alert",
    "confirm", "recovery", "validation", "client", "office", "bank",
}


# ---------------------------------------------------------------------------
# STRING DISTANCE ALGORITHMS
# ---------------------------------------------------------------------------

def levenshtein_distance(s1: str, s2: str) -> int:
    """Computes Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def jaro_winkler_similarity(s1: str, s2: str) -> float:
    """Computes Jaro-Winkler string similarity (0.0 to 1.0)."""
    if s1 == s2:
        return 1.0
    len1, len2 = len(s1), len(s2)
    if len1 == 0 or len2 == 0:
        return 0.0

    match_distance = max(len1, len2) // 2 - 1
    s1_matches = [False] * len1
    s2_matches = [False] * len2
    matches = 0

    for i in range(len1):
        start = max(0, i - match_distance)
        end = min(i + match_distance + 1, len2)
        for j in range(start, end):
            if s2_matches[j]:
                continue
            if s1[i] != s2[j]:
                continue
            s1_matches[i] = True
            s2_matches[j] = True
            matches += 1
            break

    if matches == 0:
        return 0.0

    transpositions = 0
    k = 0
    for i in range(len1):
        if not s1_matches[i]:
            continue
        while not s2_matches[k]:
            k += 1
        if s1[i] != s2[k]:
            transpositions += 1
        k += 1

    jaro = (
        (matches / len1) +
        (matches / len2) +
        ((matches - transpositions / 2) / matches)
    ) / 3.0

    # Winkler prefix bonus (up to 4 characters)
    prefix = 0
    for i in range(min(4, len1, len2)):
        if s1[i] == s2[i]:
            prefix += 1
        else:
            break

    return round(jaro + prefix * 0.1 * (1.0 - jaro), 4)


def normalize_homoglyphs(text: str) -> Tuple[str, bool]:
    """Replaces confusable homoglyphs with standard ASCII latin characters."""
    normalized = []
    has_homoglyphs = False
    for char in text.lower():
        if char in HOMOGLYPH_MAP:
            normalized.append(HOMOGLYPH_MAP[char])
            has_homoglyphs = True
        else:
            normalized.append(char)
    return "".join(normalized), has_homoglyphs


# ---------------------------------------------------------------------------
# BRAND IMPERSONATION ANALYZER
# ---------------------------------------------------------------------------

class BrandImpersonationMatch:
    def __init__(
        self,
        brand_name: str,
        technique: str,
        severity: str,
        confidence: float,
        title: str,
        description: str,
        risk_points: int,
        evidence: Dict[str, Any],
    ):
        self.brand_name = brand_name
        self.technique = technique
        self.severity = severity
        self.confidence = confidence
        self.title = title
        self.description = description
        self.risk_points = risk_points
        self.evidence = evidence


def analyze_brand_impersonation(url_or_domain: str) -> List[BrandImpersonationMatch]:
    """
    Evaluates target domain against targeted brand catalog for typosquatting,
    homoglyphs, combosquatting, and subdomain abuse.
    """
    clean = url_or_domain.strip().lower()
    if "://" in clean:
        clean = urlparse(clean).netloc.split(":")[0]
    domain = clean

    parts = domain.split(".")
    tld = parts[-1] if len(parts) > 1 else ""
    sld = parts[-2] if len(parts) > 1 else parts[0]
    subdomains = parts[:-2] if len(parts) > 2 else []

    matches: List[BrandImpersonationMatch] = []

    # Check each protected brand
    for brand, info in TARGETED_BRANDS.items():
        official_domains = info["domains"]

        # If the domain is officially owned by the brand, skip
        if any(domain == off or domain.endswith(f".{off}") for off in official_domains):
            continue

        # 1. Subdomain Spoofing (e.g. paypal.com.attacker-controlled.net)
        for off in official_domains:
            if off in subdomains or any(sub == brand for sub in subdomains):
                matches.append(
                    BrandImpersonationMatch(
                        brand_name=brand,
                        technique="subdomain_spoofing",
                        severity="critical",
                        confidence=0.95,
                        title=f"Subdomain Brand Spoofing: {brand.upper()}",
                        description=(
                            f"The domain embeds legitimate brand identity '{brand}' in a subdomain "
                            f"to deceive users, while the actual base domain is controlled by a third party."
                        ),
                        risk_points=50,
                        evidence={"subdomains": subdomains, "base_domain": f"{sld}.{tld}", "brand": brand},
                    )
                )
                break

        # 2. Homoglyph Replacement Detection
        normalized_sld, had_homoglyphs = normalize_homoglyphs(sld)
        if had_homoglyphs and brand in normalized_sld and brand not in sld:
            matches.append(
                BrandImpersonationMatch(
                    brand_name=brand,
                    technique="homoglyph_replacement",
                    severity="critical",
                    confidence=0.98,
                    title=f"Internationalized Homoglyph Attack: {brand.upper()}",
                    description=(
                        f"The domain uses visual character substitution (Cyrillic/confusable lookalikes) "
                        f"to spoof the legitimate brand '{brand}'."
                    ),
                    risk_points=60,
                    evidence={"raw_domain": domain, "normalized": normalized_sld, "spoofed_brand": brand},
                )
            )

        # 3. Combosquatting (e.g. paypal-verify, sbi-security, apple-support)
        if brand in sld and not any(sld == off.split(".")[0] for off in official_domains):
            # Check if brand is combined with suspicious affix
            has_affix = any(affix in sld for affix in SUSPICIOUS_AFFIXES)
            if has_affix or "-" in sld or "_" in sld:
                matches.append(
                    BrandImpersonationMatch(
                        brand_name=brand,
                        technique="combosquatting",
                        severity="high",
                        confidence=0.92,
                        title=f"Combosquatting Brand Mimicry: {brand.upper()}",
                        description=(
                            f"The domain combines high-value brand '{brand}' with security or authentication "
                            f"keywords ('{sld}') to fabricate legitimate corporate authority."
                        ),
                        risk_points=45,
                        evidence={"sld": sld, "brand": brand, "category": info["category"]},
                    )
                )

        # 4. Levenshtein / Typosquatting Distance on SLD
        primary_brand_sld = official_domains[0].split(".")[0]
        if len(sld) >= 4 and len(primary_brand_sld) >= 4:
            dist = levenshtein_distance(sld, primary_brand_sld)
            sim = jaro_winkler_similarity(sld, primary_brand_sld)

            if dist == 1 or (dist == 2 and len(primary_brand_sld) >= 6) or sim >= 0.90:
                if sld != primary_brand_sld:
                    matches.append(
                        BrandImpersonationMatch(
                            brand_name=brand,
                            technique="typosquatting",
                            severity="high",
                            confidence=0.90,
                            title=f"Typosquatting Edit Distance: {brand.upper()}",
                            description=(
                                f"Domain '{sld}' differs by only {dist} edit(s) (Jaro-Winkler: {sim}) "
                                f"from official domain '{primary_brand_sld}'. This is characteristic of typo-lure trapping."
                            ),
                            risk_points=40,
                            evidence={"domain_sld": sld, "official_sld": primary_brand_sld, "edit_distance": dist, "similarity": sim},
                        )
                    )

    return matches


# ---------------------------------------------------------------------------
# DATABASE PERSISTENCE
# ---------------------------------------------------------------------------

def save_brand_impersonation_findings_to_db_sync(
    scan_id: uuid.UUID,
    matches: List[BrandImpersonationMatch],
    db: Any,
) -> List[ScanFinding]:
    """Persists brand impersonation detections into `scan_findings`."""
    persisted: List[ScanFinding] = []

    for m in matches:
        finding = ScanFinding(
            scan_id=scan_id,
            category="brand_impersonation",
            title=m.title,
            severity=m.severity,
            confidence=m.confidence,
            description=m.description,
            evidence=m.evidence,
            recommendation=f"Do not interact with this site. It is an unverified replica targeting {m.brand_name.upper()} users.",
            risk_points=m.risk_points,
            raw_data={"technique": m.technique, "brand": m.brand_name},
        )
        db.add(finding)
        persisted.append(finding)

    if persisted:
        db.commit()
        for f in persisted:
            db.refresh(f)

    return persisted
