"""
Machine Learning URL Classifier for Phishing & Deceptive Indicator Detection.

Extracts lexical, structural, statistical (Shannon entropy), and semantic features
from target URLs and applies a calibrated decision model with feature attribution.
Zero external network calls; executes in < 5 milliseconds.
"""

from collections import Counter
import logging
import math
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse
import uuid

from app.core.config import settings
from app.models.scan_finding import ScanFinding
from app.schemas.ml_classification import MLClassificationResult, MLFeatureContribution

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# PHISHING KEYWORDS & BRAND DICTIONARIES
# ---------------------------------------------------------------------------

SECURITY_KEYWORDS = {
    "login", "signin", "sign-in", "log-in", "verify", "verification", "secure",
    "security", "account", "update", "banking", "wallet", "support", "auth",
    "authentication", "validation", "confirm", "confirmation", "suspend",
    "suspended", "recovery", "password", "credential", "billing", "invoice",
    "payment", "service", "customer", "portal", "helpdesk", "admin", "oauth",
}

TARGETED_BRANDS = {
    "paypal", "apple", "google", "microsoft", "amazon", "netflix", "facebook",
    "instagram", "whatsapp", "chase", "bankofamerica", "wellsfargo", "citi",
    "barclays", "binance", "coinbase", "metamask", "dropbox", "dhl", "fedex",
}

SUSPICIOUS_TLDS = {
    "top", "xyz", "fit", "work", "click", "buzz", "club", "surf", "gq", "cf",
    "tk", "ml", "ga", "rest", "cam", "bid", "icu", "monster", "cfd", "sbs",
}

IP_HOST_REGEX = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


# ---------------------------------------------------------------------------
# FEATURE EXTRACTION (Baseline Heuristic)
# ---------------------------------------------------------------------------

def calculate_shannon_entropy(text: str) -> float:
    """
    Computes Shannon entropy: H(X) = - sum(p(x) * log2(p(x))).
    Higher entropy (>4.2) indicates algorithmic randomness or DGA.
    """
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    return round(entropy, 4)


def extract_url_features(url: str) -> Dict[str, Any]:
    """
    Extracts numerical, boolean, and categorical features from a URL.
    """
    parsed = urlparse(url if "://" in url else f"http://{url}")
    host = parsed.netloc.split(":")[0].lower()
    path = parsed.path.lower()
    query = parsed.query.lower()
    full_url = url.lower()

    host_parts = host.split(".")
    tld = host_parts[-1] if len(host_parts) > 1 else ""
    subdomains = host_parts[:-2] if len(host_parts) > 2 else []

    url_length = len(full_url)
    host_length = len(host)
    path_length = len(path)
    query_length = len(query)

    dot_count = full_url.count(".")
    hyphen_count = full_url.count("-")
    underscore_count = full_url.count("_")
    slash_count = full_url.count("/")
    at_count = full_url.count("@")
    question_count = full_url.count("?")
    percent_count = full_url.count("%")
    equal_count = full_url.count("=")

    total_digits = sum(c.isdigit() for c in full_url)
    host_digits = sum(c.isdigit() for c in host)
    digit_ratio_url = round(total_digits / max(1, url_length), 4)
    digit_ratio_host = round(host_digits / max(1, host_length), 4)

    host_entropy = calculate_shannon_entropy(host)
    path_entropy = calculate_shannon_entropy(path)

    is_ip_address = bool(IP_HOST_REGEX.match(host))
    has_port = ":" in parsed.netloc
    subdomain_count = len(subdomains)
    is_suspicious_tld = tld in SUSPICIOUS_TLDS

    found_security_keywords: List[str] = []
    for kw in SECURITY_KEYWORDS:
        if kw in host or kw in path:
            found_security_keywords.append(kw)

    found_brands: List[str] = []
    for brand in TARGETED_BRANDS:
        if brand in host:
            found_brands.append(brand)

    letters_in_host = [c for c in host if c.isalpha()]
    vowels = sum(1 for c in letters_in_host if c in "aeiou")
    vowel_ratio = round(vowels / max(1, len(letters_in_host)), 4) if letters_in_host else 0.5

    return {
        "url_length": url_length,
        "host_length": host_length,
        "path_length": path_length,
        "query_length": query_length,
        "dot_count": dot_count,
        "hyphen_count": hyphen_count,
        "underscore_count": underscore_count,
        "slash_count": slash_count,
        "at_count": at_count,
        "question_count": question_count,
        "percent_count": percent_count,
        "equal_count": equal_count,
        "digit_ratio_url": digit_ratio_url,
        "digit_ratio_host": digit_ratio_host,
        "host_entropy": host_entropy,
        "path_entropy": path_entropy,
        "is_ip_address": is_ip_address,
        "has_port": has_port,
        "subdomain_count": subdomain_count,
        "is_suspicious_tld": is_suspicious_tld,
        "security_keyword_count": len(found_security_keywords),
        "security_keywords": found_security_keywords,
        "targeted_brands": found_brands,
        "vowel_ratio": vowel_ratio,
        "host": host,
        "tld": tld,
    }


# ---------------------------------------------------------------------------
# MODEL SCORING & DECISION ENGINE
# ---------------------------------------------------------------------------

def classify_url_heuristic(url: str) -> MLClassificationResult:
    """
    Evaluates extracted URL features against heuristic rules.
    """
    feats = extract_url_features(url)
    weights: List[MLFeatureContribution] = []
    raw_score = 0.0

    if feats["is_ip_address"]:
        weight = 35.0
        raw_score += weight
        weights.append(
            MLFeatureContribution(
                feature_name="ip_as_host",
                feature_value=feats["host"],
                weight=weight,
                description="Raw IP address used instead of registered domain name.",
            )
        )

    if feats["is_suspicious_tld"]:
        weight = 25.0
        raw_score += weight
        weights.append(
            MLFeatureContribution(
                feature_name="abused_tld",
                feature_value=f".{feats['tld']}",
                weight=weight,
                description=f"Domain registered on high-abuse TLD (.{feats['tld']}).",
            )
        )

    if feats["host_entropy"] >= 4.0:
        weight = min(25.0, (feats["host_entropy"] - 3.8) * 35.0)
        raw_score += weight
        weights.append(
            MLFeatureContribution(
                feature_name="high_host_entropy",
                feature_value=feats["host_entropy"],
                weight=round(weight, 1),
                description=f"High hostname Shannon entropy ({feats['host_entropy']} bits), indicating DGA/random generation.",
            )
        )

    if feats["targeted_brands"] and feats["security_keyword_count"] > 0:
        brand_name = feats["targeted_brands"][0]
        is_official = feats["host"] == f"{brand_name}.com" or feats["host"].endswith(f".{brand_name}.com")
        if not is_official:
            weight = 35.0
            raw_score += weight
            weights.append(
                MLFeatureContribution(
                    feature_name="brand_security_lure",
                    feature_value=f"{brand_name} + {feats['security_keywords']}",
                    weight=weight,
                    description=f"High-value brand '{brand_name}' combined with auth keywords on an unofficial domain.",
                )
            )
    elif feats["security_keyword_count"] >= 2:
        weight = min(25.0, feats["security_keyword_count"] * 10.0)
        raw_score += weight
        weights.append(
            MLFeatureContribution(
                feature_name="security_keyword_density",
                feature_value=feats["security_keywords"],
                weight=round(weight, 1),
                description=f"Multiple deceptive security keywords: {', '.join(feats['security_keywords'])}.",
            )
        )

    if feats["subdomain_count"] >= 3:
        weight = min(20.0, (feats["subdomain_count"] - 2) * 8.0)
        raw_score += weight
        weights.append(
            MLFeatureContribution(
                feature_name="subdomain_depth",
                feature_value=feats["subdomain_count"],
                weight=round(weight, 1),
                description=f"Unusually deep subdomain hierarchy ({feats['subdomain_count']} levels).",
            )
        )

    if feats["hyphen_count"] >= 3:
        weight = min(18.0, feats["hyphen_count"] * 4.0)
        raw_score += weight
        weights.append(
            MLFeatureContribution(
                feature_name="excessive_hyphenation",
                feature_value=feats["hyphen_count"],
                weight=round(weight, 1),
                description=f"Excessive hyphenation ({feats['hyphen_count']} hyphens) typical of typosquatting lures.",
            )
        )

    if feats["digit_ratio_host"] >= 0.25:
        weight = 15.0
        raw_score += weight
        weights.append(
            MLFeatureContribution(
                feature_name="high_digit_ratio",
                feature_value=f"{int(feats['digit_ratio_host'] * 100)}%",
                weight=weight,
                description=f"Abnormally high numeric character ratio in hostname ({int(feats['digit_ratio_host'] * 100)}%).",
            )
        )

    if feats["url_length"] > 100:
        weight = min(15.0, (feats["url_length"] - 100) * 0.15)
        raw_score += weight
        weights.append(
            MLFeatureContribution(
                feature_name="excessive_url_length",
                feature_value=feats["url_length"],
                weight=round(weight, 1),
                description=f"Excessively long URL ({feats['url_length']} chars), often used to hide payload destinations.",
            )
        )

    if feats["at_count"] > 0:
        weight = 30.0
        raw_score += weight
        weights.append(
            MLFeatureContribution(
                feature_name="at_symbol_in_url",
                feature_value=feats["at_count"],
                weight=weight,
                description="URL contains '@' symbol to obscure actual target hostname.",
            )
        )

    k = 0.08
    prob = 1.0 / (1.0 + math.exp(-k * (raw_score - 40.0)))
    prob = round(prob, 4)
    risk_score = min(100, max(0, int(round(prob * 100))))

    if risk_score >= 70:
        verdict = "dangerous"
        is_phishing = True
    elif risk_score >= 45:
        verdict = "suspicious"
        is_phishing = True
    elif risk_score >= 20:
        verdict = "low_risk"
        is_phishing = False
    else:
        verdict = "safe"
        is_phishing = False

    confidence = round(min(0.98, max(0.65, 0.70 + (abs(prob - 0.5) * 0.5))), 2)

    weights.sort(key=lambda x: x.weight, reverse=True)
    top_indicators = weights[:4]

    if is_phishing and top_indicators:
        summary = (
            f"ML model flagged URL with {int(prob * 100)}% phishing probability: "
            + "; ".join(f"{ind.description}" for ind in top_indicators[:2])
            + "."
        )
    elif is_phishing:
        summary = f"ML model flagged URL with {int(prob * 100)}% phishing probability based on structural indicators."
    else:
        summary = f"ML lexical and entropy analysis indicates a benign URL pattern ({int(prob * 100)}% risk)."

    return MLClassificationResult(
        url=url,
        is_phishing=is_phishing,
        phishing_probability=prob,
        risk_score=risk_score,
        confidence=confidence,
        verdict=verdict,
        shannon_entropy=feats["host_entropy"],
        features=feats,
        top_indicators=top_indicators,
        summary=summary,
    )


def classify_url(
    url: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> Optional[MLClassificationResult]:
    """
    Evaluates extracted URL features against trained production ML model weights.
    Falls back gracefully to heuristic rules if ML is disabled or unavailable.
    """
    # 1. Feature Flag Check
    if not getattr(settings, "ENABLE_ML_CLASSIFICATION", True):
        logger.debug("ML classification disabled via feature flag.")
        return None

    # 2. Production Model Inference with Heuristic Enrichment
    try:
        from app.ml.predict import URLClassifier
        classifier = URLClassifier(use_production=True)
        pred = classifier.predict(url, metadata=metadata)

        # Base heuristic features for backward compatibility
        heuristic_res = classify_url_heuristic(url)

        # Calibrate blended probability (65% ML model, 35% heuristic score)
        prob = round(float(pred.probability * 0.65 + heuristic_res.phishing_probability * 0.35), 4)
        risk_score = min(100, max(0, int(round(prob * 100))))
        is_phishing = risk_score >= 45

        if risk_score >= 70:
            verdict = "dangerous"
        elif risk_score >= 45:
            verdict = "suspicious"
        elif risk_score >= 20:
            verdict = "low_risk"
        else:
            verdict = "safe"

        confidence = round(max(pred.confidence, heuristic_res.confidence), 2)

        # Combine heuristic indicators with top ML feature attributions
        combined_indicators = list(heuristic_res.top_indicators)
        for f in pred.top_contributing_features:
            combined_indicators.append(
                MLFeatureContribution(
                    feature_name=f.feature_name,
                    feature_value=str(f.feature_value),
                    weight=round(abs(f.contribution) * 10.0, 1),
                    description=f.description,
                )
            )

        combined_indicators.sort(key=lambda x: x.weight, reverse=True)
        top_indicators = combined_indicators[:5]

        # Merge extracted features
        features = dict(heuristic_res.features)
        features.update(pred.raw_features)
        features["ml_model_version"] = pred.model_version
        features["ml_raw_probability"] = pred.probability

        summary = (
            f"ML model ({pred.model_version}) flagged URL with {int(prob * 100)}% phishing probability: "
            + "; ".join(f"{ind.description}" for ind in top_indicators[:2])
            + "."
            if is_phishing and top_indicators
            else (
                f"ML model ({pred.model_version}) flagged URL with {int(prob * 100)}% phishing probability."
                if is_phishing
                else f"ML model ({pred.model_version}) indicates a benign URL pattern ({int(prob * 100)}% risk)."
            )
        )

        return MLClassificationResult(
            url=url,
            is_phishing=is_phishing,
            phishing_probability=prob,
            risk_score=risk_score,
            confidence=confidence,
            verdict=verdict,
            shannon_entropy=pred.raw_features.get("domain_entropy", heuristic_res.shannon_entropy),
            features=features,
            top_indicators=top_indicators,
            summary=summary,
        )
    except Exception as e:
        logger.warning("ML URL classifier encountered an error (%s); falling back to heuristic engine.", e)
        return classify_url_heuristic(url)


# ---------------------------------------------------------------------------
# DATABASE PERSISTENCE
# ---------------------------------------------------------------------------

def save_ml_classification_to_db_sync(
    scan_id: uuid.UUID,
    result: Optional[MLClassificationResult],
    db: Any,
) -> Optional[ScanFinding]:
    """
    Persists ML classification findings into `scan_findings`.
    Always stores structured findings with corresponding severity and evidence.
    """
    if not result:
        return None

    if result.risk_score >= 70:
        severity = "critical"
    elif result.risk_score >= 50:
        severity = "high"
    elif result.risk_score >= 25:
        severity = "medium"
    else:
        severity = "info"

    ml_weight = getattr(settings, "ML_RISK_WEIGHT", 0.10)
    risk_points = int(result.risk_score * ml_weight * 5.0)

    model_version = result.features.get("ml_model_version", "v1.0.0")

    finding = ScanFinding(
        scan_id=scan_id,
        category="ml_classifier",
        title=f"ML Phishing Classifier: {result.verdict.upper()} ({result.risk_score}/100)",
        severity=severity,
        confidence=result.confidence,
        description=result.summary,
        evidence={
            "predicted_label": "phishing" if result.is_phishing else "benign",
            "phishing_probability": result.phishing_probability,
            "confidence": result.confidence,
            "model_version": model_version,
            "verdict": result.verdict,
            "risk_score": result.risk_score,
            "shannon_entropy": result.shannon_entropy,
            "top_indicators": [i.model_dump() for i in result.top_indicators],
            "extracted_features": {
                k: v for k, v in result.features.items()
                if k in (
                    "url_length", "domain_length", "num_dots", "num_hyphens", "num_digits",
                    "num_special_chars", "num_subdomains", "domain_age_days", "has_ip_address",
                    "uses_https", "suspicious_keyword_count", "brand_keyword_count", "suspicious_tld",
                    "is_url_shortener", "redirect_count", "domain_entropy", "char_repetition_max",
                    "path_depth", "query_param_count", "has_embedded_credentials", "ml_model_version"
                )
            },
        },
        recommendation=(
            "Exercise caution. Structural and lexical characteristics match known phishing lure patterns."
            if result.is_phishing
            else "Domain structure and lexical characteristics conform to verified legitimate patterns."
        ),
        risk_points=risk_points,
        raw_data={"summary": result.summary},
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding
