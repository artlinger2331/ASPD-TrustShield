"""
Explainable Risk Engine for TrustShield.

Consolidates all security telemetry layers:
1. Threat Intelligence feeds (Google Safe Browsing, URLhaus, VirusTotal)
2. Safe Content & Form Analysis (credential harvesting, brand spoofing, clickfix)
3. Domain Infrastructure & DNS (age, suspicious TLD, DMARC/SPF)
4. SSL/TLS Certificate & PKI Trust (chain validity, expiry, CT logs)
5. Web Security Headers (HSTS, CSP, cookie flags)
6. Machine Learning URL Classifier (entropy, structural, lexical)

Generates calibrated composite risk scores, verdicts, factor attribution,
executive summaries, and actionable remediation advice.
"""

from typing import List, Dict, Any, Optional, Tuple
from app.models.scan_finding import ScanFinding
from app.models.certificate import Certificate
from app.models.threat_intel import ThreatIntelResult
from app.schemas.ml_classification import MLClassificationResult
from app.schemas.risk_engine import TelemetrySubscore, RiskExplanation


def evaluate_risk(
    findings: List[ScanFinding],
    certificate: Optional[Certificate] = None,
    threat_intel_results: Optional[List[ThreatIntelResult]] = None,
    ml_result: Optional[MLClassificationResult] = None,
    domain: Optional[str] = None,
) -> RiskExplanation:
    """
    Synthesizes all telemetry findings into an explainable risk evaluation.
    """
    threat_intel_results = threat_intel_results or []

    # Partition findings by telemetry layer
    CONTENT_CATEGORIES = {
        "credential_harvesting",
        "brand_impersonation",
        "login_form",
        "sensitive_inputs",
        "deceptive_content",
        "malicious_lure",
        "suspicious_script",
        "anti_analysis",
        "hidden_elements",
        "clickfix_deception",
    }
    content_findings = [f for f in findings if f.category in CONTENT_CATEGORIES]
    domain_findings = [f for f in findings if f.category in ("domain_infrastructure", "dns_security", "url_heuristics", "url_syntax")]
    cert_findings = [f for f in findings if f.category == "tls_certificate"]
    header_findings = [f for f in findings if f.category == "security_headers"]
    ml_findings = [f for f in findings if f.category == "ml_classifier"]

    # 1. Threat Intel Layer
    threat_score = 0
    threat_evidence: List[str] = []
    for t in threat_intel_results:
        if t.match_type and t.match_type.upper() not in ("CLEAN", "SKIPPED", "ERROR"):
            threat_score = max(threat_score, 95)
            threat_evidence.append(f"Flagged by {t.source} ({t.match_type})")

    # 2. Content & Forms Layer
    content_risk_points = sum(f.risk_points for f in content_findings)
    content_score = min(100, max(0, content_risk_points))
    content_evidence = [f.title for f in content_findings[:3]]

    # 3. Domain & DNS Layer
    domain_risk_points = sum(f.risk_points for f in domain_findings)
    domain_score = min(100, max(0, domain_risk_points))
    domain_evidence = [f.title for f in domain_findings[:3]]

    # 4. Certificate Layer
    cert_risk_points = sum(f.risk_points for f in cert_findings)
    if certificate and not certificate.is_valid:
        cert_risk_points = max(cert_risk_points, 75)
    cert_score = min(100, max(0, cert_risk_points))
    cert_evidence = [f.title for f in cert_findings[:3]]

    # 5. Security Headers Layer
    header_risk_points = sum(f.risk_points for f in header_findings)
    header_score = min(100, max(0, header_risk_points))
    header_evidence = [f.title for f in header_findings[:3]]

    # 6. ML Classifier Layer
    if ml_result:
        ml_score = ml_result.risk_score
        ml_evidence = [ind.description for ind in ml_result.top_indicators[:2]]
    else:
        ml_score = min(100, sum(f.risk_points for f in ml_findings))
        ml_evidence = [f.title for f in ml_findings[:2]]

    # Calculate status per subscore
    def get_status(score: int) -> str:
        if score >= 70:
            return "danger"
        elif score >= 35:
            return "warning"
        return "safe"

    subscores: Dict[str, TelemetrySubscore] = {
        "threat_intel": TelemetrySubscore(
            layer="threat_intel",
            display_name="Threat Intelligence Feeds",
            score=threat_score,
            status=get_status(threat_score),
            findings_count=len(threat_evidence),
            key_evidence=threat_evidence,
        ),
        "content": TelemetrySubscore(
            layer="content",
            display_name="Page Content & Forms",
            score=content_score,
            status=get_status(content_score),
            findings_count=len(content_findings),
            key_evidence=content_evidence,
        ),
        "domain": TelemetrySubscore(
            layer="domain",
            display_name="Domain & DNS Architecture",
            score=domain_score,
            status=get_status(domain_score),
            findings_count=len(domain_findings),
            key_evidence=domain_evidence,
        ),
        "certificate": TelemetrySubscore(
            layer="certificate",
            display_name="SSL/TLS & CA Trust",
            score=cert_score,
            status=get_status(cert_score),
            findings_count=len(cert_findings),
            key_evidence=cert_evidence,
        ),
        "headers": TelemetrySubscore(
            layer="headers",
            display_name="Security Headers",
            score=header_score,
            status=get_status(header_score),
            findings_count=len(header_findings),
            key_evidence=header_evidence,
        ),
        "ml_classifier": TelemetrySubscore(
            layer="ml_classifier",
            display_name="ML Phishing Classifier",
            score=ml_score,
            status=get_status(ml_score),
            findings_count=len(ml_findings) if not ml_result else len(ml_result.top_indicators),
            key_evidence=ml_evidence,
        ),
    }

    # Weighted blend calculation
    raw_composite = (
        0.35 * threat_score +
        0.30 * content_score +
        0.15 * domain_score +
        0.10 * cert_score +
        0.05 * header_score +
        0.05 * ml_score
    )

    # Apply Defense Overrides
    if threat_score >= 80:
        composite_score = max(90, int(round(raw_composite)))
    elif content_score >= 60:
        composite_score = max(75, content_score)
    elif content_score >= 40:
        composite_score = max(55, content_score)
    elif cert_score >= 75:
        composite_score = max(65, int(round(raw_composite)))
    elif ml_score >= 70:
        composite_score = max(65, int(round(raw_composite)))
    else:
        composite_score = min(100, max(0, int(round(raw_composite))))

    # Verdict determination
    if composite_score >= 70:
        verdict = "dangerous"
        verdict_label = "Dangerous"
    elif composite_score >= 45:
        verdict = "suspicious"
        verdict_label = "Suspicious"
    elif composite_score >= 20:
        verdict = "low_risk"
        verdict_label = "Low Risk"
    else:
        verdict = "safe"
        verdict_label = "Safe"

    # Positive & Negative Factor Attribution
    positive_factors: List[str] = []
    negative_factors: List[str] = []

    # Evaluate positive factors
    if threat_score == 0:
        positive_factors.append("No active listings on global threat intelligence feeds (Clean reputation).")
    if certificate and certificate.is_valid and certificate.ca_trust_status == "trusted":
        positive_factors.append(f"Valid TLS certificate issued by trusted CA ({certificate.issuer or 'Trusted CA'}).")
    if certificate and certificate.ct_log_present:
        positive_factors.append("Certificate Transparency (CT) logs verified in public ledgers.")
    if content_score == 0:
        positive_factors.append("No deceptive login forms, password harvesters, or brand impersonation found.")
    if domain_score == 0:
        positive_factors.append("Standard domain registration without high-abuse TLD or dynamic DNS markers.")

    # Evaluate negative factors
    critical_findings = [f.title for f in findings if f.severity in ("critical", "high")]
    if threat_evidence:
        negative_factors.extend(threat_evidence)
    if critical_findings:
        negative_factors.extend(critical_findings[:3])
    if ml_score >= 50 and ml_evidence:
        negative_factors.extend(ml_evidence[:2])

    # Calibrate confidence score
    confidence = 0.85
    if certificate is not None:
        confidence += 0.05
    if threat_intel_results:
        confidence += 0.04
    if ml_result is not None:
        confidence += 0.03
    confidence = round(min(0.99, confidence), 2)

    # Synthesize explainable summary
    if verdict == "dangerous":
        lead_factors = negative_factors[:2] if negative_factors else ["Multiple critical security threats detected"]
        summary = f"Dangerous: {'; '.join(lead_factors)}."
        recommendation = "Do not visit this site or input credentials, passwords, or payment cards."
    elif verdict == "suspicious":
        lead_factors = negative_factors[:2] if negative_factors else ["Elevated risk indicators observed"]
        summary = f"Suspicious: {'; '.join(lead_factors)}."
        recommendation = "Exercise caution. Confirm the identity of the site operator before interacting."
    elif verdict == "low_risk":
        summary = "Low Risk: Minor security warnings detected (e.g. missing HTTP defense headers), but no malicious payloads."
        recommendation = "Website appears generally safe. Ensure HTTPS connection remains active."
    else:
        summary = "Safe: Website exhibits established domain reputation, valid TLS encryption, and no phishing or malware signatures."
        recommendation = "Safe to browse."

    return RiskExplanation(
        risk_score=composite_score,
        verdict=verdict,
        verdict_label=verdict_label,
        confidence=confidence,
        summary=summary,
        recommendation=recommendation,
        subscores=subscores,
        positive_factors=positive_factors,
        negative_factors=negative_factors,
    )
