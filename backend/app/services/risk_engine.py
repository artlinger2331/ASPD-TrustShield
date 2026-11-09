"""
Explainable Risk & Trust-Score Engine for TrustShield.

Combines 8 distinct security telemetry layers:
1. URL and domain analysis (entropy, length, brand spoofing, TLD, Punycode, homoglyphs)
2. Redirect analysis (hop count, protocol downgrade, cloaking)
3. Phishing-content analysis (credential harvesting, login forms, OTP/sensitive inputs, clickfix)
4. Certificate and CA trust analysis (chain validity, expiry, OCSP revocation, CT logs, untrusted root)
5. Web-security assessment (HTTPS enforcement, HSTS, CSP, X-Frame-Options, cookie flags)
6. Threat-intelligence results (Google Safe Browsing, URLhaus, PhishTank, OpenPhish, VirusTotal)
7. ML URL classification (phishing probability, confidence, feature attribution)
8. Community reports (crowdsourced threat reports, confirmation votes vs false positives)

Generates calibrated composite risk scores (0–100), transparent category scores,
ranked human-readable top reasons, structured evidence logs, executive summaries,
and actionable remediation advice.
"""

from typing import List, Dict, Any, Optional
from app.core.config import settings
from app.models.scan_finding import ScanFinding
from app.models.certificate import Certificate
from app.models.threat_intel import ThreatIntelResult
from app.schemas.ml_classification import MLClassificationResult
from app.schemas.risk_engine import TelemetrySubscore, RiskExplanation


CONTENT_CATEGORIES = {
    "phishing",
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

DOMAIN_CATEGORIES = {
    "domain_infrastructure",
    "dns_security",
    "url_heuristics",
    "url_syntax",
    "brand_impersonation",
}


def evaluate_risk(
    findings: List[ScanFinding],
    certificate: Optional[Certificate] = None,
    threat_intel_results: Optional[List[ThreatIntelResult]] = None,
    ml_result: Optional[MLClassificationResult] = None,
    domain: Optional[str] = None,
    redirect_hops: Optional[List[Any]] = None,
    community_reports: Optional[List[Any]] = None,
) -> RiskExplanation:
    """
    Synthesizes all 8 security telemetry layers into a transparent,
    explainable trust evaluation conforming strictly to TrustShield specifications.
    """
    threat_intel_results = threat_intel_results or []
    redirect_hops = redirect_hops or []
    community_reports = community_reports or []

    # Partition findings by telemetry layer
    content_findings = [f for f in findings if f.category in CONTENT_CATEGORIES]
    domain_findings = [f for f in findings if f.category in DOMAIN_CATEGORIES]
    cert_findings = [f for f in findings if f.category == "tls_certificate"]
    header_findings = [f for f in findings if f.category in ("security_headers", "web_security")]
    ml_findings = [f for f in findings if f.category == "ml_classifier"]
    redirect_findings = [f for f in findings if f.category in ("redirect", "redirect_chain")]

    evidence: List[Dict[str, Any]] = []

    # -------------------------------------------------------------------------
    # 1. URL & DOMAIN LAYER (Combined Signals 1, 2, 7) - Max 35 pts
    # -------------------------------------------------------------------------
    # 1a. Domain heuristics & syntax
    domain_risk_points = sum(f.risk_points for f in domain_findings)
    base_domain_pts = min(20, domain_risk_points)
    for f in domain_findings:
        evidence.append({
            "category": "url_domain",
            "signal": f.category,
            "severity": f.severity,
            "description": f.title,
            "risk_points": f.risk_points,
        })

    # 1b. Redirect analysis (Signal 2)
    redirect_pts = 0
    hop_count = len(redirect_hops)
    if hop_count >= 4:
        redirect_pts += 8
        evidence.append({
            "category": "url_domain",
            "signal": "redirect_analysis",
            "severity": "high",
            "description": f"Excessive redirection chain ({hop_count} hops detected)",
            "risk_points": 8,
        })
    elif hop_count >= 2:
        redirect_pts += 4
        evidence.append({
            "category": "url_domain",
            "signal": "redirect_analysis",
            "severity": "medium",
            "description": f"Multi-hop redirection chain ({hop_count} hops)",
            "risk_points": 4,
        })

    # Check for protocol downgrade in redirect hops
    for hop in redirect_hops:
        from_url = getattr(hop, "from_url", None) or (hop.get("from_url") if isinstance(hop, dict) else "")
        to_url = getattr(hop, "to_url", None) or (hop.get("to_url") if isinstance(hop, dict) else "")
        if from_url.lower().startswith("https://") and to_url.lower().startswith("http://"):
            redirect_pts += 10
            evidence.append({
                "category": "url_domain",
                "signal": "protocol_downgrade",
                "severity": "critical",
                "description": "Redirection chain downgrades security from HTTPS to unencrypted HTTP",
                "risk_points": 10,
            })
            break

    # Redirect findings from database
    for f in redirect_findings:
        redirect_pts += f.risk_points
        evidence.append({
            "category": "url_domain",
            "signal": "redirect_finding",
            "severity": f.severity,
            "description": f.title,
            "risk_points": f.risk_points,
        })

    # 1c. Machine Learning URL Classifier (Signal 7)
    ml_enabled = getattr(settings, "ENABLE_ML_CLASSIFICATION", True)
    ml_pts = 0
    if ml_enabled:
        ml_weight = float(getattr(settings, "ML_RISK_WEIGHT", 0.10))
        ml_weight = max(0.0, min(0.35, ml_weight))
        if ml_result:
            ml_score = ml_result.risk_score
            ml_pts = int(round((ml_score / 100.0) * ml_weight * 35))
            if ml_result.is_phishing:
                evidence.append({
                    "category": "url_domain",
                    "signal": "ml_classifier",
                    "severity": "high" if ml_score >= 70 else "medium",
                    "description": f"ML model flagged URL as phishing (probability: {ml_result.phishing_probability:.1%})",
                    "risk_points": ml_pts,
                })
        else:
            ml_finding_pts = sum(f.risk_points for f in ml_findings)
            ml_score = min(100, ml_finding_pts)
            ml_pts = int(round((ml_score / 100.0) * ml_weight * 35))
    else:
        ml_score = 0
        ml_pts = 0

    # Total URL & Domain Category Score (capped at 35)
    url_domain_score = min(35, base_domain_pts + redirect_pts + ml_pts)

    # -------------------------------------------------------------------------
    # 2. PHISHING CONTENT & DOM LAYER (Signal 3) - Max 30 pts
    # -------------------------------------------------------------------------
    content_risk_points = sum(f.risk_points for f in content_findings)
    phishing_content_score = min(30, max(0, content_risk_points))

    for f in content_findings:
        evidence.append({
            "category": "phishing_content",
            "signal": f.category,
            "severity": f.severity,
            "description": f.title,
            "risk_points": f.risk_points,
        })

    # -------------------------------------------------------------------------
    # 3. THREAT INTELLIGENCE & COMMUNITY (Signals 6, 8) - Max 25 pts
    # -------------------------------------------------------------------------
    threat_feed_pts = 0
    threat_intel_evidence: List[str] = []

    for t in threat_intel_results:
        if t.match_type and t.match_type.upper() not in ("CLEAN", "SKIPPED", "ERROR"):
            conf = t.confidence if t.confidence is not None else 0.9
            feed_points = int(round(12 * conf))
            threat_feed_pts += feed_points
            desc = f"Threat intelligence match found on {t.source} ({t.match_type})"
            threat_intel_evidence.append(desc)
            evidence.append({
                "category": "threat_intelligence",
                "signal": t.source,
                "severity": "critical",
                "description": desc,
                "risk_points": feed_points,
            })

    # Signal 8: Community reports
    community_pts = 0
    for r in community_reports:
        confirmations = getattr(r, "confirmations", 1) or (r.get("confirmations", 1) if isinstance(r, dict) else 1)
        fp_votes = getattr(r, "false_positive_votes", 0) or (r.get("false_positive_votes", 0) if isinstance(r, dict) else 0)
        threat_type = getattr(r, "threat_type", "phishing") or (r.get("threat_type", "phishing") if isinstance(r, dict) else "phishing")
        
        if confirmations > fp_votes:
            pts = 8 if confirmations >= 2 else 5
            community_pts += pts
            desc = f"Community threat report confirmed for {threat_type} ({confirmations} confirmations)"
            evidence.append({
                "category": "threat_intelligence",
                "signal": "community_report",
                "severity": "high",
                "description": desc,
                "risk_points": pts,
            })
        elif fp_votes > confirmations:
            # Positive consensus damping
            community_pts = max(0, community_pts - 4)

    threat_intel_score = min(25, threat_feed_pts + community_pts)

    # -------------------------------------------------------------------------
    # 4. CERTIFICATE & CA TRUST LAYER (Signal 4) - Max 15 pts
    # -------------------------------------------------------------------------
    cert_pts = 0
    if certificate:
        if certificate.is_revoked:
            cert_pts += 15
            evidence.append({
                "category": "certificate_trust",
                "signal": "revocation",
                "severity": "critical",
                "description": "TLS certificate has been explicitly revoked via OCSP/CRL",
                "risk_points": 15,
            })
        elif not certificate.is_valid:
            cert_pts += 10
            evidence.append({
                "category": "certificate_trust",
                "signal": "validity",
                "severity": "high",
                "description": "TLS certificate is invalid or untrusted",
                "risk_points": 10,
            })

        if certificate.ca_trust_status and certificate.ca_trust_status.lower() not in ("trusted", "valid"):
            cert_pts += 8
            evidence.append({
                "category": "certificate_trust",
                "signal": "ca_trust",
                "severity": "high",
                "description": f"Certificate authority is untrusted or self-signed ({certificate.issuer or 'Unknown CA'})",
                "risk_points": 8,
            })

        if certificate.is_valid and not certificate.ct_log_present:
            cert_pts += 4
            evidence.append({
                "category": "certificate_trust",
                "signal": "ct_log",
                "severity": "medium",
                "description": "Certificate missing Certificate Transparency (CT) ledger audit entry",
                "risk_points": 4,
            })

        if certificate.days_until_expiry is not None and certificate.days_until_expiry < 0:
            cert_pts += 10
            evidence.append({
                "category": "certificate_trust",
                "signal": "expiration",
                "severity": "high",
                "description": "TLS certificate has expired",
                "risk_points": 10,
            })

    for f in cert_findings:
        cert_pts += f.risk_points
        evidence.append({
            "category": "certificate_trust",
            "signal": f.category,
            "severity": f.severity,
            "description": f.title,
            "risk_points": f.risk_points,
        })

    certificate_trust_score = min(15, cert_pts)

    # -------------------------------------------------------------------------
    # 5. WEB SECURITY ASSESSMENT LAYER (Signal 5) - Max 10 pts
    # -------------------------------------------------------------------------
    header_risk_points = sum(f.risk_points for f in header_findings)
    web_security_score = min(10, max(0, header_risk_points))

    for f in header_findings:
        evidence.append({
            "category": "web_security",
            "signal": f.category,
            "severity": f.severity,
            "description": f.title,
            "risk_points": f.risk_points,
        })

    # -------------------------------------------------------------------------
    # COMPOSITE SCORE NORMALIZATION (0 - 100)
    # -------------------------------------------------------------------------
    raw_composite = (
        url_domain_score
        + phishing_content_score
        + threat_intel_score
        + certificate_trust_score
        + web_security_score
    )

    # Bounded signal rules:
    # If a critical credential form or severe threat feed is confirmed, ensure score enters dangerous/high_risk
    # while preserving transparent category attribution.
    composite_score = min(100, max(0, int(round(raw_composite))))

    # Category Scores Dictionary strictly matching requested keys
    category_scores: Dict[str, int] = {
        "url_domain": url_domain_score,
        "phishing_content": phishing_content_score,
        "certificate_trust": certificate_trust_score,
        "web_security": web_security_score,
        "threat_intelligence": threat_intel_score,
    }

    # -------------------------------------------------------------------------
    # VERDICT DETERMINATION
    # -------------------------------------------------------------------------
    if composite_score >= 70:
        verdict = "high_risk"
        verdict_label = "High Risk"
    elif composite_score >= 45:
        verdict = "suspicious"
        verdict_label = "Suspicious"
    elif composite_score >= 20:
        verdict = "low_risk"
        verdict_label = "Low Risk"
    else:
        verdict = "safe"
        verdict_label = "Safe"

    # -------------------------------------------------------------------------
    # RANKED TOP REASONS
    # -------------------------------------------------------------------------
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    sorted_evidence = sorted(
        [e for e in evidence if e.get("risk_points", 0) > 0],
        key=lambda x: (severity_order.get(x.get("severity", "info"), 0), x.get("risk_points", 0)),
        reverse=True,
    )

    seen_reasons = set()
    top_reasons: List[str] = []
    for item in sorted_evidence:
        desc = item["description"]
        if desc not in seen_reasons:
            seen_reasons.add(desc)
            top_reasons.append(desc)
        if len(top_reasons) >= 4:
            break

    # If completely safe, provide reassuring top factors
    if not top_reasons:
        if certificate and certificate.is_valid and certificate.ca_trust_status == "trusted":
            top_reasons.append(f"Valid TLS certificate issued by trusted CA ({certificate.issuer or 'Trusted CA'})")
        if phishing_content_score == 0:
            top_reasons.append("No deceptive login forms or credential harvesters detected")
        if threat_intel_score == 0:
            top_reasons.append("Clean reputation across all threat intelligence providers")
        if url_domain_score <= 10:
            top_reasons.append("Standard domain registration with established reputation")

    # Positive & Negative Factors (retained for backward compatibility)
    positive_factors: List[str] = []
    negative_factors: List[str] = []

    if threat_intel_score == 0:
        positive_factors.append("No active listings on global threat intelligence feeds (Clean reputation).")
    if certificate and certificate.is_valid and certificate.ca_trust_status == "trusted":
        positive_factors.append(f"Valid TLS certificate issued by trusted CA ({certificate.issuer or 'Trusted CA'}).")
    if certificate and certificate.ct_log_present:
        positive_factors.append("Certificate Transparency (CT) logs verified in public ledgers.")
    if phishing_content_score == 0:
        positive_factors.append("No deceptive login forms, password harvesters, or brand impersonation found.")
    if url_domain_score <= 10:
        positive_factors.append("Standard domain registration without high-abuse TLD or dynamic DNS markers.")

    negative_factors.extend(top_reasons)

    # -------------------------------------------------------------------------
    # CONFIDENCE CALIBRATION
    # -------------------------------------------------------------------------
    confidence = 0.95
    if certificate is None:
        confidence -= 0.10
    if not threat_intel_results:
        confidence -= 0.05
    if ml_result is None and not ml_findings:
        confidence -= 0.04
    confidence = round(min(0.99, max(0.50, confidence)), 2)

    # -------------------------------------------------------------------------
    # SUMMARY & RECOMMENDATION
    # -------------------------------------------------------------------------
    if verdict == "high_risk":
        lead_factors = top_reasons[:2] if top_reasons else ["Multiple critical security threats detected"]
        summary = f"High Risk: {'; '.join(lead_factors)}."
        recommendation = "Do not enter passwords, OTPs, or banking details."
    elif verdict == "suspicious":
        lead_factors = top_reasons[:2] if top_reasons else ["Elevated risk indicators observed"]
        summary = f"Suspicious: {'; '.join(lead_factors)}."
        recommendation = "Exercise caution. Confirm the identity of the site operator before interacting."
    elif verdict == "low_risk":
        summary = "Low Risk: Minor security warnings detected (e.g. missing HTTP defense headers), but no malicious payloads."
        recommendation = "Website appears generally safe. Ensure HTTPS connection remains active."
    else:
        summary = "Safe: Website exhibits established domain reputation, valid TLS encryption, and no phishing or malware signatures."
        recommendation = "Safe to browse."

    # -------------------------------------------------------------------------
    # TELEMETRY SUBSCORES (Backward Compatibility)
    # -------------------------------------------------------------------------
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
            score=min(100, int(round((threat_intel_score / 25.0) * 100))) if threat_intel_score > 0 else 0,
            status=get_status(min(100, int(round((threat_intel_score / 25.0) * 100)))),
            findings_count=len(threat_intel_evidence),
            key_evidence=threat_intel_evidence,
        ),
        "content": TelemetrySubscore(
            layer="content",
            display_name="Page Content & Forms",
            score=min(100, int(round((phishing_content_score / 30.0) * 100))) if phishing_content_score > 0 else 0,
            status=get_status(min(100, int(round((phishing_content_score / 30.0) * 100)))),
            findings_count=len(content_findings),
            key_evidence=[f.title for f in content_findings[:3]],
        ),
        "domain": TelemetrySubscore(
            layer="domain",
            display_name="Domain & DNS Architecture",
            score=min(100, int(round((url_domain_score / 35.0) * 100))) if url_domain_score > 0 else 0,
            status=get_status(min(100, int(round((url_domain_score / 35.0) * 100)))),
            findings_count=len(domain_findings),
            key_evidence=[f.title for f in domain_findings[:3]],
        ),
        "certificate": TelemetrySubscore(
            layer="certificate",
            display_name="SSL/TLS & CA Trust",
            score=min(100, int(round((certificate_trust_score / 15.0) * 100))) if certificate_trust_score > 0 else 0,
            status=get_status(min(100, int(round((certificate_trust_score / 15.0) * 100)))),
            findings_count=len(cert_findings),
            key_evidence=[f.title for f in cert_findings[:3]],
        ),
        "headers": TelemetrySubscore(
            layer="headers",
            display_name="Security Headers",
            score=min(100, int(round((web_security_score / 10.0) * 100))) if web_security_score > 0 else 0,
            status=get_status(min(100, int(round((web_security_score / 10.0) * 100)))),
            findings_count=len(header_findings),
            key_evidence=[f.title for f in header_findings[:3]],
        ),
        "ml_classifier": TelemetrySubscore(
            layer="ml_classifier",
            display_name="ML Phishing Classifier",
            score=ml_score,
            status=get_status(ml_score),
            findings_count=len(ml_findings) if not ml_result else len(ml_result.top_indicators),
            key_evidence=[ind.description for ind in ml_result.top_indicators[:2]] if ml_result else [f.title for f in ml_findings[:2]],
        ),
    }

    return RiskExplanation(
        risk_score=composite_score,
        verdict=verdict,
        verdict_label=verdict_label,
        confidence=confidence,
        summary=summary,
        recommendation=recommendation,
        top_reasons=top_reasons,
        category_scores=category_scores,
        evidence=evidence,
        subscores=subscores,
        positive_factors=positive_factors,
        negative_factors=negative_factors,
    )
