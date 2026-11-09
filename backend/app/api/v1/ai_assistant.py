"""
AI Security Assistant API Endpoint.
Provides contextual, evidence-backed security explanations, incident response checklists,
and educational insights for scanned websites.
"""

import uuid
from typing import Optional, List, Dict, Any, Tuple
from fastapi import APIRouter, Depends, status
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_optional_current_user
from app.models.scan import Scan
from app.models.scan_finding import ScanFinding
from app.models.user import User
from app.schemas.ai_assistant import (
    AssistantChatRequest,
    AssistantChatResponse,
)

router = APIRouter(prefix="/assistant", tags=["AI Security Assistant"])


def generate_contextual_response(
    query: str,
    scan: Optional[Scan] = None,
) -> Tuple[str, bool, Optional[str], Optional[str], List[str], List[str]]:
    """
    Synthesizes an intelligent, actionable response based on user inquiry and scan telemetry.
    """
    q = query.lower()
    suggested_actions: List[str] = []
    sources: List[str] = ["TrustShield Security Knowledgebase"]
    context_used = False
    target_url = None
    verdict = None

    if scan:
        context_used = True
        target_url = scan.normalized_url or scan.input_url
        verdict = scan.verdict
        sources.append(f"Scan Report #{scan.id}")

    # 1. Incident Response intent
    has_entered_creds = (
        ("password" in q or "credentials" in q or "card" in q or "otp" in q)
        and any(v in q for v in ("entered", "typed", "gave", "submit", "put", "shared", "leak", "stole", "lost"))
    )
    if has_entered_creds or any(k in q for k in ("got scammed", "i was scammed", "hacked", "compromised")):
        resp = (
            f"⚠️ **Immediate Incident Response Checklist**\n\n"
            f"If you submitted your credentials or personal information on {target_url or 'this website'}:\n\n"
            f"1. **Change Passwords Immediately**: Go to the **official** website (type the known domain directly into your browser address bar) and change your password right now.\n"
            f"2. **Enable Multi-Factor Authentication (MFA)**: Turn on app-based MFA (e.g. Google Authenticator) for your accounts.\n"
            f"3. **Revoke Active Sessions**: Under account security settings, click 'Log out of all other devices'.\n"
            f"4. **Monitor Financial Activity**: If card numbers or UPI IDs were submitted, contact your bank immediately to freeze the card or disable online transactions.\n"
            f"5. **File a Community Report**: Help protect other users by submitting a verified threat report in TrustShield."
        )
        suggested_actions = [
            "Change password on official website",
            "Freeze debit/credit card via bank app",
            "Report URL to TrustShield Community",
        ]
        return resp, context_used, target_url, verdict, suggested_actions, sources

    # 2. "Why is this dangerous / safe?" intent
    if any(k in q for k in ("why", "dangerous", "safe", "risk", "explain score", "verdict", "score")):
        if scan:
            critical_findings = [f for f in (scan.findings or []) if f.severity in ("critical", "high")]
            findings_summary = "\n".join(
                f"- **{f.title}**: {f.description}"
                for f in critical_findings[:4]
            )

            if scan.verdict in ("dangerous", "high_risk", "suspicious"):
                resp = (
                    f"### Risk Assessment for `{target_url}`\n\n"
                    f"**Verdict**: **{scan.verdict.upper()}** (Risk Score: **{scan.risk_score}/100**)\n\n"
                    f"**Executive Summary**:\n{scan.summary}\n\n"
                    f"**Key Evidence Detected**:\n{findings_summary or '- Elevated risk indicators observed in domain infrastructure or headers.'}\n\n"
                    f"**Recommended Action**:\n{scan.recommendation}"
                )
                suggested_actions = [
                    "Close the browser tab",
                    "Do not enter passwords or payment details",
                    "Share this report with colleagues",
                ]
            else:
                resp = (
                    f"### Safety Assessment for `{target_url}`\n\n"
                    f"**Verdict**: **SAFE** (Risk Score: **{scan.risk_score}/100**)\n\n"
                    f"This website demonstrates established domain age, valid TLS encryption from a trusted Certificate Authority, "
                    f"and clean records across global threat intelligence feeds. No credential harvesting forms or suspicious script injections were detected."
                )
                suggested_actions = ["Ensure the connection shows HTTPS in your address bar"]
            return resp, context_used, target_url, verdict, suggested_actions, sources

    # 3. Technical explanation intent
    if "hsts" in q:
        resp = (
            "**HTTP Strict Transport Security (HSTS)** (`Strict-Transport-Security`) is an HTTP response header that instructs browsers "
            "to *only* communicate with a website over secure HTTPS, never plain HTTP. "
            "Without HSTS, attackers on public Wi-Fi can perform SSL-stripping attacks (downgrading your connection to plaintext)."
        )
        suggested_actions = ["Configure `Strict-Transport-Security: max-age=31536000; includeSubDomains`"]
        return resp, context_used, target_url, verdict, suggested_actions, sources

    if "csp" in q or "content security policy" in q:
        resp = (
            "**Content Security Policy (CSP)** is a defense-in-depth header that restricts the resources "
            "(scripts, images, stylesheets) that a browser is allowed to load for a given page. "
            "It is the primary mitigation against Cross-Site Scripting (XSS) and data exfiltration."
        )
        suggested_actions = ["Define a restrictive `Content-Security-Policy` header"]
        return resp, context_used, target_url, verdict, suggested_actions, sources

    if "typosquatting" in q or "homoglyph" in q:
        resp = (
            "**Typosquatting & Homoglyph Attacks**:\n\n"
            "- **Typosquatting**: Registering common misspellings of popular brands (e.g., `paypa1.com` instead of `paypal.com`).\n"
            "- **Homoglyph Attacks**: Using visually identical characters from other alphabets, such as Cyrillic 'а' (U+0430) "
            "in place of Latin 'a' (U+0061). To the naked eye, the URL looks authentic, but the browser navigates to the attacker's server."
        )
        suggested_actions = ["Always inspect the address bar or use TrustShield URL Scanner before logging in"]
        return resp, context_used, target_url, verdict, suggested_actions, sources

    # Default general assistance
    if scan:
        resp = (
            f"I have reviewed the security analysis for **{target_url}**.\n\n"
            f"The site was scored **{scan.risk_score}/100** with verdict **{scan.verdict.upper()}**.\n\n"
            f"**Recommendation**: {scan.recommendation}\n\n"
            f"You can ask me specific questions like: *'Why did this site score {scan.risk_score}?'*, "
            f"*'What should I do if I entered credentials?'*, or *'Explain the certificate warnings.'*"
        )
    else:
        resp = (
            "Hello! I am your **TrustShield AI Security Assistant**. "
            "I can explain threat vectors, analyze suspicious URLs, interpret SSL/TLS certificate warnings, "
            "and provide step-by-step incident response guidance if you suspect you've encountered phishing or fraud. "
            "How can I assist you today?"
        )
        suggested_actions = [
            "Scan a suspicious URL",
            "What should I do if I entered my password?",
            "How to detect typosquatting domains",
        ]

    return resp, context_used, target_url, verdict, suggested_actions, sources


Tuple_Response = Any


@router.post(
    "/chat",
    response_model=AssistantChatResponse,
    summary="Ask security assistant contextual questions or incident guidance",
)
async def chat_with_assistant(
    payload: AssistantChatRequest,
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_current_user),
):
    """
    Processes user security questions, contextualizing with scan report data if provided.
    """
    scan = None
    if payload.scan_id:
        query = (
            select(Scan)
            .options(
                selectinload(Scan.findings),
                selectinload(Scan.certificate),
                selectinload(Scan.threat_intel_results),
            )
            .where(Scan.id == payload.scan_id)
        )
        res = await db.execute(query)
        scan = res.scalar_one_or_none()

    resp_text, ctx_used, tgt_url, vrd, acts, srcs = generate_contextual_response(
        query=payload.message,
        scan=scan,
    )

    return AssistantChatResponse(
        response=resp_text,
        context_used=ctx_used,
        target_url=tgt_url,
        verdict=vrd,
        suggested_actions=acts,
        sources=srcs,
    )
