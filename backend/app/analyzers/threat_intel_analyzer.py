"""
Multi-Provider Threat Intelligence Analyzer & Persistence Engine.

Coordinates reputation and malware intelligence across pluggable provider adapters:
1. Google Safe Browsing (Lookup API v4)
2. URLhaus (abuse.ch)
3. PhishTank
4. OpenPhish
5. VirusTotal (v3)

Includes dual-tier caching (Redis + memory fallback), fault-isolated circuit breaking,
and database persistence into `threat_intel_results` and `scan_findings`.
"""

import hashlib
import json
import logging
import time
import uuid
from typing import Dict, Any, Optional, List, Tuple

from app.core.config import settings
from app.models.threat_intel import ThreatIntelResult
from app.models.scan_finding import ScanFinding
from app.schemas.threat_intel import ThreatIntelMatch, ThreatIntelAnalysisResult
from app.services.providers import (
    GLOBAL_THREAT_INTEL_MANAGER,
    get_threat_intel_manager,
    NormalizedThreatResult,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# BACKWARD COMPATIBLE IN-MEMORY CACHE EXPORTS
# ---------------------------------------------------------------------------

_MEMORY_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = {}
CACHE_TTL_SECONDS = 3600


def _get_cache(key: str) -> Optional[Dict[str, Any]]:
    """Legacy helper: retrieves cached payload from manager or memory fallback."""
    # Check manager first
    cached_list = GLOBAL_THREAT_INTEL_MANAGER._get_cache(key)
    if cached_list is not None:
        return {"matches": cached_list}

    # Direct memory cache fallback
    now = time.time()
    if key in _MEMORY_CACHE:
        expires_at, payload = _MEMORY_CACHE[key]
        if now < expires_at:
            return payload
        else:
            del _MEMORY_CACHE[key]
    return None


def _set_cache(key: str, payload: Dict[str, Any], ttl: int = CACHE_TTL_SECONDS) -> None:
    """Legacy helper: stores payload in manager cache and memory fallback."""
    matches = payload.get("matches", [])
    GLOBAL_THREAT_INTEL_MANAGER._set_cache(key, matches, ttl=ttl)
    _MEMORY_CACHE[key] = (time.time() + ttl, payload)


# ---------------------------------------------------------------------------
# DIRECT PROVIDER WRAPPERS (Backward Compatibility)
# ---------------------------------------------------------------------------

def query_google_safe_browsing(url: str, api_key: Optional[str] = None) -> ThreatIntelMatch:
    """Queries Google Safe Browsing provider adapter."""
    provider = GLOBAL_THREAT_INTEL_MANAGER.get_provider("google_safe_browsing")
    if provider:
        if api_key:
            from app.services.providers.google_safe_browsing import GoogleSafeBrowsingProvider
            custom_provider = GoogleSafeBrowsingProvider(api_key=api_key)
            return custom_provider.query(url).to_threat_intel_match()
        return provider.query(url).to_threat_intel_match()
    return ThreatIntelMatch(source="google_safe_browsing", match_type="SKIPPED", is_malicious=False)


def query_urlhaus(url: str, auth_key: Optional[str] = None) -> ThreatIntelMatch:
    """Queries URLhaus provider adapter."""
    provider = GLOBAL_THREAT_INTEL_MANAGER.get_provider("urlhaus")
    if provider:
        if auth_key:
            from app.services.providers.urlhaus import URLhausProvider
            custom_provider = URLhausProvider(auth_key=auth_key)
            return custom_provider.query(url).to_threat_intel_match()
        return provider.query(url).to_threat_intel_match()
    return ThreatIntelMatch(source="urlhaus", match_type="CLEAN", is_malicious=False)


def query_virustotal(url: str, api_key: Optional[str] = None) -> ThreatIntelMatch:
    """Queries VirusTotal provider adapter."""
    provider = GLOBAL_THREAT_INTEL_MANAGER.get_provider("virustotal")
    if provider:
        if api_key:
            from app.services.providers.virustotal import VirusTotalProvider
            custom_provider = VirusTotalProvider(api_key=api_key)
            return custom_provider.query(url).to_threat_intel_match()
        return provider.query(url).to_threat_intel_match()
    return ThreatIntelMatch(source="virustotal", match_type="SKIPPED", is_malicious=False)


# ---------------------------------------------------------------------------
# COMPOSITE THREAT INTELLIGENCE ANALYZER
# ---------------------------------------------------------------------------

def analyze_threat_intel(
    url: str,
    resolve_network: bool = True,
    mock_matches: Optional[List[ThreatIntelMatch]] = None,
) -> ThreatIntelAnalysisResult:
    """
    Coordinates multi-provider threat intelligence scanning with circuit-breaker protection,
    exponential backoff retries, and dual-tier caching.
    """
    clean_url = url.strip()

    # 1. Mock override for testing
    if mock_matches is not None:
        matches = mock_matches
    else:
        # 2. Query through the pluggable ThreatIntelManager
        normalized_results = GLOBAL_THREAT_INTEL_MANAGER.query_all(
            url=clean_url,
            resolve_network=resolve_network,
            use_cache=True,
        )
        matches = [r.to_threat_intel_match() for r in normalized_results]

    malicious_matches = [m for m in matches if m.is_malicious]
    clean_matches = [m for m in matches if not m.is_malicious and m.match_type == "CLEAN"]

    is_flagged = len(malicious_matches) > 0
    highest_confidence = max((m.confidence or 0.0 for m in malicious_matches), default=0.0) if is_flagged else 0.90

    if is_flagged:
        sources_str = ", ".join(m.source for m in malicious_matches)
        threat_types = ", ".join(set(m.match_type or "MALICIOUS" for m in malicious_matches))
        summary = f"Flagged as {threat_types} by {sources_str} threat intelligence."
    else:
        summary = "No security intelligence feeds reported this domain as malicious."

    return ThreatIntelAnalysisResult(
        url=clean_url,
        is_flagged=is_flagged,
        matches=matches,
        malicious_count=len(malicious_matches),
        clean_count=len(clean_matches),
        highest_confidence=highest_confidence,
        summary=summary,
    )


# ---------------------------------------------------------------------------
# DATABASE PERSISTENCE
# ---------------------------------------------------------------------------

def save_threat_intel_to_db_sync(
    scan_id: uuid.UUID,
    result: ThreatIntelAnalysisResult,
    db: Any,
) -> List[ThreatIntelResult]:
    """
    Persists threat intel matches to `threat_intel_results` and creates
    a high-priority `ScanFinding` record if any provider flagged the URL as malicious.
    """
    persisted: List[ThreatIntelResult] = []

    for m in result.matches:
        record = ThreatIntelResult(
            scan_id=scan_id,
            source=m.source,
            match_type=m.match_type,
            confidence=m.confidence,
            details=m.details,
            raw_response=m.raw_response,
        )
        db.add(record)
        persisted.append(record)

    # If flagged as malicious, create a high-priority ScanFinding
    if result.is_flagged:
        flagged_sources = [m.source for m in result.matches if m.is_malicious]
        finding = ScanFinding(
            scan_id=scan_id,
            category="threat_intelligence",
            title=f"Flagged by Threat Intelligence ({', '.join(flagged_sources)})",
            severity="critical",
            confidence=result.highest_confidence,
            description=result.summary,
            evidence={
                "flagged_sources": flagged_sources,
                "matches": [m.model_dump() for m in result.matches if m.is_malicious],
            },
            recommendation="Do not access or browse this website. It is confirmed dangerous by global threat feeds.",
            risk_points=80,
            raw_data={"summary": result.summary},
        )
        db.add(finding)

    db.commit()
    for r in persisted:
        db.refresh(r)

    return persisted
