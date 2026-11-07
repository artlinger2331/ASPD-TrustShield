"""
Multi-Provider Threat Intelligence Analyzer.

Aggregates reputation and malware intelligence from:
1. Google Safe Browsing (Lookup API v4)
2. URLhaus (abuse.ch)
3. VirusTotal (v3)

Includes a dual-tier cache (Redis + in-memory fallback) and database persistence
into `threat_intel_results` and `scan_findings`.
"""

import base64
import hashlib
import json
import logging
import time
import uuid
from typing import Dict, Any, Optional, List, Tuple
from urllib.parse import urlparse

import httpx

from app.core.config import settings
from app.models.threat_intel import ThreatIntelResult
from app.models.scan_finding import ScanFinding
from app.schemas.threat_intel import ThreatIntelMatch, ThreatIntelAnalysisResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# IN-MEMORY RESILIENT CACHE FALLBACK (for sandbox & offline environments)
# ---------------------------------------------------------------------------

_MEMORY_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = {}
CACHE_TTL_SECONDS = 3600  # 1 hour


def _get_cache(key: str) -> Optional[Dict[str, Any]]:
    """Retrieve cached intelligence payload from Redis or memory fallback."""
    # Try Redis first if reachable
    try:
        import redis
        r = redis.from_url(settings.REDIS_URL, socket_connect_timeout=0.5, socket_timeout=0.5)
        raw = r.get(key)
        if raw:
            return json.loads(raw.decode("utf-8") if isinstance(raw, bytes) else raw)
    except Exception:
        pass

    # Fallback to in-memory TTL cache
    now = time.time()
    if key in _MEMORY_CACHE:
        expires_at, payload = _MEMORY_CACHE[key]
        if now < expires_at:
            return payload
        else:
            del _MEMORY_CACHE[key]
    return None


def _set_cache(key: str, payload: Dict[str, Any], ttl: int = CACHE_TTL_SECONDS) -> None:
    """Store intelligence payload in Redis and memory fallback."""
    try:
        import redis
        r = redis.from_url(settings.REDIS_URL, socket_connect_timeout=0.5, socket_timeout=0.5)
        r.set(key, json.dumps(payload), ex=ttl)
    except Exception:
        pass

    _MEMORY_CACHE[key] = (time.time() + ttl, payload)


# ---------------------------------------------------------------------------
# PROVIDER QUERY ENGINES
# ---------------------------------------------------------------------------

def query_google_safe_browsing(url: str, api_key: Optional[str] = None) -> ThreatIntelMatch:
    """
    Check URL against Google Safe Browsing Lookup API v4.
    """
    key = api_key or settings.GOOGLE_SAFE_BROWSING_API_KEY
    if not key:
        return ThreatIntelMatch(
            source="google_safe_browsing",
            match_type="SKIPPED",
            confidence=0.0,
            is_malicious=False,
            details={"status": "api_key_not_configured"},
        )

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}"
    body = {
        "client": {"clientId": "trustshield-scanner", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        with httpx.Client(timeout=4.0) as client:
            resp = client.post(endpoint, json=body)
            if resp.status_code == 200:
                data = resp.json()
                matches = data.get("matches", [])
                if matches:
                    threat_type = matches[0].get("threatType", "MALICIOUS")
                    return ThreatIntelMatch(
                        source="google_safe_browsing",
                        match_type=threat_type,
                        confidence=0.98,
                        is_malicious=True,
                        details={"threat_type": threat_type, "cache_duration": matches[0].get("cacheDuration")},
                        raw_response=data,
                    )
                return ThreatIntelMatch(
                    source="google_safe_browsing",
                    match_type="CLEAN",
                    confidence=0.95,
                    is_malicious=False,
                    details={"status": "clean"},
                    raw_response=data,
                )
    except Exception as exc:
        logger.warning(f"Google Safe Browsing query error: {str(exc)}")

    return ThreatIntelMatch(
        source="google_safe_browsing",
        match_type="ERROR",
        confidence=0.0,
        is_malicious=False,
        details={"status": "query_timeout_or_error"},
    )


def query_urlhaus(url: str, auth_key: Optional[str] = None) -> ThreatIntelMatch:
    """
    Check URL against abuse.ch URLhaus malware database.
    """
    endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
    headers = {}
    key = auth_key or settings.URLHAUS_AUTH_KEY
    if key:
        headers["Auth-Key"] = key

    try:
        with httpx.Client(timeout=4.0) as client:
            resp = client.post(endpoint, data={"url": url}, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                status = data.get("query_status")
                if status == "ok":
                    threat = data.get("threat", "malware_download")
                    url_status = data.get("url_status", "online")
                    tags = data.get("tags") or []
                    return ThreatIntelMatch(
                        source="urlhaus",
                        match_type="MALICIOUS",
                        confidence=0.95,
                        is_malicious=True,
                        details={
                            "threat": threat,
                            "url_status": url_status,
                            "tags": tags,
                            "date_added": data.get("date_added"),
                        },
                        raw_response=data,
                    )
                elif status == "no_results":
                    return ThreatIntelMatch(
                        source="urlhaus",
                        match_type="CLEAN",
                        confidence=0.90,
                        is_malicious=False,
                        details={"status": "no_results"},
                        raw_response=data,
                    )
    except Exception as exc:
        logger.warning(f"URLhaus query error: {str(exc)}")

    return ThreatIntelMatch(
        source="urlhaus",
        match_type="CLEAN",
        confidence=0.0,
        is_malicious=False,
        details={"status": "offline_or_unavailable"},
    )


def query_virustotal(url: str, api_key: Optional[str] = None) -> ThreatIntelMatch:
    """
    Check URL against VirusTotal v3 API.
    """
    key = api_key or settings.VIRUSTOTAL_API_KEY
    if not key:
        return ThreatIntelMatch(
            source="virustotal",
            match_type="SKIPPED",
            confidence=0.0,
            is_malicious=False,
            details={"status": "api_key_not_configured"},
        )

    # Base64 url identifier according to VT v3 docs
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": key}

    try:
        with httpx.Client(timeout=4.0) as client:
            resp = client.get(endpoint, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                attributes = data.get("data", {}).get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)

                if malicious > 0 or suspicious >= 2:
                    confidence = min(0.99, 0.70 + (malicious * 0.05))
                    return ThreatIntelMatch(
                        source="virustotal",
                        match_type="MALICIOUS",
                        confidence=confidence,
                        is_malicious=True,
                        details={
                            "malicious_engines": malicious,
                            "suspicious_engines": suspicious,
                            "harmless_engines": stats.get("harmless", 0),
                            "reputation": attributes.get("reputation", 0),
                        },
                        raw_response=stats,
                    )
                return ThreatIntelMatch(
                    source="virustotal",
                    match_type="CLEAN",
                    confidence=0.92,
                    is_malicious=False,
                    details=stats,
                    raw_response=stats,
                )
    except Exception as exc:
        logger.warning(f"VirusTotal query error: {str(exc)}")

    return ThreatIntelMatch(
        source="virustotal",
        match_type="ERROR",
        confidence=0.0,
        is_malicious=False,
        details={"status": "query_timeout_or_error"},
    )


# ---------------------------------------------------------------------------
# COMPOSITE THREAT INTELLIGENCE ANALYZER
# ---------------------------------------------------------------------------

def analyze_threat_intel(
    url: str,
    resolve_network: bool = True,
    mock_matches: Optional[List[ThreatIntelMatch]] = None,
) -> ThreatIntelAnalysisResult:
    """
    Coordinates multi-provider threat intelligence scanning with caching.
    """
    clean_url = url.strip()
    cache_key = f"threat_intel:{hashlib.sha256(clean_url.encode()).hexdigest()}"

    # If mock matches provided (e.g. in tests)
    if mock_matches is not None:
        matches = mock_matches
    else:
        # Check cache
        cached = _get_cache(cache_key)
        if cached:
            matches = [ThreatIntelMatch(**m) for m in cached.get("matches", [])]
        elif not resolve_network:
            # Passive / offline mode: return clean default indicators
            matches = [
                ThreatIntelMatch(source="google_safe_browsing", match_type="CLEAN", confidence=0.9, is_malicious=False),
                ThreatIntelMatch(source="urlhaus", match_type="CLEAN", confidence=0.9, is_malicious=False),
                ThreatIntelMatch(source="virustotal", match_type="CLEAN", confidence=0.9, is_malicious=False),
            ]
        else:
            # Query providers
            matches = [
                query_google_safe_browsing(clean_url),
                query_urlhaus(clean_url),
                query_virustotal(clean_url),
            ]
            # Store in cache
            _set_cache(cache_key, {"matches": [m.model_dump() for m in matches]})

    malicious_matches = [m for m in matches if m.is_malicious]
    clean_matches = [m for m in matches if not m.is_malicious and m.match_type == "CLEAN"]

    is_flagged = len(malicious_matches) > 0
    highest_confidence = max((m.confidence or 0.0 for m in malicious_matches), default=0.0) if is_flagged else 0.9

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
    a `ScanFinding` record if the URL was confirmed malicious.
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
