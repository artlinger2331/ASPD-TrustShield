"""
Unit and integration tests for Multi-Provider Threat Intelligence Analyzer.
"""

import uuid
import pytest
from app.analyzers.threat_intel_analyzer import (
    analyze_threat_intel,
    save_threat_intel_to_db_sync,
    _MEMORY_CACHE,
    _get_cache,
    _set_cache,
)
from app.models.scan import Scan
from app.models.threat_intel import ThreatIntelResult
from app.models.scan_finding import ScanFinding
from app.schemas.threat_intel import ThreatIntelMatch
from app.db.session import local_session_factory


def test_threat_intel_cache_mechanism():
    """Verify in-memory and TTL caching operations."""
    test_key = "threat_intel:test_cache_key"
    payload = {"matches": [{"source": "google_safe_browsing", "match_type": "CLEAN"}]}
    
    _set_cache(test_key, payload, ttl=60)
    cached = _get_cache(test_key)
    assert cached is not None
    assert cached["matches"][0]["source"] == "google_safe_browsing"


def test_threat_intel_offline_benign():
    """Verify clean results in passive/offline mode."""
    res = analyze_threat_intel("https://google.com", resolve_network=False)
    assert res.is_flagged is False
    assert res.malicious_count == 0
    assert len(res.matches) == 3


def test_threat_intel_flagged_detection():
    """Verify malicious classification when providers return matches."""
    mock_matches = [
        ThreatIntelMatch(
            source="google_safe_browsing",
            match_type="SOCIAL_ENGINEERING",
            confidence=0.98,
            is_malicious=True,
            details={"threat_type": "SOCIAL_ENGINEERING"},
        ),
        ThreatIntelMatch(
            source="urlhaus",
            match_type="MALICIOUS",
            confidence=0.95,
            is_malicious=True,
            details={"threat": "malware_download"},
        ),
        ThreatIntelMatch(
            source="virustotal",
            match_type="CLEAN",
            confidence=0.9,
            is_malicious=False,
        ),
    ]

    res = analyze_threat_intel("https://evil-phish-portal.xyz/login", mock_matches=mock_matches)
    assert res.is_flagged is True
    assert res.malicious_count == 2
    assert res.highest_confidence >= 0.95
    assert "google_safe_browsing" in res.summary


def test_threat_intel_database_persistence():
    """Verify that results are saved to threat_intel_results and critical finding is generated in scan_findings."""
    session = local_session_factory()
    try:
        scan = Scan(
            input_url="https://malicious-test-link.xyz/bank",
            normalized_url="https://malicious-test-link.xyz/bank",
            status="running",
        )
        session.add(scan)
        session.commit()
        session.refresh(scan)

        mock_matches = [
            ThreatIntelMatch(
                source="urlhaus",
                match_type="MALICIOUS",
                confidence=0.95,
                is_malicious=True,
                details={"threat": "credential_stealer"},
            ),
        ]
        res = analyze_threat_intel("https://malicious-test-link.xyz/bank", mock_matches=mock_matches)
        persisted = save_threat_intel_to_db_sync(scan.id, res, session)

        assert len(persisted) == 1
        assert persisted[0].source == "urlhaus"
        assert persisted[0].match_type == "MALICIOUS"

        # Check that a critical scan finding was also generated
        finding = session.query(ScanFinding).filter(
            ScanFinding.scan_id == scan.id,
            ScanFinding.category == "threat_intelligence",
        ).first()

        assert finding is not None
        assert finding.severity == "critical"
        assert finding.risk_points == 80
        assert "urlhaus" in finding.title
    finally:
        session.close()
