"""
Google Safe Browsing Lookup API v4 Provider Adapter.
"""

from typing import Any, Dict, Optional
import httpx

from app.core.config import settings
from app.services.providers.base import ThreatIntelProvider, NormalizedThreatResult


class GoogleSafeBrowsingProvider(ThreatIntelProvider):
    """
    Queries Google Safe Browsing Lookup API v4 for malware, phishing, and social engineering.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        timeout: float = 3.5,
        max_retries: int = 2,
        backoff_factor: float = 0.5,
        failure_threshold: int = 3,
        cooldown_seconds: float = 60.0,
    ):
        super().__init__(
            name="google_safe_browsing",
            timeout=timeout,
            max_retries=max_retries,
            backoff_factor=backoff_factor,
            failure_threshold=failure_threshold,
            cooldown_seconds=cooldown_seconds,
        )
        self.api_key = api_key or getattr(settings, "GOOGLE_SAFE_BROWSING_API_KEY", "")

    def is_configured(self) -> bool:
        return bool(self.api_key and self.api_key.strip())

    def _execute_query(self, url: str, client: httpx.Client) -> NormalizedThreatResult:
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.api_key}"
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

        resp = client.post(endpoint, json=body)
        resp.raise_for_status()

        data = resp.json()
        matches = data.get("matches", [])
        if matches:
            threat_type = matches[0].get("threatType", "MALICIOUS")
            return NormalizedThreatResult(
                source=self.name,
                match_found=True,
                threat_type=threat_type,
                confidence=0.98,
                details={
                    "threat_type": threat_type,
                    "platform_type": matches[0].get("platformType"),
                    "cache_duration": matches[0].get("cacheDuration"),
                    "total_matches": len(matches),
                },
                raw_response=data,
                status="ok",
            )

        return NormalizedThreatResult(
            source=self.name,
            match_found=False,
            threat_type="CLEAN",
            confidence=0.95,
            details={"status": "clean"},
            raw_response=data,
            status="ok",
        )
