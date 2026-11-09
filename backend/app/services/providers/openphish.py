"""
OpenPhish Active Phishing Threat Intelligence Provider Adapter.
"""

from typing import Any, Dict, Optional
import httpx

from app.core.config import settings
from app.services.providers.base import ThreatIntelProvider, NormalizedThreatResult


class OpenPhishProvider(ThreatIntelProvider):
    """
    Queries OpenPhish global phishing intelligence feeds and API.
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
            name="openphish",
            timeout=timeout,
            max_retries=max_retries,
            backoff_factor=backoff_factor,
            failure_threshold=failure_threshold,
            cooldown_seconds=cooldown_seconds,
        )
        self.api_key = api_key or getattr(settings, "OPENPHISH_API_KEY", "")

    def is_configured(self) -> bool:
        return bool(self.api_key and self.api_key.strip())

    def _execute_query(self, url: str, client: httpx.Client) -> NormalizedThreatResult:
        endpoint = "https://api.openphish.com/v1/url"
        headers = {
            "X-API-Key": self.api_key.strip(),
            "User-Agent": "trustshield-threat-scanner/1.0",
        }

        resp = client.post(endpoint, json={"url": url}, headers=headers)
        resp.raise_for_status()

        data = resp.json()
        is_phish = bool(data.get("phishing", False) or data.get("in_feed", False))

        if is_phish:
            target = data.get("target") or data.get("brand") or "Generic Phishing"
            return NormalizedThreatResult(
                source=self.name,
                match_found=True,
                threat_type="PHISHING",
                confidence=0.94,
                details={
                    "target_brand": target,
                    "sector": data.get("sector"),
                    "ip": data.get("ip"),
                    "country": data.get("country"),
                    "discovery_time": data.get("discovery_time"),
                },
                raw_response=data,
                status="ok",
            )

        return NormalizedThreatResult(
            source=self.name,
            match_found=False,
            threat_type="CLEAN",
            confidence=0.90,
            details={"status": "clean"},
            raw_response=data,
            status="ok",
        )
