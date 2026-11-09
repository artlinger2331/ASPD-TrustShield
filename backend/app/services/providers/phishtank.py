"""
PhishTank Community-Verified Phishing Intelligence Provider Adapter.
"""

from typing import Any, Dict, Optional
import httpx

from app.core.config import settings
from app.services.providers.base import ThreatIntelProvider, NormalizedThreatResult


class PhishTankProvider(ThreatIntelProvider):
    """
    Queries PhishTank crowdsourced and verified anti-phishing registry.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        timeout: float = 3.5,
        max_retries: int = 2,
    ):
        super().__init__(
            name="phishtank",
            timeout=timeout,
            max_retries=max_retries,
        )
        self.api_key = api_key or getattr(settings, "PHISHTANK_API_KEY", "")

    def is_configured(self) -> bool:
        # PhishTank API supports queries with or without an application key
        return True

    def _execute_query(self, url: str, client: httpx.Client) -> NormalizedThreatResult:
        endpoint = "https://checkurl.phishtank.com/checkurl/"
        data: Dict[str, Any] = {
            "url": url,
            "format": "json",
        }
        if self.api_key and self.api_key.strip():
            data["app_key"] = self.api_key.strip()

        headers = {
            "User-Agent": "phishtank/trustshield-security-scanner",
        }

        resp = client.post(endpoint, data=data, headers=headers)
        resp.raise_for_status()

        resp_data = resp.json()
        results = resp_data.get("results", {})

        in_database = bool(results.get("in_database", False))
        is_valid_phish = bool(results.get("valid", False))
        is_verified = bool(results.get("verified", False))

        if in_database and is_valid_phish:
            confidence = 0.98 if is_verified else 0.88
            return NormalizedThreatResult(
                source=self.name,
                match_found=True,
                threat_type="PHISHING",
                confidence=confidence,
                details={
                    "phish_id": results.get("phish_id"),
                    "phish_detail_page": results.get("phish_detail_page"),
                    "verified": is_verified,
                    "verified_at": results.get("verification_time"),
                },
                raw_response=resp_data,
                status="ok",
            )

        return NormalizedThreatResult(
            source=self.name,
            match_found=False,
            threat_type="CLEAN",
            confidence=0.90,
            details={
                "in_database": in_database,
                "status": "clean",
            },
            raw_response=resp_data,
            status="ok",
        )
