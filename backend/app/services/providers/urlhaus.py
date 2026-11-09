"""
abuse.ch URLhaus Malware & Botnet C2 Intelligence Provider Adapter.
"""

from typing import Any, Dict, Optional
import httpx

from app.core.config import settings
from app.services.providers.base import ThreatIntelProvider, NormalizedThreatResult


class URLhausProvider(ThreatIntelProvider):
    """
    Queries abuse.ch URLhaus database for active malware download payloads and botnets.
    """

    def __init__(
        self,
        auth_key: Optional[str] = None,
        timeout: float = 3.5,
        max_retries: int = 2,
        backoff_factor: float = 0.5,
        failure_threshold: int = 3,
        cooldown_seconds: float = 60.0,
    ):
        super().__init__(
            name="urlhaus",
            timeout=timeout,
            max_retries=max_retries,
            backoff_factor=backoff_factor,
            failure_threshold=failure_threshold,
            cooldown_seconds=cooldown_seconds,
        )
        self.auth_key = auth_key or getattr(settings, "URLHAUS_AUTH_KEY", "")

    def is_configured(self) -> bool:
        # Public URLhaus query works without auth key, but uses Auth-Key if available
        return True

    def _execute_query(self, url: str, client: httpx.Client) -> NormalizedThreatResult:
        endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
        headers = {}
        if self.auth_key and self.auth_key.strip():
            headers["Auth-Key"] = self.auth_key.strip()

        resp = client.post(endpoint, data={"url": url}, headers=headers)
        resp.raise_for_status()

        data = resp.json()
        query_status = data.get("query_status")

        if query_status == "ok":
            threat = data.get("threat", "malware_download")
            return NormalizedThreatResult(
                source=self.name,
                match_found=True,
                threat_type="MALWARE",
                confidence=0.95,
                details={
                    "threat": threat,
                    "url_status": data.get("url_status", "online"),
                    "tags": data.get("tags") or [],
                    "date_added": data.get("date_added"),
                    "reporter": data.get("reporter"),
                },
                raw_response=data,
                status="ok",
            )
        elif query_status == "no_results":
            return NormalizedThreatResult(
                source=self.name,
                match_found=False,
                threat_type="CLEAN",
                confidence=0.90,
                details={"status": "no_results"},
                raw_response=data,
                status="ok",
            )

        return NormalizedThreatResult(
            source=self.name,
            match_found=False,
            threat_type="CLEAN",
            confidence=0.85,
            details={"status": query_status or "clean"},
            raw_response=data,
            status="ok",
        )
