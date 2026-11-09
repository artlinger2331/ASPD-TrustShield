"""
VirusTotal v3 Multi-Engine Security Telemetry Provider Adapter.
"""

import base64
from typing import Any, Dict, Optional
import httpx

from app.core.config import settings
from app.services.providers.base import ThreatIntelProvider, NormalizedThreatResult


class VirusTotalProvider(ThreatIntelProvider):
    """
    Queries VirusTotal v3 REST API across 70+ antivirus and threat engine scanners.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        timeout: float = 3.5,
        max_retries: int = 2,
    ):
        super().__init__(
            name="virustotal",
            timeout=timeout,
            max_retries=max_retries,
        )
        self.api_key = api_key or getattr(settings, "VIRUSTOTAL_API_KEY", "")

    def is_configured(self) -> bool:
        return bool(self.api_key and self.api_key.strip())

    def _execute_query(self, url: str, client: httpx.Client) -> NormalizedThreatResult:
        # Base64 urlsafe string identifier per VirusTotal v3 specification
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {
            "x-apikey": self.api_key.strip(),
            "Accept": "application/json",
        }

        resp = client.get(endpoint, headers=headers)

        # 404 Not Found in VirusTotal indicates URL is not cataloged in their database
        if resp.status_code == 404:
            return NormalizedThreatResult(
                source=self.name,
                match_found=False,
                threat_type="CLEAN",
                confidence=0.75,
                details={"status": "not_in_database"},
                raw_response={"message": "URL not cataloged in VirusTotal database"},
                status="ok",
            )

        resp.raise_for_status()

        data = resp.json()
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        malicious_count = stats.get("malicious", 0)
        suspicious_count = stats.get("suspicious", 0)
        harmless_count = stats.get("harmless", 0)
        reputation = attributes.get("reputation", 0)

        is_malicious = bool(malicious_count >= 1 or suspicious_count >= 2)

        if is_malicious:
            confidence = min(0.99, round(0.70 + (malicious_count * 0.05) + (suspicious_count * 0.02), 2))
            return NormalizedThreatResult(
                source=self.name,
                match_found=True,
                threat_type="MALICIOUS",
                confidence=confidence,
                details={
                    "malicious_engines": malicious_count,
                    "suspicious_engines": suspicious_count,
                    "harmless_engines": harmless_count,
                    "reputation": reputation,
                    "categories": attributes.get("categories", {}),
                },
                raw_response=stats,
                status="ok",
            )

        return NormalizedThreatResult(
            source=self.name,
            match_found=False,
            threat_type="CLEAN",
            confidence=0.92,
            details={
                "malicious_engines": malicious_count,
                "suspicious_engines": suspicious_count,
                "harmless_engines": harmless_count,
                "reputation": reputation,
            },
            raw_response=stats,
            status="ok",
        )
