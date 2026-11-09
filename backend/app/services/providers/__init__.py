"""
Pluggable Threat Intelligence Providers for TrustShield.
"""

from app.services.providers.base import (
    CircuitBreaker,
    CircuitState,
    NormalizedThreatResult,
    ProviderHealth,
    ThreatIntelProvider,
)
from app.services.providers.google_safe_browsing import GoogleSafeBrowsingProvider
from app.services.providers.urlhaus import URLhausProvider
from app.services.providers.phishtank import PhishTankProvider
from app.services.providers.openphish import OpenPhishProvider
from app.services.providers.virustotal import VirusTotalProvider
from app.services.providers.manager import (
    ThreatIntelManager,
    GLOBAL_THREAT_INTEL_MANAGER,
    get_threat_intel_manager,
)

__all__ = [
    "CircuitBreaker",
    "CircuitState",
    "NormalizedThreatResult",
    "ProviderHealth",
    "ThreatIntelProvider",
    "GoogleSafeBrowsingProvider",
    "URLhausProvider",
    "PhishTankProvider",
    "OpenPhishProvider",
    "VirusTotalProvider",
    "ThreatIntelManager",
    "GLOBAL_THREAT_INTEL_MANAGER",
    "get_threat_intel_manager",
]

