"""
Pluggable Threat Intelligence Manager & Concurrent Multi-Provider Coordinator.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
import logging
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from app.core.config import settings
from app.services.providers.base import (
    ThreatIntelProvider,
    NormalizedThreatResult,
)
from app.services.providers.google_safe_browsing import GoogleSafeBrowsingProvider
from app.services.providers.urlhaus import URLhausProvider
from app.services.providers.phishtank import PhishTankProvider
from app.services.providers.openphish import OpenPhishProvider
from app.services.providers.virustotal import VirusTotalProvider

logger = logging.getLogger(__name__)


class ThreatIntelManager:
    """
    Coordinates multi-provider threat intelligence scanning with concurrent execution,
    circuit breaker isolation, and dual-tier (Redis + memory) caching.
    """

    def __init__(
        self,
        cache_ttl_seconds: Optional[int] = None,
        max_workers: int = 5,
    ):
        self.cache_ttl = cache_ttl_seconds or getattr(settings, "THREAT_INTEL_CACHE_TTL", 3600)
        self.max_workers = max_workers
        self._providers: Dict[str, ThreatIntelProvider] = {}
        self._memory_cache: Dict[str, Tuple[float, List[Dict[str, Any]]]] = {}
        self._cache_lock = threading.Lock()

        # Register default providers
        self.register_provider(GoogleSafeBrowsingProvider())
        self.register_provider(URLhausProvider())
        self.register_provider(PhishTankProvider())
        self.register_provider(OpenPhishProvider())
        self.register_provider(VirusTotalProvider())

    def register_provider(self, provider: ThreatIntelProvider) -> None:
        """Registers a threat intelligence provider adapter."""
        self._providers[provider.name] = provider

    def get_provider(self, name: str) -> Optional[ThreatIntelProvider]:
        """Retrieves a registered provider by name."""
        return self._providers.get(name)

    def list_providers(self) -> List[str]:
        """Lists names of all registered providers."""
        return list(self._providers.keys())

    # -----------------------------------------------------------------------
    # DUAL-TIER CACHE (Redis + In-Memory Fallback)
    # -----------------------------------------------------------------------

    def _make_cache_key(self, url: str) -> str:
        clean_url = url.strip().lower()
        return f"threat_intel:v2:{hashlib.sha256(clean_url.encode()).hexdigest()}"

    def _get_cache(self, key: str) -> Optional[List[Dict[str, Any]]]:
        # 1. Try Redis first
        try:
            import redis
            r = redis.from_url(settings.REDIS_URL, socket_connect_timeout=0.3, socket_timeout=0.3)
            raw = r.get(key)
            if raw:
                data = json.loads(raw.decode("utf-8") if isinstance(raw, bytes) else raw)
                if isinstance(data, list):
                    return data
        except Exception:
            pass

        # 2. In-memory TTL fallback
        with self._cache_lock:
            if key in self._memory_cache:
                expires_at, payload = self._memory_cache[key]
                if time.time() < expires_at:
                    return payload
                else:
                    del self._memory_cache[key]
        return None

    def _set_cache(self, key: str, payload: List[Dict[str, Any]], ttl: Optional[int] = None) -> None:
        expiry = ttl or self.cache_ttl
        # 1. Store in Redis
        try:
            import redis
            r = redis.from_url(settings.REDIS_URL, socket_connect_timeout=0.3, socket_timeout=0.3)
            r.set(key, json.dumps(payload), ex=expiry)
        except Exception:
            pass

        # 2. Store in memory fallback
        with self._cache_lock:
            self._memory_cache[key] = (time.time() + expiry, payload)

    def clear_cache(self) -> None:
        """Clears in-memory cache entries."""
        with self._cache_lock:
            self._memory_cache.clear()

    # -----------------------------------------------------------------------
    # CONCURRENT MULTI-PROVIDER EXECUTION
    # -----------------------------------------------------------------------

    def query_all(
        self,
        url: str,
        resolve_network: bool = True,
        use_cache: bool = True,
        providers_subset: Optional[List[str]] = None,
    ) -> List[NormalizedThreatResult]:
        """
        Queries all configured threat intelligence providers concurrently.
        Guarantees bounded completion time and fault isolation.
        """
        clean_url = url.strip()
        cache_key = self._make_cache_key(clean_url)

        # 1. Check cache
        if use_cache:
            cached_data = self._get_cache(cache_key)
            if cached_data:
                return [NormalizedThreatResult(**item) for item in cached_data]

        # 2. Select active providers
        enabled_names = providers_subset or getattr(settings, "ENABLED_THREAT_INTEL_PROVIDERS", list(self._providers.keys()))
        active_providers = [p for name, p in self._providers.items() if name in enabled_names]

        # 3. Passive / offline fallback mode
        if not resolve_network:
            results = [
                NormalizedThreatResult(
                    source=p.name,
                    match_found=False,
                    threat_type="CLEAN",
                    confidence=0.90,
                    details={"status": "offline_mode"},
                    status="ok",
                )
                for p in active_providers
            ]
            return results

        # 4. Concurrent execution pool
        results_by_name: Dict[str, NormalizedThreatResult] = {}
        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(active_providers) or 1)) as executor:
            future_to_provider = {
                executor.submit(p.query, clean_url): p
                for p in active_providers
            }

            timeout_limit = getattr(settings, "THREAT_INTEL_REQUEST_TIMEOUT", 3.5) + 1.5

            for future in as_completed(future_to_provider, timeout=timeout_limit):
                provider = future_to_provider[future]
                try:
                    res = future.result()
                    results_by_name[provider.name] = res
                except Exception as exc:
                    logger.error(f"Uncaught exception querying provider {provider.name}: {exc}")
                    results_by_name[provider.name] = NormalizedThreatResult(
                        source=provider.name,
                        match_found=False,
                        threat_type="ERROR",
                        confidence=0.0,
                        details={"status": "error", "error": str(exc)},
                        status="error",
                    )

        # Ensure all active providers are represented even if worker timed out
        final_results: List[NormalizedThreatResult] = []
        for p in active_providers:
            if p.name in results_by_name:
                final_results.append(results_by_name[p.name])
            else:
                final_results.append(
                    NormalizedThreatResult(
                        source=p.name,
                        match_found=False,
                        threat_type="TIMEOUT",
                        confidence=0.0,
                        details={"status": "timeout", "error": "pool_timeout_exceeded"},
                        status="timeout",
                    )
                )

        # 5. Populate cache
        if use_cache and final_results:
            self._set_cache(cache_key, [r.to_dict() for r in final_results])

        return final_results

    # -----------------------------------------------------------------------
    # HEALTH & TELEMETRY
    # -----------------------------------------------------------------------

    def get_provider_health(self) -> Dict[str, Dict[str, Any]]:
        """
        Returns runtime health and circuit breaker metrics across all providers.
        """
        health_report = {}
        for name, provider in self._providers.items():
            h = provider.health.to_dict()
            h["circuit"] = provider.circuit_breaker.get_status()
            h["configured"] = provider.is_configured()
            health_report[name] = h
        return health_report

    def reset_all_circuits(self) -> None:
        """Resets all provider circuit breakers to CLOSED."""
        for provider in self._providers.values():
            provider.circuit_breaker.reset()


GLOBAL_THREAT_INTEL_MANAGER = ThreatIntelManager()


def get_threat_intel_manager() -> ThreatIntelManager:
    """Returns singleton ThreatIntelManager instance."""
    return GLOBAL_THREAT_INTEL_MANAGER

