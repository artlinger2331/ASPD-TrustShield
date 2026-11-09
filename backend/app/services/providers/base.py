"""
Base Provider Contract & Reliability Framework for TrustShield Threat Intelligence.

Includes:
- Thread-safe CircuitBreaker with CLOSED, OPEN, HALF_OPEN state machine.
- ProviderHealth tracking runtime query counters, error rates, and circuit status.
- NormalizedThreatResult standardizing multi-vendor threat match structures.
- ThreatIntelProvider abstract base class with exponential backoff, jitter, timeouts,
  and graceful fault isolation.
"""

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import logging
import random
import threading
import time
from typing import Any, Dict, List, Optional, Tuple, Union

import httpx

from app.schemas.threat_intel import ThreatIntelMatch

logger = logging.getLogger(__name__)


class CircuitState(str, Enum):
    CLOSED = "CLOSED"        # Normal operation: requests pass through
    OPEN = "OPEN"            # Tripped: requests fail fast without network calls
    HALF_OPEN = "HALF_OPEN"  # Testing: limited probe requests permitted


class CircuitBreaker:
    """
    Thread-safe circuit breaker protecting against repeated failures from upstream APIs.
    """

    def __init__(
        self,
        failure_threshold: int = 3,
        cooldown_seconds: float = 60.0,
        half_open_max_trials: int = 1,
    ):
        self.failure_threshold = failure_threshold
        self.cooldown_seconds = cooldown_seconds
        self.half_open_max_trials = half_open_max_trials

        self._state = CircuitState.CLOSED
        self._consecutive_failures = 0
        self._opened_at: Optional[float] = None
        self._trial_count = 0
        self._lock = threading.Lock()

    @property
    def state(self) -> CircuitState:
        with self._lock:
            if self._state == CircuitState.OPEN:
                if self._opened_at and (time.time() - self._opened_at >= self.cooldown_seconds):
                    self._state = CircuitState.HALF_OPEN
                    self._trial_count = 0
            return self._state

    def can_execute(self) -> bool:
        """
        Determines whether a network request should be attempted.
        """
        with self._lock:
            now = time.time()
            if self._state == CircuitState.OPEN:
                if self._opened_at and (now - self._opened_at >= self.cooldown_seconds):
                    self._state = CircuitState.HALF_OPEN
                    self._trial_count = 1
                    return True
                return False
            elif self._state == CircuitState.HALF_OPEN:
                if self._trial_count < self.half_open_max_trials:
                    self._trial_count += 1
                    return True
                return False
            return True

    def record_success(self) -> None:
        """
        Records a successful request, resetting failures and restoring CLOSED state.
        """
        with self._lock:
            self._consecutive_failures = 0
            self._opened_at = None
            self._trial_count = 0
            self._state = CircuitState.CLOSED

    def record_failure(self, error: str = "") -> None:
        """
        Records an execution failure, incrementing failures and tripping to OPEN if threshold reached.
        """
        with self._lock:
            self._consecutive_failures += 1
            if self._state == CircuitState.HALF_OPEN or self._consecutive_failures >= self.failure_threshold:
                self._state = CircuitState.OPEN
                self._opened_at = time.time()
                self._trial_count = 0
                logger.warning(
                    f"Circuit breaker tripped to OPEN after {self._consecutive_failures} failures. "
                    f"Cooldown: {self.cooldown_seconds}s. Reason: {error}"
                )

    def reset(self) -> None:
        """
        Manually resets the circuit breaker to CLOSED.
        """
        with self._lock:
            self._state = CircuitState.CLOSED
            self._consecutive_failures = 0
            self._opened_at = None
            self._trial_count = 0

    def get_status(self) -> Dict[str, Any]:
        """
        Returns circuit breaker telemetry for health monitoring.
        """
        st = self.state
        remaining_cooldown = 0.0
        if st == CircuitState.OPEN and self._opened_at:
            remaining_cooldown = max(0.0, self.cooldown_seconds - (time.time() - self._opened_at))

        return {
            "state": st.value,
            "consecutive_failures": self._consecutive_failures,
            "cooldown_remaining_seconds": round(remaining_cooldown, 1),
        }


@dataclass
class ProviderHealth:
    """
    Runtime health metrics and operational status for an intelligence provider.
    """
    name: str
    status: str = "healthy"  # "healthy", "degraded", "failing", "disabled", "cooldown"
    total_requests: int = 0
    success_count: int = 0
    failure_count: int = 0
    consecutive_failures: int = 0
    last_error: Optional[str] = None
    last_success_at: Optional[str] = None
    last_failure_at: Optional[str] = None
    avg_latency_ms: float = 0.0
    _total_latency_ms: float = 0.0

    def record_success(self, latency_ms: float) -> None:
        self.total_requests += 1
        self.success_count += 1
        self.consecutive_failures = 0
        self._total_latency_ms += latency_ms
        self.avg_latency_ms = round(self._total_latency_ms / max(1, self.success_count), 1)
        self.last_success_at = datetime.now(timezone.utc).isoformat()
        self.status = "healthy"

    def record_failure(self, error: str, is_circuit_open: bool = False) -> None:
        self.total_requests += 1
        self.failure_count += 1
        self.consecutive_failures += 1
        self.last_error = error
        self.last_failure_at = datetime.now(timezone.utc).isoformat()
        if is_circuit_open:
            self.status = "cooldown"
        elif self.consecutive_failures >= 3:
            self.status = "failing"
        else:
            self.status = "degraded"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "total_requests": self.total_requests,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "consecutive_failures": self.consecutive_failures,
            "last_error": self.last_error,
            "last_success_at": self.last_success_at,
            "last_failure_at": self.last_failure_at,
            "avg_latency_ms": self.avg_latency_ms,
        }


@dataclass
class NormalizedThreatResult:
    """
    Standardized result contract across all threat intelligence providers.
    """
    source: str
    match_found: bool  # True if confirmed malicious / phishing / malware
    threat_type: Optional[str] = "CLEAN"  # "MALWARE", "PHISHING", "SOCIAL_ENGINEERING", "CLEAN", "SKIPPED", "ERROR"
    confidence: float = 0.0  # 0.0 to 1.0
    details: Dict[str, Any] = field(default_factory=dict)
    raw_response: Optional[Dict[str, Any]] = None
    status: str = "ok"  # "ok", "skipped", "timeout", "circuit_open", "error"
    execution_time_ms: float = 0.0
    queried_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_threat_intel_match(self) -> ThreatIntelMatch:
        """
        Converts to the existing ThreatIntelMatch Pydantic schema for seamless
        compatibility with the Scan Orchestrator and Report APIs.
        """
        match_type = self.threat_type if self.match_found else ("CLEAN" if self.status == "ok" else self.status.upper())
        return ThreatIntelMatch(
            source=self.source,
            match_type=match_type,
            confidence=round(self.confidence, 2),
            is_malicious=self.match_found,
            details=self.details or {},
            raw_response=self.raw_response or {},
        )


class ThreatIntelProvider(ABC):
    """
    Abstract Base Class for all pluggable threat intelligence adapters.
    Provides automated circuit breaking, exponential backoff with jitter,
    and resilience against network degradation.
    """

    def __init__(
        self,
        name: str,
        timeout: float = 3.5,
        max_retries: int = 2,
        backoff_factor: float = 0.5,
        failure_threshold: int = 3,
        cooldown_seconds: float = 60.0,
    ):
        self.name = name
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.circuit_breaker = CircuitBreaker(
            failure_threshold=failure_threshold,
            cooldown_seconds=cooldown_seconds,
        )
        self.health = ProviderHealth(name=name)

    @abstractmethod
    def is_configured(self) -> bool:
        """
        Returns True if the provider has all necessary API keys and credentials.
        """
        pass

    @abstractmethod
    def _execute_query(self, url: str, client: httpx.Client) -> NormalizedThreatResult:
        """
        Provider-specific HTTP query logic. Must be overridden by subclasses.
        """
        pass

    def query(self, url: str) -> NormalizedThreatResult:
        """
        Executes query against provider with circuit breaker, timeout, retry with backoff,
        and graceful fallback. Never raises unhandled exceptions.
        """
        start_time = time.time()
        queried_at = datetime.now(timezone.utc).isoformat()

        # 1. Configuration check
        if not self.is_configured():
            self.health.status = "disabled"
            return NormalizedThreatResult(
                source=self.name,
                match_found=False,
                threat_type="SKIPPED",
                confidence=0.0,
                details={"status": "api_key_not_configured"},
                status="skipped",
                execution_time_ms=0.0,
                queried_at=queried_at,
            )

        # 2. Circuit breaker check
        if not self.circuit_breaker.can_execute():
            cb_status = self.circuit_breaker.get_status()
            self.health.record_failure(
                error=f"Circuit open (cooldown remaining: {cb_status['cooldown_remaining_seconds']}s)",
                is_circuit_open=True,
            )
            return NormalizedThreatResult(
                source=self.name,
                match_found=False,
                threat_type="SKIPPED",
                confidence=0.0,
                details={
                    "status": "circuit_open",
                    "cooldown_remaining_seconds": cb_status["cooldown_remaining_seconds"],
                },
                status="circuit_open",
                execution_time_ms=round((time.time() - start_time) * 1000.0, 2),
                queried_at=queried_at,
            )

        # 3. Execution with exponential backoff retry loop
        last_exception: Optional[Exception] = None
        for attempt in range(self.max_retries + 1):
            try:
                with httpx.Client(timeout=self.timeout) as client:
                    result = self._execute_query(url=url, client=client)
                    latency_ms = round((time.time() - start_time) * 1000.0, 2)
                    result.execution_time_ms = latency_ms
                    result.queried_at = queried_at

                    self.circuit_breaker.record_success()
                    self.health.record_success(latency_ms)
                    return result

            except httpx.HTTPStatusError as http_err:
                last_exception = http_err
                status_code = http_err.response.status_code
                # Never retry client authentication or validation errors (401, 403, 404, 422)
                if 400 <= status_code < 500 and status_code not in (408, 429):
                    logger.warning(f"Provider {self.name} client error HTTP {status_code}; not retrying.")
                    break

                if attempt < self.max_retries:
                    sleep_time = self.backoff_factor * (2 ** attempt) + random.uniform(0.05, 0.2)
                    time.sleep(sleep_time)

            except (httpx.TimeoutException, httpx.RequestError) as req_err:
                last_exception = req_err
                if attempt < self.max_retries:
                    sleep_time = self.backoff_factor * (2 ** attempt) + random.uniform(0.05, 0.2)
                    time.sleep(sleep_time)

            except Exception as exc:
                last_exception = exc
                logger.error(f"Unexpected error in provider {self.name}: {exc}", exc_info=True)
                break

        # 4. Graceful degradation on failure (Scan must never crash)
        latency_ms = round((time.time() - start_time) * 1000.0, 2)
        err_msg = str(last_exception) if last_exception else "unknown_error"
        is_timeout = isinstance(last_exception, httpx.TimeoutException)

        self.circuit_breaker.record_failure(err_msg)
        self.health.record_failure(err_msg, is_circuit_open=(self.circuit_breaker.state == CircuitState.OPEN))

        status_tag = "timeout" if is_timeout else "error"
        return NormalizedThreatResult(
            source=self.name,
            match_found=False,
            threat_type="ERROR" if not is_timeout else "TIMEOUT",
            confidence=0.0,
            details={"status": status_tag, "error": err_msg},
            status=status_tag,
            execution_time_ms=latency_ms,
            queried_at=queried_at,
        )

