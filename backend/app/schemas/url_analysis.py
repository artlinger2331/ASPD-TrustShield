"""
Pydantic Schemas for URL Validation, Normalization, and Heuristic Forensics.
"""

from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class URLParts(BaseModel):
    """Segmented architectural parts of a canonicalized URL."""
    scheme: str = Field(..., description="Normalized scheme: http or https")
    host: str = Field(..., description="Normalized hostname or IP")
    port: Optional[int] = Field(None, description="Explicit port number if non-default")
    registered_domain: str = Field(..., description="Registered base domain (e.g. google.com, bbc.co.uk)")
    subdomain: Optional[str] = Field(None, description="Subdomain prefix (e.g. secure.login)")
    tld: str = Field(..., description="Top Level Domain suffix (e.g. com, co.uk)")
    path: str = Field("/", description="Normalized URL path")
    query: Optional[str] = Field(None, description="Raw query string")
    query_params: Dict[str, Any] = Field(default_factory=dict, description="Parsed query parameter dictionary")
    fragment: Optional[str] = Field(None, description="URL fragment anchor")
    unicode_host: str = Field(..., description="Host decoded from Punycode into Unicode characters")


class URLHeuristics(BaseModel):
    """Security threat flags and heuristic indicators discovered in URL structure."""
    is_ip: bool = Field(False, description="Whether the host is a raw IPv4 or IPv6 address")
    is_shortener: bool = Field(False, description="Whether domain matches known URL shorteners")
    is_punycode: bool = Field(False, description="Whether domain contains xn-- Punycode label")
    has_homoglyphs: bool = Field(False, description="Whether Unicode host uses lookalike/Cyrillic homoglyphs")
    has_excessive_subdomains: bool = Field(False, description="Whether URL contains 3 or more subdomain labels")
    subdomain_count: int = Field(0, description="Total number of subdomain labels")
    has_suspicious_tld: bool = Field(False, description="Whether TLD matches high-abuse/suspicious lists")
    has_embedded_credentials: bool = Field(False, description="Whether URL contained userinfo@ credentials")
    is_overly_long: bool = Field(False, description="Whether URL length exceeds 255 characters")
    url_length: int = Field(..., description="Total character count of the URL")
    suspicious_keywords_found: List[str] = Field(default_factory=list, description="Phishing keywords detected in URL")
    heuristic_risk_score: int = Field(0, description="Synthesized heuristic risk contribution (0-100)")


class RedirectHop(BaseModel):
    """Detailed telemetry for a single verified HTTP redirect hop."""
    hop_number: int
    from_url: str
    to_url: str
    status_code: int
    latency_ms: Optional[float] = None


class URLValidationRequest(BaseModel):
    """Payload to validate and inspect a target URL."""
    url: str = Field(
        ...,
        min_length=1,
        max_length=2048,
        description="Target URL to inspect",
        examples=["https://paypa1-security.com/login?verify=account"],
    )
    resolve_dns: bool = Field(
        True,
        description="Whether to perform DNS resolution and verify resolved IP against SSRF blocklist",
    )
    trace_redirects: bool = Field(
        False,
        description="Whether to safely follow and trace redirects up to 5 hops with per-hop SSRF validation",
    )


class URLValidationResponse(BaseModel):
    """Complete structured outcome of URL validation and forensic normalization."""
    is_valid: bool = Field(..., description="Whether URL passed syntax and SSRF security requirements")
    input_url: str = Field(..., description="Original raw user input")
    normalized_url: Optional[str] = Field(None, description="SSRF-safe canonicalized URL for scanning")
    error_message: Optional[str] = Field(None, description="Explanation if URL was rejected or failed SSRF check")
    parts: Optional[URLParts] = None
    heuristics: Optional[URLHeuristics] = None
    redirect_chain: List[RedirectHop] = Field(default_factory=list, description="Step-by-step redirect chain")
    findings: List[Dict[str, Any]] = Field(default_factory=list, description="Structured security findings ready for database persistence")

