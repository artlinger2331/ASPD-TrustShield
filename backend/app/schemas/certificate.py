"""
Pydantic v2 schemas for SSL/TLS Certificate, Chain, and CA Trust analysis.
"""

from datetime import datetime
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, ConfigDict, Field, model_validator
from app.schemas.content_analysis import ContentFindingSchema


class CertificateChainNode(BaseModel):
    """
    Individual certificate node in the TLS trust path.
    Complies with required format: {"level": "...", "subject": "...", "issuer": "..."}
    and preserves backwards-compatibility fields ('name', 'type', 'status').
    """
    level: str = Field(..., description="root, intermediate, or leaf")
    subject: str = Field(..., description="Certificate Subject Distinguished Name or Common Name")
    issuer: str = Field(..., description="Certificate Issuer Distinguished Name or Common Name")
    name: Optional[str] = None
    type: Optional[str] = None
    status: str = Field(default="trusted", description="trusted, valid, untrusted, self_signed, or revoked")

    @model_validator(mode="before")
    @classmethod
    def populate_defaults_and_aliases(cls, data: Any) -> Any:
        if isinstance(data, dict):
            # If name is provided but subject is missing
            if "name" in data and "subject" not in data:
                data["subject"] = data["name"]
            # If type is provided but level is missing
            if "type" in data and "level" not in data:
                t = str(data["type"]).lower()
                if "root" in t:
                    data["level"] = "root"
                elif "intermediate" in t:
                    data["level"] = "intermediate"
                else:
                    data["level"] = "leaf"
            # If issuer is missing, default to subject for root, or unknown
            if "issuer" not in data:
                data["issuer"] = data.get("subject", "Unknown Issuer")
            # If level is provided, ensure name & type exist for legacy readers
            if "level" in data:
                lvl = data["level"].lower()
                if not data.get("type"):
                    data["type"] = "Root CA" if lvl == "root" else ("Intermediate CA" if lvl == "intermediate" else "Website Certificate")
                if not data.get("name"):
                    data["name"] = data.get("subject", "")
        return data


class CertificateChainPayload(BaseModel):
    """
    Structured certificate-chain visualization payload matching user specification:
    {
      "chain": [
        {"level": "root", "subject": "Root CA", "issuer": "Root CA"},
        {"level": "intermediate", "subject": "Intermediate CA", "issuer": "Root CA"},
        {"level": "leaf", "subject": "example.com", "issuer": "Intermediate CA"}
      ]
    }
    """
    chain: List[CertificateChainNode] = Field(default_factory=list)


class CertificateAnalysisResult(BaseModel):
    """
    Consolidated TLS certificate, validation, cryptographic audit,
    and CA trust telemetry.
    """
    https: bool = False
    subject: Optional[str] = None
    issuer: Optional[str] = None
    serial_number: Optional[str] = None
    signature_algorithm: Optional[str] = None
    public_key_type: Optional[str] = None
    public_key_bits: Optional[int] = None
    valid_from: Optional[datetime] = None
    valid_to: Optional[datetime] = None
    days_until_expiry: Optional[int] = None
    is_valid: bool = False
    is_revoked: bool = False
    revocation_status: str = "not_revoked"  # not_revoked, revoked, check_unavailable, no_ocsp_or_crl
    chain_valid: bool = False
    ct_log_present: bool = False
    ct_sct_count: int = 0
    ca_trust_status: str = "trusted"  # trusted, distrusted, incident_flagged, self_signed, unknown
    ca_incident: Optional[Dict[str, Any]] = None
    weak_algo: bool = False
    weak_key: bool = False
    san_matched: bool = False
    san_list: List[str] = Field(default_factory=list)
    chain: List[CertificateChainNode] = Field(default_factory=list)
    warning: Optional[str] = None
    raw_certificate: Dict[str, Any] = Field(default_factory=dict)
    findings: List[ContentFindingSchema] = Field(default_factory=list)
    total_risk_points: int = 0
    max_severity: str = "info"

    model_config = ConfigDict(from_attributes=True)

    def to_chain_payload(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Returns the structured visualization payload containing the 3-tier chain.
        """
        return {
            "chain": [
                {
                    "level": node.level,
                    "subject": node.subject,
                    "issuer": node.issuer,
                }
                for node in self.chain
            ]
        }
