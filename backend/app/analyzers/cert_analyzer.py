"""
TrustShield SSL/TLS Certificate & CA Trust Analyzer (Adapter)
Delegates to core services: certificate_analyzer and ca_trust_monitor,
providing full backwards compatibility for all existing imports.
"""

from app.services.ca_trust_monitor import (
    DISTRUSTED_CAS,
    KNOWN_CA_INCIDENTS,
    FREE_AUTOMATED_CAS,
    check_ca_trust,
    check_weak_key_generation,
    is_roca_vulnerable,
)

from app.services.certificate_analyzer import (
    PRECERT_SCT_OID,
    EV_POLICY_OIDS,
    fetch_server_certificate,
    matches_san,
    parse_x509_certificate,
    analyze_certificate,
    save_certificate_to_db_sync,
    save_certificate_to_db,
)

__all__ = [
    "DISTRUSTED_CAS",
    "KNOWN_CA_INCIDENTS",
    "FREE_AUTOMATED_CAS",
    "PRECERT_SCT_OID",
    "EV_POLICY_OIDS",
    "fetch_server_certificate",
    "matches_san",
    "parse_x509_certificate",
    "analyze_certificate",
    "save_certificate_to_db_sync",
    "save_certificate_to_db",
    "check_ca_trust",
    "check_weak_key_generation",
    "is_roca_vulnerable",
]
