"""
TrustShield ORM Models Package
Exports all domain entities for SQLAlchemy and Alembic schema management.
"""

from app.db.base import Base
from app.models.user import User
from app.models.scan import Scan
from app.models.scan_finding import ScanFinding
from app.models.certificate import Certificate
from app.models.threat_intel import ThreatIntelResult
from app.models.community_report import CommunityReport
from app.models.watchlist import WatchlistItem
from app.models.alert import Alert

__all__ = [
    "Base",
    "User",
    "Scan",
    "ScanFinding",
    "Certificate",
    "ThreatIntelResult",
    "CommunityReport",
    "WatchlistItem",
    "Alert",
]

