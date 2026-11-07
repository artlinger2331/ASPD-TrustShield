"""Initial TrustShield Schema

Revision ID: 0001_initial_schema
Revises: 
Create Date: 2026-11-07 05:15:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0001_initial_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Compatible JSONB / JSON type for multi-engine support
JSON_TYPE = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
UUID_TYPE = postgresql.UUID(as_uuid=True)


def upgrade() -> None:
    # 1. users
    op.create_table(
        "users",
        sa.Column("id", UUID_TYPE, primary_key=True, nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("hashed_password", sa.String(length=255), nullable=False),
        sa.Column("full_name", sa.String(length=255), nullable=True),
        sa.Column("role", sa.String(length=32), nullable=False, server_default="user"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)
    op.create_index("ix_users_role", "users", ["role"])

    # 2. scans
    op.create_table(
        "scans",
        sa.Column("id", UUID_TYPE, primary_key=True, nullable=False),
        sa.Column("user_id", UUID_TYPE, sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("input_url", sa.Text(), nullable=False),
        sa.Column("normalized_url", sa.Text(), nullable=False),
        sa.Column("final_url", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="queued"),
        sa.Column("verdict", sa.String(length=32), nullable=True),
        sa.Column("risk_score", sa.Integer(), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("recommendation", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_scans_user_id", "scans", ["user_id"])
    op.create_index("ix_scans_normalized_url", "scans", ["normalized_url"])
    op.create_index("ix_scans_status", "scans", ["status"])
    op.create_index("ix_scans_verdict", "scans", ["verdict"])
    op.create_index("ix_scans_user_created", "scans", ["user_id", "created_at"])
    op.create_index("ix_scans_status_created", "scans", ["status", "created_at"])

    # 3. scan_findings
    op.create_table(
        "scan_findings",
        sa.Column("id", UUID_TYPE, primary_key=True, nullable=False),
        sa.Column("scan_id", UUID_TYPE, sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("category", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("evidence", JSON_TYPE, nullable=True),
        sa.Column("recommendation", sa.Text(), nullable=True),
        sa.Column("risk_points", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("raw_data", JSON_TYPE, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_scan_findings_scan_id", "scan_findings", ["scan_id"])
    op.create_index("ix_scan_findings_category", "scan_findings", ["category"])
    op.create_index("ix_scan_findings_severity", "scan_findings", ["severity"])
    op.create_index("ix_findings_scan_severity", "scan_findings", ["scan_id", "severity"])
    op.create_index("ix_findings_scan_category", "scan_findings", ["scan_id", "category"])

    # 4. certificates
    op.create_table(
        "certificates",
        sa.Column("id", UUID_TYPE, primary_key=True, nullable=False),
        sa.Column("scan_id", UUID_TYPE, sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, unique=True),
        sa.Column("subject", sa.String(length=512), nullable=True),
        sa.Column("issuer", sa.String(length=512), nullable=True),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=True),
        sa.Column("valid_to", sa.DateTime(timezone=True), nullable=True),
        sa.Column("days_until_expiry", sa.Integer(), nullable=True),
        sa.Column("is_valid", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("is_revoked", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("chain_valid", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("ct_log_present", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("ca_trust_status", sa.String(length=64), nullable=True),
        sa.Column("raw_certificate", JSON_TYPE, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_certificates_scan_id", "certificates", ["scan_id"], unique=True)
    op.create_index("ix_certificates_valid_to", "certificates", ["valid_to"])

    # 5. threat_intel_results
    op.create_table(
        "threat_intel_results",
        sa.Column("id", UUID_TYPE, primary_key=True, nullable=False),
        sa.Column("scan_id", UUID_TYPE, sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("match_type", sa.String(length=64), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("details", JSON_TYPE, nullable=True),
        sa.Column("raw_response", JSON_TYPE, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_threat_intel_results_scan_id", "threat_intel_results", ["scan_id"])
    op.create_index("ix_threat_intel_results_source", "threat_intel_results", ["source"])
    op.create_index("ix_threat_intel_scan_source", "threat_intel_results", ["scan_id", "source"])

    # 6. community_reports
    op.create_table(
        "community_reports",
        sa.Column("id", UUID_TYPE, primary_key=True, nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("domain", sa.String(length=255), nullable=False),
        sa.Column("reporter_id", UUID_TYPE, sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("threat_type", sa.String(length=64), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("screenshot_url", sa.Text(), nullable=True),
        sa.Column("source", sa.String(length=32), nullable=False, server_default="community"),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="pending"),
        sa.Column("confirmations", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("false_positive_votes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_community_reports_domain", "community_reports", ["domain"])
    op.create_index("ix_community_reports_reporter_id", "community_reports", ["reporter_id"])
    op.create_index("ix_community_reports_threat_type", "community_reports", ["threat_type"])
    op.create_index("ix_community_reports_source", "community_reports", ["source"])
    op.create_index("ix_community_reports_status", "community_reports", ["status"])
    op.create_index("ix_reports_domain_status", "community_reports", ["domain", "status"])
    op.create_index("ix_reports_threat_status", "community_reports", ["threat_type", "status"])

    # 7. watchlist_items
    op.create_table(
        "watchlist_items",
        sa.Column("id", UUID_TYPE, primary_key=True, nullable=False),
        sa.Column("user_id", UUID_TYPE, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("domain", sa.String(length=255), nullable=False),
        sa.Column("alert_types", JSON_TYPE, nullable=True),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("user_id", "domain", name="uq_user_watchlist_domain"),
    )
    op.create_index("ix_watchlist_items_user_id", "watchlist_items", ["user_id"])
    op.create_index("ix_watchlist_items_domain", "watchlist_items", ["domain"])
    op.create_index("ix_watchlist_items_is_active", "watchlist_items", ["is_active"])
    op.create_index("ix_watchlist_user_active", "watchlist_items", ["user_id", "is_active"])

    # 8. alerts
    op.create_table(
        "alerts",
        sa.Column("id", UUID_TYPE, primary_key=True, nullable=False),
        sa.Column("user_id", UUID_TYPE, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("watchlist_item_id", UUID_TYPE, sa.ForeignKey("watchlist_items.id", ondelete="CASCADE"), nullable=True),
        sa.Column("alert_type", sa.String(length=64), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("is_read", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_alerts_user_id", "alerts", ["user_id"])
    op.create_index("ix_alerts_watchlist_item_id", "alerts", ["watchlist_item_id"])
    op.create_index("ix_alerts_alert_type", "alerts", ["alert_type"])
    op.create_index("ix_alerts_is_read", "alerts", ["is_read"])
    op.create_index("ix_alerts_created_at", "alerts", ["created_at"])
    op.create_index("ix_alerts_user_read_created", "alerts", ["user_id", "is_read", "created_at"])


def downgrade() -> None:
    op.drop_table("alerts")
    op.drop_table("watchlist_items")
    op.drop_table("community_reports")
    op.drop_table("threat_intel_results")
    op.drop_table("certificates")
    op.drop_table("scan_findings")
    op.drop_table("scans")
    op.drop_table("users")
