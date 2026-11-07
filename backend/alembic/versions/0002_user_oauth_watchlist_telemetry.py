"""User OAuth and Watchlist Telemetry Extensions

Revision ID: 0002_user_oauth_watchlist
Revises: 0001_initial_schema
Create Date: 2026-11-07 08:55:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0002_user_oauth_watchlist"
down_revision: Union[str, None] = "0001_initial_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Update users table with batch_alter_table for SQLite & Postgres compatibility
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("auth_provider", sa.String(length=32), nullable=False, server_default="local")
        )
        batch_op.add_column(
            sa.Column("oauth_id", sa.String(length=255), nullable=True)
        )
        batch_op.add_column(
            sa.Column("avatar_url", sa.String(length=1024), nullable=True)
        )
        batch_op.alter_column(
            "hashed_password",
            existing_type=sa.String(length=255),
            nullable=True,
        )
        batch_op.create_index("ix_users_oauth_id", ["oauth_id"], unique=False)

    # 2. Update watchlist_items table with cached risk & certificate telemetry
    with op.batch_alter_table("watchlist_items", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("last_risk_score", sa.Integer(), nullable=True)
        )
        batch_op.add_column(
            sa.Column("last_verdict", sa.String(length=32), nullable=True)
        )
        batch_op.add_column(
            sa.Column("cert_days_left", sa.Integer(), nullable=True)
        )


def downgrade() -> None:
    with op.batch_alter_table("watchlist_items", schema=None) as batch_op:
        batch_op.drop_column("cert_days_left")
        batch_op.drop_column("last_verdict")
        batch_op.drop_column("last_risk_score")

    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.drop_index("ix_users_oauth_id")
        batch_op.drop_column("avatar_url")
        batch_op.drop_column("oauth_id")
        batch_op.drop_column("auth_provider")
        batch_op.alter_column(
            "hashed_password",
            existing_type=sa.String(length=255),
            nullable=False,
        )
