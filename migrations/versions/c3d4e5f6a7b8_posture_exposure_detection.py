"""posture_exposure_detection

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-06-13 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "c3d4e5f6a7b8"
down_revision: Union[str, None] = "b2c3d4e5f6a7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "exposure_findings",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("agent_id", sa.String(length=16), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(length=16), nullable=False),
        sa.Column("process", sa.String(length=256), nullable=True),
        sa.Column("local_address", sa.String(length=64), nullable=True),
        sa.Column("state", sa.String(length=32), nullable=True),
        sa.Column("risk_level", sa.String(length=16), nullable=False),
        sa.Column("scanned_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["agent_id"], ["hosts.agent_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "agent_id",
            "port",
            "protocol",
            "local_address",
            name="uq_exposure_findings_agent_port",
        ),
    )
    op.create_index("ix_exposure_findings_agent_id", "exposure_findings", ["agent_id"])
    op.create_index("ix_exposure_findings_risk_level", "exposure_findings", ["risk_level"])

    op.create_table(
        "detection_coverage",
        sa.Column("agent_id", sa.String(length=16), nullable=False),
        sa.Column("fim_enabled", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("rootcheck_enabled", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("alerts_24h", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("rules_firing", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("silent_rules_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("channels_active", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("scanned_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["agent_id"], ["hosts.agent_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("agent_id"),
    )
    op.create_index("ix_detection_coverage_scanned_at", "detection_coverage", ["scanned_at"])


def downgrade() -> None:
    op.drop_index("ix_detection_coverage_scanned_at", table_name="detection_coverage")
    op.drop_table("detection_coverage")
    op.drop_index("ix_exposure_findings_risk_level", table_name="exposure_findings")
    op.drop_index("ix_exposure_findings_agent_id", table_name="exposure_findings")
    op.drop_table("exposure_findings")
