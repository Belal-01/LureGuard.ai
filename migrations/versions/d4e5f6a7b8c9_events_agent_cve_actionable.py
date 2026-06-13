"""events_agent_cve_actionable

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-06-13 14:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "d4e5f6a7b8c9"
down_revision: Union[str, None] = "c3d4e5f6a7b8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("events", sa.Column("agent_id", sa.String(length=16), nullable=True))
    op.add_column("events", sa.Column("agent_name", sa.String(length=128), nullable=True))
    op.add_column("events", sa.Column("agent_ip", postgresql.INET(), nullable=True))
    op.create_index("ix_events_agent_id_ts", "events", ["agent_id", "ts"], unique=False)

    op.add_column(
        "cve_findings",
        sa.Column("actionable", sa.Boolean(), nullable=False, server_default="true"),
    )
    op.add_column(
        "cve_findings",
        sa.Column("service_running", sa.Boolean(), nullable=False, server_default="false"),
    )
    op.add_column("cve_findings", sa.Column("priority_score", sa.Integer(), nullable=True))
    op.add_column("cve_findings", sa.Column("on_kev", sa.Boolean(), nullable=False, server_default="false"))
    op.create_index("ix_cve_findings_actionable", "cve_findings", ["actionable"], unique=False)
    op.create_index("ix_cve_findings_priority_score", "cve_findings", ["priority_score"], unique=False)

    op.add_column("exposure_findings", sa.Column("bind_scope", sa.String(length=32), nullable=True))
    op.add_column(
        "detection_coverage",
        sa.Column("events_last_at", sa.DateTime(), nullable=True),
    )
    op.add_column(
        "detection_coverage",
        sa.Column("rules_firing_count", sa.Integer(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_column("detection_coverage", "rules_firing_count")
    op.drop_column("detection_coverage", "events_last_at")
    op.drop_column("exposure_findings", "bind_scope")
    op.drop_index("ix_cve_findings_priority_score", table_name="cve_findings")
    op.drop_index("ix_cve_findings_actionable", table_name="cve_findings")
    op.drop_column("cve_findings", "on_kev")
    op.drop_column("cve_findings", "priority_score")
    op.drop_column("cve_findings", "service_running")
    op.drop_column("cve_findings", "actionable")
    op.drop_index("ix_events_agent_id_ts", table_name="events")
    op.drop_column("events", "agent_ip")
    op.drop_column("events", "agent_name")
    op.drop_column("events", "agent_id")
