"""investigation_findings_timeline_iocs

Revision ID: f6a7b8c9d0e1
Revises: e5f6a7b8c9d0
Create Date: 2026-06-16 22:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "f6a7b8c9d0e1"
down_revision: Union[str, None] = "e5f6a7b8c9d0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("investigations", sa.Column("detection_source", sa.String(length=64), nullable=True))
    op.add_column("investigations", sa.Column("asset_criticality", sa.String(length=16), nullable=True))
    op.add_column("investigations", sa.Column("mttd_seconds", sa.Integer(), nullable=True))
    op.add_column("investigations", sa.Column("kill_chain_summary", sa.Text(), nullable=True))

    op.create_table(
        "findings",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("investigation_id", sa.UUID(), nullable=False),
        sa.Column("evidence_id", sa.String(length=16), nullable=False),
        sa.Column("finding", sa.Text(), nullable=False),
        sa.Column("citation", sa.Text(), nullable=False),
        sa.Column("mitre_technique", sa.String(length=32), nullable=True),
        sa.Column("mitre_tactic", sa.String(length=64), nullable=True),
        sa.Column("severity", sa.String(length=8), nullable=True),
        sa.Column("verdict", sa.String(length=32), nullable=True),
        sa.Column("confidence", sa.String(length=16), nullable=True),
        sa.Column("ioc_type", sa.String(length=32), nullable=True),
        sa.Column("ioc_value", sa.Text(), nullable=True),
        sa.Column("ts", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["investigation_id"], ["investigations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_findings_investigation_id", "findings", ["investigation_id"], unique=False)
    op.create_index("ix_findings_mitre_technique", "findings", ["mitre_technique"], unique=False)
    op.create_index("ix_findings_severity", "findings", ["severity"], unique=False)

    op.create_table(
        "timeline_events",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("investigation_id", sa.UUID(), nullable=False),
        sa.Column("ts_event", sa.DateTime(), nullable=False),
        sa.Column("phase", sa.String(length=32), nullable=True),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("source", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["investigation_id"], ["investigations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_timeline_events_investigation_id", "timeline_events", ["investigation_id"], unique=False)
    op.create_index("ix_timeline_events_ts_event", "timeline_events", ["ts_event"], unique=False)

    op.create_table(
        "iocs",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("investigation_id", sa.UUID(), nullable=False),
        sa.Column("type", sa.String(length=32), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("defanged", sa.Text(), nullable=True),
        sa.Column("reputation", sa.String(length=32), nullable=True),
        sa.Column("source", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["investigation_id"], ["investigations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_iocs_investigation_id", "iocs", ["investigation_id"], unique=False)
    op.create_index("ix_iocs_type", "iocs", ["type"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_iocs_type", table_name="iocs")
    op.drop_index("ix_iocs_investigation_id", table_name="iocs")
    op.drop_table("iocs")
    op.drop_index("ix_timeline_events_ts_event", table_name="timeline_events")
    op.drop_index("ix_timeline_events_investigation_id", table_name="timeline_events")
    op.drop_table("timeline_events")
    op.drop_index("ix_findings_severity", table_name="findings")
    op.drop_index("ix_findings_mitre_technique", table_name="findings")
    op.drop_index("ix_findings_investigation_id", table_name="findings")
    op.drop_table("findings")
    op.drop_column("investigations", "kill_chain_summary")
    op.drop_column("investigations", "mttd_seconds")
    op.drop_column("investigations", "asset_criticality")
    op.drop_column("investigations", "detection_source")
