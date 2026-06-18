"""investigation_quality — event enrichment, blocklist, container CVEs, criticality

Revision ID: h8i9j0k1l2m3
Revises: g7h8i9j0k1l2
Create Date: 2026-06-18 23:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "h8i9j0k1l2m3"
down_revision: Union[str, None] = "g7h8i9j0k1l2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("events", sa.Column("wazuh_rule_description", sa.Text(), nullable=True))
    op.add_column("events", sa.Column("geo_country", sa.String(length=2), nullable=True))
    op.add_column("events", sa.Column("geo_city", sa.String(length=128), nullable=True))

    op.add_column("decisions", sa.Column("event_id", postgresql.UUID(as_uuid=True), nullable=True))
    op.create_foreign_key(
        "fk_decisions_event_id",
        "decisions",
        "events",
        ["event_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index("ix_decisions_event_id", "decisions", ["event_id"])

    op.add_column(
        "hosts",
        sa.Column("criticality", sa.String(length=10), nullable=False, server_default="medium"),
    )

    op.create_table(
        "blocklist",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("ip", postgresql.INET(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("investigation_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("added_by", sa.String(length=64), nullable=True),
        sa.Column("added_at", sa.DateTime(), nullable=False),
        sa.Column("executed", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("executed_at", sa.DateTime(), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["investigation_id"], ["investigations.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("ip", name="uq_blocklist_ip"),
    )
    op.create_index("ix_blocklist_executed", "blocklist", ["executed"])

    op.create_table(
        "container_cve_findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("agent_id", sa.String(length=16), nullable=False),
        sa.Column("image_ref", sa.Text(), nullable=False),
        sa.Column("cve_id", sa.String(length=64), nullable=True),
        sa.Column("package_name", sa.Text(), nullable=True),
        sa.Column("installed_version", sa.Text(), nullable=True),
        sa.Column("fixed_version", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(length=16), nullable=True),
        sa.Column("cvss", sa.Float(), nullable=True),
        sa.Column("scanned_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_container_cve_agent_id", "container_cve_findings", ["agent_id"])
    op.create_index("ix_container_cve_image_ref", "container_cve_findings", ["image_ref"])

    op.create_table(
        "watched_events",
        sa.Column("event_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("watched_at", sa.DateTime(), nullable=False),
        sa.Column("investigation_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.PrimaryKeyConstraint("event_id"),
    )


def downgrade() -> None:
    op.drop_table("watched_events")
    op.drop_index("ix_container_cve_image_ref", table_name="container_cve_findings")
    op.drop_index("ix_container_cve_agent_id", table_name="container_cve_findings")
    op.drop_table("container_cve_findings")
    op.drop_index("ix_blocklist_executed", table_name="blocklist")
    op.drop_table("blocklist")
    op.drop_column("hosts", "criticality")
    op.drop_index("ix_decisions_event_id", table_name="decisions")
    op.drop_constraint("fk_decisions_event_id", "decisions", type_="foreignkey")
    op.drop_column("decisions", "event_id")
    op.drop_column("events", "geo_city")
    op.drop_column("events", "geo_country")
    op.drop_column("events", "wazuh_rule_description")
