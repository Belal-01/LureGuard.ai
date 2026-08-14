"""investigation link on events + token/cost accounting on agent_actions

Register items SCH-1 and SCH-3.

SCH-1: events had no path to investigations, so agent verdict could not be
compared against Wazuh rule level — the one view a SIEM structurally cannot
produce, and the product's differentiator.

SCH-3: agent_actions recorded duration_ms but no tokens or cost, leaving
cost-per-triage with no data source.

Both columns are nullable: these tables have existing rows, and most events
never belong to an investigation.

Revision ID: m3n4o5p6q7r8
Revises: k1l2m3n4o5p6
Create Date: 2026-08-14 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "m3n4o5p6q7r8"
down_revision: Union[str, None] = "k1l2m3n4o5p6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # SCH-1 — join key for verdict-vs-Wazuh-level
    op.add_column(
        "events",
        sa.Column("investigation_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_foreign_key(
        "fk_events_investigation_id",
        "events",
        "investigations",
        ["investigation_id"],
        ["id"],
    )
    op.create_index("ix_events_investigation_id", "events", ["investigation_id"])

    # SCH-3 — cost per triage. Numeric, not Float: money is never binary float.
    op.add_column("agent_actions", sa.Column("input_tokens", sa.Integer(), nullable=True))
    op.add_column("agent_actions", sa.Column("output_tokens", sa.Integer(), nullable=True))
    op.add_column("agent_actions", sa.Column("cost_usd", sa.Numeric(12, 6), nullable=True))


def downgrade() -> None:
    op.drop_column("agent_actions", "cost_usd")
    op.drop_column("agent_actions", "output_tokens")
    op.drop_column("agent_actions", "input_tokens")

    op.drop_index("ix_events_investigation_id", table_name="events")
    op.drop_constraint("fk_events_investigation_id", "events", type_="foreignkey")
    op.drop_column("events", "investigation_id")
