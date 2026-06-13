"""agentic_analyst_tables

Revision ID: a1b2c3d4e5f6
Revises: 5e1281735254
Create Date: 2026-06-12 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "a1b2c3d4e5f6"
down_revision: Union[str, None] = "5e1281735254"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "investigations",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("trigger", sa.String(length=32), nullable=False),
        sa.Column("subject", sa.String(length=256), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("verdict", sa.String(length=32), nullable=True),
        sa.Column("confidence", sa.String(length=16), nullable=True),
        sa.Column("severity", sa.String(length=8), nullable=True),
        sa.Column("started_at", sa.DateTime(), nullable=False),
        sa.Column("closed_at", sa.DateTime(), nullable=True),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_investigations_started_at", "investigations", ["started_at"], unique=False)

    op.create_table(
        "agent_actions",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("investigation_id", sa.UUID(), nullable=True),
        sa.Column("tool_name", sa.String(length=128), nullable=False),
        sa.Column("args", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("result_summary", sa.Text(), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("ts", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["investigation_id"], ["investigations.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_agent_actions_ts", "agent_actions", ["ts"], unique=False)
    op.create_index(
        "ix_agent_actions_investigation_id", "agent_actions", ["investigation_id"], unique=False
    )

    op.create_table(
        "reports",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("investigation_id", sa.UUID(), nullable=True),
        sa.Column("title", sa.String(length=256), nullable=False),
        sa.Column("file_path", sa.Text(), nullable=False),
        sa.Column("format", sa.String(length=16), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["investigation_id"], ["investigations.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "hosts",
        sa.Column("agent_id", sa.String(length=16), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("ip", postgresql.INET(), nullable=True),
        sa.Column("os", sa.String(length=128), nullable=True),
        sa.Column("wazuh_status", sa.String(length=32), nullable=True),
        sa.Column("enrolled_by", sa.String(length=16), nullable=True),
        sa.Column("enrolled_at", sa.DateTime(), nullable=True),
        sa.Column("last_seen", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("agent_id"),
    )


def downgrade() -> None:
    op.drop_table("hosts")
    op.drop_table("reports")
    op.drop_index("ix_agent_actions_investigation_id", table_name="agent_actions")
    op.drop_index("ix_agent_actions_ts", table_name="agent_actions")
    op.drop_table("agent_actions")
    op.drop_index("ix_investigations_started_at", table_name="investigations")
    op.drop_table("investigations")
