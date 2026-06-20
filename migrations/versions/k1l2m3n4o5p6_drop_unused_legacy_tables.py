"""Drop unused legacy sessions/alerts/summaries tables and decisions.session_id."""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "k1l2m3n4o5p6"
down_revision: Union[str, None] = "j0k1l2m3n4o5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_table("summaries")
    op.drop_table("alerts")
    op.drop_constraint("decisions_session_id_fkey", "decisions", type_="foreignkey")
    op.drop_column("decisions", "session_id")
    op.drop_table("sessions")


def downgrade() -> None:
    op.create_table(
        "sessions",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("src_ip", postgresql.INET(), nullable=True),
        sa.Column("profile_id", sa.String(length=32), nullable=True),
        sa.Column("opened_at", sa.DateTime(), nullable=True),
        sa.Column("closed_at", sa.DateTime(), nullable=True),
        sa.Column("event_count", sa.Integer(), nullable=True),
        sa.Column("p", sa.Float(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.add_column("decisions", sa.Column("session_id", sa.UUID(), nullable=True))
    op.create_foreign_key(
        "decisions_session_id_fkey",
        "decisions",
        "sessions",
        ["session_id"],
        ["id"],
    )
    op.create_table(
        "alerts",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("decision_id", sa.UUID(), nullable=True),
        sa.Column("ts", sa.DateTime(), nullable=True),
        sa.Column("category", sa.String(length=16), nullable=True),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("sent", sa.Boolean(), nullable=True),
        sa.ForeignKeyConstraint(["decision_id"], ["decisions.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "summaries",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("session_id", sa.UUID(), nullable=True),
        sa.Column("provider", sa.String(length=32), nullable=True),
        sa.Column("model", sa.String(length=64), nullable=True),
        sa.Column("prompt_hash", sa.String(length=64), nullable=True),
        sa.Column("summary_text", sa.Text(), nullable=True),
        sa.Column("tokens_in", sa.Integer(), nullable=True),
        sa.Column("tokens_out", sa.Integer(), nullable=True),
        sa.Column("latency_ms", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["session_id"], ["sessions.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
