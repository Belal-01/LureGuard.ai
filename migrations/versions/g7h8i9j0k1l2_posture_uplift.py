"""posture_uplift — SCA, user inventory, EPSS, EOL, scan jobs

Revision ID: g7h8i9j0k1l2
Revises: f6a7b8c9d0e1
Create Date: 2026-06-18 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "g7h8i9j0k1l2"
down_revision: Union[str, None] = "f6a7b8c9d0e1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "sca_findings",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("agent_id", sa.String(length=16), nullable=False),
        sa.Column("policy_id", sa.String(length=128), nullable=False),
        sa.Column("policy_name", sa.String(length=256), nullable=True),
        sa.Column("check_id", sa.String(length=64), nullable=False),
        sa.Column("title", sa.Text(), nullable=True),
        sa.Column("result", sa.String(length=32), nullable=False),
        sa.Column("compliance", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("remediation", sa.Text(), nullable=True),
        sa.Column("scanned_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["agent_id"], ["hosts.agent_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "agent_id",
            "policy_id",
            "check_id",
            name="uq_sca_findings_agent_policy_check",
        ),
    )
    op.create_index("ix_sca_findings_agent_id", "sca_findings", ["agent_id"])
    op.create_index("ix_sca_findings_result", "sca_findings", ["result"])

    op.create_table(
        "user_findings",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("agent_id", sa.String(length=16), nullable=False),
        sa.Column("username", sa.String(length=128), nullable=False),
        sa.Column("uid", sa.Integer(), nullable=True),
        sa.Column("gid", sa.Integer(), nullable=True),
        sa.Column("shell", sa.String(length=256), nullable=True),
        sa.Column("last_login", sa.String(length=64), nullable=True),
        sa.Column("risk_level", sa.String(length=16), nullable=False),
        sa.Column("scanned_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["agent_id"], ["hosts.agent_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("agent_id", "username", name="uq_user_findings_agent_user"),
    )
    op.create_index("ix_user_findings_agent_id", "user_findings", ["agent_id"])
    op.create_index("ix_user_findings_risk_level", "user_findings", ["risk_level"])

    op.create_table(
        "posture_scan_jobs",
        sa.Column("job_id", sa.String(length=64), nullable=False),
        sa.Column("agent_id", sa.String(length=16), nullable=True),
        sa.Column("agent_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("trigger", sa.String(length=32), nullable=True),
        sa.Column("agents_total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("agents_completed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("results", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(), nullable=False),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("job_id"),
    )
    op.create_index("ix_posture_scan_jobs_status", "posture_scan_jobs", ["status"])

    op.add_column("cve_findings", sa.Column("epss_score", sa.Float(), nullable=True))
    op.add_column("hosts", sa.Column("eol_os", sa.Boolean(), nullable=False, server_default="false"))


def downgrade() -> None:
    op.drop_column("hosts", "eol_os")
    op.drop_column("cve_findings", "epss_score")
    op.drop_index("ix_posture_scan_jobs_status", table_name="posture_scan_jobs")
    op.drop_table("posture_scan_jobs")
    op.drop_index("ix_user_findings_risk_level", table_name="user_findings")
    op.drop_index("ix_user_findings_agent_id", table_name="user_findings")
    op.drop_table("user_findings")
    op.drop_index("ix_sca_findings_result", table_name="sca_findings")
    op.drop_index("ix_sca_findings_agent_id", table_name="sca_findings")
    op.drop_table("sca_findings")
