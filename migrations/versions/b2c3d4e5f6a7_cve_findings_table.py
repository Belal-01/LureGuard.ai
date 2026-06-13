"""cve_findings_table

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-06-13 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "b2c3d4e5f6a7"
down_revision: Union[str, None] = "a1b2c3d4e5f6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "cve_findings",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("agent_id", sa.String(length=16), nullable=False),
        sa.Column("package_name", sa.String(length=256), nullable=False),
        sa.Column("package_version", sa.String(length=128), nullable=False),
        sa.Column("cve_id", sa.String(length=32), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("cvss", sa.Float(), nullable=True),
        sa.Column("fix_version", sa.String(length=128), nullable=True),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("source", sa.String(length=16), nullable=False, server_default="osv"),
        sa.Column("scanned_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["agent_id"], ["hosts.agent_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "agent_id",
            "package_name",
            "package_version",
            "cve_id",
            name="uq_cve_findings_agent_pkg_cve",
        ),
    )
    op.create_index("ix_cve_findings_agent_id", "cve_findings", ["agent_id"], unique=False)
    op.create_index("ix_cve_findings_severity", "cve_findings", ["severity"], unique=False)
    op.create_index("ix_cve_findings_scanned_at", "cve_findings", ["scanned_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_cve_findings_scanned_at", table_name="cve_findings")
    op.drop_index("ix_cve_findings_severity", table_name="cve_findings")
    op.drop_index("ix_cve_findings_agent_id", table_name="cve_findings")
    op.drop_table("cve_findings")
