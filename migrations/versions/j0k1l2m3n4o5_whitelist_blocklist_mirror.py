"""whitelist entries mirror blocklist — pending recommend + human confirm."""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "j0k1l2m3n4o5"
down_revision: Union[str, None] = "i9j0k1l2m3n4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "whitelist",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.execute("UPDATE whitelist SET id = gen_random_uuid() WHERE id IS NULL")
    op.alter_column("whitelist", "id", nullable=False)

    op.add_column(
        "whitelist",
        sa.Column("executed", sa.Boolean(), nullable=False, server_default="true"),
    )
    op.add_column("whitelist", sa.Column("executed_at", sa.DateTime(), nullable=True))
    op.add_column(
        "whitelist",
        sa.Column("investigation_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.add_column("whitelist", sa.Column("notes", sa.Text(), nullable=True))

    op.create_foreign_key(
        "fk_whitelist_investigation_id",
        "whitelist",
        "investigations",
        ["investigation_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.drop_constraint("whitelist_pkey", "whitelist", type_="primary")
    op.create_primary_key("whitelist_pkey", "whitelist", ["id"])
    op.create_unique_constraint("uq_whitelist_ip", "whitelist", ["ip"])
    op.create_index("ix_whitelist_executed", "whitelist", ["executed"])


def downgrade() -> None:
    op.drop_index("ix_whitelist_executed", table_name="whitelist")
    op.drop_constraint("uq_whitelist_ip", "whitelist", type_="unique")
    op.drop_constraint("whitelist_pkey", "whitelist", type_="primary")
    op.create_primary_key("whitelist_pkey", "whitelist", ["ip"])
    op.drop_constraint("fk_whitelist_investigation_id", "whitelist", type_="foreignkey")
    op.drop_column("whitelist", "notes")
    op.drop_column("whitelist", "investigation_id")
    op.drop_column("whitelist", "executed_at")
    op.drop_column("whitelist", "executed")
    op.drop_column("whitelist", "id")
