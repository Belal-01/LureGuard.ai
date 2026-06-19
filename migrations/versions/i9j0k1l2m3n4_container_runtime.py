"""container_runtime snapshot from agent-side Trivy script."""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "i9j0k1l2m3n4"
down_revision: Union[str, None] = "h8i9j0k1l2m3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "container_runtime",
        sa.Column("agent_id", sa.String(length=16), primary_key=True),
        sa.Column("containers", postgresql.JSONB(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("container_runtime")
