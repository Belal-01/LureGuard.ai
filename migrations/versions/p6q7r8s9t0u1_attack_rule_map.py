"""attack_rule_map — ATT&CK technique mapping queryable from Grafana (GFA-7)

ML-4 produced core/attack_map.json: 218 Wazuh rules mapped to 42 techniques.
Grafana queries Postgres, not the filesystem, so the coverage dashboard cannot
read that file — the mapping has to live in a table to be joinable against
`events.wazuh_rule_id`.

The table is a projection of the JSON, not a second source of truth: it is
truncated and reloaded by `core.attack_seed.load_attack_map()`, which runs at
Core startup. Editing rows here is pointless; edit the JSON and reload.

Revision ID: p6q7r8s9t0u1
Revises: n4o5p6q7r8s9
Create Date: 2026-08-15 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "p6q7r8s9t0u1"
down_revision: Union[str, None] = "n4o5p6q7r8s9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "attack_rule_map",
        sa.Column("wazuh_rule_id", sa.Integer(), nullable=False),
        sa.Column("technique", sa.String(length=16), nullable=False),
        sa.Column("tactic", sa.String(length=64), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("source", sa.String(length=32)),
        sa.PrimaryKeyConstraint("wazuh_rule_id", "technique", name="attack_rule_map_pkey"),
    )
    op.create_index("ix_attack_rule_map_technique", "attack_rule_map", ["technique"])
    op.create_index("ix_attack_rule_map_tactic", "attack_rule_map", ["tactic"])


def downgrade() -> None:
    op.drop_index("ix_attack_rule_map_tactic", table_name="attack_rule_map")
    op.drop_index("ix_attack_rule_map_technique", table_name="attack_rule_map")
    op.drop_table("attack_rule_map")
