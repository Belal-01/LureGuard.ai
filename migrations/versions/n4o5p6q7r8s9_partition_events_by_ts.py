"""partition events table by ts (RANGE) — STO-2

Register item STO-2, gated by decision STO-7: there is no retention anywhere
in the product today — events grows until disk fills. Keeping events in
Postgres (not moving to OpenSearch) means partitioning is the prerequisite:
retention becomes `DROP TABLE events_2026_05` (a catalog op) instead of a
bulk DELETE (WAL amplification, index bloat, needs a locking VACUUM FULL to
reclaim disk).

Postgres cannot ALTER a heap table into a partitioned one, so this creates a
new partitioned `events`, copies rows across, and swaps it in for the old
heap table. Safe on a populated database: the old table is only dropped
after every row has landed in the new one.

Composite PK — knock-on effects:
  Postgres requires every unique constraint on a partitioned table to
  include the partition key, so events' PK becomes (id, ts) instead of a
  bare id. That breaks two things that assumed a single-column PK:
    - decisions.event_id had FK `fk_decisions_event_id` -> events.id. A
      partitioned table can't offer a unique constraint on id alone, and
      giving decisions an event_ts column just to satisfy a composite FK
      would force `DROP TABLE events_2026_05` to scan decisions for
      referencing rows before the drop is allowed — reintroducing the exact
      cost this migration exists to remove. The FK is dropped; event_id
      stays as a plain, unenforced reference (see core/db/models.py).
    - events.investigation_id -> investigations.id (added in m3n4o5p6q7r8)
      is unaffected: events is the referencing (many) side, investigations
      keeps its untouched single-column PK, and Postgres has supported FKs
      *from* a partitioned table since PG11. Recreated as-is.

Partition strategy:
  A DEFAULT partition catches every row that doesn't match a dated range —
  this is what makes the data copy safe without knowing the table's ts
  range up front, and it is the safety net against the alternative failure
  mode: a missing partition makes INSERT fail, which is a silent ingest
  outage. Two dated monthly partitions (this month, next month) are also
  pre-created so new writes immediately land in a droppable partition
  instead of piling into DEFAULT. Ongoing partition creation is the
  retention job's job, not this migration's.

Indexes:
  ix_events_src_ip_ts, ix_events_agent_id_ts, ix_events_investigation_id
  are recreated unchanged (partitioned-table indexes propagate to every
  partition automatically). A new ix_events_ts_brin BRIN index on ts
  replaces what would otherwise be a bare btree: inserts are append-only
  and physically correlated with ts, so a BRIN summary gives the same
  range-scan pruning at a fraction of the size and write cost of a btree.

Revision ID: n4o5p6q7r8s9
Revises: m3n4o5p6q7r8
Create Date: 2026-08-14 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "n4o5p6q7r8s9"
down_revision: Union[str, None] = "m3n4o5p6q7r8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Shared column list — kept identical between the new partitioned table and
# the downgrade's restored heap table.
_EVENT_COLUMNS = [
    sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
    sa.Column("ts", sa.DateTime(), nullable=False),
    sa.Column("src_ip", postgresql.INET(), nullable=True),
    sa.Column("src_port", sa.Integer(), nullable=True),
    sa.Column("channel", sa.String(length=32), nullable=False),
    sa.Column("event_type", sa.String(length=64), nullable=False),
    sa.Column("username", sa.String(length=128), nullable=True),
    sa.Column("success", sa.Boolean(), nullable=True),
    sa.Column("profile_id", sa.String(length=32), nullable=True),
    sa.Column("wazuh_rule_id", sa.Integer(), nullable=True),
    sa.Column("wazuh_rule_level", sa.Integer(), nullable=True),
    sa.Column("agent_id", sa.String(length=16), nullable=True),
    sa.Column("agent_name", sa.String(length=128), nullable=True),
    sa.Column("agent_ip", postgresql.INET(), nullable=True),
    sa.Column("ingestion_path", sa.String(length=16), nullable=True),
    sa.Column("syscheck_path", sa.Text(), nullable=True),
    sa.Column("syscheck_event", sa.String(length=16), nullable=True),
    sa.Column("syscheck_sha256_after", sa.String(length=64), nullable=True),
    sa.Column("raw_ref", sa.Text(), nullable=True),
    sa.Column("wazuh_rule_description", sa.Text(), nullable=True),
    sa.Column("geo_country", sa.String(length=2), nullable=True),
    sa.Column("geo_city", sa.String(length=128), nullable=True),
    sa.Column("investigation_id", postgresql.UUID(as_uuid=True), nullable=True),
]
_COLUMN_NAMES = [c.name for c in _EVENT_COLUMNS]


def upgrade() -> None:
    # decisions.event_id can no longer FK a partitioned events.id (see module
    # docstring) — drop it before the old table goes away.
    op.drop_constraint("fk_decisions_event_id", "decisions", type_="foreignkey")

    # Move the old heap table out of the way. Renaming a table does NOT rename
    # its indexes/constraints, so free those names explicitly — the new
    # partitioned table reuses them.
    op.rename_table("events", "events_old")
    op.drop_index("ix_events_src_ip_ts", table_name="events_old")
    op.drop_index("ix_events_agent_id_ts", table_name="events_old")
    op.drop_index("ix_events_investigation_id", table_name="events_old")
    op.execute("ALTER TABLE events_old DROP CONSTRAINT fk_events_investigation_id")
    op.execute("ALTER TABLE events_old DROP CONSTRAINT events_pkey")

    # New partitioned table. PK must include the partition key (ts).
    op.create_table(
        "events",
        *[c.copy() for c in _EVENT_COLUMNS],
        sa.PrimaryKeyConstraint("id", "ts", name="events_pkey"),
        sa.ForeignKeyConstraint(
            ["investigation_id"], ["investigations.id"],
            name="fk_events_investigation_id",
        ),
        postgresql_partition_by="RANGE (ts)",
    )

    # Pre-create this month + next month so new writes land in a droppable
    # partition immediately, plus a DEFAULT partition as the safety net —
    # without it, a row outside every pre-created range fails to INSERT,
    # which is a silent ingest outage.
    op.execute(
        """
        DO $$
        DECLARE
            start_this date := date_trunc('month', now())::date;
            start_next date := (date_trunc('month', now()) + interval '1 month')::date;
            start_after date := (date_trunc('month', now()) + interval '2 month')::date;
        BEGIN
            EXECUTE format(
                'CREATE TABLE events_%s PARTITION OF events FOR VALUES FROM (%L) TO (%L)',
                to_char(start_this, 'YYYY_MM'), start_this, start_next
            );
            EXECUTE format(
                'CREATE TABLE events_%s PARTITION OF events FOR VALUES FROM (%L) TO (%L)',
                to_char(start_next, 'YYYY_MM'), start_next, start_after
            );
        END $$;
        """
    )
    op.execute("CREATE TABLE events_default PARTITION OF events DEFAULT")

    # Indexes — propagate automatically to every partition (present + future).
    op.create_index("ix_events_src_ip_ts", "events", ["src_ip", "ts"])
    op.create_index("ix_events_agent_id_ts", "events", ["agent_id", "ts"])
    op.create_index("ix_events_investigation_id", "events", ["investigation_id"])
    op.create_index(
        "ix_events_ts_brin", "events", ["ts"], postgresql_using="brin"
    )

    # Copy rows — DEFAULT partition absorbs everything outside the two
    # pre-created dated ranges, so this cannot fail on unknown historical data.
    cols = ", ".join(_COLUMN_NAMES)
    op.execute(f"INSERT INTO events ({cols}) SELECT {cols} FROM events_old")

    op.drop_table("events_old")


def downgrade() -> None:
    # Rename the partitioned table aside; DROP TABLE on it later cascades to
    # every partition (dated + default) in one statement. Renaming doesn't
    # rename its indexes/constraints, so free the names the heap table reuses.
    op.rename_table("events", "events_new")
    op.drop_index("ix_events_src_ip_ts", table_name="events_new")
    op.drop_index("ix_events_agent_id_ts", table_name="events_new")
    op.drop_index("ix_events_investigation_id", table_name="events_new")
    op.execute("ALTER TABLE events_new DROP CONSTRAINT fk_events_investigation_id")
    op.execute("ALTER TABLE events_new DROP CONSTRAINT events_pkey")

    op.create_table(
        "events",
        *[c.copy() for c in _EVENT_COLUMNS],
        sa.PrimaryKeyConstraint("id", name="events_pkey"),
        sa.ForeignKeyConstraint(
            ["investigation_id"], ["investigations.id"],
            name="fk_events_investigation_id",
        ),
    )
    op.create_index("ix_events_src_ip_ts", "events", ["src_ip", "ts"])
    op.create_index("ix_events_agent_id_ts", "events", ["agent_id", "ts"])
    op.create_index("ix_events_investigation_id", "events", ["investigation_id"])

    cols = ", ".join(_COLUMN_NAMES)
    op.execute(f"INSERT INTO events ({cols}) SELECT {cols} FROM events_new")

    op.drop_table("events_new")

    op.create_foreign_key(
        "fk_decisions_event_id",
        "decisions",
        "events",
        ["event_id"],
        ["id"],
        ondelete="SET NULL",
    )
