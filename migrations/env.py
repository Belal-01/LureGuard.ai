"""Alembic environment — uses async engine."""
from logging.config import fileConfig
from sqlalchemy import pool
from sqlalchemy.ext.asyncio import async_engine_from_config
from alembic import context

config = context.config
if config.config_file_name:
    fileConfig(config.config_file_name)

# Import your models so Alembic can detect them
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'core'))
from db.models import Base
target_metadata = Base.metadata


def run_migrations_online():
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()
