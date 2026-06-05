"""Alembic environment — uses async engine."""
import asyncio
from logging.config import fileConfig
import sys, os
from sqlalchemy import pool
from sqlalchemy.ext.asyncio import async_engine_from_config
from alembic import context

config = context.config
# Skipping fileConfig since alembic.ini in this project lacks [loggers] sections
# and the app uses loguru.

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'core'))
from db.models import Base
from db.session import _get_db_url

# Dynamically set the database URL
config.set_main_option("sqlalchemy.url", _get_db_url())

target_metadata = Base.metadata


def do_run_migrations(connection):
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations():
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online():
    asyncio.run(run_async_migrations())



if context.is_offline_mode():
    pass
else:
    run_migrations_online()
