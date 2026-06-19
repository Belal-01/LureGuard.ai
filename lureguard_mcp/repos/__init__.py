"""Re-export package for Postgres repositories."""

from lureguard_mcp.repos.connection import get_conn

__all__ = ["get_conn"]
