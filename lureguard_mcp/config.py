"""Configuration for host-side MCP server."""

from __future__ import annotations

import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
REPORTS_DIR = REPO_ROOT / "reports"
AGENT_CONFIG_TEMPLATE = REPO_ROOT / "wazuh" / "agent-ossec.conf"


def load_env_file() -> None:
    """Load repo `.env` into os.environ (setdefault — explicit env wins)."""
    env_file = REPO_ROOT / ".env"
    if not env_file.exists():
        return
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip())


load_env_file()


def _read_secret(name: str) -> str:
    path = REPO_ROOT / "secrets" / name
    if path.exists():
        return path.read_text(encoding="utf-8").strip()
    return ""


def database_url_sync() -> str:
    """psycopg2 DSN (sync) for host-side MCP."""
    if url := os.getenv("DATABASE_URL", "").strip():
        return url.replace("postgresql+asyncpg://", "postgresql://")
    pw = _read_secret("db_password.txt") or os.getenv("POSTGRES_PASSWORD", "lureguard")
    host = os.getenv("POSTGRES_HOST", "localhost")
    port = os.getenv("POSTGRES_PORT", "5433")
    return f"postgresql://lureguard:{pw}@{host}:{port}/lureguard"


def wazuh_api_url() -> str:
    return os.getenv("WAZUH_API_URL", "https://localhost:55000").rstrip("/")


def wazuh_api_user() -> str:
    return os.getenv("WAZUH_API_USER", "wazuh")


def wazuh_api_password() -> str:
    return os.getenv("WAZUH_API_PASSWORD", "LureGuard-Wazuh-Dev-2026!")


def wazuh_verify_ssl() -> bool:
    return os.getenv("WAZUH_API_VERIFY_SSL", "false").lower() in ("1", "true", "yes")


def virustotal_api_key() -> str:
    return os.getenv("VIRUSTOTAL_API_KEY", "").strip()


def abuseipdb_api_key() -> str:
    return os.getenv("ABUSEIPDB_API_KEY", "").strip()


def urlhaus_api_url() -> str:
    return os.getenv(
        "URLHAUS_API_URL",
        "https://urlhaus-api.abuse.ch/v1/url/",
    ).strip()


def onboard_ssh_password() -> str:
    return os.getenv("ONBOARD_SSH_PASSWORD", "").strip()


def wazuh_agent_manager_ip(target_ip: str | None = None) -> str:
    """IP/hostname agents use to reach the manager (override for multi-homed hosts)."""
    if override := os.getenv("WAZUH_AGENT_MANAGER_IP", "").strip():
        return override
    if target_ip:
        import socket

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((target_ip, 22))
            route_ip = s.getsockname()[0]
            if route_ip and not route_ip.startswith("127."):
                return route_ip
        except OSError:
            pass
        finally:
            s.close()
    return os.getenv("WAZUH_MANAGER_IP", "").strip()


def wazuh_agent_register_ip() -> str:
    """IP stored on manager for new agents. Use 'any' when Docker NAT breaks source-IP checks."""
    return os.getenv("WAZUH_AGENT_REGISTER_IP", "any").strip() or "any"


def manager_container() -> str:
    return os.getenv("WAZUH_MANAGER_CONTAINER", "wazuh-manager")
