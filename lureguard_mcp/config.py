"""Configuration for host-side MCP server."""

from __future__ import annotations

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

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


def _pgpass_covers(host: str, port: str, dbname: str = "lureguard", user: str = "lureguard") -> bool:
    """True if ~/.pgpass or $PGPASSFILE has an entry for this connection.

    libpq reads this file itself once a DSN carries no password — we only need
    to detect it so we know to omit the password and log the mechanism (SEC-4).
    """
    path = Path(os.getenv("PGPASSFILE", "").strip() or (Path.home() / ".pgpass"))
    if not path.exists():
        return False
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            fields = line.split(":")
            if len(fields) == 5 and all(
                f in ("*", v) for f, v in zip(fields[:4], (host, port, dbname, user))
            ):
                return True
    except OSError:
        pass
    return False


def database_url_sync() -> str:
    """psycopg2 DSN (sync) for host-side MCP.

    SEC-4: under ADR-4 this connection crosses a network (collector on the
    VPS, analyst on a laptop), so it needs both encryption in transit and a
    credential that isn't a plaintext password sitting in .env.

    sslmode default: "disable" only when talking to localhost/127.0.0.1 (no
    network hop, matches today's behaviour and the local dev Postgres which
    has no TLS configured) — "require" for any other host, so a remote
    connection is encrypted by default instead of silently staying plaintext
    until someone remembers to opt in. "require" stops passive sniffing but
    not an active MITM (it doesn't authenticate the server); set
    POSTGRES_SSLMODE=verify-full with POSTGRES_SSLROOTCERT once a CA is
    available for that guarantee.

    Credential precedence, most to least preferred, logged either way:
    1. ~/.pgpass or $PGPASSFILE (native libpq mechanism — no secret handled here)
    2. secrets/db_password.txt (existing file-based secret)
    3. POSTGRES_PASSWORD env var (plaintext .env fallback — kept for compat)
    4. hardcoded "lureguard" dev default
    """
    if url := os.getenv("DATABASE_URL", "").strip():
        return url.replace("postgresql+asyncpg://", "postgresql://")

    host = os.getenv("POSTGRES_HOST", "localhost")
    port = os.getenv("POSTGRES_PORT", "5433")

    sslmode = os.getenv("POSTGRES_SSLMODE", "").strip()
    if not sslmode:
        sslmode = "disable" if host in ("localhost", "127.0.0.1") else "require"
    sslrootcert = os.getenv("POSTGRES_SSLROOTCERT", "").strip()

    if _pgpass_covers(host, port):
        pw, mechanism = None, "~/.pgpass or PGPASSFILE"
    elif file_secret := _read_secret("db_password.txt"):
        pw, mechanism = file_secret, "secrets/db_password.txt"
    elif env_pw := os.getenv("POSTGRES_PASSWORD", "").strip():
        pw, mechanism = env_pw, "POSTGRES_PASSWORD env var (plaintext .env fallback)"
    else:
        pw, mechanism = "lureguard", "hardcoded dev default"
    logger.info("database_url_sync: credential source = %s", mechanism)

    auth = f"lureguard:{pw}@" if pw is not None else "lureguard@"
    url = f"postgresql://{auth}{host}:{port}/lureguard?sslmode={sslmode}"
    if sslrootcert:
        url += f"&sslrootcert={sslrootcert}"
    return url


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


def auto_triage_level() -> int:
    return int(os.getenv("AUTO_TRIAGE_LEVEL", "12"))


def allow_agent_block() -> bool:
    """When false (default), confirm_block_ip rejects non-human callers."""
    return os.getenv("LUREGUARD_ALLOW_AGENT_BLOCK", "false").lower() in ("1", "true", "yes")


def allow_agent_whitelist() -> bool:
    """When false (default), confirm_whitelist_ip rejects non-human callers."""
    return os.getenv("LUREGUARD_ALLOW_AGENT_WHITELIST", "false").lower() in ("1", "true", "yes")


def allow_agent_system_update() -> bool:
    """When false (default), apply/rollback system update rejects non-human callers."""
    return os.getenv("LUREGUARD_ALLOW_AGENT_SYSTEM_UPDATE", "false").lower() in (
        "1",
        "true",
        "yes",
    )


def allow_agent_restart() -> bool:
    """When false (default), confirm_restart_agent rejects non-human callers."""
    return os.getenv("LUREGUARD_ALLOW_AGENT_RESTART", "false").lower() in (
        "1",
        "true",
        "yes",
    )


def onboard_ssh_key() -> str:
    """Path to the private key used to reach enrolled hosts (SEC-3).

    Preferred over ONBOARD_SSH_PASSWORD. `~` is expanded so the usual
    ~/.ssh/id_ed25519 form works. Empty string means unset.
    """
    raw = os.getenv("ONBOARD_SSH_KEY", "").strip()
    return os.path.expanduser(raw) if raw else ""


def ssh_strict_host_keys() -> bool:
    """When true, SSH uses StrictHostKeyChecking=yes (full strict). Default is accept-new."""
    return os.getenv("LUREGUARD_SSH_STRICT_HOST_KEYS", "false").lower() in (
        "1",
        "true",
        "yes",
    )
