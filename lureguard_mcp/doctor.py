"""LureGuard doctor — environment and stack health checks."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import logging

# Suppress httpx noise before any health-check imports run.
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

REPO_ROOT = Path(__file__).resolve().parents[1]


@dataclass
class Check:
    label: str
    ok: bool
    hint: str = ""
    required: bool = True


def _green(text: str) -> str:
    if sys.stdout.isatty():
        return f"\033[32m{text}\033[0m"
    return text


def _red(text: str) -> str:
    if sys.stdout.isatty():
        return f"\033[31m{text}\033[0m"
    return text


def _yellow(text: str) -> str:
    if sys.stdout.isatty():
        return f"\033[33m{text}\033[0m"
    return text


def _dim(text: str) -> str:
    if sys.stdout.isatty():
        return f"\033[2m{text}\033[0m"
    return text


def _container_running(name: str) -> bool:
    r = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", name],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return r.returncode == 0 and r.stdout.strip() == "true"


def check_docker() -> Check:
    if shutil.which("docker") is None:
        return Check("Docker", False, "Install Docker Desktop")
    try:
        subprocess.run(["docker", "info"], capture_output=True, check=True, timeout=10)
    except Exception:
        return Check("Docker", False, "Start Docker Desktop")
    return Check("Docker", True)


def check_compose_services() -> Check:
    required = {
        "lureguard-postgres": "postgres",
        "lureguard-core": "lureguard-core",
        "wazuh-manager": "wazuh-manager",
    }
    missing = [label for name, label in required.items() if not _container_running(name)]
    if missing:
        return Check(
            "Core stack containers",
            False,
            f"Not running: {', '.join(missing)} — run: docker compose up -d",
        )
    return Check("Core stack containers", True)


def check_postgres() -> Check:
    try:
        from lureguard_mcp.db import get_conn

        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                cur.fetchone()
    except Exception as exc:
        return Check("Postgres :5433", False, f"{exc}")
    return Check("Postgres :5433", True)


def check_agent_schema() -> Check:
    try:
        from lureguard_mcp.db import get_conn

        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'investigations')"
                )
                if not cur.fetchone()[0]:
                    return Check(
                        "Agent DB schema",
                        False,
                        "Run: make migrate   (or: docker compose restart lureguard-core)",
                    )
    except Exception as exc:
        return Check("Agent DB schema", False, str(exc))
    return Check("Agent DB schema", True)


def check_core_health() -> Check:
    try:
        import httpx

        r = httpx.get("http://localhost:8080/health", timeout=5)
        if r.status_code == 200:
            return Check("Core API :8080", True)
        return Check("Core API :8080", False, f"HTTP {r.status_code}")
    except Exception as exc:
        return Check("Core API :8080", False, str(exc))


def check_wazuh_api() -> Check:
    try:
        import httpx

        base = os.getenv("WAZUH_API_URL", "https://localhost:55000").rstrip("/")
        r = httpx.get(f"{base}/", verify=False, timeout=5)
        if r.status_code >= 500:
            return Check(
                "Wazuh API :55000",
                False,
                "API unreachable — run: docker compose up -d --force-recreate wazuh-manager",
            )
    except httpx.ConnectError:
        return Check(
            "Wazuh API :55000",
            False,
            "Port not open — run: docker compose up -d --force-recreate wazuh-manager",
        )
    except Exception:
        pass

    try:
        from lureguard_mcp.wazuh_client import WazuhClient

        ok, msg = WazuhClient().health_check()
        if ok:
            return Check("Wazuh API auth", True)
        if "401" in msg or "403" in msg:
            return Check(
                "Wazuh API auth",
                False,
                "Bad credentials — set WAZUH_API_USER/PASSWORD in .env",
            )
        return Check("Wazuh API auth", False, msg)
    except Exception as exc:
        return Check("Wazuh API auth", False, str(exc))


def check_integratord() -> Check:
    if not _container_running("wazuh-manager"):
        return Check("Wazuh integratord", False, "wazuh-manager not running", required=False)
    try:
        r = subprocess.run(
            ["docker", "exec", "wazuh-manager", "test", "-f", "/var/ossec/integrations/custom-lureguard.py"],
            capture_output=True,
            timeout=10,
        )
        if r.returncode == 0:
            return Check("Wazuh integratord", True)
        return Check("Wazuh integratord", False, "custom-lureguard.py missing in manager")
    except Exception as exc:
        return Check("Wazuh integratord", False, str(exc))


def check_grafana() -> Check:
    try:
        import httpx

        r = httpx.get("http://localhost:3000/api/health", timeout=5)
        if r.status_code == 200:
            return Check("Grafana :3000", True)
        return Check(
            "Grafana :3000",
            False,
            f"HTTP {r.status_code} — run: docker compose up -d grafana",
            required=False,
        )
    except Exception as exc:
        return Check(
            "Grafana :3000",
            False,
            f"{exc} — run: docker compose up -d grafana",
            required=False,
        )


def check_env() -> Check:
    if not (REPO_ROOT / ".env").exists():
        return Check(".env file", False, "Copy .env.example to .env and fill Telegram + Wazuh API")
    return Check(".env file", True)


def check_mcp_server() -> Check:
    venv_python = REPO_ROOT / ".venv" / "bin" / "python"
    if not venv_python.exists():
        return Check(
            "MCP Python package",
            False,
            "Run: make venv",
        )
    try:
        import lureguard_mcp.server  # noqa: F401
    except Exception as exc:
        return Check("MCP Python package", False, f"Run: make venv — {exc}")
    return Check("MCP Python package", True)


def check_opencode_cli() -> Check:
    if shutil.which("opencode"):
        return Check("opencode CLI", True)
    return Check(
        "opencode CLI",
        False,
        "Install: brew install opencode",
    )


def check_opencode_config() -> Check:
    if not shutil.which("opencode"):
        return Check("opencode.json schema", False, "Install opencode first")
    cfg = REPO_ROOT / "opencode.json"
    if not cfg.exists():
        return Check("opencode.json schema", False, "Missing opencode.json in repo root")
    r = subprocess.run(
        ["opencode", "debug", "config"],
        capture_output=True,
        text=True,
        timeout=30,
        cwd=str(REPO_ROOT),
    )
    if r.returncode != 0:
        err = (r.stderr or r.stdout or "invalid config").strip().splitlines()
        hint = err[0][:200] if err else "Run: opencode debug config"
        return Check("opencode.json schema", False, hint)
    return Check("opencode.json schema", True)


def check_opencode_mcp() -> Check:
    if not shutil.which("opencode"):
        return Check("opencode MCP lureguard", False, "Install opencode first")
    r = subprocess.run(
        ["opencode", "mcp", "list"],
        capture_output=True,
        text=True,
        timeout=90,
        cwd=str(REPO_ROOT),
    )
    out = (r.stdout or "") + (r.stderr or "")
    if "lureguard" in out and ("connected" in out.lower() or "✓" in out):
        return Check("opencode MCP lureguard", True)
    hint = "Run: opencode mcp list — ensure .venv exists and lureguard MCP starts"
    if r.returncode != 0 and out.strip():
        hint = out.strip().splitlines()[-1][:200]
    return Check("opencode MCP lureguard", False, hint)


def check_opencode_providers() -> Check:
    """OpenCode works with free Zen models (big-pickle, etc.) — no paid API key required."""
    if not shutil.which("opencode"):
        return Check("opencode LLM ready", False, "Install opencode first")

    if os.getenv("OPENAI_API_KEY") or os.getenv("ANTHROPIC_API_KEY"):
        return Check("opencode LLM ready", True, "Using env API key")

    auth_file = Path.home() / ".local" / "share" / "opencode" / "auth.json"
    if auth_file.exists() and auth_file.stat().st_size > 4:
        return Check("opencode LLM ready", True, "Using saved provider credentials")

    r = subprocess.run(
        ["opencode", "models"],
        capture_output=True,
        text=True,
        timeout=30,
        cwd=str(REPO_ROOT),
    )
    out = r.stdout or ""
    free_models = [line.strip() for line in out.splitlines() if line.strip().startswith("opencode/")]
    if free_models:
        default = "opencode/big-pickle" if any("big-pickle" in m for m in free_models) else free_models[0]
        return Check(
            "opencode LLM ready",
            True,
            f"Free Zen models available (e.g. {default}) — no API key needed",
        )

    return Check(
        "opencode LLM ready",
        False,
        "No models found — run: opencode providers login  or check network",
    )


def check_optional_intel() -> Check:
    missing = []
    if not os.getenv("VIRUSTOTAL_API_KEY"):
        missing.append("VIRUSTOTAL_API_KEY")
    if not os.getenv("ABUSEIPDB_API_KEY"):
        missing.append("ABUSEIPDB_API_KEY")
    if missing:
        return Check(
            "Threat intel keys",
            True,
            f"Optional unset: {', '.join(missing)}",
            required=False,
        )
    return Check("Threat intel keys", True, required=False)


def _print_check(c: Check) -> None:
    if c.ok:
        mark = _green("✓")
    elif c.required:
        mark = _red("✗")
    else:
        mark = _yellow("!")
    print(f"  {mark}  {c.label}")
    if c.hint:
        print(f"      {_dim('→ ' + c.hint)}")


def run_doctor() -> int:
    print("lureguard doctor")
    print("─" * 44)

    required_checks = [
        check_docker(),
        check_compose_services(),
        check_postgres(),
        check_agent_schema(),
        check_core_health(),
        check_wazuh_api(),
        check_integratord(),
        check_env(),
        check_mcp_server(),
        check_opencode_cli(),
        check_opencode_config(),
        check_opencode_mcp(),
        check_opencode_providers(),
    ]
    optional_checks = [
        check_grafana(),
        check_optional_intel(),
    ]

    print("Required")
    required_issues = 0
    for c in required_checks:
        _print_check(c)
        if not c.ok and c.required:
            required_issues += 1

    print("")
    print("Optional")
    for c in optional_checks:
        _print_check(c)

    print("─" * 44)
    if required_issues:
        print(
            f"Result: {required_issues} required issue(s). "
            "Fix above, then: make doctor"
        )
        return 1
    print("All required checks passed. Run: opencode")
    return 0


def main() -> None:
    env_file = REPO_ROOT / ".env"
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                os.environ.setdefault(k.strip(), v.strip())
    sys.exit(run_doctor())


if __name__ == "__main__":
    main()
