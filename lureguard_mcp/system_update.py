"""Wrap update-system.py for MCP (opencode has bash denied)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from lureguard_mcp.config import REPO_ROOT, allow_agent_system_update

_SCRIPT = REPO_ROOT / "update-system.py"


def _run(cmd: str) -> tuple[int, str, str]:
    proc = subprocess.run(
        [sys.executable, str(_SCRIPT), cmd],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=300,
    )
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def _deny_agent_caller(caller: str, action: str) -> dict | None:
    if caller != "human" and not allow_agent_system_update():
        return {
            "ok": False,
            "status": "denied",
            "error": (
                f"{action} requires human approval. "
                "Set LUREGUARD_ALLOW_AGENT_SYSTEM_UPDATE=true only for testing."
            ),
        }
    return None


def check_system_update() -> dict:
    code, out, err = _run("check")
    if code != 0:
        return {"ok": False, "error": err or out or "check failed"}
    try:
        payload = json.loads(out)
        payload["ok"] = True
        return payload
    except json.JSONDecodeError:
        return {"ok": False, "error": out or err or "invalid check output"}


def apply_system_update(*, caller: str = "human") -> dict:
    denied = _deny_agent_caller(caller, "apply_system_update")
    if denied:
        return denied
    code, out, err = _run("apply")
    return {
        "ok": code == 0,
        "stdout": out,
        "stderr": err,
        "next_steps": ["make migrate", "docker compose up -d", "restart opencode"],
    }


def dismiss_system_update() -> dict:
    code, out, err = _run("dismiss")
    return {"ok": code == 0, "message": out or err}


def rollback_system_update(*, caller: str = "human") -> dict:
    denied = _deny_agent_caller(caller, "rollback_system_update")
    if denied:
        return denied
    code, out, err = _run("rollback")
    return {"ok": code == 0, "stdout": out, "stderr": err}
