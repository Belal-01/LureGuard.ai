"""Safe SSH remote command execution for posture/containment tools."""

from __future__ import annotations

import ipaddress
import logging
import os
import shlex
import subprocess
from typing import Any

from lureguard_mcp.config import onboard_ssh_key, ssh_strict_host_keys

logger = logging.getLogger(__name__)


class SSHValidationError(ValueError):
    pass


def validate_ip(value: str, *, field: str = "ip") -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise SSHValidationError(f"invalid {field}: {value!r}") from exc


def run_remote_shell(
    host_ip: str,
    remote_command: str,
    *,
    password: str | None = None,
    private_key: str | None = None,
    user: str = "ubuntu",
    timeout: int = 30,
) -> dict[str, Any]:
    """Run a remote command over SSH without interpolating host into a shell.

    SEC-3: prefers key authentication. A key is passed by path and never leaves
    the filesystem; the password path remains as an explicit fallback so
    existing lab setups keep working, but is no longer the only option.

    Which method was used is logged, because a silent fall back to a password
    when a key was configured is exactly the kind of quiet behaviour this
    codebase is trying to remove.
    """
    host = validate_ip(host_ip, field="host_ip")
    ssh_target = f"{user}@{host}"
    host_key_opt = (
        "StrictHostKeyChecking=yes"
        if ssh_strict_host_keys()
        else "StrictHostKeyChecking=accept-new"
    )

    key_path = private_key or onboard_ssh_key()
    env = dict(os.environ)

    if key_path:
        if not os.path.isfile(key_path):
            return {
                "host": host,
                "ok": False,
                "error": (
                    f"SSH key configured but not readable at {key_path} — refusing to "
                    "fall back to password auth silently. Fix the path or unset "
                    "ONBOARD_SSH_KEY."
                ),
            }
        logger.debug(f"ssh {ssh_target}: key auth ({key_path})")
        full_cmd = [
            "ssh",
            "-i", key_path,
            "-o", host_key_opt,
            "-o", "IdentitiesOnly=yes",
            "-o", "PasswordAuthentication=no",
            "-T", ssh_target, remote_command,
        ]
    elif password:
        logger.debug(f"ssh {ssh_target}: password auth (SEC-3: prefer ONBOARD_SSH_KEY)")
        # `sshpass -e` reads the password from the environment. The previous
        # `sshpass -p <password>` put it in argv, where any local user could
        # read it out of `ps` — a worse exposure than the .env file itself.
        env["SSHPASS"] = password
        full_cmd = [
            "sshpass", "-e",
            "ssh",
            "-o", host_key_opt,
            "-T", ssh_target, remote_command,
        ]
    else:
        return {
            "host": host,
            "ok": False,
            "error": "no SSH credential — set ONBOARD_SSH_KEY (preferred) or ONBOARD_SSH_PASSWORD",
        }

    try:
        proc = subprocess.run(
            full_cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
        )
        return {
            "host": host,
            "ok": proc.returncode == 0,
            "stdout": proc.stdout or "",
            "stderr": proc.stderr or "",
            "returncode": proc.returncode,
        }
    except Exception as exc:
        return {"host": host, "ok": False, "error": str(exc)}


def build_sudo_remote_command(password: str, inner_command: str) -> str:
    """Build a remote bash -lc command with quoted password and inner command."""
    sudo_pipe = f"echo {shlex.quote(password)} | sudo -S"
    return f"{sudo_pipe} bash -lc {shlex.quote(inner_command)}"
