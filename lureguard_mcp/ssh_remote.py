"""Safe SSH remote command execution for posture/containment tools."""

from __future__ import annotations

import ipaddress
import shlex
import subprocess
from typing import Any

from lureguard_mcp.config import ssh_strict_host_keys


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
    password: str,
    user: str = "ubuntu",
    timeout: int = 30,
) -> dict[str, Any]:
    """Run a remote command via sshpass+ssh without interpolating host into shell."""
    host = validate_ip(host_ip, field="host_ip")
    ssh_target = f"{user}@{host}"
    host_key_opt = (
        "StrictHostKeyChecking=accept-new"
        if ssh_strict_host_keys()
        else "StrictHostKeyChecking=no"
    )
    full_cmd = [
        "sshpass",
        "-p",
        password,
        "ssh",
        "-o",
        host_key_opt,
        "-T",
        ssh_target,
        remote_command,
    ]
    try:
        proc = subprocess.run(
            full_cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
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
