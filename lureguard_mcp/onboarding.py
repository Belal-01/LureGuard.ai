"""SSH-based Wazuh agent onboarding via MCP."""

from __future__ import annotations

import asyncio
import shlex
import socket
from pathlib import Path

import asyncssh

from lureguard_mcp.config import AGENT_CONFIG_TEMPLATE, manager_container, onboard_ssh_password, wazuh_agent_manager_ip
from lureguard_mcp.db import upsert_host_db
from lureguard_mcp.wazuh_client import WazuhClient


def _detect_manager_ip(target_ip: str | None = None) -> str:
    """Return Wazuh manager address agents should use to connect back to this host."""
    ip = wazuh_agent_manager_ip(target_ip)
    if ip:
        return ip

    for iface in ("en0", "en1", "eth0", "ens33", "ens3", "wlan0"):
        try:
            import subprocess

            if Path("/sbin/ipconfig").exists():
                out = subprocess.check_output(
                    ["ipconfig", "getifaddr", iface], stderr=subprocess.DEVNULL, text=True
                ).strip()
                if out:
                    return out
            out = subprocess.check_output(
                ["bash", "-lc", f"ip -4 addr show {iface} 2>/dev/null | awk '/inet /{{print $2}}' | cut -d/ -f1"],
                text=True,
            ).strip()
            if out:
                return out.split("\n")[0]
        except Exception:
            continue
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()


def _register_on_manager(name: str) -> dict[str, str | bool]:
    return WazuhClient().register_agent(name)


async def _run(cmd: list[str], *, timeout: float = 120.0) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        raise RuntimeError(f"Command timed out: {' '.join(cmd)}")
    return proc.returncode or 0, stdout.decode(), stderr.decode()


async def _vm_exec(
    conn: asyncssh.SSHClientConnection,
    command: str,
    *,
    sudo_password: str,
    sudo: bool = True,
) -> str:
    """Run a command on the VM. Uses sudo -S with safely quoted password and command."""
    if sudo:
        wrapped = f"echo {shlex.quote(sudo_password)} | sudo -S bash -lc {shlex.quote(command)}"
        result = await conn.run(wrapped, check=False)
    else:
        result = await conn.run(command, check=False)
    if result.exit_status != 0:
        raise RuntimeError(result.stderr or result.stdout or f"exit {result.exit_status}")
    return (result.stdout or "").strip()


async def _vm_sftp_write(conn: asyncssh.SSHClientConnection, remote_path: str, content: str) -> None:
    async with conn.start_sftp_client() as sftp:
        async with sftp.open(remote_path, "w") as remote:
            await remote.write(content)


async def onboard_host(
    ip: str,
    ssh_user: str = "ubuntu",
    *,
    ssh_password: str | None = None,
    agent_name: str | None = None,
    agent_id: str | None = None,
) -> dict:
    password = ssh_password or onboard_ssh_password()
    if not password:
        return {
            "success": False,
            "error": "SSH password required. Set ONBOARD_SSH_PASSWORD in .env or pass ssh_password.",
        }

    hostname = agent_name or f"lureguard-{ip.replace('.', '-')}"
    manager_ip = _detect_manager_ip(ip)

    if not AGENT_CONFIG_TEMPLATE.exists():
        return {"success": False, "error": f"Missing agent template: {AGENT_CONFIG_TEMPLATE}"}

    agent_config = AGENT_CONFIG_TEMPLATE.read_text(encoding="utf-8").replace(
        "__WAZUH_MANAGER_IP__", manager_ip
    )

    try:
        reg = await asyncio.to_thread(_register_on_manager, hostname)
        aid = agent_id or str(reg["id"])
        full_key = str(reg["key"])
        reused = bool(reg.get("reused"))

        async with asyncssh.connect(
            ip,
            username=ssh_user,
            password=password,
            known_hosts=None,
        ) as conn:
            pkg_check = await conn.run("dpkg -l wazuh-agent 2>/dev/null | grep -c '^ii' || echo 0")
            installed = (pkg_check.stdout or "0").strip()
            if installed == "0":
                await _vm_exec(
                    conn,
                    "curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg",
                    sudo_password=password,
                )
                await _vm_sftp_write(
                    conn,
                    "/tmp/lureguard-wazuh.list",
                    "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main\n",
                )
                await _vm_exec(
                    conn,
                    "cp /tmp/lureguard-wazuh.list /etc/apt/sources.list.d/wazuh.list",
                    sudo_password=password,
                )
                await _vm_exec(conn, "apt-get update -qq", sudo_password=password)
                await _vm_exec(
                    conn,
                    "apt-get install -y wazuh-agent=4.14.5-1",
                    sudo_password=password,
                )

            async with conn.start_sftp_client() as sftp:
                async with sftp.open("/tmp/lureguard-ossec.conf", "w") as remote:
                    await remote.write(agent_config)
            await _vm_exec(
                conn,
                "cp /tmp/lureguard-ossec.conf /var/ossec/etc/ossec.conf && "
                "chmod 640 /var/ossec/etc/ossec.conf && "
                "chown root:wazuh /var/ossec/etc/ossec.conf",
                sudo_password=password,
            )

            await _vm_sftp_write(
                conn,
                "/tmp/lureguard-agent-import.in",
                f"I\n{full_key}\ny\nQ\n",
            )
            await _vm_exec(
                conn,
                "cat /tmp/lureguard-agent-import.in | /var/ossec/bin/manage_agents",
                sudo_password=password,
            )
            await _vm_exec(conn, "systemctl enable wazuh-agent", sudo_password=password)
            await _vm_exec(conn, "systemctl restart wazuh-agent", sudo_password=password)

            await asyncio.sleep(3)
            status_out = await _vm_exec(
                conn, "systemctl is-active wazuh-agent || true", sudo_password=password
            )

        await asyncio.sleep(10)
        _, agent_list, _ = await _run(
            ["docker", "exec", manager_container(), "/var/ossec/bin/agent_control", "-l"]
        )
        wazuh_status = "unknown"
        for line in agent_list.splitlines():
            if f"ID: {aid}," not in line:
                continue
            if "Active" in line and "Never connected" not in line:
                wazuh_status = "active"
            elif "Never connected" in line or "Disconnected" in line:
                wazuh_status = "disconnected"
            break

        upsert_host_db(
            agent_id=aid,
            name=hostname,
            ip=ip,
            wazuh_status=wazuh_status,
            enrolled_by="agent",
        )

        if wazuh_status != "active":
            return {
                "success": False,
                "error": (
                    f"Agent installed on {ip} but manager reports status '{wazuh_status}' "
                    f"(agent {aid}). VM service: {status_out}. "
                    f"Manager address in agent config: {manager_ip}. "
                    "From the VM, verify TCP to that address on ports 1514/1515. "
                    "Override with WAZUH_AGENT_MANAGER_IP in .env if auto-detect is wrong."
                ),
                "agent_id": aid,
                "agent_name": hostname,
                "manager_ip": manager_ip,
                "vm_ip": ip,
                "service_status": status_out,
                "wazuh_status": wazuh_status,
                "reused_registration": reused,
            }

        return {
            "success": True,
            "agent_id": aid,
            "agent_name": hostname,
            "manager_ip": manager_ip,
            "vm_ip": ip,
            "service_status": status_out,
            "wazuh_status": wazuh_status,
            "reused_registration": reused,
            "message": f"Host {ip} onboarded as agent {aid} ({hostname}). Check Grafana fleet dashboard.",
        }
    except Exception as exc:
        return {"success": False, "error": str(exc)}
