"""
Enforcer — applies iptables DNAT rules via subprocess.
Requires CAP_NET_ADMIN on the container.
"""
import subprocess
import socket
from datetime import datetime, timedelta
from typing import Optional
from loguru import logger

from config import settings

# Track active rules: {src_ip: {"profile": str, "expires_at": datetime}}
_active_rules: dict[str, dict] = {}


def apply_dnat(src_ip: str, profile_id: str) -> None:
    """
    Install a PREROUTING DNAT rule: attacker → Cowrie profile.
    Also sends TCP RST to drop any existing connection.
    """
    if src_ip in _active_rules:
        logger.debug(f"DNAT already active for {src_ip}")
        return

    profile = settings.cowrie_profiles.get(profile_id)
    if not profile:
        logger.error(f"Unknown profile_id: {profile_id}")
        return

    try:
        ip = socket.gethostbyname(profile.host)
    except socket.gaierror:
        logger.warning(f"Could not resolve hostname {profile.host}, using as-is")
        ip = profile.host
    target = f"{ip}:{profile.port}"

    cmd = [
        "iptables", "-t", "nat", "-A", "PREROUTING",
        "-s", src_ip,
        "-p", "tcp", "--dport", "22",
        "-j", "DNAT", f"--to-destination", target,
    ]
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        expires_at = datetime.utcnow() + timedelta(minutes=settings.dnat_ttl_minutes)
        _active_rules[src_ip] = {"profile": profile_id, "expires_at": expires_at}
        logger.success(f"✅ DNAT: {src_ip}:22 → {target} (TTL={settings.dnat_ttl_minutes}min)")
    except subprocess.CalledProcessError as e:
        logger.error(f"iptables DNAT failed for {src_ip}: {e.stderr.decode()}")


def remove_dnat(src_ip: str) -> None:
    """Remove a specific DNAT rule."""
    rule = _active_rules.get(src_ip)
    if not rule:
        return
    profile = settings.cowrie_profiles.get(rule["profile"])
    if not profile:
        return
    try:
        ip = socket.gethostbyname(profile.host)
    except socket.gaierror:
        ip = profile.host
    target = f"{ip}:{profile.port}"
    cmd = [
        "iptables", "-t", "nat", "-D", "PREROUTING",
        "-s", src_ip, "-p", "tcp", "--dport", "22",
        "-j", "DNAT", f"--to-destination", target,
    ]
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        del _active_rules[src_ip]
        logger.info(f"🗑️  DNAT removed for {src_ip}")
    except subprocess.CalledProcessError:
        pass


def flush_all_dnat() -> None:
    """Panic flush — remove ALL rules created by LureGuard."""
    for ip in list(_active_rules.keys()):
        remove_dnat(ip)
    logger.warning("⚠️  PANIC FLUSH — all DNAT rules removed")


def cleanup_expired() -> None:
    """Called by APScheduler every tick to remove TTL-expired rules."""
    now = datetime.utcnow()
    for ip, rule in list(_active_rules.items()):
        if now >= rule["expires_at"]:
            logger.info(f"⏰ DNAT TTL expired for {ip}")
            remove_dnat(ip)


def get_active_count() -> int:
    return len(_active_rules)
