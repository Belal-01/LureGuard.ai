from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


@dataclass
class WhitelistEntry:
    ip: Optional[ipaddress._BaseAddress]
    network: Optional[ipaddress._BaseNetwork]
    user: Optional[str]
    expires_at: Optional[datetime]


class WhitelistChecker:
    def __init__(self, config_path: Path, reload_interval_seconds: int = 30):
        self.config_path = Path(config_path)
        self.reload_interval_seconds = reload_interval_seconds
        self.entries: list[WhitelistEntry] = []
        self._last_loaded_mtime: float | None = None
        self._load()

    def _parse_iso_ts(self, raw: str | None) -> Optional[datetime]:
        if not raw:
            return None
        value = raw.strip()
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(value)
        except ValueError:
            return None
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    def _load(self) -> None:
        if not self.config_path.exists():
            self.entries = []
            self._last_loaded_mtime = None
            return

        mtime = self.config_path.stat().st_mtime
        if self._last_loaded_mtime is not None and mtime == self._last_loaded_mtime:
            return

        payload = json.loads(self.config_path.read_text(encoding="utf-8-sig"))
        parsed: list[WhitelistEntry] = []
        for raw_entry in payload.get("entries", []):
            ip_obj = None
            net_obj = None
            raw_ip = raw_entry.get("ip")
            raw_cidr = raw_entry.get("cidr")
            if raw_ip:
                try:
                    ip_obj = ipaddress.ip_address(raw_ip)
                except ValueError:
                    continue
            if raw_cidr:
                try:
                    net_obj = ipaddress.ip_network(raw_cidr, strict=False)
                except ValueError:
                    continue
            if ip_obj is None and net_obj is None:
                continue

            parsed.append(
                WhitelistEntry(
                    ip=ip_obj,
                    network=net_obj,
                    user=raw_entry.get("user"),
                    expires_at=self._parse_iso_ts(raw_entry.get("expires_at")),
                )
            )

        self.entries = parsed
        self._last_loaded_mtime = mtime

    def _refresh_if_needed(self) -> None:
        self._load()

    def is_whitelisted(self, src_ip: str | None, src_user: str | None, event_ts: datetime) -> bool:
        self._refresh_if_needed()

        if not src_ip:
            return False
        try:
            ip_obj = ipaddress.ip_address(src_ip)
        except ValueError:
            return False

        for entry in self.entries:
            if entry.expires_at is not None and event_ts > entry.expires_at:
                continue
            if entry.user and src_user and entry.user != src_user:
                continue
            if entry.user and not src_user:
                continue

            ip_match = entry.ip is not None and ip_obj == entry.ip
            cidr_match = entry.network is not None and ip_obj in entry.network
            if ip_match or cidr_match:
                return True

        return False
