"""Wazuh Manager REST API client."""

from __future__ import annotations

import json
from typing import Any

import httpx

from lureguard_mcp.config import (
    wazuh_api_password,
    wazuh_api_url,
    wazuh_api_user,
    wazuh_agent_register_ip,
    wazuh_verify_ssl,
)


class WazuhClient:
    def __init__(self) -> None:
        self.base = wazuh_api_url()
        self.user = wazuh_api_user()
        self.password = wazuh_api_password()
        self.verify = wazuh_verify_ssl()
        self._token: str | None = None

    def _authenticate(self, client: httpx.Client) -> str:
        resp = client.post(
            f"{self.base}/security/user/authenticate",
            auth=(self.user, self.password),
        )
        resp.raise_for_status()
        data = resp.json()
        token = data.get("data", {}).get("token")
        if not token:
            raise RuntimeError("Wazuh API authentication failed: no token returned")
        self._token = token
        return token

    def _headers(self, client: httpx.Client) -> dict[str, str]:
        if not self._token:
            self._authenticate(client)
        return {"Authorization": f"Bearer {self._token}"}

    def _request(self, method: str, path: str, **kwargs: Any) -> dict:
        with httpx.Client(verify=self.verify, timeout=30.0) as client:
            headers = self._headers(client)
            resp = client.request(method, f"{self.base}{path}", headers=headers, **kwargs)
            if resp.status_code == 401:
                self._token = None
                headers = self._headers(client)
                resp = client.request(method, f"{self.base}{path}", headers=headers, **kwargs)
            resp.raise_for_status()
            return resp.json()

    def list_agents(self, *, status: str | None = None, limit: int = 500) -> dict:
        params: dict[str, Any] = {"limit": limit}
        if status:
            params["status"] = status
        return self._request("GET", "/agents", params=params)

    def get_agent(self, agent_id: str) -> dict:
        return self._request("GET", f"/agents/{agent_id}")

    def get_agent_processes(self, agent_id: str, limit: int = 50, offset: int = 0) -> dict:
        return self._request(
            "GET",
            f"/syscollector/{agent_id}/processes",
            params={"limit": limit, "offset": offset},
        )

    def get_agent_ports(self, agent_id: str, limit: int = 50, offset: int = 0) -> dict:
        return self._request(
            "GET",
            f"/syscollector/{agent_id}/ports",
            params={"limit": limit, "offset": offset},
        )

    def get_syscheck_results(self, agent_id: str, limit: int = 1) -> dict:
        return self._request("GET", f"/syscheck/{agent_id}", params={"limit": limit})

    def get_rootcheck_results(self, agent_id: str, limit: int = 1) -> dict:
        return self._request("GET", f"/rootcheck/{agent_id}", params={"limit": limit})

    def list_rules(self, limit: int = 500) -> dict:
        return self._request("GET", "/rules", params={"limit": limit})

    def get_agent_packages(self, agent_id: str, limit: int = 50, offset: int = 0) -> dict:
        return self._request(
            "GET",
            f"/syscollector/{agent_id}/packages",
            params={"limit": limit, "offset": offset},
        )

    def get_agent_os(self, agent_id: str) -> dict:
        return self._request("GET", f"/syscollector/{agent_id}/os")

    def get_rules_summary(self, limit: int = 20) -> dict:
        return self._request("GET", "/rules", params={"limit": limit, "sort": "-level"})

    def get_manager_status(self) -> dict:
        return self._request("GET", "/manager/status")

    def restart_agent(self, agent_id: str) -> dict:
        return self._request("PUT", f"/agents/{agent_id}/restart")

    def get_agent_key(self, agent_id: str) -> str:
        resp = self._request("GET", f"/agents/{agent_id}/key")
        items = resp.get("data", {}).get("affected_items", [])
        if not items:
            raise RuntimeError(f"No key returned for agent {agent_id}")
        key = items[0].get("key", "")
        if not key:
            raise RuntimeError(f"Empty key for agent {agent_id}")
        return key

    def find_agent(self, *, name: str | None = None, ip: str | None = None) -> dict | None:
        resp = self.list_agents(limit=500)
        for agent in resp.get("data", {}).get("affected_items", []):
            if agent.get("id") == "000":
                continue
            if name and agent.get("name") == name:
                return agent
            if ip and agent.get("ip") == ip:
                return agent
        return None

    def register_agent(self, name: str, register_ip: str | None = None) -> dict[str, str | bool]:
        """Create agent on manager or reuse existing match by name. Returns id, key, reused."""
        reg_ip = register_ip or wazuh_agent_register_ip()
        existing = self.find_agent(name=name)
        if existing:
            aid = str(existing["id"])
            return {
                "id": aid,
                "key": self.get_agent_key(aid),
                "reused": True,
            }
        try:
            resp = self._request("POST", "/agents", json={"name": name, "ip": reg_ip})
        except httpx.HTTPStatusError as exc:
            detail = ""
            try:
                detail = exc.response.json().get("detail", "")
            except Exception:
                detail = str(exc)
            if "same IP" in detail or "same name" in detail.lower():
                existing = self.find_agent(name=name)
                if existing:
                    aid = str(existing["id"])
                    return {
                        "id": aid,
                        "key": self.get_agent_key(aid),
                        "reused": True,
                    }
            raise RuntimeError(f"Wazuh agent registration failed: {detail or exc}") from exc
        data = resp.get("data", {})
        aid = str(data.get("id", ""))
        key = data.get("key", "")
        if not aid or not key:
            raise RuntimeError("Wazuh API returned empty agent id or key")
        return {"id": aid, "key": key, "reused": False}

    def health_check(self) -> tuple[bool, str]:
        try:
            self.get_manager_status()
            return True, "ok"
        except Exception as exc:
            return False, str(exc)


def compact_json(data: Any, *, max_len: int = 12000) -> str:
    text = json.dumps(data, indent=2, default=str)
    if len(text) > max_len:
        return text[: max_len - 80] + "\n... (truncated)"
    return text
