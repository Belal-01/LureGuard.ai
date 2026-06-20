"""
Wazuh integratord script — POST alert JSON to LureGuard /wazuh/event.

Configured in ossec.conf:
  <integration>
    <name>custom-lureguard</name>
    <hook_url>http://lureguard-core:8080/wazuh/event</hook_url>
    ...
  </integration>
"""

from __future__ import annotations

import json
import os
import sys

ERR_NO_REQUEST_MODULE = 1
ERR_BAD_ARGUMENTS = 2
ERR_FILE_NOT_FOUND = 6
ERR_INVALID_JSON = 7

try:
    import requests
except ModuleNotFoundError:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(ERR_NO_REQUEST_MODULE)

pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
LOG_FILE = f"{pwd}/logs/integrations.log"

ALERT_INDEX = 1
API_KEY_INDEX = 2
WEBHOOK_INDEX = 3

# Must match <group> in wazuh/ossec.conf integration block
_FORWARD_GROUPS = frozenset(
    {
        "sshd",
        "authentication_failed",
        "authentication_success",
        "authentication_failures",
        "invalid_login",
        "syscheck",
        "rootcheck",
        "lureguard_custom",
        "cowrie",
        "web",
        "apache",
        "nginx",
        "web-accesslog",
        "web-attack",
        "sql_injection",
        "xss",
        "scanner",
        "attack",
        "docker",
    }
)


def _debug(msg: str) -> None:
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as handle:
            handle.write(msg + "\n")
    except OSError:
        pass


def _should_forward(alert: dict) -> bool:
    groups = alert.get("rule", {}).get("groups", []) or []
    if isinstance(groups, str):
        groups = [g.strip() for g in groups.split(",") if g.strip()]
    return bool(_FORWARD_GROUPS.intersection(groups))


def _load_alert(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        _debug(f"# alert file missing: {path}")
        sys.exit(ERR_FILE_NOT_FOUND)
    except json.JSONDecodeError as exc:
        _debug(f"# invalid alert json: {exc}")
        sys.exit(ERR_INVALID_JSON)


def _normalize_alert(alert: dict) -> dict:
    """Ensure fields expected by LureGuard FastAPI model are always present."""
    normalized = dict(alert)
    normalized.setdefault("timestamp", "")
    normalized.setdefault("rule", {})
    normalized.setdefault("agent", {})
    normalized.setdefault("data", {})
    if normalized.get("full_log") is None:
        normalized["full_log"] = normalized.get("previous_output") or ""
    if not isinstance(normalized.get("rule"), dict):
        normalized["rule"] = {}
    if not isinstance(normalized.get("agent"), dict):
        normalized["agent"] = {}
    if not isinstance(normalized.get("data"), dict):
        normalized["data"] = {}
    return normalized


def _post_alert(alert: dict, webhook: str, api_key: str = "") -> None:
    headers = {"Content-Type": "application/json", "Accept-Charset": "UTF-8"}
    if api_key:
        headers["X-LureGuard-Token"] = api_key
    payload = _normalize_alert(alert)
    response = requests.post(webhook, json=payload, headers=headers, timeout=10)
    _debug(f"# POST {webhook} -> {response.status_code}")


def main(args: list[str]) -> None:
    if len(args) < 4:
        _debug("# ERROR: wrong arguments")
        sys.exit(ERR_BAD_ARGUMENTS)

    alert_path = args[ALERT_INDEX]
    # Single source of truth: INGEST_TOKEN env (from .env via docker-compose).
    # Falls back to the ossec.conf <api_key> arg for non-Docker setups.
    api_key = os.getenv("INGEST_TOKEN", "").strip()
    if not api_key and len(args) > API_KEY_INDEX:
        api_key = args[API_KEY_INDEX]
    webhook = args[WEBHOOK_INDEX]

    alert = _load_alert(alert_path)
    if not _should_forward(alert):
        return

    _post_alert(alert, webhook, api_key=api_key)


if __name__ == "__main__":
    main(sys.argv)
