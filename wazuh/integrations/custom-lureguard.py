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
import time

ERR_NO_REQUEST_MODULE = 1
ERR_BAD_ARGUMENTS = 2
ERR_FILE_NOT_FOUND = 6
ERR_INVALID_JSON = 7
ERR_DELIVERY_FAILED = 8

# Non-retryable: the request reached the server and it told us this is
# permanently wrong (bad token, bad payload). Retrying just wastes the
# integratord queue's time budget.
_PERMANENT_STATUS = {400, 401, 403, 404, 422}

# stdlib only. integratord fork/execs this file once per alert, so every
# top-level import is paid per event: `import requests` measured ~49ms in the
# manager's bundled interpreter versus ~8.5ms for bare startup, almost all of
# it urllib3 and its transitive ssl/email/charset imports (ING-7). urllib
# is already loaded by the interpreter and costs nothing extra.
import urllib.error
import urllib.request

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


class AlertDeliveryError(Exception):
    """Raised when an alert could not be delivered to LureGuard core.

    Caught by main() so the process exits with a distinct code instead of
    a bare traceback; catchable by any other caller that wants to
    dead-letter the alert instead of losing it.
    """


def _post_alert(
    alert: dict,
    webhook: str,
    api_key: str = "",
    max_attempts: int = 3,
    backoff_seconds: float = 0.25,
    timeout_seconds: float = 3.0,
) -> None:
    # Total worst-case budget must stay near the original single 10s call:
    # integratord runs this once per alert with a finite queue, so a longer
    # budget makes a slow core cause Wazuh itself to drop alerts (ING-3).
    #   3 attempts x 3s timeout + (0.25 + 0.5) backoff = ~9.75s.
    # Raising max_attempts or timeout_seconds trades ING-3 for ING-1 — don't,
    # without measuring integratord queue depth first.
    headers = {"Content-Type": "application/json", "Accept-Charset": "UTF-8"}
    if api_key:
        headers["X-LureGuard-Token"] = api_key
    payload = _normalize_alert(alert)
    body = json.dumps(payload).encode("utf-8")

    last_error: Exception | None = None
    for attempt in range(1, max_attempts + 1):
        req = urllib.request.Request(
            webhook, data=body, headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout_seconds) as response:
                status = response.status
            _debug(f"# POST {webhook} attempt {attempt}/{max_attempts} -> {status}")
            if 200 <= status < 300:
                return
            last_error = AlertDeliveryError(f"POST {webhook} -> {status}")
        except urllib.error.HTTPError as exc:
            # urllib raises on 4xx/5xx rather than returning them, so the
            # permanent-vs-retryable split lives here.
            detail = ""
            try:
                detail = exc.read().decode("utf-8", "replace")[:200]
            except Exception:  # noqa: BLE001 - body is best-effort context only
                pass
            _debug(f"# POST {webhook} attempt {attempt}/{max_attempts} -> {exc.code}")
            if exc.code in _PERMANENT_STATUS:
                # Wrong token / bad request — retrying is pointless, fail loud now.
                raise AlertDeliveryError(
                    f"POST {webhook} rejected with {exc.code} (non-retryable): {detail}"
                ) from exc
            last_error = AlertDeliveryError(f"POST {webhook} -> {exc.code}")
        except (urllib.error.URLError, OSError) as exc:
            _debug(f"# POST {webhook} attempt {attempt}/{max_attempts} raised: {exc}")
            last_error = exc

        if attempt < max_attempts:
            time.sleep(backoff_seconds * attempt)

    raise AlertDeliveryError(
        f"POST {webhook} failed after {max_attempts} attempts: {last_error}"
    ) from last_error


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

    try:
        _post_alert(alert, webhook, api_key=api_key)
    except AlertDeliveryError as exc:
        _debug(f"# ALERT LOST: {exc}")
        sys.exit(ERR_DELIVERY_FAILED)


if __name__ == "__main__":
    main(sys.argv)
