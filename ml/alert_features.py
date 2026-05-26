"""
Tabular features for Wazuh alert-level classification (multi-channel, not SSH-only).

Used to align Kaggle CSV rows and Hugging Face / JSON alerts into one feature schema.
"""
from __future__ import annotations

import json
import math
import re
from datetime import datetime, timezone
from typing import Any

import pandas as pd

# Fixed schema for multi-dataset alert triage (TP=1, FP=0).
ALERT_FEATURE_COLUMNS = [
    "rule_level",
    "rule_id",
    "decoder_hash",
    "firedtimes_log",
    "has_srcip",
    "has_srcuser",
    "has_dstip",
    "has_url",
    "has_syscheck",
    "is_sshd",
    "is_web",
    "is_syscheck",
    "is_rootcheck",
    "is_active_response",
    "is_ossec",
    "is_auth_failed",
    "is_auth_success",
    "decoder_sshd",
    "decoder_web",
    "decoder_syscheck",
    "full_log_len_log",
    "hour_sin",
    "hour_cos",
    "weekday",
]

_LABEL_CANDIDATES = (
    "label",
    "target",
    "y",
    "class",
    "is_attack",
    "is_malicious",
    "true_positive",
    "alert_label",
    "attack_label",
    "Label",
    "Target",
    "output",
)

_NORMAL_ATTACK_LABELS = {"normal", "benign"}

_POSITIVE_STRINGS = {
    "1",
    "true",
    "yes",
    "attack",
    "malicious",
    "tp",
    "true positive",
    "true_positive",
    "positive",
}

_NEGATIVE_STRINGS = {
    "0",
    "false",
    "no",
    "benign",
    "fp",
    "false positive",
    "false_positive",
    "negative",
}

_KAGGLE_COLUMN_ALIASES: dict[str, str] = {
    "rulelevel": "rule_level",
    "rule_level": "rule_level",
    "level": "rule_level",
    "ruleid": "rule_id",
    "rule_id": "rule_id",
    "rule.id": "rule_id",
    "firedtimes": "firedtimes",
    "srcip": "has_srcip",
    "has_srcip": "has_srcip",
    "srcuser": "has_srcuser",
    "has_srcuser": "has_srcuser",
}


def _norm_key(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def decoder_hash_value(decoder_name: str) -> float:
    text = (decoder_name or "unknown").strip().lower()
    return float(abs(hash(text)) % 10000) / 10000.0


def _parse_timestamp(timestamp: str) -> datetime | None:
    if not timestamp:
        return None
    text = str(timestamp).strip().replace("+0000", "+00:00")
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
    ):
        try:
            dt = datetime.strptime(text, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            continue
    return None


def _parse_hour(timestamp: str) -> int:
    dt = _parse_timestamp(timestamp)
    return dt.hour if dt else 0


def _parse_weekday(timestamp: str) -> int:
    dt = _parse_timestamp(timestamp)
    return float(dt.weekday()) if dt else 0.0


def _groups_list(alert: dict[str, Any]) -> list[str]:
    rule = alert.get("rule") or {}
    groups = rule.get("groups") if isinstance(rule, dict) else []
    if isinstance(groups, list):
        return [str(g).lower() for g in groups]
    return []


def _rule_int(alert: dict[str, Any]) -> tuple[int, int, float]:
    rule = alert.get("rule") or {}
    if not isinstance(rule, dict):
        return 0, 0, 0.0
    try:
        level = int(rule.get("level", 0))
    except (TypeError, ValueError):
        level = 0
    try:
        rule_id = int(rule.get("id", 0))
    except (TypeError, ValueError):
        rule_id = 0
    try:
        fired = float(rule.get("firedtimes", 0))
    except (TypeError, ValueError):
        fired = 0.0
    return level, rule_id, fired


def featurize_wazuh_alert(alert: dict[str, Any]) -> dict[str, float]:
    """Map one Wazuh alert dict (JSON) to ALERT_FEATURE_COLUMNS."""
    groups = _groups_list(alert)
    level, rule_id, fired = _rule_int(alert)
    data = alert.get("data") if isinstance(alert.get("data"), dict) else {}
    decoder = alert.get("decoder") if isinstance(alert.get("decoder"), dict) else {}
    decoder_name = str(decoder.get("name", "")).lower()
    parent = str(decoder.get("parent", "")).lower()
    full_log = str(alert.get("full_log") or "")
    full_lower = full_log.lower()
    location = str(alert.get("location") or "").lower()
    syscheck = alert.get("syscheck")

    hour = _parse_hour(str(alert.get("timestamp") or ""))
    hour_rad = 2.0 * math.pi * hour / 24.0

    has_srcip = bool(data.get("srcip") or data.get("src_ip"))
    has_srcuser = bool(data.get("srcuser") or data.get("dstuser"))
    has_dstip = bool(data.get("dstip"))
    has_url = bool(data.get("url"))

    is_sshd = "sshd" in groups or "sshd" in decoder_name or "sshd" in parent
    is_web = "web" in groups or "accesslog" in groups or "web-accesslog" in decoder_name
    is_syscheck = "syscheck" in groups or syscheck is not None
    is_rootcheck = "rootcheck" in groups
    is_active_response = "active_response" in groups or "active-responses" in location
    is_ossec = "ossec" in groups
    is_auth_failed = "authentication_failed" in groups or "invalid_login" in groups
    is_auth_success = "authentication_success" in groups

    decoder_key = decoder_name or parent or ""

    return {
        "rule_level": float(level),
        "rule_id": float(rule_id),
        "decoder_hash": decoder_hash_value(decoder_key),
        "firedtimes_log": float(math.log1p(max(fired, 0.0))),
        "has_srcip": 1.0 if has_srcip else 0.0,
        "has_srcuser": 1.0 if has_srcuser else 0.0,
        "has_dstip": 1.0 if has_dstip else 0.0,
        "has_url": 1.0 if has_url else 0.0,
        "has_syscheck": 1.0 if syscheck is not None else 0.0,
        "is_sshd": 1.0 if is_sshd else 0.0,
        "is_web": 1.0 if is_web else 0.0,
        "is_syscheck": 1.0 if is_syscheck else 0.0,
        "is_rootcheck": 1.0 if is_rootcheck else 0.0,
        "is_active_response": 1.0 if is_active_response else 0.0,
        "is_ossec": 1.0 if is_ossec else 0.0,
        "is_auth_failed": 1.0 if is_auth_failed else 0.0,
        "is_auth_success": 1.0 if is_auth_success else 0.0,
        "decoder_sshd": 1.0 if "sshd" in decoder_name or "sshd" in parent else 0.0,
        "decoder_web": 1.0 if "web" in decoder_name or "accesslog" in decoder_name else 0.0,
        "decoder_syscheck": 1.0 if "syscheck" in decoder_name else 0.0,
        "full_log_len_log": float(math.log1p(len(full_log))),
        "hour_sin": float(math.sin(hour_rad)),
        "hour_cos": float(math.cos(hour_rad)),
        "weekday": float(_parse_weekday(str(alert.get("timestamp") or ""))),
    }


def normalize_label(value: Any) -> int | None:
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return None
    if isinstance(value, (int, bool)):
        return 1 if int(value) == 1 else 0
    if isinstance(value, float):
        return 1 if value >= 0.5 else 0
    text = str(value).strip().lower()
    if text in _NORMAL_ATTACK_LABELS:
        return 0
    if text in _POSITIVE_STRINGS:
        return 1
    if text in _NEGATIVE_STRINGS:
        return 0
    # Multi-class attack names (dirb, wpscan, …) → malicious
    if text and text not in _NEGATIVE_STRINGS:
        return 1
    return None


def true_labeled_row_to_features(row: pd.Series) -> dict[str, float]:
    """Map ml/datasets/true_labeled_dataset.csv rows to ALERT_FEATURE_COLUMNS."""
    decoder = str(row.get("decoder_name", "")).lower()
    src_ip = str(row.get("src_ip", "")).lower()
    has_srcip = src_ip not in ("", "unknown", "nan", "none")

    try:
        rule_level = float(row.get("rule_level", 0))
    except (TypeError, ValueError):
        rule_level = 0.0
    try:
        rule_id = float(row.get("rule_id", 0))
    except (TypeError, ValueError):
        rule_id = 0.0

    is_web = "web" in decoder or "accesslog" in decoder
    is_sshd = decoder == "sshd" or "sshd" in decoder

    return {
        "rule_level": rule_level,
        "rule_id": rule_id,
        "decoder_hash": decoder_hash_value(decoder),
        "firedtimes_log": 0.0,
        "has_srcip": 1.0 if has_srcip else 0.0,
        "has_srcuser": 0.0,
        "has_dstip": 0.0,
        "has_url": 1.0 if is_web else 0.0,
        "has_syscheck": 0.0,
        "is_sshd": 1.0 if is_sshd else 0.0,
        "is_web": 1.0 if is_web else 0.0,
        "is_syscheck": 0.0,
        "is_rootcheck": 0.0,
        "is_active_response": 0.0,
        "is_ossec": 1.0 if decoder in ("ossec", "freshclam") else 0.0,
        "is_auth_failed": 0.0,
        "is_auth_success": 0.0,
        "decoder_sshd": 1.0 if is_sshd else 0.0,
        "decoder_web": 1.0 if is_web else 0.0,
        "decoder_syscheck": 0.0,
        "full_log_len_log": 0.0,
        "hour_sin": 0.0,
        "hour_cos": 1.0,
        "weekday": 0.0,
    }


def detect_label_column(df: pd.DataFrame) -> str | None:
    for col in _LABEL_CANDIDATES:
        if col in df.columns:
            return col
    for col in df.columns:
        if _norm_key(col) in {_norm_key(c) for c in _LABEL_CANDIDATES}:
            return col
        if "label" in _norm_key(col) or col.lower().endswith("_label"):
            return col
    return None


def kaggle_row_to_features(row: pd.Series) -> dict[str, float]:
    """
    Map a Kaggle feature CSV row into ALERT_FEATURE_COLUMNS when columns differ.
    Uses native columns when present; otherwise derives flags from common names.
    """
    mapping = {_norm_key(c): c for c in row.index}

    def get_num(*keys: str, default: float = 0.0) -> float:
        for key in keys:
            col = mapping.get(_norm_key(key))
            if col is not None and pd.notna(row[col]):
                try:
                    return float(row[col])
                except (TypeError, ValueError):
                    pass
        return default

    def get_flag(*keys: str) -> float:
        for key in keys:
            col = mapping.get(_norm_key(key))
            if col is None or pd.isna(row[col]):
                continue
            val = row[col]
            if isinstance(val, (int, float)):
                return 1.0 if float(val) != 0.0 else 0.0
            text = str(val).strip().lower()
            if text in ("1", "true", "yes"):
                return 1.0
        return 0.0

    # If CSV already uses our schema, pass through directly.
    if all(c in row.index for c in ALERT_FEATURE_COLUMNS):
        return {c: float(row[c]) for c in ALERT_FEATURE_COLUMNS}

    level = get_num("rule_level", "rulelevel", "level", default=0.0)
    rule_id = get_num("rule_id", "ruleid", "rule.id", default=0.0)
    fired = get_num("firedtimes", "fired_times", default=0.0)

    decoder_col = mapping.get(_norm_key("decoder_name")) or mapping.get(_norm_key("decoder"))
    decoder_text = str(row[decoder_col]) if decoder_col is not None and pd.notna(row[decoder_col]) else ""

    return {
        "rule_level": level,
        "rule_id": rule_id,
        "decoder_hash": decoder_hash_value(decoder_text),
        "firedtimes_log": float(math.log1p(max(fired, 0.0))),
        "has_srcip": get_flag("has_srcip", "srcip", "src_ip"),
        "has_srcuser": get_flag("has_srcuser", "srcuser", "username"),
        "has_dstip": get_flag("has_dstip", "dstip"),
        "has_url": get_flag("has_url", "url"),
        "has_syscheck": get_flag("has_syscheck", "syscheck"),
        "is_sshd": get_flag("is_sshd", "sshd", "group_sshd"),
        "is_web": get_flag("is_web", "web", "group_web"),
        "is_syscheck": get_flag("is_syscheck", "syscheck"),
        "is_rootcheck": get_flag("is_rootcheck", "rootcheck"),
        "is_active_response": get_flag("is_active_response", "active_response"),
        "is_ossec": get_flag("is_ossec", "ossec"),
        "is_auth_failed": get_flag("is_auth_failed", "authentication_failed"),
        "is_auth_success": get_flag("is_auth_success", "authentication_success"),
        "decoder_sshd": get_flag("decoder_sshd"),
        "decoder_web": get_flag("decoder_web"),
        "decoder_syscheck": get_flag("decoder_syscheck"),
        "full_log_len_log": get_num("full_log_len_log", "full_log_len", default=0.0),
        "hour_sin": get_num("hour_sin", default=0.0),
        "hour_cos": get_num("hour_cos", default=0.0),
        "weekday": get_num("weekday", default=0.0),
    }


def parse_alert_json(text: str) -> dict[str, Any]:
    return json.loads(text)


def featurize_normalized_event(event: Any) -> dict[str, float]:
    """Build alert features from a live NormalizedEvent (no synthetic data)."""
    channel = (getattr(event, "channel", None) or "").lower()
    event_type = (getattr(event, "event_type", None) or "").lower()
    location = (getattr(event, "location", None) or "").lower()
    src_ip = getattr(event, "src_ip", None)

    is_sshd = channel == "sshd" or "sshd" in event_type
    is_web = channel in ("unknown",) and "web" in (getattr(event, "raw_ref", "") or "").lower()
    is_syscheck = channel == "syscheck"
    is_rootcheck = channel == "rootcheck"
    is_auth_failed = event_type == "auth_failed"
    is_auth_success = event_type == "auth_success"
    has_srcip = bool(src_ip)

    return {
        "rule_level": float(getattr(event, "wazuh_rule_level", 0) or 0),
        "rule_id": float(getattr(event, "wazuh_rule_id", 0) or 0),
        "decoder_hash": decoder_hash_value(channel or "unknown"),
        "firedtimes_log": 0.0,
        "has_srcip": 1.0 if has_srcip else 0.0,
        "has_srcuser": 1.0 if getattr(event, "username", None) else 0.0,
        "has_dstip": 0.0,
        "has_url": 0.0,
        "has_syscheck": 1.0 if is_syscheck else 0.0,
        "is_sshd": 1.0 if is_sshd else 0.0,
        "is_web": 1.0 if is_web else 0.0,
        "is_syscheck": 1.0 if is_syscheck else 0.0,
        "is_rootcheck": 1.0 if is_rootcheck else 0.0,
        "is_active_response": 1.0 if "active-response" in location else 0.0,
        "is_ossec": 1.0 if channel == "unknown" and "ossec" in location else 0.0,
        "is_auth_failed": 1.0 if is_auth_failed else 0.0,
        "is_auth_success": 1.0 if is_auth_success else 0.0,
        "decoder_sshd": 1.0 if is_sshd else 0.0,
        "decoder_web": 1.0 if is_web else 0.0,
        "decoder_syscheck": 1.0 if is_syscheck else 0.0,
        "full_log_len_log": float(math.log1p(len(getattr(event, "raw_ref", "") or ""))),
        "hour_sin": 0.0,
        "hour_cos": 1.0,
        "weekday": 0.0,
    }


def rows_to_frame(rows: list[dict[str, float]], labels: list[int], sources: list[str]) -> pd.DataFrame:
    df = pd.DataFrame(rows, columns=ALERT_FEATURE_COLUMNS)
    df["target"] = labels
    df["source"] = sources
    return df
