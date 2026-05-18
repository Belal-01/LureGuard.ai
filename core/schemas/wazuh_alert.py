"""
Pydantic model for incoming Wazuh integratord alert JSON.
Tolerant of optional fields and extra keys from Wazuh.
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class WazuhAlert(BaseModel):
    model_config = ConfigDict(extra="ignore")

    timestamp: str = ""
    rule: dict[str, Any] = Field(default_factory=dict)
    agent: dict[str, Any] = Field(default_factory=dict)
    data: dict[str, Any] = Field(default_factory=dict)
    syscheck: dict[str, Any] | None = None
    location: str = ""
    full_log: str = ""

    @field_validator("rule", "agent", "data", mode="before")
    @classmethod
    def _coerce_dict(cls, value: Any) -> dict[str, Any]:
        if value is None:
            return {}
        if isinstance(value, dict):
            return value
        return {}

    @field_validator("full_log", "location", mode="before")
    @classmethod
    def _coerce_str_field(cls, value: Any) -> str:
        if value is None:
            return ""
        return str(value)

    @field_validator("timestamp", mode="before")
    @classmethod
    def _coerce_timestamp(cls, value: Any) -> str:
        if value is None:
            return ""
        return str(value)

    @property
    def rule_groups(self) -> list[str]:
        groups = self.rule.get("groups")
        if isinstance(groups, list):
            return [str(g) for g in groups]
        return []

    @property
    def rule_id(self) -> int:
        raw = self.rule.get("id", 0)
        try:
            return int(raw)
        except (TypeError, ValueError):
            return 0

    @property
    def rule_level(self) -> int:
        raw = self.rule.get("level", 0)
        try:
            return int(raw)
        except (TypeError, ValueError):
            return 0

    @property
    def rule_description(self) -> str:
        return str(self.rule.get("description", "") or "")

    @property
    def agent_name(self) -> str:
        return str(self.agent.get("name", "") or "")

    @property
    def agent_id_str(self) -> str:
        return str(self.agent.get("id", "") or "")

    @property
    def agent_ip(self) -> str:
        return str(self.agent.get("ip", "") or "")
