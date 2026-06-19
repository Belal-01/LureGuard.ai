"""Consistent JSON serialization for MCP tool responses."""

from __future__ import annotations

import json
from typing import Any

from lureguard_mcp.wazuh_client import compact_json


def mcp_json(data: Any, *, compact: bool = False, max_len: int = 12000) -> str:
    if compact:
        return compact_json(data, max_len=max_len)
    return json.dumps(data, indent=2, default=str)
