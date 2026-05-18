"""
Internal normalized event schema — the common format
that all modules work with after the Collector normalizes Wazuh alerts.
"""
import uuid
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class NormalizedEvent(BaseModel):
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    ts: datetime = Field(default_factory=datetime.utcnow)
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    channel: str                   # sshd | syscheck | rootcheck | cowrie
    event_type: str                # auth_failed | auth_success | fim_change | ...
    username: Optional[str] = None
    success: bool = False
    profile_id: Optional[str] = None   # dev-server | db-server | None
    wazuh_rule_id: int = 0
    wazuh_rule_level: int = 0
    wazuh_rule_description: Optional[str] = None
    agent_name: Optional[str] = None
    agent_id: Optional[str] = None
    agent_ip: Optional[str] = None
    location: Optional[str] = None
    ingestion_path: str = "wazuh"  # wazuh | direct
    syscheck_path: Optional[str] = None
    syscheck_event: Optional[str] = None
    syscheck_sha256_after: Optional[str] = None
    raw_ref: str = ""
