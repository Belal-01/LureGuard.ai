"""
Pydantic model for incoming Wazuh integratord alert JSON.
"""
from pydantic import BaseModel, Field
from typing import Optional


class WazuhRule(BaseModel):
    id: int
    level: int = 0
    description: str = ""
    groups: list[str] = []


class WazuhAgent(BaseModel):
    name: str = "unknown"
    id: str = "000"


class WazuhData(BaseModel):
    srcip: Optional[str] = None
    srcuser: Optional[str] = None
    status: Optional[str] = None


class WazuhSyscheck(BaseModel):
    path: Optional[str] = None
    event: Optional[str] = None      # added | modified | deleted
    sha256_after: Optional[str] = None


class WazuhAlert(BaseModel):
    """Full Wazuh alert payload (integratord format)."""
    timestamp: str
    rule: WazuhRule
    agent: WazuhAgent = WazuhAgent()
    data: WazuhData = WazuhData()
    syscheck: Optional[WazuhSyscheck] = None
    full_log: str = ""
