from pydantic import BaseModel

class WazuhAlert(BaseModel):
    timestamp: str
    rule: dict  # يحتوي على id و groups
    agent: dict # يحتوي على name و id
    data: dict  # الحقول الجوهرية: srcip, srcuser, status
    full_log: str
