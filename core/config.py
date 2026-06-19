"""Settings loaded from config/core.yaml (Core ML + DNAT only; agent uses opencode + .env)."""

from pathlib import Path

import yaml
from pydantic import BaseModel
from pydantic_settings import BaseSettings


class ThresholdsConfig(BaseModel):
    t1: float = 0.55
    t2: float = 0.85


class CowrieProfileConfig(BaseModel):
    host: str
    port: int


class Settings(BaseSettings):
    config_path: str = "/app/config/core.yaml"

    thresholds: ThresholdsConfig = ThresholdsConfig()
    cowrie_profiles: dict[str, CowrieProfileConfig] = {}
    window_seconds: int = 300
    dnat_ttl_minutes: int = 60
    min_attempts_for_alert: int = 8

    def load_yaml(self) -> None:
        path = Path(self.config_path)
        if not path.exists():
            return
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        if "thresholds" in data:
            self.thresholds = ThresholdsConfig(**data["thresholds"])
        if "cowrie_profiles" in data:
            self.cowrie_profiles = {
                k: CowrieProfileConfig(**v)
                for k, v in data["cowrie_profiles"].items()
            }
        for key in ("window_seconds", "dnat_ttl_minutes", "min_attempts_for_alert"):
            if key in data:
                setattr(self, key, data[key])
        if "policy" in data and isinstance(data["policy"], dict):
            if "min_attempts_for_alert" in data["policy"]:
                self.min_attempts_for_alert = int(data["policy"]["min_attempts_for_alert"])


settings = Settings()
settings.load_yaml()
