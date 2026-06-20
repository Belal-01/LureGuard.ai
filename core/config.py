"""Settings loaded from config/core.yaml (Core ML + DNAT only; agent uses opencode + .env)."""

import os
from pathlib import Path

import yaml
from pydantic import BaseModel
from pydantic_settings import BaseSettings


def _read_secret_file(name: str) -> str:
    path = Path(f"/run/secrets/{name}")
    if path.exists():
        return path.read_text(encoding="utf-8").strip()
    return ""


def ingest_token() -> str:
    return os.getenv("INGEST_TOKEN", "").strip() or _read_secret_file("ingest_token")


def ingest_allow_unauthenticated() -> bool:
    """When true, missing INGEST_TOKEN allows unauthenticated ingest (dev only)."""
    raw = os.getenv("INGEST_ALLOW_UNAUTHENTICATED", "").strip().lower()
    if raw in ("0", "false", "no"):
        return False
    if raw in ("1", "true", "yes"):
        return True
    # Default: allow only when no token is configured
    return not ingest_token()


def admin_token() -> str:
    return os.getenv("ADMIN_TOKEN", "").strip() or _read_secret_file("admin_token")


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
