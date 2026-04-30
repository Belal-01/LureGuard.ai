"""
Settings — loaded from /app/config/core.yaml via pydantic-settings.
All secrets injected from /run/secrets/* at runtime.
"""
from pathlib import Path
from pydantic import BaseModel
from pydantic_settings import BaseSettings
import yaml


class ThresholdsConfig(BaseModel):
    t1: float = 0.40
    t2: float = 0.70


class LLMConfig(BaseModel):
    provider: str = "disabled"   # ollama|openai|anthropic|openai_compatible|disabled
    model: str = ""
    base_url: str = ""
    timeout_seconds: int = 60
    max_tokens: int = 512


class CowrieProfileConfig(BaseModel):
    host: str
    port: int


class Settings(BaseSettings):
    # loaded from ENV (injected by Docker)
    config_path: str = "/app/config/core.yaml"

    # runtime state (mutable — updated via Admin API)
    thresholds: ThresholdsConfig = ThresholdsConfig()
    llm: LLMConfig = LLMConfig()
    cowrie_profiles: dict[str, CowrieProfileConfig] = {}
    window_seconds: int = 300
    tick_interval_seconds: int = 2
    dnat_ttl_minutes: int = 60

    def load_yaml(self) -> None:
        """Load settings from core.yaml."""
        path = Path(self.config_path)
        if not path.exists():
            return
        with open(path) as f:
            data = yaml.safe_load(f)
        if "thresholds" in data:
            self.thresholds = ThresholdsConfig(**data["thresholds"])
        if "llm" in data:
            self.llm = LLMConfig(**data["llm"])
        if "cowrie_profiles" in data:
            self.cowrie_profiles = {
                k: CowrieProfileConfig(**v)
                for k, v in data["cowrie_profiles"].items()
            }
        for key in ("window_seconds", "tick_interval_seconds", "dnat_ttl_minutes"):
            if key in data:
                setattr(self, key, data[key])


# Singleton — import this everywhere
settings = Settings()
settings.load_yaml()
