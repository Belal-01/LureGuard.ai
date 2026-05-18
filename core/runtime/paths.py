from __future__ import annotations

import os
from pathlib import Path


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def models_dir() -> Path:
    if env := os.getenv("MODELS_DIR"):
        return Path(env)
    docker_path = Path("/app/models")
    if docker_path.exists():
        return docker_path
    return repo_root() / "ml" / "models"


def whitelist_path() -> Path:
    if env := os.getenv("WHITELIST_PATH"):
        return Path(env)
    config_file = Path(os.getenv("CONFIG_PATH", repo_root() / "config" / "core.yaml"))
    candidate = config_file.parent / "whitelist.json"
    if candidate.exists():
        return candidate
    return models_dir() / "whitelist.json"
