from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG = {
    "analysis": {
        "max_file_size_mb": 200,
        "max_string_file_size_mb": 50,
        "min_string_length": 5,
        "keep_extracted": True,
        "jobs": 1,
    },
    "paths": {
        "high_risk": [
            "/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin",
            "/lib/systemd", "/etc/systemd", "/etc/cron.d", "/etc/cron.daily",
            "/usr/lib/browser", "/opt", "/var/spool/cron",
        ]
    },
}


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def load_config(config_path: Path | None = None, keywords_path: Path | None = None) -> dict[str, Any]:
    root = Path(__file__).resolve().parents[2]
    config = DEFAULT_CONFIG
    config = deep_merge(config, load_yaml(root / "config" / "default.yaml"))
    if config_path:
        config = deep_merge(config, load_yaml(config_path))
    keywords = load_yaml(keywords_path or (root / "config" / "keywords.yaml"))
    config["keywords"] = keywords
    return config