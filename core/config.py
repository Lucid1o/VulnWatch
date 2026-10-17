"""
core/config.py
==============
Configuration loader for VulnWatch.
Reads config.yaml with sensible fallbacks.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    yaml = None  # Fallback to simple parser if PyYAML is absent

CONFIG_PATH = Path("config.yaml")

DEFAULT_CONFIG: dict[str, Any] = {
    "app_name": "VulnWatch",
    "team_mode": False,
}


def load_config(config_path: Path | str | None = None) -> dict[str, Any]:
    """
    Load configuration from YAML file or return defaults.

    Parameters
    ----------
    config_path:
        Optional path to configuration file. Defaults to 'config.yaml'.

    Returns
    -------
    dict[str, Any]
        Configuration key-value dictionary.
    """
    target = Path(config_path) if config_path else CONFIG_PATH
    if not target.exists():
        return dict(DEFAULT_CONFIG)

    try:
        content = target.read_text(encoding="utf-8")
        if yaml is not None:
            data = yaml.safe_load(content)
            if isinstance(data, dict):
                merged = dict(DEFAULT_CONFIG)
                merged.update(data)
                return merged
        else:
            # Simple text parsing fallback for team_mode
            merged = dict(DEFAULT_CONFIG)
            for line in content.splitlines():
                stripped = line.strip()
                if stripped.startswith("team_mode:"):
                    val = stripped.split(":", 1)[1].strip().lower()
                    merged["team_mode"] = val in ("true", "1", "yes")
            return merged
    except Exception:
        pass

    return dict(DEFAULT_CONFIG)


def is_team_mode_enabled(config: dict[str, Any] | None = None) -> bool:
    """Return True if team_mode is enabled in the configuration."""
    cfg = config if config is not None else load_config()
    return bool(cfg.get("team_mode", False))
