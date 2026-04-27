"""PhishHawk configuration system.

Loads settings from (lowest to highest priority):
  1. Built-in defaults
  2. /etc/phishhawk/config.toml  (system)
  3. ~/.phishhawk/config.toml    (user)
  4. Environment variables prefixed with PHISHHAWK_

Environment variable mapping:
  PHISHHAWK_HATCHERY_ENDPOINT  → hatchery.endpoint
  PHISHHAWK_DNS_TIMEOUT        → dns.timeout
  PHISHHAWK_SCORING_WEIGHT_AUTH  → scoring.weights.authentication
  PHISHHAWK_SCORING_WEIGHT_HDR  → scoring.weights.headers
  PHISHHAWK_SCORING_WEIGHT_URL  → scoring.weights.urls
  PHISHHAWK_SCORING_WEIGHT_ATT  → scoring.weights.attachments
  PHISHHAWK_SCORING_WEIGHT_IOC  → scoring.weights.iocs
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:
        tomllib = None  # type: ignore[assignment]


import copy

_DEFAULTS = {
    "hatchery": {"endpoint": "http://localhost:8000/api", "timeout": 30},
    "dns": {"timeout": 10, "retries": 2},
    "scoring": {
        "weights": {
            "authentication": 30,
            "headers": 15,
            "urls": 25,
            "attachments": 15,
            "iocs": 15,
        },
    },
    "output": {"terminal_width": 100, "color": True},
    "dkim": {"selectors": ["default", "google", "selector1", "selector2"]},
}

_ENV_MAP = {
    "PHISHHAWK_HATCHERY_ENDPOINT": ("hatchery", "endpoint"),
    "PHISHHAWK_DNS_TIMEOUT": ("dns", "timeout"),
    "PHISHHAWK_SCORING_WEIGHT_AUTH": ("scoring", "weights", "authentication"),
    "PHISHHAWK_SCORING_WEIGHT_HDR": ("scoring", "weights", "headers"),
    "PHISHHAWK_SCORING_WEIGHT_URL": ("scoring", "weights", "urls"),
    "PHISHHAWK_SCORING_WEIGHT_ATT": ("scoring", "weights", "attachments"),
    "PHISHHAWK_SCORING_WEIGHT_IOC": ("scoring", "weights", "iocs"),
}

_DEFAULT_DKIM_SELECTORS = ["default", "google", "selector1", "selector2"]


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base (override wins)."""
    result = base.copy()
    for key, val in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(val, dict):
            result[key] = _deep_merge(result[key], val)
        else:
            result[key] = val
    return result


def _load_toml(path: Path) -> dict:
    """Load a TOML file, returning {} on failure."""
    if tomllib is None:
        return {}
    if not path.is_file():
        return {}
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except Exception:
        return {}


def _apply_env(config: dict) -> dict:
    """Override config values from environment variables."""
    for env_key, path in _ENV_MAP.items():
        val = os.environ.get(env_key)
        if val is None:
            continue
        try:
            typed: int | float | str = int(val)
        except ValueError:
            try:
                typed = float(val)
            except ValueError:
                typed = val
        d = config
        for part in path[:-1]:
            d = d.setdefault(part, {})
        d[path[-1]] = typed
    return config


@dataclass
class PhishHawkConfig:
    """Resolved configuration, accessible as attributes."""

    hatchery_endpoint: str = "http://localhost:8000/api"
    hatchery_timeout: int = 30
    dns_timeout: int = 10
    dns_retries: int = 2
    weight_authentication: int = 30
    weight_headers: int = 15
    weight_urls: int = 25
    weight_attachments: int = 15
    weight_iocs: int = 15
    terminal_width: int = 100
    color: bool = True
    dkim_selectors: list[str] = field(default_factory=lambda: list(_DEFAULT_DKIM_SELECTORS))

    @classmethod
    def load(cls, user_path: Path | None = None) -> PhishHawkConfig:
        """Load config from defaults → system → user → env."""
        config: dict = copy.deepcopy(_DEFAULTS)
        config = _deep_merge(config, _DEFAULTS)

        # System config
        sys_path = Path("/etc/phishhawk/config.toml")
        config = _deep_merge(config, _load_toml(sys_path))

        # User config
        cfg_path = user_path or Path.home() / ".phishhawk" / "config.toml"
        config = _deep_merge(config, _load_toml(cfg_path))

        # Environment overrides
        config = _apply_env(config)

        # Flatten into dataclass
        h = config.get("hatchery", {})
        d = config.get("dns", {})
        s = config.get("scoring", {})
        w = s.get("weights", {})
        o = config.get("output", {})
        dk = config.get("dkim", {})

        return cls(
            hatchery_endpoint=h.get("endpoint", "http://localhost:8000/api"),
            hatchery_timeout=h.get("timeout", 30),
            dns_timeout=d.get("timeout", 10),
            dns_retries=d.get("retries", 2),
            weight_authentication=w.get("authentication", 30),
            weight_headers=w.get("headers", 15),
            weight_urls=w.get("urls", 25),
            weight_attachments=w.get("attachments", 15),
            weight_iocs=w.get("iocs", 15),
            terminal_width=o.get("terminal_width", 100),
            color=o.get("color", True),
            dkim_selectors=dk.get("selectors", list(_DEFAULT_DKIM_SELECTORS)),
        )


# Singleton — loaded once per process
_config: PhishHawkConfig | None = None


def get_config() -> PhishHawkConfig:
    """Get the global config (lazy-loaded)."""
    global _config
    if _config is None:
        _config = PhishHawkConfig.load()
    return _config


def reload_config(user_path: Path | None = None) -> PhishHawkConfig:
    """Force reload config (e.g., after editing config file)."""
    global _config
    _config = PhishHawkConfig.load(user_path)
    return _config
