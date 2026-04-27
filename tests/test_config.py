"""Tests for config module."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

from phishhawk.config import (
    PhishHawkConfig,
    _apply_env,
    _deep_merge,
    _load_toml,
    get_config,
    reload_config,
)


def test_deep_merge_basic() -> None:
    base = {"a": 1, "b": {"c": 2}}
    override = {"b": {"d": 3}, "e": 4}
    result = _deep_merge(base, override)
    assert result == {"a": 1, "b": {"c": 2, "d": 3}, "e": 4}


def test_deep_merge_override() -> None:
    base = {"a": {"x": 1}}
    override = {"a": {"x": 99}}
    result = _deep_merge(base, override)
    assert result["a"]["x"] == 99


def test_load_toml_nonexistent() -> None:
    assert _load_toml(Path("/nonexistent/file.toml")) == {}


def test_load_toml_valid(tmp_path: Path) -> None:
    cfg = tmp_path / "config.toml"
    cfg.write_text('[hatchery]\nendpoint = "http://custom:9999/api"\n')
    result = _load_toml(cfg)
    assert result["hatchery"]["endpoint"] == "http://custom:9999/api"


def test_apply_env() -> None:
    config = {
        "hatchery": {"endpoint": "default", "timeout": 30},
        "dns": {"timeout": 10},
        "scoring": {"weights": {"authentication": 30}},
    }
    with patch.dict(os.environ, {"PHISHHAWK_HATCHERY_ENDPOINT": "http://env:8080/api", "PHISHHAWK_DNS_TIMEOUT": "20"}):
        result = _apply_env(config)
        assert result["hatchery"]["endpoint"] == "http://env:8080/api"
        assert result["dns"]["timeout"] == 20


def test_config_defaults() -> None:
    cfg = PhishHawkConfig.load(user_path=Path("/nonexistent"))
    assert cfg.hatchery_endpoint == "http://localhost:8000/api"
    assert cfg.dns_timeout == 10
    assert cfg.weight_authentication == 30
    assert cfg.color is True


def test_config_user_override(tmp_path: Path) -> None:
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text('[hatchery]\nendpoint = "http://custom:9999"\ntimeout = 60\n')
    cfg = PhishHawkConfig.load(user_path=cfg_file)
    assert cfg.hatchery_endpoint == "http://custom:9999"
    assert cfg.hatchery_timeout == 60


def test_config_env_override() -> None:
    # Save and remove any existing env var
    saved = os.environ.pop("PHISHHAWK_DNS_TIMEOUT", None)
    os.environ["PHISHHAWK_DNS_TIMEOUT"] = "42"
    try:
        cfg = PhishHawkConfig.load(user_path=Path("/nonexistent"))
        assert cfg.dns_timeout == 42
    finally:
        os.environ.pop("PHISHHAWK_DNS_TIMEOUT", None)
        if saved is not None:
            os.environ["PHISHHAWK_DNS_TIMEOUT"] = saved


def test_get_config_singleton() -> None:
    # Reset singleton
    import phishhawk.config as _cfg
    _cfg._config = None
    c1 = get_config()
    c2 = get_config()
    assert c1 is c2


def test_reload_config(tmp_path: Path) -> None:
    import phishhawk.config as _cfg
    # Clean env and singleton
    saved_env = {}
    for k in list(os.environ):
        if k.startswith("PHISHHAWK_"):
            saved_env[k] = os.environ.pop(k)
    _cfg._config = None
    c1 = reload_config(user_path=Path("/nonexistent"))
    assert c1.dns_timeout == 10, f"Expected 10, got {c1.dns_timeout}, env={os.environ.get('PHISHHAWK_DNS_TIMEOUT')}"
    os.environ["PHISHHAWK_DNS_TIMEOUT"] = "99"
    c2 = reload_config(user_path=Path("/nonexistent"))
    assert c2.dns_timeout == 99
    # Cleanup
    os.environ.pop("PHISHHAWK_DNS_TIMEOUT", None)
    os.environ.update(saved_env)
    _cfg._config = None
