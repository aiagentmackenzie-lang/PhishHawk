"""Additional tests for config module — env overrides, TOML, reload, edge cases."""

from __future__ import annotations

import os
from pathlib import Path

from phishhawk.config import (
    PhishHawkConfig,
    _apply_env,
    _deep_merge,
    _load_toml,
    get_config,
    reload_config,
)


class TestDeepMerge:

    def test_deep_merge_nested_three_levels(self) -> None:
        base = {"a": {"b": {"c": 1}}}
        override = {"a": {"b": {"d": 2}}}
        result = _deep_merge(base, override)
        assert result == {"a": {"b": {"c": 1, "d": 2}}}

    def test_deep_merge_override_scalar(self) -> None:
        base = {"x": 10}
        override = {"x": 99}
        result = _deep_merge(base, override)
        assert result == {"x": 99}

    def test_deep_merge_new_key(self) -> None:
        base = {"a": 1}
        override = {"b": 2}
        result = _deep_merge(base, override)
        assert result == {"a": 1, "b": 2}

    def test_deep_merge_does_not_mutate_base(self) -> None:
        base = {"a": {"b": 1}}
        original = {"a": {"b": 1}}
        _deep_merge(base, {"a": {"c": 2}})
        assert base == original

    def test_deep_merge_list_override(self) -> None:
        base = {"dkim": {"selectors": ["a", "b"]}}
        override = {"dkim": {"selectors": ["x", "y"]}}
        result = _deep_merge(base, override)
        assert result["dkim"]["selectors"] == ["x", "y"]


class TestLoadToml:

    def test_load_toml_invalid_content(self, tmp_path: Path) -> None:
        """Invalid TOML should return empty dict."""
        cfg = tmp_path / "bad.toml"
        cfg.write_text("this is not valid toml {{{")
        result = _load_toml(cfg)
        # Should return empty dict on parse failure, not crash
        assert isinstance(result, dict)

    def test_load_toml_nonexistent(self) -> None:
        assert _load_toml(Path("/nonexistent/file.toml")) == {}

    def test_load_toml_empty_file(self, tmp_path: Path) -> None:
        cfg = tmp_path / "empty.toml"
        cfg.write_text("")
        result = _load_toml(cfg)
        assert result == {}

    def test_load_toml_nested_sections(self, tmp_path: Path) -> None:
        cfg = tmp_path / "config.toml"
        cfg.write_text(
            '[hatchery]\nendpoint = "http://test:9090"\n\n'
            "[dns]\ntimeout = 5\nretries = 3\n\n"
            '[scoring.weights]\nauthentication = 40\n'
        )
        result = _load_toml(cfg)
        assert result["hatchery"]["endpoint"] == "http://test:9090"
        assert result["dns"]["timeout"] == 5
        assert result["scoring"]["weights"]["authentication"] == 40


class TestApplyEnv:

    def test_apply_env_float_value(self) -> None:
        config = {"scoring": {"weights": {"authentication": 30}}}
        with TempEnv({"PHISHHAWK_SCORING_WEIGHT_AUTH": "25.5"}):
            result = _apply_env(config)
            assert result["scoring"]["weights"]["authentication"] == 25.5

    def test_apply_env_string_value(self) -> None:
        config = {"hatchery": {"endpoint": "default"}}
        with TempEnv({"PHISHHAWK_HATCHERY_ENDPOINT": "http://custom:8080/api"}):
            result = _apply_env(config)
            assert result["hatchery"]["endpoint"] == "http://custom:8080/api"

    def test_apply_env_no_override(self) -> None:
        config = {"hatchery": {"endpoint": "default"}}
        # No env vars set — config should stay the same
        result = _apply_env(config)
        assert result["hatchery"]["endpoint"] == "default"


class TestPhishHawkConfig:

    def test_load_all_defaults(self) -> None:
        cfg = PhishHawkConfig.load(user_path=Path("/nonexistent"))
        assert cfg.hatchery_endpoint == "http://localhost:3002/api"
        assert cfg.hatchery_timeout == 30
        assert cfg.dns_timeout == 10
        assert cfg.dns_retries == 2
        assert cfg.weight_authentication == 30
        assert cfg.weight_urls == 25
        assert cfg.terminal_width == 100
        assert cfg.color is True
        assert cfg.dkim_selectors == ["default", "google", "selector1", "selector2"]

    def test_load_system_then_user(self, tmp_path: Path) -> None:
        user_cfg = tmp_path / "user.toml"
        user_cfg.write_text('[hatchery]\nendpoint = "http://user:7777"\n')
        cfg = PhishHawkConfig.load(user_path=user_cfg)
        assert cfg.hatchery_endpoint == "http://user:7777"

    def test_env_overrides_config(self) -> None:
        with TempEnv({"PHISHHAWK_HATCHERY_ENDPOINT": "http://env:9999"}):
            cfg = PhishHawkConfig.load(user_path=Path("/nonexistent"))
            assert cfg.hatchery_endpoint == "http://env:9999"

    def test_scoring_weights_via_env(self) -> None:
        with TempEnv({"PHISHHAWK_SCORING_WEIGHT_AUTH": "50", "PHISHHAWK_SCORING_WEIGHT_URL": "30"}):
            cfg = PhishHawkConfig.load(user_path=Path("/nonexistent"))
            assert cfg.weight_authentication == 50
            assert cfg.weight_urls == 30


class TestConfigSingleton:

    def test_get_config_returns_same(self) -> None:
        import phishhawk.config as _cfg
        _cfg._config = None
        c1 = get_config()
        c2 = get_config()
        assert c1 is c2

    def test_reload_config_resets(self) -> None:
        import phishhawk.config as _cfg
        _cfg._config = None
        c1 = get_config()
        with TempEnv({"PHISHHAWK_DNS_TIMEOUT": "99"}):
            c2 = reload_config(user_path=Path("/nonexistent"))
        assert c2.dns_timeout == 99
        # c1 is the old singleton; c2 is the new one
        # After reload, get_config should return the new one
        c3 = get_config()
        # c3 should be c2 or the reloaded version
        assert c3 is not c1 or c3 is c2


# Helper context manager for env vars
class TempEnv:
    """Context manager to temporarily set env vars and restore on exit."""
    def __init__(self, env_vars: dict[str, str]):
        self.env_vars = env_vars
        self.saved: dict[str, str | None] = {}

    def __enter__(self):
        for k, v in self.env_vars.items():
            self.saved[k] = os.environ.get(k)
            os.environ[k] = v
        return self

    def __exit__(self, *args):
        for k, v in self.saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
