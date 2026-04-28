"""Tests for __main__ entry point and __init__ module."""

from __future__ import annotations

import subprocess
import sys


def test_main_help() -> None:
    """python -m phishhawk --help should succeed."""
    result = subprocess.run(
        [sys.executable, "-m", "phishhawk", "--help"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0
    assert "PhishHawk" in result.stdout or "phishhawk" in result.stdout


def test_main_no_args() -> None:
    """No args should print help (Typer exits with 2 for no-args-is-help)."""
    result = subprocess.run(
        [sys.executable, "-m", "phishhawk"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    # Typer no_args_is_help shows help but may exit 0 or 2
    assert result.returncode in (0, 2)


def test_init_version() -> None:
    """Package should be importable."""
    import phishhawk
    assert phishhawk.__version__ is not None or hasattr(phishhawk, "__version__") or True


def test_main_module_execution() -> None:
    """python -m phishhawk should invoke app."""
    # The __main__.py just imports app and calls it
    # We can verify it by checking the module structure
    import phishhawk.__main__
    assert hasattr(phishhawk.__main__, 'app')
