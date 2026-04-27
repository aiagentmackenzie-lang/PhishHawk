"""Pytest fixtures and helpers."""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def sample_eml_path() -> str:
    return str(FIXTURES_DIR / "sample.eml")
