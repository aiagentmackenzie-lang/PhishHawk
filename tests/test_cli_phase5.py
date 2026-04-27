"""Tests for Phase 5 CLI additions: markdown, misp, stix, ndjson, compare."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"
SAMPLE_EML = FIXTURES / "sample.eml"

PYTHON = sys.executable
CLI = [PYTHON, "-m", "phishhawk"]


def _run(*args) -> subprocess.CompletedProcess:
    return subprocess.run(
        CLI + list(args),
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent.parent,
    )


def test_cli_markdown_output() -> None:
    result = _run("analyze", str(SAMPLE_EML), "--output", "markdown")
    assert result.returncode == 0
    assert "PhishHawk Forensic Report" in result.stdout
    assert "## Executive Summary" in result.stdout


def test_cli_markdown_outfile(tmp_path) -> None:
    out = tmp_path / "report.md"
    result = _run("analyze", str(SAMPLE_EML), "--output", "markdown", "--outfile", str(out))
    assert result.returncode == 0
    assert out.exists()
    assert "PhishHawk Forensic Report" in out.read_text()


def test_cli_misp_output() -> None:
    result = _run("analyze", str(SAMPLE_EML), "--output", "misp")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert "Event" in data
    assert "Attribute" in data["Event"]


def test_cli_stix_output() -> None:
    result = _run("analyze", str(SAMPLE_EML), "--output", "stix")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data["type"] == "bundle"


def test_cli_batch_ndjson(tmp_path) -> None:
    out = tmp_path / "batch.ndjson"
    result = _run("batch", str(FIXTURES), "--output", "ndjson", "--outfile", str(out))
    assert result.returncode == 0
    assert out.exists()
    lines = [line for line in out.read_text().strip().split("\n") if line]
    assert len(lines) >= 1
    for line in lines:
        obj = json.loads(line)
        assert obj["tool"] == "PhishHawk"


def test_cli_compare_terminal() -> None:
    result = _run("compare", str(SAMPLE_EML), str(SAMPLE_EML))
    assert result.returncode == 0
    assert "Campaign Comparison" in result.stdout


def test_cli_compare_json(tmp_path) -> None:
    out = tmp_path / "compare.json"
    result = _run(
        "compare", str(SAMPLE_EML), str(SAMPLE_EML), "--output", "json", "--outfile", str(out)
    )
    assert result.returncode == 0
    data = json.loads(out.read_text())
    assert "campaign_comparison" in data
    assert "diff" in data["campaign_comparison"]


def test_cli_compare_markdown() -> None:
    result = _run("compare", str(SAMPLE_EML), str(SAMPLE_EML), "--output", "markdown")
    assert result.returncode == 0
    assert "Campaign Comparison Report" in result.stdout
