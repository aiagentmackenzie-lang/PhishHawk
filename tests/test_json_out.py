"""Tests for JSON and NDJSON output formatters."""

from __future__ import annotations

import json
from pathlib import Path

from phishhawk.models import (
    CategoryScore,
    EmailAnalysis,
    HeaderInfo,
    IOCs,
    RiskLevel,
    RiskScore,
)
from phishhawk.output.json_out import export_json, export_ndjson


def _minimal_analysis() -> EmailAnalysis:
    return EmailAnalysis(
        file="test.eml",
        headers=HeaderInfo(from_address="attacker@evil.com", to_addresses=["victim@example.com"]),
        risk=RiskScore(total=50, level=RiskLevel.MEDIUM, categories=[
            CategoryScore(category="authentication", score=50, findings=["SPF fail"]),
        ]),
        iocs=IOCs(domains=["evil.com"], emails=["attacker@evil.com"]),
        mitre=["T1566.002"],
        recommendations=["Block domain"],
    )


def test_export_json_returns_string() -> None:
    analysis = _minimal_analysis()
    result = export_json(analysis)
    data = json.loads(result)
    assert data["file"] == "test.eml"
    assert data["risk"]["total"] == 50
    assert data["iocs"]["domains"] == ["evil.com"]
    assert data["iocs"]["total_count"] == 2


def test_export_json_writes_file(tmp_path: Path) -> None:
    analysis = _minimal_analysis()
    outfile = str(tmp_path / "out.json")
    export_json(analysis, outfile)
    assert Path(outfile).exists()
    data = json.loads(Path(outfile).read_text())
    assert data["file"] == "test.eml"


def test_export_ndjson_returns_string() -> None:
    a1 = _minimal_analysis()
    a2 = _minimal_analysis()
    a2.file = "test2.eml"
    result = export_ndjson([a1, a2])
    lines = result.strip().split("\n")
    assert len(lines) == 2
    d1 = json.loads(lines[0])
    d2 = json.loads(lines[1])
    assert d1["file"] == "test.eml"
    assert d2["file"] == "test2.eml"


def test_export_ndjson_writes_file(tmp_path: Path) -> None:
    analysis = _minimal_analysis()
    outfile = str(tmp_path / "batch.ndjson")
    export_ndjson([analysis], outfile)
    assert Path(outfile).exists()
    lines = Path(outfile).read_text().strip().split("\n")
    assert len(lines) == 1


def test_export_json_total_count_in_output() -> None:
    """total_count computed field must appear in JSON output."""
    analysis = _minimal_analysis()
    data = json.loads(export_json(analysis))
    assert "total_count" in data["iocs"]
    assert data["iocs"]["total_count"] == 2


def test_export_json_empty_iocs() -> None:
    analysis = EmailAnalysis(
        file="clean.eml",
        headers=HeaderInfo(),
        risk=RiskScore(total=0, level=RiskLevel.LOW, categories=[]),
        iocs=IOCs(),
    )
    data = json.loads(export_json(analysis))
    assert data["iocs"]["total_count"] == 0
