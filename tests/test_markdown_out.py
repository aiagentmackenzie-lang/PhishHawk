"""Tests for Markdown report generator — Phase 5."""

from __future__ import annotations

from phishhawk.models import EmailAnalysis, HeaderInfo, IOCs, RiskLevel, RiskScore
from phishhawk.output.markdown_out import export_markdown


def _minimal_analysis() -> EmailAnalysis:
    return EmailAnalysis(
        file="test.eml",
        file_hash="sha256:abc",
        headers=HeaderInfo(
            subject="Test Subject",
            from_address="alice@example.com",
            to_addresses=["bob@example.com"],
        ),
        risk=RiskScore(total=45, level=RiskLevel.MEDIUM),
        iocs=IOCs(
            ipv4=["8.8.8.8"],
            domains=["evil.com"],
            urls=["https://evil.com"],
            emails=["phish@evil.com"],
            crypto_addresses=["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"],
        ),
        mitre=["T1566.002"],
        recommendations=["Block domain"],
    )


def test_export_markdown_contains_title() -> None:
    analysis = _minimal_analysis()
    md = export_markdown(analysis)
    assert "# PhishHawk Forensic Report" in md


def test_export_markdown_contains_risk() -> None:
    analysis = _minimal_analysis()
    md = export_markdown(analysis)
    assert "45/100" in md
    assert "MEDIUM" in md


def test_export_markdown_contains_iocs() -> None:
    analysis = _minimal_analysis()
    md = export_markdown(analysis)
    assert "8.8.8.8" in md
    assert "evil.com" in md
    assert "https://evil.com" in md
    assert "phish@evil.com" in md
    assert "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" in md


def test_export_markdown_contains_mitre() -> None:
    analysis = _minimal_analysis()
    md = export_markdown(analysis)
    assert "T1566.002" in md
    assert "Spearphishing Link" in md


def test_export_markdown_contains_recommendations() -> None:
    analysis = _minimal_analysis()
    md = export_markdown(analysis)
    assert "Block domain" in md


def test_export_markdown_writes_file(tmp_path) -> None:
    analysis = _minimal_analysis()
    out = tmp_path / "report.md"
    export_markdown(analysis, outfile=str(out))
    assert out.exists()
    assert "PhishHawk Forensic Report" in out.read_text()
