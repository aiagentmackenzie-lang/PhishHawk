"""Tests for the core analysis engine."""

from __future__ import annotations

from phishhawk.engine import run_analysis


def test_run_analysis_sample_eml() -> None:
    """run_analysis on the sample fixture should return a valid EmailAnalysis."""
    analysis = run_analysis("tests/fixtures/sample.eml")
    assert analysis.file.endswith("sample.eml")
    assert analysis.file_hash is not None
    assert analysis.risk.total >= 0
    assert analysis.risk.level.value in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    assert len(analysis.risk.categories) > 0
    assert analysis.headers is not None
    assert analysis.iocs is not None
    assert analysis.mitre is not None
    assert isinstance(analysis.recommendations, list)


def test_run_analysis_file_not_found() -> None:
    """run_analysis should raise FileNotFoundError for missing files."""
    import pytest
    with pytest.raises(FileNotFoundError):
        run_analysis("tests/fixtures/nonexistent.eml")


def test_run_analysis_iocs_populated() -> None:
    """IOC extraction should find IPs, domains, emails in sample."""
    analysis = run_analysis("tests/fixtures/sample.eml")
    assert len(analysis.iocs.domains) > 0
    assert len(analysis.iocs.emails) > 0
    assert analysis.iocs.total_count > 0


def test_run_analysis_mitre_populated() -> None:
    """MITRE mapping should produce technique IDs for the sample."""
    analysis = run_analysis("tests/fixtures/sample.eml")
    assert len(analysis.mitre) > 0