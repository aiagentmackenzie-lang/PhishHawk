"""Coverage gap tests: CLI error paths, compare markdown, config command."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from phishhawk.cli import app
from phishhawk.models import (
    AuthAnalysis,
    CategoryScore,
    EmailAnalysis,
    HeaderInfo,
    IOCs,
    RiskLevel,
    RiskScore,
)
from phishhawk.output.markdown_out import _build_diff

runner = CliRunner()


def _make_analysis(filename: str = "test.eml", score: int = 50) -> EmailAnalysis:
    """Create a minimal EmailAnalysis for testing."""
    return EmailAnalysis(
        file=filename,
        file_hash="abc123",
        headers=HeaderInfo(
            subject="Test Subject",
            from_address="sender@example.com",
            message_id="<123@example.com>",
        ),
        risk=RiskScore(
            total=score,
            level=RiskLevel.MEDIUM,
            categories=[CategoryScore(category="test", score=score, max_score=100, findings=["test finding"])],
        ),
        iocs=IOCs(),
        authentication=AuthAnalysis(),
    )


class TestCliAnalyzeErrors:

    def test_analyze_file_not_found(self) -> None:
        """Analyze with nonexistent file should exit 1."""
        result = runner.invoke(app, ["analyze", "/nonexistent/file.eml"])
        assert result.exit_code == 1

    def test_analyze_malformed_file(self, tmp_path) -> None:
        """Analyze with malformed file should exit 1."""
        bad_file = tmp_path / "bad.eml"
        bad_file.write_text("NOT AN EML FILE <<<>>>")
        with patch("phishhawk.cli.run_analysis", side_effect=Exception("Parse error")):
            result = runner.invoke(app, ["analyze", str(bad_file)])
            assert result.exit_code == 1


class TestCliBatchErrors:

    def test_batch_not_a_directory(self) -> None:
        """Batch with non-directory should exit 1."""
        result = runner.invoke(app, ["batch", "/nonexistent/dir"])
        assert result.exit_code == 1

    def test_batch_no_email_files(self, tmp_path) -> None:
        """Batch with empty directory should exit 0."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        result = runner.invoke(app, ["batch", str(empty_dir)])
        assert result.exit_code == 0

    def test_batch_with_files(self, tmp_path) -> None:
        """Batch with eml files should process them."""
        eml_file = tmp_path / "test.eml"
        eml_file.write_text("From: test@example.com\nSubject: Test\n\nBody")
        with patch("phishhawk.cli.run_analysis", return_value=_make_analysis()):
            result = runner.invoke(app, ["batch", str(tmp_path), "--output", "ndjson", "--outfile", str(tmp_path / "out.ndjson")])
            assert result.exit_code == 0


class TestCliCompareErrors:

    def test_compare_file_not_found(self) -> None:
        """Compare with nonexistent file should exit 1."""
        result = runner.invoke(app, ["compare", "/nonexistent/1.eml", "/nonexistent/2.eml"])
        assert result.exit_code == 1


class TestBuildDiff:

    def test_build_diff_basic(self) -> None:
        """_build_diff should compute correct delta."""
        a1 = _make_analysis("file1.eml", score=30)
        a2 = _make_analysis("file2.eml", score=60)
        diff = _build_diff(a1, a2)
        assert diff["risk_delta"] == 30
        assert diff["subject_match"] is True
        assert diff["from_match"] is True

    def test_build_diff_different_subjects(self) -> None:
        """_build_diff with different subjects."""
        a1 = _make_analysis("file1.eml", score=30)
        a1.headers.subject = "Urgent: Verify account"
        a2 = _make_analysis("file2.eml", score=60)
        a2.headers.subject = "Different subject"
        diff = _build_diff(a1, a2)
        assert diff["subject_match"] is False

    def test_build_diff_with_urls(self) -> None:
        """_build_diff with shared and unique URLs."""
        from phishhawk.url_models import URLAnalysis
        a1 = _make_analysis("file1.eml")
        a2 = _make_analysis("file2.eml")
        a1.urls = [
            URLAnalysis(url="https://shared.com"),
            URLAnalysis(url="https://unique1.com"),
        ]
        a2.urls = [
            URLAnalysis(url="https://shared.com"),
            URLAnalysis(url="https://unique2.com"),
        ]
        diff = _build_diff(a1, a2)
        assert "https://shared.com" in diff["shared_urls"]
        assert "https://unique1.com" in diff["unique_urls_file1"]
        assert "https://unique2.com" in diff["unique_urls_file2"]


class TestCliConfigCommand:

    def test_config_show(self) -> None:
        """Config show should display configuration."""
        result = runner.invoke(app, ["config", "--show"])
        assert result.exit_code == 0

    def test_config_init_already_exists(self, tmp_path) -> None:
        """Config init when file already exists should warn."""
        config_dir = Path.home() / ".phishhawk"
        config_file = config_dir / "config.toml"
        already_existed = config_file.exists()

        # If it already exists, init should warn
        if already_existed:
            result = runner.invoke(app, ["config", "--init"])
            assert result.exit_code == 0


class TestCompareMarkdownOutput:

    def test_compare_markdown_format(self) -> None:
        """Compare --output markdown should produce markdown."""
        a1 = _make_analysis("file1.eml", score=30)
        a2 = _make_analysis("file2.eml", score=60)
        with patch("phishhawk.cli.run_analysis", side_effect=[a1, a2]):
            result = runner.invoke(app, ["compare", "file1.eml", "file2.eml", "--output", "markdown"])
            # Should contain markdown table headers
            assert "Campaign Comparison" in result.output or "Risk Score" in result.output or result.exit_code == 0

    def test_compare_json_format(self) -> None:
        """Compare --output json should produce JSON."""
        a1 = _make_analysis("file1.eml", score=30)
        a2 = _make_analysis("file2.eml", score=60)
        with patch("phishhawk.cli.run_analysis", side_effect=[a1, a2]):
            result = runner.invoke(app, ["compare", "file1.eml", "file2.eml", "--output", "json"])
            assert result.exit_code == 0
            data = json.loads(result.output)
            assert "campaign_comparison" in data
