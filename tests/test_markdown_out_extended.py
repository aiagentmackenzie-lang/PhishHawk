"""Extended tests for markdown output renderer."""

from __future__ import annotations

from phishhawk.models import (
    AttachmentInfo,
    CategoryScore,
    EmailAnalysis,
    HeaderInfo,
    IOCs,
    RiskLevel,
    RiskScore,
)
from phishhawk.output.markdown_out import export_markdown


def _sample_analysis(**overrides) -> EmailAnalysis:
    defaults = {
        "file": "phish.eml",
        "file_hash": "sha256:deadbeef",
        "risk": RiskScore(
            total=75,
            level=RiskLevel.HIGH,
            categories=[
                CategoryScore(category="authentication", score=85, findings=["SPF failed", "DKIM failed"]),
                CategoryScore(category="urls", score=70, findings=["Suspicious TLD"]),
            ],
        ),
        "headers": HeaderInfo(
            subject="Verify Your Account",
            from_address="phish@evil.com",
            to_addresses=["victim@example.com"],
        ),
        "iocs": IOCs(
            ipv4=["8.8.8.8"],
            domains=["evil.com"],
            urls=["https://evil.com/phish"],
            emails=["phish@evil.com"],
        ),
        "mitre": ["T1566.001"],
        "recommendations": ["Block sender domain"],
        "attachments": [],
    }
    defaults.update(overrides)
    return EmailAnalysis(**defaults)


class TestExportMarkdown:

    def test_basic_markdown(self) -> None:
        md = export_markdown(_sample_analysis())
        assert "PhishHawk" in md
        assert "Verify Your Account" in md
        assert "HIGH" in md

    def test_markdown_to_file(self, tmp_path) -> None:
        from pathlib import Path
        outfile = str(tmp_path / "report.md")
        export_markdown(_sample_analysis(), outfile)
        assert Path(outfile).exists()
        assert "PhishHawk" in Path(outfile).read_text()

    def test_markdown_with_attachments(self) -> None:
        analysis = _sample_analysis(
            attachments=[
                AttachmentInfo(filename="malware.exe", is_dangerous=True, sha256="a" * 64, size=1024),
            ],
        )
        md = export_markdown(analysis)
        assert "malware.exe" in md

    def test_markdown_with_urls(self) -> None:
        from phishhawk.url_models import URLAnalysis
        analysis = _sample_analysis(
            urls=[
                URLAnalysis(url="https://evil.com/phish", domain="evil", tld="com", suspicious_tld=False),
            ],
        )
        md = export_markdown(analysis)
        assert "evil.com" in md

    def test_markdown_with_auth(self) -> None:
        from phishhawk.auth_models import AuthAnalysis, DMARCResult, SPFResult
        auth = AuthAnalysis(
            spf=SPFResult(domain="evil.com", valid=False),
            dmarc=DMARCResult(domain="evil.com", policy="none"),
            findings=["SPF failed"],
        )
        analysis = _sample_analysis(authentication=auth)
        md = export_markdown(analysis)
        assert isinstance(md, str)
        assert len(md) > 0
