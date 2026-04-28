"""Coverage gap tests: markdown_out compare function and IOC/forensics paths."""

from __future__ import annotations

from phishhawk.auth_models import AlignmentCheck, DMARCResult, SPFResult
from phishhawk.models import (
    AttachmentInfo,
    AuthAnalysis,
    CategoryScore,
    EmailAnalysis,
    HeaderInfo,
    IOCs,
    RiskLevel,
    RiskScore,
)
from phishhawk.output.markdown_out import export_markdown, render_compare_markdown


def _make_analysis(filename: str = "test.eml", score: int = 50) -> EmailAnalysis:
    return EmailAnalysis(
        file=filename,
        file_hash="sha256abc",
        headers=HeaderInfo(
            subject="Test Subject",
            from_address="sender@example.com",
            from_display_name="Amazon",
            message_id="<123@example.com>",
        ),
        risk=RiskScore(
            total=score,
            level=RiskLevel.MEDIUM,

            categories=[CategoryScore(category="test", score=score,  findings=["finding"])],
        ),
        iocs=IOCs(),
        authentication=AuthAnalysis(
            spf=SPFResult(domain="example.com", valid=True),
            dmarc=DMARCResult(domain="example.com", valid=True, policy="reject"),
            alignment=AlignmentCheck(from_domain="example.com", spf_aligned=True, dkim_aligned=True, dmarc_pass=True),
        ),
    )


class TestExportMarkdownIOCs:

    def test_markdown_with_ipv6(self) -> None:
        """Markdown report with IPv6 IOCs."""
        analysis = _make_analysis()
        analysis.iocs.ipv6 = ["2001:db8::1"]
        md = export_markdown(analysis)
        assert "IPv6" in md
        assert "2001:db8::1" in md

    def test_markdown_with_crypto_addresses(self) -> None:
        """Markdown report with crypto addresses."""
        analysis = _make_analysis()
        analysis.iocs.crypto_addresses = ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"]
        md = export_markdown(analysis)
        assert "Cryptocurrency" in md

    def test_markdown_with_file_hashes(self) -> None:
        """Markdown report with file hashes."""
        analysis = _make_analysis()
        analysis.iocs.file_hashes = ["abc123def456"]
        md = export_markdown(analysis)
        assert "File Hashes" in md

    def test_markdown_with_emails(self) -> None:
        """Markdown report with email IOCs."""
        analysis = _make_analysis()
        analysis.iocs.emails = ["evil@phishing.com"]
        md = export_markdown(analysis)
        assert "Email Addresses" in md

    def test_markdown_with_domains(self) -> None:
        """Markdown report with domain IOCs."""
        analysis = _make_analysis()
        analysis.iocs.domains = ["evil.com"]
        md = export_markdown(analysis)
        assert "Domains" in md


class TestExportMarkdownAuthDetails:

    def test_markdown_with_ptr(self) -> None:
        """Markdown report with PTR records."""
        from phishhawk.auth_models import PTRRecord
        analysis = _make_analysis()
        analysis.authentication.ptr = [PTRRecord(ip="1.2.3.4", hostname="mail.example.com")]
        md = export_markdown(analysis)
        assert "PTR" in md

    def test_markdown_with_timestamp_drift(self) -> None:
        """Markdown report with timestamp drift."""
        analysis = _make_analysis()
        analysis.authentication.timestamp_drift_flagged = True
        analysis.authentication.timestamp_drift_seconds = 7200
        md = export_markdown(analysis)
        assert "Timestamp Drift" in md

    def test_markdown_with_dkim(self) -> None:
        """Markdown report with DKIM results."""
        from phishhawk.auth_models import DKIMSelectorResult
        analysis = _make_analysis()
        analysis.authentication.dkim = [DKIMSelectorResult(selector="default", domain="example.com", valid=True)]
        md = export_markdown(analysis)
        assert "DKIM" in md


class TestExportMarkdownAttachments:

    def test_markdown_with_attachments(self) -> None:
        """Markdown report with attachments."""
        analysis = _make_analysis()
        att = AttachmentInfo(
            filename="doc.pdf",
            mime_type="application/pdf",
            size=10000,
            sha256="abc123",
        )
        analysis.attachments = [att]
        md = export_markdown(analysis)
        assert "Attachments" in md
        assert "doc.pdf" in md


class TestExportMarkdownRiskLevels:

    def test_markdown_high_risk(self) -> None:
        """High risk should have warning text."""
        analysis = _make_analysis(score=75)
        analysis.risk.level = RiskLevel.HIGH
        md = export_markdown(analysis)
        assert "high-risk" in md

    def test_markdown_critical_risk(self) -> None:
        """Critical risk should have double warning."""
        analysis = _make_analysis(score=90)
        analysis.risk.level = RiskLevel.CRITICAL
        md = export_markdown(analysis)
        assert "high-risk" in md  # Both HIGH and CRITICAL use "high-risk"

    def test_markdown_low_risk(self) -> None:
        """Low risk should have clean text."""
        analysis = _make_analysis(score=10)
        analysis.risk.level = RiskLevel.LOW
        md = export_markdown(analysis)
        assert "low-risk" in md


class TestRenderCompareMarkdown:

    def test_compare_markdown(self) -> None:
        """render_compare_markdown should produce a comparison report."""
        a1 = _make_analysis("file1.eml", score=30)
        a2 = _make_analysis("file2.eml", score=60)
        md = render_compare_markdown(a1, a2)
        assert "Campaign Comparison" in md
        assert "Risk Score" in md
        assert "Shared URLs" in md
        assert "Unique URLs" in md
        assert "Shared MITRE" in md
        assert "Shared Attachment" in md

    def test_compare_markdown_with_shared_urls(self) -> None:
        """Compare markdown with shared URLs should list them."""
        from phishhawk.url_models import URLAnalysis
        a1 = _make_analysis("file1.eml")
        a2 = _make_analysis("file2.eml")
        a1.urls = [URLAnalysis(url="https://shared.com")]
        a2.urls = [URLAnalysis(url="https://shared.com")]
        md = render_compare_markdown(a1, a2)
        assert "https://shared.com" in md
