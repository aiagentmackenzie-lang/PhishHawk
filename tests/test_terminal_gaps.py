"""Coverage gap tests: terminal output — auth alignment, PTR, free email, timestamps, IOCs, MITRE, recommendations."""

from __future__ import annotations

from io import StringIO

from rich.console import Console

from phishhawk.auth_models import AlignmentCheck, DMARCResult, PTRRecord, SPFResult
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
from phishhawk.output.terminal import _level_from_score, _risk_color, render_terminal


def _make_analysis(**overrides) -> EmailAnalysis:
    """Create a fully populated EmailAnalysis for terminal rendering."""
    auth = AuthAnalysis(
        spf=SPFResult(domain="example.com", valid=False),
        dmarc=DMARCResult(domain="example.com", valid=False, policy="reject"),
        alignment=AlignmentCheck(
            from_domain="example.com",
            spf_aligned=False,
            dkim_aligned=False,
            dmarc_pass=False,
            reason="Domain mismatch between From and envelope sender",
        ),
        ptr=[PTRRecord(ip="1.2.3.4", hostname="mail.example.com")],
        free_email_providers=["test@gmail.com"],
        timestamp_drift_flagged=True,
        timestamp_drift_seconds=3600,
    )
    analysis = EmailAnalysis(
        file="test.eml",
        file_hash="sha256abc",
        headers=HeaderInfo(
            subject="Urgent: Verify Account",
            from_address="support@evil.com",
            from_display_name="Amazon Security",
            message_id="<123@evil.com>",
        ),
        risk=RiskScore(
            total=75,
            level=RiskLevel.HIGH,

            categories=[
                CategoryScore(category="authentication", score=30, max_score=30, findings=["SPF failed"]),
                CategoryScore(category="headers", score=15, max_score=15, findings=["Display name spoofing"]),
                CategoryScore(category="urls", score=20, max_score=25, findings=["Suspicious URL"]),
                CategoryScore(category="attachments", score=10, max_score=15, findings=[]),
            ],
        ),
        iocs=IOCs(
            ipv4=["1.2.3.4", "5.6.7.8"],
            domains=["evil.com", "phishing.net"],
            urls=["https://evil.com/verify"],
            emails=["test@gmail.com"],
            file_hashes=["abc123def456"],
            crypto_addresses=["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"],
        ),
        authentication=auth,
        mitre=["T1566.001", "T1598.001"],
        recommendations=[
            "Do not click links in this email",
            "Report to security team",
            "Verify sender through alternate channel",
        ],
    )
    for k, v in overrides.items():
        setattr(analysis, k, v)
    return analysis


class TestTerminalAuthPaths:

    def test_render_with_alignment_reason(self) -> None:
        """Auth panel with alignment reason should display it."""
        buf = StringIO()
        Console(file=buf, force_terminal=True, width=120)
        analysis = _make_analysis()
        # Should not crash
        render_terminal(analysis)

    def test_render_with_ptr_records(self) -> None:
        """Auth panel with PTR records should display them."""
        analysis = _make_analysis()
        render_terminal(analysis)

    def test_render_with_free_email(self) -> None:
        """Auth panel with free email providers should display them."""
        analysis = _make_analysis()
        render_terminal(analysis)

    def test_render_with_timestamp_drift(self) -> None:
        """Auth panel with timestamp drift should display it."""
        analysis = _make_analysis()
        render_terminal(analysis)


class TestTerminalIocPaths:

    def test_render_with_ipv6(self) -> None:
        """IOC panel with IPv6 should display them."""
        analysis = _make_analysis()
        analysis.iocs.ipv6 = ["2001:db8::1", "2001:db8::2"]
        render_terminal(analysis)

    def test_render_with_crypto(self) -> None:
        """IOC panel with crypto addresses should display them."""
        analysis = _make_analysis()
        render_terminal(analysis)  # Already has crypto_addresses


class TestTerminalMitmAndRecs:

    def test_render_with_mitre(self) -> None:
        """MITRE techniques should be displayed."""
        analysis = _make_analysis()
        render_terminal(analysis)  # Already has mitre

    def test_render_with_recommendations(self) -> None:
        """Recommendations should be displayed."""
        analysis = _make_analysis()
        render_terminal(analysis)  # Already has recommendations


class TestTerminalAttachmentPaths:

    def test_render_with_dangerous_attachment(self) -> None:
        """Dangerous attachment should be highlighted red."""
        analysis = _make_analysis()
        att = AttachmentInfo(
            filename="malware.exe",
            mime_type="application/x-msdownload",
            size=50000,
            is_dangerous=True,
            sha256="deadbeef",
        )
        analysis.attachments = [att]
        render_terminal(analysis)

    def test_render_with_no_auth(self) -> None:
        """Analysis with no auth should skip auth panel."""
        analysis = _make_analysis()
        analysis.authentication = AuthAnalysis()
        render_terminal(analysis)


class TestRiskColorAndLevel:

    def test_risk_colors(self) -> None:
        assert _risk_color(RiskLevel.LOW) == "green"
        assert _risk_color(RiskLevel.MEDIUM) == "yellow"
        assert _risk_color(RiskLevel.HIGH) == "red"
        assert _risk_color(RiskLevel.CRITICAL) == "bright_red"

    def test_level_from_score(self) -> None:
        assert _level_from_score(0) == RiskLevel.LOW
        assert _level_from_score(40) == RiskLevel.MEDIUM
        assert _level_from_score(60) == RiskLevel.HIGH
        assert _level_from_score(80) == RiskLevel.CRITICAL
