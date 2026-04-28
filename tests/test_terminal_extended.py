"""Extended tests for terminal output renderer."""

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
from phishhawk.output.terminal import render_terminal


def _sample_analysis(**overrides) -> EmailAnalysis:
    defaults = {
        "file": "test.eml",
        "file_hash": "sha256:abc123",
        "risk": RiskScore(
            total=65,
            level=RiskLevel.HIGH,
            categories=[
                CategoryScore(category="authentication", score=80, findings=["SPF failed"]),
                CategoryScore(category="urls", score=60, findings=["Suspicious TLD"]),
                CategoryScore(category="attachments", score=50, findings=["No suspicious attachments"]),
                CategoryScore(category="headers", score=10, findings=["Headers appear normal"]),
                CategoryScore(category="iocs", score=40, findings=["Domains found: 3"]),
            ],
        ),
        "headers": HeaderInfo(
            subject="Urgent: Verify Account",
            from_address="security@amaz0n-security.com",
            from_display_name="Amazon",
            reply_to="support@gmail.com",
            message_id="<abc123@evil.com>",
        ),
        "iocs": IOCs(
            ipv4=["192.168.1.100"],
            domains=["amaz0n-security.com", "micros0ft-login.com"],
            urls=["https://micros0ft-login.com/verify"],
            emails=["support@gmail.com"],
        ),
        "mitre": ["T1566.001", "T1598.001"],
        "recommendations": ["Do not click links", "Report to IT"],
        "attachments": [
            AttachmentInfo(filename="invoice.exe", is_dangerous=True, size=256),
        ],
    }
    defaults.update(overrides)
    return EmailAnalysis(**defaults)


class TestRenderTerminal:

    def test_render_basic(self) -> None:
        """Terminal rendering should not crash on basic analysis."""
        analysis = _sample_analysis()
        # render_terminal uses Console, which writes to stdout
        # Just verify it doesn't crash
        render_terminal(analysis)

    def test_render_with_urls(self) -> None:
        from phishhawk.url_models import URLAnalysis
        analysis = _sample_analysis(
            urls=[
                URLAnalysis(url="https://micros0ft-login.com/verify", domain="micros0ft-login", tld="com", suspicious_tld=False),
                URLAnalysis(url="https://bit.ly/abc", is_shortened=True, domain="bit", tld="ly"),
            ],
        )
        render_terminal(analysis)

    def test_render_no_attachments(self) -> None:
        analysis = _sample_analysis(attachments=[])
        render_terminal(analysis)

    def test_render_no_iocs(self) -> None:
        analysis = _sample_analysis(iocs=IOCs())
        render_terminal(analysis)

    def test_render_low_risk(self) -> None:
        analysis = _sample_analysis(
            risk=RiskScore(total=10, level=RiskLevel.LOW, categories=[
                CategoryScore(category="authentication", score=5, findings=["No issues"]),
            ]),
        )
        render_terminal(analysis)

    def test_render_critical_risk(self) -> None:
        analysis = _sample_analysis(
            risk=RiskScore(total=90, level=RiskLevel.CRITICAL, categories=[
                CategoryScore(category="authentication", score=95, findings=["All auth failed"]),
            ]),
        )
        render_terminal(analysis)
