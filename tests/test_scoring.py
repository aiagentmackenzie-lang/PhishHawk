"""Tests for risk scoring engine."""

from __future__ import annotations

from phishhawk.models import AttachmentInfo, HeaderInfo, ParsedEmail, RiskLevel
from phishhawk.scoring import score_email


def test_score_email_low_risk() -> None:
    parsed = ParsedEmail(
        file_path="low.eml",
        file_type="eml",
        headers=HeaderInfo(
            from_address="alice@example.com",
            authentication_results="spf=pass dkim=pass dmarc=pass",
            message_id="<123@example.com>",
            received=[{}] * 2,
        ),
        attachments=[],
    )
    risk = score_email(parsed)
    assert risk.total < 40
    assert risk.level == RiskLevel.LOW
    assert any(c.category == "authentication" for c in risk.categories)


def test_score_email_high_risk() -> None:
    parsed = ParsedEmail(
        file_path="high.eml",
        file_type="eml",
        headers=HeaderInfo(
            from_address="security@evil.com",
            from_display_name="Amazon",
            reply_to="support@gmail.com",
            authentication_results="spf=fail dkim=fail dmarc=fail",
            message_id=None,
            received=[{}] * 7,
        ),
        attachments=[
            AttachmentInfo(
                filename="invoice.exe",
                mime_type="application/octet-stream",
                size=1024,
                is_dangerous=True,
            ),
        ],
    )
    risk = score_email(parsed)
    assert risk.total == 35  # (100+40+35+0+0)//5 — placeholders active in Phase 1
    auth_cat = next(c for c in risk.categories if c.category == "authentication")
    assert any("Display name spoofing" in f for f in auth_cat.findings)
