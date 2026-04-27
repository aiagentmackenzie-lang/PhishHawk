"""Tests for scoring engine edge cases."""

from __future__ import annotations

from phishhawk.attachment_models import (
    AttachmentForensics,
    OfficeMacroAnalysis,
    PDFAnalysis,
)
from phishhawk.auth_models import (
    AlignmentCheck,
    AuthAnalysis,
    DMARCResult,
    SPFResult,
)
from phishhawk.models import (
    AttachmentInfo,
    HeaderInfo,
    IOCs,
    ParsedEmail,
    RiskLevel,
)
from phishhawk.scoring import (
    score_attachments,
    score_authentication,
    score_email,
    score_headers,
    score_iocs,
    score_urls,
)
from phishhawk.url_models import URLAnalysis


def _parsed(**overrides) -> ParsedEmail:
    defaults = {
        "file_path": "test.eml",
        "file_type": "eml",
        "headers": HeaderInfo(from_address="test@example.com", to_addresses=["victim@example.com"]),
    }
    defaults.update(overrides)
    return ParsedEmail(**defaults)


def test_score_email_empty() -> None:
    """Minimal email should score LOW."""
    parsed = _parsed()
    risk = score_email(parsed)
    assert risk.total >= 0
    assert risk.level in (RiskLevel.LOW, RiskLevel.MEDIUM)


def test_score_email_with_auth_failure() -> None:
    """Auth analysis with failures should increase score."""
    parsed = _parsed(headers=HeaderInfo(
        from_address="phish@evil.com",
        to_addresses=["victim@example.com"],
        authentication_results="spf=fail; dkim=fail; dmarc=fail",
        reply_to="support@freemail.com",
    ))
    auth = AuthAnalysis(
        spf=SPFResult(domain="evil.com", valid=False, errors=["No SPF record"]),
        dmarc=DMARCResult(domain="evil.com", policy="none", valid=False),
        alignment=AlignmentCheck(from_domain="evil.com", spf_aligned=False, dkim_aligned=False, dmarc_pass=False),
        free_email_providers=["support@freemail.com (freemail.com)"],
        findings=["SPF fail", "DKIM fail", "DMARC fail"],
    )
    risk = score_email(parsed, auth=auth)
    # Auth category should score high; total is averaged
    auth_cat = [c for c in risk.categories if c.category == "authentication"][0]
    assert auth_cat.score >= 80


def test_score_headers_missing_message_id() -> None:
    """Missing Message-ID should add to score."""
    headers = HeaderInfo()
    result = score_headers(headers)
    assert result.score > 0
    assert any("Message-ID" in f for f in result.findings)


def test_score_headers_normal() -> None:
    """Normal headers should have low score."""
    from datetime import datetime, timezone
    headers = HeaderInfo(message_id="<abc@example.com>", date=datetime(2026, 1, 1, tzinfo=timezone.utc))
    result = score_headers(headers)
    assert result.score == 0


def test_score_headers_excessive_hops() -> None:
    """Many Received hops should flag."""
    from phishhawk.models import ReceivedHop
    headers = HeaderInfo(received=[ReceivedHop(from_host=f"h{i}") for i in range(8)])
    result = score_headers(headers)
    assert result.score > 0
    assert any("Received" in f for f in result.findings)


def test_score_iocs_crypto() -> None:
    """Crypto addresses should heavily increase IOC score."""
    iocs = IOCs(crypto_addresses=["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"])
    result = score_iocs(iocs)
    assert result.score >= 30
    assert any("Crypto" in f for f in result.findings)


def test_score_iocs_empty() -> None:
    """Empty IOCs should return default finding."""
    result = score_iocs(IOCs())
    assert result.score == 0
    assert "No IOCs" in result.findings[0]


def test_score_iocs_max_cap() -> None:
    """IOC score should be capped at 100."""
    iocs = IOCs(
        ipv4=[f"10.0.0.{i}" for i in range(50)],
        domains=[f"evil{i}.com" for i in range(50)],
        urls=[f"https://evil{i}.com" for i in range(50)],
        crypto_addresses=["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"] * 5,
    )
    result = score_iocs(iocs)
    assert result.score <= 100


def test_score_attachments_dangerous() -> None:
    """Dangerous extension should add to score."""
    att = AttachmentInfo(filename="malware.exe", mime_type="application/octet-stream", size=1024, is_dangerous=True)
    result = score_attachments([att])
    assert result.score >= 40
    assert any("Dangerous" in f for f in result.findings)


def test_score_attachments_macros() -> None:
    """Office macros should increase score."""
    att = AttachmentInfo(filename="doc.xls", mime_type="application/vnd.ms-excel", size=50000, is_dangerous=False)
    forensics = [AttachmentForensics(
        filename="doc.xls",
        office_macros=OfficeMacroAnalysis(has_macros=True, macro_count=3, suspicious=True, suspicious_keywords=["AutoOpen"]),
        findings=["VBA macros detected"],
    )]
    result = score_attachments([att], forensics)
    assert result.score >= 60


def test_score_attachments_pdf_js() -> None:
    """PDF with JS should increase score."""
    att = AttachmentInfo(filename="evil.pdf", mime_type="application/pdf", size=10000, is_dangerous=False)
    forensics = [AttachmentForensics(
        filename="evil.pdf",
        pdf=PDFAnalysis(has_js=True, has_uris=True, suspicious_objects_count=2, num_pages=5),
        findings=["PDF JavaScript detected"],
    )]
    result = score_attachments([att], forensics)
    assert result.score >= 40


def test_score_urls_homograph() -> None:
    """Homograph URL should increase score."""
    urls = [URLAnalysis(url="https://páypal.com/login", domain="páypal", tld="com", is_homograph=True)]
    result = score_urls(urls)
    assert result.score >= 40


def test_score_urls_clean() -> None:
    """Clean URL list should return low score."""
    urls = [URLAnalysis(url="https://example.com", domain="example", tld="com")]
    result = score_urls(urls)
    assert result.score == 0


def test_score_urls_empty() -> None:
    """No URLs should return 0 score."""
    result = score_urls([])
    assert result.score == 0
    assert "No URLs" in result.findings[0]


def test_score_authentication_reply_to_mismatch() -> None:
    """Reply-To different from From should flag."""
    headers = HeaderInfo(
        from_address="security@amazon.com",
        reply_to="attacker@evil.com",
    )
    result = score_authentication(headers)
    assert result.score >= 30
    assert any("Reply-To" in f for f in result.findings)


def test_score_authentication_display_name_spoof() -> None:
    """Display name spoofing should flag."""
    headers = HeaderInfo(
        from_address="attacker@evil.com",
        from_display_name="Amazon",
    )
    result = score_authentication(headers)
    assert result.score >= 35
    assert any("spoof" in f.lower() for f in result.findings)
