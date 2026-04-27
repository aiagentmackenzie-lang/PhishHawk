"""Tests for header parsing."""

from __future__ import annotations

from email.message import EmailMessage

from phishhawk.headers import extract_address, extract_display_name, parse_headers, parse_received


def test_extract_address() -> None:
    assert extract_address('"Amazon" <security@example.com>') == "security@example.com"
    assert extract_address("security@example.com") == "security@example.com"
    assert extract_address(None) is None


def test_extract_display_name() -> None:
    assert extract_display_name('"Amazon" <security@example.com>') == "Amazon"
    assert extract_display_name("security@example.com") is None


def test_parse_headers() -> None:
    msg = EmailMessage()
    msg["Subject"] = "Test Subject"
    msg["From"] = '"Alice" <alice@example.com>'
    msg["To"] = "bob@example.com, charlie@example.com"
    msg["Reply-To"] = "reply@evil.com"
    msg["Message-ID"] = "<msg123@example.com>"
    msg["Authentication-Results"] = "spf=pass dkim=fail dmarc=pass"

    headers = parse_headers(msg)
    assert headers.subject == "Test Subject"
    assert headers.from_address == "alice@example.com"
    assert headers.from_display_name == "Alice"
    assert headers.to_addresses == ["bob@example.com", "charlie@example.com"]
    assert headers.reply_to == "reply@evil.com"
    assert headers.message_id == "<msg123@example.com>"
    assert headers.authentication_results == "spf=pass dkim=fail dmarc=pass"


def test_parse_received() -> None:
    raw = (
        "from mail.evil.com (mail.evil.com [192.168.1.100]) "
        "by mx.google.com with ESMTPS id abc123; "
        "Mon, 25 Apr 2026 08:30:00 +0000"
    )
    hop = parse_received(raw)
    assert hop.from_host == "mail.evil.com"
    assert hop.by_host == "mx.google.com"
    assert hop.with_proto == "ESMTPS"
    assert hop.ip == "192.168.1.100"
    assert hop.timestamp is not None
    assert hop.raw == raw
