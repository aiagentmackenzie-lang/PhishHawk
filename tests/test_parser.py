"""Tests for email parser dispatcher."""

from __future__ import annotations

import pytest

from phishhawk.parser import parse_email


def test_parse_email_not_found() -> None:
    with pytest.raises(FileNotFoundError):
        parse_email("/nonexistent/path/file.eml")


def test_parse_sample_eml(sample_eml_path: str) -> None:
    parsed = parse_email(sample_eml_path)
    assert parsed.file_type == "eml"
    assert parsed.file_sha256 is not None
    assert parsed.headers.from_address == "security@amaz0n-security.com"
    assert parsed.headers.from_display_name == "Amazon"
    assert parsed.headers.reply_to == "support@gmail.com"
    assert len(parsed.headers.received) == 2
    assert parsed.body_text and "verify your account" in parsed.body_text
    assert parsed.body_html and "micros0ft-login.com" in parsed.body_html
    assert len(parsed.attachments) == 1
    assert parsed.attachments[0].filename == "invoice.exe"
    assert parsed.attachments[0].is_dangerous is True
    assert parsed.attachments[0].sha256 is not None
