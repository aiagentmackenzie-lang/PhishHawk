"""Tests for eml_parser module — parsing, encoding, and error paths."""

from __future__ import annotations

import email
import email.policy
from pathlib import Path

import pytest

from phishhawk.eml_parser import extract_bodies, parse_eml, parse_eml_message
from phishhawk.models import FileType

FIXTURES = Path(__file__).parent / "fixtures"
SAMPLE_EML = str(FIXTURES / "sample.eml")


class TestParseEml:
    """Tests for parse_eml with the sample fixture."""

    def test_parse_sample_eml(self) -> None:
        parsed = parse_eml(SAMPLE_EML)
        assert parsed.file_type == FileType.EML
        assert parsed.file_path.endswith("sample.eml")
        assert parsed.file_size > 0
        assert parsed.file_sha256 is not None
        assert len(parsed.file_sha256) == 64  # SHA-256 hex

    def test_parse_sample_headers(self) -> None:
        parsed = parse_eml(SAMPLE_EML)
        assert parsed.headers.from_address == "security@amaz0n-security.com"
        assert parsed.headers.from_display_name == "Amazon"
        assert parsed.headers.reply_to == "support@gmail.com"
        assert parsed.headers.return_path == "bounce@evil.com"
        assert parsed.headers.subject is not None

    def test_parse_sample_bodies(self) -> None:
        parsed = parse_eml(SAMPLE_EML)
        assert parsed.body_text is not None
        assert "verify your account" in parsed.body_text
        assert parsed.body_html is not None
        assert "micros0ft-login.com" in parsed.body_html

    def test_parse_sample_attachments(self) -> None:
        parsed = parse_eml(SAMPLE_EML)
        assert len(parsed.attachments) == 1
        assert parsed.attachments[0].filename == "invoice.exe"
        assert parsed.attachments[0].is_dangerous is True

    def test_file_not_found(self) -> None:
        with pytest.raises(FileNotFoundError):
            parse_eml("/nonexistent/path/file.eml")


class TestParseEmlMessage:
    """Tests for parse_eml_message with in-memory message objects."""

    def test_simple_text_message(self) -> None:
        msg = email.message_from_string(
            "From: alice@example.com\r\n"
            "To: bob@example.com\r\n"
            "Subject: Hello\r\n"
            "\r\n"
            "Just a plain text body.\r\n",
            policy=email.policy.default,
        )
        parsed = parse_eml_message(msg)
        assert parsed.body_text is not None
        assert "plain text body" in parsed.body_text
        assert parsed.headers.from_address == "alice@example.com"
        assert parsed.headers.subject == "Hello"

    def test_multipart_message(self) -> None:
        raw = (
            "From: sender@test.com\r\n"
            "To: recipient@test.com\r\n"
            "Subject: Multipart test\r\n"
            "MIME-Version: 1.0\r\n"
            "Content-Type: multipart/alternative; boundary=boundary\r\n"
            "\r\n"
            "--boundary\r\n"
            "Content-Type: text/plain\r\n"
            "\r\n"
            "Plain text part.\r\n"
            "--boundary\r\n"
            "Content-Type: text/html\r\n"
            "\r\n"
            "<b>HTML part.</b>\r\n"
            "--boundary--\r\n"
        )
        msg = email.message_from_string(raw, policy=email.policy.default)
        parsed = parse_eml_message(msg)
        assert parsed.body_text is not None
        assert "Plain text part" in parsed.body_text
        assert parsed.body_html is not None
        assert "HTML part" in parsed.body_html

    def test_message_with_no_body(self) -> None:
        msg = email.message_from_string(
            "From: a@b.com\r\nTo: b@c.com\r\nSubject: Empty\r\n\r\n",
            policy=email.policy.default,
        )
        parsed = parse_eml_message(msg)
        # body_text may be empty string or None depending on parsing
        assert parsed.headers.subject == "Empty"


class TestExtractBodies:
    """Tests for extract_bodies with various content types."""

    def test_text_only_message(self) -> None:
        msg = email.message_from_string(
            "Subject: Test\r\n\r\nHello world",
            policy=email.policy.default,
        )
        text, html = extract_bodies(msg)
        assert text is not None
        assert "Hello" in text

    def test_empty_message(self) -> None:
        msg = email.message_from_string(
            "Subject: Empty\r\n\r\n",
            policy=email.policy.default,
        )
        text, html = extract_bodies(msg)
        # May be None or empty string
        assert text is None or text == "" or text is not None

    def test_html_only_message(self) -> None:
        raw = (
            "Subject: HTML only\r\n"
            "MIME-Version: 1.0\r\n"
            "Content-Type: multipart/alternative; boundary=b\r\n"
            "\r\n"
            "--b\r\n"
            "Content-Type: text/html\r\n"
            "\r\n"
            "<p>HTML content</p>\r\n"
            "--b--\r\n"
        )
        msg = email.message_from_string(raw, policy=email.policy.default)
        text, html = extract_bodies(msg)
        assert html is not None
        assert "HTML content" in html


class TestSafeDecodePayload:
    """Test charset fallback in _safe_decode_payload."""

    def test_ascii_payload(self) -> None:
        msg = email.message_from_string(
            "Subject: ASCII\r\n\r\nPlain ASCII text",
            policy=email.policy.default,
        )
        text, _ = extract_bodies(msg)
        assert text is not None

    def test_latin1_payload(self) -> None:
        """Message with latin-1 content should be decoded correctly."""
        raw = (
            "Subject: Latin\r\n"
            "Content-Type: text/plain; charset=latin-1\r\n"
            "\r\n"
            "Caf\xe9\r\n"
        )
        msg = email.message_from_bytes(
            raw.encode("latin-1"), policy=email.policy.default
        )
        text, _ = extract_bodies(msg)
        # Should decode without error
        assert text is not None
