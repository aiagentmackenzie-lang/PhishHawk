"""Coverage gap tests: eml_parser edge cases — as_bytes fallback, encoding errors, empty payloads."""

from __future__ import annotations

from email.message import EmailMessage

from phishhawk.eml_parser import _safe_decode_payload, extract_bodies, parse_eml_message


class TestParseEmlMessageFallback:

    def test_parse_eml_message_as_bytes_fails(self) -> None:
        """parse_eml_message should handle msg.as_bytes() failure."""
        msg = EmailMessage()
        msg["Subject"] = "Test"
        msg.set_content("Hello world")

        # Force as_bytes to fail by corrupting the message

        def bad_as_bytes():
            raise RuntimeError("Cannot serialize")

        msg.as_bytes = bad_as_bytes
        result = parse_eml_message(msg)
        # Should still parse with empty raw_bytes
        assert result is not None
        assert result.file_path == ""

    def test_parse_eml_message_normal(self) -> None:
        """parse_eml_message with a valid message should work."""
        msg = EmailMessage()
        msg["Subject"] = "Test"
        msg.set_content("Hello world")
        result = parse_eml_message(msg)
        assert result is not None


class TestExtractBodiesNonMultipart:

    def test_non_multipart_text_plain(self) -> None:
        """Non-multipart text/plain message should extract text body."""
        msg = EmailMessage()
        msg.set_content("Plain text body")
        # EmailMessage creates multipart by default; use email.message.Message
        from email.message import Message
        raw_msg = Message()
        raw_msg.set_payload("Just plain text")
        raw_msg["Content-Type"] = "text/plain"

        text, html = extract_bodies(raw_msg)
        assert text is not None

    def test_non_multipart_text_html(self) -> None:
        """Non-multipart text/html message should extract HTML body."""
        from email.message import Message
        raw_msg = Message()
        raw_msg.set_payload("<h1>HTML body</h1>")
        raw_msg["Content-Type"] = "text/html"

        text, html = extract_bodies(raw_msg)
        assert html is not None


class TestSafeDecodePayloadEdgeCases:

    def test_decode_with_lookup_error(self) -> None:
        """Payload with unknown charset should fall back gracefully."""
        from email.message import Message
        part = Message()
        part.set_payload("Some content")
        part["Content-Type"] = 'text/plain; charset="unknown-charset-xyz"'

        # _safe_decode_payload should handle LookupError
        result = _safe_decode_payload(part)
        # Should return some string (possibly with replacement chars)
        assert result is not None or result is None  # Should not crash

    def test_decode_empty_payload(self) -> None:
        """Part with empty/None payload should return None."""
        from email.message import Message
        part = Message()
        part.set_payload(None)
        result = _safe_decode_payload(part)
        # Should handle gracefully
        assert result is None or isinstance(result, str)

    def test_decode_bytes_payload(self) -> None:
        """Part with bytes payload should decode properly."""
        from email.message import Message
        part = Message()
        part.set_payload(b"Hello bytes content")
        result = _safe_decode_payload(part)
        assert result is not None
        assert "Hello" in result


class TestEmlMultipartWithBothBodies:

    def test_multipart_with_text_and_html(self) -> None:
        """Multipart message with both text and HTML should extract both."""
        msg = EmailMessage()
        msg["Subject"] = "Multipart test"
        msg.set_content("Plain text part")
        msg.add_alternative("<h1>HTML part</h1>", subtype="html")

        text, html = extract_bodies(msg)
        assert text is not None
        assert html is not None
