"""Tests for parser dispatcher — .msg and .mbox routing."""

from __future__ import annotations

from pathlib import Path

import pytest

from phishhawk.models import FileType
from phishhawk.parser import parse_email


class TestParserDispatchEml:
    """Default path: .eml files."""

    def test_parse_eml_extension(self) -> None:
        """Files with .eml extension should route to parse_eml."""
        result = parse_email("tests/fixtures/sample.eml")
        assert result.file_type == FileType.EML

    def test_parse_unknown_extension_defaults_to_eml(self, tmp_path: Path) -> None:
        """Unknown extension should be treated as .eml."""
        eml_content = (
            "From: test@example.com\r\n"
            "To: recipient@example.com\r\n"
            "Subject: Test\r\n"
            "\r\n"
            "Body text\r\n"
        )
        eml_file = tmp_path / "test.unknown"
        eml_file.write_text(eml_content)
        result = parse_email(str(eml_file))
        assert result.file_type == FileType.EML


class TestParserDispatchMsg:
    """MSG routing — extract_msg not installed in dev."""

    def test_parse_msg_import_error(self, tmp_path: Path) -> None:
        """Parsing .msg file without extract_msg should raise ImportError."""
        msg_file = tmp_path / "test.msg"
        msg_file.write_bytes(b"Dummy MSG content")
        with pytest.raises(ImportError, match="extract-msg"):
            parse_email(str(msg_file))


class TestParserDispatchMbox:
    """MBOX routing."""

    def test_parse_mbox_empty(self, tmp_path: Path) -> None:
        """Empty .mbox should raise ValueError."""
        import mailbox
        mbox_path = tmp_path / "empty.mbox"
        mbox = mailbox.mbox(str(mbox_path))
        mbox.flush()
        mbox.close()
        with pytest.raises(ValueError):
            parse_email(str(mbox_path))


class TestParserFileNotFound:
    def test_file_not_found(self) -> None:
        with pytest.raises(FileNotFoundError):
            parse_email("/nonexistent/path/file.eml")

    def test_file_not_found_msg(self) -> None:
        with pytest.raises(FileNotFoundError):
            parse_email("/nonexistent/path/file.msg")
