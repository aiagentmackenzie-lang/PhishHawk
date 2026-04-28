"""Tests for mbox_parser module."""

from __future__ import annotations

import mailbox
from email.message import EmailMessage
from pathlib import Path

import pytest

from phishhawk.mbox_parser import parse_mbox
from phishhawk.models import FileType


@pytest.fixture
def sample_mbox_path(tmp_path: Path) -> str:
    """Create a minimal .mbox file with one message."""
    mbox_path = tmp_path / "test.mbox"
    mbox = mailbox.mbox(str(mbox_path))
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["To"] = "recipient@example.com"
    msg["Subject"] = "Test Mbox Message"
    msg["Date"] = "Mon, 27 Apr 2026 10:00:00 +0000"
    msg.set_content("This is a test mbox message body.")
    mbox.add(msg)
    mbox.flush()
    mbox.close()
    return str(mbox_path)


@pytest.fixture
def empty_mbox_path(tmp_path: Path) -> str:
    """Create an empty .mbox file."""
    mbox_path = tmp_path / "empty.mbox"
    mbox = mailbox.mbox(str(mbox_path))
    mbox.flush()
    mbox.close()
    return str(mbox_path)


class TestParseMbox:

    def test_parse_mbox_single_message(self, sample_mbox_path: str) -> None:
        """Parse a .mbox file with one message."""
        parsed = parse_mbox(sample_mbox_path)
        assert parsed.file_type == FileType.MBOX
        assert parsed.file_path.endswith(".mbox")
        assert parsed.file_size > 0
        assert parsed.headers is not None
        assert parsed.headers.subject == "Test Mbox Message"
        assert parsed.headers.from_address == "sender@example.com"

    def test_parse_mbox_body(self, sample_mbox_path: str) -> None:
        """Body text should be extracted from mbox messages."""
        parsed = parse_mbox(sample_mbox_path)
        assert parsed.body_text is not None
        assert "test mbox message" in parsed.body_text.lower()

    def test_parse_empty_mbox(self, empty_mbox_path: str) -> None:
        """Empty mbox should raise ValueError."""
        with pytest.raises(ValueError, match="[Ee]mpty|No valid"):
            parse_mbox(empty_mbox_path)

    def test_parse_mbox_not_found(self) -> None:
        """Missing file should raise appropriate error."""
        with pytest.raises((FileNotFoundError, OSError, ValueError)):
            parse_mbox("/nonexistent/path/file.mbox")

    def test_mbox_file_size(self, sample_mbox_path: str) -> None:
        """Parsed mbox should report correct file size."""
        parsed = parse_mbox(sample_mbox_path)
        actual_size = Path(sample_mbox_path).stat().st_size
        assert parsed.file_size == actual_size
