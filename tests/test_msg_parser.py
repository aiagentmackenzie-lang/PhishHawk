"""Tests for msg_parser module — Outlook .msg file parsing."""

from __future__ import annotations

from pathlib import Path

import pytest

from phishhawk.msg_parser import parse_msg


class TestParseMsg:

    def test_parse_msg_import_error(self, tmp_path: Path) -> None:
        """If extract_msg is not installed, parse_msg should raise ImportError."""
        # Create a dummy .msg file
        msg_path = tmp_path / "test.msg"
        msg_path.write_bytes(b"dummy msg content")

        # extract_msg is likely not installed in test env (it's optional)
        # so this should raise ImportError
        with pytest.raises(ImportError, match="extract-msg"):
            parse_msg(str(msg_path))

    def test_parse_msg_not_found(self) -> None:
        """Non-existent file should raise an error."""
        with pytest.raises((ImportError, FileNotFoundError)):
            parse_msg("/nonexistent/path/test.msg")
