"""Parse .mbox files using stdlib mailbox module."""

from __future__ import annotations

import mailbox
from pathlib import Path

from phishhawk.eml_parser import parse_eml_message
from phishhawk.models import FileType, ParsedEmail


def parse_mbox(file_path: str) -> ParsedEmail:
    """Parse an .mbox file and return the first message as a normalized model."""
    mbox = mailbox.mbox(file_path)
    if not mbox:
        raise ValueError(f"Empty or unreadable mbox file: {file_path}")

    # Get first non-empty message
    first_msg = None
    for key in mbox:
        candidate = mbox[key]
        if candidate:
            first_msg = candidate
            break

    if first_msg is None:
        raise ValueError(f"No valid messages in mbox: {file_path}")

    parsed = parse_eml_message(first_msg)
    parsed.file_path = str(Path(file_path).absolute())
    parsed.file_type = FileType.MBOX
    parsed.file_size = Path(file_path).stat().st_size
    return parsed
