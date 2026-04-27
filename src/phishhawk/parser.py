"""Main parser dispatcher — routes to format-specific backends."""

from __future__ import annotations

from pathlib import Path

from phishhawk.models import ParsedEmail
from phishhawk.utils import file_type_from_path


def parse_email(file_path: str) -> ParsedEmail:
    """Parse an email file and return a normalized ParsedEmail model."""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Email file not found: {file_path}")

    file_type = file_type_from_path(file_path)

    if file_type == "msg":
        from phishhawk.msg_parser import parse_msg

        return parse_msg(file_path)
    elif file_type == "mbox":
        from phishhawk.mbox_parser import parse_mbox

        return parse_mbox(file_path)
    else:
        from phishhawk.eml_parser import parse_eml

        return parse_eml(file_path)
