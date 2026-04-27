"""Parse .eml files using Python stdlib email module."""

from __future__ import annotations

import email
import email.policy
from pathlib import Path
from typing import Any

from phishhawk.attachments import extract_attachments_from_message
from phishhawk.headers import parse_headers
from phishhawk.models import FileType, ParsedEmail
from phishhawk.utils import compute_hashes


def parse_eml(file_path: str) -> ParsedEmail:
    """Parse a .eml file into a normalized model."""
    path = Path(file_path)
    raw_bytes = path.read_bytes()
    msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)
    return _parse_message_object(msg, str(path.absolute()), FileType.EML, raw_bytes)


def parse_eml_message(msg: Any) -> ParsedEmail:
    """Parse an already-loaded email.message.Message object."""
    try:
        raw_bytes = msg.as_bytes()
    except Exception:
        raw_bytes = b""
    return _parse_message_object(msg, "", FileType.EML, raw_bytes)


def _parse_message_object(
    msg: Any,
    file_path: str,
    file_type: FileType,
    raw_bytes: bytes,
) -> ParsedEmail:
    headers = parse_headers(msg)
    body_text, body_html = extract_bodies(msg)
    attachments = extract_attachments_from_message(msg)
    hashes = compute_hashes(raw_bytes)

    return ParsedEmail(
        file_path=file_path,
        file_type=file_type,
        file_size=len(raw_bytes),
        file_sha256=hashes["sha256"],
        headers=headers,
        body_text=body_text,
        body_html=body_html,
        attachments=attachments,
    )


def extract_bodies(msg: Any) -> tuple[str | None, str | None]:
    """Extract plain-text and HTML body parts."""
    text: str | None = None
    html: str | None = None

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == "text/plain" and text is None:
                text = _safe_decode_payload(part)
            elif ctype == "text/html" and html is None:
                html = _safe_decode_payload(part)
    else:
        ctype = msg.get_content_type()
        payload = _safe_decode_payload(msg)
        if ctype == "text/plain":
            text = payload
        elif ctype == "text/html":
            html = payload

    return text, html


def _safe_decode_payload(part: Any) -> str | None:
    """Decode payload with robust charset fallback chain."""
    try:
        content = part.get_content()
        if isinstance(content, bytes):
            return content.decode("utf-8", errors="replace")
        return str(content) if content is not None else None
    except (UnicodeDecodeError, LookupError, AttributeError):
        payload = part.get_payload(decode=True)
        if payload is None:
            return None
        for encoding in ("utf-8", "latin-1", "cp1252"):
            try:
                return payload.decode(encoding)
            except UnicodeDecodeError:
                continue
        return payload.decode("utf-8", errors="replace")
