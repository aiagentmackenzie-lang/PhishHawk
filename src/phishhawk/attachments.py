"""Attachment handling, hashing, and static analysis."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from phishhawk.models import AttachmentInfo
from phishhawk.utils import compute_hashes

DANGEROUS_EXTENSIONS: set[str] = {
    ".exe",
    ".scr",
    ".bat",
    ".cmd",
    ".com",
    ".pif",
    ".vbs",
    ".js",
    ".jse",
    ".wsf",
    ".hta",
    ".ps1",
    ".sh",
    ".jar",
    ".dll",
    ".zip",
    ".rar",
    ".7z",
}


def process_attachment(filename: str, mime_type: str, payload: bytes) -> AttachmentInfo:
    """Compute hashes and flag dangerous attachments."""
    hashes = compute_hashes(payload)
    ext = Path(filename).suffix.lower()
    is_dangerous = ext in DANGEROUS_EXTENSIONS

    return AttachmentInfo(
        filename=filename,
        mime_type=mime_type,
        size=len(payload),
        md5=hashes["md5"],
        sha1=hashes["sha1"],
        sha256=hashes["sha256"],
        is_dangerous=is_dangerous,
    )


def extract_attachments_from_message(msg: Any) -> tuple[list[AttachmentInfo], dict[str, bytes]]:
    """Walk a MIME message and extract all attachment payloads.

    Returns (attachments list, raw_payloads dict).
    """
    attachments: list[AttachmentInfo] = []
    raw_payloads: dict[str, bytes] = {}

    if not msg.is_multipart():
        return attachments, raw_payloads

    for part in msg.walk():
        cdisp = part.get_content_disposition()
        filename = part.get_filename()

        if cdisp == "attachment" or filename:
            payload = part.get_payload(decode=True) or b""
            att = process_attachment(
                filename or "unnamed.bin",
                part.get_content_type() or "application/octet-stream",
                payload,
            )
            att.content_disposition = cdisp
            att.content_id = part.get("Content-ID")
            attachments.append(att)
            raw_payloads[att.filename] = payload

    return attachments, raw_payloads
