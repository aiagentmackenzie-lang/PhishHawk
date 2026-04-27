"""Parse .msg (Outlook) files using extract-msg library."""

from __future__ import annotations

from pathlib import Path

from phishhawk.attachments import process_attachment
from phishhawk.headers import extract_address, extract_addresses, parse_date
from phishhawk.models import AttachmentInfo, FileType, HeaderInfo, ParsedEmail


def parse_msg(file_path: str) -> ParsedEmail:
    """Parse an Outlook .msg file into a normalized model."""
    try:
        import extract_msg
    except ImportError as exc:
        raise ImportError(
            "extract-msg is required for .msg parsing. "
            "Install with: pip install 'phishhawk[msg]' or 'phishhawk[all]'"
        ) from exc

    msg = extract_msg.Message(file_path)

    headers = HeaderInfo(
        subject=msg.subject,
        from_address=extract_address(str(msg.sender)) if msg.sender else None,
        from_display_name=msg.sender_name or None,
        to_addresses=extract_addresses(str(msg.to)) if msg.to else [],
        cc_addresses=extract_addresses(str(msg.cc)) if msg.cc else [],
        reply_to=extract_address(str(msg.reply_to)) if msg.reply_to else None,
        date=parse_date(str(msg.date)) if msg.date else None,
        message_id=msg.message_id,
        received=[],
    )

    attachments: list[AttachmentInfo] = []
    raw_payloads: dict[str, bytes] = {}
    for att in msg.attachments:
        if hasattr(att, "data") and att.data:
            info = process_attachment(
                getattr(att, "name", None) or "unnamed.bin",
                getattr(att, "mimetype", None) or "application/octet-stream",
                att.data,
            )
            attachments.append(info)
            raw_payloads[info.filename] = att.data

    return ParsedEmail(
        file_path=str(Path(file_path).absolute()),
        file_type=FileType.MSG,
        headers=headers,
        body_text=msg.body or None,
        body_html=msg.htmlBody or None,
        attachments=attachments,
        raw_payloads=raw_payloads,
    )
