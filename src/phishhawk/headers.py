"""Header extraction and Received chain parsing."""

from __future__ import annotations

import re
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import Any

from phishhawk.models import HeaderInfo, ReceivedHop


def parse_headers(msg: Any) -> HeaderInfo:
    """Extract and structure all headers from an email message object."""
    raw_headers: dict[str, list[str]] = {}
    for key, value in msg.items():
        raw_headers.setdefault(key, []).append(str(value))

    received_raw = raw_headers.get("Received", [])
    received_hops = [parse_received(r) for r in received_raw]

    return HeaderInfo(
        subject=_safe_header(msg, "Subject"),
        from_address=extract_address(_safe_header(msg, "From")),
        from_display_name=extract_display_name(_safe_header(msg, "From")),
        to_addresses=extract_addresses(_safe_header(msg, "To")),
        cc_addresses=extract_addresses(_safe_header(msg, "Cc")),
        bcc_addresses=extract_addresses(_safe_header(msg, "Bcc")),
        reply_to=extract_address(_safe_header(msg, "Reply-To")),
        return_path=extract_address(_safe_header(msg, "Return-Path")),
        date=parse_date(_safe_header(msg, "Date")),
        message_id=_safe_header(msg, "Message-ID"),
        received=received_hops,
        authentication_results=_safe_header(msg, "Authentication-Results"),
        raw_headers=raw_headers,
    )


def _safe_header(msg: Any, key: str) -> str | None:
    val = msg.get(key)
    return str(val) if val is not None else None


def extract_address(header_value: str | None) -> str | None:
    """Extract bare email address from a header value."""
    if not header_value:
        return None
    match = re.search(r"<([^>]+)>", header_value)
    if match:
        return match.group(1).strip()
    if "@" in header_value:
        return header_value.strip()
    return None


def extract_display_name(header_value: str | None) -> str | None:
    """Extract display name portion from a From header."""
    if not header_value:
        return None
    if "<" in header_value:
        name = header_value.split("<")[0].strip().strip('"').strip("'")
        return name if name else None
    return None


def extract_addresses(header_value: str | None) -> list[str]:
    """Extract all bare email addresses from a comma-separated header."""
    if not header_value:
        return []
    # naive split; robust enough for most test data
    parts = [p.strip() for p in header_value.split(",")]
    return [addr for p in parts if (addr := extract_address(p)) is not None]


def parse_date(date_str: str | None) -> datetime | None:
    """Parse an RFC 2822 Date header into a datetime."""
    if not date_str:
        return None
    try:
        return parsedate_to_datetime(date_str)
    except Exception:
        return None


def parse_received(received: str) -> ReceivedHop:
    """Parse a single Received header into structured data."""
    hop = ReceivedHop(raw=received)

    # from host
    m = re.search(r"from\s+([^\s\[;(]+)", received, re.IGNORECASE)
    if m:
        hop.from_host = m.group(1).strip()

    # by host
    m = re.search(r"by\s+([^\s\[;(]+)", received, re.IGNORECASE)
    if m:
        hop.by_host = m.group(1).strip()

    # with protocol
    m = re.search(r"with\s+([^\s;]+)", received, re.IGNORECASE)
    if m:
        hop.with_proto = m.group(1).strip()

    # IP in brackets
    m = re.search(r"\[([0-9a-fA-F.:]+)\]", received)
    if m:
        hop.ip = m.group(1)

    # Date/time inside Received (last attempt)
    # RFC 5322 date usually appears at the end
    try:
        # grab last ; if present, everything after is the date
        if ";" in received:
            date_part = received.rsplit(";", 1)[-1].strip()
            hop.timestamp = parsedate_to_datetime(date_part)
    except Exception:
        pass

    return hop
