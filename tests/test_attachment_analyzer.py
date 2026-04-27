"""Tests for attachment forensics."""

from __future__ import annotations

from phishhawk.attachment_analyzer import (
    analyze_pdf,
    extract_archive,
    scan_yara,
)
from phishhawk.models import AttachmentInfo


def test_analyze_pdf_js() -> None:
    """Detect embedded JavaScript in a PDF."""
    payload = b"%PDF-1.4\n1 0 obj\n/JavaScript\nendobj\n%%EOF"
    att = AttachmentInfo(filename="test.pdf", mime_type="application/pdf", size=len(payload))
    result = analyze_pdf(att, payload)
    assert result["has_js"] is True


def test_analyze_pdf_uri() -> None:
    """Detect embedded URI in a PDF."""
    payload = b"%PDF-1.4\n/URI (https://evil.com)\n%%EOF"
    att = AttachmentInfo(filename="test.pdf", mime_type="application/pdf", size=len(payload))
    result = analyze_pdf(att, payload)
    assert result["has_uris"] is True


def test_extract_archive_zip() -> None:
    """Extract a simple ZIP archive."""
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("hello.txt", b"hello world")
    payload = buf.getvalue()
    results = extract_archive(payload, "test.zip")
    assert len(results) == 1
    assert results[0].filename == "hello.txt"


def test_scan_yara_builtin() -> None:
    """Run built-in YARA against suspicious strings."""
    payload = b"This file runs cmd.exe and powershell to do evil things"
    att = AttachmentInfo(filename="test.bin", mime_type="application/octet-stream", size=len(payload))
    result = scan_yara(att, payload)
    assert result["match_count"] >= 1
    assert "SuspiciousStrings" in result["matches"]
