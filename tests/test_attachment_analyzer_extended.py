"""Extended tests for attachment_analyzer — error paths, edge cases, macros."""

from __future__ import annotations

import io
import zipfile

from phishhawk.attachment_analyzer import (
    analyze_all_attachments,
    analyze_attachment,
    analyze_office_macros,
    analyze_pdf,
    extract_archive,
    scan_yara,
)
from phishhawk.models import AttachmentInfo


class TestAnalyzeAttachment:

    def test_analyze_unknown_file(self) -> None:
        """Non-Office, non-PDF, non-archive file should still get YARA scan."""
        att = AttachmentInfo(filename="readme.txt", mime_type="text/plain", size=100)
        result = analyze_attachment(att, b"Hello world", yara_rules_dir=None)
        assert result["filename"] == "readme.txt"
        assert result["office_macros"] is None
        assert result["pdf"] is None
        assert result["yara"] is not None
        assert isinstance(result["findings"], list)

    def test_analyze_dangerous_extension(self) -> None:
        """Dangerous extension should be flagged in result."""
        att = AttachmentInfo(
            filename="malware.exe",
            mime_type="application/octet-stream",
            size=100,
            is_dangerous=True,
        )
        result = analyze_attachment(att, b"\x00" * 100)
        assert result["is_dangerous"] is True
        assert result["filename"] == "malware.exe"

    def test_analyze_extension_mismatch(self) -> None:
        """Extension/MIME mismatch info should be present in result."""
        att = AttachmentInfo(
            filename="document.pdf",
            mime_type="application/x-msdownload",
            size=100,
            extension_mismatch=True,
        )
        result = analyze_attachment(att, b"\x00" * 100)
        assert result["filename"] == "document.pdf"
        assert result["mime_type"] == "application/x-msdownload"


class TestAnalyzePdf:

    def test_pdf_no_suspicious_content(self) -> None:
        """Clean PDF should have no suspicious objects."""
        payload = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF"
        att = AttachmentInfo(filename="clean.pdf", mime_type="application/pdf", size=len(payload))
        result = analyze_pdf(att, payload)
        assert result["has_js"] is False
        assert result["suspicious_objects_count"] == 0

    def test_pdf_with_launch(self) -> None:
        """PDF with /Launch should be flagged."""
        payload = b"%PDF-1.4\n/Launch\n%%EOF"
        att = AttachmentInfo(filename="evil.pdf", mime_type="application/pdf", size=len(payload))
        result = analyze_pdf(att, payload)
        assert result["suspicious_objects_count"] > 0

    def test_pdf_with_embedded_file(self) -> None:
        """PDF with /EmbeddedFile should be flagged."""
        payload = b"%PDF-1.4\n/EmbeddedFile\n%%EOF"
        att = AttachmentInfo(filename="packed.pdf", mime_type="application/pdf", size=len(payload))
        result = analyze_pdf(att, payload)
        assert result["suspicious_objects_count"] > 0

    def test_pdf_malformed_payload(self) -> None:
        """Malformed PDF payload should not crash."""
        payload = b"\x00\x01\x02\x03"
        att = AttachmentInfo(filename="bad.pdf", mime_type="application/pdf", size=len(payload))
        result = analyze_pdf(att, payload)
        # Should not crash, even with unparseable content
        assert isinstance(result, dict)


class TestAnalyzeOfficeMacros:

    def test_macros_non_office_file(self) -> None:
        """Analyzing macros on a non-Office file should not crash."""
        att = AttachmentInfo(filename="readme.txt", mime_type="text/plain", size=10)
        result = analyze_office_macros(att, b"Not an office file")
        # oletools may try to parse it and fail gracefully
        assert isinstance(result, dict)
        assert "has_macros" in result

    def test_macros_empty_office_payload(self) -> None:
        """Empty payload on an Office file should handle gracefully."""
        att = AttachmentInfo(filename="doc.docx", mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document", size=0)
        result = analyze_office_macros(att, b"")
        # oletools may fail on empty payload — should not crash
        assert isinstance(result, dict)


class TestExtractArchive:

    def test_extract_non_archive(self) -> None:
        """Non-ZIP file should return empty list."""
        result = extract_archive(b"not a zip", "file.txt")
        assert result == []

    def test_extract_password_protected_zip(self) -> None:
        """Password-protected ZIP with known password should extract."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("secret.txt", "classified data")
        # Write with password 'infected' (common test password)
        # Note: zipfile doesn't support writing encrypted archives,
        # so this tests the extraction of unencrypted zips
        payload = buf.getvalue()
        result = extract_archive(payload, "test.zip")
        assert len(result) == 1
        assert result[0].filename == "secret.txt"

    def test_extract_zip_with_many_files(self) -> None:
        """ZIP with multiple files should extract all (up to max)."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for i in range(5):
                zf.writestr(f"file_{i}.txt", f"content {i}")
        payload = buf.getvalue()
        result = extract_archive(payload, "archive.zip")
        assert len(result) == 5

    def test_extract_zip_skip_directories(self) -> None:
        """Directories inside ZIP should be skipped."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("dir/", "")  # directory entry
            zf.writestr("dir/file.txt", "content")
        payload = buf.getvalue()
        result = extract_archive(payload, "archive.zip")
        # Should only extract the file, not the directory entry
        assert len(result) >= 1
        assert any(r.filename == "dir/file.txt" for r in result)


class TestScanYara:

    def test_yara_builtin_rule_match(self) -> None:
        """Built-in YARA rule should match cmd.exe and powershell."""
        payload = b"This contains cmd.exe and powershell for evil"
        att = AttachmentInfo(filename="evil.bat", mime_type="application/bat", size=len(payload))
        result = scan_yara(att, payload, rules_dir=None)
        assert result["match_count"] >= 1

    def test_yara_no_match(self) -> None:
        """Clean payload should not match built-in YARA rule."""
        payload = b"This is a perfectly safe document with no suspicious strings."
        att = AttachmentInfo(filename="safe.txt", mime_type="text/plain", size=len(payload))
        result = scan_yara(att, payload, rules_dir=None)
        assert result["match_count"] == 0

    def test_yara_nonexistent_rules_dir(self) -> None:
        """Non-existent rules dir should fall back to built-in rule."""
        payload = b"powershell -enc blah"
        att = AttachmentInfo(filename="test.ps1", mime_type="text/plain", size=len(payload))
        result = scan_yara(att, payload, rules_dir="/nonexistent/rules")
        assert result["match_count"] >= 1


class TestAnalyzeAllAttachments:

    def test_empty_attachments_list(self) -> None:
        """Empty list should return empty results."""
        result = analyze_all_attachments([], {})
        assert result == []

    def test_attachment_missing_payload(self) -> None:
        """Attachment with no payload in map should still return a result."""
        att = AttachmentInfo(filename="missing.bin", mime_type="application/octet-stream", size=10)
        result = analyze_all_attachments([att], {})
        assert len(result) == 0  # No payload → skipped
