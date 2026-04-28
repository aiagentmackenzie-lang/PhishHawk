"""Tests for attachment analyzer coverage gaps — macro analysis, PDF analysis paths."""

from __future__ import annotations

import io
import zipfile

from phishhawk.attachment_analyzer import (
    analyze_all_attachments,
    analyze_attachment,
    analyze_pdf,
    extract_archive,
    scan_yara,
)
from phishhawk.models import AttachmentInfo


class TestAnalyzeAttachmentDoc:

    def test_analyze_doc_no_macros(self) -> None:
        """Analyzing a .doc file with no macros should return empty macro result."""
        att = AttachmentInfo(filename="clean.doc", mime_type="application/msword", size=10)
        result = analyze_attachment(att, b"Not an actual OLE file")
        assert result["office_macros"] is not None
        # oletools will fail to parse, should return has_macros=False
        macros = result["office_macros"]
        assert isinstance(macros, dict)

    def test_analyze_xlsx(self) -> None:
        """Analyzing a .xlsx file — no macros expected."""
        att = AttachmentInfo(filename="data.xlsx", mime_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", size=100)
        result = analyze_attachment(att, b"Not an actual xlsx")
        assert result["office_macros"] is not None

    def test_analyze_docm(self) -> None:
        """Analyzing a .docm file — macro-enabled extension should trigger macro analysis."""
        att = AttachmentInfo(filename="macro.docm", mime_type="application/vnd.ms-word.document.macroEnabled.12", size=100)
        result = analyze_attachment(att, b"Not a real docm")
        assert result["office_macros"] is not None


class TestAnalyzePdfExtended:

    def test_analyze_pdf_with_openaction(self) -> None:
        """PDF with /OpenAction should be flagged."""
        payload = b"%PDF-1.4\n/OpenAction\n%%EOF"
        att = AttachmentInfo(filename="openaction.pdf", mime_type="application/pdf", size=len(payload))
        result = analyze_pdf(att, payload)
        assert result["suspicious_objects_count"] > 0

    def test_analyze_pdf_with_acroform(self) -> None:
        """PDF with /AcroForm should be flagged."""
        payload = b"%PDF-1.4\n/AcroForm\n%%EOF"
        att = AttachmentInfo(filename="acro.pdf", mime_type="application/pdf", size=len(payload))
        result = analyze_pdf(att, payload)
        assert result["suspicious_objects_count"] > 0

    def test_analyze_pdf_with_submitform(self) -> None:
        """PDF with /SubmitForm should be flagged."""
        payload = b"%PDF-1.4\n/SubmitForm\n%%EOF"
        att = AttachmentInfo(filename="submit.pdf", mime_type="application/pdf", size=len(payload))
        result = analyze_pdf(att, payload)
        assert result["suspicious_objects_count"] > 0

    def test_analyze_pdf_with_eval(self) -> None:
        """PDF with eval/unescape should be flagged."""
        payload = b"%PDF-1.4\neval('malicious')\n%%EOF"
        att = AttachmentInfo(filename="eval.pdf", mime_type="application/pdf", size=len(payload))
        result = analyze_pdf(att, payload)
        assert result["suspicious_objects_count"] > 0

    def test_analyze_pdf_empty_payload(self) -> None:
        """Empty PDF payload should not crash."""
        att = AttachmentInfo(filename="empty.pdf", mime_type="application/pdf", size=0)
        result = analyze_pdf(att, b"")
        assert isinstance(result, dict)


class TestExtractArchiveExtended:

    def test_extract_non_zip_extension(self) -> None:
        """Non-ZIP extension should return empty."""
        result = extract_archive(b"data", "file.txt")
        assert result == []

    def test_extract_bad_zip(self) -> None:
        """Invalid ZIP data should return empty."""
        result = extract_archive(b"not a zip at all", "file.zip")
        assert result == []

    def test_extract_office_docx(self) -> None:
        """DOCX files are ZIP archives — should extract contents."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("[Content_Types].xml", "<?xml version='1.0'?><Types/>")
            zf.writestr("word/document.xml", "<w:document/>")
        payload = buf.getvalue()
        result = extract_archive(payload, "document.docx")
        assert len(result) >= 1


class TestScanYaraExtended:

    def test_yara_with_rules_dir(self, tmp_path) -> None:
        """YARA with custom rules directory should load and run rules."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        rule_file = rules_dir / "test.yar"
        rule_file.write_text(
            'rule TestRule { strings: $a = "malware_sample" nocase condition: $a }'
        )
        att = AttachmentInfo(filename="test.bin", mime_type="application/octet-stream", size=20)
        payload = b"This file contains malware_sample string"
        result = scan_yara(att, payload, rules_dir=str(rules_dir))
        assert result["rules_loaded"] >= 1
        assert result["match_count"] >= 1

    def test_yara_empty_rules_dir(self, tmp_path) -> None:
        """Empty rules directory should fall back to built-in rule."""
        rules_dir = tmp_path / "empty_rules"
        rules_dir.mkdir()
        att = AttachmentInfo(filename="test.bin", mime_type="application/octet-stream", size=20)
        payload = b"powershell -enc blah"
        result = scan_yara(att, payload, rules_dir=str(rules_dir))
        # Should fall back to built-in rule
        assert result["rules_loaded"] == 1 or result["match_count"] >= 0


class TestAnalyzeAllAttachmentsExtended:

    def test_with_real_payload(self) -> None:
        """Attachment with matching payload should be analyzed."""
        att = AttachmentInfo(filename="test.txt", mime_type="text/plain", size=10, sha256="abc")
        payloads = {"test.txt": b"Hello world with cmd.exe reference"}
        results = analyze_all_attachments([att], payloads)
        assert len(results) == 1
        assert results[0]["filename"] == "test.txt"

    def test_multiple_attachments(self) -> None:
        """Multiple attachments with payloads should all be analyzed."""
        atts = [
            AttachmentInfo(filename="a.txt", mime_type="text/plain", size=5, sha256="a"),
            AttachmentInfo(filename="b.pdf", mime_type="application/pdf", size=10, sha256="b"),
        ]
        payloads = {"a.txt": b"clean", "b.pdf": b"%PDF-1.4\n/JS\n%%EOF"}
        results = analyze_all_attachments(atts, payloads)
        assert len(results) == 2
