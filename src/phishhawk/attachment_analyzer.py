"""Advanced attachment forensics: macros, PDF, YARA, archives."""

from __future__ import annotations

import io
import re
import zipfile
from pathlib import Path
from typing import Any

from phishhawk.models import AttachmentInfo

COMMON_ARCHIVE_PASSWORDS: list[str] = [
    "", "infected", "malware", "1234", "password", "123456",
    "abc123", "password123", "sample", "test", "archive",
]

PDF_SUSPICIOUS_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"/JS\s+"),                       # JavaScript
    re.compile(r"/JavaScript\s+"),
    re.compile(r"/OpenAction\s+"),
    re.compile(r"/Launch\s+"),
    re.compile(r"/EmbeddedFile\s+"),
    re.compile(r"/URI\s*\("),
    re.compile(r"/AA\s+"),                       # Additional actions
    re.compile(r"/SubmitForm\s+"),
    re.compile(r"/AcroForm\s+"),                 # AcroForm
    re.compile(r"(eval|unescape|String\.fromCharCode)", re.IGNORECASE),
]

DANGEROUS_EXTENSIONS: set[str] = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".js",
    ".jse", ".wsf", ".hta", ".ps1", ".sh", ".jar", ".dll", ".bin",
}


def analyze_office_macros(att: AttachmentInfo, payload: bytes) -> dict[str, Any]:
    """Analyze Office document for VBA macros using oletools.

    Returns dict with keys: has_macros, macro_count, suspicious, vba_code_preview.
    """
    result: dict[str, Any] = {
        "has_macros": False,
        "macro_count": 0,
        "suspicious": False,
        "suspicious_keywords": [],
        "vba_code_preview": "",
    }
    try:
        import oletools.olevba as olevba

        vba = olevba.VBA_Parser(filename=att.filename, data=payload)
        if vba.detect_vba_macros():
            result["has_macros"] = True
            macros = list(vba.extract_macros())
            result["macro_count"] = len(macros)

            all_code = ""
            for _, _, _, code in macros:
                if isinstance(code, bytes):
                    code = code.decode("utf-8", errors="replace")
                all_code += code + "\n"

            result["vba_code_preview"] = all_code[:2000]

            # Suspicious keyword scan
            suspicious_keywords = {
                "autoexec": ["autoopen", "autoclose", "document_open", "workbook_open"],
                "shell": ["shell", "wscript.shell", "createobject", "run"],
                "network": ["xmlhttp", "winhttp", "urlmon", "internetopen"],
                "obfuscation": ["base64", "powershell", "cmd.exe", "mshta", "regsvr32"],
                "persistence": ["startup", "template", "normal.dot"],
                "anti-analysis": ["environ", "virtual", "sandboxie", "vmware"],
            }
            found: list[str] = []
            code_lower = all_code.lower()
            for category, keywords in suspicious_keywords.items():
                for kw in keywords:
                    if kw in code_lower:
                        found.append(f"{category}:{kw}")
            if found:
                result["suspicious"] = True
                result["suspicious_keywords"] = found[:20]
        vba.close()
    except Exception:
        pass
    return result


def analyze_pdf(att: AttachmentInfo, payload: bytes) -> dict[str, Any]:
    """Analyze PDF for embedded JavaScript, URIs, suspicious objects.

    Returns dict with keys: has_js, has_uris, suspicious_objects_count,
    object_summary, urls_found.
    """
    result: dict[str, Any] = {
        "has_js": False,
        "has_uris": False,
        "suspicious_objects_count": 0,
        "object_summary": [],
        "urls_found": [],
        "num_pages": 0,
    }
    try:
        import pdfplumber

        with pdfplumber.open(io.BytesIO(payload)) as pdf:
            result["num_pages"] = len(pdf.pages)
            for page in pdf.pages:
                urls = page.hyperlinks or []
                for u in urls:
                    uri = u.get("uri") or ""
                    if uri:
                        result["urls_found"].append(uri)
    except Exception:
        pass

    # Always regex the raw bytes for PDF-specific patterns (works even on malformed PDFs)
    try:
        text = payload.decode("latin-1", errors="replace")
        for pattern in PDF_SUSPICIOUS_PATTERNS:
            matches = pattern.findall(text)
            if matches:
                result["suspicious_objects_count"] += len(matches)
                result["object_summary"].append(pattern.pattern[:40])
        result["has_js"] = "/JS" in text or "/JavaScript" in text
        result["has_uris"] = "/URI" in text or bool(result["urls_found"])
    except Exception:
        pass
    return result


def scan_yara(att: AttachmentInfo, payload: bytes, rules_dir: str | None = None) -> dict[str, Any]:
    """Run YARA rules against attachment payload.

    Returns dict with keys: matches (list of rule names), match_count.
    """
    result: dict[str, Any] = {"matches": [], "match_count": 0, "rules_loaded": 0}
    try:
        import yara

        rules: yara.Rules | None = None
        # Build rules from directory
        if rules_dir and Path(rules_dir).exists():
            filepath_mapping: dict[str, str] = {
                str(p): str(p) for p in Path(rules_dir).rglob("*.yar*")
            }
            if filepath_mapping:
                rules = yara.compile(filepaths=filepath_mapping)
                result["rules_loaded"] = len(filepath_mapping)
        else:
            # Compile a minimal built-in rule
            rules = yara.compile(source='rule SuspiciousStrings { strings: $a = "cmd.exe" nocase $b = "powershell" nocase condition: any of them }')
            result["rules_loaded"] = 1

        if rules:
            matches = rules.match(data=payload)
            result["matches"] = [m.rule for m in matches]
            result["match_count"] = len(matches)
    except Exception:
        pass
    return result


def extract_archive(
    payload: bytes,
    filename: str,
    max_files: int = 50,
    max_total_size: int = 50 * 1024 * 1024,
) -> list[AttachmentInfo]:
    """Extract ZIP archives with password brute-forcing.

    Returns list of extracted AttachmentInfo objects.
    """
    extracted: list[AttachmentInfo] = []
    ext = Path(filename).suffix.lower()
    if ext not in {".zip", ".jar", ".docx", ".xlsx", ".pptx"}:
        return extracted

    for password in COMMON_ARCHIVE_PASSWORDS:
        try:
            with zipfile.ZipFile(io.BytesIO(payload)) as zf:
                total_size = 0
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    total_size += info.file_size
                    if total_size > max_total_size:
                        break
                    if len(extracted) >= max_files:
                        break
                    try:
                        pwd = password.encode("utf-8") if password else None
                        data = zf.read(info.filename, pwd=pwd)
                        att = AttachmentInfo(
                            filename=info.filename,
                            mime_type="application/octet-stream",
                            size=len(data),
                        )
                        extracted.append(att)
                    except (RuntimeError, zipfile.BadZipFile):
                        continue
            # If we got here without exception, extraction succeeded
            break
        except zipfile.BadZipFile:
            break
        except RuntimeError:
            continue  # wrong password, try next

    return extracted


def analyze_attachment(
    att: AttachmentInfo,
    payload: bytes,
    yara_rules_dir: str | None = None,
) -> dict[str, Any]:
    """Run full static forensics on a single attachment.

    Returns aggregate analysis dict.
    """
    analysis: dict[str, Any] = {
        "filename": att.filename,
        "sha256": att.sha256,
        "mime_type": att.mime_type,
        "is_dangerous": att.is_dangerous,
        "office_macros": None,
        "pdf": None,
        "yara": None,
        "archive_extracted": [],
        "findings": [],
    }

    ext = Path(att.filename).suffix.lower()

    # Office macro analysis
    if ext in {".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx", ".pptm", ".dotm"}:
        office = analyze_office_macros(att, payload)
        analysis["office_macros"] = office
        if office.get("has_macros"):
            analysis["findings"].append(f"VBA macros found: {office['macro_count']} module(s)")
        if office.get("suspicious"):
            kw = ", ".join(office.get("suspicious_keywords", [])[:5])
            analysis["findings"].append(f"Suspicious macro keywords: {kw}")

    # PDF analysis
    if ext == ".pdf":
        pdf = analyze_pdf(att, payload)
        analysis["pdf"] = pdf
        if pdf.get("has_js"):
            analysis["findings"].append("PDF contains embedded JavaScript")
        if pdf.get("has_uris"):
            analysis["findings"].append(f"PDF contains {len(pdf.get('urls_found', []))} embedded URL(s)")
        if pdf.get("suspicious_objects_count"):
            analysis["findings"].append(f"PDF has {pdf['suspicious_objects_count']} suspicious object(s)")

    # YARA scanning
    yara_result = scan_yara(att, payload, yara_rules_dir)
    analysis["yara"] = yara_result
    if yara_result.get("match_count"):
        rules = ", ".join(yara_result.get("matches", [])[:5])
        analysis["findings"].append(f"YARA matches: {rules}")

    # Archive extraction
    archive = extract_archive(payload, att.filename)
    if archive:
        analysis["archive_extracted"] = [a.model_dump() for a in archive]
        analysis["findings"].append(f"ZIP archive extracted: {len(archive)} file(s)")

    return analysis


def analyze_all_attachments(
    attachments: list[AttachmentInfo],
    raw_payload_map: dict[str, bytes],
    yara_rules_dir: str | None = None,
) -> list[dict[str, Any]]:
    """Run forensics on all attachments."""
    results: list[dict[str, object]] = []
    for att in attachments:
        payload = raw_payload_map.get(att.filename, b"")
        if payload:
            results.append(analyze_attachment(att, payload, yara_rules_dir))
    return results
