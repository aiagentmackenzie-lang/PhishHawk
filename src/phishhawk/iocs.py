"""IOC (Indicators of Compromise) extraction engine — Phase 5.

Passive by default: no outbound network calls.
"""

from __future__ import annotations

import ipaddress
import re

from phishhawk.models import HeaderInfo, IOCs, ParsedEmail

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

IPV4_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
)

# Simplified IPv6 — catches most common forms
IPV6_PATTERN = re.compile(
    r"\b(?:"
    r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,7}:|"
    r"(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|"
    r"[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|"
    r":(?::[0-9a-fA-F]{1,4}){1,7}|"
    r"fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|"
    r"::(?:ffff(?::0{1,4}){0,1}:){0,1}"
    r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)|"
    r"(?:[0-9a-fA-F]{1,4}:){1,4}:"
    r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)"
    r")\b"
)

# Domain extraction — reasonably strict
DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}\b"
)

# URL extraction — catches http(s), ftp(s) and common defanged variants including bracket-escaped dots
SCHEME_PATTERN = re.compile(
    r"(?:https?|hxxps?|ftp):\/\/[^\s<>\"{}|\\^`]+"
)

# Email addresses
EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b"
)

# Cryptocurrency addresses
BTC_PATTERN = re.compile(
    r"\b(?:1[a-km-zA-HJ-NP-Z1-9]{25,34}|3[a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[ac-hj-np-z02-9]{11,71})\b"
)
ETH_PATTERN = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
XMR_PATTERN = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93,}")

# File hashes
MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_PATTERN = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")

# HTML tag stripper
HTML_TAG_RE = re.compile(r"<[^>]+>")

# Authentication-Results keyword false positives for domain extraction
AUTH_RESULT_KEYWORDS: set[str] = {
    "smtp.mailfrom", "header.from", "smtp.helo",
    "header.return-path", "header.reply-to",
}

# File extension false positives for domain extraction
FILE_EXTENSIONS: set[str] = {
    "html", "htm", "php", "asp", "aspx", "jsp", "json", "xml", "txt",
    "css", "js", "jpg", "jpeg", "png", "gif", "pdf", "doc", "docx",
    "xls", "xlsx", "zip", "exe", "dll", "py", "md", "log", "csv",
    "svg", "ico", "mp3", "mp4", "avi", "mov", "wmv", "flv", "swf",
    "tar", "gz", "bz2", "7z", "rar", "iso", "img", "dmg", "pkg",
    "deb", "rpm", "msi", "apk", "ipa", "jar", "war", "ear",
}


def _dedup(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


def _extract(pattern: re.Pattern, text: str) -> list[str]:
    if not text:
        return []
    return pattern.findall(text)


def _is_private_or_loopback(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


def _strip_html(text: str | None) -> str:
    if not text:
        return ""
    return HTML_TAG_RE.sub(" ", text)


def extract_ips(text: str, *, from_headers: bool = False) -> tuple[list[str], list[str]]:
    """Extract IPv4 and IPv6 from text.

    RFC 1918 / link-local / loopback addresses are excluded from body text
    but kept when from_headers=True.
    """
    if not text:
        return [], []

    ipv4: list[str] = []
    for m in IPV4_PATTERN.finditer(text):
        ip = m.group()
        start, end = m.start(), m.end()
        before = text[max(0, start - 10):start]
        after = text[end:end + 10]
        # Reject if part of a longer dotted-number sequence (e.g. ESMTPS id)
        if re.search(r"\d+\.$", before) and re.search(r"^\.\d+", after):
            continue
        ipv4.append(ip)

    ipv6 = _extract(IPV6_PATTERN, text)

    if not from_headers:
        ipv4 = [ip for ip in ipv4 if not _is_private_or_loopback(ip)]
        ipv6 = [ip for ip in ipv6 if not _is_private_or_loopback(ip)]

    return _dedup(ipv4), _dedup(ipv6)


def extract_domains(text: str) -> list[str]:
    """Extract domain-like strings from text, filtering file-extension and auth-result false positives."""
    domains = _extract(DOMAIN_PATTERN, text)
    filtered: list[str] = []
    for d in domains:
        lower = d.lower()
        parts = lower.split(".")
        if len(parts) < 2:
            continue
        if parts[-1] in FILE_EXTENSIONS:
            continue
        # Filter Authentication-Results false positives
        # e.g. "smtp.mailfrom" and "header.from" look like domains to the regex
        if lower in AUTH_RESULT_KEYWORDS:
            continue
        filtered.append(d)
    return _dedup(filtered)


def extract_urls(text: str) -> list[str]:
    """Extract URLs (including defanged) from text."""
    return _dedup(_extract(SCHEME_PATTERN, text))


def extract_emails(text: str) -> list[str]:
    """Extract email addresses."""
    return _dedup(_extract(EMAIL_PATTERN, text))


def extract_crypto(text: str) -> list[str]:
    """Extract cryptocurrency addresses (BTC, ETH, XMR)."""
    btc = _extract(BTC_PATTERN, text)
    eth = _extract(ETH_PATTERN, text)
    xmr = _extract(XMR_PATTERN, text)
    return _dedup(btc + eth + xmr)


def _hash_candidates(text: str, pattern: re.Pattern, length: int) -> list[str]:
    """Extract hash candidates, ensuring they aren't substrings of longer hex sequences."""
    found = pattern.findall(text)
    result: list[str] = []
    text_lower = text.lower()
    for f in found:
        idx = text_lower.find(f.lower())
        before = text[idx - 1] if idx > 0 else " "
        after = text[idx + length] if idx + length < len(text) else " "
        # Exclude if neighbour is hex
        if before in "0123456789abcdefABCDEF" or after in "0123456789abcdefABCDEF":
            continue
        result.append(f)
    return _dedup(result)


def extract_file_hashes(text: str) -> list[str]:
    """Extract MD5, SHA1, SHA256 hashes from body text."""
    md5 = _hash_candidates(text, MD5_PATTERN, 32)
    sha1 = _hash_candidates(text, SHA1_PATTERN, 40)
    sha256 = _hash_candidates(text, SHA256_PATTERN, 64)
    return md5 + sha1 + sha256


def _header_text(headers: HeaderInfo) -> str:
    """Flatten headers into a single string for regex extraction."""
    parts: list[str] = []
    if headers.subject:
        parts.append(headers.subject)
    if headers.from_address:
        parts.append(headers.from_address)
    if headers.reply_to:
        parts.append(headers.reply_to)
    if headers.return_path:
        parts.append(headers.return_path)
    parts.extend(headers.to_addresses)
    parts.extend(headers.cc_addresses)
    parts.extend(headers.bcc_addresses)
    for hop in headers.received:
        parts.extend(filter(None, [hop.from_host, hop.by_host, hop.ip, hop.helo]))
    for vals in (headers.raw_headers or {}).values():
        parts.extend(vals)
    return " ".join(parts)


def extract_iocs(parsed: ParsedEmail) -> IOCs:
    """Extract all IOCs from a parsed email.

    Passive by default: no outbound network calls.
    """
    body_parts: list[str] = []
    if parsed.body_text:
        body_parts.append(parsed.body_text)
    if parsed.body_html:
        body_parts.append(_strip_html(parsed.body_html))
    body_text = " ".join(body_parts)

    header_text = _header_text(parsed.headers) if parsed.headers else ""

    # Body extraction (private IPs excluded)
    ipv4_body, ipv6_body = extract_ips(body_text, from_headers=False)
    # Header extraction (private IPs kept — they matter in received chain)
    ipv4_hdr, ipv6_hdr = extract_ips(header_text, from_headers=True)

    all_ipv4 = _dedup(ipv4_body + ipv4_hdr)
    all_ipv6 = _dedup(ipv6_body + ipv6_hdr)

    domains = _dedup(extract_domains(body_text) + extract_domains(header_text))
    urls = _dedup(extract_urls(body_text) + extract_urls(header_text))
    emails = _dedup(extract_emails(body_text) + extract_emails(header_text))
    file_hashes = _dedup(extract_file_hashes(body_text) + extract_file_hashes(header_text))
    crypto_addresses = _dedup(extract_crypto(body_text) + extract_crypto(header_text))

    return IOCs(
        ipv4=all_ipv4,
        ipv6=all_ipv6,
        domains=domains,
        urls=urls,
        emails=emails,
        file_hashes=file_hashes,
        crypto_addresses=crypto_addresses,
    )
