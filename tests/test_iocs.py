"""Tests for IOC extraction engine — Phase 5."""

from __future__ import annotations

from phishhawk.iocs import (
    extract_crypto,
    extract_domains,
    extract_emails,
    extract_file_hashes,
    extract_iocs,
    extract_ips,
    extract_urls,
)
from phishhawk.models import HeaderInfo, IOCs, ParsedEmail


def test_extract_ips_basic() -> None:
    text = "Contact us at 8.8.8.8 or 192.168.1.1 and fe80::1"
    ipv4, ipv6 = extract_ips(text, from_headers=False)
    assert "8.8.8.8" in ipv4
    assert "192.168.1.1" not in ipv4  # RFC1918 excluded from body
    assert "fe80::1" not in ipv6  # link-local excluded from body


def test_extract_ips_from_headers() -> None:
    text = "Received: from mail.example.com [192.168.1.1]"
    ipv4, ipv6 = extract_ips(text, from_headers=True)
    assert "192.168.1.1" in ipv4


def test_extract_ips_false_positive_dotted_number() -> None:
    """ESMTPS id strings like abc123.2026.04.25.08.30.00 must not yield IPs."""
    text = "ESMTPS id abc123.2026.04.25.08.30.00"
    ipv4, _ = extract_ips(text, from_headers=True)
    assert "04.25.08.30" not in ipv4
    assert "08.30.00" not in ipv4


def test_extract_domains() -> None:
    text = "Visit example.com and sub.evil.co.uk for info"
    domains = extract_domains(text)
    assert "example.com" in domains
    assert "sub.evil.co.uk" in domains


def test_extract_domains_filters_file_extensions() -> None:
    text = "index.html script.js image.png"
    domains = extract_domains(text)
    assert "index.html" not in domains
    assert "script.js" not in domains
    assert "image.png" not in domains


def test_extract_urls() -> None:
    text = "Check https://evil.com/run.exe and hxxps://bad[.]com/phish"
    urls = extract_urls(text)
    assert "https://evil.com/run.exe" in urls
    assert "hxxps://bad[.]com/phish" in urls


def test_extract_emails() -> None:
    text = "From alice@example.com and Bob_Smith+tag@evil.co.uk"
    emails = extract_emails(text)
    assert "alice@example.com" in emails
    assert "Bob_Smith+tag@evil.co.uk" in emails


def test_extract_crypto() -> None:
    text = (
        "BTC: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa "
        "ETH: 0xdAC17F958D2ee523a2206206994597C13D831ec7 "
        "XMR: 46BeWrHULiXV1WqrFL1UVdLaC4qTdRzGpDj6yPaZS7TJf9BWWxLrP87DZgRBC2"
        "aeTWAa3kB6gFqTZQd3d5DGC6xGv7QmH5YVfQdQ7"
    )
    crypto = extract_crypto(text)
    assert "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" in crypto
    assert "0xdAC17F958D2ee523a2206206994597C13D831ec7" in crypto
    assert any(c.startswith("4") for c in crypto)


def test_extract_file_hashes() -> None:
    text = (
        "MD5: d41d8cd98f00b204e9800998ecf8427e "
        "SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709 "
        "SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    hashes = extract_file_hashes(text)
    assert "d41d8cd98f00b204e9800998ecf8427e" in hashes
    assert "da39a3ee5e6b4b0d3255bfef95601890afd80709" in hashes
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in hashes


def test_extract_file_hashes_filters_substrings() -> None:
    """A 32-hex embedded inside a longer hex string should be rejected."""
    text = "longhex d41d8cd98f00b204e9800998ecf8427eabcd1234 morehex"
    # The 32-char candidate starts at d41d... but after it is 'abcd' which is hex,
    # so it should be filtered out.
    hashes = extract_file_hashes(text)
    assert "d41d8cd98f00b204e9800998ecf8427e" not in hashes


def test_extract_iocs_integration() -> None:
    parsed = ParsedEmail(
        file_path="test.eml",
        file_type="eml",
        headers=HeaderInfo(
            from_address="attacker@evil.com",
            to_addresses=["victim@example.com"],
            subject="Invoice",
            raw_headers={
                "Received": ["from mail.evil.com (192.168.1.100)"],
            },
        ),
        body_text="Pay at https://evil.com/invoice BTC 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        body_html='<html><a href="https://evil.com/invoice">click</a></html>',
    )
    iocs = extract_iocs(parsed)
    assert isinstance(iocs, IOCs)
    assert "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" in iocs.crypto_addresses
    assert "https://evil.com/invoice" in iocs.urls
    assert "evil.com" in iocs.domains
    assert "attacker@evil.com" in iocs.emails
    assert "victim@example.com" in iocs.emails
    assert "192.168.1.100" in iocs.ipv4  # from headers, kept
    assert iocs.total_count > 0


def test_iocs_total_count_serialises() -> None:
    """total_count (computed_field) must appear in JSON/model_dump output."""
    iocs = IOCs(
        ipv4=["1.2.3.4"],
        domains=["evil.com"],
        urls=["https://evil.com/phish"],
        emails=["a@b.com"],
    )
    dumped = iocs.model_dump()
    assert "total_count" in dumped
    assert dumped["total_count"] == 4


def test_extract_domains_filters_auth_results() -> None:
    """smtp.mailfrom and header.from must not appear as domains."""
    text = "Authentication-Results: smtp.mailfrom=evil.com; header.from=evil.com"
    domains = extract_domains(text)
    assert "smtp.mailfrom" not in domains
    assert "header.from" not in domains
    # The actual domain (evil.com) should still be extracted from the value
    assert "evil.com" in domains
