"""Tests for URL extraction and analysis."""

from __future__ import annotations

from phishhawk.url_analyzer import (
    domain_entropy,
    extract_and_analyze_urls,
    extract_urls,
    is_defanged,
    is_homograph,
    is_raw_ip,
    is_shortened,
    is_suspicious_tld,
    refang,
)


def test_extract_urls_basic() -> None:
    text = "Visit https://example.com/page?q=1 for more info."
    urls = extract_urls(text)
    assert "https://example.com/page?q=1" in urls


def test_extract_urls_defanged() -> None:
    text = "Go to hxxps://evil[.]com/login to verify"
    urls = extract_urls(text)
    assert "https://evil.com/login" in urls


def test_extract_urls_none() -> None:
    assert extract_urls(None) == set()
    assert extract_urls("") == set()


def test_refang() -> None:
    assert refang("hxxps://evil[.]com") == "https://evil.com"
    assert refang("hxxp://test(dot)org") == "http://test.org"


def test_is_defanged() -> None:
    assert is_defanged("hxxps://evil[.]com") is True
    assert is_defanged("https://example.com") is False


def test_is_shortened() -> None:
    assert is_shortened("https://bit.ly/abc123") is True
    assert is_shortened("https://example.com") is False


def test_is_suspicious_tld() -> None:
    assert is_suspicious_tld("evil.xyz") is True
    assert is_suspicious_tld("example.com") is False


def test_is_raw_ip() -> None:
    assert is_raw_ip("http://192.168.1.1/") is True
    assert is_raw_ip("https://example.com") is False


def test_is_homograph_punycode() -> None:
    assert is_homograph("xn--r-0ga.example") is True


def test_domain_entropy() -> None:
    # Random-looking domain should have high entropy
    high = domain_entropy("xn--r7ty66k")
    low = domain_entropy("aaaaaa")
    assert high > low
    assert high > 3.0


def test_extract_and_analyze_urls() -> None:
    text = "Click here: https://micros0ft-login.com/verify"
    html = '<a href="https://bit.ly/abc123">link</a>'
    results = extract_and_analyze_urls(text, html, "", allow_outbound=False)
    urls = [r.url for r in results]
    assert any("micros0ft-login.com" in u for u in urls)
    assert any("bit.ly" in u for u in urls)

    # Check suspicious TLD is False for com
    micros0ft = next(r for r in results if "micros0ft-login.com" in r.url)
    assert micros0ft.domain == "micros0ft-login"
    assert micros0ft.tld == "com"
    assert micros0ft.raw_ip is False


def test_extract_and_analyze_urls_no_content() -> None:
    results = extract_and_analyze_urls(None, None, None, allow_outbound=False)
    assert results == []
