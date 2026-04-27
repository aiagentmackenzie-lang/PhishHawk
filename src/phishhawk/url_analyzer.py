"""URL extraction, analysis, and forensics."""

from __future__ import annotations

import math
import re
import socket
import ssl
import unicodedata
from urllib.parse import urlparse

import requests
import tldextract

from phishhawk.url_models import SSLInfo, URLAnalysis, WHOISInfo

# Defang / refang patterns
DEFANG_PATTERNS: list[tuple[str, str]] = [
    ("hxxp", "http"),
    ("hxxps", "https"),
    ("[.]", "."),
    ("[:]/[/]", "://"),
    ("(dot)", "."),
    ("[/]", "/"),
]

# Known URL shorteners
SHORTENERS: set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "buff.ly", "goo.gl",
    "short.link", "is.gd", "v.gd", "lnkd.in", "fb.me", "x.co",
    "tr.im", "cli.gs", "su.pr", "short.ie", "short.to", "ow.li",
    "cutt.ly", "rebrand.ly", "short.io", "tiny.cc", "t2m.io",
}

# Suspicious TLDs
SUSPICIOUS_TLDS: set[str] = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click",
    ".link", ".work", ".date", ".party", ".download", ".racing",
    ".win", ".bid", ".loan", ".men", ".review", ".trade",
    ".accountant", ".science", ".country", ".gdn", ".kim",
}


def refang(url: str) -> str:
    """Refang a defanged URL back to normal form."""
    cleaned = url.strip()
    for bad, good in DEFANG_PATTERNS:
        cleaned = cleaned.replace(bad, good)
    # Remove whitespace breaking
    cleaned = cleaned.replace(" ", "").replace("\n", "").replace("\t", "")
    return cleaned


def is_defanged(url: str) -> bool:
    """Check if a URL appears defanged."""
    lowered = url.lower()
    return any(bad in lowered for bad, _ in DEFANG_PATTERNS)


def extract_urls(text: str | None) -> set[str]:
    """Extract all URLs from text, including defanged variants."""
    if not text:
        return set()

    # Handle defanged variants in the raw text
    # This regex captures http, https, ftp, and defanged schemes
    pattern = re.compile(
        r"(?:https?|hxxps?|ftp|ftps)://"
        r"[\w\-._~:/?#[\]@!$\u0026'()*+,;=%]+"
    )

    # Also capture bracket-escaped domains like evil[.]com
    bracket_pattern = re.compile(
        r"(?:https?|hxxps?|ftp|ftps)?://?"
        r"[\w\-]+(?:\[?\]?\.\[?\]?[\w\-]+)+"
    )

    raw_urls = set(pattern.findall(text)) | set(bracket_pattern.findall(text))

    # Refang and normalize
    normalized: set[str] = set()
    for u in raw_urls:
        refanged = refang(u)
        # Ensure it starts with a scheme after refanging
        if not refanged.startswith(("http://", "https://", "ftp://", "ftps://")):
            refanged = "http://" + refanged
        normalized.add(refanged)

    return normalized


def domain_entropy(domain: str) -> float:
    """Calculate Shannon entropy of a domain string for DGA detection."""
    if not domain:
        return 0.0
    domain = domain.lower().replace(".", "")
    length = len(domain)
    if length == 0:
        return 0.0
    freq: dict[str, int] = {}
    for char in domain:
        freq[char] = freq.get(char, 0) + 1
    entropy = -sum((count / length) * math.log2(count / length) for count in freq.values())
    return round(entropy, 3)


def is_suspicious_tld(domain: str) -> bool:
    """Check if domain uses a suspicious TLD."""
    lower = domain.lower()
    return any(lower.endswith(tld) for tld in SUSPICIOUS_TLDS)


def is_raw_ip(url: str) -> bool:
    """Check if URL uses raw IP instead of hostname."""
    try:
        parsed = urlparse(url)
        hostname = parsed.netloc.split(":")[0]
        socket.inet_aton(hostname)
        return True
    except (OSError, ValueError):
        try:
            socket.inet_pton(socket.AF_INET6, hostname)
            return True
        except (OSError, ValueError, UnboundLocalError):
            return False


def is_homograph(domain: str) -> bool:
    """Detect IDN homograph attacks via punycode + mixed-script check."""
    # Check if domain has punycode prefix
    if "xn--" in domain.lower():
        return True
    # Check for mixed Unicode scripts (e.g., Cyrillic 'а' in "аррӏе.com")
    scripts: set[str] = set()
    for char in domain:
        script = unicodedata.name(char, "").split(" ")[0]
        if script in ("LATIN", "CYRILLIC", "GREEK", "ARMENIAN", "GEORGIAN"):
            scripts.add(script)
    # Mixed Latin + non-Latin is suspicious
    return bool("LATIN" in scripts and len(scripts) > 1)


def is_shortened(url: str) -> bool:
    """Check if URL uses a known shortener domain."""
    parsed = urlparse(url)
    hostname = parsed.netloc.lower()
    return hostname in SHORTENERS


def trace_redirects(
    url: str,
    max_hops: int = 10,
    timeout: int = 30,
    allow_outbound: bool = False,
) -> list[str]:
    """Trace redirect chain for a URL.

    **Passive by default**: does nothing unless allow_outbound=True.
    """
    if not allow_outbound:
        return []
    chain: list[str] = []
    current = url
    try:
        for _ in range(max_hops):
            resp = requests.head(
                current,
                timeout=timeout,
                allow_redirects=False,
                headers={"User-Agent": "PhishHawk/1.0"},
            )
            if resp.status_code in (301, 302, 307, 308):
                location = resp.headers.get("Location")
                if location and location != current:
                    chain.append(location)
                    current = location
                else:
                    break
            else:
                break
    except Exception:
        pass
    return chain


def analyze_ssl(url: str, timeout: int = 10) -> SSLInfo | None:
    """Analyze SSL/TLS certificate for an HTTPS URL.

    **Passive by default**: only runs if URL is HTTPS.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return None
    hostname = parsed.netloc.split(":")[0]
    try:
        context = ssl.create_default_context()
        sock = socket.create_connection((hostname, 443), timeout=timeout)
        ssock = context.wrap_socket(sock, server_hostname=hostname)
        with sock, ssock:
            cert = ssock.getpeercert()
            cipher = ssock.cipher()
            version = ssock.version()

            issuer = ", ".join(f"{k}={v}" for k, v in cert.get("issuer", []))
            subject = ", ".join(f"{k}={v}" for k, v in cert.get("subject", []))

            not_after = cert.get("notAfter")
            not_before = cert.get("notBefore")

            return SSLInfo(
                issuer=issuer or None,
                subject=subject or None,
                valid_from=not_before or None,
                valid_until=not_after or None,
                domain_match=hostname in subject if subject else None,
                cipher=cipher[0] if cipher else None,
                tls_version=version,
            )
    except Exception:
        return None
        return None


def analyze_whois(domain: str) -> WHOISInfo | None:
    """Perform WHOIS lookup for domain age and metadata."""
    try:
        import whois

        w = whois.whois(domain)
        info = WHOISInfo()
        if getattr(w, "creation_date", None):
            from datetime import datetime
            created = w.creation_date
            if isinstance(created, list):
                created = created[0]
            if isinstance(created, datetime):
                info.created = created.isoformat()
                age = (datetime.utcnow() - created).days
                info.domain_age_days = age
                info.newly_registered = age < 30
        if getattr(w, "registrar", None):
            info.registrar = w.registrar
        if getattr(w, "expiration_date", None):
            expires = w.expiration_date
            if isinstance(expires, list):
                expires = expires[0]
            if isinstance(expires, datetime):
                info.expires = expires.isoformat()
        if getattr(w, "status", None):
            info.status = w.status if isinstance(w.status, list) else [str(w.status)]
        return info
    except Exception:
        return None


def analyze_url(
    url: str,
    allow_outbound: bool = False,
    source_context: str | None = None,
) -> URLAnalysis:
    """Run full URL analysis pipeline.

    **Passive by default**: no network requests unless allow_outbound=True.
    """
    analysis = URLAnalysis(url=url, source_context=source_context)

    # Refanging
    if is_defanged(url):
        analysis.is_defanged = True
        url = refang(url)
        analysis.final_url = url

    # Parse domain parts
    parsed = urlparse(url)
    parsed.netloc.split(":")[0]
    analysis.raw_ip = is_raw_ip(url)

    # Extract domain, subdomain, TLD
    try:
        extracted = tldextract.extract(url)
        analysis.subdomain = extracted.subdomain or None
        analysis.domain = extracted.domain or None
        analysis.tld = extracted.suffix or None
    except Exception:
        pass

    # Homograph detection
    full_domain = parsed.netloc.split(":")[0]
    analysis.is_homograph = is_homograph(full_domain)

    # Shortener detection
    analysis.is_shortened = is_shortened(url)

    # Suspicious TLD
    analysis.suspicious_tld = is_suspicious_tld(full_domain)

    # DGA / entropy
    if analysis.domain:
        analysis.domain_entropy = domain_entropy(analysis.domain)
        analysis.dga_suspected = analysis.domain_entropy > 4.0

    # Outbound analysis (sandbox mode only)
    if allow_outbound:
        analysis.redirect_chain = trace_redirects(url, allow_outbound=True)
        if analysis.redirect_chain:
            analysis.final_url = analysis.redirect_chain[-1]

        if parsed.scheme == "https":
            analysis.ssl = analyze_ssl(url)

        if analysis.domain:
            analysis.whois = analyze_whois(f"{analysis.domain}.{analysis.tld}" if analysis.tld else analysis.domain)

    return analysis


def extract_and_analyze_urls(
    text: str | None,
    html: str | None,
    subject: str | None,
    headers: dict[str, list[str]] | None = None,
    allow_outbound: bool = False,
) -> list[URLAnalysis]:
    """Extract and analyze all URLs from email parts."""
    all_text = f"{text or ''}\n{html or ''}\n{subject or ''}"

    # Also scan key headers
    if headers:
        for key in ("Reply-To", "From", "Return-Path", "List-Unsubscribe"):
            for val in headers.get(key, []):
                all_text += f"\n{val}"

    raw_urls = extract_urls(all_text)

    # Determine source context for each URL (crude but effective)
    results: list[URLAnalysis] = []
    for url in raw_urls:
        source = "body"
        if subject and url in subject:
            source = "subject"
        elif html and url in html:
            source = "html"
        results.append(analyze_url(url, allow_outbound=allow_outbound, source_context=source))

    return results
