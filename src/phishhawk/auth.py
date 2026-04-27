"""Live DNS authentication analysis: SPF, DKIM, DMARC, PTR, GeoIP, alignment."""

from __future__ import annotations

import re
from datetime import datetime

import dns.resolver

from phishhawk.auth_models import (
    AlignmentCheck,
    AuthAnalysis,
    DKIMSelectorResult,
    DMARCResult,
    GeoIPResult,
    PTRRecord,
    SPFResult,
)
from phishhawk.headers import HeaderInfo, ReceivedHop

FREE_PROVIDERS: set[str] = {
    "gmail.com",
    "yahoo.com",
    "hotmail.com",
    "outlook.com",
    "aol.com",
    "protonmail.com",
    "mail.ru",
    "yandex.ru",
    "icloud.com",
    "live.com",
    "msn.com",
    "qq.com",
    "163.com",
    "126.com",
}

COMMON_DKIM_SELECTORS: list[str] = [
    "default",
    "google",
    "selector1",
    "selector2",
    "mail",
    "dkim",
    "smtp",
    "mx",
]


def _domain_from_address(addr: str | None) -> str | None:
    if not addr:
        return None
    if "@" in addr:
        return addr.split("@")[-1].strip().lower()
    return None


def _strip_angle_brackets(val: str | None) -> str | None:
    if not val:
        return None
    val = val.strip()
    if val.startswith("<") and val.endswith(">"):
        return val[1:-1]
    return val


def parse_auth_header(header: str | None) -> dict[str, str]:
    """Parse Authentication-Results header for SPF/DKIM/DMARC subresults."""
    out: dict[str, str] = {}
    if not header:
        return out
    header = _strip_angle_brackets(header) or ""
    for method in ("spf", "dkim", "dmarc"):
        # match spf=pass, spf=fail, etc.
        m = re.search(rf"{method}=(\w+)", header, re.IGNORECASE)
        if m:
            out[method] = m.group(1).lower()
    return out


def validate_spf(domain: str) -> SPFResult:
    """Validate SPF DNS record for a domain."""
    result = SPFResult(domain=domain)
    try:
        import checkdmarc

        check = checkdmarc.test_spf(domain)
        result.record = check.get("record", "")
        result.valid = check.get("valid", False)
        if "warnings" in check:
            result.warnings.extend(check["warnings"])
        if "errors" in check:
            result.errors.extend(check["errors"])
    except Exception as exc:
        result.dns_available = False
        result.errors.append(str(exc))
    return result


def validate_dmarc(domain: str) -> DMARCResult:
    """Validate DMARC DNS record for a domain."""
    result = DMARCResult(domain=domain)
    try:
        import checkdmarc

        check = checkdmarc.test_dmarc(domain)
        record = check.get("record", "")
        result.record = record
        result.valid = check.get("valid", False)
        # parse policy, pct, rua, ruf from record string
        if record:
            m = re.search(r"p=(\w+)", record)
            if m:
                result.policy = m.group(1).lower()
            m = re.search(r"pct=(\d+)", record)
            if m:
                result.pct = int(m.group(1))
            m = re.search(r"rua=([^;\s]+)", record)
            if m:
                result.rua = m.group(1)
            m = re.search(r"ruf=([^;\s]+)", record)
            if m:
                result.ruf = m.group(1)
        result.alignment_required = result.policy in ("quarantine", "reject")
        if "warnings" in check:
            result.warnings.extend(check["warnings"])
        if "errors" in check:
            result.errors.extend(check["errors"])
    except Exception as exc:
        result.dns_available = False
        result.errors.append(str(exc))
    return result


def validate_dkim(domain: str, selectors: list[str] | None = None) -> list[DKIMSelectorResult]:
    """Probe DKIM selectors for a domain."""
    if selectors is None:
        selectors = COMMON_DKIM_SELECTORS
    results: list[DKIMSelectorResult] = []
    for selector in selectors:
        r = DKIMSelectorResult(selector=selector)
        try:
            import checkdmarc

            check = checkdmarc.test_dkim(domain, selector)
            r.domain = domain
            r.record = check.get("record", "")
            r.valid = check.get("valid", False)
            if "warnings" in check:
                r.warnings.extend(check["warnings"])
            if "errors" in check:
                r.errors.extend(check["errors"])
        except Exception as exc:
            r.dns_available = False
            r.errors.append(str(exc))
        results.append(r)
    return results


def ptr_lookup(ip: str) -> PTRRecord:
    """Reverse DNS lookup for an IP address."""
    record = PTRRecord(ip=ip)
    try:
        # dnspython reverse lookup
        reversed_dns = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(reversed_dns, "PTR")
        if answers:
            record.hostname = str(answers[0]).rstrip(".")
    except Exception:
        record.dns_available = False
    return record


def geoip_lookup(ip: str) -> GeoIPResult:
    """Stub GeoIP lookup (requires MaxMind DB for full enrichment)."""
    return GeoIPResult(ip=ip, enriched=False)


def check_alignment(
    from_domain: str | None,
    spf_domain: str | None,
    dkim_domains: list[str],
    dmarc_policy: str | None,
) -> AlignmentCheck:
    """Check DMARC alignment: From domain vs SPF and DKIM domains."""
    alignment = AlignmentCheck(from_domain=from_domain)

    if spf_domain:
        alignment.spf_domain = spf_domain
        if from_domain:
            alignment.spf_aligned = from_domain.lower() == spf_domain.lower()

    for dkim_domain in dkim_domains:
        alignment.dkim_domain = dkim_domain
        if from_domain:
            alignment.dkim_aligned = from_domain.lower() == dkim_domain.lower()
            if alignment.dkim_aligned:
                break

    # DMARC pass if either SPF or DKIM aligned (and both pass at auth level)
    alignment.dmarc_pass = alignment.spf_aligned or alignment.dkim_aligned
    if dmarc_policy and not alignment.dmarc_pass:
        alignment.reason = f"DMARC policy={dmarc_policy}: neither SPF nor DKIM aligned with From domain"

    return alignment


def check_free_email(addresses: list[str | None]) -> list[str]:
    """Flag free/disposable email providers."""
    flagged: list[str] = []
    for addr in addresses:
        domain = _domain_from_address(addr)
        if domain and domain in FREE_PROVIDERS:
            flagged.append(f"{addr} ({domain})")
    return flagged


def check_timestamp_drift(
    date_header: datetime | None,
    first_received: ReceivedHop | None,
    threshold_seconds: int = 1800,
) -> tuple[bool, int | None]:
    """Compare Date header vs first Received hop timestamp."""
    if not date_header or not (first_received and first_received.timestamp):
        return False, None
    drift = abs(int((date_header - first_received.timestamp).total_seconds()))
    return drift > threshold_seconds, drift


def analyze_authentication(headers: HeaderInfo) -> AuthAnalysis:
    """Full authentication analysis pipeline."""
    analysis = AuthAnalysis(header_auth_results=headers.authentication_results)

    from_addr = headers.from_address
    from_domain = _domain_from_address(from_addr)
    return_path_domain = _domain_from_address(headers.return_path)
    reply_to_domain = _domain_from_address(headers.reply_to)

    header_auth = parse_auth_header(headers.authentication_results)
    analysis.findings.append(f"Header auth: SPF={header_auth.get('spf','unknown')} "
                              f"DKIM={header_auth.get('dkim','unknown')} "
                              f"DMARC={header_auth.get('dmarc','unknown')}")

    # Live DNS validation
    if from_domain:
        analysis.spf = validate_spf(from_domain)
        if not analysis.spf.valid:
            analysis.findings.append(f"SPF record invalid/missing for {from_domain}")
        analysis.dmarc = validate_dmarc(from_domain)
        if analysis.dmarc.policy:
            analysis.findings.append(f"DMARC policy for {from_domain}: p={analysis.dmarc.policy}")
        analysis.dkim = validate_dkim(from_domain)

    # Alignment
    spf_domain = return_path_domain or from_domain
    dkim_domains_found = [d.domain for d in analysis.dkim if d.domain and d.valid]
    analysis.alignment = check_alignment(
        from_domain, spf_domain, dkim_domains_found,
        analysis.dmarc.policy if analysis.dmarc else None,
    )
    if analysis.alignment and not analysis.alignment.dmarc_pass:
        analysis.findings.append("DMARC alignment failed (neither SPF nor DKIM domain matches From)")

    # Reply-To / From / Return-Path mismatch
    if reply_to_domain and from_domain and reply_to_domain != from_domain:
        analysis.findings.append(f"Reply-To domain mismatch: {reply_to_domain} != {from_domain}")
    if return_path_domain and from_domain and return_path_domain != from_domain:
        analysis.findings.append(f"Return-Path domain mismatch: {return_path_domain} != {from_domain}")

    # PTR on external Received hops
    for hop in headers.received:
        if hop.ip and not hop.ip.startswith(("127.", "10.", "192.168.", "172.16.")):
            ptr = ptr_lookup(hop.ip)
            analysis.ptr.append(ptr)
            if ptr.hostname:
                analysis.findings.append(f"PTR {hop.ip} -> {ptr.hostname}")

    # Free email providers
    free = check_free_email([headers.reply_to, headers.return_path])
    if free:
        analysis.free_email_providers = free
        analysis.findings.append(f"Free email detected: {', '.join(free)}")

    # Timestamp drift
    first_received = headers.received[-1] if headers.received else None
    drift_flagged, drift_secs = check_timestamp_drift(headers.date, first_received)
    analysis.timestamp_drift_flagged = drift_flagged
    analysis.timestamp_drift_seconds = drift_secs
    if drift_flagged and drift_secs is not None:
        analysis.findings.append(f"Timestamp drift: {drift_secs}s between Date and first Received")

    return analysis
