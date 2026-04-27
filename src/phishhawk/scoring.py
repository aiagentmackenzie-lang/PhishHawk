"""Risk scoring engine v3 — auth + URL + static heuristics."""

from __future__ import annotations

from phishhawk.attachment_models import AttachmentForensics
from phishhawk.auth_models import AuthAnalysis
from phishhawk.models import CategoryScore, HeaderInfo, ParsedEmail, RiskLevel, RiskScore
from phishhawk.url_models import URLAnalysis

SUSPICIOUS_DISPLAY_NAMES = {
    "amazon",
    "apple",
    "microsoft",
    "google",
    "paypal",
    "bank",
    "netflix",
    "linkedin",
    "facebook",
    "twitter",
    "instagram",
    "wells fargo",
    "chase",
    "citi",
}


def score_email(
    parsed: ParsedEmail,
    auth: AuthAnalysis | None = None,
    urls: list[URLAnalysis] | None = None,
    forensics: list[AttachmentForensics] | None = None,
) -> RiskScore:
    """Run all scoring modules and return aggregate risk."""
    categories: list[CategoryScore] = [
        score_authentication(parsed.headers, auth),
        score_attachments(parsed.attachments, forensics or []),
        score_headers(parsed.headers),
        score_urls(urls or []),
        CategoryScore(category="iocs", score=0, findings=["IOC extraction: Phase 5"]),
    ]

    total = sum(c.score for c in categories) // max(len(categories), 1)
    level = _level_from_score(total)

    return RiskScore(total=total, level=level, categories=categories)


def score_authentication(headers: HeaderInfo, auth: AuthAnalysis | None = None) -> CategoryScore:
    """Score email authentication posture using header heuristics + live DNS."""
    score = 0
    findings: list[str] = []

    auth_header = headers.authentication_results or ""
    auth_lower = auth_header.lower()

    if "spf=pass" in auth_lower:
        score += 10
    if "dkim=pass" in auth_lower:
        score += 10
    if "dmarc=pass" in auth_lower:
        score += 10
    if "spf=fail" in auth_lower:
        score += 40
        findings.append("SPF authentication failed (header)")
    if "dkim=fail" in auth_lower:
        score += 30
        findings.append("DKIM authentication failed (header)")
    if "dmarc=fail" in auth_lower:
        score += 40
        findings.append("DMARC authentication failed (header)")
    if "spf=softfail" in auth_lower:
        score += 20
        findings.append("SPF softfail detected (header)")
    if not auth_header:
        score += 20
        findings.append("No Authentication-Results header")

    if headers.reply_to and headers.from_address and headers.reply_to.lower() != headers.from_address.lower():
        score += 30
        findings.append(f"Reply-To mismatch: {headers.reply_to} vs {headers.from_address}")

    if headers.from_display_name and headers.from_address:
        name_lower = headers.from_display_name.lower()
        addr_lower = headers.from_address.lower()
        if any(s in name_lower for s in SUSPICIOUS_DISPLAY_NAMES) and not any(s in addr_lower for s in SUSPICIOUS_DISPLAY_NAMES):
            score += 35
            findings.append(
                f"Display name spoofing suspected: '{headers.from_display_name}'"
            )

    if auth:
        if auth.spf and auth.spf.valid is False:
            score += 20
            findings.append(f"SPF DNS record invalid for {auth.spf.domain}")
        if auth.dmarc and auth.dmarc.policy == "none":
            score += 15
            findings.append(f"DMARC policy is 'none' for {auth.dmarc.domain}")
        if auth.dmarc and auth.dmarc.policy == "reject":
            score -= 10
        if auth.alignment and not auth.alignment.dmarc_pass:
            score += 30
            findings.append("DMARC alignment failed (live DNS)")
        if auth.free_email_providers:
            score += 15
            findings.append(f"Free email provider: {', '.join(auth.free_email_providers)}")
        if auth.timestamp_drift_flagged:
            score += 10
            findings.append("Timestamp drift detected")
        for finding in auth.findings:
            if finding not in findings:
                findings.append(finding)

    return CategoryScore(
        category="authentication",
        score=min(max(score, 0), 100),
        findings=findings or ["No obvious authentication issues"],
    )


def score_attachments(
    attachments: list,
    forensics: list[AttachmentForensics] | None = None,
) -> CategoryScore:
    """Score attachment risk with forensics."""
    score = 0
    findings: list[str] = []

    for att in attachments:
        if att.is_dangerous:
            score += 40
            findings.append(f"Dangerous extension: {att.filename}")
        if att.extension_mismatch:
            score += 25
            findings.append(f"Extension/MIME mismatch: {att.filename}")

    if forensics:
        for f in forensics:
            if f.office_macros and f.office_macros.has_macros:
                score += 35
                findings.append(f"VBA macros in {f.filename}: {f.office_macros.macro_count} module(s)")
                if f.office_macros.suspicious:
                    score += 25
                    findings.append(f"Suspicious macro keywords in {f.filename}")
            if f.pdf:
                if f.pdf.has_js:
                    score += 40
                    findings.append(f"PDF JavaScript in {f.filename}")
                if f.pdf.has_uris:
                    score += 15
                    findings.append(f"PDF embedded URIs in {f.filename}")
                if f.pdf.suspicious_objects_count > 0:
                    score += 20
                    findings.append(f"PDF {f.pdf.suspicious_objects_count} suspicious object(s) in {f.filename}")
            if f.yara and f.yara.match_count > 0:
                score += 30
                findings.append(f"YARA hits in {f.filename}: {f.yara.match_count} rule(s)")
            if f.hatchery:
                if f.hatchery.get("status") == "submitted":
                    findings.append(f"HATCHERY submitted: {f.filename}")
                elif f.hatchery.get("status") == "failed":
                    findings.append(f"HATCHERY unavailable for {f.filename}")

    return CategoryScore(
        category="attachments",
        score=min(score, 100),
        findings=findings or ["No suspicious attachments"],
    )


def score_headers(headers: HeaderInfo) -> CategoryScore:
    """Score header anomalies."""
    score = 0
    findings: list[str] = []

    if not headers.message_id:
        score += 15
        findings.append("Missing Message-ID")

    if len(headers.received) > 5:
        score += 10
        findings.append(f"Excessive Received hops ({len(headers.received)})")

    if not headers.date:
        score += 10
        findings.append("Missing Date header")

    return CategoryScore(
        category="headers",
        score=min(score, 100),
        findings=findings or ["Headers appear normal"],
    )


def score_urls(urls: list[URLAnalysis]) -> CategoryScore:
    """Score URL risk based on extracted and analyzed URLs."""
    score = 0
    findings: list[str] = []

    if not urls:
        return CategoryScore(
            category="urls",
            score=0,
            findings=["No URLs found in email"],
        )

    for u in urls:
        if u.is_homograph:
            score += 40
            findings.append(f"IDN homograph attack: {u.url}")
        if u.is_shortened:
            score += 25
            findings.append(f"Shortened URL: {u.url}")
        if u.suspicious_tld:
            score += 30
            findings.append(f"Suspicious TLD: {u.domain}.{u.tld}")
        if u.raw_ip:
            score += 35
            findings.append(f"Raw IP URL: {u.url}")
        if u.dga_suspected:
            score += 20
            findings.append(f"High entropy domain (possible DGA): {u.domain}")
        if u.ssl and u.ssl.expired:
            score += 15
            findings.append(f"Expired SSL certificate: {u.domain}")
        if u.whois and u.whois.newly_registered:
            score += 25
            findings.append(f"Newly registered domain (<30 days): {u.domain}")
        if u.is_defanged:
            score += 10
            findings.append(f"Defanged URL detected: {u.url}")

    return CategoryScore(
        category="urls",
        score=min(score, 100),
        findings=findings or ["No suspicious URLs detected"],
    )


def _level_from_score(score: int) -> RiskLevel:
    if score >= 80:
        return RiskLevel.CRITICAL
    if score >= 60:
        return RiskLevel.HIGH
    if score >= 40:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW
