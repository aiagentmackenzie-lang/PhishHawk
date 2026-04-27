"""Risk scoring engine v2 — live auth + static heuristics."""

from __future__ import annotations

from phishhawk.auth_models import AuthAnalysis
from phishhawk.models import CategoryScore, HeaderInfo, ParsedEmail, RiskLevel, RiskScore

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


def score_email(parsed: ParsedEmail, auth: AuthAnalysis | None = None) -> RiskScore:
    """Run all scoring modules and return aggregate risk."""
    categories: list[CategoryScore] = [
        score_authentication(parsed.headers, auth),
        score_attachments(parsed.attachments),
        score_headers(parsed.headers),
        CategoryScore(category="urls", score=0, findings=["URL analysis: Phase 3"]),
        CategoryScore(category="iocs", score=0, findings=["IOC extraction: Phase 5"]),
    ]

    total = sum(c.score for c in categories) // max(len(categories), 1)
    level = _level_from_score(total)

    return RiskScore(total=total, level=level, categories=categories)


def score_authentication(headers: HeaderInfo, auth: AuthAnalysis | None = None) -> CategoryScore:
    """Score email authentication posture using header heuristics + live DNS."""
    score = 0
    findings: list[str] = []

    # --- Header-based static checks ---
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

    # Reply-To / From mismatch
    if headers.reply_to and headers.from_address and headers.reply_to.lower() != headers.from_address.lower():
        score += 30
        findings.append(f"Reply-To mismatch: {headers.reply_to} vs {headers.from_address}")

    # Display name spoofing
    if headers.from_display_name and headers.from_address:
        name_lower = headers.from_display_name.lower()
        addr_lower = headers.from_address.lower()
        if any(s in name_lower for s in SUSPICIOUS_DISPLAY_NAMES) and not any(s in addr_lower for s in SUSPICIOUS_DISPLAY_NAMES):
            score += 35
            findings.append(
                f"Display name spoofing suspected: '{headers.from_display_name}'"
            )

    # --- Live DNS data (Phase 2) ---
    if auth:
        if auth.spf and auth.spf.valid is False:
            score += 20
            findings.append(f"SPF DNS record invalid for {auth.spf.domain}")
        if auth.dmarc and auth.dmarc.policy == "none":
            score += 15
            findings.append(f"DMARC policy is 'none' for {auth.dmarc.domain}")
        if auth.dmarc and auth.dmarc.policy == "reject":
            score -= 10  # bonus for strong policy
        if auth.alignment and not auth.alignment.dmarc_pass:
            score += 30
            findings.append("DMARC alignment failed (live DNS)")
        if auth.free_email_providers:
            score += 15
            findings.append(f"Free email provider: {', '.join(auth.free_email_providers)}")
        if auth.timestamp_drift_flagged:
            score += 10
            findings.append("Timestamp drift detected")
        # Aggregate any additional auth findings
        for finding in auth.findings:
            if finding not in findings:
                findings.append(finding)

    return CategoryScore(
        category="authentication",
        score=min(max(score, 0), 100),
        findings=findings or ["No obvious authentication issues"],
    )


def score_attachments(attachments: list) -> CategoryScore:
    """Score attachment risk."""
    score = 0
    findings: list[str] = []

    for att in attachments:
        if att.is_dangerous:
            score += 40
            findings.append(f"Dangerous extension: {att.filename}")
        if att.extension_mismatch:
            score += 25
            findings.append(f"Extension/MIME mismatch: {att.filename}")

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


def _level_from_score(score: int) -> RiskLevel:
    if score >= 80:
        return RiskLevel.CRITICAL
    if score >= 60:
        return RiskLevel.HIGH
    if score >= 40:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW
