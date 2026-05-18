"""Markdown report generator — analyst-friendly narrative with IOC tables."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from phishhawk.mitre import get_mitre_details
from phishhawk.models import EmailAnalysis


def _iocs_table(iocs: list[str], bold: bool = True) -> str:
    """Build a markdown table for a list of strings."""
    if not iocs:
        return "_None detected_\n\n"
    lines = ["| Indicator |", "|-----------|"]
    for item in iocs:
        lines.append(f"| {item} |")
    return "\n".join(lines) + "\n\n"


def _risk_badge(level: str) -> str:
    return {
        "LOW": "🟢 LOW",
        "MEDIUM": "🟡 MEDIUM",
        "HIGH": "🔴 HIGH",
        "CRITICAL": "🔴🔴 CRITICAL",
    }.get(level.upper(), level)


def export_markdown(analysis: EmailAnalysis, outfile: str | None = None) -> str:
    """Render a forensic Markdown report from an EmailAnalysis object."""
    lines: list[str] = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Header
    lines.append("# PhishHawk Forensic Report\n")
    lines.append(f"**Analysis Date:** {now}  \n")
    lines.append(f"**File:** `{analysis.file}`  \n")
    lines.append(f"**SHA-256:** `{analysis.file_hash or 'N/A'}`  \n")
    lines.append(f"**Risk Score:** {analysis.risk.total}/100 — {_risk_badge(analysis.risk.level.value)}  \n")
    lines.append("\n---\n")

    # Executive Summary
    lines.append("## Executive Summary\n")
    if analysis.risk.level.value in ("HIGH", "CRITICAL"):
        lines.append(
            "⚠️ This email exhibits **high-risk indicators** and should be treated as a "
            "potential phishing or malware delivery attempt.\n\n"
        )
    elif analysis.risk.level.value == "MEDIUM":
        lines.append(
            "⚡ This email exhibits **medium-risk indicators**. Review the details below "
            "and validate sender authenticity before taking action.\n\n"
        )
    else:
        lines.append(
            "✅ This email exhibits **low-risk indicators**. No immediate action required, "
            "but consider standard hygiene checks.\n\n"
        )

    lines.append("### Category Breakdown\n\n")
    lines.append("| Category | Score | Findings |")
    lines.append("|----------|-------|----------|")
    for cat in analysis.risk.categories:
        findings = "; ".join(cat.findings[:3])
        if len(cat.findings) > 3:
            findings += f" (+{len(cat.findings) - 3} more)"
        lines.append(f"| {cat.category} | {cat.score}/{cat.max_score} | {findings} |")
    lines.append("")

    # Headers
    lines.append("\n---\n")
    lines.append("## Header Analysis\n")
    h = analysis.headers
    lines.append(f"- **Subject:** {h.subject or 'N/A'}")
    lines.append(f"- **From:** {h.from_address or 'N/A'}")
    if h.from_display_name:
        lines.append(f"- **Display Name:** {h.from_display_name}")
    lines.append(f"- **To:** {', '.join(h.to_addresses) or 'N/A'}")
    if h.cc_addresses:
        lines.append(f"- **CC:** {', '.join(h.cc_addresses)}")
    if h.reply_to:
        lines.append(f"- **Reply-To:** {h.reply_to}")
    if h.return_path:
        lines.append(f"- **Return-Path:** {h.return_path}")
    lines.append(f"- **Date:** {h.date.isoformat() if h.date else 'N/A'}")
    lines.append(f"- **Received Hops:** {len(h.received)}")
    lines.append("")

    # Authentication
    if analysis.authentication:
        lines.append("\n### Authentication Results\n")
        auth = analysis.authentication
        if auth.spf:
            status = "✅" if auth.spf.valid else "❌"
            lines.append(f"- **SPF** {status} `{auth.spf.domain}`")
        if auth.dkim:
            for dkim in auth.dkim:
                status = "✅" if dkim.valid else "❌"
                lines.append(f"- **DKIM** {status} `{dkim.domain}` (selector: `{dkim.selector}`)")
        if auth.dmarc:
            status = "✅" if auth.dmarc.valid else "❌"
            lines.append(f"- **DMARC** {status} `{auth.dmarc.domain}` (policy: `{auth.dmarc.policy or 'none'}`)")
        if auth.alignment:
            spf_a = "✅" if auth.alignment.spf_aligned else "❌"
            dkim_a = "✅" if auth.alignment.dkim_aligned else "❌"
            lines.append(f"- **Alignment** SPF={spf_a} DKIM={dkim_a}")
        if auth.free_email_providers:
            lines.append(f"- **Free Email Providers:** {', '.join(auth.free_email_providers)}")
        if auth.ptr:
            for p in auth.ptr[:3]:
                host = p.hostname or "No PTR"
                lines.append(f"- **PTR** `{p.ip}` → `{host}`")
        if auth.timestamp_drift_flagged:
            lines.append(f"- **Timestamp Drift:** {auth.timestamp_drift_seconds}s")
        lines.append("")

    # URLs
    if analysis.urls:
        lines.append("\n---\n")
        lines.append("## URL Analysis\n")
        lines.append("| URL | Flags |")
        lines.append("|-----|-------|")
        for u in analysis.urls:
            flags: list[str] = []
            if u.is_homograph:
                flags.append("homograph")
            if u.is_shortened:
                flags.append("shortened")
            if u.suspicious_tld:
                flags.append("suspicious-TLD")
            if u.raw_ip:
                flags.append("raw-IP")
            if u.dga_suspected:
                flags.append("DGA")
            if u.is_defanged:
                flags.append("defanged")
            if u.whois and u.whois.newly_registered:
                flags.append("new-domain")
            if not flags:
                flags.append("clean")
            display = u.url if len(u.url) <= 80 else u.url[:77] + "..."
            lines.append(f"| {display} | {', '.join(flags)} |")
        lines.append("")

    # Attachments
    if analysis.attachments:
        lines.append("\n---\n")
        lines.append("## Attachments\n")
        lines.append("| Filename | MIME Type | Size | Flags |")
        lines.append("|----------|-----------|------|-------|")
        for att in analysis.attachments:
            att_flags: list[str] = []
            if att.is_dangerous:
                att_flags.append("dangerous")
            if att.extension_mismatch:
                att_flags.append("ext-mismatch")
            f = next(
                (af for af in analysis.attachment_forensics if af.filename == att.filename),
                None,
            )
            if f:
                if f.office_macros and f.office_macros.has_macros:
                    att_flags.append("macros")
                if f.pdf and f.pdf.has_js:
                    att_flags.append("PDF-JS")
                if f.yara and f.yara.match_count > 0:
                    att_flags.append(f"YARA×{f.yara.match_count}")
            flag_str = ", ".join(att_flags) if att_flags else "clean"
            lines.append(f"| {att.filename} | {att.mime_type} | {att.size:,} | {flag_str} |")
        lines.append("")

    # IOCs
    iocs = analysis.iocs
    if iocs.total_count > 0:
        lines.append("\n---\n")
        lines.append("## Extracted IOCs\n")
        if iocs.ipv4:
            lines.append("### IPv4 Addresses\n")
            lines.append(_iocs_table(iocs.ipv4))
        if iocs.ipv6:
            lines.append("### IPv6 Addresses\n")
            lines.append(_iocs_table(iocs.ipv6))
        if iocs.domains:
            lines.append("### Domains\n")
            lines.append(_iocs_table(iocs.domains))
        if iocs.urls:
            lines.append("### URLs\n")
            lines.append(_iocs_table(iocs.urls))
        if iocs.emails:
            lines.append("### Email Addresses\n")
            lines.append(_iocs_table(iocs.emails))
        if iocs.file_hashes:
            lines.append("### File Hashes\n")
            lines.append(_iocs_table(iocs.file_hashes))
        if iocs.crypto_addresses:
            lines.append("### Cryptocurrency Addresses\n")
            lines.append(_iocs_table(iocs.crypto_addresses))

    # MITRE ATT&CK
    if analysis.mitre:
        lines.append("\n---\n")
        lines.append("## MITRE ATT&CK Mapping\n")
        details = get_mitre_details(analysis.mitre)
        for d in details:
            lines.append(f"### {d['id']} — {d['name']}\n")
            lines.append(f"- **Description:** {d['description']}\n")
            lines.append(f"- **Remediation:** {d['remediation']}\n")
        lines.append("")

    # Recommendations
    if analysis.recommendations:
        lines.append("\n---\n")
        lines.append("## Recommendations\n")
        for rec in analysis.recommendations:
            lines.append(f"- {rec}")
        lines.append("")

    # Footer
    lines.append("\n---\n")
    lines.append(f"*Report generated by PhishHawk v1.0.0 — {analysis.analysis_timestamp.isoformat()}*\n")

    md = "\n".join(lines)
    if outfile:
        Path(outfile).write_text(md)
    return md


def _build_diff(a1: EmailAnalysis, a2: EmailAnalysis) -> dict[str, Any]:
    """Build a structured diff dict for two analyses."""
    def _set(items: Iterable[str]) -> set[str]:
        return set(items)

    return {
        "risk_delta": a2.risk.total - a1.risk.total,
        "subject_match": (a1.headers.subject or "") == (a2.headers.subject or ""),
        "from_match": (a1.headers.from_address or "") == (a2.headers.from_address or ""),
        "shared_urls": list(_set(u.url for u in a1.urls) & _set(u.url for u in a2.urls)),
        "unique_urls_file1": list(_set(u.url for u in a1.urls) - _set(u.url for u in a2.urls)),
        "unique_urls_file2": list(_set(u.url for u in a2.urls) - _set(u.url for u in a1.urls)),
        "shared_domains": list(_set(a1.iocs.domains) & _set(a2.iocs.domains)),
        "unique_domains_file1": list(_set(a1.iocs.domains) - _set(a2.iocs.domains)),
        "unique_domains_file2": list(_set(a2.iocs.domains) - _set(a1.iocs.domains)),
        "shared_attachments": list(
            _set(a.sha256 for a in a1.attachments if a.sha256)
            & _set(a.sha256 for a in a2.attachments if a.sha256)
        ),
        "shared_mitre": list(_set(a1.mitre) & _set(a2.mitre)),
        "shared_emails": list(_set(a1.iocs.emails) & _set(a2.iocs.emails)),
    }


def render_compare_markdown(a1: EmailAnalysis, a2: EmailAnalysis) -> str:
    """Render a Markdown campaign comparison report for two analyses."""
    diff = _build_diff(a1, a2)
    check = "\u2705"
    cross = "\u274c"
    lines = [
        "# PhishHawk Campaign Comparison Report\n",
        f"| | **{Path(a1.file).name}** | **{Path(a2.file).name}** |",
        "|---|---|---|",
        f"| Risk Score | {a1.risk.total} | {a2.risk.total} |",
        f"| Risk Level | {a1.risk.level.value} | {a2.risk.level.value} |",
        f"| Delta | \u2014 | {'+' if diff['risk_delta'] > 0 else ''}{diff['risk_delta']} |",
        f"| Subject Match | {check if diff['subject_match'] else cross} | {check if diff['subject_match'] else cross} |",
        f"| From Match | {check if diff['from_match'] else cross} | {check if diff['from_match'] else cross} |",
        "",
        "## Shared URLs\n",
    ]
    if diff["shared_urls"]:
        for u in diff["shared_urls"]:
            lines.append(f"- {u}")
    else:
        lines.append("_None_")
    lines.append("")

    lines.append("## Unique URLs (File 1)\n")
    if diff["unique_urls_file1"]:
        for u in diff["unique_urls_file1"]:
            lines.append(f"- {u}")
    else:
        lines.append("_None_")
    lines.append("")

    lines.append("## Unique URLs (File 2)\n")
    if diff["unique_urls_file2"]:
        for u in diff["unique_urls_file2"]:
            lines.append(f"- {u}")
    else:
        lines.append("_None_")
    lines.append("")

    lines.append("## Shared MITRE ATT&CK Techniques\n")
    if diff["shared_mitre"]:
        for m in diff["shared_mitre"]:
            lines.append(f"- {m}")
    else:
        lines.append("_None_")
    lines.append("")

    lines.append("## Shared Attachment Hashes\n")
    if diff["shared_attachments"]:
        for h in diff["shared_attachments"]:
            lines.append(f"- `{h}`")
    else:
        lines.append("_None_")
    lines.append("")

    return "\n".join(lines)
