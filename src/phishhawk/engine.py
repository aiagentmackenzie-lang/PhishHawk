"""Core analysis engine — decoupled from CLI presentation.

This module contains _run_analysis() which was previously embedded in cli.py.
The CLI now delegates here for the analysis pipeline, keeping presentation
separate from orchestration.
"""

from __future__ import annotations

from phishhawk.attachment_analyzer import analyze_all_attachments
from phishhawk.attachment_models import AttachmentForensics
from phishhawk.auth import analyze_authentication
from phishhawk.iocs import extract_iocs
from phishhawk.mitre import build_recommendations, map_findings_to_mitre
from phishhawk.models import EmailAnalysis
from phishhawk.parser import parse_email
from phishhawk.scoring import score_email
from phishhawk.url_analyzer import extract_and_analyze_urls


def run_analysis(
    file: str,
    *,
    sandbox_urls: bool = False,
    detonate_attachments: bool = False,
    yara_rules: str | None = None,
) -> EmailAnalysis:
    """Core analysis pipeline — parse, enrich, score, map MITRE.

    Args:
        file: Path to the email file (.eml, .msg, .mbox).
        sandbox_urls: If True, enable outbound URL analysis (redirects, SSL, WHOIS).
        detonate_attachments: If True, submit attachments to HATCHERY sandbox.
        yara_rules: Optional path to a directory of YARA rules.

    Returns:
        EmailAnalysis with all findings populated.
    """
    parsed = parse_email(file)

    # Auth analysis
    auth = analyze_authentication(parsed.headers)

    # URL analysis
    urls = extract_and_analyze_urls(
        parsed.body_text,
        parsed.body_html,
        parsed.headers.subject,
        parsed.headers.raw_headers,
        allow_outbound=sandbox_urls,
    )

    # Attachment forensics
    forensics_raw = analyze_all_attachments(
        parsed.attachments, parsed.raw_payloads, yara_rules
    )
    forensics: list[AttachmentForensics] = []
    for fr in forensics_raw:
        f = (
            AttachmentForensics(
                filename=fr.get("filename", ""),
                sha256=fr.get("sha256"),
                mime_type=fr.get("mime_type"),
                is_dangerous=fr.get("is_dangerous", False),
                office_macros=fr.get("office_macros"),
                pdf=fr.get("pdf"),
                yara=fr.get("yara"),
                archive_extracted=fr.get("archive_extracted", []),
                findings=fr.get("findings", []),
            )
            if isinstance(fr, dict)
            else fr
        )

        if detonate_attachments:
            f.hatchery = {"status": "unavailable", "note": "HATCHERY not yet running"}
            f.findings.append("HATCHERY: unavailable — sandbox not yet running")

        forensics.append(f)

    # IOC extraction
    iocs = extract_iocs(parsed)

    # Scoring
    risk = score_email(parsed, auth, urls, forensics, iocs)

    # MITRE mapping — auto-map from all findings
    all_findings: list[str] = []
    for cat in risk.categories:
        all_findings.extend(cat.findings)
    mitre_ids = map_findings_to_mitre(all_findings)
    recs = build_recommendations(mitre_ids)
    if not recs:
        recs = ["No immediate action required"]

    return EmailAnalysis(
        file=parsed.file_path,
        file_hash=parsed.file_sha256,
        risk=risk,
        headers=parsed.headers,
        authentication=auth,
        urls=urls,
        attachments=parsed.attachments,
        attachment_forensics=forensics,
        iocs=iocs,
        mitre=mitre_ids,
        recommendations=recs,
        body_text=parsed.body_text,
        body_html=parsed.body_html,
    )