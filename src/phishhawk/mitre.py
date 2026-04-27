"""MITRE ATT&CK technique mapping — Phase 5.

Provides technique metadata and auto-mapping from PhishHawk findings.
"""

from __future__ import annotations

MITRE_TECHNIQUES: dict[str, dict[str, str]] = {
    "T1566.001": {
        "name": "Phishing: Spearphishing Attachment",
        "description": (
            "Adversaries may send spearphishing emails with a malicious attachment "
            "in an attempt to gain access to victim systems."
        ),
        "remediation": "Quarantine attachment; submit to sandbox; block sender domain.",
    },
    "T1566.002": {
        "name": "Phishing: Spearphishing Link",
        "description": (
            "Adversaries may send spearphishing emails with a malicious link "
            "in an attempt to gain access to victim systems."
        ),
        "remediation": "Block URL at proxy/firewall; inspect redirect chain; user awareness training.",
    },
    "T1566.003": {
        "name": "Phishing: Spearphishing via Service",
        "description": (
            "Adversaries may send spearphishing messages via third-party services "
            "in an attempt to gain access to victim systems."
        ),
        "remediation": "Monitor for suspicious use of legitimate services; block sender account.",
    },
    "T1204.002": {
        "name": "User Execution: Malicious File",
        "description": (
            "An adversary may rely upon a user opening a malicious file in order to gain execution."
        ),
        "remediation": "Disable Office macros via GPO; enforce AppLocker; user education.",
    },
    "T1656": {
        "name": "Impersonation",
        "description": (
            "Adversaries may impersonate users or entities in order to trick users "
            "into performing actions that benefit the adversary."
        ),
        "remediation": "Validate sender via secondary channel; enforce DMARC.",
    },
    "T1078": {
        "name": "Valid Accounts",
        "description": (
            "Adversaries may obtain and abuse credentials of existing accounts "
            "as a means of gaining Initial Access."
        ),
        "remediation": "Force password reset; enforce MFA; investigate account compromise.",
    },
    "T1589": {
        "name": "Gather Victim Identity Information",
        "description": "Adversaries may gather information about the identity of victims.",
        "remediation": "Monitor for reconnaissance; reduce public exposure of contact details.",
    },
    "T1598.003": {
        "name": "Phishing for Information: Spearphishing Link",
        "description": (
            "Adversaries may use spearphishing links to harvest credentials or other information."
        ),
        "remediation": "Block phishing domains; reset affected credentials; user awareness.",
    },
}

# Each entry is (list of lowercase keywords, technique_id)
MITRE_KEYWORD_MAP: list[tuple[list[str], str]] = [
    (["display name spoofing", "reply-to mismatch", "impersonation"], "T1656"),
    (["spf=fail", "dkim=fail", "dmarc=fail", "spf authentication failed", "dkim authentication failed", "dmarc authentication failed"], "T1566.001"),
    (["dangerous extension"], "T1566.001"),
    (["macros", "vba"], "T1204.002"),
    (["pdf javascript", "pdf js", "pdf embedded js"], "T1204.002"),
    (["yara"], "T1204.002"),
    (["homograph", "idn"], "T1566.002"),
    (["raw ip"], "T1566.002"),
    (["shortened", "shortener"], "T1566.003"),
    (["authentication failed", "no authentication-results"], "T1566.002"),
    (["alignment failed", "dmarc alignment"], "T1566.002"),
    (["timestamp drift"], "T1078"),
    (["free email provider"], "T1589"),
    (["credential harvesting", "credential"], "T1598.003"),
]


def map_findings_to_mitre(findings: list[str]) -> list[str]:
    """Return deduplicated list of MITRE technique IDs mapped from finding strings."""
    matched: list[str] = []
    for finding in findings:
        lower = finding.lower()
        for keywords, technique_id in MITRE_KEYWORD_MAP:
            if any(kw in lower for kw in keywords) and technique_id not in matched:
                matched.append(technique_id)
    return matched


def get_mitre_details(technique_ids: list[str]) -> list[dict[str, str]]:
    """Return technique metadata for display / reporting."""
    result: list[dict[str, str]] = []
    for tid in technique_ids:
        if tid in MITRE_TECHNIQUES:
            result.append({
                "id": tid,
                "name": MITRE_TECHNIQUES[tid]["name"],
                "description": MITRE_TECHNIQUES[tid]["description"],
                "remediation": MITRE_TECHNIQUES[tid]["remediation"],
            })
        else:
            result.append({"id": tid, "name": "Unknown", "description": "", "remediation": ""})
    return result


def build_recommendations(technique_ids: list[str]) -> list[str]:
    """Return remediation actions mapped from technique IDs."""
    recs: list[str] = []
    seen: set[str] = set()
    detail = get_mitre_details(technique_ids)
    for d in detail:
        rec = d["remediation"]
        if rec and rec not in seen:
            seen.add(rec)
            recs.append(rec)
    return recs
