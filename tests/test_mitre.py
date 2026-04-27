"""Tests for MITRE ATT&CK mapping — Phase 5."""

from __future__ import annotations

from phishhawk.mitre import (
    MITRE_TECHNIQUES,
    build_recommendations,
    get_mitre_details,
    map_findings_to_mitre,
)


def test_map_findings_to_mitre_display_name_spoofing() -> None:
    findings = ["Display name spoofing suspected: 'Amazon'"]
    result = map_findings_to_mitre(findings)
    assert "T1656" in result


def test_map_findings_to_mitre_auth_failures() -> None:
    findings = [
        "SPF authentication failed (header)",
        "DKIM authentication failed (header)",
    ]
    result = map_findings_to_mitre(findings)
    assert "T1566.001" in result
    assert "T1566.002" in result  # "authentication failed" also matches


def test_map_findings_to_mitre_multiple() -> None:
    findings = [
        "Display name spoofing suspected: 'Amazon'",
        "IDN homograph URL detected — possible phishing",
        "URL shortener used — inspect destination",
    ]
    result = map_findings_to_mitre(findings)
    assert "T1656" in result
    assert "T1566.002" in result
    assert "T1566.003" in result


def test_map_findings_to_mitre_no_match() -> None:
    result = map_findings_to_mitre(["Everything looks normal"])
    assert result == []


def test_get_mitre_details_known() -> None:
    details = get_mitre_details(["T1566.001"])
    assert len(details) == 1
    assert details[0]["id"] == "T1566.001"
    assert "Spearphishing Attachment" in details[0]["name"]
    assert details[0]["remediation"]


def test_get_mitre_details_unknown() -> None:
    details = get_mitre_details(["T9999.999"])
    assert details[0]["name"] == "Unknown"


def test_build_recommendations() -> None:
    recs = build_recommendations(["T1566.001", "T1656"])
    assert len(recs) >= 2
    assert all(isinstance(r, str) for r in recs)


def test_build_recommendations_dedup() -> None:
    # Passing duplicate technique IDs should not duplicate recs
    recs = build_recommendations(["T1566.001", "T1566.001"])
    # Should still only have one entry per unique remediation text
    assert len(recs) == 1


def test_all_techniques_have_fields() -> None:
    for tid, data in MITRE_TECHNIQUES.items():
        assert "name" in data
        assert "description" in data
        assert "remediation" in data
        assert tid.startswith("T")
