"""Tests for MISP and STIX 2.1 export — Phase 5."""

from __future__ import annotations

import json

from phishhawk.models import EmailAnalysis, HeaderInfo, IOCs, RiskLevel, RiskScore
from phishhawk.output.stix_out import export_misp, export_stix


def _sample_analysis() -> EmailAnalysis:
    return EmailAnalysis(
        file="suspicious.eml",
        file_hash="sha256:deadbeef",
        headers=HeaderInfo(subject="Invoice"),
        risk=RiskScore(total=75, level=RiskLevel.HIGH),
        iocs=IOCs(
            ipv4=["8.8.8.8"],
            domains=["evil.com"],
            urls=["https://evil.com/phish"],
            emails=["phish@evil.com"],
            file_hashes=["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
            crypto_addresses=["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"],
        ),
    )


def test_export_misp_structure() -> None:
    analysis = _sample_analysis()
    misp = export_misp(analysis)
    assert "Event" in misp
    event = misp["Event"]
    assert event["threat_level_id"] == "1"
    attrs = event["Attribute"]
    types = {a["type"] for a in attrs}
    assert "ip-dst" in types
    assert "domain" in types
    assert "url" in types
    assert "email" in types
    assert "sha256" in types
    assert "btc" in types


def test_export_misp_tags() -> None:
    analysis = _sample_analysis()
    misp = export_misp(analysis)
    tags = {t["name"] for t in misp["Event"]["Tag"]}
    assert any("high" in t for t in tags)


def test_export_stix_structure() -> None:
    analysis = _sample_analysis()
    stix = export_stix(analysis)
    assert stix["type"] == "bundle"
    assert stix["spec_version"] == "2.1"
    assert "objects" in stix
    indicators = stix["objects"]
    assert len(indicators) > 0
    for ind in indicators:
        assert ind["type"] == "indicator"
        assert ind["spec_version"] == "2.1"
        assert "pattern" in ind


def test_export_stix_confidence_high() -> None:
    analysis = _sample_analysis()
    stix = export_stix(analysis)
    for ind in stix["objects"]:
        assert ind["confidence"] == 75


def test_export_stix_no_duplicates() -> None:
    analysis = _sample_analysis()
    # Duplicate the same IOC to ensure dedup works
    analysis.iocs.ipv4.append("8.8.8.8")
    stix = export_stix(analysis)
    patterns = [ind["pattern"] for ind in stix["objects"]]
    assert len(patterns) == len(set(patterns))


def test_export_json_files(tmp_path) -> None:
    from phishhawk.output.stix_out import export_misp_json, export_stix_json

    analysis = _sample_analysis()
    misp_file = tmp_path / "misp.json"
    stix_file = tmp_path / "stix.json"
    export_misp_json(analysis, outfile=str(misp_file))
    export_stix_json(analysis, outfile=str(stix_file))
    assert misp_file.exists()
    assert stix_file.exists()
    assert json.loads(misp_file.read_text())["Event"]
    assert json.loads(stix_file.read_text())["type"] == "bundle"
