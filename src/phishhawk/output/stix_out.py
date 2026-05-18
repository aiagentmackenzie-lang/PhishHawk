"""MISP-compatible JSON export and optional STIX 2.1 indicators — Phase 5.

All exports are passive — no network calls.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from phishhawk.models import EmailAnalysis


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _uuid() -> str:
    """Generate RFC 4122 compliant UUID."""
    import uuid

    return str(uuid.uuid4())


def _ioc_to_misp_attr(ioc_type: str, value: str, category: str = "Network activity") -> dict:
    """Build a single MISP attribute dict."""
    return {
        "type": ioc_type,
        "value": value,
        "category": category,
        "to_ids": True,
        "comment": "Extracted by PhishHawk",
    }


def export_misp(analysis: EmailAnalysis) -> dict:
    """Return a MISP-compatible event dict from an EmailAnalysis."""
    attributes: list[dict] = []

    for ip in analysis.iocs.ipv4:
        attributes.append(_ioc_to_misp_attr("ip-dst", ip))
    for ip in analysis.iocs.ipv6:
        attributes.append(_ioc_to_misp_attr("ip-dst", ip))
    for domain in analysis.iocs.domains:
        attributes.append(_ioc_to_misp_attr("domain", domain))
    for url in analysis.iocs.urls:
        attributes.append(_ioc_to_misp_attr("url", url))
    for email in analysis.iocs.emails:
        attributes.append(_ioc_to_misp_attr("email", email, "Payload delivery"))
    for h in analysis.iocs.file_hashes:
        hash_type = "sha256" if len(h) == 64 else "sha1" if len(h) == 40 else "md5"
        attributes.append(_ioc_to_misp_attr(hash_type, h, "Payload delivery"))
    for crypto in analysis.iocs.crypto_addresses:
        attributes.append(_ioc_to_misp_attr("btc", crypto, "Financial fraud"))

    event = {
        "Event": {
            "info": f"PhishHawk analysis: {Path(analysis.file).name}",
            "threat_level_id": "1" if analysis.risk.level.value in ("HIGH", "CRITICAL") else "2",
            "analysis": "2",
            "distribution": "0",
            "timestamp": str(int(analysis.analysis_timestamp.timestamp())),
            "date": analysis.analysis_timestamp.strftime("%Y-%m-%d"),
            "Attribute": attributes,
            "Tag": [
                {"name": f"phishhawk:risk:{analysis.risk.level.value.lower()}"},
                {"name": f"phishhawk:score:{analysis.risk.total}"},
            ],
        }
    }
    return event


def export_stix(analysis: EmailAnalysis) -> dict:
    """Return a STIX 2.1 bundle with indicators for extracted IOCs."""
    indicators: list[dict] = []
    seen: set[str] = set()

    def _indicator(pattern: str, pattern_type: str, labels: list[str]) -> dict | None:
        key = f"{pattern_type}:{pattern}"
        if key in seen:
            return None
        seen.add(key)
        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{_uuid()}-{len(seen)}",
            "created": _now(),
            "modified": _now(),
            "name": f"PhishHawk: {pattern_type} indicator",
            "description": f"Extracted from {Path(analysis.file).name}",
            "pattern": pattern,
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": _now(),
            "labels": labels,
            "confidence": 75 if analysis.risk.level.value in ("HIGH", "CRITICAL") else 50,
        }

    for ip in analysis.iocs.ipv4:
        ind = _indicator(f"[ipv4-addr:value = '{ip}']", "ipv4-addr", ["malicious-activity"])
        if ind is not None:
            indicators.append(ind)
    for ip in analysis.iocs.ipv6:
        ind = _indicator(f"[ipv6-addr:value = '{ip}']", "ipv6-addr", ["malicious-activity"])
        if ind is not None:
            indicators.append(ind)
    for domain in analysis.iocs.domains:
        ind = _indicator(f"[domain-name:value = '{domain}']", "domain-name", ["malicious-activity"])
        if ind is not None:
            indicators.append(ind)
    for url in analysis.iocs.urls:
        ind = _indicator(f"[url:value = '{url}']", "url", ["malicious-activity"])
        if ind is not None:
            indicators.append(ind)
    for email in analysis.iocs.emails:
        ind = _indicator(f"[email-addr:value = '{email}']", "email-addr", ["malicious-activity"])
        if ind is not None:
            indicators.append(ind)
    for h in analysis.iocs.file_hashes:
        hash_type = "SHA-256" if len(h) == 64 else "SHA-1" if len(h) == 40 else "MD5"
        ind = _indicator(f"[file:hashes.{hash_type} = '{h}']", "file", ["malicious-activity"])
        if ind is not None:
            indicators.append(ind)

    bundle = {
        "type": "bundle",
        "id": f"bundle--{_uuid()}",
        "spec_version": "2.1",
        "objects": indicators,
    }
    return bundle


def export_misp_json(analysis: EmailAnalysis, outfile: str | None = None) -> str:
    """Serialize MISP event to JSON string. Optionally write to file."""
    data = export_misp(analysis)
    json_str = json.dumps(data, indent=2)
    if outfile:
        Path(outfile).write_text(json_str)
    return json_str


def export_stix_json(analysis: EmailAnalysis, outfile: str | None = None) -> str:
    """Serialize STIX bundle to JSON string. Optionally write to file."""
    data = export_stix(analysis)
    json_str = json.dumps(data, indent=2)
    if outfile:
        Path(outfile).write_text(json_str)
    return json_str
