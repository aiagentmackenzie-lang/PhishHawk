"""Data models for authentication analysis results."""

from __future__ import annotations

from pydantic import BaseModel, Field


class SPFResult(BaseModel):
    """SPF DNS validation result."""

    domain: str | None = None
    record: str | None = None
    valid: bool | None = None
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    dns_available: bool = True


class DKIMSelectorResult(BaseModel):
    """DKIM result for a specific selector."""

    selector: str
    domain: str | None = None
    record: str | None = None
    valid: bool = False
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    dns_available: bool = True


class DMARCResult(BaseModel):
    """DMARC DNS validation result."""

    domain: str | None = None
    record: str | None = None
    policy: str | None = None  # none, quarantine, reject
    pct: int | None = None
    rua: str | None = None
    ruf: str | None = None
    valid: bool | None = None
    alignment_required: bool = False
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    dns_available: bool = True


class AlignmentCheck(BaseModel):
    """DMARC alignment between From domain and auth domains."""

    from_domain: str | None = None
    spf_domain: str | None = None
    dkim_domain: str | None = None
    spf_aligned: bool = False
    dkim_aligned: bool = False
    dmarc_pass: bool = False
    reason: str | None = None


class PTRRecord(BaseModel):
    """Reverse DNS lookup result."""

    ip: str
    hostname: str | None = None
    dns_available: bool = True


class GeoIPResult(BaseModel):
    """GeoIP lookup result (stub for optional enricher)."""

    ip: str
    country: str | None = None
    city: str | None = None
    asn: str | None = None
    org: str | None = None
    enriched: bool = False


class AuthAnalysis(BaseModel):
    """Aggregate authentication analysis output."""

    spf: SPFResult | None = None
    dkim: list[DKIMSelectorResult] = Field(default_factory=list)
    dmarc: DMARCResult | None = None
    alignment: AlignmentCheck | None = None
    ptr: list[PTRRecord] = Field(default_factory=list)
    geoip: list[GeoIPResult] = Field(default_factory=list)
    free_email_providers: list[str] = Field(default_factory=list)
    timestamp_drift_seconds: int | None = None
    timestamp_drift_flagged: bool = False
    header_auth_results: str | None = None
    findings: list[str] = Field(default_factory=list)
