"""Data models for URL analysis results."""

from __future__ import annotations

from pydantic import BaseModel, Field


class SSLInfo(BaseModel):
    """SSL/TLS certificate details."""

    issuer: str | None = None
    subject: str | None = None
    valid_from: str | None = None
    valid_until: str | None = None
    domain_match: bool | None = None
    cipher: str | None = None
    tls_version: str | None = None
    days_until_expiry: int | None = None
    expired: bool | None = None


class WHOISInfo(BaseModel):
    """WHOIS / domain age metadata."""

    domain_age_days: int | None = None
    registrar: str | None = None
    created: str | None = None
    expires: str | None = None
    status: list[str] = Field(default_factory=list)
    newly_registered: bool | None = None


class URLAnalysis(BaseModel):
    """Complete URL analysis result."""

    url: str
    final_url: str | None = None
    redirect_chain: list[str] = Field(default_factory=list)
    is_shortened: bool = False
    is_homograph: bool = False
    is_defanged: bool = False
    suspicious_tld: bool = False
    raw_ip: bool = False
    domain_entropy: float | None = None
    domain: str | None = None
    subdomain: str | None = None
    tld: str | None = None
    ssl: SSLInfo | None = None
    whois: WHOISInfo | None = None
    vt_malicious: int | None = None
    urlscan_available: bool | None = None
    dga_suspected: bool = False
    source_context: str | None = None
