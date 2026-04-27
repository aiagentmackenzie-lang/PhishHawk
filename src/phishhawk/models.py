"""Pydantic data models for PhishHawk analysis pipeline."""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field

from phishhawk.auth_models import AuthAnalysis


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FileType(str, Enum):
    EML = "eml"
    MSG = "msg"
    MBOX = "mbox"


class ReceivedHop(BaseModel):
    """A single hop in the SMTP Received chain."""

    from_host: str | None = None
    by_host: str | None = None
    with_proto: str | None = None
    timestamp: datetime | None = None
    ip: str | None = None
    helo: str | None = None
    raw: str = ""


class AttachmentInfo(BaseModel):
    """Metadata and hashes for an email attachment."""

    filename: str
    mime_type: str = "application/octet-stream"
    size: int = 0
    content_disposition: str | None = None
    content_id: str | None = None
    md5: str | None = None
    sha1: str | None = None
    sha256: str | None = None
    is_dangerous: bool = False
    extension_mismatch: bool | None = None
    extracted_path: str | None = None


class HeaderInfo(BaseModel):
    """Parsed and normalized email headers."""

    subject: str | None = None
    from_address: str | None = None
    from_display_name: str | None = None
    to_addresses: list[str] = Field(default_factory=list)
    cc_addresses: list[str] = Field(default_factory=list)
    bcc_addresses: list[str] = Field(default_factory=list)
    reply_to: str | None = None
    return_path: str | None = None
    date: datetime | None = None
    message_id: str | None = None
    received: list[ReceivedHop] = Field(default_factory=list)
    authentication_results: str | None = None
    raw_headers: dict[str, list[str]] = Field(default_factory=dict)


class ParsedEmail(BaseModel):
    """Normalized representation of a parsed email file."""

    file_path: str
    file_type: FileType
    file_size: int = 0
    file_sha256: str | None = None
    headers: HeaderInfo = Field(default_factory=HeaderInfo)
    body_text: str | None = None
    body_html: str | None = None
    attachments: list[AttachmentInfo] = Field(default_factory=list)


class CategoryScore(BaseModel):
    """Per-category risk score breakdown."""

    category: str
    score: int = 0
    max_score: int = 100
    findings: list[str] = Field(default_factory=list)


class RiskScore(BaseModel):
    """Aggregate risk assessment."""

    total: int = 0
    level: RiskLevel = RiskLevel.LOW
    categories: list[CategoryScore] = Field(default_factory=list)


class URLInfo(BaseModel):
    """URL analysis findings."""

    url: str
    final_url: str | None = None
    redirect_chain: list[str] = Field(default_factory=list)
    is_shortened: bool = False
    is_homograph: bool = False
    suspicious_tld: bool = False
    raw_ip: bool = False
    domain_entropy: float | None = None


class IOCs(BaseModel):
    """Extracted indicators of compromise."""

    ipv4: list[str] = Field(default_factory=list)
    ipv6: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    emails: list[str] = Field(default_factory=list)
    file_hashes: list[str] = Field(default_factory=list)


class EmailAnalysis(BaseModel):
    """Top-level analysis output model (JSON schema v1)."""

    schema_version: str = "1.0.0"
    tool: str = "PhishHawk"
    analysis_timestamp: datetime = Field(default_factory=datetime.utcnow)
    file: str
    file_hash: str | None = None
    risk: RiskScore = Field(default_factory=RiskScore)
    headers: HeaderInfo = Field(default_factory=HeaderInfo)
    authentication: AuthAnalysis | None = None
    urls: list[URLInfo] = Field(default_factory=list)
    attachments: list[AttachmentInfo] = Field(default_factory=list)
    iocs: IOCs = Field(default_factory=IOCs)
    mitre: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    body_text: str | None = None
    body_html: str | None = None

    model_config = {"json_schema_extra": {
        "example": {
            "schema_version": "1.0.0",
            "tool": "PhishHawk",
            "analysis_timestamp": "2026-04-25T12:00:00Z",
            "file": "suspicious.eml",
            "file_hash": "sha256:a1b2c3...",
            "risk": {
                "score": 87,
                "level": "HIGH",
                "categories": {
                    "authentication": 95,
                    "urls": 80,
                    "attachments": 70,
                    "headers": 90,
                    "iocs": 85,
                },
            },
        }
    }}
