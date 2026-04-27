"""Attachment forensics data models."""

from __future__ import annotations

from pydantic import BaseModel, Field


class OfficeMacroAnalysis(BaseModel):
    has_macros: bool = False
    macro_count: int = 0
    suspicious: bool = False
    suspicious_keywords: list[str] = Field(default_factory=list)
    vba_code_preview: str = ""


class PDFAnalysis(BaseModel):
    has_js: bool = False
    has_uris: bool = False
    suspicious_objects_count: int = 0
    object_summary: list[str] = Field(default_factory=list)
    urls_found: list[str] = Field(default_factory=list)
    num_pages: int = 0


class YARAResult(BaseModel):
    matches: list[str] = Field(default_factory=list)
    match_count: int = 0
    rules_loaded: int = 0


class AttachmentForensics(BaseModel):
    """Complete static forensics for a single attachment."""

    filename: str
    sha256: str | None = None
    mime_type: str | None = None
    is_dangerous: bool = False
    office_macros: OfficeMacroAnalysis | None = None
    pdf: PDFAnalysis | None = None
    yara: YARAResult | None = None
    archive_extracted: list[dict[str, object]] = Field(default_factory=list)
    hatchery: dict[str, object] | None = None
    findings: list[str] = Field(default_factory=list)
