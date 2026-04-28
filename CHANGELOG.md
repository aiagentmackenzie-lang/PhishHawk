# Changelog

All notable changes to PhishHawk are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.1.0] — 2026-04-27

### Phase 1 — Core Engine
- Initial `.eml` parser with header extraction
- Risk scoring engine (0–100 scale)
- Terminal output with Rich panels
- JSON export

### Phase 2 — Header Forensics
- Authentication analysis (SPF, DKIM, DMARC)
- Received-hop timeline analysis
- Display name spoofing detection
- Free email provider detection
- Timestamp drift detection

### Phase 3 — URL Intelligence
- URL extraction from text, HTML, and headers
- Homograph attack detection
- URL shortener detection
- Suspicious TLD flagging
- DGA/entropy scoring
- Defang/refang handling
- Outbound SSL certificate analysis
- Outbound WHOIS domain age checks
- Redirect chain tracing

### Phase 4 — Attachment Forensics
- Dangerous extension detection
- Extension mismatch detection (MIME vs file magic)
- Office macro analysis (oletools/olevba)
- PDF JavaScript/suspicious object detection
- Archive extraction and nested scanning
- YARA rule matching (built-in + custom)
- HATCHERY sandbox integration

### Phase 5 — IOC Extraction & MITRE Mapping
- IPv4/IPv6/domain/URL/email extraction
- File hash computation (SHA-256)
- Cryptocurrency address detection
- MITRE ATT&CK mapping (T1566, T1598, etc.)
- STIX 2.1 output bundle
- MISP attribute export

### Phase 6 — Hardening & Polish
- Test coverage raised from 51% to 80% (176 tests)
- CI/CD pipeline (Python 3.12/3.13/3.14, Ruff lint, pytest, Docker build)
- Configuration system (TOML, env overrides, deep merge)
- Docker packaging (multi-stage, non-root, health check)
- Campaign comparison (diff two emails)
- Batch analysis mode
- Markdown report generation
- NDJSON streaming output

### Phase 7 — Production Readiness
- Test coverage raised from 80% to 92% (418+ tests)
- Architecture fixes: moved `_render_compare_markdown` to `markdown_out.py`
- Architecture fixes: replaced MD5 UUIDs with `uuid.uuid4()` in STIX output
- Architecture fixes: removed duplicate `return None` in `analyze_ssl()`
- Architecture fixes: removed redundant `_deep_merge(_DEFAULTS)` in config
- Architecture fixes: added `.docm` to macro detection extension set
- Added `CONTRIBUTING.md`
- Added `CHANGELOG.md`
- Added `.pre-commit-config.yaml`
- Added `LICENSE` (MIT)
- CI coverage gate updated to 90%