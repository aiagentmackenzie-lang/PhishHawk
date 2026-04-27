# PhishHawk — Email Security / Phishing Analyzer
## System Requirements Document (SRD) v1.0

**Lead Security Systems Architect & Lead Engineer:** Agent Mackenzie 🔍  
**Project Owner:** Raphael (Uberaba, Brazil)  
**Classification:** Internal — SOC Portfolio Build  
**Date:** 2026-04-25  
**Status:** DRAFT — Pending Review  

---

## 1. Executive Summary

PhishHawk is a forensic-grade, CLI-first email security analyzer designed for SOC analysts, incident responders, and threat hunters. It ingests suspicious email files (`.eml`, `.msg`, `.mbox`), performs deep header authentication analysis (SPF/DKIM/DMARC alignment), detonates URLs and attachments via the HATCHERY sandbox subsystem, extracts IOCs with structured MITRE ATT&CK mapping, and produces analyst-ready reports in JSON, Markdown, and terminal-native formats.

PhishHawk is not a mail gateway. It is a **triage and forensics companion** for the 40%+ of Tier 1 analyst time spent on email security alerts. It answers the interview question every SOC analyst gets: *"How do you analyze a suspicious email?"*

---

## 2. Problem Statement & Opportunity

### 2.1 Why This Matters
- **91%** of cyberattacks start with phishing.
- **94%** of malware is delivered via email.
- Tier 1 SOC analysts spend **40%+** of their time triaging email alerts.
- Email headers contain **crucial attribution data** — originating IPs, SMTP path, auth results — that is routinely missed in manual triage.

### 2.2 The Real-World Kill Chain
```
1. Attacker registers typosquat: micros0ft-login.com
2. Sends email from spoofed: security@micros0ft-login.com
3. Email passes SPF (attacker controls domain) but DMARC fails
4. Link redirects: micros0ft-login.com → evil.com/login
5. Victim enters credentials → Attacker captures → Lateral movement
6. ANALYST runs PhishHawk on .eml → Finds DMARC fail + redirect chain + homograph
7. IOCs fed to threat intel → Blocks domain network-wide
```

### 2.3 Commercial Gaps
| Tool | Cost | Gap |
|------|------|-----|
| Proofpoint TAP | Enterprise $$$$ | Black box; no forensic CLI |
| Mimecast | Enterprise $$$$ | Cloud-only; limited IOC export |
| Cofense Triage | Enterprise $$$ | Requires Cofense ecosystem |
| KnowBe4 | Training focus | Not a forensic analyzer |

**Open-source tools exist but are fragmented.** No single open-source project combines: full auth validation + URL sandboxing + attachment detonation + IOC extraction + MITRE mapping.

---

## 3. Competitive Landscape (GitHub Research)

### 3.1 Direct Competitors Analyzed

| Project | Stars | Strengths | Weaknesses (Our Opportunity) |
|---------|-------|-----------|---------------------------|
| **ninoseki/eml_analyzer** | 344 | Mature, web UI, Docker, SpamAssassin | No CLI-native sandbox; no DMARC deep-dive; no attachment detonation |
| **0xlam/PhishSage** | 2 | Solid heuristics, YARA, WHOIS, VT | No `.msg`/`.mbox`; no attachment sandbox; no screenshot; no plugin arch |
| **Josperdo/reelphish** | 0 | Clean scoring, Reply-To mismatch | No auth record validation; no attachment analysis beyond metadata |
| **Rootless-Ghost/Phishing-Analyzer** | 0 | Beginner-friendly, suspicion scoring | Minimal; no sandboxing; no structured IOC output |
| **shubham8174/Phishing-Investigation-Framework** | 0 | MITRE mapping, JSON reports | No URL/attachment sandbox; no redirect tracing |
| **martinkubecka/mailo** | 5 | EML + MSG support, IOC extraction | No analysis engine; pure extraction only |
| **sp34rh34d/Smasher** | 8 | VT + MXToolbox integration | No auth analysis; no URL detonation; no batch mode |
| **wahlflo/eml_analyzer** | 115 | Clean CLI, JSON output, attachment list | No threat scoring; no sandbox; no auth checks |
| **qeeqbox/url-sandbox** | 196 | Full browser sandbox, screenshots | Standalone URL tool; no email integration |
| **seanthegeek/yaramail** | 21 | YARA scanning of email parts | No URL analysis; no auth validation |
| **InQuest/sandboxapi** | 143 | Unified sandbox API (Cuckoo, Triage, etc.) | Library only; no email parsing |
| **domainaware/checkdmarc** | PyPI leader | Gold-standard DMARC/SPF/DKIM validation | Standalone DNS tool; no email file input |
| **t0kubetsu/mailvalidator** | 0 | A+–F grading, TLS inspection, 104 DNSBLs | Domain assessor; does not analyze email *files* |

### 3.2 Market Gap Synthesis
**No open-source project unifies:**
1. Native `.eml`, `.msg`, `.mbox` parsing
2. Deep SPF/DKIM/DMARC **alignment** validation (not just header extraction)
3. URL sandboxing with redirect chain tracing + screenshot capture
4. Attachment detonation via internal sandbox (HATCHERY)
5. Structured IOC extraction with MITRE ATT&CK T1566 mapping
6. Plugin architecture for extensibility
7. Pure CLI with JSON/Markdown/terminal output — no web UI dependency

**PhishHawk fills this gap.**

---

## 4. Functional Requirements

### 4.1 Core Parser Module (PH-001)
| ID | Requirement | Priority |
|----|-------------|----------|
| FR-001 | Ingest `.eml` (RFC 5322), `.msg` (Outlook), `.mbox` (RFC 4155) | P0 |
| FR-002 | Parse MIME multipart structures: `text/plain`, `text/html`, `multipart/mixed`, `multipart/alternative`, `multipart/related`, `message/rfc822` | P0 |
| FR-003 | Extract all headers preserving order; normalize charsets (fallback to `utf-8`, `latin-1`, `cp1252`) | P0 |
| FR-004 | Extract body content (plain + HTML) for URL/entity analysis | P0 |
| FR-005 | Extract attachment metadata: filename, MIME type, size, disposition, content-id | P0 |
| FR-006 | Safely extract attachments to configurable temp directory with anti-overwrite guards | P0 |
| FR-007 | Compute file hashes: MD5, SHA1, SHA256 for all attachments | P0 |
| FR-008 | Detect and flag embedded images used as tracking pixels | P1 |
| FR-009 | Support nested email attachments (`.eml` inside `.eml`) recursively | P1 |

### 4.2 Header Authentication Analyzer (PH-002)
| ID | Requirement | Priority |
|----|-------------|----------|
| FR-010 | Extract `Received` chain; parse each hop for IP, HELO/EHLO, timestamp, protocol | P0 |
| FR-011 | Identify originating IP (first external `Received` hop) | P0 |
| FR-012 | Parse `Authentication-Results` header for SPF, DKIM, DMARC results | P0 |
| FR-013 | Perform live DNS lookup of SPF record; validate syntax and `all` qualifier | P0 |
| FR-014 | Perform live DNS lookup of DMARC record; validate policy (`p=none/quarantine/reject`), `pct`, `rua`, `ruf` | P0 |
| FR-015 | Perform live DNS lookup of DKIM record via common selectors (`default`, `google`, `selector1`, `selector2`, `mail`, `dkim`) | P0 |
| FR-016 | **DMARC Alignment Check**: compare `From` domain vs SPF domain (`SPF alignment`) and DKIM domain (`DKIM alignment`) | P0 |
| FR-017 | Detect `Reply-To` / `Return-Path` / `From` domain mismatches | P0 |
| FR-018 | Detect `From` display name spoofing (e.g., `"Amazon" <attacker@evil.com>`) | P0 |
| FR-019 | Flag free/disposable email providers in `Reply-To` and `Return-Path` | P1 |
| FR-020 | Timestamp sanity check: compare `Date` header vs first `Received` hop; flag excessive drift (>30 min) | P1 |
| FR-021 | Reverse DNS (PTR) lookup for originating IP | P1 |
| FR-022 | GeoIP lookup for originating IP (country, ASN, org) | P1 |

### 4.3 URL Analyzer & Sandbox Bridge (PH-003)
| ID | Requirement | Priority |
|----|-------------|----------|
| FR-023 | Extract all URLs from `text/plain`, `text/html`, `Subject`, and headers | P0 |
| FR-024 | Deduplicate URLs; normalize (defang/refang support: `hxxp`, `hxxps`, `[.]`) | P0 |
| FR-025 | Detect IDN homograph attacks (punycode decoding + mixed-script detection, e.g., `páypal.com`) | P0 |
| FR-026 | Detect URL shorteners (bit.ly, tinyurl, t.co, etc.) with expansion via `HEAD` following | P0 |
| FR-027 | Trace redirect chains (follow 301/302/307/308; limit configurable default 10) | P0 |
| FR-028 | Capture final landing page screenshot via headless browser (HATCHERY bridge) | P0 |
| FR-029 | Analyze SSL/TLS certificate: issuer, validity period, domain match, cipher strength | P0 |
| FR-030 | Compute domain Shannon entropy for DGA/obfuscation detection | P1 |
| FR-031 | Flag suspicious TLDs (`.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.xyz`, `.top`) | P1 |
| FR-032 | Detect raw IP URLs vs domain-based URLs | P1 |
| FR-033 | WHOIS lookup: domain age, registrar, expiration; flag newly registered (<30 days) | P1 |
| FR-034 | VirusTotal URL lookup (optional API key) | P1 |
| FR-035 | urlscan.io submission/lookup (optional API key) | P2 |
| FR-036 | HTML body hash for landing page similarity clustering | P2 |

### 4.4 Attachment Analyzer & HATCHERY Bridge (PH-004)
| ID | Requirement | Priority |
|----|-------------|----------|
| FR-037 | Flag dangerous extensions: `.exe`, `.scr`, `.bat`, `.cmd`, `.com`, `.pif`, `.vbs`, `.js`, `.jse`, `.wsf`, `.hta`, `.ps1`, `.sh`, `.jar`, `.dll` | P0 |
| FR-038 | Macro detection in Office docs via `oletools` (olevba, mraptor) | P0 |
| FR-039 | PDF analysis: JavaScript, embedded files, suspicious URLs via `pdfid.py` / `peepdf` patterns | P0 |
| FR-040 | YARA rule scanning against attachment payloads | P0 |
| FR-041 | **HATCHERY Integration**: Submit attachments to local HATCHERY sandbox for dynamic analysis | P0 |
| FR-042 | Parse HATCHERY report: behavioral score, network indicators, dropped files, MITRE mapping | P0 |
| FR-043 | ZIP/RAR/7z extraction with password brute-forcing against common passwords (` infected`, `malware`, `1234`, etc.) | P1 |
| FR-044 | OCR extraction from image attachments for embedded URLs/text | P2 |

### 4.5 IOC Extractor (PH-005)
| ID | Requirement | Priority |
|----|-------------|----------|
| FR-045 | Extract IPv4/IPv6 addresses (excluding RFC 1918 and link-local from body; flagging in headers) | P0 |
| FR-046 | Extract domains, subdomains, and FQDNs | P0 |
| FR-047 | Extract URLs (as above) | P0 |
| FR-048 | Extract email addresses (sender, recipient, CC, BCC, body) | P0 |
| FR-049 | Extract cryptographic artifacts: Bitcoin addresses, Ethereum addresses, XMR | P1 |
| FR-050 | Extract file hashes from body (MD5, SHA1, SHA256) | P1 |
| FR-051 | Extract callback/C2 indicators: User-Agents, file paths, registry keys (from HATCHERY bridge) | P1 |
| FR-052 | Output IOCs in MISP-compatible JSON format + STIX 2.1 indicators | P2 |

### 4.6 Risk Engine & Report Generator (PH-006)
| ID | Requirement | Priority |
|----|-------------|----------|
| FR-053 | Weighted risk scoring: 0–100 with `LOW`/`MEDIUM`/`HIGH`/`CRITICAL` bands | P0 |
| FR-054 | Per-category scoring: Headers, URLs, Attachments, Auth, IOCs | P0 |
| FR-055 | Terminal output: color-coded, Rich-powered tables and panels | P0 |
| FR-056 | JSON output: structured, schema-versioned for SIEM ingestion (Splunk, Sentinel, Elastic) | P0 |
| FR-057 | Markdown report: analyst-friendly with IOC tables and MITRE mapping | P0 |
| FR-058 | PDF report generation (optional, via `weasyprint` or similar) | P2 |
| FR-059 | Batch mode: analyze entire directory of `.eml`/`.msg`/`.mbox` files | P1 |
| FR-060 | Comparison mode: diff two email analyses (e.g., campaign variants) | P2 |

### 4.7 MITRE ATT&CK Mapping
| ID | Requirement | Priority |
|----|-------------|----------|
| FR-061 | Auto-map findings to MITRE ATT&CK techniques: T1566.001 (Spearphishing Attachment), T1566.002 (Spearphishing Link), T1598.003 (Credential Harvesting), T1656 (Impersonation) | P0 |
| FR-062 | Include technique IDs, names, and remediation actions in report | P0 |

---

## 5. Non-Functional Requirements

### 5.1 Performance
| ID | Requirement |
|----|-------------|
| NFR-001 | Single `.eml` analysis (no sandbox) completes in <5 seconds |
| NFR-002 | URL redirect chain + screenshot (HATCHERY) completes in <60 seconds |
| NFR-003 | Attachment detonation (HATCHERY) completes in <300 seconds |
| NFR-004 | Batch directory analysis rate: >10 emails/minute (non-sandboxed) |
| NFR-005 | Memory footprint: <512MB peak for single analysis |

### 5.2 Security & Safety
| ID | Requirement |
|----|-------------|
| NFR-006 | **Passive by default**: URLs are scored by inspection; no outbound HEAD/GET unless `--sandbox-urls` is set |
| NFR-007 | Attachment extraction uses `chmod 600` temp files; never executes attachments locally |
| NFR-008 | All detonation happens exclusively via HATCHERY sandbox API; no local execution |
| NFR-009 | Credential isolation: API keys (VT, urlscan) via environment variables or `.env` only; `.env` in `.gitignore` by default |
| NFR-010 | Input sanitization: defend against path traversal, zip bombs, and encoding attacks |
| NFR-011 | No telemetry; fully air-gappable |

### 5.3 Reliability & Robustness
| ID | Requirement |
|----|-------------|
| NFR-012 | Graceful degradation: if DNS/WHOIS/VT is unreachable, continue analysis and flag missing enrichment |
| NFR-013 | Charset fallback chain for malformed emails: `utf-8` → `latin-1` → `cp1252` → raw bytes with hex escapes |
| NFR-014 | Timeout configuration on all network operations (default 10s DNS, 30s HTTP) |
| NFR-015 | Rate limiting for external APIs (VT: 4 req/min free tier) |

### 5.4 Usability
| ID | Requirement |
|----|-------------|
| NFR-016 | Pure CLI — no web server, no database dependency for core analysis |
| NFR-017 | Self-documenting CLI via `typer` or `click` with `--help` for all subcommands |
| NFR-018 | Configuration via `config.toml` or environment variables |
| NFR-019 | Installable via `pip install phishhawk` (future) or `git clone + pip install -e .` |
| NFR-020 | Python 3.10+ support; macOS, Linux, WSL |

### 5.5 Extensibility
| ID | Requirement |
|----|-------------|
| NFR-021 | Plugin architecture: load custom analyzers from `~/.phishhawk/plugins/` |
| NFR-022 | Hook system: pre-analysis, post-analysis, pre-report hooks |
| NFR-023 | Custom YARA rule directory support |
| NFR-024 | Themeable terminal output (dark/light) |

---

## 6. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         PHISHHAWK CLI                                │
│  (typer/click argparse — subcommands: analyze, batch, config)      │
└─────────────────────────────────────────────────────────────────────┘
                                │
          ┌─────────────────────┼─────────────────────┐
          ▼                     ▼                     ▼
┌─────────────────┐  ┌─────────────────────┐  ┌─────────────────────┐
│  Email Parser   │  │   Auth Analyzer     │  │   IOC Extractor     │
│  ─────────────   │  │   ─────────────     │  │   ─────────────     │
│  • eml (stdlib) │  │  • checkdmarc lib   │  │  • ioc-fanger        │
│  • msg (extract-│  │  • dnspython        │  │  • regex extractors  │
│    msg / olefile)│  │  • alignment logic  │  │  • crypto parsers    │
│  • mbox (mailbox)│  │  • PTR / GeoIP      │  │  • MISP JSON builder │
└────────┬────────┘  └──────────┬──────────┘  └──────────┬──────────┘
         │                      │                        │
         └──────────────────────┼────────────────────────┘
                                ▼
              ┌─────────────────────────────────┐
              │       Risk Scoring Engine        │
              │  (weighted rules + thresholds)   │
              └─────────────────┬───────────────┘
                                │
          ┌─────────────────────┼─────────────────────┐
          ▼                     ▼                     ▼
┌─────────────────┐  ┌─────────────────────┐  ┌─────────────────────┐
│  URL Analyzer   │  │ Attachment Analyzer │  │  Report Generator   │
│  ────────────   │  │ ─────────────────── │  │  ────────────────   │
│  • URLExtract   │  │ • oletools          │  │  • Rich (terminal)  │
│  • requests     │  │ • yara-python       │  │  • JSON (SIEM)      │
│  • tldextract   │  │ • HATCHERY API      │  │  • Markdown (docs)  │
│  • IDN checker  │  │ • zipfile/rarfile   │  │  • PDF (optional)    │
│  • HATCHERY     │  │                     │  │                      │
│    screenshot   │  │                     │  │                      │
└─────────────────┘  └─────────────────────┘  └─────────────────────┘
         │                      │
         └──────────────────────┘
                     │
                     ▼
            ┌──────────────┐
            │   HATCHERY   │
            │   Sandbox    │
            │   Bridge     │
            └──────────────┘
```

### 6.1 Tech Stack
| Layer | Technology |
|-------|------------|
| CLI Framework | `typer` (Python 3.10+) or `click` |
| Terminal UI | `rich` (tables, panels, progress, syntax highlighting) |
| Email Parsing | `email` (stdlib), `extract-msg`, `mailbox` |
| Office/PDF | `oletools`, `pdfplumber` / `pikepdf` |
| YARA | `yara-python` |
| DNS/Auth | `dnspython`, `checkdmarc` (library), `geoip2` |
| HTTP/URL | `requests`, `urllib3`, `tldextract` |
| IDN/Unicode | `idna`, `unicodedata2` |
| Hashing | `hashlib` (stdlib) |
| Config | `pydantic-settings`, `toml` |
| Testing | `pytest`, `pytest-cov`, `responses` (HTTP mocking) |
| HATCHERY API | REST client via `httpx` |

---

## 7. Data Flow

```
Input: suspicious.eml
│
├─→ Parse MIME structure ─────────────────────────┐
│   ├─ Headers → Auth Analyzer                    │
│   │   ├─ SPF/DKIM/DMARC DNS validation          │
│   │   ├─ Alignment check                        │
│   │   ├─ Received chain reconstruction          │
│   │   └─ GeoIP + PTR lookup                     │
│   │                                             │
│   ├─ Body (text/html) → URL Extractor           │
│   │   ├─ IDN homograph detection                │
│   │   ├─ Shortener expansion                    │
│   │   ├─ Redirect chain trace                   │
│   │   ├─ SSL cert analysis                      │
│   │   └─ HATCHERY screenshot (if --sandbox)      │
│   │                                             │
│   ├─ Attachments → Attachment Analyzer          │
│   │   ├─ Hash (MD5/SHA1/SHA256)                │
│   │   ├─ Extension / MIME mismatch              │
│   │   ├─ Macro detection (oletools)              │
│   │   ├─ YARA scan                              │
│   │   └─ HATCHERY detonation (if --detonate)   │
│   │                                             │
│   └─ All parts → IOC Extractor                  │
│       ├─ IPs, domains, URLs, emails             │
│       ├─ Crypto addresses                       │
│       └─ File hashes                            │
│                                                 │
└─→ Risk Scoring Engine ←─────────────────────────┘
    ├─ Weighted aggregation (0–100)
    ├─ Per-category breakdown
    └─ MITRE technique mapping
│
Output Reports:
├─ Terminal (Rich, color-coded)
├─ JSON (schema-versioned, SIEM-ready)
├─ Markdown (analyst narrative + IOC tables)
└─ PDF (optional, future)
```

---

## 8. Integration Points

### 8.1 HATCHERY Sandbox API
```yaml
endpoint: "http://localhost:8000/api/v1/submit"
methods:
  POST /submit/file   # Attachment detonation
  POST /submit/url    # URL sandbox + screenshot
  GET  /report/{id}   # Retrieve analysis report
auth: "API_KEY via env HATCHERY_API_KEY"
```

### 8.2 External Threat Intel (Optional)
| Provider | Data | Config |
|----------|------|--------|
| VirusTotal | URL/Domain/File reputation | `VIRUSTOTAL_API_KEY` |
| urlscan.io | URL scan + screenshot | `URLSCAN_API_KEY` |
| AbuseIPDB | IP reputation | `ABUSEIPDB_API_KEY` |
| GeoIP2 | MaxMind GeoLite2 | `MAXMIND_LICENSE_KEY` |
| Spamhaus | DNSBL queries | Direct DNS queries |

### 8.3 SIEM / SOAR Integration
- JSON output schema is versioned and documented for Splunk HTTP Event Collector, Microsoft Sentinel Log Ingestion, and Elastic ingest pipelines.
- Batch mode supports output to newline-delimited JSON (NDJSON) for streaming ingestion.

---

## 9. CLI Interface Specification

```bash
# Single email analysis
phishhawk analyze suspicious.eml
phishhawk analyze suspicious.eml --sandbox-urls --detonate-attachments
phishhawk analyze suspicious.eml --output json --outfile report.json
phishhawk analyze suspicious.eml --output markdown --outfile report.md

# Batch analysis
phishhawk batch ./phishing_samples/ --output json --outfile batch.ndjson

# Enrichment-only modes
phishhawk headers suspicious.eml --enrich mx,spamhaus,domain_age
phishhawk urls suspicious.eml --trace-redirects --screenshots
phishhawk attachments suspicious.eml --yara-rules ./rules/ --hatchery

# Configuration
phishhawk config init          # Create ~/.phishhawk/config.toml
phishhawk config show          # Display effective configuration
```

---

## 10. Phased Build Plan

### Phase 1 — Foundation (Weeks 1–2)
- [ ] Project scaffold: `pyproject.toml`, `pytest`, `ruff`, `mypy`
- [ ] Core email parser (`.eml`, `.msg`, `.mbox`)
- [ ] Header extraction and `Received` chain parser
- [ ] Attachment metadata extraction + hashing
- [ ] Basic CLI with `typer`
- [ ] Terminal output with `rich`
- [ ] JSON output schema v1

### Phase 2 — Authentication Engine (Weeks 3–4)
- [ ] SPF/DKIM/DMARC DNS validation via `checkdmarc` + `dnspython`
- [ ] DMARC alignment logic (SPF alignment + DKIM alignment)
- [ ] Reply-To/From/Return-Path mismatch detection
- [ ] GeoIP + PTR lookups
- [ ] Risk scoring engine v1

### Phase 3 — URL Analysis (Weeks 5–6)
- [ ] URL extraction from text + HTML
- [ ] IDN homograph detection
- [ ] Redirect chain tracing
- [ ] SSL certificate analysis
- [ ] WHOIS + domain age
- [ ] VirusTotal/urlscan enrichment (optional)

### Phase 4 — Attachment Forensics (Weeks 7–8)
- [ ] Dangerous extension flagging
- [ ] Macro detection (`oletools`)
- [ ] PDF analysis
- [ ] YARA integration
- [ ] HATCHERY bridge: file submission + report parsing

### Phase 5 — IOC Extraction & Reporting (Weeks 9–10)
- [ ] IOC fanger/extractor
- [ ] MISP-compatible JSON export
- [ ] MITRE ATT&CK mapping
- [ ] Markdown report with IOC tables
- [ ] Batch mode + NDJSON output

### Phase 6 — Hardening & Polish (Weeks 11–12)
- [ ] Plugin architecture
- [ ] Comprehensive test suite (>80% coverage)
- [ ] CI/CD (GitHub Actions)
- [ ] Documentation site (MkDocs)
- [ ] Docker image
- [ ] PyPI publication

---

## 11. Success Criteria

| Metric | Target |
|--------|--------|
| Single `.eml` analysis time (no sandbox) | <5s |
| DMARC/SPF/DKIM alignment accuracy | >95% vs `checkdmarc` CLI baseline |
| URL redirect chain detection rate | 100% for chains ≤10 hops |
| IDN homograph detection | 100% for known attack patterns |
| Attachment macro detection | Match `olevba` baseline |
| IOC extraction precision | >90% precision, >85% recall vs manual extraction |
| Test coverage | ≥80% |
| Install friction | `pip install -e .` or `docker run` |

---

## 12. Risks & Mitigations

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| HATCHERY API unavailable | High | Medium | Graceful fallback; static analysis only |
| Rate limiting on VT/urlscan | Medium | High | Caching; configurable delays; queue system |
| Malformed email crashes parser | High | Medium | Extensive test corpus; fuzzing; defensive parsing |
| False positives in risk scoring | Medium | Medium | Tunerable thresholds; per-category scoring; analyst override flags |
| Dependency bloat | Low | Medium | Optional extras: `pip install phishhawk[all]` vs `[minimal]` |

---

## 13. Appendices

### Appendix A: JSON Output Schema (v1 Draft)
```json
{
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
      "iocs": 85
    }
  },
  "headers": { ... },
  "authentication": {
    "spf": { "record": "...", "result": "pass", "aligned": false },
    "dkim": { "selector": "default", "result": "fail", "aligned": false },
    "dmarc": { "record": "...", "result": "fail", "policy": "reject" }
  },
  "urls": [ ... ],
  "attachments": [ ... ],
  "iocs": { ... },
  "mitre": ["T1566.002", "T1598.003"],
  "recommendations": [ ... ]
}
```

### Appendix B: Reference Projects
- `ninoseki/eml_analyzer` — https://github.com/ninoseki/eml_analyzer
- `0xlam/PhishSage` — https://github.com/0xlam/PhishSage
- `Josperdo/reelphish` — https://github.com/Josperdo/reelphish
- `domainaware/checkdmarc` — https://github.com/domainaware/checkdmarc
- `qeeqbox/url-sandbox` — https://github.com/qeeqbox/url-sandbox
- `seanthegeek/yaramail` — https://github.com/seanthegeek/yaramail
- `InQuest/sandboxapi` — https://github.com/InQuest/sandboxapi
- `t0kubetsu/mailvalidator` — https://github.com/t0kubetsu/mailvalidator
- `wahlflo/eml_analyzer` — https://github.com/wahlflo/eml_analyzer
- `sp34rh34d/Smasher` — https://github.com/sp34rh34d/Smasher

---

**Document Owner:** Agent Mackenzie 🔍 — Lead Security Systems Architect / Lead Engineer  
**Review Status:** Pending Raphael Review  
**Next Action:** Approve SRD → Initiate Phase 1 Scaffold
