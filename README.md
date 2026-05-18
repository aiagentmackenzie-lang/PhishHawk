# PhishHawk 🔍

**Forensic-grade email security analyzer for SOC analysts, incident responders, and threat hunters.**

> *"How do you analyze a suspicious email?"* — Every SOC interview, ever.

PhishHawk ingests email files (`.eml`, `.msg`, `.mbox`), performs deep header authentication analysis (SPF/DKIM/DMARC), detects URL obfuscation and redirect chains, scans attachments for macros and YARA matches, extracts structured IOCs, maps findings to MITRE ATT&CK, and produces analyst-ready reports — terminal, JSON, Markdown, STIX, and MISP formats.

## Features

- **Multi-format parsing** — `.eml` (RFC 5322), `.msg` (Outlook), `.mbox` (RFC 4155)
- **Deep header authentication** — SPF, DKIM, DMARC alignment validation (live DNS)
- **URL forensics** — Redirect tracing, IDN homograph detection, SSL analysis, WHOIS, defang/refang
- **Attachment analysis** — Hashing, macro detection, PDF analysis, YARA scanning, sandbox detonation (HATCHERY)
- **IOC extraction** — IPs, domains, URLs, emails, crypto addresses, file hashes — with MISP-compatible output
- **MITRE ATT&CK mapping** — Auto-mapping to T1566 (Phishing), T1598 (Credential Harvesting), T1656 (Spoofing)
- **Campaign comparison** — Side-by-side diff of two emails (shared IOCs, risk delta, URL overlap)
- **5 output formats** — Terminal (Rich), JSON (SIEM), Markdown (reports), STIX 2.1, MISP
- **Configurable** — TOML config (`~/.phishhawk/config.toml`) + environment variable overrides
- **Batch mode** — Directory scanning with NDJSON output
- **Docker-ready** — Multi-stage Dockerfile, non-root user

## Quick Start

```bash
# Clone and install
git clone https://github.com/aiagentmackenzie-lang/PhishHawk.git
cd PhishHawk
pip install -e ".[dev]"

# Analyze a single email (terminal output)
phishhawk analyze suspicious.eml

# JSON output (pipe to SIEM)
phishhawk analyze suspicious.eml -o json

# STIX 2.1 bundle
phishhawk analyze suspicious.eml -o stix

# MISP-compatible JSON
phishhawk analyze suspicious.eml -o misp

# Markdown report (write to file)
phishhawk analyze suspicious.eml -o markdown -f report.md

# With sandbox URL analysis and attachment detonation
phishhawk analyze suspicious.eml --sandbox-urls --detonate-attachments

# Batch analysis (NDJSON)
phishhawk batch ./phishing_samples/ -o ndjson -f batch.ndjson

# Compare two emails (campaign variant diff)
phishhawk compare phishing1.eml phishing2.eml -o json

# View / initialise configuration
phishhawk config --show
phishhawk config --init
```

## Docker

```bash
docker build -t phishhawk .
docker run --rm -v $(pwd)/emails:/data phishhawk analyze /data/suspicious.eml -o json
```

## Output Formats

| Format | Flag | Use Case |
|--------|------|----------|
| Terminal | `-o terminal` | Interactive triage |
| JSON | `-o json` | SIEM ingestion, automation |
| Markdown | `-o markdown` | Written reports, case notes |
| STIX 2.1 | `-o stix` | Threat intelligence sharing |
| MISP | `-o misp` | MISP feed import |

## Configuration

PhishHawk loads settings from (lowest → highest priority):

1. **Built-in defaults**
2. `/etc/phishhawk/config.toml` (system)
3. `~/.phishhawk/config.toml` (user)
4. `PHISHHAWK_*` environment variables

```bash
# Create default config
phishhawk config --init

# Override via env
PHISHHAWK_DNS_TIMEOUT=20 phishhawk analyze email.eml
```

Example `~/.phishhawk/config.toml`:

```toml
[hatchery]
endpoint = "http://localhost:8000/api"
timeout = 30

[dns]
timeout = 10
retries = 2

[scoring.weights]
authentication = 30
headers = 15
urls = 25
attachments = 15
iocs = 15

[dkim]
selectors = ["default", "google", "selector1", "selector2"]
```

## Architecture

```
┌──────────────────────────────────┐
│  CLI (Typer)  ──  Engine  ──  Config  │
└──────────────┬───────────────────┘
               │
    ┌──────────┼──────────┬──────────────┐
    ▼          ▼          ▼              ▼
┌────────┐ ┌────────┐ ┌──────────┐ ┌──────────┐
│ Parser │ │  Auth  │ │   URL    │ │  Attach  │
│        │ │Analyzer│ │ Analyzer │ │ Analyzer │
└────────┘ └────────┘ └──────────┘ └──────────┘
    │          │          │              │
    └──────────┴────┬─────┴──────────────┘
                    ▼
           ┌──────────────┐
           │ Risk Engine   │
           │ (weighted)    │
           └──────┬───────┘
                  │
    ┌─────────────┼─────────────┬──────────────┐
    ▼             ▼             ▼              ▼
┌────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
│Terminal│  │   JSON   │  │ Markdown │  │STIX/MISP │
│ (Rich) │  │  (SIEM)  │  │ (Report) │  │  (Intel)  │
└────────┘  └──────────┘  └──────────┘  └──────────┘
```

## Testing

```bash
# Run all tests (166+ tests, >90% coverage)
pytest tests/ -v -W error::DeprecationWarning

# With coverage
pytest tests/ --cov=src/phishhawk --cov-report=term-missing

# Lint
ruff check src/ tests/
```

## CI/CD

GitHub Actions runs on every push to `main` and PR:

- **Lint** — ruff check
- **Test** — Python 3.12, 3.13, 3.14 matrix, `--cov-fail-under=90`
- **Docker** — Build + smoke test (`phishhawk --help`)

## License

MIT — Built for the blue team.