# PhishHawk 🔍

**Forensic-grade email security analyzer for SOC analysts, incident responders, and threat hunters.**

> *"How do you analyze a suspicious email?"* — Every SOC interview, ever.

PhishHawk ingests email files (`.eml`, `.msg`, `.mbox`), performs deep header authentication analysis (SPF/DKIM/DMARC), detonates URLs and attachments via sandbox integration, extracts IOCs with structured MITRE ATT&CK mapping, and produces analyst-ready reports in JSON, Markdown, and terminal-native formats.

## Features

- **Multi-format parsing**: `.eml` (RFC 5322), `.msg` (Outlook), `.mbox` (RFC 4155)
- **Deep header authentication**: SPF, DKIM, DMARC alignment validation
- **URL forensics**: Redirect tracing, IDN homograph detection, SSL analysis
- **Attachment analysis**: Hashing, macro detection, YARA scanning, sandbox detonation
- **IOC extraction**: Structured extraction with MISP-compatible output
- **MITRE ATT&CK mapping**: Auto-mapping to T1566, T1598, T1656
- **Analyst-ready output**: Terminal (Rich), JSON (SIEM), Markdown (reports)

## Quick Start

```bash
# Clone and install
git clone https://github.com/raphael/phishhawk.git
cd phishhawk
pip install -e ".[all]"

# Analyze a single email
phishhawk analyze suspicious.eml

# Analyze with sandboxing
phishhawk analyze suspicious.eml --sandbox-urls --detonate-attachments

# Batch analysis
phishhawk batch ./phishing_samples/ --output json --outfile batch.ndjson
```

## Architecture

PhishHawk is built as a modular, CLI-first Python application:

```
┌─────────────────┐
│   CLI (typer)   │
└────────┬────────┘
         │
    ┌────┴────┬────────────┬─────────────┐
    ▼         ▼            ▼             ▼
┌────────┐ ┌────────┐ ┌──────────┐ ┌──────────┐
│ Parser │ │  Auth  │ │   URL    │ │  Attach  │
│        │ │ Analyzer│ │ Analyzer │ │ Analyzer │
└────────┘ └────────┘ └──────────┘ └──────────┘
    │         │            │             │
    └─────────┴─────┬──────┴─────────────┘
                    ▼
           ┌──────────────┐
           │ Risk Engine  │
           └──────┬───────┘
                  │
    ┌─────────────┼─────────────┐
    ▼             ▼             ▼
┌────────┐  ┌──────────┐  ┌──────────┐
│Terminal│  │   JSON   │  │ Markdown │
│ (Rich) │  │  (SIEM)  │  │ (Report) │
└────────┘  └──────────┘  └──────────┘
```

## License

MIT — Built for the blue team.
