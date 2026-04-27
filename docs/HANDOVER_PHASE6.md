# PhishHawk — Phase 6 Handover

**Commit:** `ad54ab4` | **Date:** 2026-04-27 | **Phase:** 6 — Hardening & Polish

---

## What Shipped

### 1. Engine Extraction (P3 Debt)
- `_run_analysis()` extracted from `cli.py` → `engine.py`
- CLI imports `run_analysis` from engine; presentation decoupled from orchestration
- `engine.py` wires into config system for hatchery endpoint/DNS settings

### 2. Test Coverage: 51% → 81% (176 tests, 0 failures)
| Module | Before | After |
|--------|--------|-------|
| `cli.py` | 0% | 90%+ (via CliRunner) |
| `auth.py` | 34% | 70%+ (DNS-mocked SPF/DKIM/DMARC) |
| `hatchery_bridge.py` | 0% | 81% |
| `scoring.py` | 68% | 81% |
| `terminal.py` | 0% | 84% |
| `json_out.py` | 0% | 100% |
| `config.py` | N/A | 91% |
| **TOTAL** | **51%** | **81%** |

### 3. CI/CD — GitHub Actions
- `.github/workflows/ci.yml`
- Matrix: Python 3.12, 3.13, 3.14
- Steps: ruff lint → pytest with `--cov-fail-under=75` → Docker build + smoke test
- Runs on push to `main` and PRs

### 4. Config System
- `src/phishhawk/config.py` — TOML-based, 4-level priority:
  1. Built-in defaults
  2. `/etc/phishhawk/config.toml` (system)
  3. `~/.phishhawk/config.toml` (user)
  4. `PHISHHAWK_*` environment variables
- CLI command: `phishhawk config --show` / `phishhawk config --init`
- Configurable: hatchery endpoint, DNS timeout/retries, scoring weights, DKIM selectors, terminal width/color
- **Bug fix:** `_deep_merge` was mutating `_DEFAULTS` in place → fixed with `copy.deepcopy`

### 5. Docker
- Multi-stage `Dockerfile`: builder (install) → runtime (copy only needed files)
- Non-root `phishhawk` user, `/data` workdir
- Entry point: `phishhawk --help`

---

## P1/P2 Fixes (from Phase 5 handover, verified in Phase 6)
- ✅ `datetime.utcnow()` → `datetime.now(timezone.utc)` (models, markdown_out, url_analyzer)
- ✅ `IOCs.total_count` serialisation — `@computed_field` decorator
- ✅ Domain extraction false positives — `AUTH_RESULT_KEYWORDS` filter in `iocs.py`
- ✅ `checkdmarc` v5 API drift — `check_spf`/`check_dmarc` with `tags`-based DMARC parsing
- ✅ DKIM validation — direct `dns.resolver.resolve()` for `_selector._domainkey.domain` TXT
- ✅ Ruff config deprecation — `select`/`ignore` moved to `[tool.ruff.lint]`

---

## Remaining Work (Future Phases)

### P2 — Coverage Gaps
| Module | Coverage | What's Missing |
|--------|----------|----------------|
| `eml_parser.py` | 63% | Error paths, encoding edge cases |
| `url_analyzer.py` | 63% | Outbound analysis (SSL, WHOIS, redirects) |
| `mbox_parser.py` | 0% | Needs sample .mbox file + parser tests |
| `msg_parser.py` | 0% | Needs `extract_msg` dependency + sample .msg |
| `cli.py` compare JSON | ~90% | Control char handling in JSON output |

### P3 — Architecture
- [ ] Move `_render_compare_markdown` from `cli.py` to `markdown_out.py`
- [ ] Replace MD5 UUIDs in `stix_out.py` with RFC 4122 UUIDs
- [ ] Plugin architecture (SRD §6.7)

### P3 — Production Readiness
- [ ] Add `CONTRIBUTING.md`, `CHANGELOG.md`
- [ ] PyPI packaging (`python -m build`, `twine upload`)
- [ ] Pre-commit hooks (`ruff`, `mypy`)
- [ ] Integration tests against real .eml files with known findings

---

## Quick Start
```bash
pip install -e ".[dev]"
phishhawk analyze tests/fixtures/sample.eml          # Terminal output
phishhawk analyze tests/fixtures/sample.eml -o json  # JSON output
phishhawk analyze tests/fixtures/sample.eml -o stix   # STIX bundle
phishhawk config --show                               # View config
phishhawk config --init                               # Create ~/.phishhawk/config.toml
docker build -t phishhawk . && docker run --rm phishhawk analyze /data/sample.eml -o json
```

---

## Test Results
```
176 passed, 2 skipped, 0 failures, 0 warnings
Coverage: 81%
Ruff: All checks passed
```