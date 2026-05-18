# PhishHawk Bug & Gap Log

**Session:** 2026-05-18  
**Lead:** Code Quality Controller (Pi)  
**Repo:** `/Users/main/Security Apps/PhishHawk`  
**Branch:** main  

## Initial Health Check
| Check | Result |
|-------|--------|
| `pytest tests/` | 418 passed, 2 skipped, 19 warnings (oletools dep) |
| Coverage | 92% overall |
| `ruff check src/ tests/` | Clean |
| `python -m phishhawk --help` | Returns CLI help |

---

## Bug Registry

### BUG-001 — STIX 2.1 indicator IDs are malformed
**File:** `src/phishhawk/output/stix_out.py`  
**Severity:** High (breaks STIX compatibility)  
**Details:** `_indicator()` built STIX IDs as `indicator--{uuid}-{len(seen)}`. STIX 2.1 mandates `type--UUIDv4/UUIDv5` with no extra suffix.  
**Fix:** Removed `-{len(seen)}` suffix. `seen` set already deduplicates.  
**Status:** ✅ Fixed

### BUG-002 — MISP timestamp uses non-portable `%s` strftime
**File:** `src/phishhawk/output/stix_out.py`  
**Severity:** Medium  
**Details:** `analysis.analysis_timestamp.strftime("%s")` is platform-dependent (Unix-only, not in CPython stdlib on Windows).  
**Fix:** Replaced with `int(analysis.analysis_timestamp.timestamp())`.  
**Status:** ✅ Fixed

### BUG-003 — Batch default output format/file mismatch
**File:** `src/phishhawk/cli.py`  
**Severity:** Low (UX)  
**Details:** `batch` defaulted to `output="json"` but `outfile="batch.ndjson"`, causing a JSON array inside a `.ndjson` file.  
**Fix:** Changed default `output` to `"ndjson"` to align with default filename.  
**Status:** ✅ Fixed

### BUG-004 — Compare JSON/Markdown output corrupted by Rich ANSI codes
**File:** `src/phishhawk/cli.py`  
**Severity:** Medium (machine-readability)  
**Details:** `compare` JSON and Markdown branches used `console.print(text)`, injecting ANSI escape sequences.  
**Fix:** Changed to `print(text)` and `print(md)` (consistent with `analyze` command).  
**Status:** ✅ Fixed

### BUG-005 — Dockerfile omits optional forensic dependencies
**File:** `Dockerfile`  
**Severity:** High (feature gaps in container)  
**Details:** `pip install .` only installed core deps. Missing `.msg` parsing, YARA, macro/PDF analysis, WHOIS, GeoIP.  
**Fix:** Changed install to `pip install ".[all]"`.  
**Status:** ✅ Fixed

### BUG-006 — Missing `python-whois` dependency in extras
**File:** `pyproject.toml`  
**Severity:** Medium  
**Details:** `url_analyzer.py` imports `whois` but it was not listed in any dependency group. WHOIS silently returned `None`.  
**Fix:** Added `python-whois>=0.8.0` to `[project.optional-dependencies].all`.  
**Status:** ✅ Fixed

### BUG-007 — CI Docker smoke test command is broken
**File:** `.github/workflows/ci.yml`  
**Severity:** Medium (CI failure)  
**Details:** `docker run --rm phishhawk:ci phishhawk --help` passed `phishhawk` as a subcommand to Typer.  
**Fix:** Changed to `docker run --rm phishhawk:ci --help`.  
**Status:** ✅ Fixed

### BUG-008 — README coverage threshold outdated
**File:** `README.md`  
**Severity:** Low (documentation drift)  
**Details:** README claimed `--cov-fail-under=75`. Actual CI enforces `90`. Also claimed "81% coverage" when coverage is `92%`.  
**Fix:** Updated README to `90` and adjusted coverage description.  
**Status:** ✅ Fixed

### BUG-009 — mypy type errors in attachment forensics + engine
**File:** `src/phishhawk/attachment_analyzer.py`, `src/phishhawk/engine.py`  
**Severity:** Low (type safety)  
**Details:** `dict[str, object]` return types caused 20+ mypy errors when accessing numeric keys or passing `.get()` results to typed constructors.  
**Fix:** Widened return annotations to `dict[str, Any]` across `analyze_office_macros`, `analyze_pdf`, `scan_yara`, `analyze_attachment`, `analyze_all_attachments`.  
**Status:** ✅ Fixed

### BUG-010 — mypy type error in eml_parser fallback decode
**File:** `src/phishhawk/eml_parser.py`  
**Severity:** Low  
**Details:** `part.get_payload(decode=True)` returns `Any`; mypy saw the decode chain returning `Any` instead of `str | None`.  
**Fix:** Added `isinstance(payload, bytes)` guard before decode loop.  
**Status:** ✅ Fixed

### BUG-011 — mypy type errors in markdown_out
**File:** `src/phishhawk/output/markdown_out.py`  
**Severity:** Low  
**Details:** Missing annotation on `_iocs_table()` parameter; `flags` redefined inside same function; missing return type on nested `_set` function.  
**Fix:** Added `iocs: list[str]`, renamed second `flags` to `att_flags`, typed `_set(items: Iterable[str])`.  
**Status:** ✅ Fixed

### BUG-012 — mypy type error in stix_out helper
**File:** `src/phishhawk/output/stix_out.py`  
**Severity:** Low  
**Details:** `_indicator()` could return `None` but annotation said `dict`.  
**Fix:** Changed to `dict | None` and added explicit `is not None` checks.  
**Status:** ✅ Fixed

### BUG-013 — mypy import-untyped for requests (url_analyzer + hatchery_bridge)
**File:** `src/phishhawk/url_analyzer.py`, `src/phishhawk/hatchery_bridge.py`  
**Severity:** Low  
**Details:** `import requests` missing stubs triggered `import-untyped`.  
**Fix:** Added `# type: ignore[import-untyped]`.  
**Status:** ✅ Fixed

### BUG-014 — mypy type error in config.py tomllib load
**File:** `src/phishhawk/config.py`  
**Severity:** Low  
**Details:** `tomllib.load(f)` returns `Any`; function declared to return `dict[str, Any]`.  
**Fix:** Assigned to annotated local `data: dict[str, Any]` before returning.  
**Status:** ✅ Fixed

### BUG-015 — mypy decorator error on computed_field + property
**File:** `src/phishhawk/models.py`  
**Severity:** Low (mypy limitation)  
**Details:** Pydantic v2 `@computed_field` on `@property` not supported by mypy.  
**Fix:** Added `# type: ignore[prop-decorator]`.  
**Status:** ✅ Fixed

---

## Post-Fix Health Check
| Check | Result |
|-------|--------|
| `pytest tests/` | 418 passed, 2 skipped |
| `ruff check src/ tests/` | Clean |
| `mypy src/phishhawk --ignore-missing-imports` | **0 errors** (28 files) |
| Coverage | 92% overall |

## Untouched / Non-Bug Observations
- **oletools DeprecationWarnings:** External dependency (oletools) emits PyparsingDeprecationWarnings. Not our code; safe to ignore via `-W ignore::DeprecationWarning` if desired.
- **Empty `samples/` directory:** README shows sample usage but repo ships no sample emails. Consider adding fixtures to `samples/`.
- **`analyze_whois` silently degrades:** When `python-whois` is absent, WHOIS returns `None`. Now listed in `[all]` extras.
