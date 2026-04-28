# Contributing to PhishHawk

Thanks for your interest in contributing! Here's how to get started.

## Setup

```bash
git clone https://github.com/aiagentmackenzie-lang/PhishHawk.git
cd PhishHawk
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install
```

## Development Workflow

1. **Create a branch** from `main`: `feat/your-feature` or `fix/your-fix`
2. **Write code + tests** — aim for 90%+ coverage on new code
3. **Run checks locally**:
   ```bash
   ruff check src/ tests/
   pytest --cov-fail-under=90
   ```
4. **Commit** with conventional commit messages:
   - `feat: add XYZ`
   - `fix: resolve ABC`
   - `test: add coverage for DEF`
   - `refactor: move GHI`
5. **Push & open a PR** — CI runs on Python 3.12, 3.13, 3.14

## Code Style

- **Formatter:** Ruff (Black-compatible defaults)
- **Line length:** 100
- **Type hints:** Required for all function signatures
- **Docstrings:** Google style for public functions

## Testing

- All new code must have tests
- Run the full suite: `pytest`
- Coverage gate: 90% (`--cov-fail-under=90`)
- Fixtures live in `tests/fixtures/`

## Reporting Bugs

Open a [GitHub Issue](https://github.com/aiagentmackenzie-lang/PhishHawk/issues) with:
- Python version, OS, PhishHawk version
- Minimal reproducible example
- Expected vs actual behavior

## Security Issues

**Do not file public issues for security vulnerabilities.**  
Email: security@phishhawk.dev (or DM the maintainer).

## License

By contributing, you agree your code is licensed under the [MIT License](LICENSE).