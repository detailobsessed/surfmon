# Code Review Guide

Quick reference for reviewing surfmon pull requests.

## Local Setup

```bash
git clone https://github.com/detailobsessed/surfmon.git
cd surfmon
uv sync          # installs all deps + dev tools
prek install     # installs git hooks (commit-msg, pre-commit, pre-push)
```

Requires **Python 3.14+** and [uv](https://docs.astral.sh/uv/).

## Running Checks

```bash
poe check        # lint (ruff) + typecheck (ty) in parallel
poe test         # pytest, excluding slow tests
poe test-all     # all tests including slow
poe test-cov     # tests with coverage (fails under 90%)
poe fix          # auto-fix lint + format
```

Individual tools:

```bash
uv run ruff check .          # lint only
uv run ruff format --check . # format check only
uv run ty check .            # type check only
uv run pytest -x -q          # quick test run, stop on first failure
uv run pytest --testmon      # run only tests affected by changes
```

## CI Pipeline

PRs run these jobs (all must pass via the `ci-pass` gate):

| Job | What it does |
| --- | --- |
| **changes** | Path filter — skips quality/tests if only non-source files changed |
| **links** | Lychee link checker on all markdown/HTML |
| **prek** | Full pre-commit suite (ruff, ruff-format, ty, gitleaks, shellcheck, actionlint, typos, markdownlint, ast-grep) |
| **quality** | Docs build check (zensical) |
| **tests** | pytest + coverage on Ubuntu, macOS, Windows x {highest, lowest-direct} resolution |

## Pre-commit Hooks (prek)

Hooks run automatically on commit/push. Key hooks:

- **pre-commit**: trailing whitespace, ruff lint+format, ty typecheck, ast-grep structural lint, pytest-testmon (affected tests only)
- **commit-msg**: conventional commits enforced (`feat`, `fix`, `refactor`, `test`, `docs`, `ci`, `chore`, `perf`, `style`, `build`)
- **pre-push**: full pytest with coverage (>=90%), docs build check

If a hook modifies files (e.g. ruff auto-fix), re-stage and commit again.

## What to Look For

### Architecture

```
src/surfmon/
    cli.py       # Typer CLI commands and display helpers
    config.py    # Target detection (stable/next/insiders), paths, env config
    monitor.py   # Core data collection — processes, language servers, MCP, PTYs, issue classification
    db.py        # SQLite persistence via sqlite-utils
    output.py    # Rich terminal display (tables, panels, styling) and Markdown export
```

- **`monitor.py`** owns all data collection, issue string construction, and severity classification. Constants like `ISSUE_CRITICAL_PREFIX` / `ISSUE_WARNING_PREFIX` and helpers like `max_issue_severity()` / `classify_issue_severity()` live here.
- **`output.py`** owns all Rich terminal rendering. `style_issue()` (per-issue colour markup) and `display_report()` live here.
- **`cli.py`** wires commands together — imports from both `monitor.py` and `output.py`. Display helpers specific to individual commands (e.g. `_display_ls_snapshot`) live here.
- **`db.py`** imports `classify_issue_severity` from `monitor.py` for storing issue severity. Uses `sqlite-utils` API — raw `db.execute()` is flagged by ast-grep rules.

### Conventions

- **Issue strings** use prefix markers: `✖` for critical, `⚠` for warnings. All issue-generating functions must use `ISSUE_CRITICAL_PREFIX` / `ISSUE_WARNING_PREFIX` constants, never raw Unicode.
- **Exit codes** for `check` and `ls-snapshot`: 0 (clean), 1 (warnings), 2 (critical). Other commands use standard exit codes.
- **`--json` flag** on commands must respect exit codes (compute severity before the JSON return path).
- **Ruff** is strict — extensive rule set in `pyproject.toml`. Line length is 140. Per-file ignores exist for tests, scripts, and cli.py.
- **Tests** use pytest classes (no `self` usage), `pytest-mock` for mocking, `pytest-randomly` for test order randomization. The `conftest.py` auto-sets a default target and mocks DB writes.
- **Commit messages** must follow [Conventional Commits](https://www.conventionalcommits.org/) — enforced by hook.

### Common Review Pitfalls

- New issue strings missing the `✖`/`⚠` prefix — causes severity misclassification
- `--json` code paths returning before exit code checks
- Display code double-rendering prefixes (once embedded in the string, once added by display logic)
- Forgetting to update both JSON and non-JSON paths when changing command behavior
- Using `db.execute()` instead of the sqlite-utils table API (flagged by ast-grep)
- Imports: `cli.py` imports from `output.py` but not vice versa (would create circular imports)

### Testing

- Tests live in `tests/` with one file per source module
- `test_cli.py` uses `typer.testing.CliRunner` with mocked `generate_report` / `capture_ls_snapshot`
- Issue strings in tests must include the prefix markers to match production behavior
- `pytest-testmon` tracks which tests are affected by changes — use `poe test-affected` for fast feedback

## PR Checklist

- [ ] `poe check` passes (lint + typecheck)
- [ ] `poe test` passes
- [ ] Commit messages follow conventional commits format
- [ ] New issue strings use `ISSUE_CRITICAL_PREFIX` / `ISSUE_WARNING_PREFIX`
- [ ] `--json` paths handle exit codes correctly
- [ ] Display helpers use `style_issue()` for Rich markup
- [ ] No circular imports between modules
