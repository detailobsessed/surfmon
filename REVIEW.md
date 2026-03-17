# Code Review Guide

## What to Look For

### Architecture

```
src/surfmon/
    _constants.py        # Shared constants (exit codes, Issue/IssueSeverity, PTY thresholds)
    cli.py               # Typer CLI commands — wires data collection to display
    config.py            # Target detection (stable/next/insiders), paths, env config
    db.py                # SQLite persistence via sqlite-utils
    display.py           # Interactive display helpers (watch-mode tables, history, PTY/LS snapshots, plots)
    language_servers.py  # LS detection, forensic snapshots, orphan/stale detection
    log_analysis.py      # Log file parsing and issue detection
    monitor.py           # Core orchestration — processes, MCP, snapshot capture, report assembly
    output.py            # Rich terminal display (tables, panels, styling) and Markdown export
    pty.py               # PTY leak detection — lsof parsing, PtyInfo dataclass, thresholds
    workspaces.py        # Active workspace detection — event log parsing, workspace lifecycle
```

- **`_constants.py`** is the single source for shared constants (`EXIT_OK/WARNING/CRITICAL`, `Issue`/`IssueSeverity`, PTY thresholds). All other modules import from here — never redefine these.
- **`monitor.py`** orchestrates data collection and assembles `MonitoringReport`. `max_issue_severity` lives here. Process detection (`get_windsurf_processes`, `is_main_windsurf_process`) and system info collection.
- **`language_servers.py`** owns all language server logic: `LsSnapshot`/`LsSnapshotEntry` dataclasses, `find_language_servers`, `capture_ls_snapshot`, orphan/stale workspace detection (`_build_ls_entry`). Uses `TYPE_CHECKING` import for `ProcessInfo` to avoid circular dependency with `monitor.py`.
- **`pty.py`** owns all PTY logic: `PtyInfo` dataclass (with `severity`/`color` properties), `check_pty_leak`, lsof parsing. Imports `_extract_windsurf_version` / `_get_windsurf_uptime` from `monitor.py` via a deferred import to avoid circular dependency.
- **`workspaces.py`** owns active workspace detection: event log parsing (`_parse_workspace_event`), workspace path resolution (`_resolve_workspace_path`), and `get_active_workspaces`.
- **`log_analysis.py`** owns log-file issue detection (`check_log_issues`). Imports `is_main_windsurf_process` from `monitor.py` via a deferred import.
- **`display.py`** owns interactive display: watch-mode summary tables, history table, PTY/LS forensic snapshot display, and matplotlib plot generation. Imports from `monitor.py`, `pty.py`, and `output.py`.
- **`output.py`** owns all Rich terminal rendering primitives. `style_issue()` and `display_report()` live here. No imports from other surfmon modules.
- **`cli.py`** wires commands together — imports from `monitor.py`, `display.py`, `output.py`, `db.py`, and `workspaces.py`. Lazy-imports `matplotlib` to avoid slowing CLI startup.
- **`db.py`** stores issue severity via `Issue.severity.value`. Uses `sqlite-utils` API — raw `db.execute()` is flagged by ast-grep rules.

### Conventions

- **Issues** use the `Issue` dataclass with an explicit `IssueSeverity` enum (`CRITICAL` / `WARNING`). All issue-generating functions must return `Issue` objects, never raw strings.
- **Exit codes** for `check` and `ls-snapshot`: 0 (clean), 1 (warnings), 2 (critical). Other commands use standard exit codes.
- **`--json` flag** on commands must respect exit codes (compute severity before the JSON return path).
- **Ruff** is strict — extensive rule set in `pyproject.toml`. Line length is 140. Per-file ignores exist for tests, scripts, and cli.py.
- **Tests** use pytest classes (no `self` usage), `pytest-mock` for mocking, `pytest-randomly` for test order randomization. The `conftest.py` auto-sets a default target and mocks DB writes.
- **Commit messages** must follow [Conventional Commits](https://www.conventionalcommits.org/) — enforced by hook.

### Common Review Pitfalls

- New issue code returning raw strings instead of `Issue` objects
- `--json` code paths returning before exit code checks
- Forgetting to update both JSON and non-JSON paths when changing command behavior
- Using `db.execute()` instead of the sqlite-utils table API (flagged by ast-grep)
- Imports: always import symbols from their defining module, not from a re-exporting intermediary (e.g. `from surfmon.pty import PtyInfo`, not `from surfmon.monitor import PtyInfo`)
- `output.py` has no imports from other surfmon modules — keep it that way to avoid circular imports
- `pty.py` and `log_analysis.py` use deferred imports from `monitor.py` to break circular dependencies — these are covered by `per-file-ignores` for `PLC0415` in `pyproject.toml`

### Testing

- Tests live in `tests/` with one file per source module: `test_cli.py`, `test_monitor.py`, `test_display.py`, `test_workspaces.py`, `test_pty.py`, `test_log_analysis.py`, `test_db.py`, `test_output.py`, `test_config.py`, `test_bugfixes.py`
- `test_cli.py` uses `typer.testing.CliRunner` with mocked `generate_report` / `capture_ls_snapshot`
- Issues in tests must use `Issue(IssueSeverity.*, "message")`, not raw strings
- `pytest-testmon` tracks which tests are affected by changes — use `poe test-affected` for fast feedback
- Test imports must reference the defining module directly, not monitor.py re-exports

## PR Checklist

- [ ] `poe check` passes (lint + typecheck)
- [ ] `poe test` passes
- [ ] Commit messages follow conventional commits format
- [ ] New issues use `Issue(IssueSeverity.*, "message")`, not raw strings
- [ ] `--json` paths handle exit codes correctly
- [ ] Display helpers use `style_issue()` for Rich markup
- [ ] No circular imports between modules
