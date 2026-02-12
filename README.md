# Surfmon

[![ci](https://github.com/detailobsessed/surfmon/workflows/ci/badge.svg)](https://github.com/detailobsessed/surfmon/actions?query=workflow%3Aci)
[![release](https://github.com/detailobsessed/surfmon/workflows/release/badge.svg)](https://github.com/detailobsessed/surfmon/actions?query=workflow%3Arelease)
[![documentation](https://img.shields.io/badge/docs-mkdocs-708FCC.svg?style=flat)](https://detailobsessed.github.io/surfmon/)
[![pypi version](https://img.shields.io/pypi/v/surfmon.svg)](https://pypi.org/project/surfmon/)
[![Python 3.14+](https://img.shields.io/badge/python-3.14+-blue.svg)](https://www.python.org/downloads/)
[![codecov](https://codecov.io/gh/detailobsessed/surfmon/branch/main/graph/badge.svg)](https://codecov.io/gh/detailobsessed/surfmon)

**Surf**ace **Mon**itor for Windsurf IDE — a performance monitoring and diagnostics tool for [Windsurf](https://codeium.com/windsurf) (Stable and Next).

## Installation

```bash
pip install surfmon
```

Or with [uv](https://docs.astral.sh/uv/):

```bash
uv tool install surfmon
```

For development:

```bash
git clone https://github.com/detailobsessed/surfmon.git
cd surfmon
uv sync
```

## Quick Start

```bash
# One-shot health check
surfmon check

# Verbose output with all process details
surfmon check -v

# Save reports (auto-named with timestamp)
surfmon check -s

# Target a specific Windsurf installation
surfmon check -t next
```

## Commands

### `check` — Quick Performance Snapshot

The main command. Shows system resources, Windsurf memory/CPU, active workspaces, top processes, and language servers in consistent fixed-width tables.

```bash
surfmon check                        # Basic check
surfmon check -v                     # Verbose (all processes)
surfmon check -s                     # Auto-save JSON + Markdown reports
surfmon check --json report.json     # Save JSON to specific path
surfmon check --md report.md         # Save Markdown to specific path
```

### `watch` — Live Monitoring Dashboard

Continuously monitors Windsurf with a live-updating terminal dashboard. Saves periodic JSON snapshots for historical analysis.

```bash
surfmon watch                          # Default: 5s interval, save every 5min
surfmon watch -i 10 -s 600             # Check every 10s, save every 10min
surfmon watch -i 10 -n 720             # 720 checks = 2 hours
surfmon watch -o ~/windsurf-reports    # Custom output directory
```

### `analyze` — Historical Trend Analysis

Analyzes JSON reports from `watch` sessions to detect memory leaks, process growth, and performance degradation. Optionally generates a 9-panel matplotlib visualization.

```bash
surfmon analyze reports/watch/20260204-134518/
surfmon analyze reports/watch/20260204-134518/ --plot
surfmon analyze reports/watch/20260204-134518/ --plot --output analysis.png
```

### `compare` — Before/After Diff

```bash
surfmon check --json before.json
# ... make changes ...
surfmon check --json after.json
surfmon compare before.json after.json
```

### `cleanup` — Remove Orphaned Processes

Detects and kills orphaned `chrome_crashpad_handler` processes left behind after Windsurf exits.

```bash
surfmon cleanup             # Interactive (asks for confirmation)
surfmon cleanup --force     # No confirmation
```

### `prune` — Deduplicate Watch Reports

Removes duplicate/identical JSON reports that accumulate during `watch` sessions when nothing changes.

```bash
surfmon prune reports/watch/20260204-134518/ --dry-run
surfmon prune reports/watch/20260204-134518/
```

## What It Monitors

**System** — Total/available memory, memory %, swap, CPU cores

**Windsurf Processes** — Process count, total memory & CPU, top 10 by memory, thread counts

**Language Servers** — Detects and tracks basedpyright, JDT.LS, Codeium language servers, YAML/JSON servers

**MCP Servers** — Lists enabled MCP servers from Codeium config

**Workspaces** — Active workspace paths and load times

**PTY Usage** — Windsurf PTY allocation vs system limits

**Issues** — Orphaned crash handlers, extension host crashes, update service timeouts (NextDNS), telemetry failures, `logs` directory in extensions folder

## Auto-Detection

Surfmon auto-detects whether Windsurf Stable or Windsurf Next is running and targets the active installation. Override with `-t stable` or `-t next`, or set `SURFMON_TARGET` in your environment.

## Exit Codes

- `0` — No issues detected
- `1` — Issues detected (see output)
- `130` — Interrupted (Ctrl+C)

## Common Issues

| Issue | Cause | Fix |
| ----- | ----- | --- |
| Orphaned crash handlers | Crash reporters not cleaned up on exit | `surfmon cleanup --force` |
| `logs` directory error | Marimo extension creates logs in wrong place | Move `~/.windsurf/extensions/logs` |
| Update service timeouts | NextDNS blocking `*.codeium.com` | Whitelist in NextDNS |
| High memory usage | Too many language servers or extensions | Disable unused extensions |

## Development

### Package Structure

```
src/surfmon/
    __init__.py        # Version
    cli.py             # Typer CLI — check, watch, compare, cleanup, prune, analyze
    config.py          # Target detection, paths, environment config
    monitor.py         # Core data collection — processes, language servers, MCP, PTYs
    output.py          # Rich terminal display and Markdown export
    compare.py         # Report comparison with colored diffs
tests/
    conftest.py        # Shared fixtures
    test_bugfixes.py   # Regression tests
    test_cli.py        # CLI command tests
    test_compare.py    # Report comparison tests
    test_config.py     # Configuration and target detection tests
    test_monitor.py    # Core monitoring logic tests
    test_output.py     # Display and formatting tests
```

### Running Tests

```bash
poe test              # Run tests
poe test-cov          # Run with coverage
poe lint              # Ruff check
poe typecheck         # ty check
```

### Dependencies

- **[psutil](https://github.com/giampaolo/psutil)** — Cross-platform process and system monitoring
- **[typer](https://github.com/fastapi/typer)** — CLI framework
- **[rich](https://github.com/Textualize/rich)** — Terminal output with tables and colors
- **[python-decouple](https://github.com/HBNetwork/python-decouple)** — Environment configuration
- **[matplotlib](https://matplotlib.org/)** — Visualization for `analyze` plots

### Requirements

- Python 3.14+
- macOS (tested), Linux (untested), Windows (untested) though it should work
- Windsurf IDE installed
