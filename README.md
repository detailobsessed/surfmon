# Surfmon

**Surf**ace **Mon**itor for Windsurf IDE - A comprehensive performance monitoring tool

A comprehensive monitoring tool for analyzing Windsurf IDE performance and resource usage.

## Features

- 📊 **Real-time process monitoring** - Track all Windsurf processes, memory, and CPU usage
- 🔍 **Language server detection** - Identify and monitor language servers (Java, Python, Windsurf's own, etc.)
- 🔌 **MCP server tracking** - List enabled MCP servers from configuration
- 📝 **Log analysis** - Detect common issues like extension host crashes and network timeouts
- 📤 **Multiple output formats** - Console (with colors), JSON, and Markdown
- ⚠️ **Issue detection** - Automatically identify configuration problems and performance issues

## Installation

```bash
cd surfmon
uv sync
```

## Usage

The tool provides a Typer-based CLI with multiple commands:

### Quick performance check

```bash
# Basic monitoring (console output)
uv run surfmon check

# Verbose mode (show all processes)
uv run surfmon check --verbose

# Save reports for later analysis
uv run surfmon check --json report.json --markdown report.md
```

### Continuous monitoring

```bash
# Watch mode - live updating dashboard
uv run surfmon watch

# Custom intervals
uv run surfmon watch -i 10 -s 600  # Check every 10s, save every 10min

# Run for specific number of checks
uv run surfmon watch -i 10 -n 720  # 720 checks at 10s intervals = 2 hours

# Custom output directory
uv run surfmon watch -o ~/my-windsurf-watch
```

### Compare reports

```bash
# Compare before/after reports
uv run surfmon compare before.json after.json
```

### Clean up orphaned processes

```bash
# Interactive cleanup (asks for confirmation)
uv run surfmon cleanup

# Force cleanup (no confirmation)
uv run surfmon cleanup --force
```

### Remove duplicate reports

```bash
# Dry run - see what would be deleted
uv run surfmon prune ../reports/watch --dry-run

# Actually delete duplicates (keeps latest by default)
uv run surfmon prune ../reports/watch

# Keep oldest instead of latest
uv run surfmon prune ../reports/watch --no-keep-latest
```

### Version info

```bash
uv run surfmon version
```

## What it monitors

### System Resources

- Total and available memory
- Memory usage percentage
- Swap usage
- CPU cores

### Windsurf Specific

- **Process count** - Number of Windsurf-related processes
- **Total memory** - Combined memory usage across all processes
- **Total CPU** - Combined CPU usage
- **Top processes** - Ranked by memory usage
- **Language servers** - Dedicated tracking for LS processes
- **Extensions count** - Number of installed extensions
- **MCP servers** - Which MCP servers are enabled

### Issue Detection

- **Orphaned crash handlers** - Detects chrome_crashpad_handler processes that remain after Windsurf closes
- Extension host crashes/exits
- Update service timeouts (NextDNS blocking)
- Telemetry connection failures
- `logs` directory in extensions folder (causes package.json errors)

## Exit codes

- `0` - Success, no issues detected
- `1` - Issues detected (check console output)
- `130` - Interrupted by user (Ctrl+C)

## Use cases

### 1. Before/after comparison

```bash
# Before making changes
uv run surfmon check --json before.json

# Make your changes (disable extensions, update NextDNS, etc.)

# After making changes
uv run surfmon check --json after.json

# Compare the reports
uv run surfmon compare before.json after.json
```

### 2. Continuous monitoring with live display

```bash
# Watch mode - live updating table, saves reports every 5 minutes
uv run surfmon watch

# Custom intervals
uv run surfmon watch -i 10 -s 600  # Check every 10s, save every 10min

# Run for specific duration (e.g., 2 hours = 720 checks at 10s intervals)
uv run surfmon watch -i 10 -n 720

# Custom output directory
uv run surfmon watch -o ~/my-windsurf-watch
```

This provides a **live dashboard** that updates every few seconds showing:

- Process count changes (↑/↓)
- Memory usage changes with color coding
- CPU usage trends
- Language server count
- Issue detection

**Historical tracking:** Watch mode saves timestamped JSON reports (e.g., `20260204-131500.json`) for historical analysis. If nothing changes between intervals, duplicate reports accumulate. Use `prune` to remove them:

```bash
uv run surfmon prune ../reports/watch --dry-run
```

Perfect for:

- Monitoring during long work sessions
- Detecting memory leaks over time
- Seeing immediate impact of changes
- Historical analysis of resource usage patterns

### 3. Automated health check

```bash
# Run as a health check (non-zero exit on issues)
if ! uv run surfmon check; then
    echo "Windsurf has issues!"
fi
```

## Common issues detected

| Issue | Cause | Fix |
| ----- | ----- | --- |
| Orphaned crash handlers | Windsurf bug - crash reporters not cleaned up on exit | `uv run surfmon cleanup --force` |
| `logs` directory error | Marimo extension creates logs in wrong place | `mv ~/.windsurf/extensions/logs ~/Library/Application\ Support/Windsurf/extension-logs/` |
| Update service timeouts | NextDNS blocking `windsurf-stable.codeium.com` | Whitelist `*.codeium.com` in NextDNS |
| Telemetry failures | NextDNS blocking `windsurf-telemetry.codeium.com` | Whitelist or disable telemetry |
| High memory usage | Too many language servers or extensions | Disable unused extensions |
| Multiple extension hosts | Extension crashes | Check logs for problematic extensions |

## Dependencies

- `psutil` - Cross-platform system and process utilities
- `rich` - Beautiful terminal output with tables and colors
- `typer` - CLI framework for future command expansion
- `pytest` + `pytest-cov` - Testing framework (dev)

## Requirements

- Python 3.14+ (managed by uv)
- macOS (currently, but easily portable to Linux/Windows)
- Windsurf IDE installed

## Development

### Package Structure

The tool is organized as a proper Python package:

```
surfmon/
├── src/windsurf_monitor/
│   ├── __init__.py
│   ├── cli.py              # Typer CLI with subcommands
│   ├── monitor.py          # Core monitoring logic
│   ├── output.py           # Display and formatting utilities
│   └── compare.py          # Report comparison utilities
├── tests/
│   └── test_monitor.py     # Comprehensive test suite (19 tests, 91% coverage)
├── main.py                 # Legacy script (deprecated)
├── compare.py              # Legacy script (deprecated)
├── watch.py                # Legacy script (deprecated)
├── monitor.sh              # Legacy script (deprecated)
└── pyproject.toml          # Project config with console script entry point
```

### Key Components

**Core Module** (`src/windsurf_monitor/monitor.py`):

- `ProcessInfo` - Dataclass for process information
- `SystemInfo` - Dataclass for system resources
- `MonitoringReport` - Complete report structure
- `generate_report()` - Main data collection function
- `get_windsurf_processes()` - Process detection
- `find_language_servers()` - Language server identification
- `get_mcp_config()` - MCP server configuration parsing
- `check_log_issues()` - Log analysis for common issues
- `save_report_json()` - JSON export

**CLI Module** (`src/windsurf_monitor/cli.py`):

- `check` - Quick performance check command
- `watch` - Continuous monitoring with live dashboard
- `compare` - Report comparison command
- `version` - Version information

**Output Module** (`src/windsurf_monitor/output.py`):

- `display_report()` - Rich terminal output formatting
- `save_report_markdown()` - Markdown export

**Compare Module** (`src/windsurf_monitor/compare.py`):

- `compare_reports()` - Before/after analysis with colored diffs
- `format_diff()` - Colored change formatting
- `load_report()` - JSON report loading

### Running Tests

```bash
# Run all tests
uv run pytest tests/ -v

# Run with coverage
uv run pytest tests/ --cov=windsurf_monitor --cov-report=term-missing

# Run specific test class
uv run pytest tests/test_monitor.py::TestGetWindsurfProcesses -v
```

**Test Coverage**: 19 tests covering 91% of code

- Process detection and error handling
- System info gathering
- Language server identification
- MCP config parsing
- Extension counting
- Log issue detection
- Full report generation

## Future Enhancements

### Planned

- [ ] Historical trend analysis (compare multiple JSON reports)
- [ ] Alerts when thresholds exceeded
- [ ] Extension-specific resource tracking
- [ ] Network connection monitoring
- [ ] Automatic issue remediation suggestions
- [ ] Web dashboard for reports
- [ ] Cross-platform support (Linux, Windows)
- [ ] Add tests for CLI, output, and compare modules

### Architecture Notes

The package uses a modern Typer-based CLI with proper testing infrastructure. Core logic is cleanly separated in the `src/windsurf_monitor` package, making it easy to add new commands or integrate the monitoring functionality into other tools.
