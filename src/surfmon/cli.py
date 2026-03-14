"""Typer-based CLI for Windsurf Performance Monitor."""

import json
import os
import signal
import sys
import time
from collections import defaultdict
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Protocol

import psutil
import typer

from . import __version__
from .config import TargetNotSetError, WindsurfTarget, get_paths, get_target, get_target_display_name, set_target
from .db import open_db, query_analyze_sessions, query_history_dicts, query_trend, store_check, store_ls_snapshot, store_pty_snapshot

if TYPE_CHECKING:
    from sqlite_utils import Database

from .monitor import (
    PTY_CRITICAL_COUNT,
    PTY_USAGE_CRITICAL_PERCENT,
    PTY_WARNING_COUNT,
    LsSnapshot,
    MonitoringReport,
    PtyInfo,
    _extract_windsurf_version,
    _get_windsurf_uptime,
    capture_ls_snapshot,
    check_pty_leak,
    collect_process_infos,
    format_uptime,
    generate_report,
    get_active_workspaces,
    is_main_windsurf_process,
    max_issue_severity,
)
from .output import (
    CPU_PERCENT_CRITICAL,
    CPU_PERCENT_WARNING,
    MB_PER_GB,
    WINDSURF_MEM_PERCENT_CRITICAL,
    WINDSURF_MEM_PERCENT_WARNING,
    Live,
    Table,
    _ls_entry_status_rich,
    console,
    display_report,
    make_kv_table,
    make_panel,
    make_table,
    style_issue,
)

# Language server snapshot thresholds
LS_TOTAL_MEM_CRITICAL_MB = 1024
LS_TOTAL_MEM_WARNING_MB = 512
LS_PROC_MEM_CRITICAL_MB = 500
LS_PROC_MEM_WARNING_MB = 200

# Analyze command thresholds
ANALYZE_MEM_GB_HIGH = 6
ANALYZE_MEM_GB_MEDIUM = 4
ANALYZE_PROC_CHANGE_SIGNIFICANT = 5
ANALYZE_MEM_CHANGE_LEAK_GB = 0.5
ANALYZE_MEM_CHANGE_GROWTH_GB = 0.2
MEM_DIFF_SIGNIFICANT_GB = 0.01
CPU_DIFF_SIGNIFICANT = 0.5


def _print_json(data: dict | list) -> None:
    """Print data as JSON to stdout for agent/pipe consumption."""
    print(json.dumps(data, indent=2, default=str))


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        typer.echo(f"surfmon {__version__}")
        raise typer.Exit


app = typer.Typer(
    name="surfmon",
    help="Monitor Windsurf IDE performance and resource usage",
    add_completion=False,
    context_settings={"help_option_names": ["-h", "--help"]},
)


@app.callback()
def main_callback(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-V",
            callback=version_callback,
            is_eager=True,
            help="Show version and exit.",
        ),
    ] = False,
) -> None:
    """Monitor Windsurf IDE performance and resource usage."""


_state: dict[str, bool] = {"stop_monitoring": False}


_TARGET_CHOICES = {"stable": WindsurfTarget.STABLE, "next": WindsurfTarget.NEXT, "insiders": WindsurfTarget.INSIDERS}


def target_callback(value: str | None) -> str | None:
    """Set the Windsurf target based on CLI option."""
    if value is not None:
        target = _TARGET_CHOICES.get(value.lower())
        if target is None:
            msg = f"Invalid target: {value}. Use 'stable', 'next', or 'insiders'."
            raise typer.BadParameter(msg)
        set_target(target)
    return value


def _require_target() -> None:
    """Abort with a helpful message if no target has been configured."""
    try:
        get_paths()  # triggers TargetNotSetError if unset
    except TargetNotSetError:
        console.print(
            "[red]Error: No Windsurf target specified.[/red]\n"
            "  Use [cyan]--target (-t)[/cyan] with one of: [green]stable[/green], [green]next[/green], [green]insiders[/green]\n"
            "  Or set [cyan]SURFMON_TARGET[/cyan] in your environment."
        )
        raise typer.Exit(code=1) from None


# Global option for target selection
TargetOption = Annotated[
    str | None,
    typer.Option(
        "--target",
        "-t",
        help="Required. Windsurf target: 'stable', 'next', or 'insiders'. Can also be set via SURFMON_TARGET env var.",
        callback=target_callback,
        is_eager=True,  # Process before other options
    ),
]


def _get_target_str() -> str:
    """Get the current target as a string for DB storage."""
    try:
        return get_target().value
    except TargetNotSetError:
        return ""


class _StoreFn[T](Protocol):
    """Callback signature shared by store_check, store_ls_snapshot, and store_pty_snapshot."""

    def __call__(self, db: Database, data: T, /, target: str = "") -> str: ...


def _store_to_db[T](store_fn: _StoreFn[T], data: T) -> None:
    """Best-effort DB write — log warning on failure, never crash."""
    try:
        with open_db() as db:
            store_fn(db, data, target=_get_target_str())
    except Exception as exc:
        print(f"DB write skipped: {exc}", file=sys.stderr)


def simplify_process_name(name: str) -> str:
    """Simplify Windsurf process names for plot legends.

    Extracts the helper type from names like "Windsurf Helper (GPU)"
    into "Windsurf Helper GPU" for cleaner display.
    """
    if "Helper" in name and "(" in name:
        return name.split("Helper", maxsplit=1)[0] + "Helper " + name.split("(")[1].split(")", maxsplit=1)[0]
    return name


def build_process_memory_history(reports: list[dict]) -> dict[str, list[float]]:
    """Build per-process memory history from a series of reports.

    Returns a dict mapping simplified process names to lists of memory values,
    one per report. Processes not present in a report get 0 for that position.
    """
    process_mem_history: dict[str, list[float]] = {}

    for report_idx, r in enumerate(reports):
        process_snapshot: dict[str, float] = defaultdict(float)
        for proc in r["windsurf_processes"]:
            name = simplify_process_name(proc["name"])
            process_snapshot[name] += proc["memory_mb"]

        # Append 0 for existing processes not in this snapshot
        for name, history in process_mem_history.items():
            if name not in process_snapshot:
                history.append(0)

        # For processes in this snapshot: pad with leading zeros if new, then append
        for name, mem in process_snapshot.items():
            if name not in process_mem_history:
                process_mem_history[name] = [0.0] * report_idx
            process_mem_history[name].append(mem)

    return process_mem_history


def signal_handler(_signum: int, _frame: object) -> None:
    """Handle interrupt signals gracefully."""
    _state["stop_monitoring"] = True
    console.print("\n[yellow]Stopping monitoring...[/yellow]")


def _format_change(diff: float, threshold: float = 0, fmt: str = "d", suffix: str = "") -> str:
    """Format a numeric diff as a Rich-styled change indicator.

    Returns empty string if abs(diff) <= threshold.
    """
    if abs(diff) <= threshold:
        return ""
    symbol = "↑" if diff > 0 else "↓"
    color = "red" if diff > 0 else "green"
    formatted = f"{abs(diff):{fmt}}"
    return f"[{color}]{symbol}{formatted}{suffix}[/{color}]"


def _add_pty_row(table: Table, report: MonitoringReport, prev_report: MonitoringReport | None) -> None:
    """Add PTY usage row to the summary table."""
    if not report.pty_info:
        return

    pty = report.pty_info
    pty_change = ""
    if prev_report and prev_report.pty_info:
        pty_change = _format_change(pty.windsurf_pty_count - prev_report.pty_info.windsurf_pty_count)

    usage_pct = (pty.system_pty_used / pty.system_pty_limit) * 100 if pty.system_pty_limit > 0 else 0
    pty_color = (
        "red"
        if pty.windsurf_pty_count >= PTY_CRITICAL_COUNT or usage_pct >= PTY_USAGE_CRITICAL_PERCENT
        else "yellow"
        if pty.windsurf_pty_count >= PTY_WARNING_COUNT
        else "green"
    )
    table.add_row(
        "PTYs",
        f"[{pty_color}]{pty.windsurf_pty_count}[/{pty_color}] [dim]({pty.system_pty_used}/{pty.system_pty_limit})[/dim]",
        pty_change,
    )


def _add_ls_snapshot_rows(table: Table, report: MonitoringReport) -> None:
    """Add orphaned/stale sub-rows when ls_snapshot is available."""
    if report.ls_snapshot is None:
        return
    snap = report.ls_snapshot
    if snap.total_ls_count == 0:
        return
    orphan_color = "red" if snap.orphaned_count > 0 else "green"
    table.add_row("  Orphaned", f"[{orphan_color}]{snap.orphaned_count}[/{orphan_color}]", "")
    stale_color = "yellow" if snap.stale_count > 0 else "green"
    table.add_row("  Stale", f"[{stale_color}]{snap.stale_count}[/{stale_color}]", "")


def _format_elapsed(seconds: float) -> str:
    """Format elapsed seconds as H:MM:SS or M:SS."""
    total = int(seconds)
    h, remainder = divmod(total, 3600)
    m, s = divmod(remainder, 60)
    return f"{h}:{m:02d}:{s:02d}" if h else f"{m}:{s:02d}"


def create_summary_table(
    report: MonitoringReport,
    prev_report: MonitoringReport | None = None,
    session_start: float | None = None,
) -> Table:
    """Create a live summary table for watch mode."""
    now = datetime.now(tz=UTC).astimezone().strftime("%H:%M:%S")
    elapsed = f" (elapsed {_format_elapsed(time.time() - session_start)})" if session_start is not None else ""
    table = make_kv_table(f"Windsurf Monitor - {now}{elapsed}")
    table.add_column("Change", style="yellow", ratio=1)

    # Process count
    proc_change = _format_change(report.process_count - prev_report.process_count) if prev_report else ""
    table.add_row("Processes", str(report.process_count), proc_change)

    # Memory
    mem_gb = report.total_windsurf_memory_mb / MB_PER_GB
    mem_pct = (mem_gb / report.system.total_memory_gb) * 100 if report.system.total_memory_gb > 0 else 0
    mem_str = f"{mem_gb:.2f} GB ({mem_pct:.1f}%)"

    mem_change = ""
    if prev_report:
        prev_mem_gb = prev_report.total_windsurf_memory_mb / MB_PER_GB
        mem_change = _format_change(mem_gb - prev_mem_gb, threshold=MEM_DIFF_SIGNIFICANT_GB, fmt=".2f", suffix="GB")

    mem_color = "red" if mem_pct > WINDSURF_MEM_PERCENT_CRITICAL else "yellow" if mem_pct > WINDSURF_MEM_PERCENT_WARNING else "green"
    table.add_row("Memory", f"[{mem_color}]{mem_str}[/{mem_color}]", mem_change)

    # CPU
    cpu_change = ""
    if prev_report:
        cpu_change = _format_change(
            report.total_windsurf_cpu_percent - prev_report.total_windsurf_cpu_percent,
            threshold=CPU_DIFF_SIGNIFICANT,
            fmt=".1f",
            suffix="%",
        )

    cpu_color = (
        "red"
        if report.total_windsurf_cpu_percent > CPU_PERCENT_CRITICAL
        else "yellow"
        if report.total_windsurf_cpu_percent > CPU_PERCENT_WARNING
        else "green"
    )
    table.add_row(
        "CPU",
        f"[{cpu_color}]{report.total_windsurf_cpu_percent:.1f}%[/{cpu_color}]",
        cpu_change,
    )

    # Language servers
    ls_change = _format_change(len(report.language_servers) - len(prev_report.language_servers)) if prev_report else ""
    table.add_row("Lang Servers", str(len(report.language_servers)), ls_change)

    _add_ls_snapshot_rows(table, report)

    # PTYs
    _add_pty_row(table, report, prev_report)

    # Issues
    issue_count = len(report.log_issues)
    issue_color = "red" if issue_count > 0 else "green"
    table.add_row("Issues", f"[{issue_color}]{issue_count}[/{issue_color}]", "")

    return table


@app.command()
def check(
    _target: TargetOption = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Show detailed process information")] = False,
    json_output: Annotated[bool, typer.Option("--json", help="Output report as JSON to stdout (for agent/pipe consumption)")] = False,
) -> None:
    """
    Run a quick performance check and display results.

    This is the main monitoring command that shows current Windsurf resource usage.
    All data is stored in the historical database automatically.
    """
    _require_target()
    try:
        target_name = get_target_display_name()
        with console.status(f"[cyan]Gathering {target_name} information...[/cyan]", spinner="dots"):
            report = generate_report()

        _store_to_db(store_check, report)

        exit_code = max_issue_severity(report.log_issues)

        # --json: output JSON to stdout and skip rich display
        if json_output:
            _print_json(asdict(report))
            if exit_code:
                raise typer.Exit(code=exit_code)
            return

        display_report(report, verbose=verbose)

        if exit_code:
            raise typer.Exit(code=exit_code)

    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        raise typer.Exit(code=130) from None
    else:
        tip = "Tip: run [cyan]surfmon watch[/cyan] to monitor continuously and build history for [cyan]surfmon analyze[/cyan]"
        console.print(f"[dim]{tip}[/dim]")


def _print_watch_banner(interval: int, max_reports: int) -> None:
    """Print the watch session startup banner."""
    target_name = get_target_display_name()
    console.print(f"[cyan]Starting continuous monitoring of {target_name}...[/cyan]")
    console.print(f"  Interval: {interval}s")
    if max_reports > 0:
        console.print(f"  Max reports: {max_reports}")
    console.print()
    console.print("[dim]Press Ctrl+C to stop[/dim]")
    console.print()


@app.command()
def watch(
    _target: TargetOption = None,
    interval: Annotated[int, typer.Option("--interval", "-i", help="Check interval in seconds")] = 5,
    max_reports: Annotated[int, typer.Option("--max", "-n", help="Stop after N checks (0 = infinite)")] = 0,
) -> None:
    """
    Continuously monitor Windsurf with live updates.

    Shows a live-updating dashboard with resource usage changes over time.
    All data is written to the historical database. Use 'surfmon analyze' to
    review the session afterwards.
    """
    _require_target()

    _state["stop_monitoring"] = False

    _print_watch_banner(interval, max_reports)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    prev_report = None
    report_count = 0
    session_start = time.time()

    try:
        with Live(console=console, refresh_per_second=4) as live:
            while not _state["stop_monitoring"]:
                if max_reports > 0 and report_count >= max_reports:
                    break

                report = generate_report()
                report_count += 1
                _store_to_db(store_check, report)

                live.update(create_summary_table(report, prev_report, session_start=session_start))

                prev_report = report
                time.sleep(interval)

    except KeyboardInterrupt:
        pass

    console.print()
    console.print(f"[green]✓ Monitoring stopped after {report_count} checks[/green]")


@app.command()
def history(
    command_filter: Annotated[
        str | None,
        typer.Option("--command", "-c", help="Filter by command type: check, ls-snapshot, pty-snapshot"),
    ] = None,
    limit: Annotated[int, typer.Option("--limit", "-n", help="Number of recent sessions to show")] = 20,
    since: Annotated[str | None, typer.Option("--since", "-s", help="Show sessions since duration (e.g. 24h, 7d, 2w)")] = None,
    json_output: Annotated[bool, typer.Option("--json", help="Output as JSON to stdout (for agent/pipe consumption)")] = False,
) -> None:
    """Show recent monitoring sessions from the historical database.

    Displays a table of past surfmon invocations with key metrics like
    memory usage, process counts, and issue counts.
    """
    with open_db() as db:
        try:
            rows = query_history_dicts(db, command=command_filter, limit=limit, since=since)
        except ValueError as exc:
            if json_output:
                _print_json({"error": str(exc)})
                raise typer.Exit(code=1) from exc
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(code=1) from exc

    if not rows:
        if json_output:
            _print_json([])
            return
        console.print("[yellow]No sessions found in the database.[/yellow]")
        console.print("[dim]Run 'surfmon check', 'surfmon ls-snapshot', or 'surfmon pty-snapshot' to populate it.[/dim]")
        raise typer.Exit(code=0)

    if json_output:
        _print_json(rows)
        return

    table = make_table(f"Recent Sessions ({len(rows)})")
    table.add_column("Timestamp", style="dim")
    table.add_column("Command", style="cyan")
    table.add_column("Version", style="dim")
    table.add_column("Memory", justify="right", style="yellow")
    table.add_column("Procs", justify="right")
    table.add_column("LS", justify="right")
    table.add_column("LS Mem", justify="right", style="yellow")
    table.add_column("Orphans", justify="right")
    table.add_column("PTY", justify="right")
    table.add_column("Issues", justify="right")

    for row in rows:
        mem_gb = row["total_memory_mb"] / MB_PER_GB if row["total_memory_mb"] else 0
        ls_mem_gb = row["ls_memory_mb"] / MB_PER_GB if row["ls_memory_mb"] else 0
        orphan_style = "red" if row["orphaned_count"] and row["orphaned_count"] > 0 else ""
        issue_style = "red" if row["issue_count"] and row["issue_count"] > 0 else "green"

        ts = row["timestamp"][:19] if row["timestamp"] else ""
        table.add_row(
            ts,
            row["command"] or "",
            row["windsurf_version"] or "",
            f"{mem_gb:.2f} GB" if mem_gb else "—",
            str(row["process_count"] or "—"),
            str(row["ls_count"] or "—"),
            f"{ls_mem_gb:.2f} GB" if ls_mem_gb else "—",
            f"[{orphan_style}]{row['orphaned_count'] or 0}[/{orphan_style}]" if orphan_style else str(row["orphaned_count"] or "—"),
            str(row["pty_count"] if row["pty_count"] is not None else "—"),
            f"[{issue_style}]{row['issue_count']}[/{issue_style}]",
        )

    console.print(table)


@app.command()
def trend(
    metric: Annotated[str, typer.Argument(help="Metric to trend: memory, processes, pty, ls-memory, ls-count")],
    since: Annotated[str | None, typer.Option("--since", "-s", help="Show data since duration (e.g. 24h, 7d, 2w)")] = None,
    plot: Annotated[bool, typer.Option("--plot", "-p", help="Generate a matplotlib chart")] = False,
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Save plot to file")] = None,
    json_output: Annotated[bool, typer.Option("--json", help="Output as JSON to stdout (for agent/pipe consumption)")] = False,
) -> None:
    """Show time-series trends for a metric from the historical database.

    Supported metrics: memory, processes, pty, ls-memory, ls-count.
    Use --plot to generate a visual chart.
    """
    with open_db() as db:
        try:
            data = query_trend(db, metric=metric, since=since)
        except ValueError as exc:
            if json_output:
                _print_json({"error": str(exc)})
                raise typer.Exit(code=1) from exc
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(code=1) from exc

    if not data:
        if json_output:
            _print_json([])
            return
        console.print(f"[yellow]No data found for metric '{metric}'.[/yellow]")
        console.print("[dim]Run 'surfmon check' or other commands to populate the database.[/dim]")
        raise typer.Exit(code=0)

    if json_output:
        _print_json(data)
        return

    # Table display
    table = make_table(f"Trend: {metric} ({len(data)} data points)")
    table.add_column("Timestamp", style="dim")
    table.add_column("Value", justify="right", style="cyan")

    unit = _trend_unit(metric)
    for point in data:
        ts = point["timestamp"][:19] if point["timestamp"] else ""
        table.add_row(ts, _format_trend_value(metric, point["value"]))

    console.print(table)

    if data:
        values = [p["value"] for p in data]
        _display_trend_summary(values, unit)

    if plot:
        _generate_trend_plot(metric, data, unit, output)


def _trend_unit(metric: str) -> str:
    """Return the display unit for a trend metric."""
    units = {"memory": "MB", "processes": "", "pty": "", "ls-memory": "MB", "ls-count": ""}
    return units.get(metric, "")


def _format_trend_value(metric: str, value: float) -> str:
    """Format a trend value for display."""
    if metric in {"memory", "ls-memory"}:
        return f"{value:.1f} MB"
    return str(int(value))


MIN_TREND_POINTS_FOR_CHANGE = 2


def _display_trend_summary(values: list[float], unit: str) -> None:
    """Display min/max/avg summary for trend data."""
    summary = make_kv_table("Summary")
    suffix = f" {unit}" if unit else ""
    summary.add_row("Min", f"{min(values):.1f}{suffix}")
    summary.add_row("Max", f"{max(values):.1f}{suffix}")
    summary.add_row("Avg", f"{sum(values) / len(values):.1f}{suffix}")
    if len(values) >= MIN_TREND_POINTS_FOR_CHANGE:
        change = values[-1] - values[0]
        change_color = "red" if change > 0 else "green"
        summary.add_row("Change", f"[{change_color}]{change:+.1f}{suffix}[/{change_color}]")
    console.print(summary)


def _generate_trend_plot(metric: str, data: list[dict], unit: str, output: Path | None) -> None:
    """Generate a matplotlib trend chart."""
    import matplotlib.dates as mdates
    import matplotlib.pyplot as plt

    raw_timestamps = [datetime.fromisoformat(p["timestamp"]) for p in data]
    x_values = mdates.date2num(raw_timestamps)
    values = [p["value"] for p in data]

    fig, ax = plt.subplots(figsize=(12, 5))
    ax.plot(x_values, values, "b-o", linewidth=2, markersize=4)
    ax.fill_between(x_values, 0, values, alpha=0.2)
    ax.set_title(f"surfmon trend: {metric}", fontsize=14, fontweight="bold")
    ax.set_ylabel(f"{metric}{' (' + unit + ')' if unit else ''}", fontsize=11)
    ax.grid(True, alpha=0.3)
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%m-%d %H:%M"))
    fig.autofmt_xdate()
    plt.tight_layout()

    if output is None:
        output = Path.home() / "Desktop" / f"surfmon-trend-{metric}.png"
        try:
            raw = typer.prompt("Save plot to", default=str(output))
            output = Path(os.path.expandvars(raw)).expanduser()
        except typer.Abort, KeyboardInterrupt:
            raise typer.Exit(code=1) from None

    try:
        plt.savefig(output, dpi=150, bbox_inches="tight")
        console.print(f"\n[green]✓ Plot saved to {output}[/green]")
    except OSError as e:
        console.print(f"\n[red]Error: Cannot save plot to {output}: {e}[/red]")


@app.command()
def cleanup(
    _target: TargetOption = None,
    force: Annotated[
        bool,
        typer.Option("--force", "-f", help="Skip confirmation and kill processes immediately"),
    ] = False,
) -> None:
    """Clean up orphaned Windsurf crash handlers.

    Finds and kills orphaned chrome_crashpad_handler processes that
    remain running after Windsurf has been closed. These processes
    can accumulate over time and waste system resources.
    """
    _require_target()
    app_name = get_paths().app_name
    main_windsurf_found, orphaned = _find_orphaned_crashpad_procs(app_name)

    if main_windsurf_found:
        console.print("[yellow]⚠ Windsurf is currently running. Crash handlers are not orphaned.[/yellow]")
        console.print("[dim]Close Windsurf first before running cleanup.[/dim]")
        raise typer.Exit(code=1)

    if not orphaned:
        console.print("[green]✓ No orphaned crash handlers found.[/green]")
        raise typer.Exit(code=0)

    # Display what will be killed
    console.print(f"\n[yellow]Found {len(orphaned)} orphaned crash handler(s):[/yellow]\n")

    table = make_table()
    table.add_column("PID", style="dim")
    table.add_column("Age", style="yellow")
    table.add_column("Memory", justify="right", style="cyan")

    for proc, age_days in orphaned:
        try:
            mem_mb = proc.memory_info().rss / 1024 / 1024
            table.add_row(str(proc.pid), f"{age_days:.1f} days", f"{mem_mb:.1f} MB")
        except psutil.NoSuchProcess, psutil.AccessDenied:
            pass

    console.print(table)
    console.print()

    if not force:
        confirm = typer.confirm("Kill these processes?")
        if not confirm:
            console.print("[dim]Cancelled.[/dim]")
            raise typer.Exit(code=0)

    killed, failed = _kill_processes(orphaned)

    if killed > 0:
        console.print(f"[green]✓ Successfully killed {killed} process(es)[/green]")

    if failed:
        console.print(f"\n[red]✗ Failed to kill {len(failed)} process(es):[/red]")
        for pid, error in failed:
            console.print(f"  PID {pid}: {error}")
        raise typer.Exit(code=1)


def _display_pty_snapshot(pty: PtyInfo) -> None:
    """Display a comprehensive PTY forensic snapshot to the console."""
    # Summary table
    usage_pct = (pty.system_pty_used / pty.system_pty_limit) * 100 if pty.system_pty_limit > 0 else 0
    pty_color = (
        "red"
        if pty.windsurf_pty_count >= PTY_CRITICAL_COUNT or usage_pct >= PTY_USAGE_CRITICAL_PERCENT
        else "yellow"
        if pty.windsurf_pty_count >= PTY_WARNING_COUNT
        else "green"
    )

    summary = make_kv_table("PTY Forensic Snapshot")
    summary.add_row("Windsurf PTYs", f"[{pty_color}]{pty.windsurf_pty_count}[/{pty_color}]")
    summary.add_row("System PTYs", f"{pty.system_pty_used} / {pty.system_pty_limit} ({usage_pct:.1f}%)")
    if pty.windsurf_version:
        summary.add_row("Windsurf Version", pty.windsurf_version)
    if pty.windsurf_uptime_seconds > 0:
        summary.add_row("Windsurf Uptime", format_uptime(pty.windsurf_uptime_seconds))
    console.print(summary)
    console.print()

    # Per-PID breakdown table
    if pty.per_process:
        pid_table = make_table("Windsurf Per-PID PTY Ownership")
        pid_table.add_column("PID", style="dim")
        pid_table.add_column("Process", style="cyan", ratio=2)
        pid_table.add_column("PTYs", justify="right", style="yellow")
        pid_table.add_column("FD Range", style="dim", ratio=2)

        for detail in pty.per_process:
            fds_sorted = sorted(detail.fds, key=lambda f: int(f.rstrip("urw")))
            fd_range = f"{fds_sorted[0]}..{fds_sorted[-1]}" if len(fds_sorted) > 1 else fds_sorted[0]
            pid_table.add_row(str(detail.pid), detail.name, str(detail.pty_count), fd_range)

        console.print(pid_table)
        console.print()

    # Non-Windsurf PTY holders for context
    if pty.non_windsurf_holders:
        other_table = make_table("Other PTY Holders (for context)")
        other_table.add_column("PID", style="dim")
        other_table.add_column("Process", style="cyan", ratio=2)
        other_table.add_column("PTYs", justify="right", style="green")

        for detail in pty.non_windsurf_holders:
            other_table.add_row(str(detail.pid), detail.name, str(detail.pty_count))

        console.print(other_table)
        console.print()

    # FD detail table (Windsurf only)
    if pty.fd_entries:
        fd_table = make_table("Windsurf FD Detail")
        fd_table.add_column("PID", style="dim")
        fd_table.add_column("FD", style="yellow")
        fd_table.add_column("Device", style="dim")
        fd_table.add_column("Offset", style="cyan")
        fd_table.add_column("Status", style="dim")

        for entry in sorted(pty.fd_entries, key=lambda e: (e.pid, int(e.fd.rstrip("urw")))):
            # Zero offset may indicate a leaked PTY (opened but no shell activity)
            is_zero = entry.size_off in {"0t0", "0"}
            status = "[dim]idle[/dim]" if is_zero else "[green]active[/green]"
            fd_table.add_row(str(entry.pid), entry.fd, entry.device, entry.size_off, status)

        active_count = sum(1 for e in pty.fd_entries if e.size_off not in {"0t0", "0"})
        idle_count = len(pty.fd_entries) - active_count
        console.print(fd_table)
        console.print(f"  [dim]{active_count} active, {idle_count} idle (zero offset)[/dim]")
        console.print()


@app.command(name="pty-snapshot")
def pty_snapshot(
    _target: TargetOption = None,
    json_output: Annotated[bool, typer.Option("--json", help="Output snapshot as JSON to stdout (for agent/pipe consumption)")] = False,
) -> None:
    """Capture a comprehensive PTY forensic snapshot.

    Gathers detailed PTY ownership data for diagnosing Windsurf PTY leaks.
    Shows per-PID breakdown, FD-level detail, and Windsurf version/uptime.
    Data is always stored in the historical database.
    """
    _require_target()
    try:
        target_name = get_target_display_name()
        with console.status(f"[cyan]Capturing PTY snapshot for {target_name}...[/cyan]", spinner="dots"):
            # Gather Windsurf processes for version/uptime
            proc_infos = collect_process_infos()
            pty = check_pty_leak(windsurf_processes=proc_infos)

        _store_to_db(store_pty_snapshot, pty)

        exit_code = max_issue_severity(pty.issues)

        # --json: output JSON to stdout and skip rich display
        if json_output:
            data = {"timestamp": datetime.now(tz=UTC).isoformat(), "pty_info": asdict(pty)}
            _print_json(data)
            if exit_code:
                raise typer.Exit(code=exit_code)
            return

        _display_pty_snapshot(pty)

        if exit_code:
            raise typer.Exit(code=exit_code)

    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        raise typer.Exit(code=130) from None


# Use the canonical Rich status helper from output.py.
_ls_entry_status = _ls_entry_status_rich


def _display_ls_snapshot(snapshot: LsSnapshot) -> None:
    """Display a language server forensic snapshot to the console."""
    # Summary table
    summary = make_kv_table("Language Server Snapshot")
    summary.add_row("Language Servers", str(snapshot.total_ls_count))
    if snapshot.total_ls_memory_mb > LS_TOTAL_MEM_CRITICAL_MB:
        mem_color = "red"
    elif snapshot.total_ls_memory_mb > LS_TOTAL_MEM_WARNING_MB:
        mem_color = "yellow"
    else:
        mem_color = "green"
    summary.add_row("Total LS Memory", f"[{mem_color}]{snapshot.total_ls_memory_mb:.1f} MB[/{mem_color}]")
    orphan_color = "red" if snapshot.orphaned_count > 0 else "green"
    summary.add_row("Orphaned", f"[{orphan_color}]{snapshot.orphaned_count}[/{orphan_color}]")
    stale_color = "yellow" if snapshot.stale_count > 0 else "green"
    summary.add_row("Stale", f"[{stale_color}]{snapshot.stale_count}[/{stale_color}]")
    if snapshot.windsurf_version:
        summary.add_row("Windsurf Version", snapshot.windsurf_version)
    if snapshot.windsurf_uptime_seconds > 0:
        summary.add_row("Windsurf Uptime", format_uptime(snapshot.windsurf_uptime_seconds))
    console.print(summary)
    console.print()

    # Per-LS detail table
    if snapshot.entries:
        detail = make_table("Language Server Processes")
        detail.add_column("PID", style="dim")
        detail.add_column("Language", style="cyan")
        detail.add_column("Memory", justify="right", style="yellow")
        detail.add_column("CPU %", justify="right")
        detail.add_column("Threads", justify="right", style="dim")
        detail.add_column("Runtime", style="dim")
        detail.add_column("Workspace", ratio=2)
        detail.add_column("Status")

        for entry in snapshot.entries:
            runtime = format_uptime(entry.runtime_seconds)
            status = _ls_entry_status(entry)
            if entry.memory_mb > LS_PROC_MEM_CRITICAL_MB:
                mem_style = "red"
            elif entry.memory_mb > LS_PROC_MEM_WARNING_MB:
                mem_style = "yellow"
            else:
                mem_style = "green"
            detail.add_row(
                str(entry.pid),
                entry.language,
                f"[{mem_style}]{entry.memory_mb:.1f} MB[/{mem_style}]",
                f"{entry.cpu_percent:.1f}",
                str(entry.num_threads),
                runtime,
                entry.workspace or "[dim]—[/dim]",
                status,
            )

        console.print(detail)
        console.print()

    # Issues
    if snapshot.issues:
        console.print(make_panel("[red]Issues Detected[/red]", title="⚠ Issues"))
        for issue in snapshot.issues:
            console.print(f"  {style_issue(issue)}")
        console.print()


@app.command(name="ls-snapshot")
def ls_snapshot(
    _target: TargetOption = None,
    json_output: Annotated[bool, typer.Option("--json", help="Output snapshot as JSON to stdout (for agent/pipe consumption)")] = False,
) -> None:
    """Capture a language server forensic snapshot.

    Gathers detailed per-language-server data: memory, CPU, workspace mapping,
    and orphaned workspace detection. Use for diagnosing language server memory
    leaks and runaway indexing processes. Data is always stored in the historical database.
    """
    _require_target()
    try:
        target_name = get_target_display_name()
        with console.status(f"[cyan]Capturing language server snapshot for {target_name}...[/cyan]", spinner="dots"):
            proc_infos = collect_process_infos()
            version = _extract_windsurf_version(proc_infos)
            uptime = _get_windsurf_uptime(proc_infos)
            active_workspaces = get_active_workspaces()
            snapshot = capture_ls_snapshot(proc_infos, version, uptime, active_workspaces)

        _store_to_db(store_ls_snapshot, snapshot)

        exit_code = max_issue_severity(snapshot.issues)

        if json_output:
            _print_json(asdict(snapshot))
            if exit_code:
                raise typer.Exit(code=exit_code)
            return

        _display_ls_snapshot(snapshot)

        if exit_code:
            raise typer.Exit(code=exit_code)

    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        raise typer.Exit(code=130) from None


def _display_analysis_summary(reports: list[dict], *, summary: bool = False) -> None:
    """Display timeline, key metrics, and analysis text.

    Args:
        reports: Parsed report dicts from the database.
        summary: When True, suppress the per-session timeline table.
    """
    # Session summary
    duration = reports[-1]["timestamp"] - reports[0]["timestamp"]
    console.print(
        f"[cyan]Session:[/cyan] {reports[0]['timestamp'].strftime('%Y-%m-%d %H:%M')} → "
        f"{reports[-1]['timestamp'].strftime('%H:%M')} ({len(reports)} snapshots over {duration})"
    )
    console.print()

    if not summary:
        # Timeline table
        timeline = make_table("Timeline")
        timeline.add_column("Time", style="dim")
        timeline.add_column("Proc", justify="right")
        timeline.add_column("Memory", justify="right")
        timeline.add_column("CPU", justify="right")
        timeline.add_column("LS", justify="right")
        timeline.add_column("Issues", justify="right")

        for r in reports:
            mem_gb = r["memory_mb"] / MB_PER_GB
            mem_color = "red" if mem_gb > ANALYZE_MEM_GB_HIGH else "yellow" if mem_gb > ANALYZE_MEM_GB_MEDIUM else "green"
            timeline.add_row(
                r["timestamp"].strftime("%H:%M"),
                str(r["processes"]),
                f"[{mem_color}]{mem_gb:.2f} GB[/{mem_color}]",
                f"{r['cpu']:.1f}%",
                str(r["lang_servers"]),
                str(len(r["issues"])),
            )

        console.print(timeline)
        console.print()

    # Key metrics
    _display_key_metrics(reports)

    # Analysis
    mem_change = (reports[-1]["memory_mb"] - reports[0]["memory_mb"]) / MB_PER_GB
    proc_change = reports[-1]["processes"] - reports[0]["processes"]

    console.print("[bold cyan]Analysis:[/bold cyan]")
    if mem_change > ANALYZE_MEM_CHANGE_LEAK_GB:
        console.print(f"  [red]⚠  POTENTIAL MEMORY LEAK: {mem_change:.2f} GB growth[/red]")
    elif mem_change > ANALYZE_MEM_CHANGE_GROWTH_GB:
        console.print(f"  [yellow]⚠  Memory growth: {mem_change:.2f} GB[/yellow]")
    else:
        console.print(f"  [green]✓ Memory stable (change: {mem_change:+.2f} GB)[/green]")

    if proc_change > ANALYZE_PROC_CHANGE_SIGNIFICANT:
        console.print(f"  [yellow]⚠  Process count increased by {proc_change}[/yellow]")
    elif proc_change < 0:
        console.print(f"  [green]✓ Process count decreased by {abs(proc_change)}[/green]")

    # Issues
    final_issues = reports[-1]["issues"]
    if final_issues:
        console.print(f"\n[bold red]Current Issues ({len(final_issues)}):[/bold red]")
        for issue in final_issues:
            console.print(f"  • {issue}")


def _display_key_metrics(reports: list[dict]) -> None:
    """Display key metrics comparison table."""
    metrics = make_table("Key Metrics")
    metrics.add_column("Metric", style="cyan", ratio=2)
    metrics.add_column("Start", justify="right", ratio=1)
    metrics.add_column("End", justify="right", ratio=1)
    metrics.add_column("Change", justify="right", ratio=1, overflow="fold")
    metrics.add_column("Peak", justify="right", ratio=1)

    # Process count
    proc_change = reports[-1]["processes"] - reports[0]["processes"]
    proc_color = "red" if proc_change > ANALYZE_PROC_CHANGE_SIGNIFICANT else "yellow" if proc_change > 0 else "green"
    metrics.add_row(
        "Processes",
        str(reports[0]["processes"]),
        str(reports[-1]["processes"]),
        f"[{proc_color}]{proc_change:+d}[/{proc_color}]",
        str(max(r["processes"] for r in reports)),
    )

    # Memory
    mem_change = (reports[-1]["memory_mb"] - reports[0]["memory_mb"]) / MB_PER_GB
    mem_color = "red" if mem_change > ANALYZE_MEM_CHANGE_LEAK_GB else "yellow" if mem_change > ANALYZE_MEM_CHANGE_GROWTH_GB else "green"
    metrics.add_row(
        "Memory",
        f"{reports[0]['memory_mb'] / MB_PER_GB:.2f} GB",
        f"{reports[-1]['memory_mb'] / MB_PER_GB:.2f} GB",
        f"[{mem_color}]{mem_change:+.2f} GB[/{mem_color}]",
        f"{max(r['memory_mb'] for r in reports) / MB_PER_GB:.2f} GB",
    )

    # CPU
    metrics.add_row(
        "CPU",
        f"{reports[0]['cpu']:.1f}%",
        f"{reports[-1]['cpu']:.1f}%",
        f"{reports[-1]['cpu'] - reports[0]['cpu']:+.1f}%",
        f"{max(r['cpu'] for r in reports):.1f}%",
    )

    console.print(metrics)
    console.print()


def _plot_memory_charts(axes, timestamps: list, reports: list[dict]) -> None:
    """Plot Row 1: Memory charts (total, top 5 processes, system pressure)."""
    import matplotlib.dates as mdates

    # Total Memory Usage
    ax = axes[0, 0]
    windsurf_mem = [r["memory_mb"] / 1024 for r in reports]
    system_avail = [r["system"]["available_memory_gb"] for r in reports]
    ax.plot(timestamps, windsurf_mem, "b-o", label="Windsurf", linewidth=2)
    ax.plot(timestamps, system_avail, "g--", label="System Available", alpha=0.7)
    ax.set_ylabel("Memory (GB)", fontsize=10)
    ax.set_title("Memory Usage", fontsize=11, fontweight="bold")
    ax.legend(fontsize=8)
    ax.grid(True, alpha=0.3)
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))

    # Top 5 Processes by Memory
    ax = axes[0, 1]
    process_mem_history = build_process_memory_history(reports)
    top_5 = sorted(process_mem_history.items(), key=lambda x: max(x[1]), reverse=True)[:5]
    colors = ["#1f77b4", "#ff7f0e", "#2ca02c", "#d62728", "#9467bd"]
    for (name, mem_history), color in zip(top_5, colors, strict=False):
        ax.plot(timestamps, [m / 1024 for m in mem_history], "-o", label=name, color=color, linewidth=1.5)
    ax.set_ylabel("Memory (GB)", fontsize=10)
    ax.set_title("Top 5 Processes by Memory", fontsize=11, fontweight="bold")
    ax.legend(fontsize=7, loc="best")
    ax.grid(True, alpha=0.3)
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))

    # System Memory Pressure
    ax = axes[0, 2]
    total_mem = [r["system"]["total_memory_gb"] for r in reports]
    used_mem = [r["system"]["total_memory_gb"] - r["system"]["available_memory_gb"] for r in reports]
    windsurf_mem = [r["memory_mb"] / 1024 for r in reports]
    ax.fill_between(timestamps, 0, used_mem, alpha=0.3, color="orange", label="Other Apps")
    ax.fill_between(
        timestamps,
        [u - w for u, w in zip(used_mem, windsurf_mem, strict=True)],
        used_mem,
        alpha=0.6,
        color="blue",
        label="Windsurf",
    )
    ax.axhline(y=total_mem[0], color="r", linestyle="--", alpha=0.5, label=f"Total: {total_mem[0]:.1f} GB")
    ax.set_ylabel("Memory (GB)", fontsize=10)
    ax.set_title("System Memory Pressure", fontsize=11, fontweight="bold")
    ax.legend(fontsize=8)
    ax.grid(True, alpha=0.3)
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))


def _plot_row2_charts(axes, timestamps: list, reports: list[dict]) -> None:
    """Plot Row 2: Process types, PTY usage, language servers & extensions."""
    import matplotlib.dates as mdates

    # Process Count by Type
    ax = axes[1, 0]
    proc_types = defaultdict(list)
    for r in reports:
        type_counts = defaultdict(int)
        for p in r["windsurf_processes"]:
            name = simplify_process_name(p["name"])
            if "Helper" in name:
                type_counts["Helpers"] += 1
            elif "crashpad" in name.lower():
                type_counts["Crashpad"] += 1
            else:
                type_counts["Main"] += 1
        for t in ["Main", "Helpers", "Crashpad"]:
            proc_types[t].append(type_counts[t])

    ax.stackplot(
        timestamps,
        proc_types["Main"],
        proc_types["Helpers"],
        proc_types["Crashpad"],
        labels=["Main", "Helpers", "Crashpad"],
        alpha=0.7,
    )
    ax.set_ylabel("Process Count", fontsize=10)
    ax.set_title("Process Count by Type", fontsize=11, fontweight="bold")
    ax.legend(loc="upper left", fontsize=8)
    ax.grid(True, alpha=0.3)
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))

    # PTY Usage
    _plot_pty_chart(axes[1, 1], timestamps, reports)

    # Language Servers Over Time
    ax = axes[1, 2]
    ls_count = [r["lang_servers"] for r in reports]
    ax.plot(timestamps, ls_count, "b-o", linewidth=2, label="Language Servers")
    ax.set_ylabel("Language Server Count", color="b", fontsize=10)
    ax.tick_params(axis="y", labelcolor="b")
    ax.set_title("Language Servers", fontsize=11, fontweight="bold")
    ax.legend(loc="upper left", fontsize=8)
    ax.grid(True, alpha=0.3)
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))


def _plot_pty_chart(ax, timestamps: list, reports: list[dict]) -> None:
    """Plot PTY usage with Windsurf count and system percentage."""
    import matplotlib.dates as mdates

    ax2 = ax.twinx()

    pty_infos = [r.get("pty_info") or {} for r in reports]
    windsurf_pty = [pi.get("windsurf_pty_count", 0) for pi in pty_infos]
    sys_used = [pi.get("system_pty_used", 0) for pi in pty_infos]
    sys_limit = [pi.get("system_pty_limit", 0) for pi in pty_infos]
    sys_pct = [(u / lim * 100) if lim else 0 for u, lim in zip(sys_used, sys_limit, strict=False)]

    ax.plot(timestamps, windsurf_pty, "c-o", linewidth=2, label="Windsurf PTYs")
    ax2.plot(timestamps, sys_pct, "k--", linewidth=2, label="System PTY %")

    ax.axhline(y=PTY_WARNING_COUNT, color="gold", linestyle=":", alpha=0.8, label=f"Warn: {PTY_WARNING_COUNT}")
    ax.axhline(y=PTY_CRITICAL_COUNT, color="red", linestyle=":", alpha=0.8, label=f"Crit: {PTY_CRITICAL_COUNT}")
    ax2.axhline(
        y=PTY_USAGE_CRITICAL_PERCENT,
        color="red",
        linestyle="--",
        alpha=0.4,
        label=f"Sys Crit: {PTY_USAGE_CRITICAL_PERCENT}%",
    )

    limit_val = sys_limit[0] if sys_limit else 0
    ax.set_ylabel("Windsurf PTYs", fontsize=10)
    ax2.set_ylabel("System PTY Usage (%)", fontsize=10)
    ax.set_title(
        "PTY Usage" + (f" (system limit: {limit_val})" if limit_val else ""),
        fontsize=11,
        fontweight="bold",
    )

    handles1, labels1 = ax.get_legend_handles_labels()
    handles2, labels2 = ax2.get_legend_handles_labels()
    ax.legend(handles1 + handles2, labels1 + labels2, loc="upper left", fontsize=7)
    ax.grid(True, alpha=0.3)
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))


def _plot_row3_charts(axes, timestamps: list, reports: list[dict]) -> None:
    """Plot Row 3: Thread count, average memory per process, issues over time."""
    import matplotlib.dates as mdates

    # Thread Count
    ax = axes[2, 0]
    total_threads = [sum(p["num_threads"] for p in r["windsurf_processes"]) for r in reports]
    ax.plot(timestamps, total_threads, "purple", marker="o", linewidth=2)
    ax.fill_between(timestamps, 0, total_threads, alpha=0.3, color="purple")
    ax.set_ylabel("Thread Count", fontsize=10)
    ax.set_title("Total Thread Count", fontsize=11, fontweight="bold")
    ax.grid(True, alpha=0.3)
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))

    # Average Memory per Process
    ax = axes[2, 1]
    avg_mem = [r["memory_mb"] / r["processes"] if r["processes"] > 0 else 0 for r in reports]
    ax.plot(timestamps, avg_mem, "orange", marker="o", linewidth=2)
    ax.set_ylabel("Memory per Process (MB)", fontsize=10)
    ax.set_title("Average Memory per Process", fontsize=11, fontweight="bold")
    ax.grid(True, alpha=0.3)
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))

    # Issues Over Time
    ax = axes[2, 2]
    issue_counts = [len(r["issues"]) for r in reports]
    ax.plot(timestamps, issue_counts, "m-o", linewidth=2)
    ax.fill_between(timestamps, 0, issue_counts, alpha=0.3, color="magenta")
    ax.set_ylabel("Issue Count", fontsize=10)
    ax.set_title("Issues Detected", fontsize=11, fontweight="bold")
    ax.grid(True, alpha=0.3)
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))


def _prompt_for_plot_output_path() -> Path:
    default_path = Path.home() / "Desktop" / "windsurf-leak-analysis.png"
    try:
        raw_path = typer.prompt("Save plot to", default=str(default_path))
        path = Path(os.path.expandvars(raw_path)).expanduser()

        if path.exists() and not typer.confirm(f"File exists: {path}. Overwrite?", default=False):
            raise typer.Exit(code=1)
    except typer.Abort, KeyboardInterrupt:
        raise typer.Exit(code=1) from None
    else:
        return path


def _generate_analysis_plots(reports: list[dict], output: Path) -> None:
    """Generate 3x3 matplotlib analysis plots."""
    import matplotlib.pyplot as plt

    fig, axes = plt.subplots(3, 3, figsize=(18, 14))
    fig.suptitle("Windsurf Performance Analysis", fontsize=18, y=0.995)

    timestamps = [r["timestamp"] for r in reports]

    _plot_memory_charts(axes, timestamps, reports)
    _plot_row2_charts(axes, timestamps, reports)
    _plot_row3_charts(axes, timestamps, reports)

    # Rotate all x-axis labels for better readability
    for ax in axes.flat:
        for label in ax.get_xticklabels():
            label.set_rotation(45)
            label.set_ha("right")

    plt.tight_layout()

    try:
        plt.savefig(output, dpi=150, bbox_inches="tight")
        console.print(f"\n[green]✓ Plot saved to {output}[/green]")
    except OSError as e:
        console.print(f"\n[red]Error: Cannot save plot to {output}: {e}[/red]")


@app.command()
def analyze(
    since: Annotated[str, typer.Option("--since", "-s", help="Time window to analyze (e.g. 24h, 7d, 30m)")] = "7d",
    summary: Annotated[
        bool, typer.Option("--summary", "-S", help="Show only key metrics and issues, suppress per-session timeline")
    ] = False,
    plot: Annotated[bool, typer.Option("--plot", "-p", help="Generate visualizations")] = False,
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Save plots to file")] = None,
) -> None:
    """Analyze historical check sessions to identify trends and issues.

    Reads from the surfmon database. Use --since to control the time window.
    Detects: memory leaks, process count changes, performance degradation.
    """
    with open_db() as db:
        try:
            reports = query_analyze_sessions(db, since=since)
        except ValueError as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(code=1) from exc

    if not reports:
        console.print(f"[yellow]No check sessions found in the last {since}.[/yellow]")
        console.print("[dim]Run 'surfmon check' or 'surfmon watch' to populate the database.[/dim]")
        raise typer.Exit(code=0)

    console.print()
    console.print(make_panel("[bold cyan]Historical Analysis[/bold cyan]"))
    console.print()

    _display_analysis_summary(reports, summary=summary)

    if plot:
        output_path = _prompt_for_plot_output_path() if output is None else Path(os.path.expandvars(str(output))).expanduser()

        _generate_analysis_plots(reports, output_path)


def _find_orphaned_crashpad_procs(app_name: str) -> tuple[bool, list[tuple[psutil.Process, float]]]:
    """Scan for orphaned crashpad handler processes.

    Returns:
        Tuple of (main_windsurf_found, list of (process, age_days) pairs).
    """
    orphaned = []
    main_windsurf_found = False

    for proc in psutil.process_iter(["pid", "name", "cmdline", "exe", "create_time"]):
        try:
            name = proc.info["name"] or ""
            exe = proc.info["exe"] or ""
            cmdline = " ".join(proc.info["cmdline"] or [])

            if app_name not in exe and app_name not in cmdline:
                continue

            if is_main_windsurf_process(name, exe, app_name):
                main_windsurf_found = True

            if "crashpad" in name.lower():
                create_time = proc.info["create_time"]
                age_days = (datetime.now(tz=UTC).timestamp() - create_time) / 86400
                orphaned.append((proc, age_days))

        except psutil.NoSuchProcess, psutil.AccessDenied:
            pass

    return main_windsurf_found, orphaned


def _kill_processes(processes: list[tuple[psutil.Process, float]]) -> tuple[int, list[tuple[int, str]]]:
    """Kill a list of processes. Returns (killed_count, failed_list)."""
    killed = 0
    failed = []
    for proc, _ in processes:
        try:
            proc.kill()
            killed += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            failed.append((proc.pid, str(e)))
    return killed, failed


def main():
    """Entry point for the CLI."""
    app()


if __name__ == "__main__":
    main()
