"""Typer-based CLI for Windsurf Performance Monitor."""

import json
import os
import signal
import sys
import time
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, Protocol

import matplotlib.dates as mdates
import matplotlib.pyplot as plt
import psutil
import typer

from . import __version__
from .config import TargetNotSetError, WindsurfTarget, get_paths, get_target, get_target_display_name, set_target
from .db import open_db, query_analyze_sessions, query_history_dicts, query_trend, store_check, store_ls_snapshot, store_pty_snapshot

if TYPE_CHECKING:
    from collections.abc import Callable

    from sqlite_utils import Database

from .display import (
    create_summary_table,
    display_analysis_summary,
    display_history_table,
    display_ls_snapshot,
    display_pty_snapshot,
    display_trend_summary,
    generate_analysis_plots,
)
from .monitor import (
    _extract_windsurf_version,
    _get_windsurf_uptime,
    capture_ls_snapshot,
    check_pty_leak,
    collect_process_infos,
    generate_report,
    get_active_workspaces,
    is_main_windsurf_process,
    max_issue_severity,
)
from .output import (
    Live,
    console,
    display_report,
    make_panel,
    make_table,
)


def _print_json(data: dict | list) -> None:
    """Print data as JSON to stdout for agent/pipe consumption."""
    print(json.dumps(data, indent=2, default=str))


def _query_db(query_fn: Callable[..., Any], *, json_output: bool, **kwargs: Any) -> list[dict]:
    """Run a DB query, handling errors with JSON or Rich output.

    Returns the query result on success, or exits on ValueError.
    """
    with open_db() as db:
        try:
            return query_fn(db, **kwargs)
        except ValueError as exc:
            if json_output:
                _print_json({"error": str(exc)})
            else:
                console.print(f"[red]{exc}[/red]")
            raise typer.Exit(code=1) from exc


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


def signal_handler(_signum: int, _frame: object) -> None:
    """Handle interrupt signals gracefully."""
    _state["stop_monitoring"] = True
    console.print("\n[yellow]Stopping monitoring...[/yellow]")


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
    rows = _query_db(query_history_dicts, json_output=json_output, command=command_filter, limit=limit, since=since)

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

    display_history_table(rows)


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
    data = _query_db(query_trend, json_output=json_output, metric=metric, since=since)

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
        display_trend_summary(values, unit)

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


def _generate_trend_plot(metric: str, data: list[dict], unit: str, output: Path | None) -> None:
    """Generate a matplotlib trend chart."""
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

        display_pty_snapshot(pty)

        if exit_code:
            raise typer.Exit(code=exit_code)

    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        raise typer.Exit(code=130) from None


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

        display_ls_snapshot(snapshot)

        if exit_code:
            raise typer.Exit(code=exit_code)

    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        raise typer.Exit(code=130) from None


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

    display_analysis_summary(reports, summary=summary)

    if plot:
        output_path = _prompt_for_plot_output_path() if output is None else Path(os.path.expandvars(str(output))).expanduser()

        generate_analysis_plots(reports, output_path)


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
