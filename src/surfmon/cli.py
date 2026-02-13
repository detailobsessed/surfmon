"""Typer-based CLI for Windsurf Performance Monitor."""

import hashlib
import json
import signal
import time
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import matplotlib.dates as mdates
import matplotlib.pyplot as plt
import psutil
import typer

from . import __version__
from .compare import compare_reports
from .config import WindsurfTarget, get_paths, get_target_display_name, set_target
from .monitor import MonitoringReport, generate_report, is_main_windsurf_process, save_report_json
from .output import (
    CPU_PERCENT_CRITICAL,
    CPU_PERCENT_WARNING,
    MB_PER_GB,
    PTY_COUNT_CRITICAL,
    PTY_COUNT_WARNING,
    PTY_USAGE_PERCENT_CRITICAL,
    WINDSURF_MEM_PERCENT_CRITICAL,
    WINDSURF_MEM_PERCENT_WARNING,
    Live,
    Table,
    console,
    display_report,
    make_kv_table,
    make_panel,
    make_table,
    save_report_markdown,
)

# Analyze command thresholds
ANALYZE_MEM_GB_HIGH = 6
ANALYZE_MEM_GB_MEDIUM = 4
ANALYZE_PROC_CHANGE_SIGNIFICANT = 5
ANALYZE_MEM_CHANGE_LEAK_GB = 0.5
ANALYZE_MEM_CHANGE_GROWTH_GB = 0.2
MEM_DIFF_SIGNIFICANT_GB = 0.01
CPU_DIFF_SIGNIFICANT = 0.5


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


def target_callback(value: str | None) -> str | None:
    """Set the Windsurf target based on CLI option."""
    if value is not None:
        if value.lower() == "next":
            set_target(WindsurfTarget.NEXT)
        elif value.lower() == "stable":
            set_target(WindsurfTarget.STABLE)
        else:
            msg = f"Invalid target: {value}. Use 'stable' or 'next'."
            raise typer.BadParameter(msg)
    return value


# Global option for target selection
TargetOption = Annotated[
    str | None,
    typer.Option(
        "--target",
        "-t",
        help="Windsurf target: 'stable' or 'next' (default: from SURFMON_TARGET env or 'stable')",
        callback=target_callback,
        is_eager=True,  # Process before other options
    ),
]


def simplify_process_name(name: str) -> str:
    """Simplify Windsurf process names for plot legends.

    Extracts the helper type from names like "Windsurf Helper (GPU)"
    into "Windsurf Helper GPU" for cleaner display.
    """
    if "Helper" in name and "(" in name:
        return name.split("Helper", maxsplit=1)[0] + "Helper " + name.split("(")[1].split(")")[0]
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
        if pty.windsurf_pty_count >= PTY_COUNT_CRITICAL or usage_pct >= PTY_USAGE_PERCENT_CRITICAL
        else "yellow"
        if pty.windsurf_pty_count >= PTY_COUNT_WARNING
        else "green"
    )
    table.add_row(
        "PTYs",
        f"[{pty_color}]{pty.windsurf_pty_count}[/{pty_color}] [dim]({pty.system_pty_used}/{pty.system_pty_limit})[/dim]",
        pty_change,
    )


def create_summary_table(report: MonitoringReport, prev_report: MonitoringReport | None = None) -> Table:
    """Create a live summary table for watch mode."""
    table = make_kv_table(f"Windsurf Monitor - {datetime.now(tz=UTC).astimezone().strftime('%H:%M:%S')}")
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
    save: Annotated[
        bool,
        typer.Option(
            "--save",
            "-s",
            help="Save both JSON and Markdown reports (auto-named, displays verbose output)",
        ),
    ] = False,
    json_path: Annotated[Path | None, typer.Option("--json", help="Save report as JSON")] = None,
    markdown_path: Annotated[Path | None, typer.Option("--md", help="Save report as Markdown")] = None,
) -> None:
    """
    Run a quick performance check and display results.

    This is the main monitoring command that shows current Windsurf resource usage.
    When using --save, verbose output is automatically enabled for more complete information.
    """
    try:
        # Validate flag combinations
        if json_path and str(json_path).startswith("--"):
            console.print("[red]Error: --json requires a file path. Use --save to auto-generate both reports.[/red]")
            raise typer.Exit(code=1)
        if markdown_path and str(markdown_path).startswith("--"):
            console.print("[red]Error: --md requires a file path. Use --save to auto-generate both reports.[/red]")
            raise typer.Exit(code=1)

        target_name = get_target_display_name()
        with console.status(f"[cyan]Gathering {target_name} information...[/cyan]", spinner="dots"):
            report = generate_report()

        # Auto-enable verbose when saving reports (more info is better)
        show_verbose = verbose or save or bool(json_path) or bool(markdown_path)
        display_report(report, verbose=show_verbose)

        # Handle --save flag (auto-generate filenames)
        if save:
            timestamp = datetime.now(tz=UTC).strftime("%Y%m%d-%H%M%S")
            json_path = Path(f"surfmon-{timestamp}.json")
            markdown_path = Path(f"surfmon-{timestamp}.md")

        # Show saved file paths
        if json_path or markdown_path:
            console.print()
            if json_path:
                json_path = json_path.resolve()  # Convert to absolute path
                save_report_json(report, json_path)
                console.print(f"[green]✓ JSON report saved to {json_path}[/green]")
            if markdown_path:
                markdown_path = markdown_path.resolve()  # Convert to absolute path
                save_report_markdown(report, markdown_path)
                console.print(f"[green]✓ Markdown report saved to {markdown_path}[/green]")

        # Exit with non-zero if critical issues detected
        if report.log_issues:
            raise typer.Exit(code=1)

    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        raise typer.Exit(code=130) from None


@app.command()
def watch(
    _target: TargetOption = None,
    interval: Annotated[int, typer.Option("--interval", "-i", help="Check interval in seconds")] = 5,
    output_dir: Annotated[
        Path,
        typer.Option("--output", "-o", help="Output directory for periodic reports"),
    ] = Path("../reports/watch"),
    save_interval: Annotated[int, typer.Option("--save-interval", "-s", help="Save full report every N seconds")] = 300,
    max_reports: Annotated[int, typer.Option("--max", "-n", help="Stop after N checks (0 = infinite)")] = 0,
) -> None:
    """
    Continuously monitor Windsurf with live updates.

    Shows a live-updating dashboard with resource usage changes over time.
    Saves periodic JSON reports for historical analysis.
    Each watch session creates a new timestamped folder.
    """
    # Reset stop flag at start of watch (in case of previous Ctrl+C)
    _state["stop_monitoring"] = False

    # Create session-specific subdirectory
    session_timestamp = datetime.now(tz=UTC).strftime("%Y%m%d-%H%M%S")
    session_dir = output_dir / session_timestamp
    session_dir.mkdir(parents=True, exist_ok=True)

    target_name = get_target_display_name()
    console.print(f"[cyan]Starting continuous monitoring of {target_name}...[/cyan]")
    console.print(f"  Interval: {interval}s")
    console.print(f"  Session: {session_dir}")
    console.print(f"  Save every: {save_interval}s")
    if max_reports > 0:
        console.print(f"  Max reports: {max_reports}")
    console.print()
    console.print("[dim]Press Ctrl+C to stop[/dim]")
    console.print()

    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    prev_report = None
    report_count = 0
    last_save = time.time()

    try:
        with Live(console=console, refresh_per_second=4) as live:
            while not _state["stop_monitoring"]:
                if max_reports > 0 and report_count >= max_reports:
                    break

                report = generate_report()
                report_count += 1

                # Update live display
                live.update(create_summary_table(report, prev_report))

                # Save report periodically
                current_time = time.time()
                if current_time - last_save >= save_interval:
                    timestamp = datetime.now(tz=UTC).strftime("%Y%m%d-%H%M%S")
                    json_path = session_dir / f"{timestamp}.json"
                    save_report_json(report, json_path)
                    last_save = current_time

                prev_report = report
                time.sleep(interval)

    except KeyboardInterrupt:
        pass

    console.print()
    console.print(f"[green]✓ Monitoring stopped after {report_count} checks[/green]")


@app.command()
def compare(
    before: Annotated[Path, typer.Argument(help="Path to 'before' report JSON")],
    after: Annotated[Path, typer.Argument(help="Path to 'after' report JSON")],
) -> None:
    """
    Compare two monitoring reports to show changes.

    Useful for analyzing the impact of configuration changes or identifying
    performance regressions over time.
    """
    if not before.exists():
        console.print(f"[red]Error: Before report not found: {before}[/red]")
        raise typer.Exit(code=1)

    if not after.exists():
        console.print(f"[red]Error: After report not found: {after}[/red]")
        raise typer.Exit(code=1)

    try:
        compare_reports(before, after)
    except Exception as e:
        console.print(f"[red]Error comparing reports: {e}[/red]")
        raise typer.Exit(code=1) from e


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


def _hash_report_files(json_files: list[Path]) -> dict[str, list[Path]]:
    """Hash JSON report files by content (excluding timestamp).

    Returns dict mapping content hash to list of files with that content.
    """
    content_hashes: dict[str, list[Path]] = {}

    for json_file in json_files:
        try:
            with json_file.open(encoding="utf-8") as f:
                data = json.load(f)

            data_copy = data.copy()
            data_copy.pop("timestamp", None)

            content_str = json.dumps(data_copy, sort_keys=True)
            content_hash = hashlib.sha256(content_str.encode()).hexdigest()

            if content_hash not in content_hashes:
                content_hashes[content_hash] = []
            content_hashes[content_hash].append(json_file)

        except (json.JSONDecodeError, OSError) as e:
            console.print(f"[yellow]Warning: Could not read {json_file.name}: {e}[/yellow]")

    return content_hashes


def _find_duplicate_files(content_hashes: dict[str, list[Path]], keep_latest: bool) -> tuple[list[Path], int]:
    """Identify duplicate files to remove. Returns (duplicates, unique_count)."""
    duplicates: list[Path] = []
    unique_count = 0

    for files in content_hashes.values():
        unique_count += 1
        if len(files) > 1:
            files_sorted = sorted(files)
            if keep_latest:
                duplicates.extend(files_sorted[:-1])
            else:
                duplicates.extend(files_sorted[1:])

    return duplicates, unique_count


def _delete_files(files: list[Path]) -> tuple[int, list[tuple[str, str]]]:
    """Delete files and return (deleted_count, failed_list)."""
    deleted = 0
    failed = []
    for file in files:
        try:
            file.unlink()
            deleted += 1
        except OSError as e:
            failed.append((file.name, str(e)))
    return deleted, failed


@app.command()
def prune(
    directory: Annotated[Path, typer.Argument(help="Directory containing JSON reports to prune")],
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Show what would be deleted without actually deleting")] = False,
    keep_latest: Annotated[
        bool,
        typer.Option("--keep-latest/--no-keep-latest", help="Always keep the most recent report"),
    ] = True,
) -> None:
    """Remove duplicate/identical monitoring reports.

    Compares JSON reports in a directory and removes duplicates, keeping only
    unique reports. This is useful after running watch mode for extended periods,
    as identical reports accumulate when nothing changes.

    By default, always keeps the latest report even if it's a duplicate.
    """
    if not directory.exists():
        console.print(f"[red]Error: Directory not found: {directory}[/red]")
        raise typer.Exit(code=1)

    if not directory.is_dir():
        console.print(f"[red]Error: Not a directory: {directory}[/red]")
        raise typer.Exit(code=1)

    json_files = sorted(directory.glob("*.json"))
    if not json_files:
        console.print(f"[yellow]No JSON files found in {directory}[/yellow]")
        raise typer.Exit(code=0)

    console.print(f"[cyan]Analyzing {len(json_files)} report(s)...[/cyan]\n")

    content_hashes = _hash_report_files(json_files)
    duplicates_to_remove, unique_reports = _find_duplicate_files(content_hashes, keep_latest)

    if not duplicates_to_remove:
        console.print("[green]✓ No duplicate reports found[/green]")
        console.print(f"All {len(json_files)} reports are unique.")
        raise typer.Exit(code=0)

    total_size = sum(f.stat().st_size for f in duplicates_to_remove)
    size_mb = total_size / 1024 / 1024

    console.print(f"[yellow]Found {len(duplicates_to_remove)} duplicate report(s)[/yellow]")
    console.print(f"Space to reclaim: {size_mb:.2f} MB\n")

    if dry_run:
        console.print("[dim]Dry run - files that would be deleted:[/dim]\n")
        for file in sorted(duplicates_to_remove):
            console.print(f"  {file.name}")
        console.print("\n[cyan]Run without --dry-run to actually delete these files[/cyan]")
        raise typer.Exit(code=0)

    # Show summary table
    table = make_table("Summary")
    table.add_column("Category", style="cyan", ratio=2)
    table.add_column("Count", justify="right", style="green", ratio=1)
    table.add_row("Total reports", str(len(json_files)))
    table.add_row("Unique reports", str(unique_reports))
    table.add_row("Duplicates to remove", str(len(duplicates_to_remove)))
    table.add_row("Space to reclaim", f"{size_mb:.2f} MB")
    console.print(table)
    console.print()

    confirm = typer.confirm("Delete duplicate reports?")
    if not confirm:
        console.print("[dim]Cancelled.[/dim]")
        raise typer.Exit(code=0)

    deleted, failed = _delete_files(duplicates_to_remove)

    if deleted > 0:
        console.print(f"[green]✓ Successfully deleted {deleted} duplicate report(s)[/green]")
        console.print(f"[green]✓ Reclaimed {size_mb:.2f} MB[/green]")

    if failed:
        console.print(f"\n[red]✗ Failed to delete {len(failed)} file(s):[/red]")
        for filename, error in failed:
            console.print(f"  {filename}: {error}")
        raise typer.Exit(code=1)


def _parse_timestamp(raw: str) -> datetime:
    """Parse a report timestamp, normalizing naive timestamps to UTC."""
    ts = datetime.fromisoformat(raw)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    return ts


def _load_reports(directory: Path) -> list[dict]:
    """Load and parse JSON report files from a directory."""
    report_files = sorted(directory.glob("*.json"))
    if not report_files:
        console.print(f"[yellow]No JSON reports found in {directory}[/yellow]")
        raise typer.Exit(code=0)

    reports = []
    for report_file in report_files:
        try:
            with report_file.open(encoding="utf-8") as f:
                data = json.load(f)
                reports.append({
                    "timestamp": _parse_timestamp(data["timestamp"]),
                    "processes": data["process_count"],
                    "memory_mb": data["total_windsurf_memory_mb"],
                    "cpu": data["total_windsurf_cpu_percent"],
                    "lang_servers": len(data["language_servers"]),
                    "issues": data["log_issues"],
                    "file": report_file.name,
                    "system": data["system"],
                    "windsurf_processes": data["windsurf_processes"],
                    "extensions_count": data["extensions_count"],
                    "mcp_servers_enabled": data["mcp_servers_enabled"],
                })
        except (json.JSONDecodeError, KeyError) as e:
            console.print(f"[yellow]Warning: Could not parse {report_file.name}: {e}[/yellow]")

    if not reports:
        console.print("[red]No valid reports found[/red]")
        raise typer.Exit(code=1)

    return reports


def _display_analysis_summary(reports: list[dict]) -> None:
    """Display timeline, key metrics, and analysis text."""
    # Session summary
    duration = reports[-1]["timestamp"] - reports[0]["timestamp"]
    console.print(
        f"[cyan]Session:[/cyan] {reports[0]['timestamp'].strftime('%Y-%m-%d %H:%M')} → "
        f"{reports[-1]['timestamp'].strftime('%H:%M')} ({len(reports)} snapshots over {duration})"
    )
    console.print()

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
        console.print(f"  [red]⚠️  POTENTIAL MEMORY LEAK: {mem_change:.2f} GB growth[/red]")
    elif mem_change > ANALYZE_MEM_CHANGE_GROWTH_GB:
        console.print(f"  [yellow]⚠️  Memory growth: {mem_change:.2f} GB[/yellow]")
    else:
        console.print(f"  [green]✓ Memory stable (change: {mem_change:+.2f} GB)[/green]")

    if proc_change > ANALYZE_PROC_CHANGE_SIGNIFICANT:
        console.print(f"  [yellow]⚠️  Process count increased by {proc_change}[/yellow]")
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
    """Plot Row 2: Process types, swap usage, language servers & extensions."""
    # Process Count by Type
    ax = axes[1, 0]
    helper_counts, renderer_counts, plugin_counts, main_counts = [], [], [], []
    for r in reports:
        procs = r["windsurf_processes"]
        helper_counts.append(
            sum(
                1
                for p in procs
                if "Helper" in p["name"] and "Renderer" not in p["name"] and "Plugin" not in p["name"] and "GPU" not in p["name"]
            )
        )
        renderer_counts.append(sum(1 for p in procs if "Renderer" in p["name"]))
        plugin_counts.append(sum(1 for p in procs if "Plugin" in p["name"]))
        main_counts.append(sum(1 for p in procs if "Electron" in p["name"] or ("Windsurf" in p["name"] and "Helper" not in p["name"])))

    ax.stackplot(
        timestamps,
        main_counts,
        helper_counts,
        renderer_counts,
        plugin_counts,
        labels=["Main", "Helpers", "Renderers", "Plugins"],
        colors=["#1f77b4", "#ff7f0e", "#2ca02c", "#d62728"],
        alpha=0.7,
    )
    ax.set_ylabel("Process Count", fontsize=10)
    ax.set_title("Process Count by Type", fontsize=11, fontweight="bold")
    ax.legend(loc="upper left", fontsize=8)
    ax.grid(True, alpha=0.3)
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))

    # Swap Usage
    ax = axes[1, 1]
    swap_used = [r["system"]["swap_used_gb"] for r in reports]
    swap_total = [r["system"]["swap_total_gb"] for r in reports]
    ax.plot(timestamps, swap_used, "r-o", linewidth=2, label="Used")
    ax.axhline(y=swap_total[0], color="gray", linestyle="--", alpha=0.5, label=f"Total: {swap_total[0]:.1f} GB")
    ax.fill_between(timestamps, 0, swap_used, alpha=0.3, color="red")
    ax.set_ylabel("Swap (GB)", fontsize=10)
    ax.set_title("Swap Usage", fontsize=11, fontweight="bold")
    ax.legend(fontsize=8)
    ax.grid(True, alpha=0.3)
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))

    # Language Servers & Extensions
    ax = axes[1, 2]
    ax2 = ax.twinx()
    ls_count = [r["lang_servers"] for r in reports]
    ext_count = [r["extensions_count"] for r in reports]
    line1 = ax.plot(timestamps, ls_count, "b-o", linewidth=2, label="Language Servers")
    line2 = ax2.plot(timestamps, ext_count, "g-s", linewidth=2, label="Extensions")
    ax.set_ylabel("Language Servers", color="b", fontsize=10)
    ax2.set_ylabel("Extensions", color="g", fontsize=10)
    ax.tick_params(axis="y", labelcolor="b")
    ax2.tick_params(axis="y", labelcolor="g")
    ax.set_title("Language Servers & Extensions", fontsize=11, fontweight="bold")
    lines = line1 + line2
    ax.legend(lines, [line.get_label() for line in lines], loc="upper left", fontsize=8)
    ax.grid(True, alpha=0.3)
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))


def _plot_row3_charts(axes, timestamps: list, reports: list[dict]) -> None:
    """Plot Row 3: Thread count, average memory per process, issues over time."""
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


def _generate_analysis_plots(reports: list[dict], output: Path | None) -> None:
    """Generate 3x3 matplotlib analysis plots."""
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

    if output:
        plt.savefig(output, dpi=150, bbox_inches="tight")
        console.print(f"\n[green]✓ Plot saved to {output}[/green]")
    else:
        plt.show()


@app.command()
def analyze(
    directory: Annotated[Path, typer.Argument(help="Directory containing JSON reports to analyze")],
    plot: Annotated[bool, typer.Option("--plot", "-p", help="Generate visualizations")] = False,
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Save plots to file")] = None,
) -> None:
    """Analyze historical reports to identify trends and issues.

    Examines multiple JSON reports from watch mode to detect:
    - Memory leaks and growth patterns
    - Process count changes
    - Performance degradation
    - Recurring issues
    """
    if not directory.exists():
        console.print(f"[red]Error: Directory not found: {directory}[/red]")
        raise typer.Exit(code=1)

    reports = _load_reports(directory)

    console.print()
    console.print(make_panel("[bold cyan]Historical Analysis[/bold cyan]"))
    console.print()

    _display_analysis_summary(reports)

    if plot:
        _generate_analysis_plots(reports, output)


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
