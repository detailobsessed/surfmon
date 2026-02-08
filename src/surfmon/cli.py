"""Typer-based CLI for Windsurf Performance Monitor."""

import signal
import time
from datetime import datetime
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

from .compare import compare_reports
from .config import WindsurfTarget, get_target_display_name, set_target
from .monitor import MonitoringReport, generate_report, save_report_json
from .output import display_report, save_report_markdown


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        from . import __version__

        typer.echo(f"surfmon {__version__}")
        raise typer.Exit()


app = typer.Typer(
    name="surfmon",
    help="Monitor Windsurf IDE performance and resource usage",
    add_completion=False,
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


console = Console()
stop_monitoring = False


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
        return name.split("Helper")[0] + "Helper " + name.split("(")[1].split(")")[0]
    return name


def build_process_memory_history(reports: list[dict]) -> dict[str, list[float]]:
    """Build per-process memory history from a series of reports.

    Returns a dict mapping simplified process names to lists of memory values,
    one per report. Processes not present in a report get 0 for that position.
    """
    from collections import defaultdict

    process_mem_history: dict[str, list[float]] = {}

    for report_idx, r in enumerate(reports):
        process_snapshot: dict[str, float] = defaultdict(float)
        for proc in r["windsurf_processes"]:
            name = simplify_process_name(proc["name"])
            process_snapshot[name] += proc["memory_mb"]

        # Append 0 for existing processes not in this snapshot
        for name in process_mem_history:
            if name not in process_snapshot:
                process_mem_history[name].append(0)

        # For processes in this snapshot: pad with leading zeros if new, then append
        for name, mem in process_snapshot.items():
            if name not in process_mem_history:
                process_mem_history[name] = [0.0] * report_idx
            process_mem_history[name].append(mem)

    return process_mem_history


def signal_handler(_signum: int, _frame: object) -> None:
    """Handle interrupt signals gracefully."""
    global stop_monitoring
    stop_monitoring = True
    console.print("\n[yellow]Stopping monitoring...[/yellow]")


def create_summary_table(report: MonitoringReport, prev_report: MonitoringReport | None = None) -> Table:
    """Create a live summary table for watch mode."""
    table = Table(title=f"Windsurf Monitor - {datetime.now().strftime('%H:%M:%S')}")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    table.add_column("Change", style="yellow")

    # Process count
    proc_change = ""
    if prev_report:
        diff = report.process_count - prev_report.process_count
        if diff != 0:
            symbol = "↑" if diff > 0 else "↓"
            color = "red" if diff > 0 else "green"
            proc_change = f"[{color}]{symbol}{abs(diff)}[/{color}]"

    table.add_row("Processes", str(report.process_count), proc_change)

    # Memory
    mem_gb = report.total_windsurf_memory_mb / 1024
    mem_pct = (mem_gb / report.system.total_memory_gb) * 100 if report.system.total_memory_gb > 0 else 0
    mem_str = f"{mem_gb:.2f} GB ({mem_pct:.1f}%)"

    mem_change = ""
    if prev_report:
        prev_mem_gb = prev_report.total_windsurf_memory_mb / 1024
        diff = mem_gb - prev_mem_gb
        if abs(diff) > 0.01:
            symbol = "↑" if diff > 0 else "↓"
            color = "red" if diff > 0 else "green"
            mem_change = f"[{color}]{symbol}{abs(diff):.2f}GB[/{color}]"

    mem_color = "red" if mem_pct > 20 else "yellow" if mem_pct > 10 else "green"
    table.add_row("Memory", f"[{mem_color}]{mem_str}[/{mem_color}]", mem_change)

    # CPU
    cpu_change = ""
    if prev_report:
        diff = report.total_windsurf_cpu_percent - prev_report.total_windsurf_cpu_percent
        if abs(diff) > 0.5:
            symbol = "↑" if diff > 0 else "↓"
            color = "red" if diff > 0 else "green"
            cpu_change = f"[{color}]{symbol}{abs(diff):.1f}%[/{color}]"

    cpu_color = "red" if report.total_windsurf_cpu_percent > 50 else "yellow" if report.total_windsurf_cpu_percent > 20 else "green"
    table.add_row(
        "CPU",
        f"[{cpu_color}]{report.total_windsurf_cpu_percent:.1f}%[/{cpu_color}]",
        cpu_change,
    )

    # Language servers
    ls_change = ""
    if prev_report:
        diff = len(report.language_servers) - len(prev_report.language_servers)
        if diff != 0:
            symbol = "↑" if diff > 0 else "↓"
            color = "red" if diff > 0 else "green"
            ls_change = f"[{color}]{symbol}{abs(diff)}[/{color}]"

    table.add_row("Lang Servers", str(len(report.language_servers)), ls_change)

    # PTYs
    if report.pty_info:
        pty = report.pty_info
        pty_change = ""
        if prev_report and prev_report.pty_info:
            diff = pty.windsurf_pty_count - prev_report.pty_info.windsurf_pty_count
            if diff != 0:
                symbol = "↑" if diff > 0 else "↓"
                color = "red" if diff > 0 else "green"
                pty_change = f"[{color}]{symbol}{abs(diff)}[/{color}]"

        usage_pct = (pty.system_pty_used / pty.system_pty_limit) * 100 if pty.system_pty_limit > 0 else 0
        pty_color = "red" if pty.windsurf_pty_count >= 200 or usage_pct >= 80 else "yellow" if pty.windsurf_pty_count >= 50 else "green"
        table.add_row(
            "PTYs",
            f"[{pty_color}]{pty.windsurf_pty_count}[/{pty_color}] [dim]({pty.system_pty_used}/{pty.system_pty_limit})[/dim]",
            pty_change,
        )

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
            from datetime import datetime

            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
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
    global stop_monitoring
    stop_monitoring = False

    # Create session-specific subdirectory
    session_timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
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
            while not stop_monitoring:
                if max_reports > 0 and report_count >= max_reports:
                    break

                report = generate_report()
                report_count += 1

                # Update live display
                live.update(create_summary_table(report, prev_report))

                # Save report periodically
                current_time = time.time()
                if current_time - last_save >= save_interval:
                    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
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
    from datetime import datetime

    import psutil

    from .config import get_paths

    app_name = get_paths().app_name

    # Find orphaned crashpad handlers
    orphaned = []
    main_windsurf_found = False

    for proc in psutil.process_iter(["pid", "name", "cmdline", "exe", "create_time"]):
        try:
            name = proc.info["name"] or ""
            exe = proc.info["exe"] or ""
            cmdline = " ".join(proc.info["cmdline"] or [])

            if app_name not in exe and app_name not in cmdline:
                continue

            # Check if main Windsurf process
            if (
                name.lower() == "windsurf"
                or f"{app_name}/Contents/MacOS/Windsurf" in exe
                or ("Windsurf" in name and "Helper" not in name and "crashpad" not in name.lower())
            ):
                main_windsurf_found = True

            # Track crashpad handlers
            if "crashpad" in name.lower():
                create_time = proc.info["create_time"]
                age_days = (datetime.now().timestamp() - create_time) / 86400
                orphaned.append((proc, age_days))

        except psutil.NoSuchProcess, psutil.AccessDenied:
            pass

    # Check if Windsurf is running
    if main_windsurf_found:
        console.print("[yellow]⚠ Windsurf is currently running. Crash handlers are not orphaned.[/yellow]")
        console.print("[dim]Close Windsurf first before running cleanup.[/dim]")
        raise typer.Exit(code=1)

    if not orphaned:
        console.print("[green]✓ No orphaned crash handlers found.[/green]")
        raise typer.Exit(code=0)

    # Display what will be killed
    console.print(f"\n[yellow]Found {len(orphaned)} orphaned crash handler(s):[/yellow]\n")

    table = Table(show_header=True)
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

    # Confirm before killing
    if not force:
        confirm = typer.confirm("Kill these processes?")
        if not confirm:
            console.print("[dim]Cancelled.[/dim]")
            raise typer.Exit(code=0)

    # Kill the processes
    killed = 0
    failed = []

    for proc, _ in orphaned:
        try:
            proc.kill()
            killed += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            failed.append((proc.pid, str(e)))

    # Report results
    if killed > 0:
        console.print(f"[green]✓ Successfully killed {killed} process(es)[/green]")

    if failed:
        console.print(f"\n[red]✗ Failed to kill {len(failed)} process(es):[/red]")
        for pid, error in failed:
            console.print(f"  PID {pid}: {error}")
        raise typer.Exit(code=1)


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
    import hashlib
    import json

    if not directory.exists():
        console.print(f"[red]Error: Directory not found: {directory}[/red]")
        raise typer.Exit(code=1)

    if not directory.is_dir():
        console.print(f"[red]Error: Not a directory: {directory}[/red]")
        raise typer.Exit(code=1)

    # Find all JSON files
    json_files = sorted(directory.glob("*.json"))

    if not json_files:
        console.print(f"[yellow]No JSON files found in {directory}[/yellow]")
        raise typer.Exit(code=0)

    console.print(f"[cyan]Analyzing {len(json_files)} report(s)...[/cyan]\n")

    # Group by content hash (excluding timestamp)
    content_hashes = {}
    file_info = []

    for json_file in json_files:
        try:
            with json_file.open(encoding="utf-8") as f:
                data = json.load(f)

            # Remove timestamp for comparison (it will always differ)
            data_copy = data.copy()
            data_copy.pop("timestamp", None)

            # Create hash of content
            content_str = json.dumps(data_copy, sort_keys=True)
            content_hash = hashlib.sha256(content_str.encode()).hexdigest()

            file_info.append({
                "path": json_file,
                "hash": content_hash,
                "timestamp": data.get("timestamp", ""),
                "size": json_file.stat().st_size,
            })

            if content_hash not in content_hashes:
                content_hashes[content_hash] = []
            content_hashes[content_hash].append(json_file)

        except (json.JSONDecodeError, OSError) as e:
            console.print(f"[yellow]Warning: Could not read {json_file.name}: {e}[/yellow]")

    # Find duplicates
    duplicates_to_remove = []
    unique_reports = 0

    for files in content_hashes.values():
        if len(files) > 1:
            # Sort by filename (which contains timestamp)
            files_sorted = sorted(files)

            # Keep first occurrence (oldest), remove rest
            if keep_latest:
                # Keep the latest (last in sorted list)
                duplicates_to_remove.extend(files_sorted[:-1])
            else:
                # Keep the first (oldest)
                duplicates_to_remove.extend(files_sorted[1:])

            unique_reports += 1
        else:
            unique_reports += 1

    if not duplicates_to_remove:
        console.print("[green]✓ No duplicate reports found[/green]")
        console.print(f"All {len(json_files)} reports are unique.")
        raise typer.Exit(code=0)

    # Calculate space savings
    total_size = sum(f.stat().st_size for f in duplicates_to_remove)
    size_mb = total_size / 1024 / 1024

    # Display results
    console.print(f"[yellow]Found {len(duplicates_to_remove)} duplicate report(s)[/yellow]")
    console.print(f"Space to reclaim: {size_mb:.2f} MB\n")

    if dry_run:
        console.print("[dim]Dry run - files that would be deleted:[/dim]\n")
        for file in sorted(duplicates_to_remove):
            console.print(f"  {file.name}")
        console.print("\n[cyan]Run without --dry-run to actually delete these files[/cyan]")
        raise typer.Exit(code=0)

    # Show what will be kept vs removed
    table = Table(title="Summary")
    table.add_column("Category", style="cyan")
    table.add_column("Count", justify="right", style="green")

    table.add_row("Total reports", str(len(json_files)))
    table.add_row("Unique reports", str(unique_reports))
    table.add_row("Duplicates to remove", str(len(duplicates_to_remove)))
    table.add_row("Space to reclaim", f"{size_mb:.2f} MB")

    console.print(table)
    console.print()

    # Confirm
    confirm = typer.confirm("Delete duplicate reports?")
    if not confirm:
        console.print("[dim]Cancelled.[/dim]")
        raise typer.Exit(code=0)

    # Delete duplicates
    deleted = 0
    failed = []

    for file in duplicates_to_remove:
        try:
            file.unlink()
            deleted += 1
        except OSError as e:
            failed.append((file.name, str(e)))

    # Report results
    if deleted > 0:
        console.print(f"[green]✓ Successfully deleted {deleted} duplicate report(s)[/green]")
        console.print(f"[green]✓ Reclaimed {size_mb:.2f} MB[/green]")

    if failed:
        console.print(f"\n[red]✗ Failed to delete {len(failed)} file(s):[/red]")
        for filename, error in failed:
            console.print(f"  {filename}: {error}")
        raise typer.Exit(code=1)


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
    import json
    from datetime import datetime

    if not directory.exists():
        console.print(f"[red]Error: Directory not found: {directory}[/red]")
        raise typer.Exit(code=1)

    # Load all reports
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
                    "timestamp": datetime.fromisoformat(data["timestamp"]),
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

    # Display analysis
    console.print()
    console.print(Panel.fit("[bold cyan]Historical Analysis[/bold cyan]", border_style="cyan"))
    console.print()

    # Session summary
    duration = reports[-1]["timestamp"] - reports[0]["timestamp"]
    console.print(
        f"[cyan]Session:[/cyan] {reports[0]['timestamp'].strftime('%Y-%m-%d %H:%M')} → "
        f"{reports[-1]['timestamp'].strftime('%H:%M')} ({len(reports)} snapshots over {duration})"
    )
    console.print()

    # Timeline table
    timeline = Table(title="Timeline", show_header=True)
    timeline.add_column("Time", style="dim")
    timeline.add_column("Proc", justify="right")
    timeline.add_column("Memory", justify="right")
    timeline.add_column("CPU", justify="right")
    timeline.add_column("LS", justify="right")
    timeline.add_column("Issues", justify="right")

    for r in reports:
        mem_gb = r["memory_mb"] / 1024
        mem_color = "red" if mem_gb > 6 else "yellow" if mem_gb > 4 else "green"
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
    metrics = Table(title="Key Metrics", show_header=True)
    metrics.add_column("Metric", style="cyan")
    metrics.add_column("Start", justify="right")
    metrics.add_column("End", justify="right")
    metrics.add_column("Change", justify="right")
    metrics.add_column("Peak", justify="right")

    # Process count
    proc_change = reports[-1]["processes"] - reports[0]["processes"]
    proc_color = "red" if proc_change > 5 else "yellow" if proc_change > 0 else "green"
    metrics.add_row(
        "Processes",
        str(reports[0]["processes"]),
        str(reports[-1]["processes"]),
        f"[{proc_color}]{proc_change:+d}[/{proc_color}]",
        str(max(r["processes"] for r in reports)),
    )

    # Memory
    mem_change = (reports[-1]["memory_mb"] - reports[0]["memory_mb"]) / 1024
    mem_color = "red" if mem_change > 0.5 else "yellow" if mem_change > 0.2 else "green"
    metrics.add_row(
        "Memory",
        f"{reports[0]['memory_mb'] / 1024:.2f} GB",
        f"{reports[-1]['memory_mb'] / 1024:.2f} GB",
        f"[{mem_color}]{mem_change:+.2f} GB[/{mem_color}]",
        f"{max(r['memory_mb'] for r in reports) / 1024:.2f} GB",
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

    # Analysis
    console.print("[bold cyan]Analysis:[/bold cyan]")
    if mem_change > 0.5:
        console.print(f"  [red]⚠️  POTENTIAL MEMORY LEAK: {mem_change:.2f} GB growth[/red]")
    elif mem_change > 0.2:
        console.print(f"  [yellow]⚠️  Memory growth: {mem_change:.2f} GB[/yellow]")
    else:
        console.print(f"  [green]✓ Memory stable (change: {mem_change:+.2f} GB)[/green]")

    if proc_change > 5:
        console.print(f"  [yellow]⚠️  Process count increased by {proc_change}[/yellow]")
    elif proc_change < 0:
        console.print(f"  [green]✓ Process count decreased by {abs(proc_change)}[/green]")

    # Issues
    final_issues = reports[-1]["issues"]
    if final_issues:
        console.print(f"\n[bold red]Current Issues ({len(final_issues)}):[/bold red]")
        for issue in final_issues:
            console.print(f"  • {issue}")

    # Generate plots if requested
    if plot:
        import matplotlib.dates as mdates
        import matplotlib.pyplot as plt

        fig, axes = plt.subplots(3, 3, figsize=(18, 14))
        fig.suptitle("Windsurf Performance Analysis", fontsize=18, y=0.995)

        timestamps = [r["timestamp"] for r in reports]

        # Row 1, Col 1: Total Memory Usage
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

        # Row 1, Col 2: Top 5 Processes by Memory
        ax = axes[0, 1]
        process_mem_history = build_process_memory_history(reports)

        # Plot top 5 by peak memory
        top_5 = sorted(process_mem_history.items(), key=lambda x: max(x[1]), reverse=True)[:5]
        colors = ["#1f77b4", "#ff7f0e", "#2ca02c", "#d62728", "#9467bd"]
        for (name, mem_history), color in zip(top_5, colors, strict=False):
            ax.plot(
                timestamps,
                [m / 1024 for m in mem_history],
                "-o",
                label=name,
                color=color,
                linewidth=1.5,
            )
        ax.set_ylabel("Memory (GB)", fontsize=10)
        ax.set_title("Top 5 Processes by Memory", fontsize=11, fontweight="bold")
        ax.legend(fontsize=7, loc="best")
        ax.grid(True, alpha=0.3)
        ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))

        # Row 1, Col 3: System Memory Pressure
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
        ax.axhline(
            y=total_mem[0],
            color="r",
            linestyle="--",
            alpha=0.5,
            label=f"Total: {total_mem[0]:.1f} GB",
        )
        ax.set_ylabel("Memory (GB)", fontsize=10)
        ax.set_title("System Memory Pressure", fontsize=11, fontweight="bold")
        ax.legend(fontsize=8)
        ax.grid(True, alpha=0.3)
        ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))

        # Row 2, Col 1: Process Count by Type
        ax = axes[1, 0]
        # Count different process types
        helper_counts = []
        renderer_counts = []
        plugin_counts = []
        main_counts = []
        for r in reports:
            helpers = sum(
                1
                for p in r["windsurf_processes"]
                if "Helper" in p["name"] and "Renderer" not in p["name"] and "Plugin" not in p["name"] and "GPU" not in p["name"]
            )
            renderers = sum(1 for p in r["windsurf_processes"] if "Renderer" in p["name"])
            plugins = sum(1 for p in r["windsurf_processes"] if "Plugin" in p["name"])
            main = sum(
                1 for p in r["windsurf_processes"] if "Electron" in p["name"] or ("Windsurf" in p["name"] and "Helper" not in p["name"])
            )
            helper_counts.append(helpers)
            renderer_counts.append(renderers)
            plugin_counts.append(plugins)
            main_counts.append(main)

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

        # Row 2, Col 2: Swap Usage
        ax = axes[1, 1]
        swap_used = [r["system"]["swap_used_gb"] for r in reports]
        swap_total = [r["system"]["swap_total_gb"] for r in reports]
        ax.plot(timestamps, swap_used, "r-o", linewidth=2, label="Used")
        ax.axhline(
            y=swap_total[0],
            color="gray",
            linestyle="--",
            alpha=0.5,
            label=f"Total: {swap_total[0]:.1f} GB",
        )
        ax.fill_between(timestamps, 0, swap_used, alpha=0.3, color="red")
        ax.set_ylabel("Swap (GB)", fontsize=10)
        ax.set_title("Swap Usage", fontsize=11, fontweight="bold")
        ax.legend(fontsize=8)
        ax.grid(True, alpha=0.3)
        ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))

        # Row 2, Col 3: Language Servers & Extensions
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
        labels = [line.get_label() for line in lines]
        ax.legend(lines, labels, loc="upper left", fontsize=8)
        ax.grid(True, alpha=0.3)
        ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))

        # Row 3, Col 1: Thread Count
        ax = axes[2, 0]
        total_threads = [sum(p["num_threads"] for p in r["windsurf_processes"]) for r in reports]
        ax.plot(timestamps, total_threads, "purple", marker="o", linewidth=2)
        ax.fill_between(timestamps, 0, total_threads, alpha=0.3, color="purple")
        ax.set_ylabel("Thread Count", fontsize=10)
        ax.set_title("Total Thread Count", fontsize=11, fontweight="bold")
        ax.grid(True, alpha=0.3)
        ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))

        # Row 3, Col 2: Average Memory per Process
        ax = axes[2, 1]
        avg_mem = [r["memory_mb"] / r["processes"] if r["processes"] > 0 else 0 for r in reports]
        ax.plot(timestamps, avg_mem, "orange", marker="o", linewidth=2)
        ax.set_ylabel("Memory per Process (MB)", fontsize=10)
        ax.set_title("Average Memory per Process", fontsize=11, fontweight="bold")
        ax.grid(True, alpha=0.3)
        ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))

        # Row 3, Col 3: Issues Over Time
        ax = axes[2, 2]
        issue_counts = [len(r["issues"]) for r in reports]
        ax.plot(timestamps, issue_counts, "m-o", linewidth=2)
        ax.fill_between(timestamps, 0, issue_counts, alpha=0.3, color="magenta")
        ax.set_ylabel("Issue Count", fontsize=10)
        ax.set_title("Issues Detected", fontsize=11, fontweight="bold")
        ax.grid(True, alpha=0.3)
        ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))

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


def main():
    """Entry point for the CLI."""
    app()


if __name__ == "__main__":
    main()
