#!/usr/bin/env python3
"""Continuous monitoring daemon for Windsurf performance."""

import argparse
import signal
import sys
import time
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.live import Live
from rich.table import Table

from surfmon.monitor import generate_report, save_report_json

console = Console()
stop_monitoring = False


def signal_handler(signum, frame):
    """Handle interrupt signals gracefully."""
    global stop_monitoring
    stop_monitoring = True
    console.print("\n[yellow]Stopping monitoring...[/yellow]")


def create_summary_table(report, prev_report=None):
    """Create a live summary table."""
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
    mem_pct = (mem_gb / report.system.total_memory_gb) * 100
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
        diff = (
            report.total_windsurf_cpu_percent - prev_report.total_windsurf_cpu_percent
        )
        if abs(diff) > 0.5:
            symbol = "↑" if diff > 0 else "↓"
            color = "red" if diff > 0 else "green"
            cpu_change = f"[{color}]{symbol}{abs(diff):.1f}%[/{color}]"

    cpu_color = (
        "red"
        if report.total_windsurf_cpu_percent > 50
        else "yellow"
        if report.total_windsurf_cpu_percent > 20
        else "green"
    )
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

    # Issues
    issue_count = len(report.log_issues)
    issue_color = "red" if issue_count > 0 else "green"
    table.add_row("Issues", f"[{issue_color}]{issue_count}[/{issue_color}]", "")

    return table


def monitor_continuous(
    interval: int, output_dir: Path, save_interval: int = 300, max_reports: int = 0
) -> None:
    """Monitor Windsurf continuously with live updates."""
    output_dir.mkdir(parents=True, exist_ok=True)

    console.print("[cyan]Starting continuous monitoring...[/cyan]")
    console.print(f"  Interval: {interval}s")
    console.print(f"  Output: {output_dir}")
    console.print(f"  Save every: {save_interval}s")
    if max_reports > 0:
        console.print(f"  Max reports: {max_reports}")
    console.print()
    console.print("[dim]Press Ctrl+C to stop[/dim]")
    console.print()

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
                    json_path = output_dir / f"{timestamp}.json"

                    save_report_json(report, json_path)
                    last_save = current_time

                prev_report = report
                time.sleep(interval)

    except KeyboardInterrupt:
        pass

    console.print()
    console.print(f"[green]✓ Monitoring stopped after {report_count} checks[/green]")


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Continuous Windsurf monitoring daemon"
    )
    parser.add_argument(
        "-i",
        "--interval",
        type=int,
        default=5,
        metavar="SECONDS",
        help="Monitoring interval in seconds (default: 5)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("../reports/watch"),
        metavar="DIR",
        help="Output directory for periodic reports (default: ../reports/watch)",
    )
    parser.add_argument(
        "-s",
        "--save-interval",
        type=int,
        default=300,
        metavar="SECONDS",
        help="Save full report every N seconds (default: 300 = 5 min)",
    )
    parser.add_argument(
        "-n",
        "--max-reports",
        type=int,
        default=0,
        metavar="COUNT",
        help="Stop after N monitoring cycles (default: 0 = infinite)",
    )

    args = parser.parse_args()

    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        monitor_continuous(
            args.interval, args.output, args.save_interval, args.max_reports
        )
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
