#!/usr/bin/env python3
"""Compare two Windsurf monitoring reports to show changes."""

import argparse
import json
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def load_report(path: Path) -> dict:
    """Load a JSON report."""
    with open(path) as f:
        return json.load(f)


def format_memory(mb: float) -> str:
    """Format memory in MB or GB as appropriate."""
    if mb >= 1024:
        return f"{mb / 1024:.2f} GB"
    return f"{mb:.0f} MB"


def format_diff(
    old: float, new: float, is_memory: bool = False, reverse: bool = False
) -> str:
    """Format a difference with color coding."""
    diff = new - old
    pct_change = (diff / old * 100) if old > 0 else 0

    # For memory/cpu, lower is better (unless reverse=True)
    if not reverse:
        color = "green" if diff < 0 else "red" if diff > 0 else "dim"
        symbol = "↓" if diff < 0 else "↑" if diff > 0 else "→"
    else:
        color = "green" if diff > 0 else "red" if diff < 0 else "dim"
        symbol = "↑" if diff > 0 else "↓" if diff < 0 else "→"

    if is_memory:
        return f"[{color}]{symbol} {format_memory(abs(diff))} ({pct_change:+.1f}%)[/{color}]"
    else:
        return f"[{color}]{symbol} {abs(diff):.1f} ({pct_change:+.1f}%)[/{color}]"


def compare_reports(old_path: Path, new_path: Path) -> None:
    """Compare two monitoring reports and display differences."""
    old = load_report(old_path)
    new = load_report(new_path)

    console.print()
    console.print(
        Panel.fit(
            "[bold cyan]Windsurf Performance Comparison[/bold cyan]\\n"
            + f"Before: {old['timestamp']}\\n"
            + f"After:  {new['timestamp']}",
            border_style="cyan",
        )
    )
    console.print()

    # System changes
    sys_table = Table(title="System Resource Changes", show_header=True)
    sys_table.add_column("Metric", style="cyan")
    sys_table.add_column("Before", style="dim")
    sys_table.add_column("After", style="dim")
    sys_table.add_column("Change", style="green")

    old_sys = old["system"]
    new_sys = new["system"]

    sys_table.add_row(
        "Memory Usage",
        f"{old_sys['memory_percent']:.1f}%",
        f"{new_sys['memory_percent']:.1f}%",
        format_diff(old_sys["memory_percent"], new_sys["memory_percent"]),
    )

    sys_table.add_row(
        "Available Memory",
        f"{old_sys['available_memory_gb']:.1f} GB",
        f"{new_sys['available_memory_gb']:.1f} GB",
        format_diff(
            old_sys["available_memory_gb"], new_sys["available_memory_gb"], reverse=True
        ),
    )

    sys_table.add_row(
        "Swap Used",
        f"{old_sys['swap_used_gb']:.1f} GB",
        f"{new_sys['swap_used_gb']:.1f} GB",
        format_diff(old_sys["swap_used_gb"], new_sys["swap_used_gb"]),
    )

    console.print(sys_table)
    console.print()

    # Windsurf changes
    ws_table = Table(title="Windsurf Resource Changes", show_header=True)
    ws_table.add_column("Metric", style="cyan")
    ws_table.add_column("Before", style="dim")
    ws_table.add_column("After", style="dim")
    ws_table.add_column("Change", style="green")

    ws_table.add_row(
        "Process Count",
        str(old["process_count"]),
        str(new["process_count"]),
        format_diff(old["process_count"], new["process_count"]),
    )

    ws_table.add_row(
        "Total Memory",
        format_memory(old["total_windsurf_memory_mb"]),
        format_memory(new["total_windsurf_memory_mb"]),
        format_diff(
            old["total_windsurf_memory_mb"],
            new["total_windsurf_memory_mb"],
            is_memory=True,
        ),
    )

    ws_table.add_row(
        "Total CPU",
        f"{old['total_windsurf_cpu_percent']:.1f}%",
        f"{new['total_windsurf_cpu_percent']:.1f}%",
        format_diff(
            old["total_windsurf_cpu_percent"], new["total_windsurf_cpu_percent"]
        ),
    )

    ws_table.add_row(
        "Extensions",
        str(old["extensions_count"]),
        str(new["extensions_count"]),
        format_diff(old["extensions_count"], new["extensions_count"]),
    )

    ws_table.add_row(
        "MCP Servers",
        str(len(old["mcp_servers_enabled"])),
        str(len(new["mcp_servers_enabled"])),
        format_diff(len(old["mcp_servers_enabled"]), len(new["mcp_servers_enabled"])),
    )

    ws_table.add_row(
        "Language Servers",
        str(len(old["language_servers"])),
        str(len(new["language_servers"])),
        format_diff(len(old["language_servers"]), len(new["language_servers"])),
    )

    console.print(ws_table)
    console.print()

    # Language server changes
    old_ls = {ls["pid"]: ls for ls in old["language_servers"]}
    new_ls = {ls["pid"]: ls for ls in new["language_servers"]}

    if old_ls or new_ls:
        ls_table = Table(title="Language Server Changes", show_header=True)
        ls_table.add_column("PID", style="dim")
        ls_table.add_column("Status", style="cyan")
        ls_table.add_column("Memory Before", justify="right", style="dim")
        ls_table.add_column("Memory After", justify="right", style="dim")
        ls_table.add_column("Change", style="green")

        # Servers that existed before
        for pid, ls_old in old_ls.items():
            if pid in new_ls:
                ls_new = new_ls[pid]
                status = "Active"
                mem_change = format_diff(
                    ls_old["memory_mb"], ls_new["memory_mb"], is_memory=True
                )
                ls_table.add_row(
                    str(pid),
                    status,
                    format_memory(ls_old["memory_mb"]),
                    format_memory(ls_new["memory_mb"]),
                    mem_change,
                )
            else:
                ls_table.add_row(
                    str(pid),
                    "[red]Stopped[/red]",
                    format_memory(ls_old["memory_mb"]),
                    "-",
                    "",
                )

        # New servers
        for pid, ls_new in new_ls.items():
            if pid not in old_ls:
                ls_table.add_row(
                    str(pid),
                    "[green]Started[/green]",
                    "-",
                    format_memory(ls_new["memory_mb"]),
                    "",
                )

        console.print(ls_table)
        console.print()

    # Issue changes
    old_issues = set(old["log_issues"])
    new_issues = set(new["log_issues"])

    resolved = old_issues - new_issues
    new_found = new_issues - old_issues
    persisting = old_issues & new_issues

    if resolved or new_found or persisting:
        console.print("[bold cyan]Issue Changes:[/bold cyan]")
        console.print()

        if resolved:
            console.print("[bold green]✓ Resolved:[/bold green]")
            for issue in resolved:
                console.print(f"  {issue}")
            console.print()

        if new_found:
            console.print("[bold red]⚠ New Issues:[/bold red]")
            for issue in new_found:
                console.print(f"  {issue}")
            console.print()

        if persisting:
            console.print("[bold yellow]• Still Present:[/bold yellow]")
            for issue in persisting:
                console.print(f"  {issue}")
            console.print()
    else:
        console.print("[green]✓ No issues in either report[/green]")
        console.print()

    # Summary
    mem_improved = new["total_windsurf_memory_mb"] < old["total_windsurf_memory_mb"]
    proc_reduced = new["process_count"] < old["process_count"]

    if mem_improved and proc_reduced and not new_found:
        console.print("[bold green]🎉 Overall: Performance IMPROVED![/bold green]")
    elif (
        len(new_found) > 0
        or new["total_windsurf_memory_mb"] > old["total_windsurf_memory_mb"] * 1.2
    ):
        console.print("[bold red]⚠ Overall: Performance DEGRADED[/bold red]")
    else:
        console.print("[bold yellow]→ Overall: No significant change[/bold yellow]")
    console.print()


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Compare two Windsurf monitoring reports"
    )
    parser.add_argument(
        "before", type=Path, help='Path to the "before" report JSON file'
    )
    parser.add_argument("after", type=Path, help='Path to the "after" report JSON file')

    args = parser.parse_args()

    if not args.before.exists():
        console.print(f"[red]Error: Before report not found: {args.before}[/red]")
        sys.exit(1)

    if not args.after.exists():
        console.print(f"[red]Error: After report not found: {args.after}[/red]")
        sys.exit(1)

    try:
        compare_reports(args.before, args.after)
    except Exception as e:
        console.print(f"[red]Error comparing reports: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
