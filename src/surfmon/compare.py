"""Compare two monitoring reports to show changes."""

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

from .output import console, make_diff_table, make_panel, make_table


def load_report(path: Path) -> dict:
    """Load a JSON report."""
    with path.open(encoding="utf-8") as f:
        return json.load(f)


_MB_TO_GB_THRESHOLD = 1024


def format_memory(mb: float) -> str:
    """Format memory in MB or GB as appropriate."""
    if mb >= _MB_TO_GB_THRESHOLD:
        return f"{mb / _MB_TO_GB_THRESHOLD:.2f} GB"
    return f"{mb:.0f} MB"


def format_diff(old: float, new: float, is_memory: bool = False, reverse: bool = False) -> str:
    """Format a difference with color coding."""
    diff = new - old
    pct_change = (diff / old * 100) if old != 0 else 0

    # For memory/cpu, lower is better (unless reverse=True)
    if not reverse:
        color = "green" if diff < 0 else "red" if diff > 0 else "dim"
        symbol = "↓" if diff < 0 else "↑" if diff > 0 else "→"
    else:
        color = "green" if diff > 0 else "red" if diff < 0 else "dim"
        symbol = "↑" if diff > 0 else "↓" if diff < 0 else "→"

    if is_memory:
        return f"[{color}]{symbol} {format_memory(abs(diff))} ({pct_change:+.1f}%)[/{color}]"
    return f"[{color}]{symbol} {abs(diff):.1f} ({pct_change:+.1f}%)[/{color}]"


def compare_reports(old_path: Path, new_path: Path) -> None:
    """Compare two monitoring reports and display differences."""
    old = load_report(old_path)
    new = load_report(new_path)

    console.print()
    console.print(
        make_panel(
            f"Before: {old['timestamp']}\nAfter:  {new['timestamp']}",
            title="[bold cyan]Windsurf Performance Comparison[/bold cyan]",
            center=True,
        )
    )
    console.print()

    # System changes
    sys_table = make_diff_table("System Resource Changes")

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
        format_diff(old_sys["available_memory_gb"], new_sys["available_memory_gb"], reverse=True),
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
    ws_table = make_diff_table("Windsurf Resource Changes")

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
        format_diff(old["total_windsurf_cpu_percent"], new["total_windsurf_cpu_percent"]),
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
        ls_table = make_table("Language Server Changes")
        ls_table.add_column("PID", style="dim")
        ls_table.add_column("Status", style="cyan", ratio=1)
        ls_table.add_column("Memory Before", justify="right", style="dim", ratio=1)
        ls_table.add_column("Memory After", justify="right", style="dim", ratio=1)
        ls_table.add_column("Change", style="green", ratio=2, overflow="fold")

        # Servers that existed before
        for pid, ls_old in old_ls.items():
            if pid in new_ls:
                ls_new = new_ls[pid]
                status = "Active"
                mem_change = format_diff(ls_old["memory_mb"], ls_new["memory_mb"], is_memory=True)
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
    elif len(new_found) > 0 or new["total_windsurf_memory_mb"] > old["total_windsurf_memory_mb"] * 1.2:
        console.print("[bold red]⚠ Overall: Performance DEGRADED[/bold red]")
    else:
        console.print("[bold yellow]→ Overall: No significant change[/bold yellow]")
    console.print()
