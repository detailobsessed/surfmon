"""Display and formatting utilities for monitoring reports."""

from typing import TYPE_CHECKING, Any

from rich.align import Align
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

__all__ = [
    "CPU_PERCENT_CRITICAL",
    "CPU_PERCENT_WARNING",
    "MB_PER_GB",
    "PTY_COUNT_CRITICAL",
    "PTY_COUNT_WARNING",
    "PTY_USAGE_PERCENT_CRITICAL",
    "TABLE_WIDTH",
    "WINDSURF_MEM_PERCENT_CRITICAL",
    "WINDSURF_MEM_PERCENT_WARNING",
    "Live",
    "Table",
    "console",
    "display_report",
    "make_diff_table",
    "make_kv_table",
    "make_panel",
    "make_table",
    "save_report_markdown",
]

from .config import get_paths, get_target_display_name

if TYPE_CHECKING:
    from pathlib import Path

    from .monitor import MonitoringReport

console = Console()

TABLE_WIDTH = 90

# Display thresholds for color-coding
MB_PER_GB = 1024
MEMORY_PERCENT_CRITICAL = 80
MEMORY_PERCENT_WARNING = 60
WINDSURF_MEM_PERCENT_CRITICAL = 20
WINDSURF_MEM_PERCENT_WARNING = 10
CPU_PERCENT_CRITICAL = 50
CPU_PERCENT_WARNING = 20
PTY_COUNT_CRITICAL = 200
PTY_COUNT_WARNING = 50
PTY_USAGE_PERCENT_CRITICAL = 80
PROCESS_MEMORY_HIGH_MB = 1000
PROCESS_MEMORY_MEDIUM_MB = 500
LS_MEMORY_HIGH_MB = 1000
LS_MEMORY_MEDIUM_MB = 200
LS_CPU_HIGH = 5
LS_CPU_MEDIUM = 2
WORKSPACE_ID_MAX_LEN = 20
WORKSPACE_ID_TRUNCATE_LEN = 18
CMDLINE_DISPLAY_MAX_LEN = 100


def make_table(title: str | None = None, **kwargs: Any) -> Table:
    """Create a table with standard width and styling."""
    return Table(title=title, show_header=True, width=TABLE_WIDTH, **kwargs)


def make_kv_table(title: str) -> Table:
    """Create a key-value table (Metric | Value)."""
    table = make_table(title)
    table.add_column("Metric", style="cyan", ratio=1)
    table.add_column("Value", style="green", ratio=2, overflow="fold")
    return table


def make_diff_table(title: str) -> Table:
    """Create a comparison table (Metric | Before | After | Change)."""
    table = make_table(title)
    table.add_column("Metric", style="cyan", ratio=2)
    table.add_column("Before", style="dim", ratio=1)
    table.add_column("After", style="dim", ratio=1)
    table.add_column("Change", style="green", ratio=2, overflow="fold")
    return table


def make_panel(content: str, *, title: str | None = None, style: str = "cyan", center: bool = False) -> Panel:
    """Create a panel with standard width and styling."""
    body = Align.center(content) if center else content
    return Panel(body, title=title, border_style=style, width=TABLE_WIDTH)


def _display_system_table(report: MonitoringReport) -> None:
    """Display system resources table."""
    sys_table = make_kv_table("System Resources")

    sys_table.add_row("Total Memory", f"{report.system.total_memory_gb:.1f} GB")
    sys_table.add_row("Available Memory", f"{report.system.available_memory_gb:.1f} GB")

    mem_color = (
        "red"
        if report.system.memory_percent > MEMORY_PERCENT_CRITICAL
        else "yellow"
        if report.system.memory_percent > MEMORY_PERCENT_WARNING
        else "green"
    )
    sys_table.add_row(
        "Memory Usage",
        f"[{mem_color}]{report.system.memory_percent:.1f}%[/{mem_color}]",
    )
    sys_table.add_row(
        "Swap Used",
        f"{report.system.swap_used_gb:.1f} / {report.system.swap_total_gb:.1f} GB",
    )
    sys_table.add_row("CPU Cores", str(report.system.cpu_count))

    console.print(sys_table)
    console.print()


def _display_windsurf_table(report: MonitoringReport) -> None:
    """Display Windsurf resource usage table."""
    ws_table = make_kv_table("Windsurf Resource Usage")

    ws_table.add_row("Process Count", str(report.process_count))

    mem_gb = report.total_windsurf_memory_mb / MB_PER_GB
    mem_pct = (mem_gb / report.system.total_memory_gb) * 100 if report.system.total_memory_gb > 0 else 0
    mem_color = "red" if mem_pct > WINDSURF_MEM_PERCENT_CRITICAL else "yellow" if mem_pct > WINDSURF_MEM_PERCENT_WARNING else "green"
    ws_table.add_row("Total Memory", f"[{mem_color}]{mem_gb:.2f} GB ({mem_pct:.1f}%)[/{mem_color}]")

    cpu_color = (
        "red"
        if report.total_windsurf_cpu_percent > CPU_PERCENT_CRITICAL
        else "yellow"
        if report.total_windsurf_cpu_percent > CPU_PERCENT_WARNING
        else "green"
    )
    ws_table.add_row(
        "Total CPU",
        f"[{cpu_color}]{report.total_windsurf_cpu_percent:.1f}%[/{cpu_color}]",
    )

    ws_table.add_row("Extensions", str(report.extensions_count))
    ws_table.add_row("MCP Servers", str(len(report.mcp_servers_enabled)))
    ws_table.add_row("Language Servers", str(len(report.language_servers)))
    ws_table.add_row("Active Workspaces", str(len(report.active_workspaces)))
    ws_table.add_row("Launches Today", str(report.windsurf_launches_today))

    # PTY usage
    if report.pty_info:
        pty = report.pty_info
        usage_pct = (pty.system_pty_used / pty.system_pty_limit) * 100 if pty.system_pty_limit > 0 else 0
        pty_color = (
            "red"
            if pty.windsurf_pty_count >= PTY_COUNT_CRITICAL or usage_pct >= PTY_USAGE_PERCENT_CRITICAL
            else "yellow"
            if pty.windsurf_pty_count >= PTY_COUNT_WARNING
            else "green"
        )
        ws_table.add_row(
            "PTYs Held",
            f"[{pty_color}]{pty.windsurf_pty_count}[/{pty_color}] [dim](system: {pty.system_pty_used}/{pty.system_pty_limit})[/dim]",
        )

    console.print(ws_table)
    console.print()


def _display_workspaces_table(report: MonitoringReport) -> None:
    """Display active workspaces table."""
    if not report.active_workspaces:
        return

    workspace_table = make_table("Active Workspaces")
    workspace_table.add_column("ID", style="dim", max_width=20, overflow="fold")
    workspace_table.add_column("Path", style="cyan", ratio=3, overflow="fold")
    workspace_table.add_column("Exists", style="green", ratio=1)
    workspace_table.add_column("Loaded At", style="dim", ratio=2, overflow="fold")

    for ws in report.active_workspaces:
        exists_icon = "✓" if ws.exists else "❌"
        exists_color = "green" if ws.exists else "red"
        workspace_table.add_row(
            (ws.id[:WORKSPACE_ID_TRUNCATE_LEN] + "..") if len(ws.id) > WORKSPACE_ID_MAX_LEN else ws.id,
            ws.path,
            f"[{exists_color}]{exists_icon}[/{exists_color}]",
            ws.loaded_at or "Unknown",
        )

    console.print(workspace_table)
    console.print()


def _display_processes_table(report: MonitoringReport) -> None:
    """Display top processes by memory table."""
    if not report.windsurf_processes:
        return

    top_procs = sorted(report.windsurf_processes, key=lambda p: p.memory_mb, reverse=True)[:10]

    proc_table = make_table("Top 10 Processes by Memory")
    proc_table.add_column("PID", style="dim")
    proc_table.add_column("Name", style="cyan", ratio=3, overflow="fold")
    proc_table.add_column("Memory", justify="right", style="green")
    proc_table.add_column("CPU %", justify="right", style="yellow")
    proc_table.add_column("Threads", justify="right", style="dim")

    for proc in top_procs:
        mem_str = f"{proc.memory_mb:.0f} MB"
        mem_style = "red" if proc.memory_mb > PROCESS_MEMORY_HIGH_MB else "yellow" if proc.memory_mb > PROCESS_MEMORY_MEDIUM_MB else "green"
        proc_table.add_row(
            str(proc.pid),
            proc.name[:40],
            f"[{mem_style}]{mem_str}[/{mem_style}]",
            f"{proc.cpu_percent:.1f}",
            str(proc.num_threads),
        )

    console.print(proc_table)
    console.print()


def _display_language_servers_table(report: MonitoringReport) -> None:
    """Display language servers table."""
    if not report.language_servers:
        return

    ls_table = make_table("Language Servers")
    ls_table.add_column("PID", style="dim")
    ls_table.add_column("Type", style="cyan", ratio=3, overflow="fold")
    ls_table.add_column("Memory", justify="right", style="green")
    ls_table.add_column("CPU %", justify="right", style="yellow")

    for ls in report.language_servers:
        server_type = ls.cmdline
        mem_style = "red" if ls.memory_mb > LS_MEMORY_HIGH_MB else "yellow" if ls.memory_mb > LS_MEMORY_MEDIUM_MB else "green"
        cpu_style = "red" if ls.cpu_percent > LS_CPU_HIGH else "yellow" if ls.cpu_percent > LS_CPU_MEDIUM else "green"

        ls_table.add_row(
            str(ls.pid),
            server_type,
            f"[{mem_style}]{ls.memory_mb:.0f} MB[/{mem_style}]",
            f"[{cpu_style}]{ls.cpu_percent:.1f}[/{cpu_style}]",
        )

    console.print(ls_table)
    console.print()


def _display_verbose_info(report: MonitoringReport) -> None:
    """Display verbose diagnostic information."""
    console.print("[bold cyan]Verbose Diagnostic Information:[/bold cyan]")
    console.print()

    paths = get_paths()
    console.print("[cyan]Configuration Paths:[/cyan]")
    console.print(f"  Extensions: {paths.extensions_dir} ({report.extensions_count} installed)")
    console.print(f"  MCP Config: {paths.mcp_config_path}")
    console.print()

    console.print("[cyan]Process Details:[/cyan]")
    if report.windsurf_processes:
        for proc in sorted(report.windsurf_processes, key=lambda p: p.memory_mb, reverse=True):
            runtime_hours = proc.runtime_seconds / 3600
            console.print(f"  PID {proc.pid}: {proc.name}")
            console.print(
                f"    Memory: {proc.memory_mb:.0f} MB | CPU: {proc.cpu_percent:.1f}% | "
                f"Threads: {proc.num_threads} | Runtime: {runtime_hours:.1f}h"
            )
            cmdline_display = proc.cmdline[:CMDLINE_DISPLAY_MAX_LEN] + ("..." if len(proc.cmdline) > CMDLINE_DISPLAY_MAX_LEN else "")
            console.print(f"    [dim]{cmdline_display}[/dim]")
            console.print()
    else:
        console.print("  [dim]No Windsurf processes running[/dim]")
        console.print()


def display_report(report: MonitoringReport, verbose: bool = False) -> None:
    """Display report in rich terminal format."""
    console.print()

    # Determine Windsurf status
    target_name = get_target_display_name()
    status = "[red]Not Running[/red]" if report.process_count == 0 else "[green]Running[/green]"

    console.print(
        make_panel(
            f"Status: {status}\n[dim]{report.timestamp}[/dim]",
            title=f"[bold cyan]Surfmon[/bold cyan] - {target_name}",
            center=True,
        )
    )
    console.print()

    _display_system_table(report)
    _display_windsurf_table(report)
    _display_workspaces_table(report)
    _display_processes_table(report)
    _display_language_servers_table(report)

    # MCP servers
    if report.mcp_servers_enabled:
        console.print("[bold cyan]Enabled MCP Servers:[/bold cyan]")
        for server in report.mcp_servers_enabled:
            console.print(f"  • {server}")
        console.print()
    elif verbose:
        console.print("[bold cyan]MCP Servers:[/bold cyan]")
        console.print("  [dim]None configured[/dim]")
        console.print()

    # Issues
    if report.log_issues:
        console.print(
            make_panel(
                "\n".join(report.log_issues),
                title="[bold red]Issues Detected[/bold red]",
                style="red",
            )
        )
        console.print()
    else:
        console.print("[green]✓ No critical issues detected[/green]")
        console.print()

    if verbose:
        _display_verbose_info(report)


def save_report_markdown(report: MonitoringReport, output_path: Path) -> None:
    """Save report as Markdown."""
    lines = [
        "# Windsurf Performance Report",
        "",
        f"**Generated:** {report.timestamp}",
        "",
        "## System Resources",
        "",
        f"- **Total Memory:** {report.system.total_memory_gb:.1f} GB",
        f"- **Available Memory:** {report.system.available_memory_gb:.1f} GB ({100 - report.system.memory_percent:.1f}% free)",
        f"- **Memory Usage:** {report.system.memory_percent:.1f}%",
        f"- **Swap Used:** {report.system.swap_used_gb:.1f} / {report.system.swap_total_gb:.1f} GB",
        f"- **CPU Cores:** {report.system.cpu_count}",
        "",
        "## Windsurf Resource Usage",
        "",
        f"- **Process Count:** {report.process_count}",
        (
            f"- **Total Memory:** {report.total_windsurf_memory_mb / 1024:.2f} GB "
            f"({(report.total_windsurf_memory_mb / 1024 / report.system.total_memory_gb) * 100:.1f}% of system)"
            if report.system.total_memory_gb > 0
            else f"- **Total Memory:** {report.total_windsurf_memory_mb / 1024:.2f} GB"
        ),
        f"- **Total CPU:** {report.total_windsurf_cpu_percent:.1f}%",
        f"- **Extensions:** {report.extensions_count}",
        f"- **MCP Servers Enabled:** {len(report.mcp_servers_enabled)}",
        f"- **Language Servers:** {len(report.language_servers)}",
        "",
    ]

    if report.language_servers:
        lines.extend([
            "## Language Servers",
            "",
            "| PID | Type | Memory | CPU % |",
            "|-----|------|--------|-------|",
        ])
        for ls in report.language_servers:
            cmdline_lower = ls.cmdline.lower()
            if "language_server_macos_arm" in cmdline_lower:
                server_type = "Windsurf (Codeium)"
            elif "jdtls" in cmdline_lower or "eclipse.jdt" in cmdline_lower:
                server_type = "Java (JDT.LS)"
            elif "basedpyright" in cmdline_lower:
                server_type = "Python (basedpyright)"
            elif "yaml" in cmdline_lower:
                server_type = "YAML"
            elif "json" in cmdline_lower:
                server_type = "JSON"
            else:
                server_type = "Other"

            lines.append(f"| {ls.pid} | {server_type} | {ls.memory_mb:.0f} MB | {ls.cpu_percent:.1f}% |")
        lines.append("")

    if report.mcp_servers_enabled:
        lines.extend([
            "## Enabled MCP Servers",
            "",
        ])
        lines.extend(f"- {server}" for server in report.mcp_servers_enabled)
        lines.append("")

    if report.pty_info:
        pty = report.pty_info
        lines.extend([
            "## PTY Usage",
            "",
            f"- **Windsurf PTYs:** {pty.windsurf_pty_count}",
            f"- **System PTYs Used:** {pty.system_pty_used} / {pty.system_pty_limit}",
            "",
        ])

    if report.log_issues:
        lines.extend([
            "## Issues Detected",
            "",
        ])
        lines.extend(f"- {issue}" for issue in report.log_issues)
        lines.append("")

    output_path.write_text("\n".join(lines), encoding="utf-8")
