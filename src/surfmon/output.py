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
    "TABLE_WIDTH_MAX",
    "WINDSURF_MEM_PERCENT_CRITICAL",
    "WINDSURF_MEM_PERCENT_WARNING",
    "Live",
    "Table",
    "console",
    "display_report",
    "make_kv_table",
    "make_panel",
    "make_table",
    "save_report_markdown",
    "style_issue",
]

from ._constants import (
    PTY_CRITICAL_COUNT,
    PTY_USAGE_CRITICAL_PERCENT,
    PTY_WARNING_COUNT,
    Issue,
)
from .config import get_paths, get_target_display_name
from .monitor import format_uptime

if TYPE_CHECKING:
    from pathlib import Path

    from .monitor import LsSnapshot, LsSnapshotEntry, MonitoringReport

console = Console()

TABLE_WIDTH_MAX = 90


def _table_width() -> int:
    """Return display width: min of terminal width and TABLE_WIDTH_MAX."""
    try:
        return min(console.width, TABLE_WIDTH_MAX)
    except TypeError:
        return TABLE_WIDTH_MAX


# Display thresholds for color-coding
MB_PER_GB = 1024
MEMORY_PERCENT_CRITICAL = 80
MEMORY_PERCENT_WARNING = 60
WINDSURF_MEM_PERCENT_CRITICAL = 20
WINDSURF_MEM_PERCENT_WARNING = 10
CPU_PERCENT_CRITICAL = 50
CPU_PERCENT_WARNING = 20
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
    return Table(title=title, show_header=True, width=_table_width(), **kwargs)


def make_kv_table(title: str) -> Table:
    """Create a key-value table (Metric | Value)."""
    table = make_table(title)
    table.add_column("Metric", style="cyan", ratio=1)
    table.add_column("Value", style="green", ratio=2, overflow="fold")
    return table


def make_panel(content: str, *, title: str | None = None, style: str = "cyan", center: bool = False) -> Panel:
    """Create a panel with standard width and styling."""
    body = Align.center(content) if center else content
    return Panel(body, title=title, border_style=style, width=_table_width())


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


def _threshold_color(value: float, critical: float, warning: float) -> str:
    """Return 'red', 'yellow', or 'green' based on critical/warning thresholds."""
    if value > critical:
        return "red"
    if value > warning:
        return "yellow"
    return "green"


def _add_pty_kv_row(table: Table, pty: Any) -> None:
    """Add a PTY usage row to a KV table."""
    usage_pct = (pty.system_pty_used / pty.system_pty_limit) * 100 if pty.system_pty_limit > 0 else 0
    pty_color = (
        "red"
        if pty.windsurf_pty_count >= PTY_CRITICAL_COUNT or usage_pct >= PTY_USAGE_CRITICAL_PERCENT
        else "yellow"
        if pty.windsurf_pty_count >= PTY_WARNING_COUNT
        else "green"
    )
    table.add_row(
        "PTYs Held",
        f"[{pty_color}]{pty.windsurf_pty_count}[/{pty_color}] [dim](system: {pty.system_pty_used}/{pty.system_pty_limit})[/dim]",
    )


def _display_windsurf_table(report: MonitoringReport) -> None:
    """Display Windsurf resource usage table.

    When Windsurf is not running (process_count == 0), splits into a minimal
    runtime table and a separate configuration table so persisted data like
    installed extensions and MCP servers isn't confused with active state.
    """
    if report.process_count == 0:
        _display_windsurf_not_running(report)
        return

    ws_table = make_kv_table("Windsurf Resource Usage")
    ws_table.add_row("Process Count", str(report.process_count))

    mem_gb = report.total_windsurf_memory_mb / MB_PER_GB
    mem_pct = (mem_gb / report.system.total_memory_gb) * 100 if report.system.total_memory_gb > 0 else 0
    mem_color = _threshold_color(mem_pct, WINDSURF_MEM_PERCENT_CRITICAL, WINDSURF_MEM_PERCENT_WARNING)
    ws_table.add_row("Total Memory", f"[{mem_color}]{mem_gb:.2f} GB ({mem_pct:.1f}%)[/{mem_color}]")

    cpu_color = _threshold_color(report.total_windsurf_cpu_percent, CPU_PERCENT_CRITICAL, CPU_PERCENT_WARNING)
    ws_table.add_row("Total CPU", f"[{cpu_color}]{report.total_windsurf_cpu_percent:.1f}%[/{cpu_color}]")

    ws_table.add_row("Extensions", str(report.extensions_count))
    ws_table.add_row("MCP Servers", str(len(report.mcp_servers_enabled)))
    ws_table.add_row("Language Servers", str(len(report.language_servers)))
    ws_table.add_row("Active Workspaces", str(len(report.active_workspaces)))
    ws_table.add_row("Launches Today", str(report.windsurf_launches_today))

    if report.pty_info:
        _add_pty_kv_row(ws_table, report.pty_info)

    console.print(ws_table)
    console.print()


def _display_windsurf_not_running(report: MonitoringReport) -> None:
    """Display Windsurf info when not running, separating config from runtime."""
    # Minimal runtime state
    rt_table = make_kv_table("Windsurf Runtime")
    rt_table.add_row("Process Count", "[dim]0[/dim]")
    rt_table.add_row("Launches Today", str(report.windsurf_launches_today))
    console.print(rt_table)
    console.print()

    # Persisted configuration (only if there's something to show)
    has_config = report.extensions_count > 0 or report.mcp_servers_enabled or report.active_workspaces
    if has_config:
        cfg_table = make_kv_table("Windsurf Configuration")
        if report.extensions_count > 0:
            cfg_table.add_row("Installed Extensions", str(report.extensions_count))
        if report.mcp_servers_enabled:
            cfg_table.add_row("Configured MCP Servers", str(len(report.mcp_servers_enabled)))
        if report.active_workspaces:
            cfg_table.add_row("Cached Workspaces", str(len(report.active_workspaces)))
        console.print(cfg_table)
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


def _ls_entry_status_rich(entry: LsSnapshotEntry) -> str:
    """Return a Rich-styled status string for a language server entry."""
    if entry.orphaned:
        return "[red]ORPHANED[/red]"
    if entry.stale:
        return "[yellow]STALE[/yellow]"
    return "[green]ok[/green]"


def _display_language_servers_table(report: MonitoringReport) -> None:
    """Display language servers table with workspace/status columns."""
    if report.ls_snapshot is not None:
        _display_ls_snapshot_table(report.ls_snapshot)


def _display_ls_snapshot_table(snapshot: LsSnapshot) -> None:
    """Display language servers from an LsSnapshot with workspace/status columns."""
    if not snapshot.entries:
        return

    ls_table = make_table("Language Servers")
    ls_table.add_column("PID", style="dim")
    ls_table.add_column("Language", style="cyan")
    ls_table.add_column("Workspace", style="blue", ratio=2, overflow="fold")
    ls_table.add_column("Memory", justify="right", style="green")
    ls_table.add_column("CPU %", justify="right", style="yellow")
    ls_table.add_column("Status", justify="center")

    for entry in snapshot.entries:
        mem_style = "red" if entry.memory_mb > LS_MEMORY_HIGH_MB else "yellow" if entry.memory_mb > LS_MEMORY_MEDIUM_MB else "green"
        cpu_style = "red" if entry.cpu_percent > LS_CPU_HIGH else "yellow" if entry.cpu_percent > LS_CPU_MEDIUM else "green"

        ls_table.add_row(
            str(entry.pid),
            entry.language,
            entry.workspace or "[dim]—[/dim]",
            f"[{mem_style}]{entry.memory_mb:.0f} MB[/{mem_style}]",
            f"[{cpu_style}]{entry.cpu_percent:.1f}[/{cpu_style}]",
            _ls_entry_status_rich(entry),
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


def style_issue(issue: Issue) -> str:
    """Return a Rich-styled string for an Issue, colouring the severity marker."""
    marker = issue.severity.marker
    color = issue.severity.color
    return f"[{color}]{marker}[/{color}]  {issue.message}"


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

    # Skip detail tables already summarized in the config table when not running
    if report.process_count > 0:
        _display_workspaces_table(report)
    _display_processes_table(report)
    _display_language_servers_table(report)

    # MCP servers (skip when not running — already in config summary)
    if report.process_count > 0:
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
                "\n".join(style_issue(issue) for issue in report.log_issues),
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


def _format_pty_markdown(pty: Any) -> list[str]:
    """Format PTY info as Markdown lines for inclusion in reports."""
    usage_pct = (pty.system_pty_used / pty.system_pty_limit) * 100 if pty.system_pty_limit > 0 else 0
    lines = [
        "## PTY Usage",
        "",
        f"- **Windsurf PTYs:** {pty.windsurf_pty_count}",
        f"- **System PTYs Used:** {pty.system_pty_used} / {pty.system_pty_limit} ({usage_pct:.1f}%)",
    ]
    if pty.windsurf_version:
        lines.append(f"- **Windsurf Version:** {pty.windsurf_version}")
    if pty.windsurf_uptime_seconds > 0:
        lines.append(f"- **Windsurf Uptime:** {format_uptime(pty.windsurf_uptime_seconds)}")
    lines.append("")

    if pty.per_process:
        lines.extend([
            "### Per-PID PTY Breakdown",
            "",
            "| PID | Process | PTYs | FD Range |",
            "|-----|---------|------|----------|",
        ])
        for detail in pty.per_process:
            fds_sorted = sorted(detail.fds, key=lambda f: int(f.rstrip("urw")))
            fd_range = f"{fds_sorted[0]}..{fds_sorted[-1]}" if len(fds_sorted) > 1 else fds_sorted[0]
            lines.append(f"| {detail.pid} | {detail.name} | {detail.pty_count} | {fd_range} |")
        lines.append("")

    if pty.fd_entries:
        active = sum(1 for e in pty.fd_entries if e.size_off not in {"0t0", "0"})
        idle = len(pty.fd_entries) - active
        lines.extend([
            f"**FD Status:** {active} active, {idle} idle (zero offset)",
            "",
        ])

    return lines


def _format_ls_markdown(report: MonitoringReport) -> list[str]:
    """Format the language servers section for markdown output."""
    if not (report.ls_snapshot and report.ls_snapshot.entries):
        return []

    snap = report.ls_snapshot
    lines: list[str] = [
        "## Language Servers",
        "",
        (f"**Total:** {snap.total_ls_count} | **Orphaned:** {snap.orphaned_count} | **Stale:** {snap.stale_count}"),
        "",
        "| PID | Language | Workspace | Memory | CPU % | Status |",
        "|-----|----------|-----------|--------|-------|--------|",
    ]
    for entry in snap.entries:
        status = "ORPHANED" if entry.orphaned else "STALE" if entry.stale else "ok"
        lines.append(
            f"| {entry.pid} | {entry.language} | {entry.workspace} | {entry.memory_mb:.0f} MB | {entry.cpu_percent:.1f}% | {status} |"
        )
    lines.append("")
    return lines


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

    lines.extend(_format_ls_markdown(report))

    if report.mcp_servers_enabled:
        lines.extend([
            "## Enabled MCP Servers",
            "",
        ])
        lines.extend(f"- {server}" for server in report.mcp_servers_enabled)
        lines.append("")

    if report.pty_info:
        lines.extend(_format_pty_markdown(report.pty_info))

    if report.log_issues:
        lines.extend([
            "## Issues Detected",
            "",
        ])
        lines.extend(f"- {issue}" for issue in report.log_issues)
        lines.append("")

    output_path.write_text("\n".join(lines), encoding="utf-8")
