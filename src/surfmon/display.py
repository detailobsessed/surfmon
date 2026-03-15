"""Interactive display helpers for CLI snapshot and analysis commands.

Extracted from cli.py to reduce file size and isolate display concerns
from command logic.
"""

import time
from collections import defaultdict
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import matplotlib.dates as mdates
import matplotlib.pyplot as plt

from ._constants import (
    PTY_CRITICAL_COUNT,
    PTY_USAGE_CRITICAL_PERCENT,
    PTY_WARNING_COUNT,
)
from .monitor import (
    format_uptime,
)
from .output import (
    CPU_PERCENT_CRITICAL,
    CPU_PERCENT_WARNING,
    MB_PER_GB,
    WINDSURF_MEM_PERCENT_CRITICAL,
    WINDSURF_MEM_PERCENT_WARNING,
    console,
    make_kv_table,
    make_panel,
    make_table,
    style_issue,
)

if TYPE_CHECKING:
    from rich.table import Table

    from .monitor import LsSnapshot, LsSnapshotEntry, MonitoringReport, PtyInfo

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

# Trend display
MIN_TREND_POINTS_FOR_CHANGE = 2


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


def _fmt_gb(mb: float | None) -> str:
    """Format nullable megabytes as 'X.XX GB' or '—'."""
    if not mb:
        return "—"
    return f"{mb / MB_PER_GB:.2f} GB"


def _fmt_or_dash(value: object) -> str:
    """Format a nullable value as a string, using '—' for falsy values."""
    return str(value) if value else "—"


def _fmt_styled_count(count: int | None, bad_color: str = "red", good_color: str = "") -> str:
    """Style a count: bad_color when positive, good_color otherwise, '—' when None."""
    if count is None:
        return "—"
    if count > 0 and bad_color:
        return f"[{bad_color}]{count}[/{bad_color}]"
    if good_color:
        return f"[{good_color}]{count}[/{good_color}]"
    return _fmt_or_dash(count)


def _format_history_row(row: dict) -> tuple[str, ...]:
    """Format a single history row into display strings for the table."""
    return (
        row["timestamp"][:19] if row["timestamp"] else "",
        row["command"] or "",
        row["windsurf_version"] or "",
        _fmt_gb(row["total_memory_mb"]),
        _fmt_or_dash(row["process_count"]),
        _fmt_or_dash(row["ls_count"]),
        _fmt_gb(row["ls_memory_mb"]),
        _fmt_styled_count(row["orphaned_count"]),
        _fmt_or_dash(row["pty_count"]) if row["pty_count"] is not None else "—",
        _fmt_styled_count(row["issue_count"], good_color="green"),
    )


def display_history_table(rows: list[dict]) -> None:
    """Display a Rich table of historical monitoring sessions."""
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
        table.add_row(*_format_history_row(row))

    console.print(table)


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


def _format_elapsed(seconds: float) -> str:
    """Format elapsed seconds as H:MM:SS or M:SS."""
    total = int(seconds)
    h, remainder = divmod(total, 3600)
    m, s = divmod(remainder, 60)
    return f"{h}:{m:02d}:{s:02d}" if h else f"{m}:{s:02d}"


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
    orphan_color = "red" if snap.orphaned_count > 0 else "green"
    table.add_row("  Orphaned", f"[{orphan_color}]{snap.orphaned_count}[/{orphan_color}]", "")
    stale_color = "yellow" if snap.stale_count > 0 else "green"
    table.add_row("  Stale", f"[{stale_color}]{snap.stale_count}[/{stale_color}]", "")


def _add_memory_row(table: Table, report: MonitoringReport, prev_report: MonitoringReport | None) -> None:
    """Add memory usage row to the summary table."""
    mem_gb = report.total_windsurf_memory_mb / MB_PER_GB
    mem_pct = (mem_gb / report.system.total_memory_gb) * 100 if report.system.total_memory_gb > 0 else 0
    mem_str = f"{mem_gb:.2f} GB ({mem_pct:.1f}%)"

    mem_change = ""
    if prev_report:
        prev_mem_gb = prev_report.total_windsurf_memory_mb / MB_PER_GB
        mem_change = _format_change(mem_gb - prev_mem_gb, threshold=MEM_DIFF_SIGNIFICANT_GB, fmt=".2f", suffix="GB")

    mem_color = "red" if mem_pct > WINDSURF_MEM_PERCENT_CRITICAL else "yellow" if mem_pct > WINDSURF_MEM_PERCENT_WARNING else "green"
    table.add_row("Memory", f"[{mem_color}]{mem_str}[/{mem_color}]", mem_change)


def _add_cpu_row(table: Table, report: MonitoringReport, prev_report: MonitoringReport | None) -> None:
    """Add CPU usage row to the summary table."""
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

    _add_memory_row(table, report, prev_report)
    _add_cpu_row(table, report, prev_report)

    # Language servers
    ls_change = _format_change(len(report.language_servers) - len(prev_report.language_servers)) if prev_report else ""
    table.add_row("Lang Servers", str(len(report.language_servers)), ls_change)

    _add_ls_snapshot_rows(table, report)
    _add_pty_row(table, report, prev_report)

    # Issues
    issue_count = len(report.log_issues)
    issue_color = "red" if issue_count > 0 else "green"
    table.add_row("Issues", f"[{issue_color}]{issue_count}[/{issue_color}]", "")

    return table


def _pty_summary_table(pty: PtyInfo) -> None:
    """Display PTY summary KV table."""
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


def _pty_per_pid_table(pty: PtyInfo) -> None:
    """Display per-PID PTY breakdown table."""
    pid_table = make_table("Windsurf Per-PID PTY Ownership")
    pid_table.add_column("PID", style="dim")
    pid_table.add_column("Process", style="cyan", ratio=2)
    pid_table.add_column("PTYs", justify="right", style="yellow")
    pid_table.add_column("FD Range", style="dim", ratio=2)

    for detail in pty.per_process or []:
        fds_sorted = sorted(detail.fds, key=lambda f: int(f.rstrip("urw")))
        fd_range = f"{fds_sorted[0]}..{fds_sorted[-1]}" if len(fds_sorted) > 1 else fds_sorted[0]
        pid_table.add_row(str(detail.pid), detail.name, str(detail.pty_count), fd_range)

    console.print(pid_table)
    console.print()


def _pty_other_holders_table(pty: PtyInfo) -> None:
    """Display non-Windsurf PTY holders table."""
    other_table = make_table("Other PTY Holders (for context)")
    other_table.add_column("PID", style="dim")
    other_table.add_column("Process", style="cyan", ratio=2)
    other_table.add_column("PTYs", justify="right", style="green")

    for detail in pty.non_windsurf_holders or []:
        other_table.add_row(str(detail.pid), detail.name, str(detail.pty_count))

    console.print(other_table)
    console.print()


def _pty_fd_detail_table(pty: PtyInfo) -> None:
    """Display Windsurf FD detail table."""
    fd_table = make_table("Windsurf FD Detail")
    fd_table.add_column("PID", style="dim")
    fd_table.add_column("FD", style="yellow")
    fd_table.add_column("Device", style="dim")
    fd_table.add_column("Offset", style="cyan")
    fd_table.add_column("Status", style="dim")

    for entry in sorted(pty.fd_entries or [], key=lambda e: (e.pid, int(e.fd.rstrip("urw")))):
        is_zero = entry.size_off in {"0t0", "0"}
        status = "[dim]idle[/dim]" if is_zero else "[green]active[/green]"
        fd_table.add_row(str(entry.pid), entry.fd, entry.device, entry.size_off, status)

    fd_list = pty.fd_entries or []
    active_count = sum(1 for e in fd_list if e.size_off not in {"0t0", "0"})
    idle_count = len(fd_list) - active_count
    console.print(fd_table)
    console.print(f"  [dim]{active_count} active, {idle_count} idle (zero offset)[/dim]")
    console.print()


def display_pty_snapshot(pty: PtyInfo) -> None:
    """Display a comprehensive PTY forensic snapshot to the console."""
    _pty_summary_table(pty)
    if pty.per_process:
        _pty_per_pid_table(pty)
    if pty.non_windsurf_holders:
        _pty_other_holders_table(pty)
    if pty.fd_entries:
        _pty_fd_detail_table(pty)


def _ls_entry_status(entry: LsSnapshotEntry) -> str:
    """Return a Rich-styled status string for a language server entry."""
    if entry.orphaned:
        return "[red]ORPHANED[/red]"
    if entry.stale:
        return "[yellow]STALE[/yellow]"
    return "[green]ok[/green]"


def _ls_mem_style(memory_mb: float) -> str:
    """Return color style for a language server memory value."""
    if memory_mb > LS_PROC_MEM_CRITICAL_MB:
        return "red"
    if memory_mb > LS_PROC_MEM_WARNING_MB:
        return "yellow"
    return "green"


def _ls_summary_table(snapshot: LsSnapshot) -> None:
    """Print the LS snapshot summary KV table."""
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


def _ls_detail_table(snapshot: LsSnapshot) -> None:
    """Print the per-LS process detail table."""
    if not snapshot.entries:
        return
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
        mem_style = _ls_mem_style(entry.memory_mb)
        detail.add_row(
            str(entry.pid),
            entry.language,
            f"[{mem_style}]{entry.memory_mb:.1f} MB[/{mem_style}]",
            f"{entry.cpu_percent:.1f}",
            str(entry.num_threads),
            format_uptime(entry.runtime_seconds),
            entry.workspace or "[dim]—[/dim]",
            _ls_entry_status(entry),
        )

    console.print(detail)
    console.print()


def display_ls_snapshot(snapshot: LsSnapshot) -> None:
    """Display a language server forensic snapshot to the console."""
    _ls_summary_table(snapshot)
    _ls_detail_table(snapshot)

    if snapshot.issues:
        console.print(make_panel("[red]Issues Detected[/red]", title="⚠ Issues"))
        for issue in snapshot.issues:
            console.print(f"  {style_issue(issue)}")
        console.print()


def display_analysis_summary(reports: list[dict], *, summary: bool = False) -> None:
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
        _display_timeline_table(reports)

    # Key metrics
    _display_key_metrics(reports)

    # Analysis
    _display_analysis_text(reports)


def _display_timeline_table(reports: list[dict]) -> None:
    """Display per-session timeline table."""
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


def _display_analysis_text(reports: list[dict]) -> None:
    """Display memory/process analysis text."""
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


def display_trend_summary(values: list[float], unit: str) -> None:
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


def _plot_memory_charts(axes: Any, timestamps: list, reports: list[dict]) -> None:
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


def _plot_pty_chart(ax: Any, timestamps: list, reports: list[dict]) -> None:
    """Plot PTY usage with Windsurf count and system percentage."""
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


def _plot_row2_charts(axes: Any, timestamps: list, reports: list[dict]) -> None:
    """Plot Row 2: Process types, PTY usage, language servers & extensions."""
    # Process Count by Type
    ax = axes[1, 0]
    proc_types: dict[str, list[int]] = defaultdict(list)
    for r in reports:
        type_counts: dict[str, int] = defaultdict(int)
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


def _plot_row3_charts(axes: Any, timestamps: list, reports: list[dict]) -> None:
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


def generate_analysis_plots(reports: list[dict], output: Any) -> None:
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

    try:
        plt.savefig(output, dpi=150, bbox_inches="tight")
        console.print(f"\n[green]✓ Plot saved to {output}[/green]")
    except OSError as e:
        console.print(f"\n[red]Error: Cannot save plot to {output}: {e}[/red]")
