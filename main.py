#!/usr/bin/env python3
"""Windsurf Performance Monitor - Analyze Windsurf IDE performance and resource usage."""

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

import psutil
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


@dataclass
class ProcessInfo:
    """Information about a Windsurf process."""

    pid: int
    name: str
    cpu_percent: float
    memory_mb: float
    memory_percent: float
    num_threads: int
    runtime_seconds: float
    cmdline: str


@dataclass
class SystemInfo:
    """System-wide resource information."""

    total_memory_gb: float
    available_memory_gb: float
    memory_percent: float
    cpu_count: int
    swap_total_gb: float
    swap_used_gb: float


@dataclass
class MonitoringReport:
    """Complete monitoring report."""

    timestamp: str
    system: SystemInfo
    windsurf_processes: list[ProcessInfo]
    total_windsurf_memory_mb: float
    total_windsurf_cpu_percent: float
    process_count: int
    language_servers: list[ProcessInfo]
    mcp_servers_enabled: list[str]
    extensions_count: int
    log_issues: list[str]


def get_windsurf_processes() -> list[psutil.Process]:
    """Find all Windsurf-related processes."""
    windsurf_procs = []
    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            name = proc.info["name"] or ""
            cmdline = " ".join(proc.info["cmdline"] or [])
            if "windsurf" in name.lower() or "windsurf" in cmdline.lower():
                windsurf_procs.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return windsurf_procs


def get_process_info(proc: psutil.Process) -> ProcessInfo | None:
    """Extract detailed information from a process."""
    try:
        with proc.oneshot():
            cpu_percent = proc.cpu_percent(interval=0.1)
            memory_info = proc.memory_info()
            memory_mb = memory_info.rss / 1024 / 1024
            memory_percent = proc.memory_percent()
            num_threads = proc.num_threads()
            create_time = proc.create_time()
            runtime = datetime.now().timestamp() - create_time
            cmdline = " ".join(proc.cmdline())

            # Truncate cmdline if too long
            if len(cmdline) > 200:
                cmdline = cmdline[:200] + "..."

            return ProcessInfo(
                pid=proc.pid,
                name=proc.name(),
                cpu_percent=cpu_percent,
                memory_mb=memory_mb,
                memory_percent=memory_percent,
                num_threads=num_threads,
                runtime_seconds=runtime,
                cmdline=cmdline,
            )
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None


def get_system_info() -> SystemInfo:
    """Get system-wide resource information."""
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()

    return SystemInfo(
        total_memory_gb=mem.total / 1024 / 1024 / 1024,
        available_memory_gb=mem.available / 1024 / 1024 / 1024,
        memory_percent=mem.percent,
        cpu_count=psutil.cpu_count(),
        swap_total_gb=swap.total / 1024 / 1024 / 1024,
        swap_used_gb=swap.used / 1024 / 1024 / 1024,
    )


def find_language_servers(processes: list[ProcessInfo]) -> list[ProcessInfo]:
    """Identify language server processes."""
    keywords = [
        "language_server",
        "jdtls",
        "gopls",
        "pyright",
        "pylance",
        "basedpyright",
        "yaml-language-server",
        "json-language-server",
    ]
    return [p for p in processes if any(kw in p.cmdline.lower() for kw in keywords)]


def get_mcp_config() -> list[str]:
    """Read MCP configuration and return enabled servers."""
    mcp_config_path = Path.home() / ".codeium" / "windsurf" / "mcp_config.json"
    if not mcp_config_path.exists():
        return []

    try:
        with open(mcp_config_path) as f:
            config = json.load(f)
            servers = config.get("mcpServers", {})
            return [
                name for name, cfg in servers.items() if not cfg.get("disabled", False)
            ]
    except (json.JSONDecodeError, KeyError):
        return []


def count_extensions() -> int:
    """Count installed Windsurf extensions."""
    ext_dir = Path.home() / ".windsurf" / "extensions"
    if not ext_dir.exists():
        return 0

    # Count directories that look like extensions (have version numbers)
    count = 0
    for item in ext_dir.iterdir():
        if item.is_dir() and item.name != "logs":
            # Simple heuristic: has a version-like pattern
            if any(char.isdigit() for char in item.name):
                count += 1
    return count


def check_log_issues() -> list[str]:
    """Check for common issues in Windsurf logs."""
    issues = []

    # Check for logs directory in extensions (causing package.json error)
    logs_dir = Path.home() / ".windsurf" / "extensions" / "logs"
    if logs_dir.exists():
        issues.append(
            "⚠️  'logs' directory exists in extensions folder (causes package.json errors)"
        )

    # Check latest log directory
    log_base = Path.home() / "Library" / "Application Support" / "Windsurf" / "logs"
    if log_base.exists():
        log_dirs = sorted(log_base.iterdir(), reverse=True)
        if log_dirs:
            latest_log = log_dirs[0]

            # Check for extension host crashes
            main_log = latest_log / "main.log"
            if main_log.exists():
                try:
                    with open(main_log) as f:
                        content = f.read()
                        if "Extension host" in content and "exited" in content:
                            crash_count = content.count("Extension host with pid")
                            if crash_count > 0:
                                issues.append(
                                    f"⚠️  {crash_count} extension host exits detected"
                                )

                        if "UpdateService error" in content:
                            issues.append(
                                "⚠️  Update service timeouts detected (check NextDNS)"
                            )
                except Exception:
                    pass

            # Check network errors
            network_log = latest_log / "network-shared.log"
            if network_log.exists():
                try:
                    with open(network_log) as f:
                        content = f.read()
                        telemetry_errors = content.count(
                            "windsurf-telemetry.codeium.com"
                        )
                        if telemetry_errors > 5:
                            issues.append(
                                f"⚠️  {telemetry_errors} telemetry connection failures (check NextDNS)"
                            )
                except Exception:
                    pass

    return issues


def generate_report() -> MonitoringReport:
    """Generate complete monitoring report."""
    procs = get_windsurf_processes()
    proc_infos = [pi for p in procs if (pi := get_process_info(p)) is not None]

    total_memory = sum(p.memory_mb for p in proc_infos)
    total_cpu = sum(p.cpu_percent for p in proc_infos)

    return MonitoringReport(
        timestamp=datetime.now().isoformat(),
        system=get_system_info(),
        windsurf_processes=proc_infos,
        total_windsurf_memory_mb=total_memory,
        total_windsurf_cpu_percent=total_cpu,
        process_count=len(proc_infos),
        language_servers=find_language_servers(proc_infos),
        mcp_servers_enabled=get_mcp_config(),
        extensions_count=count_extensions(),
        log_issues=check_log_issues(),
    )


def display_report(report: MonitoringReport, verbose: bool = False) -> None:
    """Display report in rich terminal format."""
    console.print()
    console.print(
        Panel.fit(
            "[bold cyan]Windsurf Performance Monitor[/bold cyan]\n"
            + f"Report generated: {report.timestamp}",
            border_style="cyan",
        )
    )
    console.print()

    # System overview
    sys_table = Table(title="System Resources", show_header=True)
    sys_table.add_column("Metric", style="cyan")
    sys_table.add_column("Value", style="green")

    sys_table.add_row("Total Memory", f"{report.system.total_memory_gb:.1f} GB")
    sys_table.add_row("Available Memory", f"{report.system.available_memory_gb:.1f} GB")

    mem_color = (
        "red"
        if report.system.memory_percent > 80
        else "yellow"
        if report.system.memory_percent > 60
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

    # Windsurf summary
    ws_table = Table(title="Windsurf Resource Usage", show_header=True)
    ws_table.add_column("Metric", style="cyan")
    ws_table.add_column("Value", style="green")

    ws_table.add_row("Process Count", str(report.process_count))

    mem_gb = report.total_windsurf_memory_mb / 1024
    mem_pct = (
        report.total_windsurf_memory_mb / 1024 / report.system.total_memory_gb
    ) * 100
    mem_color = "red" if mem_pct > 20 else "yellow" if mem_pct > 10 else "green"
    ws_table.add_row(
        "Total Memory", f"[{mem_color}]{mem_gb:.2f} GB ({mem_pct:.1f}%)[/{mem_color}]"
    )

    cpu_color = (
        "red"
        if report.total_windsurf_cpu_percent > 50
        else "yellow"
        if report.total_windsurf_cpu_percent > 20
        else "green"
    )
    ws_table.add_row(
        "Total CPU",
        f"[{cpu_color}]{report.total_windsurf_cpu_percent:.1f}%[/{cpu_color}]",
    )

    ws_table.add_row("Extensions", str(report.extensions_count))
    ws_table.add_row("MCP Servers", str(len(report.mcp_servers_enabled)))
    ws_table.add_row("Language Servers", str(len(report.language_servers)))

    console.print(ws_table)
    console.print()

    # Top processes
    if report.windsurf_processes:
        top_procs = sorted(
            report.windsurf_processes, key=lambda p: p.memory_mb, reverse=True
        )[:10]

        proc_table = Table(title="Top 10 Processes by Memory", show_header=True)
        proc_table.add_column("PID", style="dim")
        proc_table.add_column("Name", style="cyan")
        proc_table.add_column("Memory", justify="right", style="green")
        proc_table.add_column("CPU %", justify="right", style="yellow")
        proc_table.add_column("Threads", justify="right", style="dim")

        for proc in top_procs:
            mem_str = f"{proc.memory_mb:.0f} MB"
            mem_style = (
                "red"
                if proc.memory_mb > 1000
                else "yellow"
                if proc.memory_mb > 500
                else "green"
            )
            proc_table.add_row(
                str(proc.pid),
                proc.name[:40],
                f"[{mem_style}]{mem_str}[/{mem_style}]",
                f"{proc.cpu_percent:.1f}",
                str(proc.num_threads),
            )

        console.print(proc_table)
        console.print()

    # Language servers
    if report.language_servers:
        ls_table = Table(title="Language Servers", show_header=True)
        ls_table.add_column("PID", style="dim")
        ls_table.add_column("Type", style="cyan")
        ls_table.add_column("Memory", justify="right", style="green")
        ls_table.add_column("CPU %", justify="right", style="yellow")

        for ls in report.language_servers:
            # Extract server type from cmdline
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

            mem_style = (
                "red"
                if ls.memory_mb > 1000
                else "yellow"
                if ls.memory_mb > 200
                else "green"
            )
            cpu_style = (
                "red"
                if ls.cpu_percent > 5
                else "yellow"
                if ls.cpu_percent > 2
                else "green"
            )

            ls_table.add_row(
                str(ls.pid),
                server_type,
                f"[{mem_style}]{ls.memory_mb:.0f} MB[/{mem_style}]",
                f"[{cpu_style}]{ls.cpu_percent:.1f}[/{cpu_style}]",
            )

        console.print(ls_table)
        console.print()

    # MCP servers
    if report.mcp_servers_enabled:
        console.print("[bold cyan]Enabled MCP Servers:[/bold cyan]")
        for server in report.mcp_servers_enabled:
            console.print(f"  • {server}")
        console.print()

    # Issues
    if report.log_issues:
        console.print(
            Panel(
                "\n".join(report.log_issues),
                title="[bold red]Issues Detected[/bold red]",
                border_style="red",
            )
        )
        console.print()
    else:
        console.print("[green]✓ No critical issues detected[/green]")
        console.print()

    # Verbose output
    if verbose:
        console.print("[bold cyan]All Processes:[/bold cyan]")
        for proc in sorted(
            report.windsurf_processes, key=lambda p: p.memory_mb, reverse=True
        ):
            runtime_hours = proc.runtime_seconds / 3600
            console.print(f"  PID {proc.pid}: {proc.name}")
            console.print(
                f"    Memory: {proc.memory_mb:.0f} MB | CPU: {proc.cpu_percent:.1f}% | "
                f"Threads: {proc.num_threads} | Runtime: {runtime_hours:.1f}h"
            )
            console.print(f"    [dim]{proc.cmdline[:100]}...[/dim]")
            console.print()


def save_report_json(report: MonitoringReport, output_path: Path) -> None:
    """Save report as JSON for later comparison."""
    with open(output_path, "w") as f:
        json.dump(asdict(report), f, indent=2)
    console.print(f"[green]✓ Report saved to {output_path}[/green]")


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
        f"- **Total Memory:** {report.total_windsurf_memory_mb / 1024:.2f} GB ({(report.total_windsurf_memory_mb / 1024 / report.system.total_memory_gb) * 100:.1f}% of system)",
        f"- **Total CPU:** {report.total_windsurf_cpu_percent:.1f}%",
        f"- **Extensions:** {report.extensions_count}",
        f"- **MCP Servers Enabled:** {len(report.mcp_servers_enabled)}",
        f"- **Language Servers:** {len(report.language_servers)}",
        "",
    ]

    if report.language_servers:
        lines.extend(
            [
                "## Language Servers",
                "",
                "| PID | Type | Memory | CPU % |",
                "|-----|------|--------|-------|",
            ]
        )
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

            lines.append(
                f"| {ls.pid} | {server_type} | {ls.memory_mb:.0f} MB | {ls.cpu_percent:.1f}% |"
            )
        lines.append("")

    if report.mcp_servers_enabled:
        lines.extend(
            [
                "## Enabled MCP Servers",
                "",
            ]
        )
        for server in report.mcp_servers_enabled:
            lines.append(f"- {server}")
        lines.append("")

    if report.log_issues:
        lines.extend(
            [
                "## Issues Detected",
                "",
            ]
        )
        for issue in report.log_issues:
            lines.append(f"- {issue}")
        lines.append("")

    with open(output_path, "w") as f:
        f.write("\n".join(lines))
    console.print(f"[green]✓ Markdown report saved to {output_path}[/green]")


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Monitor Windsurf IDE performance and resource usage"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show detailed process information"
    )
    parser.add_argument(
        "--json",
        type=Path,
        metavar="PATH",
        help="Save report as JSON to specified path",
    )
    parser.add_argument(
        "--markdown",
        type=Path,
        metavar="PATH",
        help="Save report as Markdown to specified path",
    )

    args = parser.parse_args()

    try:
        console.print("[cyan]Gathering system information...[/cyan]")
        report = generate_report()

        display_report(report, verbose=args.verbose)

        if args.json:
            save_report_json(report, args.json)

        if args.markdown:
            save_report_markdown(report, args.markdown)

        # Exit with non-zero if critical issues detected
        if report.log_issues:
            sys.exit(1)

    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
