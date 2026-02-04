"""Core monitoring functionality."""

import json
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

import psutil

from surfmon.config import get_paths


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
class WorkspaceInfo:
    """Information about a Windsurf workspace."""

    id: str
    path: str
    exists: bool
    loaded_at: str | None = None


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
    active_workspaces: list[WorkspaceInfo]
    windsurf_launches_today: int


def get_windsurf_processes() -> list[psutil.Process]:
    """Find all Windsurf-related processes.

    Only matches processes from the configured Windsurf app, excluding:
    - This monitoring tool itself (surfmon)
    - Unrelated processes that happen to contain "windsurf" in their path
    - Orphaned crashpad handlers when the main Windsurf process isn't running
    """
    paths = get_paths()
    app_name = paths.app_name  # e.g., "Windsurf.app" or "Windsurf - Next.app"

    windsurf_procs = []
    main_windsurf_found = False

    # First pass: find all potential Windsurf processes and check for main process
    for proc in psutil.process_iter(["pid", "name", "cmdline", "exe"]):
        try:
            name = proc.info["name"] or ""
            cmdline = " ".join(proc.info["cmdline"] or [])
            exe = proc.info["exe"] or ""

            # Skip the monitoring tool itself
            if "surfmon" in cmdline.lower():
                continue

            # Only match processes from the configured Windsurf app
            if app_name in exe or app_name in cmdline:
                windsurf_procs.append(proc)

                # Check if this is the main Windsurf/Electron process (not a helper/crashpad)
                if (
                    name.lower() in ["windsurf", "electron"]
                    or f"{app_name}/Contents/MacOS/Windsurf" in exe
                    or f"{app_name}/Contents/MacOS/Electron" in exe
                ):
                    # Exclude helpers and crashpad
                    if "Helper" not in name and "crashpad" not in name.lower():
                        main_windsurf_found = True

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    # If no main Windsurf process found, filter out crashpad handlers (they're orphaned)
    if not main_windsurf_found:
        filtered_procs = []
        for p in windsurf_procs:
            try:
                if "crashpad" not in p.name().lower():
                    filtered_procs.append(p)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass  # Process terminated, skip it
        windsurf_procs = filtered_procs

    return windsurf_procs


def get_process_info(
    proc: psutil.Process, initial_cpu: float = 0.0
) -> ProcessInfo | None:
    """Extract detailed information from a process.

    Args:
        proc: Process to extract info from
        initial_cpu: Pre-sampled CPU percentage (if available)
    """
    try:
        with proc.oneshot():
            cmdline = " ".join(proc.cmdline())
            memory_info = proc.memory_info()
            memory_mb = memory_info.rss / 1024 / 1024
            memory_percent = proc.memory_percent()
            num_threads = proc.num_threads()
            create_time = proc.create_time()
            runtime = datetime.now().timestamp() - create_time

            return ProcessInfo(
                pid=proc.pid,
                name=proc.name(),
                cpu_percent=initial_cpu,
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
    """Identify language server processes and extract context.

    Returns language servers with enhanced cmdline showing:
    - Workspace ID (what project it's indexing)
    - Language (e.g., Java, Python, Go)
    - Special flags (indexing, LSP mode, etc.)
    """
    keywords = [
        "language_server",
        "jdtls",
        "gopls",
        "pyright",
        "pylance",
        "basedpyright",
        "yaml-language-server",
        "json-language-server",
        "rust-analyzer",
        "eclipse.jdt",
    ]
    servers = [p for p in processes if any(kw in p.cmdline.lower() for kw in keywords)]

    # Enhance cmdline with extracted context
    import re

    for server in servers:
        cmdline = server.cmdline
        enhanced = False

        # Extract workspace ID for Codeium language server
        workspace_match = re.search(r"--workspace_id\s+(\S+)", cmdline)
        if workspace_match:
            workspace = workspace_match.group(1).replace("file_", "").replace("_", "/")
            # Shorten to last 2-3 path components
            parts = workspace.split("/")
            workspace_short = "/".join(parts[-3:]) if len(parts) > 3 else workspace
            server.cmdline = f"{server.name} [workspace: {workspace_short}]"
            enhanced = True

        # Extract language for JDT LS
        if not enhanced and (
            "jdtls" in cmdline.lower() or "eclipse.jdt" in cmdline.lower()
        ):
            # Try to find project path
            data_match = re.search(r"-data\s+(\S+)", cmdline)
            if data_match:
                project = data_match.group(1).split("/")[-1]
                server.cmdline = f"{server.name} [Java: {project}]"
            else:
                server.cmdline = f"{server.name} [Java Language Server]"
            enhanced = True

        # Other language servers - identify by name
        if not enhanced:
            if "gopls" in cmdline.lower():
                server.cmdline = f"{server.name} [Go Language Server]"
                enhanced = True
            elif "pyright" in cmdline.lower() or "pylance" in cmdline.lower():
                server.cmdline = f"{server.name} [Python Language Server]"
                enhanced = True
            elif "rust-analyzer" in cmdline.lower():
                server.cmdline = f"{server.name} [Rust Language Server]"
                enhanced = True

        # If not enhanced, truncate the original cmdline
        if not enhanced and len(server.cmdline) > 200:
            server.cmdline = server.cmdline[:200] + "..."

    return servers


def get_mcp_config() -> list[str]:
    """Read MCP configuration and return enabled servers."""
    mcp_config_path = get_paths().mcp_config_path
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
    ext_dir = get_paths().extensions_dir
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


def check_orphaned_workspaces() -> list[str]:
    """Check for orphaned workspace indexes consuming memory and disk space.

    Detects language servers indexing non-existent workspaces - a major bug
    that can waste 1+ GB of RAM and hundreds of MB of disk space.
    """
    issues = []
    import re
    import subprocess

    # Find all running language servers
    try:
        result = subprocess.run(
            ["ps", "aux"], capture_output=True, text=True, check=False
        )

        for line in result.stdout.split("\n"):
            if "language_server_macos_arm" not in line:
                continue

            # Extract workspace_id
            workspace_match = re.search(r"--workspace_id\s+(\S+)", line)
            database_match = re.search(r"--database_dir\s+(\S+)", line)

            if workspace_match and database_match:
                workspace_id = workspace_match.group(1)
                database_dir = database_match.group(1)

                # Convert workspace_id to actual path
                workspace_path = workspace_id.replace("file_", "").replace("_", "/")
                workspace_path_obj = Path("/" + workspace_path)

                # Check if workspace exists
                if not workspace_path_obj.exists():
                    # Get database size
                    db_path = Path(database_dir)
                    db_size_mb = 0
                    if db_path.exists():
                        db_size_mb = (
                            sum(
                                f.stat().st_size
                                for f in db_path.rglob("*")
                                if f.is_file()
                            )
                            / 1024
                            / 1024
                        )

                    # Get memory usage from the process
                    pid_match = re.search(r"^\S+\s+(\d+)", line)
                    mem_mb = 0
                    if pid_match:
                        try:
                            proc = psutil.Process(int(pid_match.group(1)))
                            mem_mb = proc.memory_info().rss / 1024 / 1024
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass

                    workspace_short = (
                        "/".join(workspace_path.split("/")[-3:])
                        if "/" in workspace_path
                        else workspace_path
                    )
                    issues.append(
                        f"🔴 CRITICAL: Language server indexing non-existent workspace '{workspace_short}' "
                        f"(consuming {mem_mb:.0f} MB RAM, {db_size_mb:.0f} MB disk) - "
                        f"Fix: Close Windsurf, run: rm -rf {database_dir}"
                    )
    except Exception:
        pass  # Silently fail if we can't detect

    return issues


def check_log_issues() -> list[str]:
    """Check for common issues in Windsurf logs.

    Parses recent Windsurf logs to detect:
    - Orphaned workspace indexes (CRITICAL - can waste 1+ GB RAM)
    - Orphaned crash handlers
    - Extension host crashes
    - Network/telemetry errors
    - OOM (out of memory) errors
    - Renderer crashes
    - Extension errors
    """
    issues = []

    # Check for orphaned workspace indexes (CRITICAL issue)
    issues.extend(check_orphaned_workspaces())

    # Check for orphaned crashpad handlers
    orphaned = []
    main_windsurf_found = False
    app_name = get_paths().app_name

    for proc in psutil.process_iter(["pid", "name", "cmdline", "exe", "create_time"]):
        try:
            name = proc.info["name"] or ""
            exe = proc.info["exe"] or ""
            cmdline = " ".join(proc.info["cmdline"] or [])

            if app_name not in exe and app_name not in cmdline:
                continue

            # Check if this is the main Windsurf/Electron process
            if (
                name.lower() in ["windsurf", "electron"]
                or f"{app_name}/Contents/MacOS/Windsurf" in exe
                or f"{app_name}/Contents/MacOS/Electron" in exe
            ):
                # Exclude helpers and crashpad
                if "Helper" not in name and "crashpad" not in name.lower():
                    main_windsurf_found = True

            # Track crashpad handlers
            if "crashpad" in name.lower():
                create_time = proc.info["create_time"]
                age_days = (datetime.now().timestamp() - create_time) / 86400
                orphaned.append((proc.info["pid"], age_days))

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    # If no main process but crashpad handlers exist, they're orphaned
    if not main_windsurf_found and orphaned:
        pids = [str(pid) for pid, _ in orphaned]
        oldest_days = max(age for _, age in orphaned)

        # Format age in human-readable format
        if oldest_days < 1:
            # Less than a day - show hours/minutes/seconds
            oldest_seconds = oldest_days * 86400
            if oldest_seconds < 60:
                age_str = f"{oldest_seconds:.0f}s"
            elif oldest_seconds < 3600:
                age_str = f"{oldest_seconds / 60:.0f}m"
            else:
                hours = int(oldest_seconds / 3600)
                minutes = int((oldest_seconds % 3600) / 60)
                age_str = f"{hours}h {minutes}m"
        else:
            age_str = f"{oldest_days:.1f} days"

        issues.append(
            f"⚠️  {len(orphaned)} orphaned crash handler(s) (oldest: {age_str}, PIDs: {', '.join(pids[:3])}{', ...' if len(pids) > 3 else ''}) - Fix: surfmon cleanup --force"
        )

    # Check for logs directory in extensions (causing package.json error)
    paths = get_paths()
    logs_dir = paths.extensions_dir / "logs"
    if logs_dir.exists():
        # Try to identify which extension created it
        culprit = "unknown extension"
        try:
            log_files = list(logs_dir.glob("*.log"))
            if log_files:
                # Get the name from the first log file
                culprit = log_files[0].stem  # e.g., "marimo.log" -> "marimo"
        except Exception:
            pass

        issues.append(
            f"⚠️  'logs' directory in extensions folder ({culprit} logging to wrong location) - Fix: rm -rf ~/{paths.dotfile_dir}/extensions/logs"
        )

    # Check latest log directory
    log_base = paths.logs_dir
    if log_base.exists():
        log_dirs = sorted(log_base.iterdir(), reverse=True)
        if log_dirs:
            latest_log = log_dirs[0]

            # Check main.log for extension host crashes and critical errors
            main_log = latest_log / "main.log"
            if main_log.exists():
                try:
                    # Only read last 50KB to avoid performance issues on large logs
                    with open(main_log) as f:
                        f.seek(0, 2)  # Go to end
                        file_size = f.tell()
                        f.seek(max(0, file_size - 50000))  # Read last 50KB
                        content = f.read()

                        # Extension host crashes (non-zero exit codes only)
                        import re

                        crash_lines = re.findall(
                            r"Extension host with pid (\d+) exited with code: (\d+)",
                            content,
                        )
                        crashes = [pid for pid, code in crash_lines if code != "0"]
                        if crashes:
                            issues.append(
                                f"🔴 {len(crashes)} extension host crash(es) - PIDs: {', '.join(crashes[:3])}{', ...' if len(crashes) > 3 else ''}"
                            )

                        # Update service errors
                        if "UpdateService error" in content:
                            issues.append(
                                "⚠️  Update service timeouts detected (check NextDNS)"
                            )

                        # OOM errors
                        if (
                            "out of memory" in content.lower()
                            or "oom" in content.lower()
                        ):
                            issues.append("🔴 Out of memory errors detected")

                        # Renderer crashes
                        renderer_crashes = content.count("GPU process crashed")
                        if renderer_crashes > 0:
                            issues.append(
                                f"⚠️  {renderer_crashes} GPU/renderer crashes detected"
                            )

                except Exception:
                    pass

            # Check shared process log for extension errors
            sharedprocess_log = latest_log / "sharedprocess.log"
            if sharedprocess_log.exists():
                try:
                    with open(sharedprocess_log) as f:
                        f.seek(0, 2)
                        file_size = f.tell()
                        f.seek(max(0, file_size - 30000))
                        content = f.read()

                        # Extract specific extension errors
                        import re

                        error_lines = [
                            line
                            for line in content.split("\n")
                            if "[error]" in line.lower()
                            # Skip known harmless errors
                            and "ENOENT" not in line
                            and "marketplace" not in line
                            and "logs/package.json"
                            not in line  # Already reported separately
                        ]

                        # Try to extract extension IDs from errors
                        extension_errors = {}
                        for line in error_lines:
                            # Look for extension IDs in format: publisher.extension-name
                            ext_match = re.search(
                                r"([a-z0-9-]+\.[a-z0-9-]+)", line.lower()
                            )
                            if ext_match:
                                ext_id = ext_match.group(1)
                                extension_errors[ext_id] = (
                                    extension_errors.get(ext_id, 0) + 1
                                )

                        if extension_errors:
                            # Report top 3 problematic extensions
                            sorted_exts = sorted(
                                extension_errors.items(),
                                key=lambda x: x[1],
                                reverse=True,
                            )
                            ext_summary = ", ".join(
                                [f"{ext} ({count})" for ext, count in sorted_exts[:3]]
                            )
                            issues.append(
                                f"⚠️  Extension errors: {ext_summary}{' ...' if len(sorted_exts) > 3 else ''}"
                            )
                        elif len(error_lines) > 10:
                            # Generic error count if we can't identify extensions
                            issues.append(
                                f"⚠️  {len(error_lines)} extension errors in shared process"
                            )

                except Exception:
                    pass

            # Check network errors
            network_log = latest_log / "network-shared.log"
            if network_log.exists():
                try:
                    with open(network_log) as f:
                        f.seek(0, 2)
                        file_size = f.tell()
                        f.seek(max(0, file_size - 30000))
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


def get_active_workspaces() -> list[WorkspaceInfo]:
    """Detect currently loaded workspaces from logs and storage.

    Returns:
        List of WorkspaceInfo with ID, path, existence status, and load time.
    """
    workspaces = []
    log_base = get_paths().logs_dir

    if not log_base.exists():
        return workspaces

    # Find most recent log directory
    log_dirs = sorted(log_base.iterdir(), reverse=True)
    if not log_dirs:
        return workspaces

    latest_log = log_dirs[0]
    main_log = latest_log / "main.log"

    if not main_log.exists():
        return workspaces

    try:
        import re

        with open(main_log) as f:
            for line in f:
                # Look for workspace load events
                # Format: "WindsurfWindowsMainManager: Window will load {"workspaceUri":{"id":"...","configPath":{..."fsPath":"/path/to/workspace"...}}}"
                if "Window will load" in line and "workspaceUri" in line:
                    # Extract workspace ID and path using regex
                    id_match = re.search(r'"id":"([^"]+)"', line)
                    path_match = re.search(r'"fsPath":"([^"]+)"', line)
                    time_match = re.match(r"^([^ ]+\s+[^ ]+)", line)

                    if id_match and path_match:
                        workspace_id = id_match.group(1)
                        workspace_path = path_match.group(1)
                        loaded_at = time_match.group(1) if time_match else None

                        # Check if path exists
                        path_exists = Path(workspace_path).exists()

                        # Check if already added (avoid duplicates)
                        if not any(w.id == workspace_id for w in workspaces):
                            workspaces.append(
                                WorkspaceInfo(
                                    id=workspace_id,
                                    path=workspace_path,
                                    exists=path_exists,
                                    loaded_at=loaded_at,
                                )
                            )
    except Exception:
        pass

    return workspaces


def count_windsurf_launches_today() -> int:
    """Count how many times Windsurf was launched today.

    Counts unique log directories created today.
    """
    log_base = get_paths().logs_dir

    if not log_base.exists():
        return 0

    today = datetime.now().date()
    launches = 0

    try:
        for log_dir in log_base.iterdir():
            if not log_dir.is_dir():
                continue

            # Log directories are named with timestamp: 20260204T151929
            try:
                # Parse directory name to get date
                dir_name = log_dir.name
                if "T" in dir_name:
                    date_str = dir_name.split("T")[0]  # Get YYYYMMDD part
                    dir_date = datetime.strptime(date_str, "%Y%m%d").date()

                    if dir_date == today:
                        launches += 1
            except (ValueError, IndexError):
                continue
    except Exception:
        pass

    return launches


def generate_report() -> MonitoringReport:
    """Generate complete monitoring report with optimized CPU sampling."""
    import time

    # Get processes
    procs = get_windsurf_processes()

    # Initialize CPU sampling (non-blocking)
    cpu_samples = {}
    for proc in procs:
        try:
            proc.cpu_percent()  # First call initializes, returns 0.0
            cpu_samples[proc.pid] = proc
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    # Sleep once for all processes (instead of once per process)
    if cpu_samples:
        time.sleep(0.5)  # 500ms is enough for reasonable CPU measurement

    # Get final CPU samples
    cpu_values = {}
    for pid, proc in cpu_samples.items():
        try:
            cpu_values[pid] = proc.cpu_percent()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            cpu_values[pid] = 0.0

    # Build process info with pre-sampled CPU
    proc_infos = []
    for p in procs:
        cpu = cpu_values.get(p.pid, 0.0)
        if pi := get_process_info(p, initial_cpu=cpu):
            proc_infos.append(pi)

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
        active_workspaces=get_active_workspaces(),
        windsurf_launches_today=count_windsurf_launches_today(),
    )


def save_report_json(report: MonitoringReport, output_path: Path) -> None:
    """Save report as JSON."""
    with open(output_path, "w") as f:
        json.dump(asdict(report), f, indent=2)
