"""Core monitoring functionality."""

import contextlib
import json
import operator
import os
import re
import subprocess  # noqa: S404
import time
from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path

import psutil

from surfmon.config import get_paths

# Monitoring thresholds
CMDLINE_TRUNCATE_LEN = 200
PATH_COMPONENTS_SHORT = 3
MAX_DISPLAY_ITEMS = 3
TELEMETRY_ERROR_THRESHOLD = 5
EXTENSION_ERROR_LINES_THRESHOLD = 10
SECONDS_PER_MINUTE = 60
SECONDS_PER_HOUR = 3600
SECONDS_PER_DAY = 86400
LSOF_MIN_FIELDS = 8
PTY_CRITICAL_COUNT = 200
PTY_WARNING_COUNT = 50
PTY_USAGE_CRITICAL_PERCENT = 80
LOG_TAIL_BYTES = 50000
SHARED_LOG_TAIL_BYTES = 30000

# Issue severity markers used in log_issues strings
ISSUE_CRITICAL_PREFIX = "✖"
ISSUE_WARNING_PREFIX = "⚠"

# Exit codes for the check command
EXIT_OK = 0
EXIT_WARNING = 1
EXIT_CRITICAL = 2


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
class PtyFdEntry:
    """Single lsof line parsed for a PTY file descriptor."""

    command: str
    pid: int
    fd: str  # e.g., "33u"
    device: str  # e.g., "15,0" (major,minor)
    size_off: str  # e.g., "0t0" or "0t2077"


@dataclass
class PtyProcessDetail:
    """Per-PID PTY ownership detail."""

    pid: int
    name: str
    pty_count: int
    fds: list[str]  # e.g., ["33u", "34u", "37u"]


@dataclass
class PtyInfo:
    """PTY usage information for Windsurf."""

    windsurf_pty_count: int
    system_pty_limit: int
    system_pty_used: int
    # Forensic detail (added for PTY leak diagnosis)
    per_process: list[PtyProcessDetail] | None = None
    fd_entries: list[PtyFdEntry] | None = None
    non_windsurf_holders: list[PtyProcessDetail] | None = None
    windsurf_version: str = ""
    windsurf_uptime_seconds: float = 0.0
    raw_lsof: str = ""
    issues: list[str] = field(default_factory=list)


@dataclass
class LsSnapshotEntry:
    """Forensic detail for a single language server process."""

    pid: int
    name: str
    language: str
    memory_mb: float
    memory_percent: float
    cpu_percent: float
    num_threads: int
    runtime_seconds: float
    workspace: str
    orphaned: bool
    stale: bool = False


@dataclass
class LsSnapshot:
    """Language server forensic snapshot."""

    timestamp: str
    windsurf_version: str
    windsurf_uptime_seconds: float
    total_ls_count: int
    total_ls_memory_mb: float
    orphaned_count: int
    stale_count: int
    entries: list[LsSnapshotEntry]
    orphan_issues: list[str]
    stale_issues: list[str]
    issues: list[str] = field(init=False)

    def __post_init__(self) -> None:
        self.issues = self.orphan_issues + self.stale_issues


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
    windsurf_version: str = ""
    windsurf_uptime_seconds: float = 0.0
    pty_info: PtyInfo | None = None
    ls_snapshot: LsSnapshot | None = None


def is_main_windsurf_process(name: str, exe: str, app_name: str) -> bool:
    """Check if a process is the main Windsurf/Electron process (not a helper/crashpad).

    This is the single source of truth for main-process detection, used by:
    - get_windsurf_processes() to filter orphaned crashpad handlers
    - _check_orphaned_crashpad_handlers() for issue reporting
    - cli.py _find_orphaned_crashpad_procs() for the cleanup command
    """
    return (
        (
            name.lower() in {"windsurf", "electron"}
            or f"{app_name}/Contents/MacOS/Windsurf" in exe
            or f"{app_name}/Contents/MacOS/Electron" in exe
        )
        and "Helper" not in name
        and "crashpad" not in name.lower()
    )


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
            if proc.pid == os.getpid():
                continue

            # Only match processes from the configured Windsurf app
            if app_name in exe or app_name in cmdline:
                windsurf_procs.append(proc)

                if is_main_windsurf_process(name, exe, app_name):
                    main_windsurf_found = True

        except psutil.NoSuchProcess, psutil.AccessDenied:
            pass

    # If no main Windsurf process found, filter out crashpad handlers (they're orphaned)
    if not main_windsurf_found:
        filtered_procs = []
        for p in windsurf_procs:
            try:
                if "crashpad" not in p.name().lower():
                    filtered_procs.append(p)
            except psutil.NoSuchProcess, psutil.AccessDenied:
                pass  # Process terminated, skip it
        windsurf_procs = filtered_procs

    return windsurf_procs


def get_process_info(proc: psutil.Process, initial_cpu: float = 0.0) -> ProcessInfo | None:
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
            runtime = datetime.now(tz=UTC).timestamp() - create_time

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
    except psutil.NoSuchProcess, psutil.AccessDenied:
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


def _enhance_language_server_cmdline(p: ProcessInfo) -> str | None:
    """Build an enhanced cmdline description for a language server process."""
    cmdline = p.cmdline
    cmdline_lower = cmdline.lower()
    enhanced = None

    # Extract workspace ID for Codeium language server
    workspace_id = _extract_workspace_id(cmdline)
    if workspace_id:
        workspace_short = _format_workspace_short(workspace_id)
        enhanced = f"{p.name} [workspace: {workspace_short}]"

    # Extract language for JDT LS
    elif "jdtls" in cmdline_lower or "eclipse.jdt" in cmdline_lower:
        data_match = re.search(r"-data\s+(\S+)", cmdline)
        project = data_match.group(1).split("/")[-1] if data_match else None
        enhanced = f"{p.name} [Java: {project}]" if project else f"{p.name} [Java Language Server]"

    # Other language servers - identify by keyword
    elif "gopls" in cmdline_lower:
        enhanced = f"{p.name} [Go Language Server]"
    elif "pyright" in cmdline_lower or "pylance" in cmdline_lower:
        enhanced = f"{p.name} [Python Language Server]"
    elif "rust-analyzer" in cmdline_lower:
        enhanced = f"{p.name} [Rust Language Server]"

    # Truncate long cmdlines if no enhancement found
    elif len(cmdline) > CMDLINE_TRUNCATE_LEN:
        enhanced = cmdline[:CMDLINE_TRUNCATE_LEN] + "..."

    return enhanced


def find_language_servers(processes: list[ProcessInfo]) -> list[ProcessInfo]:
    """Identify language server processes from the process list."""
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

    result = []
    for p in processes:
        if not any(kw in p.cmdline.lower() for kw in keywords):
            continue

        enhanced = _enhance_language_server_cmdline(p)
        if enhanced is not None:
            result.append(replace(p, cmdline=enhanced))
        else:
            result.append(p)

    return result


_LS_LANGUAGE_KEYWORDS: list[tuple[list[str], str]] = [
    (["jdtls", "eclipse.jdt"], "Java"),
    (["gopls"], "Go"),
    (["pyright", "pylance", "basedpyright"], "Python"),
    (["rust-analyzer"], "Rust"),
    (["yaml-language-server"], "YAML"),
    (["json-language-server"], "JSON"),
    (["language_server_macos_arm", "language_server"], "Codeium"),
]


def _detect_language(cmdline: str) -> str:
    """Detect the programming language a language server handles from its cmdline."""
    lower = cmdline.lower()
    for keywords, language in _LS_LANGUAGE_KEYWORDS:
        if any(kw in lower for kw in keywords):
            return language
    return "Unknown"


def _resolve_workspace_path(workspace_id: str) -> Path | None:
    """Resolve a Codeium workspace_id to an existing filesystem path.

    Codeium encodes ``/``, ``-``, and ``.`` as ``_`` in its ``--workspace_id``
    argument.  A naïve ``replace("_", "/")`` produces false paths for any
    directory whose name contains hyphens or dots (e.g. ``copier-uv-bleeding``
    becomes ``copier/uv/bleeding``).

    This function walks the filesystem, trying ``/``, ``-``, and ``.`` for each
    encoded underscore until it finds a path that actually exists.  Returns
    ``None`` when no valid decoding is found (truly orphaned workspace).
    """
    raw = workspace_id.removeprefix("file_")
    segments = raw.split("_")

    # Fast path: simple all-slashes decode
    simple = Path("/" + "/".join(segments))
    if simple.exists():
        return simple

    return _try_joiners(Path("/"), segments)


def _try_joiners(base: Path, segments: list[str]) -> Path | None:
    """Try ``/``, ``-``, and ``.`` for each underscore between *segments*."""
    if len(segments) == 1:
        candidate = base / segments[0]
        return candidate if candidate.exists() else None

    first, rest = segments[0], segments[1:]

    # Option 1: underscore was / (new path component)
    child = base / first
    if child.is_dir():
        result = _try_joiners(child, rest)
        if result is not None:
            return result

    # Option 2/3: underscore was - or . (merge with next segment)
    for joiner in ("-", "."):
        merged = [first + joiner + rest[0], *rest[1:]]
        result = _try_joiners(base, merged)
        if result is not None:
            return result

    return None


def _extract_workspace_id(cmdline: str) -> str | None:
    """Extract raw Codeium workspace_id from a process command line."""
    match = re.search(r"--workspace_id\s+(\S+)", cmdline)
    return match.group(1) if match else None


def _format_workspace_short(workspace_id: str) -> str:
    """Resolve a workspace_id and format it as a short display path."""
    resolved = _resolve_workspace_path(workspace_id)
    return _format_workspace_display(workspace_id, resolved)


def _format_workspace_display(workspace_id: str, resolved: Path | None) -> str:
    """Format a workspace_id as a short display path using a pre-resolved path."""
    if resolved is not None:
        parts = resolved.parts
        return "/".join(parts[-PATH_COMPONENTS_SHORT:]) if len(parts) > PATH_COMPONENTS_SHORT else str(resolved)
    # Fallback: naïve decode for display
    workspace = workspace_id.removeprefix("file_").replace("_", "/")
    parts = workspace.split("/")
    return "/".join(parts[-PATH_COMPONENTS_SHORT:]) if len(parts) > PATH_COMPONENTS_SHORT else workspace


def _extract_workspace_from_cmdline(cmdline: str) -> str:
    """Extract workspace path from a language server command line."""
    workspace_id = _extract_workspace_id(cmdline)
    if workspace_id:
        return _format_workspace_short(workspace_id)

    data_match = re.search(r"-data\s+(\S+)", cmdline)
    if data_match:
        return data_match.group(1).split("/")[-1]

    return ""


def _is_orphaned_workspace(cmdline: str) -> bool:
    """Check if a language server is indexing a non-existent workspace."""
    workspace_id = _extract_workspace_id(cmdline)
    if not workspace_id:
        return False
    return _resolve_workspace_path(workspace_id) is None


def _is_stale_workspace(cmdline: str, active_ws_paths: set[str]) -> bool:
    """Check if a language server is for a workspace not currently open in the IDE.

    Returns True when the workspace exists on disk (not orphaned) but does
    not appear in the set of active Windsurf workspace paths.
    Returns False when active_ws_paths is empty (cannot determine staleness).
    """
    if not active_ws_paths:
        return False
    workspace_id = _extract_workspace_id(cmdline)
    if not workspace_id:
        return False
    resolved = _resolve_workspace_path(workspace_id)
    if resolved is None:
        return False
    return str(resolved) not in active_ws_paths


def _format_orphan_issue(ls: ProcessInfo, workspace: str, cmdline: str) -> str:
    """Build a detailed orphan-workspace issue string.

    Includes database directory size and cleanup command when the
    ``--database_dir`` flag is present in the process command line.
    """
    msg = (
        f"{ISSUE_CRITICAL_PREFIX}  CRITICAL: {ls.name} (PID {ls.pid}) indexing non-existent workspace "
        f"'{workspace}' — consuming {ls.memory_mb:.0f} MB RAM"
    )
    db_match = re.search(r"--database_dir\s+(\S+)", cmdline)
    if db_match:
        db_path = Path(db_match.group(1))
        db_size_mb = 0
        if db_path.exists():
            db_size_mb = sum(f.stat().st_size for f in db_path.rglob("*") if f.is_file()) / 1024 / 1024
        msg += f", {db_size_mb:.0f} MB disk) - Fix: Close Windsurf, run: rm -rf {db_path}"
    return msg


def capture_ls_snapshot(
    proc_infos: list[ProcessInfo],
    windsurf_version: str,
    windsurf_uptime: float,
    active_workspaces: list[WorkspaceInfo] | None = None,
) -> LsSnapshot:
    """Capture a forensic snapshot of all language server processes.

    Returns structured data about every language server: memory, CPU,
    workspace mapping, orphaned status (indexing deleted workspace), and
    stale status (workspace exists but not open in the IDE).
    """
    lang_servers = find_language_servers(proc_infos)
    active_ws_paths = {ws.path for ws in active_workspaces} if active_workspaces else set()

    entries = []
    orphan_issues: list[str] = []
    stale_issues: list[str] = []
    total_memory = 0.0

    for ls in lang_servers:
        # Use original cmdline for detection (before enhancement)
        original_proc = next((p for p in proc_infos if p.pid == ls.pid), ls)
        language = _detect_language(original_proc.cmdline)

        # Resolve workspace path once — avoids redundant filesystem walks
        # for display formatting, orphan detection, and stale detection.
        workspace_id = _extract_workspace_id(original_proc.cmdline)
        resolved_path = _resolve_workspace_path(workspace_id) if workspace_id else None

        if workspace_id:
            workspace = _format_workspace_display(workspace_id, resolved_path)
        else:
            workspace = _extract_workspace_from_cmdline(original_proc.cmdline)

        orphaned = workspace_id is not None and resolved_path is None
        stale = not orphaned and bool(active_ws_paths) and resolved_path is not None and str(resolved_path) not in active_ws_paths

        entry = LsSnapshotEntry(
            pid=ls.pid,
            name=ls.name,
            language=language,
            memory_mb=ls.memory_mb,
            memory_percent=ls.memory_percent,
            cpu_percent=ls.cpu_percent,
            num_threads=ls.num_threads,
            runtime_seconds=ls.runtime_seconds,
            workspace=workspace,
            orphaned=orphaned,
            stale=stale,
        )
        entries.append(entry)
        total_memory += ls.memory_mb

        if orphaned:
            orphan_issues.append(
                _format_orphan_issue(ls, workspace, original_proc.cmdline)
            )
        elif stale:
            stale_issues.append(
                f"{ISSUE_WARNING_PREFIX}  {ls.name} (PID {ls.pid}) still running for closed workspace "
                f"'{workspace}' — consuming {ls.memory_mb:.0f} MB RAM"
            )

    # Sort by memory descending for easy triage
    entries.sort(key=lambda e: e.memory_mb, reverse=True)

    return LsSnapshot(
        timestamp=datetime.now(tz=UTC).isoformat(),
        windsurf_version=windsurf_version,
        windsurf_uptime_seconds=windsurf_uptime,
        total_ls_count=len(entries),
        total_ls_memory_mb=total_memory,
        orphaned_count=len(orphan_issues),
        stale_count=len(stale_issues),
        entries=entries,
        orphan_issues=orphan_issues,
        stale_issues=stale_issues,
    )


def get_mcp_config() -> list[str]:
    """Read MCP configuration and return enabled servers."""
    mcp_config_path = get_paths().mcp_config_path
    if not mcp_config_path.exists():
        return []

    try:
        with mcp_config_path.open(encoding="utf-8") as f:
            config = json.load(f)
            servers = config.get("mcpServers", {})
            return [name for name, cfg in servers.items() if not cfg.get("disabled", False)]
    except json.JSONDecodeError, KeyError:
        return []


def count_extensions() -> int:
    """Count installed Windsurf extensions."""
    ext_dir = get_paths().extensions_dir
    if not ext_dir.exists():
        return 0

    # Count directories that look like extensions (have version numbers)
    count = 0
    for item in ext_dir.iterdir():
        # Simple heuristic: directory with version-like pattern (has digits)
        if item.is_dir() and item.name != "logs" and any(char.isdigit() for char in item.name):
            count += 1
    return count


def _check_orphaned_workspace_proc(cmdline: str, proc: psutil.Process) -> str | None:
    """Check a single language server process for orphaned workspace indexing.

    Returns an issue string if the process is indexing a non-existent workspace, else None.
    """
    if "language_server_macos_arm" not in cmdline:
        return None

    workspace_id = _extract_workspace_id(cmdline)
    database_match = re.search(r"--database_dir\s+(\S+)", cmdline)

    if not (workspace_id and database_match):
        return None

    if not _is_orphaned_workspace(cmdline):
        return None

    database_dir = database_match.group(1)

    # Get database size
    db_path = Path(database_dir)
    db_size_mb = 0
    if db_path.exists():
        db_size_mb = sum(f.stat().st_size for f in db_path.rglob("*") if f.is_file()) / 1024 / 1024

    # Get memory usage from the process
    mem_mb = 0
    with contextlib.suppress(psutil.NoSuchProcess, psutil.AccessDenied):
        mem_mb = proc.memory_info().rss / 1024 / 1024

    # Naïve decode for display — workspace doesn't exist so _resolve_workspace_path
    # would redundantly walk the filesystem and return None again.
    workspace = workspace_id.removeprefix("file_").replace("_", "/")
    parts = workspace.split("/")
    workspace_short = "/".join(parts[-PATH_COMPONENTS_SHORT:]) if len(parts) > PATH_COMPONENTS_SHORT else workspace
    return (
        f"{ISSUE_CRITICAL_PREFIX}  CRITICAL: Language server indexing non-existent workspace '{workspace_short}' "
        f"(consuming {mem_mb:.0f} MB RAM, {db_size_mb:.0f} MB disk) - "
        f"Fix: Close Windsurf, run: rm -rf {database_dir}"
    )


def check_orphaned_workspaces() -> list[str]:
    """Check for orphaned workspace indexes consuming memory and disk space.

    Detects language servers indexing non-existent workspaces - a major bug
    that can waste 1+ GB of RAM and hundreds of MB of disk space.
    """
    issues = []

    try:
        for proc in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                cmdline = " ".join(proc.info["cmdline"] or [])
                issue = _check_orphaned_workspace_proc(cmdline, proc)
                if issue:
                    issues.append(issue)
            except psutil.NoSuchProcess, psutil.AccessDenied:
                continue
    except psutil.Error, OSError, re.error:
        pass  # Silently fail if we can't detect processes or parse cmdline

    return issues


def _get_system_pty_limit() -> int:
    """Get system PTY limit from sysctl. Returns 511 (macOS default) on failure."""
    try:
        result = subprocess.run(
            ["sysctl", "-n", "kern.tty.ptmx_max"],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if result.returncode == 0:
            return int(result.stdout.strip())
    except subprocess.TimeoutExpired, ValueError, OSError:
        pass
    return 511


def _parse_lsof_line(line: str) -> PtyFdEntry | None:
    """Parse a single lsof output line into a PtyFdEntry.

    lsof format: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
    """
    parts = line.split()
    if len(parts) < LSOF_MIN_FIELDS:
        return None
    try:
        pid = int(parts[1])
    except ValueError:
        return None
    return PtyFdEntry(
        command=parts[0],
        pid=pid,
        fd=parts[3],
        device=parts[5],
        size_off=parts[6],
    )


def _group_entries_by_pid(
    entries: list[PtyFdEntry],
) -> list[PtyProcessDetail]:
    """Group PtyFdEntry list into per-PID summaries."""
    pid_map: dict[int, list[PtyFdEntry]] = {}
    for entry in entries:
        pid_map.setdefault(entry.pid, []).append(entry)
    return [
        PtyProcessDetail(
            pid=pid,
            name=fds[0].command,
            pty_count=len(fds),
            fds=[e.fd for e in fds],
        )
        for pid, fds in sorted(pid_map.items(), key=lambda kv: len(kv[1]), reverse=True)
    ]


def _extract_windsurf_version(processes: list[ProcessInfo]) -> str:
    """Extract Windsurf version from the main Electron process cmdline."""
    for proc in processes:
        match = re.search(r"--windsurf_version\s+(\S+)", proc.cmdline)
        if match:
            return match.group(1)
    return ""


def _get_windsurf_uptime(processes: list[ProcessInfo]) -> float:
    """Get uptime of the longest-running Windsurf process in seconds."""
    if not processes:
        return 0.0
    return max(p.runtime_seconds for p in processes)


def _classify_pty_issues(
    windsurf_pty_count: int,
    system_pty_used: int,
    system_pty_limit: int,
) -> list[str]:
    """Generate issue strings for PTY leak severity.

    Returns a list of 0 or 1 issue strings, classified as critical or warning
    using the standard ``ISSUE_CRITICAL_PREFIX`` / ``ISSUE_WARNING_PREFIX`` markers.
    """
    if windsurf_pty_count <= 0:
        return []

    usage_pct = (system_pty_used / system_pty_limit) * 100 if system_pty_limit > 0 else 0

    if windsurf_pty_count >= PTY_CRITICAL_COUNT or usage_pct >= PTY_USAGE_CRITICAL_PERCENT:
        return [
            (
                f"{ISSUE_CRITICAL_PREFIX}  CRITICAL: Windsurf processes are holding {windsurf_pty_count} PTYs "
                f"(system: {system_pty_used}/{system_pty_limit}, {usage_pct:.0f}% used) "
                f"- Fix: Restart all Windsurf instances to release leaked PTYs"
            )
        ]

    if windsurf_pty_count >= PTY_WARNING_COUNT:
        return [
            (
                f"{ISSUE_WARNING_PREFIX}  Windsurf PTY leak detected: {windsurf_pty_count} PTYs held "
                f"(system: {system_pty_used}/{system_pty_limit}) "
                f"- Monitor closely, restart all Windsurf instances if it keeps growing"
            )
        ]

    return []


def check_pty_leak(windsurf_processes: list[ProcessInfo] | None = None) -> PtyInfo:
    """Check for PTY (pseudo-terminal) leak by Windsurf.

    Windsurf (and other Electron-based IDEs) can leak PTYs by not closing
    them when terminal sessions end. This can exhaust the system PTY limit
    (macOS default: 511), preventing new terminals from being opened anywhere.

    Args:
        windsurf_processes: Pre-collected Windsurf ProcessInfo list for version/uptime
            extraction. Pass None to skip version/uptime (backwards-compatible).

    Returns:
        PtyInfo with Windsurf PTY count, system limit, total system usage,
        and forensic detail (per-process breakdown, FD entries, raw lsof).
    """
    system_pty_limit = _get_system_pty_limit()
    windsurf_pty_count = 0
    system_pty_used = 0
    windsurf_entries: list[PtyFdEntry] = []
    non_windsurf_entries: list[PtyFdEntry] = []
    raw_lsof = ""

    # Count PTYs using lsof
    app_name = get_paths().app_name
    try:
        result = subprocess.run(
            ["lsof", "/dev/ptmx"],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode == 0:
            raw_lsof = result.stdout
            lines = result.stdout.strip().split("\n")
            data_lines = lines[1:] if len(lines) > 1 else []
            system_pty_used = len(data_lines)

            # The app_name contains ".app" but lsof COMMAND column shows just the binary name
            windsurf_cmd_prefix = app_name.split(".")[0].strip().split()[0]

            for line in data_lines:
                entry = _parse_lsof_line(line)
                if entry is None:
                    continue
                if windsurf_cmd_prefix in entry.command:
                    windsurf_entries.append(entry)
                    windsurf_pty_count += 1
                else:
                    non_windsurf_entries.append(entry)
    except subprocess.TimeoutExpired, OSError:
        pass

    # Extract version and uptime from process list if available
    version = ""
    uptime = 0.0
    if windsurf_processes:
        version = _extract_windsurf_version(windsurf_processes)
        uptime = _get_windsurf_uptime(windsurf_processes)

    issues = _classify_pty_issues(windsurf_pty_count, system_pty_used, system_pty_limit)

    return PtyInfo(
        windsurf_pty_count=windsurf_pty_count,
        system_pty_limit=system_pty_limit,
        system_pty_used=system_pty_used,
        per_process=_group_entries_by_pid(windsurf_entries),
        fd_entries=windsurf_entries,
        non_windsurf_holders=_group_entries_by_pid(non_windsurf_entries),
        windsurf_version=version,
        windsurf_uptime_seconds=uptime,
        raw_lsof=raw_lsof,
        issues=issues,
    )


def format_uptime(seconds: float) -> str:
    """Format uptime seconds as a human-readable string.

    Shared by CLI display, PTY snapshot, LS snapshot, and Markdown reports.
    """
    if seconds <= 0:
        return "unknown"
    total = int(seconds)
    h, remainder = divmod(total, 3600)
    m, s = divmod(remainder, 60)
    if h > 0:
        return f"{h}h {m}m {s}s"
    if m > 0:
        return f"{m}m {s}s"
    return f"{s}s"


def _format_age_str(days: float) -> str:
    """Format age in days to human-readable string."""
    if days >= 1:
        return f"{days:.1f} days"
    oldest_seconds = days * SECONDS_PER_DAY
    if oldest_seconds < SECONDS_PER_MINUTE:
        return f"{oldest_seconds:.0f}s"
    if oldest_seconds < SECONDS_PER_HOUR:
        return f"{oldest_seconds / SECONDS_PER_MINUTE:.0f}m"
    hours = int(oldest_seconds / SECONDS_PER_HOUR)
    minutes = int((oldest_seconds % SECONDS_PER_HOUR) / SECONDS_PER_MINUTE)
    return f"{hours}h {minutes}m"


def _read_log_tail(log_path: Path, tail_bytes: int) -> str | None:
    """Read the last tail_bytes of a log file, or None on failure."""
    if not log_path.exists():
        return None
    try:
        with log_path.open(encoding="utf-8") as f:
            f.seek(0, 2)
            file_size = f.tell()
            f.seek(max(0, file_size - tail_bytes))
            return f.read()
    except OSError, UnicodeDecodeError:
        return None


def _check_orphaned_crashpad_handlers() -> list[str]:
    """Check for orphaned crashpad handler processes."""
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

            if is_main_windsurf_process(name, exe, app_name):
                main_windsurf_found = True

            if "crashpad" in name.lower():
                create_time = proc.info["create_time"]
                age_days = (datetime.now(tz=UTC).timestamp() - create_time) / 86400
                orphaned.append((proc.info["pid"], age_days))

        except psutil.NoSuchProcess, psutil.AccessDenied:
            pass

    if main_windsurf_found or not orphaned:
        return []

    pids = [str(pid) for pid, _ in orphaned]
    oldest_days = max(age for _, age in orphaned)
    age_str = _format_age_str(oldest_days)
    pids_str = ", ".join(pids[:MAX_DISPLAY_ITEMS]) + (", ..." if len(pids) > MAX_DISPLAY_ITEMS else "")
    return [
        (
            f"{ISSUE_WARNING_PREFIX}  {len(orphaned)} orphaned crash handler(s) "
            f"(oldest: {age_str}, PIDs: {pids_str}) - Fix: surfmon cleanup --force"
        )
    ]


def _check_extension_logs_dir() -> list[str]:
    """Check for logs directory in extensions folder (package.json error)."""
    paths = get_paths()
    logs_dir = paths.extensions_dir / "logs"
    if not logs_dir.exists():
        return []

    culprit = "unknown extension"
    try:
        log_files = list(logs_dir.glob("*.log"))
        if log_files:
            culprit = log_files[0].stem
    except OSError:
        pass

    return [
        (
            f"{ISSUE_WARNING_PREFIX}  'logs' directory in extensions folder ({culprit} logging to wrong location) - "
            f"Fix: rm -rf ~/{paths.dotfile_dir}/extensions/logs"
        )
    ]


def _check_main_log_issues(latest_log: Path) -> list[str]:
    """Check main.log for extension host crashes, OOM, and renderer crashes."""
    content = _read_log_tail(latest_log / "main.log", LOG_TAIL_BYTES)
    if content is None:
        return []

    issues = []

    # Extension host crashes (non-zero exit codes only)
    crash_lines = re.findall(
        r"Extension host with pid (\d+) exited with code: (\d+)",
        content,
    )
    crashes = [pid for pid, code in crash_lines if code != "0"]
    if crashes:
        pids_str = ", ".join(crashes[:MAX_DISPLAY_ITEMS]) + (", ..." if len(crashes) > MAX_DISPLAY_ITEMS else "")
        issues.append(f"{ISSUE_CRITICAL_PREFIX}  {len(crashes)} extension host crash(es) - PIDs: {pids_str}")

    update_errors = content.count("UpdateService error")
    if update_errors:
        issues.append(f"{ISSUE_WARNING_PREFIX}  {update_errors} update check request(s) timed out (check DNS/firewall settings)")

    if "out of memory" in content.lower() or "oom" in content.lower():
        issues.append(f"{ISSUE_CRITICAL_PREFIX}  Out of memory errors detected")

    renderer_crashes = content.count("GPU process crashed")
    if renderer_crashes > 0:
        issues.append(f"{ISSUE_WARNING_PREFIX}  {renderer_crashes} GPU/renderer crash(es) detected")

    return issues


def _check_shared_process_log_issues(latest_log: Path) -> list[str]:
    """Check sharedprocess.log for extension errors."""
    content = _read_log_tail(latest_log / "sharedprocess.log", SHARED_LOG_TAIL_BYTES)
    if content is None:
        return []

    error_lines = [
        line
        for line in content.split("\n")
        if "[error]" in line.lower() and "ENOENT" not in line and "marketplace" not in line and "logs/package.json" not in line
    ]

    # Try to extract extension IDs from errors
    extension_errors: dict[str, int] = {}
    for line in error_lines:
        ext_match = re.search(r"([a-z0-9-]+\.[a-z0-9-]+)", line.lower())
        if ext_match:
            ext_id = ext_match.group(1)
            extension_errors[ext_id] = extension_errors.get(ext_id, 0) + 1

    if extension_errors:
        sorted_exts = sorted(extension_errors.items(), key=operator.itemgetter(1), reverse=True)
        ext_summary = ", ".join([f"{ext} ({count})" for ext, count in sorted_exts[:MAX_DISPLAY_ITEMS]])
        return [f"{ISSUE_WARNING_PREFIX}  Extension errors: {ext_summary}{' ...' if len(sorted_exts) > MAX_DISPLAY_ITEMS else ''}"]

    if len(error_lines) > EXTENSION_ERROR_LINES_THRESHOLD:
        return [f"{ISSUE_WARNING_PREFIX}  {len(error_lines)} extension errors in shared process"]

    return []


def _check_network_log_issues(latest_log: Path) -> list[str]:
    """Check network-shared.log for telemetry connection failures."""
    content = _read_log_tail(latest_log / "network-shared.log", SHARED_LOG_TAIL_BYTES)
    if content is None:
        return []

    telemetry_errors = content.count("windsurf-telemetry.codeium.com")
    if telemetry_errors > TELEMETRY_ERROR_THRESHOLD:
        return [
            (
                f"{ISSUE_WARNING_PREFIX}  {telemetry_errors} telemetry connection failure(s) "
                f"to windsurf-telemetry.codeium.com (check DNS/firewall settings)"
            )
        ]
    return []


def check_log_issues(*, include_orphans: bool = True) -> list[str]:
    """Check for common issues in Windsurf logs.

    Parses recent Windsurf logs to detect:
    - Orphaned workspace indexes (CRITICAL - can waste 1+ GB RAM)
    - Orphaned crash handlers
    - Extension host crashes
    - Network/telemetry errors
    - OOM (out of memory) errors
    - Renderer crashes
    - Extension errors

    Args:
        include_orphans: When False, skip the orphaned-workspace process scan.
            Set to False when the caller performs its own orphan detection
            (e.g. via ``capture_ls_snapshot``) to avoid a redundant
            ``psutil.process_iter`` walk.
    """
    issues = []

    if include_orphans:
        issues.extend(check_orphaned_workspaces())
    issues.extend(_check_orphaned_crashpad_handlers())
    issues.extend(_check_extension_logs_dir())

    # Check latest log directory
    log_base = get_paths().logs_dir
    if log_base.exists():
        log_dirs = sorted(log_base.iterdir(), reverse=True)
        if log_dirs:
            latest_log = log_dirs[0]
            issues.extend(_check_main_log_issues(latest_log))
            issues.extend(_check_shared_process_log_issues(latest_log))
            issues.extend(_check_network_log_issues(latest_log))

    return issues


def _parse_workspace_event(line: str) -> tuple[str, WorkspaceInfo] | None:
    """Parse a workspace load or close event from a log line.

    Returns a (event_type, WorkspaceInfo) tuple where event_type is
    ``"load"`` or ``"close"``, or ``None`` if the line is not a
    workspace event.
    """
    if "workspaceUri" not in line:
        return None

    if "Window will load" in line:
        event_type = "load"
    elif "Window will close" in line:
        event_type = "close"
    else:
        return None

    id_match = re.search(r'"id":"([^"]+)"', line)
    path_match = re.search(r'"fsPath":"([^"]+)"', line)
    if not (id_match and path_match):
        return None

    time_match = re.match(r"^([^ ]+\s+[^ ]+)", line)
    ws = WorkspaceInfo(
        id=id_match.group(1),
        path=path_match.group(1),
        exists=Path(path_match.group(1)).exists(),
        loaded_at=time_match.group(1) if time_match else None,
    )
    return (event_type, ws)


def get_active_workspaces() -> list[WorkspaceInfo]:
    """Detect currently loaded workspaces from logs and storage.

    Parses both ``Window will load`` and ``Window will close`` events
    from the latest log session to build an accurate active set.

    Returns:
        List of WorkspaceInfo with ID, path, existence status, and load time.
    """
    active: dict[str, WorkspaceInfo] = {}
    log_base = get_paths().logs_dir

    if not log_base.exists():
        return []

    log_dirs = sorted(log_base.iterdir(), reverse=True)
    if not log_dirs:
        return []

    main_log = log_dirs[0] / "main.log"
    if not main_log.exists():
        return []

    try:
        with main_log.open(encoding="utf-8") as f:
            for line in f:
                event = _parse_workspace_event(line)
                if event is None:
                    continue
                event_type, ws = event
                if event_type == "load":
                    active[ws.id] = ws
                else:
                    active.pop(ws.id, None)
    except OSError, UnicodeDecodeError:
        pass  # Can't read or parse main.log for workspaces

    return list(active.values())


def count_windsurf_launches_today() -> int:
    """Count how many times Windsurf was launched today.

    Counts unique log directories created today.
    """
    log_base = get_paths().logs_dir

    if not log_base.exists():
        return 0

    today = datetime.now(tz=UTC).date()
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
                    dir_date = datetime.strptime(date_str, "%Y%m%d").replace(tzinfo=UTC).date()

                    if dir_date == today:
                        launches += 1
            except ValueError, IndexError:
                continue
    except OSError:
        pass  # Can't read logs directory

    return launches


def collect_process_infos() -> list[ProcessInfo]:
    """Collect Windsurf process infos with CPU sampling.

    Initializes CPU counters, waits 500ms, then reads final values.
    Shared by generate_report() and CLI snapshot commands.
    """
    procs = get_windsurf_processes()

    cpu_samples: dict[int, psutil.Process] = {}
    for proc in procs:
        try:
            proc.cpu_percent()
            cpu_samples[proc.pid] = proc
        except psutil.NoSuchProcess, psutil.AccessDenied:
            pass

    if cpu_samples:
        time.sleep(0.5)

    cpu_values: dict[int, float] = {}
    for pid, proc in cpu_samples.items():
        try:
            cpu_values[pid] = proc.cpu_percent()
        except psutil.NoSuchProcess, psutil.AccessDenied:
            cpu_values[pid] = 0.0

    result = []
    for p in procs:
        cpu = cpu_values.get(p.pid, 0.0)
        if pi := get_process_info(p, initial_cpu=cpu):
            result.append(pi)

    return result


def generate_report() -> MonitoringReport:
    """Generate complete monitoring report with optimized CPU sampling."""
    proc_infos = collect_process_infos()

    total_memory = sum(p.memory_mb for p in proc_infos)
    total_cpu = sum(p.cpu_percent for p in proc_infos)

    # Check PTY usage (pass process info for version/uptime extraction)
    pty_info = check_pty_leak(windsurf_processes=proc_infos)

    # Build log issues — skip orphan scan here; capture_ls_snapshot
    # performs orphan detection from the already-collected proc_infos,
    # avoiding a redundant psutil.process_iter walk.
    log_issues = check_log_issues(include_orphans=False)

    log_issues.extend(pty_info.issues)

    language_servers = find_language_servers(proc_infos)
    active_workspaces = get_active_workspaces()
    windsurf_version = _extract_windsurf_version(proc_infos)
    windsurf_uptime = _get_windsurf_uptime(proc_infos)

    ls_snapshot = capture_ls_snapshot(
        proc_infos,
        windsurf_version,
        windsurf_uptime,
        active_workspaces=active_workspaces,
    )
    log_issues.extend(ls_snapshot.issues)

    return MonitoringReport(
        timestamp=datetime.now(tz=UTC).isoformat(),
        system=get_system_info(),
        windsurf_processes=proc_infos,
        total_windsurf_memory_mb=total_memory,
        total_windsurf_cpu_percent=total_cpu,
        process_count=len(proc_infos),
        language_servers=language_servers,
        mcp_servers_enabled=get_mcp_config(),
        extensions_count=count_extensions(),
        log_issues=log_issues,
        active_workspaces=active_workspaces,
        windsurf_launches_today=count_windsurf_launches_today(),
        windsurf_version=windsurf_version,
        windsurf_uptime_seconds=windsurf_uptime,
        pty_info=pty_info,
        ls_snapshot=ls_snapshot,
    )


def classify_issue_severity(message: str) -> str:
    """Classify a single issue string into a severity label.

    Returns ``"critical"`` or ``"warning"`` based on the prefix marker
    (``✖`` → critical, ``⚠`` → warning).

    Issues without a recognised prefix are treated as warnings (safe default).
    """
    stripped = message.lstrip()
    if stripped.startswith(ISSUE_CRITICAL_PREFIX):
        return "critical"
    if stripped.startswith(ISSUE_WARNING_PREFIX):
        return "warning"
    return "warning"


def max_issue_severity(issues: list[str]) -> int:
    """Determine the highest severity among issue strings.

    Returns EXIT_OK (0) for no issues, EXIT_WARNING (1) for warnings only,
    or EXIT_CRITICAL (2) if any critical issue is present.

    Delegates per-issue classification to :func:`classify_issue_severity`.
    """
    if not issues:
        return EXIT_OK
    for issue in issues:
        if classify_issue_severity(issue) == "critical":
            return EXIT_CRITICAL
    return EXIT_WARNING


def save_report_json(report: MonitoringReport, output_path: Path) -> None:
    """Save report as JSON.

    Excludes raw_lsof from regular reports to keep file sizes small.
    The pty-snapshot command serializes PtyInfo directly for full forensic detail.
    """
    data = asdict(report)
    if data.get("pty_info"):
        data["pty_info"].pop("raw_lsof", None)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
