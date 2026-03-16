"""Core monitoring functionality."""

import json
import os
import re
import time
from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path

import psutil

from surfmon._constants import (
    CMDLINE_TRUNCATE_LEN,
    EXIT_CRITICAL,
    EXIT_OK,
    EXIT_WARNING,
    ISSUE_CRITICAL_PREFIX,
    ISSUE_WARNING_PREFIX,
)
from surfmon.config import get_paths
from surfmon.log_analysis import check_log_issues
from surfmon.pty import PtyInfo, check_pty_leak
from surfmon.workspaces import (
    WorkspaceInfo,
    _extract_workspace_from_cmdline,
    _extract_workspace_id,
    _format_workspace_display,
    _format_workspace_short,
    _resolve_workspace_path,
    count_windsurf_launches_today,
    get_active_workspaces,
)


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


def _filter_orphaned_crashpad(procs: list[psutil.Process]) -> list[psutil.Process]:
    """Remove orphaned crashpad handlers from a process list."""
    filtered = []
    for p in procs:
        try:
            if "crashpad" not in p.name().lower():
                filtered.append(p)
        except psutil.NoSuchProcess, psutil.AccessDenied:
            pass
    return filtered


def _matches_windsurf_app(info: dict, app_name: str) -> bool:
    """Return True if a process info dict belongs to the Windsurf app."""
    exe = info["exe"] or ""
    cmdline = " ".join(info["cmdline"] or [])
    return app_name in exe or app_name in cmdline


def get_windsurf_processes() -> list[psutil.Process]:
    """Find all Windsurf-related processes.

    Only matches processes from the configured Windsurf app, excluding:
    - This monitoring tool itself (surfmon)
    - Unrelated processes that happen to contain "windsurf" in their path
    - Orphaned crashpad handlers when the main Windsurf process isn't running
    """
    app_name = get_paths().app_name
    my_pid = os.getpid()

    windsurf_procs = []
    main_windsurf_found = False

    for proc in psutil.process_iter(["pid", "name", "cmdline", "exe"]):
        try:
            if proc.info["pid"] == my_pid:
                continue
            if not _matches_windsurf_app(proc.info, app_name):
                continue

            windsurf_procs.append(proc)
            if is_main_windsurf_process(proc.info["name"] or "", proc.info["exe"] or "", app_name):
                main_windsurf_found = True

        except psutil.NoSuchProcess, psutil.AccessDenied:
            pass

    if not main_windsurf_found:
        windsurf_procs = _filter_orphaned_crashpad(windsurf_procs)

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


_LS_KEYWORD_LABELS: tuple[tuple[tuple[str, ...], str], ...] = (
    (("gopls",), "Go Language Server"),
    (("pyright", "pylance"), "Python Language Server"),
    (("rust-analyzer",), "Rust Language Server"),
)


def _enhance_language_server_cmdline(p: ProcessInfo) -> str | None:
    """Build an enhanced cmdline description for a language server process."""
    cmdline = p.cmdline
    cmdline_lower = cmdline.lower()

    # Extract workspace ID for Codeium language server
    workspace_id = _extract_workspace_id(cmdline)
    if workspace_id:
        return f"{p.name} [workspace: {_format_workspace_short(workspace_id)}]"

    # Extract language for JDT LS
    if "jdtls" in cmdline_lower or "eclipse.jdt" in cmdline_lower:
        data_match = re.search(r"-data\s+(\S+)", cmdline)
        project = data_match.group(1).split("/")[-1] if data_match else None
        return f"{p.name} [Java: {project}]" if project else f"{p.name} [Java Language Server]"

    # Simple keyword → label lookup
    for keywords, label in _LS_KEYWORD_LABELS:
        if any(kw in cmdline_lower for kw in keywords):
            return f"{p.name} [{label}]"

    # Truncate long cmdlines if no enhancement found
    if len(cmdline) > CMDLINE_TRUNCATE_LEN:
        return cmdline[:CMDLINE_TRUNCATE_LEN] + "..."

    return None


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


def _build_ls_entry(
    ls: ProcessInfo,
    proc_infos: list[ProcessInfo],
    active_ws_paths: set[str],
) -> tuple[LsSnapshotEntry, str | None]:
    """Build a single LsSnapshotEntry with optional issue string.

    Returns (entry, issue_string) where issue_string is None when healthy.
    """
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

    issue = None
    if orphaned:
        issue = _format_orphan_issue(ls, workspace, original_proc.cmdline)
    elif stale:
        issue = (
            f"{ISSUE_WARNING_PREFIX}  {ls.name} (PID {ls.pid}) still running for closed workspace "
            f"'{workspace}' — consuming {ls.memory_mb:.0f} MB RAM"
        )

    return entry, issue


def _format_orphan_issue(ls: ProcessInfo, workspace: str, cmdline: str) -> str:
    """Build a detailed orphan-workspace issue string.

    Includes database directory size and cleanup command when the
    ``--database_dir`` flag is present in the process command line.
    """
    prefix = f"{ISSUE_CRITICAL_PREFIX}  CRITICAL: {ls.name} (PID {ls.pid}) indexing non-existent workspace '{workspace}'"
    db_match = re.search(r"--database_dir\s+(\S+)", cmdline)
    if db_match:
        db_path = Path(db_match.group(1))
        db_size_mb = 0
        try:
            if db_path.exists():
                db_size_mb = sum(f.stat().st_size for f in db_path.rglob("*") if f.is_file()) / 1024 / 1024
        except OSError:
            pass
        return f"{prefix} (consuming {ls.memory_mb:.0f} MB RAM, {db_size_mb:.0f} MB disk) - Fix: Close Windsurf, run: rm -rf {db_path}"
    return f"{prefix} — consuming {ls.memory_mb:.0f} MB RAM"


def capture_ls_snapshot(
    proc_infos: list[ProcessInfo],
    windsurf_version: str,
    windsurf_uptime: float,
    active_workspaces: list[WorkspaceInfo] | None = None,
    lang_servers: list[ProcessInfo] | None = None,
) -> LsSnapshot:
    """Capture a forensic snapshot of all language server processes.

    Returns structured data about every language server: memory, CPU,
    workspace mapping, orphaned status (indexing deleted workspace), and
    stale status (workspace exists but not open in the IDE).
    """
    if lang_servers is None:
        lang_servers = find_language_servers(proc_infos)
    active_ws_paths = {ws.path for ws in active_workspaces} if active_workspaces else set()

    entries = []
    orphan_issues: list[str] = []
    stale_issues: list[str] = []
    total_memory = 0.0

    for ls in lang_servers:
        entry, issue = _build_ls_entry(ls, proc_infos, active_ws_paths)
        entries.append(entry)
        total_memory += entry.memory_mb

        if issue and ISSUE_CRITICAL_PREFIX in issue:
            orphan_issues.append(issue)
        elif issue:
            stale_issues.append(issue)

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

    # Log issues (orphan detection handled by capture_ls_snapshot below)
    log_issues = check_log_issues()

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
        lang_servers=language_servers,
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
