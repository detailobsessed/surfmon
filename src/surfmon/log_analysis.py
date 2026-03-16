"""Log analysis and issue detection for Windsurf logs."""

from __future__ import annotations

import operator
import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import psutil

if TYPE_CHECKING:
    from pathlib import Path

from surfmon._constants import (
    EXTENSION_ERROR_LINES_THRESHOLD,
    ISSUE_CRITICAL_PREFIX,
    ISSUE_WARNING_PREFIX,
    LOG_TAIL_BYTES,
    MAX_DISPLAY_ITEMS,
    SECONDS_PER_DAY,
    SECONDS_PER_HOUR,
    SECONDS_PER_MINUTE,
    SHARED_LOG_TAIL_BYTES,
    TELEMETRY_ERROR_THRESHOLD,
)
from surfmon.config import get_paths
from surfmon.workspaces import check_orphaned_workspaces


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


def _scan_crashpad_processes(app_name: str) -> tuple[bool, list[tuple[int, float]]]:
    """Scan running processes for crashpad handlers and main Windsurf.

    Returns:
        Tuple of (main_windsurf_found, orphaned) where orphaned is a list
        of (pid, age_days) tuples for crashpad handler processes.
    """
    from surfmon.monitor import is_main_windsurf_process

    orphaned: list[tuple[int, float]] = []
    main_windsurf_found = False

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

    return main_windsurf_found, orphaned


def _check_orphaned_crashpad_handlers() -> list[str]:
    """Check for orphaned crashpad handler processes."""
    main_found, orphaned = _scan_crashpad_processes(get_paths().app_name)

    if main_found or not orphaned:
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
