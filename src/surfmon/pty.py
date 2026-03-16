"""PTY leak detection and forensic analysis for Windsurf."""

from __future__ import annotations

import subprocess  # noqa: S404
from dataclasses import dataclass, field

from surfmon._constants import (
    LSOF_MIN_FIELDS,
    PTY_CRITICAL_COUNT,
    PTY_USAGE_CRITICAL_PERCENT,
    PTY_WARNING_COUNT,
    Issue,
    IssueSeverity,
)
from surfmon.config import get_paths


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
    issues: list[Issue] = field(default_factory=list)


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


def _classify_pty_issues(
    windsurf_pty_count: int,
    system_pty_used: int,
    system_pty_limit: int,
) -> list[Issue]:
    """Generate issues for PTY leak severity.

    Returns a list of 0 or 1 :class:`Issue` objects, classified as critical
    or warning based on PTY count and system usage thresholds.
    """
    if windsurf_pty_count <= 0:
        return []

    usage_pct = (system_pty_used / system_pty_limit) * 100 if system_pty_limit > 0 else 0

    if windsurf_pty_count >= PTY_CRITICAL_COUNT or usage_pct >= PTY_USAGE_CRITICAL_PERCENT:
        return [
            Issue(
                IssueSeverity.CRITICAL,
                f"Windsurf processes are holding {windsurf_pty_count} PTYs "
                f"(system: {system_pty_used}/{system_pty_limit}, {usage_pct:.0f}% used) "
                f"- Fix: Restart all Windsurf instances to release leaked PTYs",
            )
        ]

    if windsurf_pty_count >= PTY_WARNING_COUNT:
        return [
            Issue(
                IssueSeverity.WARNING,
                f"Windsurf PTY leak detected: {windsurf_pty_count} PTYs held "
                f"(system: {system_pty_used}/{system_pty_limit}) "
                f"- Monitor closely, restart all Windsurf instances if it keeps growing",
            )
        ]

    return []


@dataclass
class _LsofResult:
    """Parsed lsof /dev/ptmx output."""

    windsurf_entries: list[PtyFdEntry]
    non_windsurf_entries: list[PtyFdEntry]
    system_pty_used: int
    raw_lsof: str


def _run_lsof_ptmx(app_name: str) -> _LsofResult:
    """Run lsof /dev/ptmx and partition entries into windsurf vs non-windsurf."""
    try:
        result = subprocess.run(
            ["lsof", "/dev/ptmx"],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except subprocess.TimeoutExpired, OSError:
        return _LsofResult([], [], 0, "")

    if result.returncode != 0:
        return _LsofResult([], [], 0, "")

    lines = result.stdout.strip().split("\n")
    data_lines = lines[1:] if len(lines) > 1 else []

    # The app_name contains ".app" but lsof COMMAND column shows just the binary name
    windsurf_cmd_prefix = app_name.split(".", maxsplit=1)[0].strip().split()[0]

    windsurf_entries: list[PtyFdEntry] = []
    non_windsurf_entries: list[PtyFdEntry] = []
    for line in data_lines:
        entry = _parse_lsof_line(line)
        if entry is None:
            continue
        if windsurf_cmd_prefix in entry.command:
            windsurf_entries.append(entry)
        else:
            non_windsurf_entries.append(entry)

    return _LsofResult(windsurf_entries, non_windsurf_entries, len(data_lines), result.stdout)


def check_pty_leak(windsurf_processes: list | None = None) -> PtyInfo:
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
    lsof = _run_lsof_ptmx(get_paths().app_name)

    # Extract version and uptime from process list if available
    version = ""
    uptime = 0.0
    if windsurf_processes:
        from surfmon.monitor import _extract_windsurf_version, _get_windsurf_uptime

        version = _extract_windsurf_version(windsurf_processes)
        uptime = _get_windsurf_uptime(windsurf_processes)

    windsurf_pty_count = len(lsof.windsurf_entries)

    return PtyInfo(
        windsurf_pty_count=windsurf_pty_count,
        system_pty_limit=system_pty_limit,
        system_pty_used=lsof.system_pty_used,
        per_process=_group_entries_by_pid(lsof.windsurf_entries),
        fd_entries=lsof.windsurf_entries,
        non_windsurf_holders=_group_entries_by_pid(lsof.non_windsurf_entries),
        windsurf_version=version,
        windsurf_uptime_seconds=uptime,
        raw_lsof=lsof.raw_lsof,
        issues=_classify_pty_issues(windsurf_pty_count, lsof.system_pty_used, system_pty_limit),
    )
