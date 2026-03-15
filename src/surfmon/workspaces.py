"""Workspace detection, resolution, and orphan/stale analysis."""

import contextlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import psutil

from surfmon._constants import ISSUE_CRITICAL_PREFIX, PATH_COMPONENTS_SHORT
from surfmon.config import get_paths


@dataclass
class WorkspaceInfo:
    """Information about a Windsurf workspace."""

    id: str
    path: str
    exists: bool
    loaded_at: str | None = None


# ---------------------------------------------------------------------------
# Workspace path resolution
# ---------------------------------------------------------------------------


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


def _extract_workspace_id(cmdline: str) -> str | None:
    """Extract workspace ID from a language server command line."""
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

    # Fallback: look for -data argument
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


# ---------------------------------------------------------------------------
# Orphaned workspace detection (process-level)
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Active workspace tracking (from logs)
# ---------------------------------------------------------------------------


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
