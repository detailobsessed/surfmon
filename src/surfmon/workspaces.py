"""Workspace detection, resolution, and active workspace tracking."""

import re
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path

from surfmon._constants import PATH_COMPONENTS_SHORT
from surfmon.config import get_paths


@dataclass(slots=True, frozen=True)
class WorkspaceInfo:
    """Information about a Windsurf workspace."""

    id: str
    path: str
    exists: bool
    loaded_at: str | None = None


# ---------------------------------------------------------------------------
# Workspace path resolution
# ---------------------------------------------------------------------------

_MIN_HEX_LEN = 2  # minimum chars for a percent-encoded sequence (e.g. _20 → space)


def _try_joiners(base: Path, segments: list[str]) -> Path | None:
    """Try ``/``, ``-``, ``.``, ``~``, and percent-decoded chars for each underscore."""
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

    # Option 2/3/4: underscore was -, ., or ~ (merge with next segment)
    for joiner in ("-", ".", "~"):
        merged = [first + joiner + rest[0], *rest[1:]]
        result = _try_joiners(base, merged)
        if result is not None:
            return result

    # Option 5: percent-encoded character (_XX where XX is hex)
    # Codeium URL-encodes special chars (e.g. space → %20) then replaces % with _,
    # so _20 in the workspace_id represents a literal space in the path.
    if len(rest[0]) >= _MIN_HEX_LEN:
        hex_prefix = rest[0][:_MIN_HEX_LEN]
        try:
            decoded_char = chr(int(hex_prefix, 16))
        except ValueError:
            decoded_char = ""
        if decoded_char and decoded_char.isprintable():
            suffix = rest[0][_MIN_HEX_LEN:]
            merged = [first + decoded_char + suffix, *rest[1:]]
            result = _try_joiners(base, merged)
            if result is not None:
                return result

    return None


def _resolve_workspace_path(workspace_id: str) -> Path | None:
    """Resolve a Codeium workspace_id to an existing filesystem path.

    Codeium encodes ``/``, ``-``, ``.``, and ``~`` as ``_`` in its
    ``--workspace_id`` argument, and URL-encodes other special characters
    (e.g. space → ``%20``) with ``%`` also replaced by ``_`` (so space
    becomes ``_20``).  A naïve ``replace("_", "/")`` produces false paths
    for any directory whose name contains hyphens, dots, tildes, or spaces.

    This function walks the filesystem, trying ``/``, ``-``, ``.``, ``~``,
    and percent-decoded characters for each encoded underscore until it finds
    a path that actually exists.  Returns ``None`` when no valid decoding is
    found (truly orphaned workspace).
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


def _parse_log_dir_date(name: str) -> date | None:
    """Parse a log directory name (e.g. '20260204T151929') into a date, or None."""
    if "T" not in name:
        return None
    try:
        return datetime.strptime(name.split("T", maxsplit=1)[0], "%Y%m%d").replace(tzinfo=UTC).date()
    except ValueError, IndexError:
        return None


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
            dir_date = _parse_log_dir_date(log_dir.name)
            if dir_date == today:
                launches += 1
    except OSError:
        pass  # Can't read logs directory

    return launches
