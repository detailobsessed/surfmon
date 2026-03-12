"""SQLite historical database for surfmon.

Stores structured investigation data in ~/.surfmon/surfmon.db using sqlite-utils.
Every check, ls-snapshot, pty-snapshot, and watch invocation writes to this DB,
enabling trending, cross-session analysis, and advanced reporting.
"""

import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

from sqlite_utils import Database
from sqlite_utils.db import NotFoundError, Table

from . import __version__

if TYPE_CHECKING:
    from .monitor import LsSnapshot, MonitoringReport, PtyInfo

DB_DIR = Path.home() / ".surfmon"
DB_PATH = DB_DIR / "surfmon.db"

# Bump this when adding migrations. Each migration upgrades from (version - 1) to version.
SCHEMA_VERSION: int = 1

# Duration shorthand parser: "24h", "7d", "30m"
_DURATION_UNITS = {"m": "minutes", "h": "hours", "d": "days", "w": "weeks"}


def _parse_since(since: str) -> datetime:
    """Parse a human duration string like '24h', '7d', '30m' into a UTC datetime."""
    unit = since[-1].lower()
    if unit not in _DURATION_UNITS:
        msg = f"Invalid duration unit '{unit}'. Use m/h/d/w (e.g. '24h', '7d')."
        raise ValueError(msg)
    value = int(since[:-1])
    delta = timedelta(**{_DURATION_UNITS[unit]: value})
    return datetime.now(tz=UTC) - delta


def get_db(db_path: Path | None = None) -> Database:
    """Open (or create) the surfmon database and ensure schema exists."""
    path = db_path or DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    db = Database(path)
    _ensure_schema(db)
    return db


def _get_schema_version(db: Database) -> int:
    """Read the current schema version from the _meta table, or 0 if missing."""
    if "_meta" not in db.table_names():
        return 0
    try:
        row = Table(db, "_meta").get("schema_version")
    except NotFoundError:
        return 0
    return int(row["value"])


def _set_schema_version(db: Database, version: int) -> None:
    """Write the schema version to the _meta table."""
    if "_meta" not in db.table_names():
        Table(db, "_meta").create({"key": str, "value": str}, pk="key")
    Table(db, "_meta").upsert({"key": "schema_version", "value": str(version)}, pk="key")


# Migrations: list of callables, each upgrading from (index + 1) to (index + 2).
# Each callable receives the Database and performs the schema change.
_MIGRATIONS: list = []


def _ensure_schema(db: Database) -> None:
    """Create tables if they don't exist, then run pending migrations."""
    # Capture state before CREATE TABLE blocks modify it.
    # Legacy DBs (pre-migration-framework) have tables but no _meta table.
    is_legacy = "sessions" in db.table_names() and "_meta" not in db.table_names()

    if "sessions" not in db.table_names():
        Table(db, "sessions").create(
            {
                "id": str,
                "timestamp": str,
                "command": str,
                "windsurf_version": str,
                "windsurf_target": str,
                "windsurf_uptime_s": float,
                "surfmon_version": str,
            },
            pk="id",
        )

    if "system_snapshots" not in db.table_names():
        Table(db, "system_snapshots").create(
            {
                "session_id": str,
                "total_memory_gb": float,
                "available_memory_gb": float,
                "memory_percent": float,
                "cpu_count": int,
                "swap_total_gb": float,
                "swap_used_gb": float,
            },
            pk="session_id",
            foreign_keys=[("session_id", "sessions", "id")],
        )

    if "processes" not in db.table_names():
        Table(db, "processes").create(
            {
                "id": int,
                "session_id": str,
                "pid": int,
                "name": str,
                "cpu_percent": float,
                "memory_mb": float,
                "memory_percent": float,
                "num_threads": int,
                "runtime_s": float,
                "cmdline": str,
            },
            pk="id",
            foreign_keys=[("session_id", "sessions", "id")],
        )

    if "ls_entries" not in db.table_names():
        Table(db, "ls_entries").create(
            {
                "id": int,
                "session_id": str,
                "pid": int,
                "name": str,
                "language": str,
                "memory_mb": float,
                "cpu_percent": float,
                "num_threads": int,
                "runtime_s": float,
                "workspace": str,
                "orphaned": int,
            },
            pk="id",
            foreign_keys=[("session_id", "sessions", "id")],
        )

    if "pty_snapshots" not in db.table_names():
        Table(db, "pty_snapshots").create(
            {
                "session_id": str,
                "windsurf_pty_count": int,
                "system_pty_limit": int,
                "system_pty_used": int,
            },
            pk="session_id",
            foreign_keys=[("session_id", "sessions", "id")],
        )

    if "pty_per_process" not in db.table_names():
        Table(db, "pty_per_process").create(
            {
                "id": int,
                "session_id": str,
                "pid": int,
                "name": str,
                "pty_count": int,
                "fds": str,
            },
            pk="id",
            foreign_keys=[("session_id", "sessions", "id")],
        )

    if "issues" not in db.table_names():
        Table(db, "issues").create(
            {
                "id": int,
                "session_id": str,
                "severity": str,
                "message": str,
            },
            pk="id",
            foreign_keys=[("session_id", "sessions", "id")],
        )

    # Fresh DB: CREATE TABLE blocks above always reflect the latest schema,
    # so just stamp the version and skip migrations entirely.
    current = _get_schema_version(db)
    if current == 0:
        if is_legacy:
            # Legacy DB created before migration framework — treat as v1.
            current = 1
            _set_schema_version(db, current)
        else:
            _set_schema_version(db, SCHEMA_VERSION)
            return

    # Existing DB: run pending migrations, bumping version after each so
    # partial failures don't re-execute already-succeeded migrations.
    for target_version in range(current + 1, SCHEMA_VERSION + 1):
        migration_index = target_version - 2  # version 2 → index 0
        if migration_index >= len(_MIGRATIONS):
            msg = f"Missing migration for schema version {target_version} (expected _MIGRATIONS[{migration_index}])"
            raise RuntimeError(msg)
        _MIGRATIONS[migration_index](db)
        _set_schema_version(db, target_version)


def _new_session_id() -> str:
    return str(uuid.uuid4())


def _classify_issue_severity(message: str) -> str:
    """Classify issue severity from its message text."""
    msg_lower = message.lower()
    if "critical" in msg_lower or "✖" in message:
        return "critical"
    if "⚠" in message or "warning" in msg_lower or "leak" in msg_lower:
        return "warning"
    return "info"


def store_check(db: Database, report: MonitoringReport, target: str = "") -> str:
    """Store a full check report. Returns the session ID."""
    session_id = _new_session_id()

    Table(db, "sessions").insert({
        "id": session_id,
        "timestamp": report.timestamp,
        "command": "check",
        "windsurf_version": report.windsurf_version,
        "windsurf_target": target,
        "windsurf_uptime_s": report.windsurf_uptime_seconds,
        "surfmon_version": __version__,
    })

    Table(db, "system_snapshots").insert({
        "session_id": session_id,
        "total_memory_gb": report.system.total_memory_gb,
        "available_memory_gb": report.system.available_memory_gb,
        "memory_percent": report.system.memory_percent,
        "cpu_count": report.system.cpu_count,
        "swap_total_gb": report.system.swap_total_gb,
        "swap_used_gb": report.system.swap_used_gb,
    })

    for proc in report.windsurf_processes:
        Table(db, "processes").insert({
            "session_id": session_id,
            "pid": proc.pid,
            "name": proc.name,
            "cpu_percent": proc.cpu_percent,
            "memory_mb": proc.memory_mb,
            "memory_percent": proc.memory_percent,
            "num_threads": proc.num_threads,
            "runtime_s": proc.runtime_seconds,
            "cmdline": proc.cmdline,
        })

    if report.pty_info:
        _store_pty_data(db, session_id, report.pty_info)

    for issue_msg in report.log_issues:
        Table(db, "issues").insert({
            "session_id": session_id,
            "severity": _classify_issue_severity(issue_msg),
            "message": issue_msg,
        })

    return session_id


def store_ls_snapshot(db: Database, snapshot: LsSnapshot, target: str = "") -> str:
    """Store a language server snapshot. Returns the session ID."""
    session_id = _new_session_id()

    Table(db, "sessions").insert({
        "id": session_id,
        "timestamp": snapshot.timestamp,
        "command": "ls-snapshot",
        "windsurf_version": snapshot.windsurf_version,
        "windsurf_target": target,
        "windsurf_uptime_s": snapshot.windsurf_uptime_seconds,
        "surfmon_version": __version__,
    })

    for entry in snapshot.entries:
        Table(db, "ls_entries").insert({
            "session_id": session_id,
            "pid": entry.pid,
            "name": entry.name,
            "language": entry.language,
            "memory_mb": entry.memory_mb,
            "cpu_percent": entry.cpu_percent,
            "num_threads": entry.num_threads,
            "runtime_s": entry.runtime_seconds,
            "workspace": entry.workspace,
            "orphaned": int(entry.orphaned),
        })

    for issue_msg in snapshot.issues:
        Table(db, "issues").insert({
            "session_id": session_id,
            "severity": _classify_issue_severity(issue_msg),
            "message": issue_msg,
        })

    return session_id


def store_pty_snapshot(db: Database, pty: PtyInfo, target: str = "") -> str:
    """Store a PTY forensic snapshot. Returns the session ID."""
    session_id = _new_session_id()

    Table(db, "sessions").insert({
        "id": session_id,
        "timestamp": datetime.now(tz=UTC).isoformat(),
        "command": "pty-snapshot",
        "windsurf_version": pty.windsurf_version,
        "windsurf_target": target,
        "windsurf_uptime_s": pty.windsurf_uptime_seconds,
        "surfmon_version": __version__,
    })

    _store_pty_data(db, session_id, pty)
    return session_id


def _store_pty_data(db: Database, session_id: str, pty: PtyInfo) -> None:
    """Store PTY-related data (shared between check and pty-snapshot)."""
    Table(db, "pty_snapshots").insert({
        "session_id": session_id,
        "windsurf_pty_count": pty.windsurf_pty_count,
        "system_pty_limit": pty.system_pty_limit,
        "system_pty_used": pty.system_pty_used,
    })

    if pty.per_process:
        for detail in pty.per_process:
            Table(db, "pty_per_process").insert({
                "session_id": session_id,
                "pid": detail.pid,
                "name": detail.name,
                "pty_count": detail.pty_count,
                "fds": json.dumps(detail.fds),
            })


def query_history(
    db: Database,
    command: str | None = None,
    limit: int = 20,
    since: str | None = None,
) -> list[tuple]:
    """Query recent sessions with summary metrics.

    Returns a list of tuples with session info plus aggregated metrics.
    """
    where_clauses = []
    params = []

    if command:
        where_clauses.append("s.command = ?")
        params.append(command)

    if since:
        cutoff = _parse_since(since)
        where_clauses.append("s.timestamp >= ?")
        params.append(cutoff.isoformat())

    parts = [
        "SELECT",
        "    s.id, s.timestamp, s.command, s.windsurf_version, s.windsurf_target,",
        "    s.windsurf_uptime_s, s.surfmon_version,",
        "    (SELECT COUNT(*) FROM processes p WHERE p.session_id = s.id) AS process_count,",
        "    (SELECT COALESCE(SUM(p.memory_mb), 0) FROM processes p WHERE p.session_id = s.id) AS total_memory_mb,",
        "    (SELECT COUNT(*) FROM ls_entries l WHERE l.session_id = s.id) AS ls_count,",
        "    (SELECT COALESCE(SUM(l.memory_mb), 0) FROM ls_entries l WHERE l.session_id = s.id) AS ls_memory_mb,",
        "    (SELECT COUNT(*) FROM ls_entries l WHERE l.session_id = s.id AND l.orphaned = 1) AS orphaned_count,",
        "    (SELECT ps.windsurf_pty_count FROM pty_snapshots ps WHERE ps.session_id = s.id) AS pty_count,",
        "    (SELECT COUNT(*) FROM issues i WHERE i.session_id = s.id) AS issue_count",
        "FROM sessions s",
    ]
    if where_clauses:
        parts.append("WHERE " + " AND ".join(where_clauses))
    parts.extend(["ORDER BY s.timestamp DESC", "LIMIT ?"])
    params.append(limit)
    sql = " ".join(parts)

    return list(db.execute(sql, params).fetchall())


HISTORY_COLUMNS = [
    "id",
    "timestamp",
    "command",
    "windsurf_version",
    "windsurf_target",
    "windsurf_uptime_s",
    "surfmon_version",
    "process_count",
    "total_memory_mb",
    "ls_count",
    "ls_memory_mb",
    "orphaned_count",
    "pty_count",
    "issue_count",
]


def query_history_dicts(
    db: Database,
    command: str | None = None,
    limit: int = 20,
    since: str | None = None,
) -> list[dict]:
    """Query recent sessions, returning list of dicts."""
    rows = query_history(db, command=command, limit=limit, since=since)
    return [dict(zip(HISTORY_COLUMNS, row, strict=True)) for row in rows]


_TREND_QUERIES: dict[str, tuple[str, str | None, str | None]] = {
    "memory": (
        ("SELECT s.timestamp, COALESCE(SUM(p.memory_mb), 0) AS value FROM sessions s LEFT JOIN processes p ON p.session_id = s.id"),
        "check",
        "GROUP BY s.id",
    ),
    "processes": (
        ("SELECT s.timestamp, COUNT(p.id) AS value FROM sessions s LEFT JOIN processes p ON p.session_id = s.id"),
        "check",
        "GROUP BY s.id",
    ),
    "pty": (
        ("SELECT s.timestamp, ps.windsurf_pty_count AS value FROM sessions s JOIN pty_snapshots ps ON ps.session_id = s.id"),
        None,
        None,
    ),
    "ls-memory": (
        ("SELECT s.timestamp, COALESCE(SUM(l.memory_mb), 0) AS value FROM sessions s LEFT JOIN ls_entries l ON l.session_id = s.id"),
        "ls-snapshot",
        "GROUP BY s.id",
    ),
    "ls-count": (
        ("SELECT s.timestamp, COUNT(l.id) AS value FROM sessions s LEFT JOIN ls_entries l ON l.session_id = s.id"),
        "ls-snapshot",
        "GROUP BY s.id",
    ),
}

TREND_METRICS = list(_TREND_QUERIES)


def query_trend(
    db: Database,
    metric: str,
    since: str | None = None,
) -> list[dict]:
    """Query time-series data for a specific metric.

    Supported metrics: memory, processes, pty, ls-memory, ls-count
    Returns list of {timestamp, value} dicts ordered chronologically.
    """
    if metric not in _TREND_QUERIES:
        msg = f"Unknown metric '{metric}'. Choose from: {', '.join(_TREND_QUERIES)}"
        raise ValueError(msg)

    select_join, fixed_command, group_by = _TREND_QUERIES[metric]
    where_parts: list[str] = []
    params: list = []

    if fixed_command:
        where_parts.append("s.command = ?")
        params.append(fixed_command)

    if since:
        cutoff = _parse_since(since)
        where_parts.append("s.timestamp >= ?")
        params.append(cutoff.isoformat())

    parts = [select_join]
    if where_parts:
        parts.append("WHERE " + " AND ".join(where_parts))
    if group_by:
        parts.append(group_by)
    parts.append("ORDER BY s.timestamp")

    sql = " ".join(parts)
    rows = db.execute(sql, params).fetchall()
    return [{"timestamp": row[0], "value": row[1]} for row in rows]
