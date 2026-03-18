"""Language server detection and forensic snapshot capture."""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from surfmon._constants import (
    CMDLINE_TRUNCATE_LEN,
    Issue,
    IssueSeverity,
)
from surfmon.workspaces import (
    WorkspaceInfo,
    _extract_workspace_from_cmdline,
    _extract_workspace_id,
    _format_workspace_display,
    _format_workspace_short,
    _resolve_workspace_path,
)

if TYPE_CHECKING:
    from .monitor import ProcessInfo


@dataclass(slots=True, frozen=True)
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


@dataclass(slots=True, frozen=True)
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
    orphan_issues: list[Issue]
    stale_issues: list[Issue]
    issues: list[Issue] = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "issues", self.orphan_issues + self.stale_issues)


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
) -> tuple[LsSnapshotEntry, Issue | None]:
    """Build a single LsSnapshotEntry with optional Issue.

    Returns (entry, issue) where issue is None when healthy.
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

    orphaned = workspace_id is not None and workspace_id.startswith("file_") and resolved_path is None
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
        issue = Issue(
            IssueSeverity.WARNING,
            f"{ls.name} (PID {ls.pid}) still running for closed workspace '{workspace}' — consuming {ls.memory_mb:.0f} MB RAM",
        )

    return entry, issue


def _format_orphan_issue(ls: ProcessInfo, workspace: str, cmdline: str) -> Issue:
    """Build a detailed orphan-workspace issue.

    Includes database directory size and cleanup command when the
    ``--database_dir`` flag is present in the process command line.
    """
    base = f"{ls.name} (PID {ls.pid}) indexing non-existent workspace '{workspace}'"
    db_match = re.search(r"--database_dir\s+(\S+)", cmdline)
    if db_match:
        db_path = Path(db_match.group(1))
        db_size_mb = 0
        try:
            if db_path.exists():
                db_size_mb = sum(f.stat().st_size for f in db_path.rglob("*") if f.is_file()) / 1024 / 1024
        except OSError:
            pass
        return Issue(
            IssueSeverity.CRITICAL,
            f"{base} (consuming {ls.memory_mb:.0f} MB RAM, {db_size_mb:.0f} MB disk) - Fix: Close Windsurf, run: rm -rf {db_path}",
        )
    return Issue(IssueSeverity.CRITICAL, f"{base} — consuming {ls.memory_mb:.0f} MB RAM")


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
    orphan_issues: list[Issue] = []
    stale_issues: list[Issue] = []
    total_memory = 0.0

    for ls in lang_servers:
        entry, issue = _build_ls_entry(ls, proc_infos, active_ws_paths)
        entries.append(entry)
        total_memory += entry.memory_mb

        if issue and issue.severity == IssueSeverity.CRITICAL:
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
