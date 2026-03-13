"""Tests for surfmon.db — SQLite historical database."""

from datetime import UTC, datetime

import pytest
from sqlite_utils import Database
from sqlite_utils.db import Table

from surfmon.db import (
    HISTORY_COLUMNS,
    SCHEMA_VERSION,
    _classify_issue_severity,
    _ensure_schema,
    _get_schema_version,
    _parse_since,
    _set_schema_version,
    get_db,
    query_analyze_sessions,
    query_history,
    query_history_dicts,
    query_trend,
    store_check,
    store_ls_snapshot,
    store_pty_snapshot,
)
from surfmon.monitor import (
    LsSnapshot,
    LsSnapshotEntry,
    MonitoringReport,
    ProcessInfo,
    PtyInfo,
    PtyProcessDetail,
    SystemInfo,
)


@pytest.fixture
def db(tmp_path):
    """Create an in-memory-like DB in tmp_path for test isolation."""
    database = get_db(tmp_path / "test.db")
    yield database
    if database.conn:
        database.conn.close()


def _make_system_info():
    return SystemInfo(
        total_memory_gb=96.0,
        available_memory_gb=48.0,
        memory_percent=50.0,
        cpu_count=10,
        swap_total_gb=8.0,
        swap_used_gb=1.0,
    )


def _make_process(pid=1234, name="language_server_macos_arm", memory_mb=500.0):
    return ProcessInfo(
        pid=pid,
        name=name,
        cpu_percent=5.0,
        memory_mb=memory_mb,
        memory_percent=1.5,
        num_threads=20,
        runtime_seconds=3600.0,
        cmdline=f"/app/{name} --workspace_id file_Users_ismar_repos_surfmon",
    )


def _make_report(  # noqa: PLR0913
    *,
    timestamp=None,
    processes=None,
    pty_info=None,
    issues=None,
    windsurf_version="",
    windsurf_uptime_seconds=0.0,
):
    return MonitoringReport(
        timestamp=timestamp or datetime.now(tz=UTC).isoformat(),
        system=_make_system_info(),
        windsurf_processes=[_make_process()] if processes is None else processes,
        total_windsurf_memory_mb=2048.0,
        total_windsurf_cpu_percent=15.0,
        process_count=5,
        language_servers=[],
        mcp_servers_enabled=["server1"],
        extensions_count=20,
        log_issues=issues or [],
        active_workspaces=[],
        windsurf_launches_today=3,
        windsurf_version=windsurf_version,
        windsurf_uptime_seconds=windsurf_uptime_seconds,
        pty_info=pty_info,
    )


def _make_ls_snapshot(timestamp=None, entries=None, issues=None):
    return LsSnapshot(
        timestamp=timestamp or datetime.now(tz=UTC).isoformat(),
        windsurf_version="1.9577.1024",
        windsurf_uptime_seconds=7200.0,
        total_ls_count=2,
        total_ls_memory_mb=800.0,
        orphaned_count=0,
        entries=entries
        or [
            LsSnapshotEntry(
                pid=5678,
                name="language_server_macos_arm",
                language="python",
                memory_mb=400.0,
                memory_percent=1.2,
                cpu_percent=3.0,
                num_threads=15,
                runtime_seconds=3600.0,
                workspace="repos/surfmon",
                orphaned=False,
            ),
        ],
        issues=issues or [],
    )


def _make_pty_info():
    return PtyInfo(
        windsurf_pty_count=25,
        system_pty_limit=2048,
        system_pty_used=150,
        per_process=[
            PtyProcessDetail(pid=1234, name="Windsurf", pty_count=20, fds=["33u", "34u"]),
        ],
        windsurf_version="1.9577.1024",
        windsurf_uptime_seconds=7200.0,
    )


class TestEnsureSchema:
    def test_creates_all_tables(self, db):
        expected = {"sessions", "system_snapshots", "processes", "ls_entries", "pty_snapshots", "pty_per_process", "issues"}
        assert expected.issubset(set(db.table_names()))

    def test_idempotent(self, db):
        tables_before = set(db.table_names())
        # Re-open same DB — schema should not fail
        from surfmon.db import _ensure_schema

        _ensure_schema(db)
        assert set(db.table_names()) == tables_before


class TestSchemaMigration:
    def test_fresh_db_gets_current_version(self, db):
        assert _get_schema_version(db) == SCHEMA_VERSION

    def test_meta_table_exists(self, db):
        assert "_meta" in db.table_names()

    def test_idempotent_rerun_keeps_version(self, db):
        _ensure_schema(db)
        assert _get_schema_version(db) == SCHEMA_VERSION

    def test_legacy_db_without_meta_runs_migrations(self, monkeypatch, tmp_path):
        """Legacy DB (pre-migration-framework) has tables but no _meta — should migrate from v1."""
        legacy_db = Database(tmp_path / "legacy.db")
        # Create tables manually to simulate a pre-migration DB
        Table(legacy_db, "sessions").create(
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
        assert "sessions" in legacy_db.table_names()
        assert "_meta" not in legacy_db.table_names()

        migration_ran = []

        def fake_migrate_v2(_database):
            migration_ran.append(2)

        import surfmon.db as db_mod

        monkeypatch.setattr(db_mod, "SCHEMA_VERSION", 2)
        monkeypatch.setattr(db_mod, "_MIGRATIONS", [fake_migrate_v2])
        _ensure_schema(legacy_db)
        assert "_meta" in legacy_db.table_names()
        assert _get_schema_version(legacy_db) == 2
        assert migration_ran == [2]

        # Second call should be a no-op (no longer detected as legacy)
        migration_ran.clear()
        _ensure_schema(legacy_db)
        assert _get_schema_version(legacy_db) == 2
        assert migration_ran == []
        if legacy_db.conn:
            legacy_db.conn.close()

    def test_migration_runs_on_old_db(self, db, monkeypatch):
        # Simulate a v1 DB that needs upgrading to v2
        _set_schema_version(db, 1)
        migration_ran = []

        def fake_migrate_v2(_database):
            migration_ran.append(2)

        import surfmon.db as db_mod

        monkeypatch.setattr(db_mod, "SCHEMA_VERSION", 2)
        monkeypatch.setattr(db_mod, "_MIGRATIONS", [fake_migrate_v2])
        _ensure_schema(db)
        assert _get_schema_version(db) == 2
        assert migration_ran == [2]

    def test_skips_already_applied_migrations(self, db, monkeypatch):
        # DB is already at SCHEMA_VERSION — no migrations should run
        migration_ran = []

        def fake_migrate(_database):
            migration_ran.append(True)

        import surfmon.db as db_mod

        monkeypatch.setattr(db_mod, "_MIGRATIONS", [fake_migrate])
        _ensure_schema(db)
        assert migration_ran == []

    def test_multiple_migrations_run_in_order(self, db, monkeypatch):
        _set_schema_version(db, 1)
        order = []

        def migrate_v2(_database):
            order.append(2)

        def migrate_v3(_database):
            order.append(3)

        import surfmon.db as db_mod

        monkeypatch.setattr(db_mod, "SCHEMA_VERSION", 3)
        monkeypatch.setattr(db_mod, "_MIGRATIONS", [migrate_v2, migrate_v3])
        _ensure_schema(db)
        assert _get_schema_version(db) == 3
        assert order == [2, 3]

    def test_partial_failure_preserves_successful_migrations(self, db, monkeypatch):
        _set_schema_version(db, 1)
        ran = []

        def migrate_v2(_database):
            ran.append(2)

        def migrate_v3(_database):
            msg = "v3 boom"
            raise RuntimeError(msg)

        import surfmon.db as db_mod

        monkeypatch.setattr(db_mod, "SCHEMA_VERSION", 3)
        monkeypatch.setattr(db_mod, "_MIGRATIONS", [migrate_v2, migrate_v3])
        with pytest.raises(RuntimeError, match="v3 boom"):
            _ensure_schema(db)
        # v2 succeeded and was recorded; v3 failed
        assert _get_schema_version(db) == 2
        assert ran == [2]


class TestStoreCheck:
    def test_basic_roundtrip(self, db):
        report = _make_report()
        session_id = store_check(db, report, target="next")

        assert session_id
        session = next(db["sessions"].rows_where("id = ?", [session_id]))
        assert session["command"] == "check"
        assert session["windsurf_target"] == "next"

    def test_stores_processes(self, db):
        procs = [_make_process(pid=i, memory_mb=100.0 * i) for i in range(1, 4)]
        report = _make_report(processes=procs)
        session_id = store_check(db, report)

        rows = list(db["processes"].rows_where("session_id = ?", [session_id]))
        assert len(rows) == 3

    def test_stores_system_snapshot(self, db):
        report = _make_report()
        session_id = store_check(db, report)

        rows = list(db["system_snapshots"].rows_where("session_id = ?", [session_id]))
        assert len(rows) == 1
        assert rows[0]["total_memory_gb"] == 96.0

    def test_stores_pty_info(self, db):
        pty = _make_pty_info()
        report = _make_report(pty_info=pty)
        session_id = store_check(db, report)

        rows = list(db["pty_snapshots"].rows_where("session_id = ?", [session_id]))
        assert len(rows) == 1
        assert rows[0]["windsurf_pty_count"] == 25

    def test_stores_issues(self, db):
        report = _make_report(issues=["⚠ Memory leak detected", "Critical failure"])
        session_id = store_check(db, report)

        rows = list(db["issues"].rows_where("session_id = ?", [session_id]))
        assert len(rows) == 2

    def test_stores_version_and_uptime(self, db):
        report = _make_report(windsurf_version="1.9577.1024+next.abc", windsurf_uptime_seconds=7200.0)
        session_id = store_check(db, report)

        session = next(db["sessions"].rows_where("id = ?", [session_id]))
        assert session["windsurf_version"] == "1.9577.1024+next.abc"
        assert session["windsurf_uptime_s"] == 7200.0

    def test_no_pty_info(self, db):
        report = _make_report(pty_info=None)
        session_id = store_check(db, report)

        rows = list(db["pty_snapshots"].rows_where("session_id = ?", [session_id]))
        assert len(rows) == 0


class TestStoreLsSnapshot:
    def test_basic_roundtrip(self, db):
        snapshot = _make_ls_snapshot()
        session_id = store_ls_snapshot(db, snapshot, target="stable")

        session = next(db["sessions"].rows_where("id = ?", [session_id]))
        assert session["command"] == "ls-snapshot"
        assert session["windsurf_version"] == "1.9577.1024"

    def test_stores_entries(self, db):
        snapshot = _make_ls_snapshot()
        session_id = store_ls_snapshot(db, snapshot)

        rows = list(db["ls_entries"].rows_where("session_id = ?", [session_id]))
        assert len(rows) == 1
        assert rows[0]["language"] == "python"
        assert rows[0]["orphaned"] == 0

    def test_stores_orphaned_entries(self, db):
        entry = LsSnapshotEntry(
            pid=9999,
            name="ls",
            language="typescript",
            memory_mb=200.0,
            memory_percent=0.5,
            cpu_percent=1.0,
            num_threads=10,
            runtime_seconds=600.0,
            workspace="",
            orphaned=True,
        )
        snapshot = _make_ls_snapshot(entries=[entry])
        session_id = store_ls_snapshot(db, snapshot)

        rows = list(db["ls_entries"].rows_where("session_id = ?", [session_id]))
        assert rows[0]["orphaned"] == 1

    def test_stores_issues(self, db):
        snapshot = _make_ls_snapshot(issues=["⚠ High memory usage"])
        session_id = store_ls_snapshot(db, snapshot)

        rows = list(db["issues"].rows_where("session_id = ?", [session_id]))
        assert len(rows) == 1
        assert rows[0]["severity"] == "warning"


class TestStorePtySnapshot:
    def test_basic_roundtrip(self, db):
        pty = _make_pty_info()
        session_id = store_pty_snapshot(db, pty, target="insiders")

        session = next(db["sessions"].rows_where("id = ?", [session_id]))
        assert session["command"] == "pty-snapshot"
        assert session["windsurf_target"] == "insiders"

    def test_stores_pty_per_process(self, db):
        pty = _make_pty_info()
        session_id = store_pty_snapshot(db, pty)

        rows = list(db["pty_per_process"].rows_where("session_id = ?", [session_id]))
        assert len(rows) == 1
        assert rows[0]["pty_count"] == 20


class TestQueryHistory:
    def test_empty_db(self, db):
        assert query_history(db) == []

    def test_returns_recent_sessions(self, db):
        store_check(db, _make_report(timestamp="2025-01-01T10:00:00+00:00"))
        store_check(db, _make_report(timestamp="2025-01-01T11:00:00+00:00"))

        rows = query_history(db)
        assert len(rows) == 2
        # Most recent first
        assert rows[0][1] == "2025-01-01T11:00:00+00:00"

    def test_filter_by_command(self, db):
        store_check(db, _make_report())
        store_ls_snapshot(db, _make_ls_snapshot())

        rows = query_history(db, command="ls-snapshot")
        assert len(rows) == 1

    def test_limit(self, db):
        for i in range(5):
            store_check(db, _make_report(timestamp=f"2025-01-01T{10 + i}:00:00+00:00"))

        rows = query_history(db, limit=3)
        assert len(rows) == 3

    def test_since_filter(self, db):
        store_check(db, _make_report(timestamp="2020-01-01T00:00:00+00:00"))
        store_check(db, _make_report(timestamp=datetime.now(tz=UTC).isoformat()))

        rows = query_history(db, since="1h")
        assert len(rows) == 1


class TestQueryHistoryDicts:
    def test_returns_dicts(self, db):
        store_check(db, _make_report())
        rows = query_history_dicts(db)
        assert len(rows) == 1
        assert set(rows[0].keys()) == set(HISTORY_COLUMNS)


class TestQueryTrend:
    def test_empty_db(self, db):
        assert query_trend(db, metric="memory") == []

    def test_memory_trend(self, db):
        store_check(db, _make_report(timestamp="2025-01-01T10:00:00+00:00"))
        store_check(db, _make_report(timestamp="2025-01-01T11:00:00+00:00"))

        data = query_trend(db, metric="memory")
        assert len(data) == 2
        assert "timestamp" in data[0]
        assert "value" in data[0]

    def test_process_count_trend(self, db):
        store_check(db, _make_report(timestamp="2025-01-01T10:00:00+00:00"))
        data = query_trend(db, metric="processes")
        assert len(data) == 1

    def test_pty_trend(self, db):
        pty = _make_pty_info()
        store_pty_snapshot(db, pty)

        data = query_trend(db, metric="pty")
        assert len(data) == 1
        assert data[0]["value"] == 25

    def test_ls_memory_trend(self, db):
        store_ls_snapshot(db, _make_ls_snapshot())
        data = query_trend(db, metric="ls-memory")
        assert len(data) == 1

    def test_ls_count_trend(self, db):
        store_ls_snapshot(db, _make_ls_snapshot())
        data = query_trend(db, metric="ls-count")
        assert len(data) == 1
        assert data[0]["value"] == 1

    def test_invalid_metric(self, db):
        with pytest.raises(ValueError, match="Unknown metric"):
            query_trend(db, metric="invalid")

    def test_since_filter(self, db):
        store_check(db, _make_report(timestamp="2020-01-01T00:00:00+00:00"))
        store_check(db, _make_report(timestamp=datetime.now(tz=UTC).isoformat()))

        data = query_trend(db, metric="memory", since="1h")
        assert len(data) == 1


class TestParseSince:
    def test_hours(self):
        result = _parse_since("24h")
        assert (datetime.now(tz=UTC) - result).total_seconds() == pytest.approx(86400, abs=5)

    def test_days(self):
        result = _parse_since("7d")
        assert (datetime.now(tz=UTC) - result).total_seconds() == pytest.approx(604800, abs=5)

    def test_minutes(self):
        result = _parse_since("30m")
        assert (datetime.now(tz=UTC) - result).total_seconds() == pytest.approx(1800, abs=5)

    def test_weeks(self):
        result = _parse_since("2w")
        assert (datetime.now(tz=UTC) - result).total_seconds() == pytest.approx(1209600, abs=5)

    def test_invalid_unit(self):
        with pytest.raises(ValueError, match="Invalid duration unit"):
            _parse_since("5x")


class TestClassifyIssueSeverity:
    def test_critical(self):
        assert _classify_issue_severity("Critical failure occurred") == "critical"
        assert _classify_issue_severity("✖ Process crashed") == "critical"

    def test_warning(self):
        assert _classify_issue_severity("⚠ Memory leak detected") == "warning"
        assert _classify_issue_severity("Warning: high memory") == "warning"
        assert _classify_issue_severity("Potential memory leak") == "warning"

    def test_info(self):
        assert _classify_issue_severity("Extensions loaded") == "info"


class TestQueryAnalyzeSessions:
    def test_empty_db(self, db):
        assert query_analyze_sessions(db) == []

    def test_basic_roundtrip(self, db):
        store_check(db, _make_report(timestamp="2025-01-01T10:00:00+00:00"))
        store_check(db, _make_report(timestamp="2025-01-01T11:00:00+00:00"))

        sessions = query_analyze_sessions(db)
        assert len(sessions) == 2
        assert sessions[0]["timestamp"] < sessions[1]["timestamp"]

    def test_returns_expected_keys(self, db):
        store_check(db, _make_report())
        session = query_analyze_sessions(db)[0]
        assert {
            "session_id",
            "timestamp",
            "processes",
            "memory_mb",
            "cpu",
            "lang_servers",
            "issues",
            "system",
            "pty_info",
            "windsurf_processes",
        }.issubset(session.keys())

    def test_attaches_processes(self, db):
        procs = [
            _make_process(pid=1, name="Windsurf", memory_mb=600.0),
            _make_process(pid=2, name="Windsurf Helper", memory_mb=200.0),
        ]
        store_check(db, _make_report(processes=procs))
        session = query_analyze_sessions(db)[0]
        assert len(session["windsurf_processes"]) == 2
        assert session["windsurf_processes"][0]["memory_mb"] >= session["windsurf_processes"][1]["memory_mb"]

    def test_attaches_issues(self, db):
        store_check(db, _make_report(issues=["⚠ High memory", "⚠ Leak detected"]))
        session = query_analyze_sessions(db)[0]
        assert len(session["issues"]) == 2

    def test_ls_count_codeium(self, db):
        proc = _make_process(name="language_server_macos_arm", memory_mb=500.0)
        store_check(db, _make_report(processes=[proc]))
        session = query_analyze_sessions(db)[0]
        assert session["lang_servers"] == 1

    def test_ls_count_pyright(self, db):
        proc = _make_process(
            name="node",
            memory_mb=300.0,
        )
        proc = ProcessInfo(
            pid=proc.pid,
            name="node",
            cpu_percent=proc.cpu_percent,
            memory_mb=proc.memory_mb,
            memory_percent=proc.memory_percent,
            num_threads=proc.num_threads,
            runtime_seconds=proc.runtime_seconds,
            cmdline="node /path/to/pyright-langserver --stdio",
        )
        store_check(db, _make_report(processes=[proc]))
        session = query_analyze_sessions(db)[0]
        assert session["lang_servers"] == 1

    def test_ls_count_non_ls_process(self, db):
        proc = ProcessInfo(
            pid=99,
            name="Windsurf",
            cpu_percent=5.0,
            memory_mb=800.0,
            memory_percent=2.0,
            num_threads=20,
            runtime_seconds=3600.0,
            cmdline="/Applications/Windsurf.app/Contents/MacOS/Windsurf",
        )
        store_check(db, _make_report(processes=[proc]))
        session = query_analyze_sessions(db)[0]
        assert session["lang_servers"] == 0

    def test_session_without_pty_info(self, db):
        store_check(db, _make_report(pty_info=None))
        session = query_analyze_sessions(db)[0]
        assert session["pty_info"] is None

    def test_session_with_pty_info(self, db):
        store_check(db, _make_report(pty_info=_make_pty_info()))
        session = query_analyze_sessions(db)[0]
        assert session["pty_info"] is not None
        assert session["pty_info"]["windsurf_pty_count"] == 25

    def test_since_filter_excludes_old_sessions(self, db):
        store_check(db, _make_report(timestamp="2020-01-01T00:00:00+00:00"))
        store_check(db, _make_report(timestamp=datetime.now(tz=UTC).isoformat()))
        sessions = query_analyze_sessions(db, since="1h")
        assert len(sessions) == 1

    def test_ignores_non_check_commands(self, db):
        store_check(db, _make_report())
        store_ls_snapshot(db, _make_ls_snapshot())
        sessions = query_analyze_sessions(db)
        assert len(sessions) == 1

    def test_system_info_populated(self, db):
        store_check(db, _make_report())
        session = query_analyze_sessions(db)[0]
        assert session["system"]["total_memory_gb"] == 96.0
        assert session["system"]["available_memory_gb"] == 48.0

    def test_session_with_no_processes(self, db):
        report = _make_report(processes=[])
        store_check(db, report)
        session = query_analyze_sessions(db)[0]
        assert session["processes"] == 0
        assert session["memory_mb"] == 0.0
        assert session["windsurf_processes"] == []
