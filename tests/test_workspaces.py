"""Tests for workspace detection and management."""

from pathlib import Path
from unittest.mock import Mock

from surfmon.workspaces import (
    _extract_workspace_from_cmdline,
    _parse_workspace_event,
    _resolve_workspace_path,
    count_windsurf_launches_today,
    get_active_workspaces,
)

_P_RESOLVE_WS = "surfmon.workspaces._resolve_workspace_path"
_P_GET_PATHS = "surfmon.workspaces.get_paths"
_TEST_WS_PATH = "/Users/test/my-project"
_APP_SUPPORT = "Application Support"
_MAIN_LOG = "main.log"
_LOG_TS_1 = "20260204T123456"
_LOG_TS_2 = "20260314T120000"
_DEV_HOME = "/Users/dev"
_DEV_REPOS = "/Users/dev/repos"
_COPIER_UV = "/Users/dev/repos/copier-uv-bleeding"
_FS_BASE = ["/", "/Users", _DEV_HOME, _DEV_REPOS]


def _patch_fs(monkeypatch, dirs, files=()):
    """Patch Path.is_dir and Path.exists for deterministic resolver tests."""
    dir_set = {str(Path(d)) for d in dirs}
    file_set = {str(Path(f)) for f in files}

    monkeypatch.setattr(Path, "is_dir", lambda self: str(self) in dir_set)
    monkeypatch.setattr(Path, "exists", lambda self: str(self) in dir_set or str(self) in file_set)


LOAD_LINE = (
    "2026-03-13 08:20:06.089 [info] WindsurfWindowsMainManager: Window will load "
    '{"windowId":1,"workspaceUri":{"id":"abc123","uri":{"$mid":1,'
    '"fsPath":"/Users/test/my-project","external":"file:///Users/test/my-project",'
    '"path":"/Users/test/my-project","scheme":"file"}}}'
)

CLOSE_LINE = (
    "2026-03-13 15:16:50.366 [info] WindsurfWindowsMainManager: Window will close "
    '{"windowId":1,"workspaceUri":{"id":"abc123","uri":{"$mid":1,'
    '"fsPath":"/Users/test/my-project","external":"file:///Users/test/my-project",'
    '"path":"/Users/test/my-project","scheme":"file"}}}'
)


class TestGetActiveWorkspaces:
    """Tests for get_active_workspaces."""

    def test_returns_empty_if_logs_missing(self, tmp_path, monkeypatch):
        """Should return empty list if logs directory doesn't exist."""
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        result = get_active_workspaces()

        assert result == []

    def test_parses_workspace_from_main_log(self, tmp_path, monkeypatch):
        """Should parse workspace load events from main.log."""
        log_dir = tmp_path / "Library" / _APP_SUPPORT / "Windsurf" / "logs" / _LOG_TS_1
        log_dir.mkdir(parents=True)

        # Create the workspace file
        workspace_file = tmp_path / "workspace.code-workspace"
        workspace_file.touch()
        workspace_path = str(workspace_file)

        main_log = log_dir / _MAIN_LOG
        log_content = (
            f"2026-02-04 12:34:56.789 [info] WindsurfWindowsMainManager: "
            f'Window will load {{"windowId":1,"workspaceUri":{{"id":"abc123",'
            f'"configPath":{{"fsPath":"{workspace_path}"}}}}}}'
        )
        main_log.write_text(log_content, encoding="utf-8")

        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        result = get_active_workspaces()

        assert len(result) == 1
        assert result[0].id == "abc123"
        assert "workspace.code-workspace" in result[0].path
        assert result[0].exists is True
        assert result[0].loaded_at == "2026-02-04 12:34:56.789"

    def test_detects_non_existent_workspace(self, tmp_path, monkeypatch):
        """Should detect when workspace path doesn't exist."""
        log_dir = tmp_path / "Library" / _APP_SUPPORT / "Windsurf" / "logs" / _LOG_TS_1
        log_dir.mkdir(parents=True)
        main_log = log_dir / _MAIN_LOG
        log_content = (
            "2026-02-04 12:34:56.789 [info] WindsurfWindowsMainManager: "
            'Window will load {"windowId":1,"workspaceUri":{"id":"xyz789",'
            '"configPath":{"fsPath":"/Users/test/nonexistent.code-workspace"}}}'
        )
        main_log.write_text(log_content, encoding="utf-8")

        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        result = get_active_workspaces()

        assert len(result) == 1
        assert result[0].exists is False


class TestCountWindsurfLaunchesToday:
    """Tests for count_windsurf_launches_today."""

    def test_returns_zero_if_logs_missing(self, tmp_path, monkeypatch):
        """Should return 0 if logs directory doesn't exist."""
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        result = count_windsurf_launches_today()

        assert result == 0

    def test_counts_todays_launches(self, tmp_path, monkeypatch):
        """Should count only log directories from today."""
        from datetime import UTC, datetime, timedelta

        log_base = tmp_path / "Library" / _APP_SUPPORT / "Windsurf" / "logs"
        log_base.mkdir(parents=True)

        # Create log directories for today (UTC, matching production code)
        today_str = datetime.now(tz=UTC).strftime("%Y%m%d")
        (log_base / f"{today_str}T120000").mkdir()
        (log_base / f"{today_str}T130000").mkdir()
        (log_base / f"{today_str}T140000").mkdir()

        # Create a log directory from yesterday
        yesterday = datetime.now(tz=UTC) - timedelta(days=1)
        yesterday_str = yesterday.strftime("%Y%m%d")
        (log_base / f"{yesterday_str}T120000").mkdir()

        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        result = count_windsurf_launches_today()

        assert result == 3


class TestWorkspaceParsingEdgeCases:
    """Tests for _parse_workspace_event edge cases."""

    def test_returns_none_for_unrelated_line(self):
        """Should return None for lines without workspace info."""
        result = _parse_workspace_event("some random log line")

        assert result is None

    def test_returns_none_for_incomplete_match(self):
        """Should return None when id or path can't be extracted."""
        line = 'Window will load {"workspaceUri": {"incomplete": true}}'
        result = _parse_workspace_event(line)

        assert result is None

    def test_empty_log_dirs(self, tmp_path, monkeypatch):
        """Should return empty list when log dir exists but has no subdirs."""
        log_base = tmp_path / "Library" / _APP_SUPPORT / "Windsurf" / "logs"
        log_base.mkdir(parents=True)

        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        result = get_active_workspaces()

        assert result == []

    def test_no_main_log(self, tmp_path, monkeypatch):
        """Should return empty list when log subdir exists but has no main.log."""
        log_dir = tmp_path / "Library" / _APP_SUPPORT / "Windsurf" / "logs" / _LOG_TS_1
        log_dir.mkdir(parents=True)

        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        result = get_active_workspaces()

        assert result == []


class TestLaunchCountOSError:
    """Tests for launch count OSError handling."""

    def test_handles_os_error_reading_logs(self, tmp_path, monkeypatch, mocker):
        """Should return 0 when logs directory can't be read."""
        log_base = tmp_path / "Library" / _APP_SUPPORT / "Windsurf" / "logs"
        log_base.mkdir(parents=True)

        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        mocker.patch.object(Path, "iterdir", side_effect=OSError("Permission denied"))

        result = count_windsurf_launches_today()

        assert result == 0


class TestLaunchCountEdgeCases:
    """Tests for launch counting edge cases."""

    def test_skips_non_directory_entries(self, tmp_path, monkeypatch):
        """Should skip non-directory entries in logs folder."""
        from datetime import UTC, datetime

        log_base = tmp_path / "Library" / _APP_SUPPORT / "Windsurf" / "logs"
        log_base.mkdir(parents=True)

        today_str = datetime.now(tz=UTC).strftime("%Y%m%d")
        (log_base / f"{today_str}T120000").mkdir()
        # Create a file (not directory) - should be skipped
        (log_base / f"{today_str}T130000.log").touch()

        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        result = count_windsurf_launches_today()

        assert result == 1

    def test_skips_malformed_directory_names(self, tmp_path, monkeypatch):
        """Should skip directories with malformed names."""
        from datetime import UTC, datetime

        log_base = tmp_path / "Library" / _APP_SUPPORT / "Windsurf" / "logs"
        log_base.mkdir(parents=True)

        today_str = datetime.now(tz=UTC).strftime("%Y%m%d")
        (log_base / f"{today_str}T120000").mkdir()
        # Create directories with malformed names
        (log_base / "invalid-name").mkdir()
        (log_base / "20260204").mkdir()  # Missing T separator

        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        result = count_windsurf_launches_today()

        assert result == 1


class TestResolveWorkspacePath:
    """Tests for Codeium workspace_id resolution (ISM-333)."""

    def test_simple_path_no_hyphens(self, monkeypatch):
        """All-slash decode works when path has no hyphens or dots."""
        _patch_fs(monkeypatch, [*_FS_BASE, f"{_DEV_REPOS}/myproject"])
        assert _resolve_workspace_path("file_Users_dev_repos_myproject") == Path("/Users/dev/repos/myproject")

    def test_hyphenated_directory(self, monkeypatch):
        """Hyphens in directory names are correctly resolved."""
        _patch_fs(monkeypatch, [*_FS_BASE, _COPIER_UV])
        assert _resolve_workspace_path("file_Users_dev_repos_copier_uv_bleeding") == Path("/Users/dev/repos/copier-uv-bleeding")

    def test_dotted_file(self, monkeypatch):
        """Dots in filenames are correctly resolved."""
        _patch_fs(
            monkeypatch,
            _FS_BASE,
            files=[f"{_DEV_REPOS}/project.code-workspace"],
        )
        assert _resolve_workspace_path("file_Users_dev_repos_project_code_workspace") == Path("/Users/dev/repos/project.code-workspace")

    def test_ambiguous_with_real_subdir(self, monkeypatch):
        """Correct resolution when a prefix also exists as a directory."""
        _patch_fs(
            monkeypatch,
            [*_FS_BASE, f"{_DEV_REPOS}/copier", _COPIER_UV],
        )
        assert _resolve_workspace_path("file_Users_dev_repos_copier_uv_bleeding") == Path("/Users/dev/repos/copier-uv-bleeding")

    def test_truly_orphaned_returns_none(self, monkeypatch):
        """Returns None for workspace_ids that don't resolve to any real path."""
        _patch_fs(monkeypatch, _FS_BASE)
        assert _resolve_workspace_path("file_Users_dev_repos_nonexistent_path") is None

    def test_mixed_dot_and_hyphen(self, monkeypatch):
        """Handles names with both dots and hyphens."""
        _patch_fs(monkeypatch, [*_FS_BASE, f"{_DEV_REPOS}/my-app.v2"])
        assert _resolve_workspace_path("file_Users_dev_repos_my_app_v2") == Path("/Users/dev/repos/my-app.v2")

    def test_code_workspace_with_real_parent_dir(self, monkeypatch):
        """surfmon.code-workspace resolves even though surfmon/ is a real dir."""
        _patch_fs(
            monkeypatch,
            [*_FS_BASE, f"{_DEV_REPOS}/surfmon"],
            files=[f"{_DEV_REPOS}/surfmon.code-workspace"],
        )
        assert _resolve_workspace_path("file_Users_dev_repos_surfmon_code_workspace") == Path("/Users/dev/repos/surfmon.code-workspace")


class TestExtractWorkspaceFromCmdline:
    """Tests for _extract_workspace_from_cmdline helper."""

    def test_extracts_workspace_id(self, monkeypatch):
        """Should extract workspace path from --workspace_id."""
        _patch_fs(monkeypatch, ["/", "/Users", "/Users/ismar", "/Users/ismar/repos", "/Users/ismar/repos/surfmon"])
        cmdline = "language_server_macos_arm --workspace_id file_Users_ismar_repos_surfmon"
        result = _extract_workspace_from_cmdline(cmdline)
        assert result == "ismar/repos/surfmon"

    def test_extracts_jdt_data_dir(self):
        """Should extract project name from -data flag."""
        cmdline = "jdtls -data /home/user/.cache/jdt/myproject"
        result = _extract_workspace_from_cmdline(cmdline)
        assert result == "myproject"

    def test_returns_empty_for_unknown(self):
        """Should return empty string when no workspace can be extracted."""
        assert not _extract_workspace_from_cmdline("gopls serve")

    def test_resolved_hyphenated_path(self, monkeypatch):
        _patch_fs(monkeypatch, [*_FS_BASE, _COPIER_UV])
        cmdline = "ls --workspace_id file_Users_dev_repos_copier_uv_bleeding --x"
        result = _extract_workspace_from_cmdline(cmdline)
        assert "copier-uv-bleeding" in result

    def test_fallback_for_unresolvable(self, monkeypatch):
        _patch_fs(monkeypatch, ["/"])
        cmdline = "ls --workspace_id file_no_such_fake_workspace --x"
        result = _extract_workspace_from_cmdline(cmdline)
        assert result == "such/fake/workspace"


class TestParseWorkspaceEvent:
    """Tests for _parse_workspace_event."""

    def test_parse_load_event(self):
        result = _parse_workspace_event(LOAD_LINE)
        assert result is not None
        event_type, ws = result
        assert event_type == "load"
        assert ws.id == "abc123"
        assert ws.path == _TEST_WS_PATH

    def test_parse_close_event(self):
        result = _parse_workspace_event(CLOSE_LINE)
        assert result is not None
        event_type, ws = result
        assert event_type == "close"
        assert ws.id == "abc123"
        assert ws.path == _TEST_WS_PATH

    def test_returns_none_for_unrelated_line(self):
        assert _parse_workspace_event("[info] Something else happened") is None

    def test_returns_none_without_workspace_uri(self):
        line = '2026-03-13 08:20:06 [info] WindsurfWindowsMainManager: Window will load {"windowId":1}'
        assert _parse_workspace_event(line) is None

    def test_returns_none_for_other_workspace_event(self):
        line = (
            "2026-03-13 08:20:06 [info] WindsurfWindowsMainManager: Window will focus "
            '{"windowId":1,"workspaceUri":{"id":"abc","uri":{"fsPath":"/tmp/x"}}}'
        )
        assert _parse_workspace_event(line) is None

    def test_extracts_loaded_at_timestamp(self):
        result = _parse_workspace_event(LOAD_LINE)
        assert result is not None
        _, ws = result
        assert ws.loaded_at == "2026-03-13 08:20:06.089"


class TestGetActiveWorkspacesCloseEvents:
    """Tests for get_active_workspaces close event handling."""

    def test_close_removes_workspace_from_active_set(self, tmp_path, mocker):
        """A workspace that is loaded then closed should not appear in results."""
        log_dir = tmp_path / _LOG_TS_2
        log_dir.mkdir()
        main_log = log_dir / _MAIN_LOG
        main_log.write_text(f"{LOAD_LINE}\n{CLOSE_LINE}\n", encoding="utf-8")

        paths_mock = Mock()
        paths_mock.logs_dir = tmp_path
        mocker.patch(_P_GET_PATHS, return_value=paths_mock)

        result = get_active_workspaces()
        assert len(result) == 0

    def test_load_after_close_re_adds_workspace(self, tmp_path, mocker):
        """A workspace closed then re-loaded should appear in results."""
        log_dir = tmp_path / _LOG_TS_2
        log_dir.mkdir()
        main_log = log_dir / _MAIN_LOG
        main_log.write_text(f"{LOAD_LINE}\n{CLOSE_LINE}\n{LOAD_LINE}\n", encoding="utf-8")

        paths_mock = Mock()
        paths_mock.logs_dir = tmp_path
        mocker.patch(_P_GET_PATHS, return_value=paths_mock)

        result = get_active_workspaces()
        assert len(result) == 1
        assert result[0].id == "abc123"

    def test_only_closed_workspace_removed(self, tmp_path, mocker):
        """Other workspaces should survive when one is closed."""
        other_load = (
            "2026-03-13 08:20:06.089 [info] WindsurfWindowsMainManager: Window will load "
            '{"windowId":2,"workspaceUri":{"id":"other456","uri":{"$mid":1,'
            '"fsPath":"/Users/test/other-project","external":"file:///Users/test/other-project",'
            '"path":"/Users/test/other-project","scheme":"file"}}}'
        )
        log_dir = tmp_path / _LOG_TS_2
        log_dir.mkdir()
        main_log = log_dir / _MAIN_LOG
        main_log.write_text(f"{LOAD_LINE}\n{other_load}\n{CLOSE_LINE}\n", encoding="utf-8")

        paths_mock = Mock()
        paths_mock.logs_dir = tmp_path
        mocker.patch(_P_GET_PATHS, return_value=paths_mock)

        result = get_active_workspaces()
        assert len(result) == 1
        assert result[0].id == "other456"
