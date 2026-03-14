"""Tests for core monitoring functionality."""

import json
from pathlib import Path
from unittest.mock import Mock

import psutil
import pytest

from surfmon.config import WindsurfTarget, reset_target, set_target
from surfmon.monitor import (
    EXIT_CRITICAL,
    EXIT_OK,
    EXIT_WARNING,
    ProcessInfo,
    PtyFdEntry,
    PtyInfo,
    SystemInfo,
    _classify_pty_issues,
    _extract_windsurf_version,
    _extract_workspace_from_cmdline,
    _get_system_pty_limit,
    _get_windsurf_uptime,
    _group_entries_by_pid,
    _is_orphaned_workspace,
    _is_stale_workspace,
    _parse_lsof_line,
    _parse_workspace_event,
    _resolve_workspace_path,
    check_log_issues,
    check_pty_leak,
    count_extensions,
    count_windsurf_launches_today,
    find_language_servers,
    generate_report,
    get_active_workspaces,
    get_mcp_config,
    get_process_info,
    get_system_info,
    get_windsurf_processes,
    max_issue_severity,
    save_report_json,
)


@pytest.fixture(autouse=True)
def reset_config_target():
    """Reset config target to STABLE before each test to ensure consistent behavior."""
    set_target(WindsurfTarget.STABLE)
    yield
    reset_target()


@pytest.fixture
def mock_process():
    """Create a mock psutil.Process."""
    proc = Mock(spec=psutil.Process)
    proc.pid = 1234
    proc.name.return_value = "Windsurf Helper"
    proc.cmdline.return_value = ["/path/to/windsurf", "--arg"]
    proc.cpu_percent.return_value = 5.0
    proc.memory_info.return_value = Mock(rss=100 * 1024 * 1024)  # 100 MB
    proc.memory_percent.return_value = 1.5
    proc.num_threads.return_value = 10
    proc.create_time.return_value = 1000.0
    # Make oneshot() a context manager
    proc.oneshot.return_value.__enter__ = Mock(return_value=proc)
    proc.oneshot.return_value.__exit__ = Mock(return_value=False)
    return proc


@pytest.fixture
def mock_system_info():
    """Create mock system info."""
    mem = Mock()
    mem.total = 32 * 1024 * 1024 * 1024  # 32 GB
    mem.available = 16 * 1024 * 1024 * 1024  # 16 GB
    mem.percent = 50.0

    swap = Mock()
    swap.total = 4 * 1024 * 1024 * 1024  # 4 GB
    swap.used = 1 * 1024 * 1024 * 1024  # 1 GB

    return mem, swap


class TestGetWindsurfProcesses:
    """Tests for get_windsurf_processes."""

    def test_finds_windsurf_processes(self, mocker):
        """Should find processes from Windsurf.app and exclude monitoring tool."""
        mock_proc_iter = mocker.patch("surfmon.monitor.psutil.process_iter")
        mocker.patch("surfmon.monitor.os.getpid", return_value=3)
        # Setup mocks
        proc1 = Mock()
        proc1.info = {
            "pid": 1,
            "name": "Windsurf",
            "cmdline": ["/Applications/Windsurf.app/Contents/MacOS/Windsurf"],
            "exe": "/Applications/Windsurf.app/Contents/MacOS/Windsurf",
        }
        proc1.name.return_value = "Windsurf"
        proc1.pid = 1

        proc2 = Mock()
        proc2.info = {
            "pid": 2,
            "name": "Windsurf Helper",
            "cmdline": ["/Applications/Windsurf.app/Contents/Frameworks/Electron Framework.framework/Windsurf Helper"],
            "exe": "/Applications/Windsurf.app/Contents/Frameworks/Electron Framework.framework/Windsurf Helper",
        }
        proc2.name.return_value = "Windsurf Helper"
        proc2.pid = 2

        # This should be excluded (monitoring tool — same PID as os.getpid())
        proc3 = Mock()
        proc3.info = {
            "pid": 3,
            "name": "python3",
            "cmdline": ["python", "-m", "surfmon", "check"],
            "exe": "/usr/bin/python3",
        }
        proc3.name.return_value = "python3"
        proc3.pid = 3

        # This should be excluded (unrelated)
        proc4 = Mock()
        proc4.info = {
            "pid": 4,
            "name": "chrome",
            "cmdline": ["/path/to/chrome"],
            "exe": "/path/to/chrome",
        }
        proc4.name.return_value = "chrome"
        proc4.pid = 4

        mock_proc_iter.return_value = [proc1, proc2, proc3, proc4]

        # Execute
        result = get_windsurf_processes()

        # Assert
        assert len(result) == 2
        assert proc1 in result
        assert proc2 in result
        assert proc3 not in result
        assert proc4 not in result

    def test_does_not_exclude_ls_with_surfmon_in_workspace(self, mocker):
        """Codeium LS indexing a workspace named 'surfmon' must not be excluded.

        Regression test: the old self-exclusion filter checked for 'surfmon' in
        the cmdline string, which falsely excluded any LS whose --workspace_id
        contained the word 'surfmon'.
        """
        mock_proc_iter = mocker.patch("surfmon.monitor.psutil.process_iter")
        mocker.patch("surfmon.monitor.os.getpid", return_value=99999)

        proc_ls = Mock()
        proc_ls.info = {
            "pid": 100,
            "name": "language_server_macos_arm",
            "cmdline": [
                "/Applications/Windsurf.app/Contents/Resources/app/extensions/windsurf/bin/language_server_macos_arm",
                "--workspace_id",
                "file_Users_ismar_repos_surfmon_code_workspace",
            ],
            "exe": "/Applications/Windsurf.app/Contents/Resources/app/extensions/windsurf/bin/language_server_macos_arm",
        }
        proc_ls.name.return_value = "language_server_macos_arm"
        proc_ls.pid = 100

        mock_proc_iter.return_value = [proc_ls]

        result = get_windsurf_processes()

        assert len(result) == 1
        assert proc_ls in result

    def test_handles_access_denied(self, mocker):
        """Should handle AccessDenied exceptions."""
        mock_proc_iter = mocker.patch("surfmon.monitor.psutil.process_iter")
        proc1 = Mock()
        proc1.info = {
            "pid": 1,
            "name": "Windsurf",
            "cmdline": ["/Applications/Windsurf.app/Contents/MacOS/Windsurf"],
            "exe": "/Applications/Windsurf.app/Contents/MacOS/Windsurf",
        }
        proc1.name.return_value = "Windsurf"

        proc2 = Mock()
        # Use __getitem__ to make info subscriptable and raise exception
        proc2.info.__getitem__ = Mock(side_effect=psutil.AccessDenied())

        mock_proc_iter.return_value = [proc1, proc2]

        result = get_windsurf_processes()
        assert len(result) == 1

    def test_handles_no_such_process(self, mocker):
        """Should handle NoSuchProcess exceptions."""
        mock_proc_iter = mocker.patch("surfmon.monitor.psutil.process_iter")
        proc1 = Mock()
        proc1.info = {
            "pid": 1,
            "name": "Windsurf",
            "cmdline": ["/Applications/Windsurf.app/Contents/MacOS/Windsurf"],
            "exe": "/Applications/Windsurf.app/Contents/MacOS/Windsurf",
        }
        proc1.name.return_value = "Windsurf"

        proc2 = Mock()
        # Use __getitem__ to make info subscriptable and raise exception
        proc2.info.__getitem__ = Mock(side_effect=psutil.NoSuchProcess(pid=2))

        mock_proc_iter.return_value = [proc1, proc2]

        result = get_windsurf_processes()
        assert len(result) == 1

    def test_filters_orphaned_crashpad_handlers(self, mocker):
        """Should filter out orphaned crashpad handlers when main Windsurf process is not running."""
        mock_proc_iter = mocker.patch("surfmon.monitor.psutil.process_iter")
        # Only crashpad handlers, no main Windsurf process
        proc1 = Mock()
        crashpad_exe = (
            "/Applications/Windsurf.app/Contents/Frameworks/Windsurf Helper (Crashpad).app/Contents/MacOS/Windsurf Helper (Crashpad)"
        )
        proc1.info = {
            "pid": 1,
            "name": "Windsurf Helper (Crashpad)",
            "cmdline": ["--crashpad-handler"],
            "exe": crashpad_exe,
        }
        proc1.name.return_value = "Windsurf Helper (Crashpad)"

        proc2 = Mock()
        proc2.info = {
            "pid": 2,
            "name": "crashpad_handler",
            "cmdline": [],
            "exe": "/Applications/Windsurf.app/Contents/Frameworks/crashpad_handler",
        }
        proc2.name.return_value = "crashpad_handler"

        mock_proc_iter.return_value = [proc1, proc2]

        result = get_windsurf_processes()

        # Crashpad handlers should be filtered out when no main Windsurf process
        assert len(result) == 0


class TestGetProcessInfo:
    """Tests for get_process_info."""

    def test_extracts_process_info(self, mock_process, mocker):
        """Should extract all process information correctly."""
        mock_datetime = mocker.patch("surfmon.monitor.datetime")
        mock_datetime.now.return_value.timestamp.return_value = 2000.0

        result = get_process_info(mock_process, initial_cpu=5.0)

        assert result is not None
        assert result.pid == 1234
        assert result.name == "Windsurf Helper"
        assert result.cpu_percent == 5.0
        assert result.memory_mb == 100.0
        assert result.runtime_seconds == 1000.0
        assert result.num_threads == 10

    def test_handles_long_cmdline(self, mock_process):
        """Should preserve full cmdline for language server detection."""
        mock_process.cmdline.return_value = ["a" * 250]

        result = get_process_info(mock_process)

        assert result is not None
        # Cmdline is no longer truncated - needed for language server detection
        assert len(result.cmdline) == 250

    def test_handles_access_denied(self, mock_process):
        """Should return None on AccessDenied."""
        mock_process.oneshot.side_effect = psutil.AccessDenied()

        result = get_process_info(mock_process)

        assert result is None

    def test_handles_no_such_process(self, mock_process):
        """Should return None on NoSuchProcess."""
        mock_process.oneshot.side_effect = psutil.NoSuchProcess(pid=1234)

        result = get_process_info(mock_process)

        assert result is None


class TestGetSystemInfo:
    """Tests for get_system_info."""

    def test_gets_system_info(self, mock_system_info, mocker):
        """Should get correct system information."""
        mock_vmem = mocker.patch("surfmon.monitor.psutil.virtual_memory")
        mock_swap = mocker.patch("surfmon.monitor.psutil.swap_memory")
        mock_cpu = mocker.patch("surfmon.monitor.psutil.cpu_count")

        mem, swap = mock_system_info
        mock_vmem.return_value = mem
        mock_swap.return_value = swap
        mock_cpu.return_value = 10

        result = get_system_info()

        assert result.total_memory_gb == 32.0
        assert result.available_memory_gb == 16.0
        assert result.memory_percent == 50.0
        assert result.cpu_count == 10
        assert result.swap_total_gb == 4.0
        assert result.swap_used_gb == 1.0


class TestFindLanguageServers:
    """Tests for find_language_servers."""

    def test_identifies_language_servers(self):
        """Should identify language server processes and enhance cmdline."""
        procs = [
            ProcessInfo(
                1,
                "language_server_macos_arm",
                0,
                100,
                0,
                10,
                100,
                "language_server_macos_arm --workspace_id file_Users_test_project",
            ),
            ProcessInfo(2, "java", 0, 200, 0, 20, 200, "eclipse.jdtls -data /path/to/project"),
            ProcessInfo(3, "python", 0, 50, 0, 5, 50, "basedpyright-langserver"),
            ProcessInfo(4, "Electron", 0, 500, 0, 30, 300, "windsurf main"),
        ]

        result = find_language_servers(procs)

        assert len(result) == 3
        # Check that language servers were identified
        assert any("language_server" in p.name for p in result)
        # Check that jdtls was enhanced with Java info
        assert any("Java" in p.cmdline for p in result)
        # Check that pyright was enhanced to Python Language Server
        assert any("Python" in p.cmdline for p in result)


class TestGetMCPConfig:
    """Tests for get_mcp_config."""

    def test_returns_empty_if_file_missing(self, tmp_path, monkeypatch):
        """Should return empty list if config file doesn't exist."""
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        result = get_mcp_config()

        assert result == []

    def test_parses_mcp_config(self, tmp_path, monkeypatch):
        """Should parse MCP config and return enabled servers."""
        config_dir = tmp_path / ".codeium" / "windsurf"
        config_dir.mkdir(parents=True)
        config_file = config_dir / "mcp_config.json"

        config = {
            "mcpServers": {
                "server1": {"disabled": False},
                "server2": {"disabled": True},
                "server3": {},  # No disabled key = enabled
            }
        }

        config_file.write_text(json.dumps(config), encoding="utf-8")
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        result = get_mcp_config()

        assert len(result) == 2
        assert "server1" in result
        assert "server3" in result
        assert "server2" not in result

    def test_handles_malformed_json(self, tmp_path, monkeypatch):
        """Should return empty list on JSON decode error."""
        config_dir = tmp_path / ".codeium" / "windsurf"
        config_dir.mkdir(parents=True)
        config_file = config_dir / "mcp_config.json"
        config_file.write_text("{invalid json", encoding="utf-8")

        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        result = get_mcp_config()

        assert result == []


class TestCountExtensions:
    """Tests for count_extensions."""

    def test_counts_extensions(self, tmp_path, monkeypatch):
        """Should count extension directories with version numbers."""
        ext_dir = tmp_path / ".windsurf" / "extensions"
        ext_dir.mkdir(parents=True)

        # Create extension-like directories
        (ext_dir / "ext1-1.0.0").mkdir()
        (ext_dir / "ext2-2.5.1").mkdir()
        (ext_dir / "logs").mkdir()  # Should be ignored
        (ext_dir / "no-version").mkdir()  # Should be ignored

        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        result = count_extensions()

        assert result == 2

    def test_returns_zero_if_dir_missing(self, tmp_path, monkeypatch):
        """Should return 0 if extensions directory doesn't exist."""
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        result = count_extensions()

        assert result == 0


class TestCheckLogIssues:
    """Tests for check_log_issues."""

    def test_detects_orphaned_crashpad_with_age_formatting(self, tmp_path, monkeypatch, mocker):
        """Should detect orphaned crashpad handlers with age formatting."""
        mock_proc_iter = mocker.patch("surfmon.monitor.psutil.process_iter")

        import time

        proc = Mock()
        proc.info = {
            "pid": 1,
            "name": "crashpad_handler",
            "cmdline": [],
            "exe": "/Applications/Windsurf.app/crashpad",
            "create_time": time.time() - 3600,  # 1 hour ago
        }
        proc.name.return_value = "crashpad_handler"
        mock_proc_iter.return_value = [proc]

        monkeypatch.setenv("HOME", str(tmp_path))
        (tmp_path / ".windsurf").mkdir()

        result = check_log_issues()

        # Should detect orphaned crashpad
        assert any("crashpad" in issue.lower() or "orphan" in issue.lower() for issue in result)

    def test_detects_logs_directory_issue(self, tmp_path, monkeypatch):
        """Should detect logs directory in extensions folder."""
        logs_dir = tmp_path / ".windsurf" / "extensions" / "logs"
        logs_dir.mkdir(parents=True)

        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        result = check_log_issues()

        assert len(result) > 0
        assert any("logs" in issue.lower() for issue in result)

    def test_identifies_logs_directory_culprit(self, tmp_path, monkeypatch):
        """Should identify which extension created the logs directory."""
        logs_dir = tmp_path / ".windsurf" / "extensions" / "logs"
        logs_dir.mkdir(parents=True)
        (logs_dir / "marimo.log").write_text("some log content", encoding="utf-8")

        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        result = check_log_issues()

        assert any("marimo" in issue.lower() for issue in result)

    def test_detects_extension_host_crashes(self, tmp_path, monkeypatch):
        """Should detect extension host crashes (non-zero exit codes) in main.log."""
        log_dir = tmp_path / "Library" / "Application Support" / "Windsurf" / "logs" / "20260204"
        log_dir.mkdir(parents=True)
        main_log = log_dir / "main.log"
        # Only crashes (non-zero exit codes) should be detected
        main_log.write_text(
            "Extension host with pid 1234 exited with code: 1, signal: unknown.\n"
            "Extension host with pid 5678 exited with code: 0, signal: unknown.\n"
            "Extension host with pid 9999 exited with code: 137, signal: unknown.\n",
            encoding="utf-8",
        )

        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        result = check_log_issues()

        # Should detect 2 crashes (PIDs 1234 and 9999, excluding 5678 which exited cleanly)
        assert any("extension host crash" in issue.lower() for issue in result)
        assert any("1234" in issue for issue in result)
        assert any("9999" in issue for issue in result)

    def test_detects_update_service_errors(self, tmp_path, monkeypatch):
        """Should detect UpdateService errors."""
        log_dir = tmp_path / "Library" / "Application Support" / "Windsurf" / "logs" / "20260204"
        log_dir.mkdir(parents=True)
        main_log = log_dir / "main.log"
        main_log.write_text("UpdateService error: timeout", encoding="utf-8")

        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        result = check_log_issues()

        assert any("update" in issue.lower() for issue in result)

    def test_detects_oom_errors(self, tmp_path, monkeypatch):
        """Should detect out of memory errors."""
        log_dir = tmp_path / "Library" / "Application Support" / "Windsurf" / "logs" / "20260204"
        log_dir.mkdir(parents=True)
        main_log = log_dir / "main.log"
        main_log.write_text("Fatal error: out of memory", encoding="utf-8")

        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        result = check_log_issues()

        assert any("memory" in issue.lower() for issue in result)

    def test_detects_renderer_crashes(self, tmp_path, monkeypatch):
        """Should detect GPU/renderer crashes."""
        log_dir = tmp_path / "Library" / "Application Support" / "Windsurf" / "logs" / "20260204"
        log_dir.mkdir(parents=True)
        main_log = log_dir / "main.log"
        main_log.write_text("GPU process crashed\nGPU process crashed\nGPU process crashed", encoding="utf-8")

        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        result = check_log_issues()

        assert any("gpu" in issue.lower() or "renderer" in issue.lower() for issue in result)

    def test_detects_extension_errors(self, tmp_path, monkeypatch):
        """Should detect extension errors in shared process log."""
        log_dir = tmp_path / "Library" / "Application Support" / "Windsurf" / "logs" / "20260204"
        log_dir.mkdir(parents=True)
        sharedprocess_log = log_dir / "sharedprocess.log"
        # Create many errors (more than threshold of 10)
        errors = "\n".join(["[ERROR] Extension error occurred" for _ in range(15)])
        sharedprocess_log.write_text(errors, encoding="utf-8")

        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        result = check_log_issues()

        assert any("extension error" in issue.lower() for issue in result)

    def test_detects_specific_extension_errors(self, tmp_path, monkeypatch):
        """Should identify specific extensions causing errors."""
        log_dir = tmp_path / "Library" / "Application Support" / "Windsurf" / "logs" / "20260204"
        log_dir.mkdir(parents=True)
        sharedprocess_log = log_dir / "sharedprocess.log"
        # Create errors with specific extension IDs
        errors = (
            "[ERROR] ms-python.python: some error\n"
            "[ERROR] ms-python.python: another error\n"
            "[ERROR] ms-python.python: third error\n"
            "[ERROR] vscodevim.vim: different error\n"
        )
        sharedprocess_log.write_text(errors, encoding="utf-8")

        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        result = check_log_issues()

        # Should report specific extension with error count
        issues_str = " ".join(result)
        assert "ms-python.python" in issues_str.lower()
        assert "3" in issues_str  # 3 errors for ms-python.python


class TestGenerateReport:
    """Tests for generate_report."""

    def test_generates_complete_report(self, mock_process, mocker):
        """Should generate a complete monitoring report."""
        # Setup mocks
        mock_sys_info = mocker.patch("surfmon.monitor.get_system_info")
        mock_procs = mocker.patch("surfmon.monitor.get_windsurf_processes")
        mock_mcp = mocker.patch("surfmon.monitor.get_mcp_config")
        mock_ext_count = mocker.patch("surfmon.monitor.count_extensions")
        mock_issues = mocker.patch("surfmon.monitor.check_log_issues")
        mock_proc_info = mocker.patch("surfmon.monitor.get_process_info")
        mock_pty = mocker.patch("surfmon.monitor.check_pty_leak")
        mocker.patch("surfmon.monitor.get_active_workspaces", return_value=[])
        mocker.patch("surfmon.monitor.count_windsurf_launches_today", return_value=0)

        mock_sys_info.return_value = SystemInfo(32, 16, 50, 10, 4, 1)
        mock_procs.return_value = [mock_process]
        mock_mcp.return_value = ["server1", "server2"]
        mock_ext_count.return_value = 33
        mock_issues.return_value = ["issue1"]
        proc_info = ProcessInfo(1234, "Windsurf", 5.0, 100.0, 1.5, 10, 100.0, "cmd")
        mock_proc_info.return_value = proc_info
        mock_pty.return_value = PtyInfo(windsurf_pty_count=5, system_pty_limit=511, system_pty_used=10)

        report = generate_report()

        assert report.system == mock_sys_info.return_value
        assert report.process_count == 1
        assert report.total_windsurf_memory_mb == 100.0
        assert report.total_windsurf_cpu_percent == 5.0
        assert len(report.mcp_servers_enabled) == 2
        assert report.extensions_count == 33
        assert len(report.log_issues) == 1
        assert report.pty_info is not None
        assert report.pty_info.windsurf_pty_count == 5


class TestGetActiveWorkspaces:
    """Tests for get_active_workspaces."""

    def test_returns_empty_if_logs_missing(self, tmp_path, monkeypatch):
        """Should return empty list if logs directory doesn't exist."""
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        result = get_active_workspaces()

        assert result == []

    def test_parses_workspace_from_main_log(self, tmp_path, monkeypatch):
        """Should parse workspace load events from main.log."""
        log_dir = tmp_path / "Library" / "Application Support" / "Windsurf" / "logs" / "20260204T123456"
        log_dir.mkdir(parents=True)

        # Create the workspace file
        workspace_file = tmp_path / "workspace.code-workspace"
        workspace_file.touch()
        workspace_path = str(workspace_file)

        main_log = log_dir / "main.log"
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
        log_dir = tmp_path / "Library" / "Application Support" / "Windsurf" / "logs" / "20260204T123456"
        log_dir.mkdir(parents=True)
        main_log = log_dir / "main.log"
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

        log_base = tmp_path / "Library" / "Application Support" / "Windsurf" / "logs"
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


class TestSaveReportJson:
    """Tests for save_report_json."""

    def test_saves_report_to_json(self, tmp_path, mocker):
        """Should save report as JSON file."""
        report = Mock()
        report.__dict__ = {"timestamp": "2026-01-01", "process_count": 5}

        output_path = tmp_path / "report.json"

        mocker.patch("surfmon.monitor.asdict", return_value=report.__dict__)
        save_report_json(report, output_path)

        assert output_path.exists()
        data = json.loads(output_path.read_text(encoding="utf-8"))
        assert data["timestamp"] == "2026-01-01"
        assert data["process_count"] == 5

    def test_excludes_raw_lsof_from_json(self, tmp_path, mocker):
        """Should strip raw_lsof from pty_info to keep report files small."""
        report = Mock()
        mocker.patch(
            "surfmon.monitor.asdict",
            return_value={
                "timestamp": "2026-01-01",
                "pty_info": {
                    "windsurf_pty_count": 5,
                    "raw_lsof": "COMMAND PID USER FD ...\nWindsurf 123 ...",
                },
            },
        )

        output_path = tmp_path / "report.json"
        save_report_json(report, output_path)

        data = json.loads(output_path.read_text(encoding="utf-8"))
        assert "raw_lsof" not in data["pty_info"]
        assert data["pty_info"]["windsurf_pty_count"] == 5


class TestLanguageServerEnhancement:
    """Additional tests for language server cmdline enhancement."""

    def test_identifies_gopls(self):
        """Should identify Go language server (gopls)."""
        procs = [
            ProcessInfo(1, "gopls", 0, 100, 0, 10, 100, "/usr/local/bin/gopls serve"),
        ]

        result = find_language_servers(procs)

        assert len(result) == 1
        assert "Go Language Server" in result[0].cmdline

    def test_identifies_rust_analyzer(self):
        """Should identify Rust language server (rust-analyzer)."""
        procs = [
            ProcessInfo(1, "rust-analyzer", 0, 100, 0, 10, 100, "/usr/local/bin/rust-analyzer"),
        ]

        result = find_language_servers(procs)

        assert len(result) == 1
        assert "Rust Language Server" in result[0].cmdline

    def test_truncates_long_cmdline(self):
        """Should truncate very long cmdlines that aren't enhanced."""
        # Use a recognized language server keyword but with a very long cmdline
        long_cmdline = "yaml-language-server " + "a" * 230
        procs = [
            ProcessInfo(1, "node", 0, 100, 0, 10, 100, long_cmdline),
        ]

        result = find_language_servers(procs)

        assert len(result) == 1
        assert len(result[0].cmdline) == 203  # 200 + "..."
        assert result[0].cmdline.endswith("...")

    def test_java_server_without_data_flag(self):
        """Should handle Java language server without -data flag."""
        procs = [
            ProcessInfo(1, "java", 0, 200, 0, 20, 200, "eclipse.jdtls some other args"),
        ]

        result = find_language_servers(procs)

        assert len(result) == 1
        assert "Java Language Server" in result[0].cmdline


class TestOrphanedCrashpadAgeFormatting:
    """Tests for orphaned crashpad handler age formatting."""

    def test_formats_age_in_seconds(self, tmp_path, monkeypatch, mocker):
        """Should format age in seconds when < 60 seconds."""
        import time

        mock_proc_iter = mocker.patch("surfmon.monitor.psutil.process_iter")

        proc = Mock()
        proc.info = {
            "pid": 1,
            "name": "crashpad_handler",
            "cmdline": [],
            "exe": "/Applications/Windsurf.app/crashpad",
            "create_time": time.time() - 30,  # 30 seconds ago
        }
        proc.name.return_value = "crashpad_handler"
        mock_proc_iter.return_value = [proc]

        monkeypatch.setenv("HOME", str(tmp_path))
        (tmp_path / ".windsurf").mkdir()

        result = check_log_issues()

        assert any("30s" in issue or "29s" in issue or "31s" in issue for issue in result)

    def test_formats_age_in_minutes(self, tmp_path, monkeypatch, mocker):
        """Should format age in minutes when < 1 hour."""
        import time

        mock_proc_iter = mocker.patch("surfmon.monitor.psutil.process_iter")

        proc = Mock()
        proc.info = {
            "pid": 1,
            "name": "crashpad_handler",
            "cmdline": [],
            "exe": "/Applications/Windsurf.app/crashpad",
            "create_time": time.time() - 900,  # 15 minutes ago
        }
        proc.name.return_value = "crashpad_handler"
        mock_proc_iter.return_value = [proc]

        monkeypatch.setenv("HOME", str(tmp_path))
        (tmp_path / ".windsurf").mkdir()

        result = check_log_issues()

        assert any("15m" in issue for issue in result)

    def test_formats_age_in_days(self, tmp_path, monkeypatch, mocker):
        """Should format age in days when >= 1 day."""
        import time

        mock_proc_iter = mocker.patch("surfmon.monitor.psutil.process_iter")

        proc = Mock()
        proc.info = {
            "pid": 1,
            "name": "crashpad_handler",
            "cmdline": [],
            "exe": "/Applications/Windsurf.app/crashpad",
            "create_time": time.time() - 172800,  # 2 days ago
        }
        proc.name.return_value = "crashpad_handler"
        mock_proc_iter.return_value = [proc]

        monkeypatch.setenv("HOME", str(tmp_path))
        (tmp_path / ".windsurf").mkdir()

        result = check_log_issues()

        assert any("2.0 days" in issue or "2 days" in issue for issue in result)


class TestNetworkLogParsing:
    """Tests for network log parsing."""

    def test_detects_telemetry_errors(self, tmp_path, monkeypatch):
        """Should detect telemetry connection failures."""
        log_dir = tmp_path / "Library" / "Application Support" / "Windsurf" / "logs" / "20260204"
        log_dir.mkdir(parents=True)
        network_log = log_dir / "network-shared.log"
        # Create many telemetry errors (more than threshold of 5)
        errors = "\n".join(["windsurf-telemetry.codeium.com connection failed" for _ in range(10)])
        network_log.write_text(errors, encoding="utf-8")

        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        result = check_log_issues()

        assert any("telemetry" in issue.lower() for issue in result)


class TestCheckPtyLeak:
    """Tests for check_pty_leak."""

    def test_returns_pty_info(self, mocker):
        """Should return PtyInfo with counts."""
        mock_run = mocker.patch("surfmon.monitor.subprocess.run")

        # Mock sysctl
        sysctl_result = Mock()
        sysctl_result.returncode = 0
        sysctl_result.stdout = "511\n"

        # Mock lsof - simulate Windsurf holding many PTYs
        lsof_lines = [
            "COMMAND     PID  USER   FD   TYPE DEVICE SIZE/OFF NODE NAME",
            *[f"Windsurf  75486 ismar   {32 + i}u   CHR   15,{i}      0t0  605 /dev/ptmx" for i in range(504)],
            "preview   50510 ismar   55u   CHR   15,5 0t222204  605 /dev/ptmx",
        ]

        lsof_result = Mock()
        lsof_result.returncode = 0
        lsof_result.stdout = "\n".join(lsof_lines)

        mock_run.side_effect = [sysctl_result, lsof_result]

        result = check_pty_leak()

        assert isinstance(result, PtyInfo)
        assert result.windsurf_pty_count == 504
        assert result.system_pty_limit == 511
        assert result.system_pty_used == 505  # 504 Windsurf + 1 preview

    def test_handles_sysctl_failure(self, mocker):
        """Should use default limit when sysctl fails."""
        mock_run = mocker.patch("surfmon.monitor.subprocess.run")

        sysctl_result = Mock()
        sysctl_result.returncode = 1
        sysctl_result.stdout = ""

        lsof_result = Mock()
        lsof_result.returncode = 0
        lsof_result.stdout = "COMMAND     PID  USER   FD   TYPE\n"

        mock_run.side_effect = [sysctl_result, lsof_result]

        result = check_pty_leak()

        assert result.system_pty_limit == 511  # Default

    def test_handles_lsof_failure(self, mocker):
        """Should return zero counts when lsof fails."""
        mock_run = mocker.patch("surfmon.monitor.subprocess.run")

        sysctl_result = Mock()
        sysctl_result.returncode = 0
        sysctl_result.stdout = "511\n"

        lsof_result = Mock()
        lsof_result.returncode = 1
        lsof_result.stdout = ""

        mock_run.side_effect = [sysctl_result, lsof_result]

        result = check_pty_leak()

        assert result.windsurf_pty_count == 0
        assert result.system_pty_used == 0

    def test_handles_timeout(self, mocker):
        """Should handle subprocess timeout gracefully."""
        import subprocess

        mock_run = mocker.patch("surfmon.monitor.subprocess.run")
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="lsof", timeout=10)

        result = check_pty_leak()

        assert result.windsurf_pty_count == 0
        assert result.system_pty_limit == 511

    def test_no_windsurf_ptys(self, mocker):
        """Should correctly count zero Windsurf PTYs when only other apps use them."""
        mock_run = mocker.patch("surfmon.monitor.subprocess.run")

        sysctl_result = Mock()
        sysctl_result.returncode = 0
        sysctl_result.stdout = "511\n"

        lsof_result = Mock()
        lsof_result.returncode = 0
        lsof_result.stdout = (
            "COMMAND     PID  USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n"
            "preview   50510 ismar   55u   CHR   15,5 0t222204  605 /dev/ptmx\n"
            "Terminal  12345 ismar   10u   CHR   15,6      0t0  605 /dev/ptmx\n"
        )

        mock_run.side_effect = [sysctl_result, lsof_result]

        result = check_pty_leak()

        assert result.windsurf_pty_count == 0
        assert result.system_pty_used == 2


class TestPtyLeakIssueDetection:
    """Tests for PTY leak issue propagation from check_pty_leak into generate_report."""

    def test_critical_pty_leak_generates_issue(self, mock_process, mocker):
        """Should generate CRITICAL issue when PTY count >= 200."""
        mock_sys_info = mocker.patch("surfmon.monitor.get_system_info")
        mock_procs = mocker.patch("surfmon.monitor.get_windsurf_processes")
        mock_mcp = mocker.patch("surfmon.monitor.get_mcp_config")
        mock_ext_count = mocker.patch("surfmon.monitor.count_extensions")
        mock_issues = mocker.patch("surfmon.monitor.check_log_issues")
        mock_proc_info = mocker.patch("surfmon.monitor.get_process_info")
        mock_pty = mocker.patch("surfmon.monitor.check_pty_leak")
        mocker.patch("surfmon.monitor.get_active_workspaces", return_value=[])
        mocker.patch("surfmon.monitor.count_windsurf_launches_today", return_value=0)

        mock_sys_info.return_value = SystemInfo(32, 16, 50, 10, 4, 1)
        mock_procs.return_value = [mock_process]
        mock_mcp.return_value = []
        mock_ext_count.return_value = 0
        mock_issues.return_value = []
        proc_info = ProcessInfo(1234, "Windsurf", 5.0, 100.0, 1.5, 10, 100.0, "cmd")
        mock_proc_info.return_value = proc_info
        mock_pty.return_value = PtyInfo(
            windsurf_pty_count=504,
            system_pty_limit=511,
            system_pty_used=509,
            issues=[
                (
                    "\u2716  CRITICAL: Windsurf processes are holding 504 PTYs "
                    "(system: 509/511, 100% used) "
                    "- Fix: Restart all Windsurf instances to release leaked PTYs"
                )
            ],
        )

        report = generate_report()

        assert report.pty_info is not None
        assert report.pty_info.windsurf_pty_count == 504
        assert any("CRITICAL" in issue and "PTY" in issue for issue in report.log_issues)

    def test_warning_pty_leak_generates_issue(self, mock_process, mocker):
        """Should generate warning issue when PTY count >= 50 but < 200."""
        mock_sys_info = mocker.patch("surfmon.monitor.get_system_info")
        mock_procs = mocker.patch("surfmon.monitor.get_windsurf_processes")
        mock_mcp = mocker.patch("surfmon.monitor.get_mcp_config")
        mock_ext_count = mocker.patch("surfmon.monitor.count_extensions")
        mock_issues = mocker.patch("surfmon.monitor.check_log_issues")
        mock_proc_info = mocker.patch("surfmon.monitor.get_process_info")
        mock_pty = mocker.patch("surfmon.monitor.check_pty_leak")
        mocker.patch("surfmon.monitor.get_active_workspaces", return_value=[])
        mocker.patch("surfmon.monitor.count_windsurf_launches_today", return_value=0)

        mock_sys_info.return_value = SystemInfo(32, 16, 50, 10, 4, 1)
        mock_procs.return_value = [mock_process]
        mock_mcp.return_value = []
        mock_ext_count.return_value = 0
        mock_issues.return_value = []
        proc_info = ProcessInfo(1234, "Windsurf", 5.0, 100.0, 1.5, 10, 100.0, "cmd")
        mock_proc_info.return_value = proc_info
        mock_pty.return_value = PtyInfo(
            windsurf_pty_count=75,
            system_pty_limit=511,
            system_pty_used=100,
            issues=[
                (
                    "\u26a0  Windsurf PTY leak detected: 75 PTYs held "
                    "(system: 100/511) "
                    "- Monitor closely, restart all Windsurf instances if it keeps growing"
                )
            ],
        )

        report = generate_report()

        assert any("PTY leak" in issue for issue in report.log_issues)
        assert not any("CRITICAL" in issue for issue in report.log_issues)

    def test_low_pty_count_no_issue(self, mock_process, mocker):
        """Should not generate issue when PTY count is low."""
        mock_sys_info = mocker.patch("surfmon.monitor.get_system_info")
        mock_procs = mocker.patch("surfmon.monitor.get_windsurf_processes")
        mock_mcp = mocker.patch("surfmon.monitor.get_mcp_config")
        mock_ext_count = mocker.patch("surfmon.monitor.count_extensions")
        mock_issues = mocker.patch("surfmon.monitor.check_log_issues")
        mock_proc_info = mocker.patch("surfmon.monitor.get_process_info")
        mock_pty = mocker.patch("surfmon.monitor.check_pty_leak")
        mocker.patch("surfmon.monitor.get_active_workspaces", return_value=[])
        mocker.patch("surfmon.monitor.count_windsurf_launches_today", return_value=0)

        mock_sys_info.return_value = SystemInfo(32, 16, 50, 10, 4, 1)
        mock_procs.return_value = [mock_process]
        mock_mcp.return_value = []
        mock_ext_count.return_value = 0
        mock_issues.return_value = []
        proc_info = ProcessInfo(1234, "Windsurf", 5.0, 100.0, 1.5, 10, 100.0, "cmd")
        mock_proc_info.return_value = proc_info
        mock_pty.return_value = PtyInfo(windsurf_pty_count=10, system_pty_limit=511, system_pty_used=20)

        report = generate_report()

        assert not any("PTY" in issue for issue in report.log_issues)


class TestClassifyPtyIssues:
    """Tests for _classify_pty_issues helper."""

    def test_no_ptys_no_issues(self):
        assert _classify_pty_issues(0, 0, 511) == []

    def test_below_warning_threshold_no_issues(self):
        assert _classify_pty_issues(10, 20, 511) == []

    def test_warning_threshold(self):
        issues = _classify_pty_issues(50, 60, 511)
        assert len(issues) == 1
        assert "PTY leak" in issues[0]
        assert "\u26a0" in issues[0]

    def test_critical_by_count(self):
        issues = _classify_pty_issues(200, 210, 511)
        assert len(issues) == 1
        assert "CRITICAL" in issues[0]
        assert "\u2716" in issues[0]

    def test_critical_by_usage_percent(self):
        issues = _classify_pty_issues(50, 420, 511)
        assert len(issues) == 1
        assert "CRITICAL" in issues[0]

    def test_zero_pty_limit_no_crash(self):
        assert _classify_pty_issues(0, 0, 0) == []


class TestSurfmonProcessExclusion:
    """Tests for excluding surfmon from process list."""

    def test_excludes_surfmon_process_by_pid(self, mocker):
        """Should exclude surfmon by PID match, not by cmdline string."""
        mock_proc_iter = mocker.patch("surfmon.monitor.psutil.process_iter")
        mocker.patch("surfmon.monitor.os.getpid", return_value=2)

        # Windsurf process
        proc1 = Mock()
        proc1.info = {
            "pid": 1,
            "name": "Windsurf",
            "cmdline": ["/Applications/Windsurf.app/Contents/MacOS/Windsurf"],
            "exe": "/Applications/Windsurf.app/Contents/MacOS/Windsurf",
        }
        proc1.name.return_value = "Windsurf"
        proc1.pid = 1

        # Surfmon process — exe contains Windsurf.app so it would pass the
        # app-name filter; the PID check must be the reason it's excluded.
        proc2 = Mock()
        proc2.info = {
            "pid": 2,
            "name": "python",
            "cmdline": ["/Applications/Windsurf.app/venv/bin/python", "-m", "surfmon"],
            "exe": "/Applications/Windsurf.app/venv/bin/python",
        }
        proc2.name.return_value = "python"
        proc2.pid = 2

        mock_proc_iter.return_value = [proc1, proc2]

        result = get_windsurf_processes()

        assert len(result) == 1
        assert proc1 in result
        assert proc2 not in result


class TestOrphanedWorkspaceDetection:
    """Tests for _check_orphaned_workspace_proc."""

    def test_detects_orphaned_workspace(self, tmp_path, mocker):
        """Should detect language server indexing a non-existent workspace."""
        from surfmon.monitor import _check_orphaned_workspace_proc

        proc = Mock()
        proc.memory_info.return_value = Mock(rss=500 * 1024 * 1024)  # 500 MB

        cmdline = "language_server_macos_arm --workspace_id file_Users_test_nonexistent_project --database_dir /tmp/fake_db_dir"

        result = _check_orphaned_workspace_proc(cmdline, proc)

        assert result is not None
        assert "CRITICAL" in result
        assert "non-existent workspace" in result

    def test_returns_none_for_non_language_server(self):
        """Should return None for non-language-server processes."""
        from surfmon.monitor import _check_orphaned_workspace_proc

        result = _check_orphaned_workspace_proc("some other process", Mock())

        assert result is None

    def test_returns_none_when_missing_flags(self):
        """Should return None when workspace_id or database_dir is missing."""
        from surfmon.monitor import _check_orphaned_workspace_proc

        cmdline = "language_server_macos_arm --workspace_id file_Users_test"
        result = _check_orphaned_workspace_proc(cmdline, Mock())

        assert result is None

    def test_returns_none_when_workspace_exists(self, mocker):
        """Should return None when workspace path exists."""
        from surfmon.monitor import _check_orphaned_workspace_proc

        # Mock Path.exists to return True so it works cross-platform (no /tmp on Windows)
        mocker.patch.object(Path, "exists", return_value=True)
        cmdline = "language_server_macos_arm --workspace_id file_tmp --database_dir /tmp/db"

        result = _check_orphaned_workspace_proc(cmdline, Mock())

        assert result is None

    def test_includes_db_size_when_db_exists(self, tmp_path, mocker):
        """Should include database size in issue when db directory exists."""
        from surfmon.monitor import _check_orphaned_workspace_proc

        proc = Mock()
        proc.memory_info.return_value = Mock(rss=100 * 1024 * 1024)

        db_dir = tmp_path / "db"
        db_dir.mkdir()
        (db_dir / "data.bin").write_bytes(b"x" * 1024)

        cmdline = f"language_server_macos_arm --workspace_id file_Users_test_nonexistent --database_dir {db_dir}"

        result = _check_orphaned_workspace_proc(cmdline, proc)

        assert result is not None
        assert "CRITICAL" in result


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
        log_base = tmp_path / "Library" / "Application Support" / "Windsurf" / "logs"
        log_base.mkdir(parents=True)

        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        result = get_active_workspaces()

        assert result == []

    def test_no_main_log(self, tmp_path, monkeypatch):
        """Should return empty list when log subdir exists but has no main.log."""
        log_dir = tmp_path / "Library" / "Application Support" / "Windsurf" / "logs" / "20260204T123456"
        log_dir.mkdir(parents=True)

        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        result = get_active_workspaces()

        assert result == []


class TestCrashpadFilterException:
    """Tests for crashpad filter exception handling."""

    def test_handles_nosuchprocess_during_filter(self, mocker):
        """Should handle NoSuchProcess during crashpad filtering."""
        mock_proc_iter = mocker.patch("surfmon.monitor.psutil.process_iter")

        # Helper process (not main, not crashpad) but raises during name() check
        proc1 = Mock()
        proc1.info = {
            "pid": 1,
            "name": "Windsurf Helper",
            "cmdline": ["/Applications/Windsurf.app/Helper"],
            "exe": "/Applications/Windsurf.app/Helper",
        }
        proc1.name.side_effect = psutil.NoSuchProcess(pid=1)

        mock_proc_iter.return_value = [proc1]

        result = get_windsurf_processes()

        assert len(result) == 0


class TestLaunchCountOSError:
    """Tests for launch count OSError handling."""

    def test_handles_os_error_reading_logs(self, tmp_path, monkeypatch, mocker):
        """Should return 0 when logs directory can't be read."""
        log_base = tmp_path / "Library" / "Application Support" / "Windsurf" / "logs"
        log_base.mkdir(parents=True)

        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        mocker.patch.object(Path, "iterdir", side_effect=OSError("Permission denied"))

        result = count_windsurf_launches_today()

        assert result == 0


class TestCPUSamplingExceptions:
    """Tests for CPU sampling exception handling in generate_report."""

    def test_handles_nosuchprocess_during_cpu_init(self, mocker):
        """Should handle NoSuchProcess during initial CPU sampling."""
        mock_sys_info = mocker.patch("surfmon.monitor.get_system_info")
        mock_procs = mocker.patch("surfmon.monitor.get_windsurf_processes")
        mock_mcp = mocker.patch("surfmon.monitor.get_mcp_config")
        mock_ext_count = mocker.patch("surfmon.monitor.count_extensions")
        mock_issues = mocker.patch("surfmon.monitor.check_log_issues")
        mock_pty = mocker.patch("surfmon.monitor.check_pty_leak")
        mocker.patch("surfmon.monitor.get_active_workspaces", return_value=[])
        mocker.patch("surfmon.monitor.count_windsurf_launches_today", return_value=0)
        mocker.patch("surfmon.monitor.time.sleep")

        mock_sys_info.return_value = SystemInfo(32, 16, 50, 10, 4, 1)
        mock_mcp.return_value = []
        mock_ext_count.return_value = 0
        mock_issues.return_value = []
        mock_pty.return_value = PtyInfo(windsurf_pty_count=0, system_pty_limit=511, system_pty_used=0)

        # Process that fails during cpu_percent() init
        proc = Mock(spec=psutil.Process)
        proc.pid = 999
        proc.cpu_percent.side_effect = psutil.NoSuchProcess(pid=999)
        mock_procs.return_value = [proc]

        # get_process_info will also fail since proc is gone
        mocker.patch("surfmon.monitor.get_process_info", return_value=None)

        report = generate_report()

        assert report.process_count == 0

    def test_handles_nosuchprocess_during_cpu_final(self, mocker):
        """Should handle NoSuchProcess during final CPU sampling."""
        mock_sys_info = mocker.patch("surfmon.monitor.get_system_info")
        mock_procs = mocker.patch("surfmon.monitor.get_windsurf_processes")
        mock_mcp = mocker.patch("surfmon.monitor.get_mcp_config")
        mock_ext_count = mocker.patch("surfmon.monitor.count_extensions")
        mock_issues = mocker.patch("surfmon.monitor.check_log_issues")
        mock_pty = mocker.patch("surfmon.monitor.check_pty_leak")
        mocker.patch("surfmon.monitor.get_active_workspaces", return_value=[])
        mocker.patch("surfmon.monitor.count_windsurf_launches_today", return_value=0)
        mocker.patch("surfmon.monitor.time.sleep")

        mock_sys_info.return_value = SystemInfo(32, 16, 50, 10, 4, 1)
        mock_mcp.return_value = []
        mock_ext_count.return_value = 0
        mock_issues.return_value = []
        mock_pty.return_value = PtyInfo(windsurf_pty_count=0, system_pty_limit=511, system_pty_used=0)

        # Process that succeeds on first cpu_percent() but fails on second
        proc = Mock(spec=psutil.Process)
        proc.pid = 999
        proc.cpu_percent.side_effect = [0.0, psutil.NoSuchProcess(pid=999)]
        mock_procs.return_value = [proc]

        mocker.patch("surfmon.monitor.get_process_info", return_value=None)

        report = generate_report()

        assert report.process_count == 0


class TestLaunchCountEdgeCases:
    """Tests for launch counting edge cases."""

    def test_skips_non_directory_entries(self, tmp_path, monkeypatch):
        """Should skip non-directory entries in logs folder."""
        from datetime import UTC, datetime

        log_base = tmp_path / "Library" / "Application Support" / "Windsurf" / "logs"
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

        log_base = tmp_path / "Library" / "Application Support" / "Windsurf" / "logs"
        log_base.mkdir(parents=True)

        today_str = datetime.now(tz=UTC).strftime("%Y%m%d")
        (log_base / f"{today_str}T120000").mkdir()
        # Create directories with malformed names
        (log_base / "invalid-name").mkdir()
        (log_base / "20260204").mkdir()  # Missing T separator

        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        result = count_windsurf_launches_today()

        assert result == 1


class TestParseLsofLine:
    """Tests for _parse_lsof_line."""

    def test_parses_valid_line(self):
        """Should parse a standard lsof output line into PtyFdEntry."""
        line = "Windsurf  75486 ismar   33u   CHR   15,0      0t0  605 /dev/ptmx"
        result = _parse_lsof_line(line)

        assert result is not None
        assert result.command == "Windsurf"
        assert result.pid == 75486
        assert result.fd == "33u"
        assert result.device == "15,0"
        assert result.size_off == "0t0"

    def test_parses_active_line_with_offset(self):
        """Should parse a line with non-zero offset."""
        line = "preview   50510 ismar   55u   CHR   15,5 0t222204  605 /dev/ptmx"
        result = _parse_lsof_line(line)

        assert result is not None
        assert result.command == "preview"
        assert result.pid == 50510
        assert result.size_off == "0t222204"

    def test_returns_none_for_short_line(self):
        """Should return None if line has fewer than LSOF_MIN_FIELDS fields."""
        result = _parse_lsof_line("too few fields")
        assert result is None

    def test_returns_none_for_empty_line(self):
        """Should return None for empty string."""
        result = _parse_lsof_line("")
        assert result is None

    def test_returns_none_for_non_integer_pid(self):
        """Should return None if PID field is not a valid integer."""
        line = "WARNING  notapid ismar   33u   CHR   15,0      0t0  605 /dev/ptmx"
        result = _parse_lsof_line(line)
        assert result is None


class TestGroupEntriesByPid:
    """Tests for _group_entries_by_pid."""

    def test_groups_entries_correctly(self):
        """Should group entries by PID and count them."""
        entries = [
            PtyFdEntry(command="Windsurf", pid=100, fd="33u", device="15,0", size_off="0t0"),
            PtyFdEntry(command="Windsurf", pid=100, fd="34u", device="15,1", size_off="0t0"),
            PtyFdEntry(command="Windsurf", pid=100, fd="35u", device="15,2", size_off="0t100"),
            PtyFdEntry(command="Windsurf", pid=200, fd="10u", device="15,3", size_off="0t0"),
        ]
        result = _group_entries_by_pid(entries)

        assert len(result) == 2
        # Sorted by count descending
        assert result[0].pid == 100
        assert result[0].pty_count == 3
        assert result[0].fds == ["33u", "34u", "35u"]
        assert result[1].pid == 200
        assert result[1].pty_count == 1

    def test_returns_empty_for_no_entries(self):
        """Should return empty list for no entries."""
        result = _group_entries_by_pid([])
        assert result == []

    def test_single_entry(self):
        """Should handle a single entry."""
        entries = [PtyFdEntry(command="App", pid=42, fd="5u", device="15,0", size_off="0t0")]
        result = _group_entries_by_pid(entries)

        assert len(result) == 1
        assert result[0].pid == 42
        assert result[0].name == "App"
        assert result[0].pty_count == 1


class TestExtractWindsurfVersion:
    """Tests for _extract_windsurf_version."""

    def test_extracts_version(self):
        """Should extract version from --windsurf_version flag."""
        procs = [
            ProcessInfo(
                pid=1,
                name="Windsurf",
                cpu_percent=0.0,
                memory_mb=100.0,
                memory_percent=1.0,
                num_threads=10,
                runtime_seconds=3600.0,
                cmdline="/Applications/Windsurf.app/Contents/MacOS/Windsurf --windsurf_version 1.99.2",
            ),
        ]
        assert _extract_windsurf_version(procs) == "1.99.2"

    def test_returns_empty_when_no_version(self):
        """Should return empty string when no version flag found."""
        procs = [
            ProcessInfo(
                pid=1,
                name="Windsurf",
                cpu_percent=0.0,
                memory_mb=100.0,
                memory_percent=1.0,
                num_threads=10,
                runtime_seconds=3600.0,
                cmdline="/Applications/Windsurf.app/Contents/MacOS/Windsurf",
            ),
        ]
        assert not _extract_windsurf_version(procs)

    def test_returns_empty_for_empty_list(self):
        """Should return empty string for empty process list."""
        assert not _extract_windsurf_version([])


class TestGetWindsurfUptime:
    """Tests for _get_windsurf_uptime."""

    def test_returns_max_uptime(self):
        """Should return the longest runtime from the process list."""
        procs = [
            ProcessInfo(
                pid=1,
                name="A",
                cpu_percent=0.0,
                memory_mb=0.0,
                memory_percent=0.0,
                num_threads=1,
                runtime_seconds=100.0,
                cmdline="",
            ),
            ProcessInfo(
                pid=2,
                name="B",
                cpu_percent=0.0,
                memory_mb=0.0,
                memory_percent=0.0,
                num_threads=1,
                runtime_seconds=7200.0,
                cmdline="",
            ),
        ]
        assert _get_windsurf_uptime(procs) == 7200.0

    def test_returns_zero_for_empty_list(self):
        """Should return 0.0 for empty process list."""
        assert _get_windsurf_uptime([]) == 0.0


class TestGetSystemPtyLimit:
    """Tests for _get_system_pty_limit."""

    def test_returns_limit_from_sysctl(self, mocker):
        """Should return the parsed sysctl value."""
        mock_run = mocker.patch("surfmon.monitor.subprocess.run")
        result_mock = Mock()
        result_mock.returncode = 0
        result_mock.stdout = "1024\n"
        mock_run.return_value = result_mock

        assert _get_system_pty_limit() == 1024

    def test_returns_default_on_failure(self, mocker):
        """Should return 511 when sysctl fails."""
        mock_run = mocker.patch("surfmon.monitor.subprocess.run")
        result_mock = Mock()
        result_mock.returncode = 1
        result_mock.stdout = ""
        mock_run.return_value = result_mock

        assert _get_system_pty_limit() == 511


class TestCheckPtyLeakForensic:
    """Tests for check_pty_leak forensic data collection."""

    def test_populates_per_process_detail(self, mocker):
        """Should populate per_process with per-PID breakdown."""
        mock_run = mocker.patch("surfmon.monitor.subprocess.run")

        sysctl_result = Mock()
        sysctl_result.returncode = 0
        sysctl_result.stdout = "511\n"

        lsof_lines = [
            "COMMAND     PID  USER   FD   TYPE DEVICE SIZE/OFF NODE NAME",
            "Windsurf  1000 ismar   33u   CHR   15,0      0t0  605 /dev/ptmx",
            "Windsurf  1000 ismar   34u   CHR   15,1 0t100000  605 /dev/ptmx",
            "Windsurf  2000 ismar   10u   CHR   15,2      0t0  605 /dev/ptmx",
            "Terminal  3000 ismar   5u    CHR   15,3 0t500000  605 /dev/ptmx",
        ]
        lsof_result = Mock()
        lsof_result.returncode = 0
        lsof_result.stdout = "\n".join(lsof_lines)

        mock_run.side_effect = [sysctl_result, lsof_result]

        result = check_pty_leak()

        assert result.windsurf_pty_count == 3
        assert result.system_pty_used == 4

        # Per-process detail
        assert result.per_process is not None
        assert len(result.per_process) == 2
        assert result.per_process[0].pid == 1000
        assert result.per_process[0].pty_count == 2
        assert result.per_process[1].pid == 2000
        assert result.per_process[1].pty_count == 1

        # FD entries
        assert result.fd_entries is not None
        assert len(result.fd_entries) == 3

        # Non-Windsurf holders
        assert result.non_windsurf_holders is not None
        assert len(result.non_windsurf_holders) == 1
        assert result.non_windsurf_holders[0].pid == 3000
        assert result.non_windsurf_holders[0].name == "Terminal"

        # Raw lsof preserved
        assert result.raw_lsof
        assert "Windsurf" in result.raw_lsof

    def test_extracts_version_and_uptime(self, mocker):
        """Should extract version and uptime when process list is provided."""
        mock_run = mocker.patch("surfmon.monitor.subprocess.run")

        sysctl_result = Mock()
        sysctl_result.returncode = 0
        sysctl_result.stdout = "511\n"

        lsof_result = Mock()
        lsof_result.returncode = 0
        lsof_result.stdout = "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"

        mock_run.side_effect = [sysctl_result, lsof_result]

        procs = [
            ProcessInfo(
                pid=1,
                name="Windsurf",
                cpu_percent=0.0,
                memory_mb=100.0,
                memory_percent=1.0,
                num_threads=10,
                runtime_seconds=7200.0,
                cmdline="/path/Windsurf --windsurf_version 2.5.0",
            ),
        ]
        result = check_pty_leak(windsurf_processes=procs)

        assert result.windsurf_version == "2.5.0"
        assert result.windsurf_uptime_seconds == 7200.0

    def test_backwards_compatible_without_processes(self, mocker):
        """Should work without process list (backwards-compatible)."""
        mock_run = mocker.patch("surfmon.monitor.subprocess.run")

        sysctl_result = Mock()
        sysctl_result.returncode = 0
        sysctl_result.stdout = "511\n"

        lsof_result = Mock()
        lsof_result.returncode = 0
        lsof_result.stdout = "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"

        mock_run.side_effect = [sysctl_result, lsof_result]

        result = check_pty_leak()

        assert not result.windsurf_version
        assert result.windsurf_uptime_seconds == 0.0
        assert result.per_process == []
        assert result.fd_entries == []

    def test_fd_detail_captures_offset(self, mocker):
        """Should capture offset values for active/idle FD classification."""
        mock_run = mocker.patch("surfmon.monitor.subprocess.run")

        sysctl_result = Mock()
        sysctl_result.returncode = 0
        sysctl_result.stdout = "511\n"

        lsof_lines = [
            "COMMAND     PID  USER   FD   TYPE DEVICE SIZE/OFF NODE NAME",
            "Windsurf  1000 ismar   33u   CHR   15,0      0t0  605 /dev/ptmx",
            "Windsurf  1000 ismar   34u   CHR   15,1 0t999999  605 /dev/ptmx",
        ]
        lsof_result = Mock()
        lsof_result.returncode = 0
        lsof_result.stdout = "\n".join(lsof_lines)

        mock_run.side_effect = [sysctl_result, lsof_result]

        result = check_pty_leak()

        assert result.fd_entries is not None
        assert len(result.fd_entries) == 2
        idle_fds = [e for e in result.fd_entries if e.size_off == "0t0"]
        active_fds = [e for e in result.fd_entries if e.size_off != "0t0"]
        assert len(idle_fds) == 1
        assert len(active_fds) == 1


class TestDetectLanguage:
    """Tests for _detect_language helper."""

    @pytest.mark.parametrize(
        ("cmdline", "expected"),
        [
            ("jdtls --config /path", "Java"),
            ("eclipse.jdt.ls.core", "Java"),
            ("gopls serve", "Go"),
            ("pyright --stdio", "Python"),
            ("pylance-langserver", "Python"),
            ("basedpyright --verbose", "Python"),
            ("rust-analyzer --stdio", "Rust"),
            ("yaml-language-server --stdio", "YAML"),
            ("json-language-server --stdio", "JSON"),
            ("language_server_macos_arm --workspace_id foo", "Codeium"),
            ("language_server --workspace_id foo", "Codeium"),
            ("some-random-process", "Unknown"),
        ],
    )
    def test_detect_language(self, cmdline, expected):
        """Should detect the correct language from cmdline."""
        from surfmon.monitor import _detect_language

        assert _detect_language(cmdline) == expected


def _patch_fs(monkeypatch, dirs, files=()):
    """Patch Path.is_dir and Path.exists for deterministic resolver tests."""
    dir_set = {str(Path(d)) for d in dirs}
    file_set = {str(Path(f)) for f in files}

    monkeypatch.setattr(Path, "is_dir", lambda self: str(self) in dir_set)
    monkeypatch.setattr(Path, "exists", lambda self: str(self) in dir_set or str(self) in file_set)


class TestResolveWorkspacePath:
    """Tests for Codeium workspace_id resolution (ISM-333)."""

    def test_simple_path_no_hyphens(self, monkeypatch):
        """All-slash decode works when path has no hyphens or dots."""
        _patch_fs(monkeypatch, ["/", "/Users", "/Users/dev", "/Users/dev/repos", "/Users/dev/repos/myproject"])
        assert _resolve_workspace_path("file_Users_dev_repos_myproject") == Path("/Users/dev/repos/myproject")

    def test_hyphenated_directory(self, monkeypatch):
        """Hyphens in directory names are correctly resolved."""
        _patch_fs(monkeypatch, ["/", "/Users", "/Users/dev", "/Users/dev/repos", "/Users/dev/repos/copier-uv-bleeding"])
        assert _resolve_workspace_path("file_Users_dev_repos_copier_uv_bleeding") == Path("/Users/dev/repos/copier-uv-bleeding")

    def test_dotted_file(self, monkeypatch):
        """Dots in filenames are correctly resolved."""
        _patch_fs(
            monkeypatch,
            ["/", "/Users", "/Users/dev", "/Users/dev/repos"],
            files=["/Users/dev/repos/project.code-workspace"],
        )
        assert _resolve_workspace_path("file_Users_dev_repos_project_code_workspace") == Path("/Users/dev/repos/project.code-workspace")

    def test_ambiguous_with_real_subdir(self, monkeypatch):
        """Correct resolution when a prefix also exists as a directory."""
        _patch_fs(
            monkeypatch,
            ["/", "/Users", "/Users/dev", "/Users/dev/repos", "/Users/dev/repos/copier", "/Users/dev/repos/copier-uv-bleeding"],
        )
        assert _resolve_workspace_path("file_Users_dev_repos_copier_uv_bleeding") == Path("/Users/dev/repos/copier-uv-bleeding")

    def test_truly_orphaned_returns_none(self, monkeypatch):
        """Returns None for workspace_ids that don't resolve to any real path."""
        _patch_fs(monkeypatch, ["/", "/Users", "/Users/dev", "/Users/dev/repos"])
        assert _resolve_workspace_path("file_Users_dev_repos_nonexistent_path") is None

    def test_mixed_dot_and_hyphen(self, monkeypatch):
        """Handles names with both dots and hyphens."""
        _patch_fs(monkeypatch, ["/", "/Users", "/Users/dev", "/Users/dev/repos", "/Users/dev/repos/my-app.v2"])
        assert _resolve_workspace_path("file_Users_dev_repos_my_app_v2") == Path("/Users/dev/repos/my-app.v2")

    def test_code_workspace_with_real_parent_dir(self, monkeypatch):
        """surfmon.code-workspace resolves even though surfmon/ is a real dir."""
        _patch_fs(
            monkeypatch,
            ["/", "/Users", "/Users/dev", "/Users/dev/repos", "/Users/dev/repos/surfmon"],
            files=["/Users/dev/repos/surfmon.code-workspace"],
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
        _patch_fs(monkeypatch, ["/", "/Users", "/Users/dev", "/Users/dev/repos", "/Users/dev/repos/copier-uv-bleeding"])
        cmdline = "ls --workspace_id file_Users_dev_repos_copier_uv_bleeding --x"
        result = _extract_workspace_from_cmdline(cmdline)
        assert "copier-uv-bleeding" in result

    def test_fallback_for_unresolvable(self, monkeypatch):
        _patch_fs(monkeypatch, ["/"])
        cmdline = "ls --workspace_id file_no_such_fake_workspace --x"
        result = _extract_workspace_from_cmdline(cmdline)
        assert result == "such/fake/workspace"


class TestIsOrphanedWorkspace:
    """Tests for _is_orphaned_workspace helper."""

    def test_not_orphaned_without_workspace_id(self):
        """Should return False when no workspace_id flag present."""
        assert _is_orphaned_workspace("gopls serve") is False

    def test_not_orphaned_for_existing_workspace(self, monkeypatch):
        """Should return False for existing workspace path."""
        _patch_fs(monkeypatch, ["/", "/opt"])
        cmdline = "language_server --workspace_id file_opt"
        assert _is_orphaned_workspace(cmdline) is False

    def test_orphaned_for_nonexistent_workspace(self, monkeypatch):
        """Should return True for non-existent workspace path."""
        _patch_fs(monkeypatch, ["/"])
        cmdline = "language_server --workspace_id file_Users_nobody_nonexistent_project_xyz"
        assert _is_orphaned_workspace(cmdline) is True

    def test_not_orphaned_with_hyphenated_path(self, monkeypatch):
        _patch_fs(monkeypatch, ["/", "/Users", "/Users/dev", "/Users/dev/repos", "/Users/dev/repos/my-project"])
        cmdline = "language_server --workspace_id file_Users_dev_repos_my_project --other"
        assert _is_orphaned_workspace(cmdline) is False


class TestCaptureLsSnapshot:
    """Tests for capture_ls_snapshot function."""

    def test_captures_language_servers(self):
        """Should capture all language server processes."""
        from surfmon.monitor import ProcessInfo, capture_ls_snapshot

        proc_infos = [
            ProcessInfo(1000, "Windsurf", 5.0, 500.0, 1.5, 20, 3600.0, "Windsurf --windsurf_version 2.5.0"),
            ProcessInfo(2000, "node", 10.0, 300.0, 0.9, 8, 3500.0, "node pyright --stdio"),
            ProcessInfo(3000, "gopls", 2.0, 150.0, 0.5, 12, 3400.0, "gopls serve"),
        ]

        snapshot = capture_ls_snapshot(proc_infos, "2.5.0", 3600.0)

        assert snapshot.total_ls_count == 2
        assert snapshot.total_ls_memory_mb == 450.0
        assert snapshot.windsurf_version == "2.5.0"
        assert snapshot.orphaned_count == 0
        assert len(snapshot.issues) == 0

    def test_detects_orphaned_workspace(self):
        """Should detect orphaned workspace and report issue."""
        from surfmon.monitor import ProcessInfo, capture_ls_snapshot

        proc_infos = [
            ProcessInfo(
                2000,
                "language_server_macos_arm",
                10.0,
                800.0,
                2.5,
                8,
                3500.0,
                "language_server_macos_arm --workspace_id file_Users_nobody_nonexistent_project --database_dir /tmp/nonexistent_db",
            ),
        ]

        snapshot = capture_ls_snapshot(proc_infos, "2.5.0", 3600.0)

        assert snapshot.orphaned_count == 1
        assert len(snapshot.issues) == 1
        assert "CRITICAL" in snapshot.issues[0]
        assert snapshot.entries[0].orphaned is True

    def test_empty_when_no_language_servers(self):
        """Should return empty snapshot when no language servers found."""
        from surfmon.monitor import ProcessInfo, capture_ls_snapshot

        proc_infos = [
            ProcessInfo(1000, "Windsurf", 5.0, 500.0, 1.5, 20, 3600.0, "Windsurf main process"),
        ]

        snapshot = capture_ls_snapshot(proc_infos, "2.5.0", 3600.0)

        assert snapshot.total_ls_count == 0
        assert snapshot.total_ls_memory_mb == 0.0
        assert snapshot.orphaned_count == 0

    def test_entries_sorted_by_memory_descending(self):
        """Should sort entries by memory usage descending."""
        from surfmon.monitor import ProcessInfo, capture_ls_snapshot

        proc_infos = [
            ProcessInfo(2000, "gopls", 2.0, 100.0, 0.3, 8, 3500.0, "gopls serve"),
            ProcessInfo(3000, "node", 5.0, 500.0, 1.5, 12, 3400.0, "node pyright --stdio"),
        ]

        snapshot = capture_ls_snapshot(proc_infos, "2.5.0", 3600.0)

        assert snapshot.entries[0].memory_mb == 500.0
        assert snapshot.entries[1].memory_mb == 100.0


class TestIsStaleWorkspace:
    """Tests for _is_stale_workspace helper."""

    def test_stale_when_path_exists_but_not_in_active_set(self, mocker):
        """Should return True when workspace exists on disk but isn't active."""
        mocker.patch(
            "surfmon.monitor._resolve_workspace_path",
            return_value=Path("/Users/test/my-project"),
        )
        cmdline = "language_server_macos_arm --workspace_id file_Users_test_my_project"

        active_paths: set[str] = {"/some/other/workspace"}
        assert _is_stale_workspace(cmdline, active_paths) is True

    def test_not_stale_when_path_in_active_set(self, mocker):
        """Should return False when workspace is in the active set."""
        mocker.patch(
            "surfmon.monitor._resolve_workspace_path",
            return_value=Path("/Users/test/my-project"),
        )
        cmdline = "language_server_macos_arm --workspace_id file_Users_test_my_project"

        active_paths: set[str] = {str(Path("/Users/test/my-project"))}
        assert _is_stale_workspace(cmdline, active_paths) is False

    def test_not_stale_when_no_workspace_id(self):
        """Should return False for processes without --workspace_id."""
        cmdline = "node pyright --stdio"
        active_paths: set[str] = {"/some/workspace"}
        assert _is_stale_workspace(cmdline, active_paths) is False

    def test_not_stale_when_path_does_not_exist(self):
        """Should return False when workspace doesn't exist (orphan, not stale)."""
        cmdline = "language_server_macos_arm --workspace_id file_Users_nobody_nonexistent"
        active_paths: set[str] = {"/some/workspace"}
        assert _is_stale_workspace(cmdline, active_paths) is False


class TestCaptureLsSnapshotStaleDetection:
    """Tests for stale LS detection in capture_ls_snapshot."""

    def test_detects_stale_workspace(self, mocker):
        """Should detect LS for workspace that exists but isn't open in IDE."""
        from surfmon.monitor import ProcessInfo, WorkspaceInfo, capture_ls_snapshot

        mocker.patch(
            "surfmon.monitor._resolve_workspace_path",
            return_value=Path("/Users/test/my-project"),
        )

        proc_infos = [
            ProcessInfo(
                2000,
                "language_server_macos_arm",
                10.0,
                800.0,
                2.5,
                8,
                3500.0,
                "language_server_macos_arm --workspace_id file_Users_test_my_project --database_dir /tmp/db",
            ),
        ]

        active_workspaces = [
            WorkspaceInfo(id="ws1", path="/some/other/workspace", exists=True),
        ]

        snapshot = capture_ls_snapshot(proc_infos, "2.5.0", 3600.0, active_workspaces)

        assert snapshot.stale_count == 1
        assert snapshot.orphaned_count == 0
        assert len(snapshot.issues) == 1
        assert "closed workspace" in snapshot.issues[0]
        assert snapshot.entries[0].stale is True
        assert snapshot.entries[0].orphaned is False

    def test_not_stale_when_workspace_active(self, mocker):
        """Should not flag LS as stale when workspace is in active set."""
        from surfmon.monitor import ProcessInfo, WorkspaceInfo, capture_ls_snapshot

        mocker.patch(
            "surfmon.monitor._resolve_workspace_path",
            return_value=Path("/Users/test/my-project"),
        )

        proc_infos = [
            ProcessInfo(
                2000,
                "language_server_macos_arm",
                10.0,
                800.0,
                2.5,
                8,
                3500.0,
                "language_server_macos_arm --workspace_id file_Users_test_my_project --database_dir /tmp/db",
            ),
        ]

        active_workspaces = [
            WorkspaceInfo(id="ws1", path=str(Path("/Users/test/my-project")), exists=True),
        ]

        snapshot = capture_ls_snapshot(proc_infos, "2.5.0", 3600.0, active_workspaces)

        assert snapshot.stale_count == 0
        assert snapshot.orphaned_count == 0
        assert len(snapshot.issues) == 0
        assert snapshot.entries[0].stale is False

    def test_no_stale_detection_without_active_workspaces(self):
        """Should skip stale detection when active_workspaces is None."""
        from surfmon.monitor import ProcessInfo, capture_ls_snapshot

        proc_infos = [
            ProcessInfo(
                2000,
                "language_server_macos_arm",
                10.0,
                800.0,
                2.5,
                8,
                3500.0,
                "language_server_macos_arm --workspace_id file_Users_nobody_nonexistent_project --database_dir /tmp/db",
            ),
        ]

        snapshot = capture_ls_snapshot(proc_infos, "2.5.0", 3600.0)

        assert snapshot.stale_count == 0
        assert snapshot.entries[0].stale is False

    def test_orphaned_takes_priority_over_stale(self):
        """Should flag as orphaned, not stale, when workspace doesn't exist."""
        from surfmon.monitor import ProcessInfo, WorkspaceInfo, capture_ls_snapshot

        proc_infos = [
            ProcessInfo(
                2000,
                "language_server_macos_arm",
                10.0,
                800.0,
                2.5,
                8,
                3500.0,
                "language_server_macos_arm --workspace_id file_Users_nobody_nonexistent_project --database_dir /tmp/db",
            ),
        ]

        active_workspaces = [
            WorkspaceInfo(id="ws1", path="/some/active/workspace", exists=True),
        ]

        snapshot = capture_ls_snapshot(proc_infos, "2.5.0", 3600.0, active_workspaces)

        assert snapshot.orphaned_count == 1
        assert snapshot.stale_count == 0
        assert snapshot.entries[0].orphaned is True
        assert snapshot.entries[0].stale is False
        assert "CRITICAL" in snapshot.issues[0]

    def test_no_stale_detection_with_empty_active_workspaces(self, mocker):
        """Should skip stale detection when active_workspaces list is empty."""
        from surfmon.monitor import ProcessInfo, capture_ls_snapshot

        mocker.patch(
            "surfmon.monitor._resolve_workspace_path",
            return_value=Path("/Users/test/my-project"),
        )

        proc_infos = [
            ProcessInfo(
                2000,
                "language_server_macos_arm",
                10.0,
                800.0,
                2.5,
                8,
                3500.0,
                "language_server_macos_arm --workspace_id file_Users_test_my_project --database_dir /tmp/db",
            ),
        ]

        snapshot = capture_ls_snapshot(proc_infos, "2.5.0", 3600.0, active_workspaces=[])

        assert snapshot.stale_count == 0
        assert snapshot.entries[0].stale is False


class TestMaxIssueSeverity:
    """Tests for max_issue_severity."""

    def test_no_issues_returns_ok(self):
        assert max_issue_severity([]) == EXIT_OK

    def test_warning_only_returns_warning(self):
        assert max_issue_severity(["\u26a0  Extension errors: some.ext (3)"]) == EXIT_WARNING

    def test_critical_only_returns_critical(self):
        assert max_issue_severity(["\u2716  CRITICAL: Orphaned workspace"]) == EXIT_CRITICAL

    def test_mixed_returns_critical(self):
        issues = [
            "\u26a0  Extension errors: some.ext (3)",
            "\u2716  CRITICAL: Orphaned workspace",
        ]
        assert max_issue_severity(issues) == EXIT_CRITICAL

    def test_multiple_warnings_returns_warning(self):
        issues = [
            "\u26a0  Extension errors: some.ext (3)",
            "\u26a0  2 orphaned crash handler(s) (oldest: 1.5 days, PIDs: 123)",
        ]
        assert max_issue_severity(issues) == EXIT_WARNING

    def test_critical_pty_issue(self):
        assert max_issue_severity(["\u2716  CRITICAL: Windsurf processes are holding 250 PTYs"]) == EXIT_CRITICAL

    def test_warning_pty_issue(self):
        assert max_issue_severity(["\u26a0  Windsurf PTY leak detected: 60 PTYs held"]) == EXIT_WARNING

    def test_extension_host_crash_is_critical(self):
        assert max_issue_severity(["\u2716  2 extension host crash(es) - PIDs: 1234, 5678"]) == EXIT_CRITICAL

    def test_oom_is_critical(self):
        assert max_issue_severity(["\u2716  Out of memory errors detected"]) == EXIT_CRITICAL

    def test_unprefixed_issue_treated_as_warning(self):
        """Issues without a recognised prefix default to warning (safe fallback)."""
        assert max_issue_severity(["Some issue without prefix"]) == EXIT_WARNING


# ---------------------------------------------------------------------------
# _parse_workspace_event
# ---------------------------------------------------------------------------

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


class TestParseWorkspaceEvent:
    """Tests for _parse_workspace_event."""

    def test_parse_load_event(self):
        result = _parse_workspace_event(LOAD_LINE)
        assert result is not None
        event_type, ws = result
        assert event_type == "load"
        assert ws.id == "abc123"
        assert ws.path == "/Users/test/my-project"

    def test_parse_close_event(self):
        result = _parse_workspace_event(CLOSE_LINE)
        assert result is not None
        event_type, ws = result
        assert event_type == "close"
        assert ws.id == "abc123"
        assert ws.path == "/Users/test/my-project"

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


# ---------------------------------------------------------------------------
# get_active_workspaces — close event handling
# ---------------------------------------------------------------------------


class TestGetActiveWorkspacesCloseEvents:
    """Tests for get_active_workspaces close event handling."""

    def test_close_removes_workspace_from_active_set(self, tmp_path, mocker):
        """A workspace that is loaded then closed should not appear in results."""
        log_dir = tmp_path / "20260314T120000"
        log_dir.mkdir()
        main_log = log_dir / "main.log"
        main_log.write_text(f"{LOAD_LINE}\n{CLOSE_LINE}\n")

        paths_mock = Mock()
        paths_mock.logs_dir = tmp_path
        mocker.patch("surfmon.monitor.get_paths", return_value=paths_mock)

        result = get_active_workspaces()
        assert len(result) == 0

    def test_load_after_close_re_adds_workspace(self, tmp_path, mocker):
        """A workspace closed then re-loaded should appear in results."""
        log_dir = tmp_path / "20260314T120000"
        log_dir.mkdir()
        main_log = log_dir / "main.log"
        main_log.write_text(f"{LOAD_LINE}\n{CLOSE_LINE}\n{LOAD_LINE}\n")

        paths_mock = Mock()
        paths_mock.logs_dir = tmp_path
        mocker.patch("surfmon.monitor.get_paths", return_value=paths_mock)

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
        log_dir = tmp_path / "20260314T120000"
        log_dir.mkdir()
        main_log = log_dir / "main.log"
        main_log.write_text(f"{LOAD_LINE}\n{other_load}\n{CLOSE_LINE}\n")

        paths_mock = Mock()
        paths_mock.logs_dir = tmp_path
        mocker.patch("surfmon.monitor.get_paths", return_value=paths_mock)

        result = get_active_workspaces()
        assert len(result) == 1
        assert result[0].id == "other456"
