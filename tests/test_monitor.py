"""Tests for core monitoring functionality."""

import json
from pathlib import Path
from unittest.mock import Mock

import psutil
import pytest

from surfmon.config import WindsurfTarget, reset_target, set_target
from surfmon.monitor import (
    ProcessInfo,
    SystemInfo,
    check_log_issues,
    count_extensions,
    count_windsurf_launches_today,
    find_language_servers,
    generate_report,
    get_active_workspaces,
    get_mcp_config,
    get_process_info,
    get_system_info,
    get_windsurf_processes,
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
        # Setup mocks
        proc1 = Mock()
        proc1.info = {
            "pid": 1,
            "name": "Windsurf",
            "cmdline": ["/Applications/Windsurf.app/Contents/MacOS/Windsurf"],
            "exe": "/Applications/Windsurf.app/Contents/MacOS/Windsurf",
        }
        proc1.name.return_value = "Windsurf"

        proc2 = Mock()
        proc2.info = {
            "pid": 2,
            "name": "Windsurf Helper",
            "cmdline": ["/Applications/Windsurf.app/Contents/Frameworks/Electron Framework.framework/Windsurf Helper"],
            "exe": "/Applications/Windsurf.app/Contents/Frameworks/Electron Framework.framework/Windsurf Helper",
        }
        proc2.name.return_value = "Windsurf Helper"

        # This should be excluded (monitoring tool)
        proc3 = Mock()
        proc3.info = {
            "pid": 3,
            "name": "python3",
            "cmdline": ["python", "windsurf-monitor", "check"],
            "exe": "/usr/bin/python3",
        }
        proc3.name.return_value = "python3"

        # This should be excluded (unrelated)
        proc4 = Mock()
        proc4.info = {
            "pid": 4,
            "name": "chrome",
            "cmdline": ["/path/to/chrome"],
            "exe": "/path/to/chrome",
        }
        proc4.name.return_value = "chrome"

        mock_proc_iter.return_value = [proc1, proc2, proc3, proc4]

        # Execute
        result = get_windsurf_processes()

        # Assert
        assert len(result) == 2
        assert proc1 in result
        assert proc2 in result
        assert proc3 not in result
        assert proc4 not in result

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

        mock_sys_info.return_value = SystemInfo(32, 16, 50, 10, 4, 1)
        mock_procs.return_value = [mock_process]
        mock_mcp.return_value = ["server1", "server2"]
        mock_ext_count.return_value = 33
        mock_issues.return_value = ["issue1"]
        proc_info = ProcessInfo(1234, "Windsurf", 5.0, 100.0, 1.5, 10, 100.0, "cmd")
        mock_proc_info.return_value = proc_info

        report = generate_report()

        assert report.system == mock_sys_info.return_value
        assert report.process_count == 1
        assert report.total_windsurf_memory_mb == 100.0
        assert report.total_windsurf_cpu_percent == 5.0
        assert len(report.mcp_servers_enabled) == 2
        assert report.extensions_count == 33
        assert len(report.log_issues) == 1


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
        from datetime import datetime

        log_base = tmp_path / "Library" / "Application Support" / "Windsurf" / "logs"
        log_base.mkdir(parents=True)

        # Create log directories for today
        today_str = datetime.now().strftime("%Y%m%d")
        (log_base / f"{today_str}T120000").mkdir()
        (log_base / f"{today_str}T130000").mkdir()
        (log_base / f"{today_str}T140000").mkdir()

        # Create a log directory from yesterday
        from datetime import timedelta

        yesterday = datetime.now() - timedelta(days=1)
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
        data = json.loads(output_path.read_text())
        assert data["timestamp"] == "2026-01-01"
        assert data["process_count"] == 5


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


class TestSurfmonProcessExclusion:
    """Tests for excluding surfmon from process list."""

    def test_excludes_surfmon_process(self, mocker):
        """Should exclude surfmon monitoring tool from process list."""
        mock_proc_iter = mocker.patch("surfmon.monitor.psutil.process_iter")

        # Windsurf process
        proc1 = Mock()
        proc1.info = {
            "pid": 1,
            "name": "Windsurf",
            "cmdline": ["/Applications/Windsurf.app/Contents/MacOS/Windsurf"],
            "exe": "/Applications/Windsurf.app/Contents/MacOS/Windsurf",
        }
        proc1.name.return_value = "Windsurf"

        # Surfmon process (should be excluded)
        proc2 = Mock()
        proc2.info = {
            "pid": 2,
            "name": "python",
            "cmdline": ["python", "-m", "surfmon", "check"],
            "exe": "/usr/bin/python",
        }
        proc2.name.return_value = "python"

        mock_proc_iter.return_value = [proc1, proc2]

        result = get_windsurf_processes()

        assert len(result) == 1
        assert proc1 in result
        assert proc2 not in result


class TestLaunchCountEdgeCases:
    """Tests for launch counting edge cases."""

    def test_skips_non_directory_entries(self, tmp_path, monkeypatch):
        """Should skip non-directory entries in logs folder."""
        from datetime import datetime

        log_base = tmp_path / "Library" / "Application Support" / "Windsurf" / "logs"
        log_base.mkdir(parents=True)

        today_str = datetime.now().strftime("%Y%m%d")
        (log_base / f"{today_str}T120000").mkdir()
        # Create a file (not directory) - should be skipped
        (log_base / f"{today_str}T130000.log").touch()

        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        result = count_windsurf_launches_today()

        assert result == 1

    def test_skips_malformed_directory_names(self, tmp_path, monkeypatch):
        """Should skip directories with malformed names."""
        from datetime import datetime

        log_base = tmp_path / "Library" / "Application Support" / "Windsurf" / "logs"
        log_base.mkdir(parents=True)

        today_str = datetime.now().strftime("%Y%m%d")
        (log_base / f"{today_str}T120000").mkdir()
        # Create directories with malformed names
        (log_base / "invalid-name").mkdir()
        (log_base / "20260204").mkdir()  # Missing T separator

        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        result = count_windsurf_launches_today()

        assert result == 1
