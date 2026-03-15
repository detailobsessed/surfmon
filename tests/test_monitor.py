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
    PtyInfo,
    SystemInfo,
    _extract_windsurf_version,
    _get_windsurf_uptime,
    count_extensions,
    find_language_servers,
    generate_report,
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
