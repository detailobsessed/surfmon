"""Tests for log analysis and issue detection."""

from pathlib import Path
from unittest.mock import Mock

import psutil

from surfmon.log_analysis import check_log_issues
from surfmon.monitor import get_windsurf_processes

_P_LA_PROC_ITER = "surfmon.log_analysis.psutil.process_iter"
_P_MON_PROC_ITER = "surfmon.monitor.psutil.process_iter"
_CRASHPAD_NAME = "crashpad_handler"
_CRASHPAD_EXE = "/Applications/Windsurf.app/crashpad"
_LOG_DATE = "20260204"
_APP_SUPPORT = "Application Support"
_DOT_WINDSURF = ".windsurf"
_MAIN_LOG = "main.log"


class TestCheckLogIssues:
    """Tests for check_log_issues."""

    def test_detects_orphaned_crashpad_with_age_formatting(self, tmp_path, monkeypatch, mocker):
        """Should detect orphaned crashpad handlers with age formatting."""
        mock_proc_iter = mocker.patch(_P_LA_PROC_ITER)

        import time

        proc = Mock()
        proc.info = {
            "pid": 1,
            "name": _CRASHPAD_NAME,
            "cmdline": [],
            "exe": _CRASHPAD_EXE,
            "create_time": time.time() - 3600,  # 1 hour ago
        }
        proc.name.return_value = _CRASHPAD_NAME
        mock_proc_iter.return_value = [proc]

        monkeypatch.setenv("HOME", str(tmp_path))
        (tmp_path / _DOT_WINDSURF).mkdir()

        result = check_log_issues()

        # Should detect orphaned crashpad
        assert any("crashpad" in issue.message.lower() or "orphan" in issue.message.lower() for issue in result)

    def test_detects_logs_directory_issue(self, tmp_path, monkeypatch):
        """Should detect logs directory in extensions folder."""
        logs_dir = tmp_path / _DOT_WINDSURF / "extensions" / "logs"
        logs_dir.mkdir(parents=True)

        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        result = check_log_issues()

        assert len(result) > 0
        assert any("logs" in issue.message.lower() for issue in result)

    def test_identifies_logs_directory_culprit(self, tmp_path, monkeypatch):
        """Should identify which extension created the logs directory."""
        logs_dir = tmp_path / _DOT_WINDSURF / "extensions" / "logs"
        logs_dir.mkdir(parents=True)
        (logs_dir / "marimo.log").write_text("some log content", encoding="utf-8")

        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        result = check_log_issues()

        assert any("marimo" in issue.message.lower() for issue in result)

    def test_detects_extension_host_crashes(self, tmp_path, monkeypatch):
        """Should detect extension host crashes (non-zero exit codes) in main.log."""
        log_dir = tmp_path / "Library" / _APP_SUPPORT / "Windsurf" / "logs" / _LOG_DATE
        log_dir.mkdir(parents=True)
        main_log = log_dir / _MAIN_LOG
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
        assert any("extension host crash" in issue.message.lower() for issue in result)
        assert any("1234" in issue.message for issue in result)
        assert any("9999" in issue.message for issue in result)

    def test_detects_update_service_errors(self, tmp_path, monkeypatch):
        """Should detect UpdateService errors."""
        log_dir = tmp_path / "Library" / _APP_SUPPORT / "Windsurf" / "logs" / _LOG_DATE
        log_dir.mkdir(parents=True)
        main_log = log_dir / _MAIN_LOG
        main_log.write_text("UpdateService error: timeout", encoding="utf-8")

        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        result = check_log_issues()

        assert any("update" in issue.message.lower() for issue in result)

    def test_detects_oom_errors(self, tmp_path, monkeypatch):
        """Should detect out of memory errors."""
        log_dir = tmp_path / "Library" / _APP_SUPPORT / "Windsurf" / "logs" / _LOG_DATE
        log_dir.mkdir(parents=True)
        main_log = log_dir / _MAIN_LOG
        main_log.write_text("Fatal error: out of memory", encoding="utf-8")

        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        result = check_log_issues()

        assert any("memory" in issue.message.lower() for issue in result)

    def test_detects_renderer_crashes(self, tmp_path, monkeypatch):
        """Should detect GPU/renderer crashes."""
        log_dir = tmp_path / "Library" / _APP_SUPPORT / "Windsurf" / "logs" / _LOG_DATE
        log_dir.mkdir(parents=True)
        main_log = log_dir / _MAIN_LOG
        main_log.write_text("GPU process crashed\nGPU process crashed\nGPU process crashed", encoding="utf-8")

        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        result = check_log_issues()

        assert any("gpu" in issue.message.lower() or "renderer" in issue.message.lower() for issue in result)

    def test_detects_extension_errors(self, tmp_path, monkeypatch):
        """Should detect extension errors in shared process log."""
        log_dir = tmp_path / "Library" / _APP_SUPPORT / "Windsurf" / "logs" / _LOG_DATE
        log_dir.mkdir(parents=True)
        sharedprocess_log = log_dir / "sharedprocess.log"
        # Create many errors (more than threshold of 10)
        errors = "\n".join(["[ERROR] Extension error occurred" for _ in range(15)])
        sharedprocess_log.write_text(errors, encoding="utf-8")

        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        result = check_log_issues()

        assert any("extension error" in issue.message.lower() for issue in result)

    def test_detects_specific_extension_errors(self, tmp_path, monkeypatch):
        """Should identify specific extensions causing errors."""
        log_dir = tmp_path / "Library" / _APP_SUPPORT / "Windsurf" / "logs" / _LOG_DATE
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
        issues_str = " ".join(issue.message for issue in result)
        assert "ms-python.python" in issues_str.lower()
        assert "3" in issues_str  # 3 errors for ms-python.python


class TestOrphanedCrashpadAgeFormatting:
    """Tests for orphaned crashpad handler age formatting."""

    def test_formats_age_in_seconds(self, tmp_path, monkeypatch, mocker):
        """Should format age in seconds when < 60 seconds."""
        import time

        mock_proc_iter = mocker.patch(_P_LA_PROC_ITER)

        proc = Mock()
        proc.info = {
            "pid": 1,
            "name": _CRASHPAD_NAME,
            "cmdline": [],
            "exe": _CRASHPAD_EXE,
            "create_time": time.time() - 30,  # 30 seconds ago
        }
        proc.name.return_value = _CRASHPAD_NAME
        mock_proc_iter.return_value = [proc]

        monkeypatch.setenv("HOME", str(tmp_path))
        (tmp_path / _DOT_WINDSURF).mkdir()

        result = check_log_issues()

        assert any("30s" in issue.message or "29s" in issue.message or "31s" in issue.message for issue in result)

    def test_formats_age_in_minutes(self, tmp_path, monkeypatch, mocker):
        """Should format age in minutes when < 1 hour."""
        import time

        mock_proc_iter = mocker.patch(_P_LA_PROC_ITER)

        proc = Mock()
        proc.info = {
            "pid": 1,
            "name": _CRASHPAD_NAME,
            "cmdline": [],
            "exe": _CRASHPAD_EXE,
            "create_time": time.time() - 900,  # 15 minutes ago
        }
        proc.name.return_value = _CRASHPAD_NAME
        mock_proc_iter.return_value = [proc]

        monkeypatch.setenv("HOME", str(tmp_path))
        (tmp_path / _DOT_WINDSURF).mkdir()

        result = check_log_issues()

        assert any("15m" in issue.message for issue in result)

    def test_formats_age_in_days(self, tmp_path, monkeypatch, mocker):
        """Should format age in days when >= 1 day."""
        import time

        mock_proc_iter = mocker.patch(_P_LA_PROC_ITER)

        proc = Mock()
        proc.info = {
            "pid": 1,
            "name": _CRASHPAD_NAME,
            "cmdline": [],
            "exe": _CRASHPAD_EXE,
            "create_time": time.time() - 172800,  # 2 days ago
        }
        proc.name.return_value = _CRASHPAD_NAME
        mock_proc_iter.return_value = [proc]

        monkeypatch.setenv("HOME", str(tmp_path))
        (tmp_path / _DOT_WINDSURF).mkdir()

        result = check_log_issues()

        assert any("2.0 days" in issue.message or "2 days" in issue.message for issue in result)


class TestNetworkLogParsing:
    """Tests for network log parsing."""

    def test_detects_telemetry_errors(self, tmp_path, monkeypatch):
        """Should detect telemetry connection failures."""
        log_dir = tmp_path / "Library" / _APP_SUPPORT / "Windsurf" / "logs" / _LOG_DATE
        log_dir.mkdir(parents=True)
        network_log = log_dir / "network-shared.log"
        # Create many telemetry errors (more than threshold of 5)
        errors = "\n".join(["windsurf-telemetry.codeium.com connection failed" for _ in range(10)])
        network_log.write_text(errors, encoding="utf-8")

        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        result = check_log_issues()

        assert any("telemetry" in issue.message.lower() for issue in result)


class TestCrashpadFilterException:
    """Tests for crashpad filter exception handling."""

    def test_handles_nosuchprocess_during_filter(self, mocker):
        """Should handle NoSuchProcess during crashpad filtering."""
        mock_proc_iter = mocker.patch(_P_MON_PROC_ITER)

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
