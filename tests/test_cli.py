"""Tests for CLI functionality."""

import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from typer.testing import CliRunner

from surfmon.cli import _parse_timestamp, app
from surfmon.config import reset_target

runner = CliRunner()


@pytest.fixture
def mock_generate_report(mocker):
    """Mock generate_report to avoid actual system calls."""
    mock_report = MagicMock()
    mock_report.process_count = 5
    mock_report.total_windsurf_memory_mb = 1000.0
    mock_report.total_windsurf_cpu_percent = 10.0
    mock_report.system.total_memory_gb = 32.0
    mock_report.language_servers = []
    mock_report.log_issues = []
    mock_report.active_workspaces = []
    mock_report.windsurf_launches_today = 2
    mock_report.extensions_count = 10
    mock_report.mcp_servers_enabled = []
    mock_report.windsurf_processes = []
    mock_report.pty_info = None
    return mocker.patch("surfmon.cli.generate_report", return_value=mock_report)


@pytest.fixture
def mock_display_report(mocker):
    """Mock display_report to avoid terminal output."""
    return mocker.patch("surfmon.cli.display_report")


class TestCheckCommand:
    """Tests for the check command."""

    def test_check_basic(self, mock_generate_report, mock_display_report):
        """Should run check command successfully."""
        result = runner.invoke(app, ["check"])
        assert result.exit_code == 0

    def test_check_with_save_flag(self, mock_generate_report, mock_display_report, tmp_path, monkeypatch, mocker):
        """Should save both JSON and Markdown with --save flag and enable verbose."""
        monkeypatch.setenv("HOME", str(tmp_path))
        mocker.patch("surfmon.cli.Path.home", return_value=tmp_path)

        mock_json = mocker.patch("surfmon.cli.save_report_json")
        mock_md = mocker.patch("surfmon.cli.save_report_markdown")
        mock_display = mocker.patch("surfmon.cli.display_report")

        result = runner.invoke(app, ["check", "--save"])

        assert result.exit_code == 0
        assert mock_json.called
        assert mock_md.called

        # Check that paths were auto-generated under ~/.surfmon/reports/
        json_path = mock_json.call_args[0][1]
        md_path = mock_md.call_args[0][1]
        assert json_path.name.startswith("surfmon-")
        assert json_path.name.endswith(".json")
        assert md_path.name.startswith("surfmon-")
        assert md_path.name.endswith(".md")
        assert ".surfmon" in str(json_path)
        assert "reports" in str(json_path)

        # Check that verbose was enabled
        assert mock_display.call_args[1]["verbose"] is True

    def test_check_with_save_short_form(self, mock_generate_report, mock_display_report, tmp_path, monkeypatch, mocker):
        """Should save both reports with -s short form."""
        monkeypatch.setenv("HOME", str(tmp_path))
        mocker.patch("surfmon.cli.Path.home", return_value=tmp_path)

        mock_json = mocker.patch("surfmon.cli.save_report_json")
        mock_md = mocker.patch("surfmon.cli.save_report_markdown")

        result = runner.invoke(app, ["check", "-s"])

        assert result.exit_code == 0
        assert mock_json.called
        assert mock_md.called

    def test_check_save_handles_write_error(self, mock_generate_report, mock_display_report, tmp_path, mocker):
        """Should handle write errors gracefully when saving reports."""
        mocker.patch("surfmon.cli.Path.home", return_value=tmp_path)
        mocker.patch("surfmon.cli.save_report_json", side_effect=OSError("Permission denied"))
        mocker.patch("surfmon.cli.save_report_markdown")

        result = runner.invoke(app, ["check", "--save"])

        assert "Cannot save JSON" in result.stdout

    def test_check_with_explicit_json_file(
        self,
        mock_generate_report,
        mock_display_report,
        tmp_path,
        mocker,
    ):
        """Should save JSON to explicit path with --json-file."""
        json_file = tmp_path / "test.json"

        mock_save = mocker.patch("surfmon.cli.save_report_json")
        result = runner.invoke(app, ["check", "--json-file", str(json_file)])

        assert result.exit_code == 0
        assert mock_save.called
        # Check that absolute path was used
        saved_path = mock_save.call_args[0][1]
        assert saved_path.is_absolute()

    def test_check_with_explicit_md_path(self, mock_generate_report, mock_display_report, tmp_path, mocker):
        """Should save Markdown to explicit path."""
        md_file = tmp_path / "test.md"

        mock_save = mocker.patch("surfmon.cli.save_report_markdown")
        result = runner.invoke(app, ["check", "--md", str(md_file)])

        assert result.exit_code == 0
        assert mock_save.called
        saved_path = mock_save.call_args[0][1]
        assert saved_path.is_absolute()

    def test_check_with_both_explicit_paths(self, mock_generate_report, mock_display_report, tmp_path, mocker):
        """Should save both formats to explicit paths."""
        json_file = tmp_path / "test.json"
        md_file = tmp_path / "test.md"

        mock_json = mocker.patch("surfmon.cli.save_report_json")
        mock_md = mocker.patch("surfmon.cli.save_report_markdown")

        result = runner.invoke(app, ["check", "--json-file", str(json_file), "--md", str(md_file)])

        assert result.exit_code == 0
        assert mock_json.called
        assert mock_md.called

    def test_check_json_stdout(self, mock_generate_report, mock_display_report, mocker):
        """Should output JSON to stdout with --json flag."""
        mocker.patch("surfmon.cli.asdict", return_value={"process_count": 5, "total_windsurf_memory_mb": 1000.0})

        result = runner.invoke(app, ["check", "--json"])

        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["process_count"] == 5
        assert data["total_windsurf_memory_mb"] == 1000.0

    def test_check_rejects_md_without_path(self, mock_generate_report, mock_display_report):
        """Should reject --md without a path argument."""
        result = runner.invoke(app, ["check", "--md", "--verbose"])

        assert result.exit_code == 1
        assert "Error: --md requires a file path" in result.stdout

    def test_check_verbose_flag(self, mock_generate_report, mock_display_report, mocker):
        """Should accept verbose flag."""
        mock_display = mocker.patch("surfmon.cli.display_report")
        result = runner.invoke(app, ["check", "--verbose"])

        assert result.exit_code == 0
        # Check that verbose was passed
        assert mock_display.call_args[1]["verbose"] is True

    def test_check_exits_with_error_on_issues(self, mock_generate_report, mock_display_report):
        """Should exit with code 1 when critical issues detected."""
        # Mock report with issues
        mock_generate_report.return_value.log_issues = ["Critical error"]

        result = runner.invoke(app, ["check"])

        assert result.exit_code == 1

    def test_check_json_exits_with_error_on_issues(self, mock_generate_report, mock_display_report, mocker):
        """Should exit with code 1 in JSON mode when critical issues detected."""
        mock_generate_report.return_value.log_issues = ["Critical error"]
        mocker.patch("surfmon.cli.asdict", return_value={"log_issues": ["Critical error"]})

        result = runner.invoke(app, ["check", "--json"])

        assert result.exit_code == 1


class TestVersionCallback:
    """Tests for version callback."""

    def test_version_flag(self):
        """Should show version with --version."""
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "surfmon" in result.stdout

    def test_version_short_flag(self):
        """Should show version with -V."""
        result = runner.invoke(app, ["-V"])
        assert result.exit_code == 0
        assert "surfmon" in result.stdout


class TestCompareCommand:
    """Tests for the compare command."""

    def test_compare_missing_before_file(self, tmp_path):
        """Should error when before file doesn't exist."""
        after_file = tmp_path / "after.json"
        after_file.write_text('{"timestamp": "2025-01-01"}', encoding="utf-8")

        result = runner.invoke(app, ["compare", str(tmp_path / "nonexistent.json"), str(after_file)])
        assert result.exit_code == 1
        assert "not found" in result.stdout

    def test_compare_missing_after_file(self, tmp_path):
        """Should error when after file doesn't exist."""
        before_file = tmp_path / "before.json"
        before_file.write_text('{"timestamp": "2025-01-01"}', encoding="utf-8")

        result = runner.invoke(app, ["compare", str(before_file), str(tmp_path / "nonexistent.json")])
        assert result.exit_code == 1
        assert "not found" in result.stdout


class TestCleanupCommand:
    """Tests for the cleanup command."""

    def test_cleanup_no_orphans(self, mocker):
        """Should handle case with no orphaned processes."""
        mock_iter = mocker.patch("psutil.process_iter")
        mock_iter.return_value = []
        result = runner.invoke(app, ["cleanup"])
        assert result.exit_code == 0
        assert "No orphaned" in result.stdout

    def test_cleanup_windsurf_running(self, mocker):
        """Should warn when Windsurf is running."""
        mock_paths = MagicMock()
        mock_paths.app_name = "Windsurf.app"
        mocker.patch("surfmon.cli.get_paths", return_value=mock_paths)

        mock_proc = MagicMock()
        mock_proc.info = {
            "pid": 1234,
            "name": "Windsurf",
            "cmdline": ["/Applications/Windsurf.app/Contents/MacOS/Windsurf"],
            "exe": "/Applications/Windsurf.app/Contents/MacOS/Windsurf",
            "create_time": 1234567890,
        }

        mock_iter = mocker.patch("surfmon.cli.psutil.process_iter")
        mock_iter.return_value = [mock_proc]
        result = runner.invoke(app, ["cleanup"])
        assert result.exit_code == 1
        assert "currently running" in result.stdout

    def test_cleanup_with_orphans_cancelled(self, mocker):
        """Should handle cancelled cleanup."""
        mock_paths = MagicMock()
        mock_paths.app_name = "Windsurf.app"
        mocker.patch("surfmon.cli.get_paths", return_value=mock_paths)

        mock_proc = MagicMock()
        mock_proc.info = {
            "pid": 5678,
            "name": "crashpad_handler",
            "cmdline": ["/Applications/Windsurf.app/crashpad_handler"],
            "exe": "/Applications/Windsurf.app/crashpad_handler",
            "create_time": 1234567890,
        }
        mock_proc.memory_info.return_value.rss = 50 * 1024 * 1024

        mock_iter = mocker.patch("surfmon.cli.psutil.process_iter")
        mock_iter.return_value = [mock_proc]
        result = runner.invoke(app, ["cleanup"], input="n\n")
        assert result.exit_code == 0
        assert "Cancelled" in result.stdout

    def test_cleanup_with_force(self, mocker):
        """Should kill orphans with --force flag."""
        mock_paths = MagicMock()
        mock_paths.app_name = "Windsurf.app"
        mocker.patch("surfmon.cli.get_paths", return_value=mock_paths)

        mock_proc = MagicMock()
        mock_proc.info = {
            "pid": 5678,
            "name": "crashpad_handler",
            "cmdline": ["/Applications/Windsurf.app/crashpad_handler"],
            "exe": "/Applications/Windsurf.app/crashpad_handler",
            "create_time": 1234567890,
        }
        mock_proc.pid = 5678
        mock_proc.memory_info.return_value.rss = 50 * 1024 * 1024

        mock_iter = mocker.patch("surfmon.cli.psutil.process_iter")
        mock_iter.return_value = [mock_proc]
        result = runner.invoke(app, ["cleanup", "--force"])
        assert result.exit_code == 0
        assert "Successfully killed" in result.stdout
        mock_proc.kill.assert_called_once()


class TestCheckSaveDirError:
    """Tests for check --save directory creation failure."""

    def test_check_save_mkdir_failure(self, mock_generate_report, mock_display_report, mocker):
        """Should exit with error when reports directory cannot be created."""
        mocker.patch.object(Path, "mkdir", side_effect=OSError("Permission denied"))

        result = runner.invoke(app, ["check", "--save"])

        assert result.exit_code == 1
        assert "Cannot create reports directory" in result.stdout

    def test_check_md_write_error(self, mock_generate_report, mock_display_report, tmp_path, mocker):
        """Should handle markdown write error gracefully."""
        mocker.patch("surfmon.cli.Path.home", return_value=tmp_path)
        mocker.patch("surfmon.cli.save_report_json")
        mocker.patch("surfmon.cli.save_report_markdown", side_effect=OSError("Disk full"))

        result = runner.invoke(app, ["check", "--save"])

        assert "Cannot save Markdown" in result.stdout


class TestPruneCommand:
    """Tests for the prune command."""

    def test_prune_nonexistent_directory(self, tmp_path):
        """Should error when directory doesn't exist."""
        result = runner.invoke(app, ["prune", str(tmp_path / "nonexistent")])
        assert result.exit_code == 1
        assert "not found" in result.stdout

    def test_prune_not_a_directory(self, tmp_path):
        """Should error when path is not a directory."""
        file_path = tmp_path / "file.txt"
        file_path.write_text("test", encoding="utf-8")
        result = runner.invoke(app, ["prune", str(file_path)])
        assert result.exit_code == 1
        assert "Not a directory" in result.stdout

    def test_prune_empty_directory(self, tmp_path):
        """Should handle empty directory."""
        result = runner.invoke(app, ["prune", str(tmp_path)])
        assert result.exit_code == 0
        assert "No JSON files" in result.stdout

    def test_prune_with_duplicates_dry_run(self, tmp_path):
        """Should find duplicates in dry-run mode."""
        # Create duplicate reports (same content hash)
        for i in range(3):
            report = {"process_count": 5, "memory_mb": 1000, "timestamp": f"2025-01-0{i + 1}"}
            (tmp_path / f"report_{i}.json").write_text(json.dumps(report), encoding="utf-8")

        result = runner.invoke(app, ["prune", str(tmp_path), "--dry-run"])
        assert result.exit_code == 0

    def test_prune_with_duplicates_confirmed(self, tmp_path):
        """Should delete duplicates when confirmed."""
        # Create duplicate reports
        for i in range(3):
            report = {"process_count": 5, "memory_mb": 1000, "timestamp": f"2025-01-0{i + 1}"}
            (tmp_path / f"report_{i}.json").write_text(json.dumps(report), encoding="utf-8")

        result = runner.invoke(app, ["prune", str(tmp_path)], input="y\n")
        assert result.exit_code == 0
        # Should have deleted some files
        remaining = list(tmp_path.glob("*.json"))
        assert len(remaining) < 3

    def test_prune_with_duplicates_cancelled(self, tmp_path):
        """Should not delete when cancelled."""
        # Create duplicate reports
        for i in range(3):
            report = {"process_count": 5, "memory_mb": 1000, "timestamp": f"2025-01-0{i + 1}"}
            (tmp_path / f"report_{i}.json").write_text(json.dumps(report), encoding="utf-8")

        result = runner.invoke(app, ["prune", str(tmp_path)], input="n\n")
        assert result.exit_code == 0
        assert "Cancelled" in result.stdout
        # All files should remain
        remaining = list(tmp_path.glob("*.json"))
        assert len(remaining) == 3

    def test_prune_keep_latest(self, tmp_path):
        """Should keep the latest report when --keep-latest is set."""
        # Create reports with different timestamps in filenames
        for i in range(3):
            report = {"process_count": 5, "memory_mb": 1000, "timestamp": f"2025-01-0{i + 1}"}
            (tmp_path / f"report_2025010{i + 1}.json").write_text(json.dumps(report), encoding="utf-8")

        result = runner.invoke(app, ["prune", str(tmp_path), "--keep-latest"], input="y\n")
        assert result.exit_code == 0


class TestAnalyzeCommand:
    """Tests for the analyze command."""

    def test_analyze_nonexistent_directory(self, tmp_path):
        """Should error when directory doesn't exist."""
        result = runner.invoke(app, ["analyze", str(tmp_path / "nonexistent")])
        assert result.exit_code == 1
        assert "not found" in result.stdout

    def test_analyze_empty_directory(self, tmp_path):
        """Should handle empty directory."""
        result = runner.invoke(app, ["analyze", str(tmp_path)])
        assert result.exit_code == 0
        assert "No JSON reports" in result.stdout

    def test_analyze_with_reports(self, tmp_path):
        """Should analyze reports successfully."""
        # Create sample reports with varied data
        for i in range(5):
            report = {
                "timestamp": f"2025-01-0{i + 1}T12:00:00",
                "process_count": 5 + i,
                "total_windsurf_memory_mb": 1000 + i * 100,
                "total_windsurf_cpu_percent": 10.0 + i,
                "memory_mb": 1000 + i * 100,
                "language_servers": [],
                "log_issues": [] if i < 3 else ["Issue detected"],
                "system": {
                    "total_memory_gb": 32.0,
                    "available_memory_gb": 16.0 - i,
                    "swap_used_gb": 1.0 + i * 0.1,
                    "swap_total_gb": 4.0,
                },
                "windsurf_processes": [
                    {"name": "Windsurf", "memory_mb": 500 + i * 50, "cpu_percent": 5.0},
                    {"name": "Helper (GPU)", "memory_mb": 200 + i * 20, "cpu_percent": 2.0},
                ],
                "extensions_count": 10 + i,
                "mcp_servers_enabled": [],
            }
            (tmp_path / f"report_{i}.json").write_text(json.dumps(report), encoding="utf-8")

        result = runner.invoke(app, ["analyze", str(tmp_path)])
        assert result.exit_code == 0

    def test_analyze_with_plot_flag(self, tmp_path):
        """Should handle --plot flag."""
        # Create sample reports with varied data for plotting
        for i in range(5):
            report = {
                "timestamp": f"2025-01-0{i + 1}T12:0{i}:00",
                "process_count": 5 + i,
                "total_windsurf_memory_mb": 1000 + i * 100,
                "total_windsurf_cpu_percent": 10.0 + i,
                "memory_mb": 1000 + i * 100,
                "language_servers": [{"pid": 1001, "name": "pylsp", "memory_mb": 50}] if i > 2 else [],
                "log_issues": ["Issue"] if i > 3 else [],
                "system": {
                    "total_memory_gb": 32.0,
                    "available_memory_gb": 16.0 - i,
                    "swap_used_gb": 1.0 + i * 0.1,
                    "swap_total_gb": 4.0,
                },
                "windsurf_processes": [
                    {"name": "Windsurf", "memory_mb": 500 + i * 50, "cpu_percent": 5.0},
                    {"name": "Helper (GPU)", "memory_mb": 200, "cpu_percent": 2.0},
                ],
                "extensions_count": 10 + i,
                "mcp_servers_enabled": [],
            }
            (tmp_path / f"report_{i}.json").write_text(json.dumps(report), encoding="utf-8")

        # Run analyze with plot - may have matplotlib warnings
        result = runner.invoke(app, ["analyze", str(tmp_path), "--plot"])
        # Check that analysis output was produced (tables shown)
        assert "Historical Analysis" in result.stdout or "Timeline" in result.stdout

    def test_analyze_with_output_file(self, tmp_path):
        """Should save plot to output file."""
        # Create sample reports with varied data
        for i in range(5):
            report = {
                "timestamp": f"2025-01-0{i + 1}T12:0{i}:00",
                "process_count": 5 + i,
                "total_windsurf_memory_mb": 1000 + i * 100,
                "total_windsurf_cpu_percent": 10.0 + i,
                "memory_mb": 1000 + i * 100,
                "language_servers": [],
                "log_issues": [],
                "system": {
                    "total_memory_gb": 32.0,
                    "available_memory_gb": 16.0 - i,
                    "swap_used_gb": 1.0 + i * 0.1,
                    "swap_total_gb": 4.0,
                },
                "windsurf_processes": [
                    {"name": "Windsurf", "memory_mb": 500 + i * 50, "cpu_percent": 5.0},
                ],
                "extensions_count": 10 + i,
                "mcp_servers_enabled": [],
            }
            (tmp_path / f"report_{i}.json").write_text(json.dumps(report), encoding="utf-8")

        output_file = tmp_path / "plot.png"
        result = runner.invoke(app, ["analyze", str(tmp_path), "--plot", "--output", str(output_file)])
        # Check that analysis output was produced
        assert "Historical Analysis" in result.stdout or "Timeline" in result.stdout


class TestTargetOption:
    """Tests for target option (required for live commands)."""

    def test_target_stable(self, mock_generate_report, mock_display_report):
        """Should accept stable target."""
        result = runner.invoke(app, ["check", "--target", "stable"])
        assert result.exit_code == 0

    def test_target_next(self, mock_generate_report, mock_display_report):
        """Should accept next target."""
        result = runner.invoke(app, ["check", "--target", "next"])
        assert result.exit_code == 0

    def test_target_insiders(self, mock_generate_report, mock_display_report):
        """Should accept insiders target."""
        result = runner.invoke(app, ["check", "--target", "insiders"])
        assert result.exit_code == 0

    def test_target_invalid(self):
        """Should reject invalid target."""
        result = runner.invoke(app, ["check", "--target", "invalid"])
        assert result.exit_code != 0
        assert "Invalid target" in result.stdout

    def test_check_requires_target(self, mock_generate_report, mock_display_report, mocker):
        """Should error when no target is set via flag or env var."""
        reset_target()
        mocker.patch("surfmon.config.config", return_value="")
        result = runner.invoke(app, ["check"])
        assert result.exit_code == 1
        assert "No Windsurf target specified" in result.stdout

    def test_cleanup_requires_target(self, mocker):
        """Should error when no target is set for cleanup."""
        reset_target()
        mocker.patch("surfmon.config.config", return_value="")
        result = runner.invoke(app, ["cleanup"])
        assert result.exit_code == 1
        assert "No Windsurf target specified" in result.stdout


class TestWatchCommand:
    """Tests for the watch command."""

    def test_watch_creates_session_directory(
        self,
        tmp_path,
        mock_generate_report,
        mocker,
    ):
        """Should create session directory."""
        mocker.patch("surfmon.cli.Live")
        mocker.patch("surfmon.cli.time.sleep", side_effect=KeyboardInterrupt)
        result = runner.invoke(app, ["watch", "--output", str(tmp_path), "--max", "1"])
        # Should exit gracefully
        assert result.exit_code == 0 or "Interrupted" in result.stdout or "stopped" in result.stdout.lower()

    def test_watch_handles_unwritable_output_dir(
        self,
        mock_generate_report,
        mocker,
    ):
        """Should exit with error when output directory cannot be created."""
        mocker.patch.object(Path, "mkdir", side_effect=OSError("Permission denied"))
        result = runner.invoke(app, ["watch", "--output", "unwritable_dir", "--max", "1"])
        assert result.exit_code == 1
        assert "Cannot create output directory" in result.stdout

    def test_watch_default_output_dir_is_absolute(self):
        """Default output dir should be under ~/.surfmon, not a relative path."""
        from surfmon.cli import DEFAULT_WATCH_DIR

        assert DEFAULT_WATCH_DIR.is_absolute(), f"Default output_dir should be absolute, got: {DEFAULT_WATCH_DIR}"
        assert ".surfmon" in str(DEFAULT_WATCH_DIR)


class TestCreateSummaryTable:
    """Tests for create_summary_table function."""

    def test_create_summary_table_basic(self, mock_generate_report):
        """Should create summary table."""
        from surfmon.cli import create_summary_table

        report = mock_generate_report.return_value
        table = create_summary_table(report)
        assert table is not None

    def test_create_summary_table_with_prev_report(self, mock_generate_report):
        """Should show changes when prev_report provided."""
        from surfmon.cli import create_summary_table

        report = mock_generate_report.return_value
        prev_report = MagicMock()
        prev_report.process_count = 3
        prev_report.total_windsurf_memory_mb = 800.0
        prev_report.total_windsurf_cpu_percent = 8.0
        prev_report.pty_info = None

        table = create_summary_table(report, prev_report)
        assert table is not None


class TestFormatElapsed:
    """Tests for _format_elapsed helper."""

    @pytest.mark.parametrize(
        ("seconds", "expected"),
        [
            (0, "0:00"),
            (59, "0:59"),
            (60, "1:00"),
            (90, "1:30"),
            (3599, "59:59"),
            (3600, "1:00:00"),
            (3661, "1:01:01"),
            (86399, "23:59:59"),
        ],
    )
    def test_format_elapsed(self, seconds, expected):
        """Should format seconds as M:SS or H:MM:SS."""
        from surfmon.cli import _format_elapsed

        assert _format_elapsed(seconds) == expected


class TestCreateSummaryTableSessionStart:
    """Tests for session_start parameter on create_summary_table."""

    def test_no_elapsed_without_session_start(self, mock_generate_report):
        """Should not show elapsed time when session_start is None."""
        from surfmon.cli import create_summary_table

        report = mock_generate_report.return_value
        table = create_summary_table(report)
        assert "elapsed" not in (table.title or "")

    def test_shows_elapsed_with_session_start(self, mock_generate_report):
        """Should show elapsed time when session_start is provided."""
        import time

        from surfmon.cli import create_summary_table

        report = mock_generate_report.return_value
        table = create_summary_table(report, session_start=time.time() - 3661)
        assert "elapsed 1:01:0" in (table.title or "")


class TestCreateSummaryTableChanges:
    """Tests for create_summary_table with prev_report showing actual changes."""

    def test_summary_table_with_increased_values(self, mock_generate_report):
        """Should show increase indicators when values go up."""
        from surfmon.cli import create_summary_table

        report = mock_generate_report.return_value
        report.process_count = 10
        report.total_windsurf_memory_mb = 2048.0
        report.total_windsurf_cpu_percent = 30.0
        report.language_servers = [MagicMock(), MagicMock()]

        prev_report = MagicMock()
        prev_report.process_count = 5
        prev_report.total_windsurf_memory_mb = 1024.0
        prev_report.total_windsurf_cpu_percent = 10.0
        prev_report.language_servers = []
        prev_report.pty_info = None

        table = create_summary_table(report, prev_report)
        assert table is not None

    def test_summary_table_with_decreased_values(self, mock_generate_report):
        """Should show decrease indicators when values go down."""
        from surfmon.cli import create_summary_table

        report = mock_generate_report.return_value
        report.process_count = 3
        report.total_windsurf_memory_mb = 512.0
        report.total_windsurf_cpu_percent = 5.0
        report.language_servers = []

        prev_report = MagicMock()
        prev_report.process_count = 8
        prev_report.total_windsurf_memory_mb = 2048.0
        prev_report.total_windsurf_cpu_percent = 25.0
        prev_report.language_servers = [MagicMock(), MagicMock()]
        prev_report.pty_info = None

        table = create_summary_table(report, prev_report)
        assert table is not None

    def test_summary_table_with_pty_info_changes(self, mock_generate_report):
        """Should show PTY changes when pty_info is present."""
        from surfmon.cli import create_summary_table

        report = mock_generate_report.return_value
        report.pty_info = MagicMock()
        report.pty_info.windsurf_pty_count = 100
        report.pty_info.system_pty_used = 200
        report.pty_info.system_pty_limit = 1024

        prev_report = MagicMock()
        prev_report.process_count = 5
        prev_report.total_windsurf_memory_mb = 1000.0
        prev_report.total_windsurf_cpu_percent = 10.0
        prev_report.language_servers = []
        prev_report.pty_info = MagicMock()
        prev_report.pty_info.windsurf_pty_count = 50

        table = create_summary_table(report, prev_report)
        assert table is not None


class TestCompareCommandErrors:
    """Tests for compare command error handling."""

    def test_compare_exception_from_compare_reports(self, tmp_path, mocker):
        """Should handle exceptions from compare_reports."""
        before_file = tmp_path / "before.json"
        after_file = tmp_path / "after.json"
        before_file.write_text('{"timestamp": "2025-01-01"}', encoding="utf-8")
        after_file.write_text('{"timestamp": "2025-01-02"}', encoding="utf-8")

        mocker.patch("surfmon.cli.compare_reports", side_effect=KeyError("missing_key"))

        result = runner.invoke(app, ["compare", str(before_file), str(after_file)])
        assert result.exit_code == 1
        assert "Error comparing" in result.stdout


class TestCleanupCommandEdgeCases:
    """Tests for cleanup command edge cases."""

    def test_cleanup_kill_failure(self, mocker):
        """Should report failed kills."""
        import psutil

        mock_paths = MagicMock()
        mock_paths.app_name = "Windsurf.app"
        mocker.patch("surfmon.cli.get_paths", return_value=mock_paths)

        mock_proc = MagicMock()
        mock_proc.info = {
            "pid": 5678,
            "name": "crashpad_handler",
            "cmdline": ["/Applications/Windsurf.app/crashpad_handler"],
            "exe": "/Applications/Windsurf.app/crashpad_handler",
            "create_time": 1234567890,
        }
        mock_proc.pid = 5678
        mock_proc.memory_info.return_value.rss = 50 * 1024 * 1024
        mock_proc.kill.side_effect = psutil.AccessDenied(pid=5678)

        mock_iter = mocker.patch("surfmon.cli.psutil.process_iter")
        mock_iter.return_value = [mock_proc]
        result = runner.invoke(app, ["cleanup", "--force"])
        assert result.exit_code == 1
        assert "Failed to kill" in result.stdout


class TestPruneCommandEdgeCases:
    """Tests for prune command edge cases."""

    def test_prune_with_corrupt_json(self, tmp_path):
        """Should warn about corrupt JSON files."""
        (tmp_path / "good.json").write_text('{"process_count": 5}', encoding="utf-8")
        (tmp_path / "bad.json").write_text("not valid json{{{", encoding="utf-8")

        result = runner.invoke(app, ["prune", str(tmp_path)])
        assert result.exit_code == 0
        assert "Warning" in result.stdout or "No duplicate" in result.stdout

    def test_prune_all_unique(self, tmp_path):
        """Should report no duplicates when all reports are unique."""
        for i in range(3):
            report = {"process_count": i, "memory_mb": 1000 + i * 500}
            (tmp_path / f"report_{i}.json").write_text(json.dumps(report), encoding="utf-8")

        result = runner.invoke(app, ["prune", str(tmp_path)])
        assert result.exit_code == 0
        assert "No duplicate" in result.stdout


class TestPruneNoKeepLatest:
    """Tests for prune --no-keep-latest option."""

    def test_prune_no_keep_latest(self, tmp_path):
        """Should keep the oldest report when --no-keep-latest is set."""
        for i in range(3):
            report = {"process_count": 5, "memory_mb": 1000, "timestamp": f"2025-01-0{i + 1}"}
            (tmp_path / f"report_2025010{i + 1}.json").write_text(json.dumps(report), encoding="utf-8")

        result = runner.invoke(app, ["prune", str(tmp_path), "--no-keep-latest"], input="y\n")
        assert result.exit_code == 0

    def test_prune_delete_failure(self, tmp_path, mocker):
        """Should report delete failures gracefully."""
        for i in range(3):
            report = {"process_count": 5, "memory_mb": 1000, "timestamp": f"2025-01-0{i + 1}"}
            (tmp_path / f"report_{i}.json").write_text(json.dumps(report), encoding="utf-8")

        mocker.patch("surfmon.cli._delete_files", return_value=(0, [("report_0.json", "Permission denied")]))

        result = runner.invoke(app, ["prune", str(tmp_path)], input="y\n")
        assert result.exit_code == 1
        assert "Failed to delete" in result.stdout


class TestAnalyzeCommandEdgeCases:
    """Tests for analyze command edge cases."""

    def test_analyze_with_invalid_json(self, tmp_path):
        """Should warn about invalid JSON and continue."""
        (tmp_path / "bad.json").write_text("not valid json", encoding="utf-8")
        result = runner.invoke(app, ["analyze", str(tmp_path)])
        assert result.exit_code == 1
        assert "No valid reports" in result.stdout

    def test_analyze_memory_leak_detection(self, tmp_path):
        """Should detect potential memory leak with large memory growth."""
        for i in range(3):
            report = {
                "timestamp": f"2025-01-01T12:0{i}:00",
                "process_count": 5,
                "total_windsurf_memory_mb": 1000 + i * 1000,
                "total_windsurf_cpu_percent": 10.0,
                "memory_mb": 1000 + i * 1000,
                "language_servers": [],
                "log_issues": [],
                "system": {"total_memory_gb": 32.0, "available_memory_gb": 16.0, "swap_used_gb": 1.0, "swap_total_gb": 4.0},
                "windsurf_processes": [{"name": "Windsurf", "memory_mb": 500, "cpu_percent": 5.0, "num_threads": 10}],
                "extensions_count": 10,
                "mcp_servers_enabled": [],
            }
            (tmp_path / f"report_{i}.json").write_text(json.dumps(report), encoding="utf-8")

        result = runner.invoke(app, ["analyze", str(tmp_path)])
        assert result.exit_code == 0
        assert "MEMORY LEAK" in result.stdout

    def test_analyze_stable_memory(self, tmp_path):
        """Should report stable memory when change is small."""
        for i in range(3):
            report = {
                "timestamp": f"2025-01-01T12:0{i}:00",
                "process_count": 5 - i,
                "total_windsurf_memory_mb": 1000 + i * 10,
                "total_windsurf_cpu_percent": 10.0,
                "memory_mb": 1000 + i * 10,
                "language_servers": [],
                "log_issues": [],
                "system": {"total_memory_gb": 32.0, "available_memory_gb": 16.0, "swap_used_gb": 1.0, "swap_total_gb": 4.0},
                "windsurf_processes": [{"name": "Windsurf", "memory_mb": 500, "cpu_percent": 5.0, "num_threads": 10}],
                "extensions_count": 10,
                "mcp_servers_enabled": [],
            }
            (tmp_path / f"report_{i}.json").write_text(json.dumps(report), encoding="utf-8")

        result = runner.invoke(app, ["analyze", str(tmp_path)])
        assert result.exit_code == 0
        assert "Memory stable" in result.stdout
        assert "Process count decreased" in result.stdout

    def test_analyze_process_increase(self, tmp_path):
        """Should warn about process count increase > 5."""
        for i in range(3):
            report = {
                "timestamp": f"2025-01-01T12:0{i}:00",
                "process_count": 5 + i * 5,
                "total_windsurf_memory_mb": 1000,
                "total_windsurf_cpu_percent": 10.0,
                "memory_mb": 1000,
                "language_servers": [],
                "log_issues": ["issue"] if i == 2 else [],
                "system": {"total_memory_gb": 32.0, "available_memory_gb": 16.0, "swap_used_gb": 1.0, "swap_total_gb": 4.0},
                "windsurf_processes": [{"name": "Windsurf", "memory_mb": 500, "cpu_percent": 5.0, "num_threads": 10}],
                "extensions_count": 10,
                "mcp_servers_enabled": [],
            }
            (tmp_path / f"report_{i}.json").write_text(json.dumps(report), encoding="utf-8")

        result = runner.invoke(app, ["analyze", str(tmp_path)])
        assert result.exit_code == 0
        assert "Process count increased" in result.stdout
        assert "Current Issues" in result.stdout

    def test_parse_timestamp_treats_naive_input_as_local_time(self):
        """Naive timestamps should be interpreted as local time before UTC normalization."""
        raw = "2025-01-01T12:00:00"
        parsed = _parse_timestamp(raw)

        expected = datetime.fromisoformat(raw).astimezone().astimezone(UTC)
        assert parsed == expected
        assert parsed.tzinfo == UTC


class TestSignalHandler:
    """Tests for signal handler."""

    def test_signal_handler_sets_stop_flag(self, mocker):
        """Should set stop_monitoring flag."""
        import surfmon.cli
        from surfmon.cli import signal_handler

        surfmon.cli._state["stop_monitoring"] = False
        mocker.patch("surfmon.cli.console")
        signal_handler(2, None)
        assert surfmon.cli._state["stop_monitoring"] is True


class TestPtySnapshotCommand:
    """Tests for the pty-snapshot command."""

    @pytest.fixture
    def _mock_pty_data(self, mocker):
        """Mock PTY data collection for pty-snapshot tests."""
        from surfmon.monitor import PtyFdEntry, PtyInfo, PtyProcessDetail

        mock_pty = PtyInfo(
            windsurf_pty_count=5,
            system_pty_limit=511,
            system_pty_used=10,
            per_process=[
                PtyProcessDetail(pid=1000, name="Windsurf", pty_count=3, fds=["33u", "34u", "35u"]),
                PtyProcessDetail(pid=2000, name="Windsurf", pty_count=2, fds=["10u", "11u"]),
            ],
            fd_entries=[
                PtyFdEntry(command="Windsurf", pid=1000, fd="33u", device="15,0", size_off="0t0"),
                PtyFdEntry(command="Windsurf", pid=1000, fd="34u", device="15,1", size_off="0t100"),
                PtyFdEntry(command="Windsurf", pid=1000, fd="35u", device="15,2", size_off="0t0"),
                PtyFdEntry(command="Windsurf", pid=2000, fd="10u", device="15,3", size_off="0t500"),
                PtyFdEntry(command="Windsurf", pid=2000, fd="11u", device="15,4", size_off="0t0"),
            ],
            non_windsurf_holders=[
                PtyProcessDetail(pid=3000, name="Terminal", pty_count=5, fds=["5u", "6u", "7u", "8u", "9u"]),
            ],
            windsurf_version="2.5.0",
            windsurf_uptime_seconds=7200.0,
            raw_lsof="COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\nWindsurf 1000 ismar 33u CHR 15,0 0t0 605 /dev/ptmx\n",
        )
        mocker.patch("surfmon.cli.collect_process_infos", return_value=[])
        mocker.patch("surfmon.cli.check_pty_leak", return_value=mock_pty)
        return mock_pty

    @pytest.mark.usefixtures("_mock_pty_data")
    def test_pty_snapshot_basic(self):
        """Should run pty-snapshot and display output."""
        result = runner.invoke(app, ["pty-snapshot"])
        assert result.exit_code == 0
        assert "PTY Forensic Snapshot" in result.output

    @pytest.mark.usefixtures("_mock_pty_data")
    def test_pty_snapshot_save_json_file(self, tmp_path):
        """Should save JSON snapshot to specified path with --json-file."""
        json_path = tmp_path / "snapshot.json"
        result = runner.invoke(app, ["pty-snapshot", "--json-file", str(json_path)])
        assert result.exit_code == 0
        assert json_path.exists()

        data = json.loads(json_path.read_text(encoding="utf-8"))
        assert "pty_info" in data
        assert data["pty_info"]["windsurf_pty_count"] == 5

    @pytest.mark.usefixtures("_mock_pty_data")
    def test_pty_snapshot_json_stdout(self):
        """Should output JSON to stdout with --json flag."""
        result = runner.invoke(app, ["pty-snapshot", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert "pty_info" in data
        assert data["pty_info"]["windsurf_pty_count"] == 5

    @pytest.mark.usefixtures("_mock_pty_data")
    def test_pty_snapshot_save_markdown(self, tmp_path):
        """Should save Markdown snapshot to specified path."""
        md_path = tmp_path / "snapshot.md"
        result = runner.invoke(app, ["pty-snapshot", "--md", str(md_path)])
        assert result.exit_code == 0
        assert md_path.exists()

        content = md_path.read_text(encoding="utf-8")
        assert "# PTY Forensic Snapshot" in content
        assert "Windsurf PTYs" in content
        assert "Per-PID Breakdown" in content
        assert "2.5.0" in content

    @pytest.mark.usefixtures("_mock_pty_data")
    def test_pty_snapshot_save_flag(self, tmp_path, monkeypatch):
        """Should auto-save both JSON and Markdown with --save."""
        monkeypatch.setattr("surfmon.cli.DEFAULT_REPORTS_DIR", tmp_path)
        result = runner.invoke(app, ["pty-snapshot", "--save"])
        assert result.exit_code == 0

        json_files = list(tmp_path.glob("pty-snapshot-*.json"))
        md_files = list(tmp_path.glob("pty-snapshot-*.md"))
        assert len(json_files) == 1
        assert len(md_files) == 1


class TestLsSnapshotCommand:
    """Tests for the ls-snapshot command."""

    @pytest.fixture
    def _mock_ls_data(self, mocker):
        """Mock language server data collection for ls-snapshot tests."""
        from surfmon.monitor import LsSnapshot, LsSnapshotEntry, ProcessInfo

        mock_proc_infos = [
            ProcessInfo(
                pid=1000,
                name="Windsurf",
                cpu_percent=5.0,
                memory_mb=500.0,
                memory_percent=1.5,
                num_threads=20,
                runtime_seconds=3600.0,
                cmdline="/Applications/Windsurf.app/Contents/MacOS/Windsurf --windsurf_version 2.5.0",
            ),
            ProcessInfo(
                pid=2000,
                name="language_server_macos_arm",
                cpu_percent=10.0,
                memory_mb=300.0,
                memory_percent=0.9,
                num_threads=8,
                runtime_seconds=3500.0,
                cmdline="language_server_macos_arm --workspace_id file_Users_ismar_repos_surfmon --database_dir /tmp/db",
            ),
            ProcessInfo(
                pid=3000,
                name="node",
                cpu_percent=2.0,
                memory_mb=150.0,
                memory_percent=0.5,
                num_threads=12,
                runtime_seconds=3400.0,
                cmdline="node /path/to/pyright --stdio",
            ),
        ]

        mock_snapshot = LsSnapshot(
            timestamp="2025-06-01T12:00:00+00:00",
            windsurf_version="2.5.0",
            windsurf_uptime_seconds=3600.0,
            total_ls_count=2,
            total_ls_memory_mb=450.0,
            orphaned_count=0,
            entries=[
                LsSnapshotEntry(
                    pid=2000,
                    name="language_server_macos_arm",
                    language="Codeium",
                    memory_mb=300.0,
                    memory_percent=0.9,
                    cpu_percent=10.0,
                    num_threads=8,
                    runtime_seconds=3500.0,
                    workspace="repos/surfmon",
                    orphaned=False,
                ),
                LsSnapshotEntry(
                    pid=3000,
                    name="node",
                    language="Python",
                    memory_mb=150.0,
                    memory_percent=0.5,
                    cpu_percent=2.0,
                    num_threads=12,
                    runtime_seconds=3400.0,
                    workspace="",
                    orphaned=False,
                ),
            ],
            issues=[],
        )

        mocker.patch("surfmon.cli.collect_process_infos", return_value=mock_proc_infos)
        mocker.patch("surfmon.cli._extract_windsurf_version", return_value="2.5.0")
        mocker.patch("surfmon.cli._get_windsurf_uptime", return_value=3600.0)
        mocker.patch("surfmon.cli.capture_ls_snapshot", return_value=mock_snapshot)
        return mock_snapshot

    @pytest.mark.usefixtures("_mock_ls_data")
    def test_ls_snapshot_basic(self):
        """Should run ls-snapshot and display output."""
        result = runner.invoke(app, ["ls-snapshot"])
        assert result.exit_code == 0
        assert "Language Server Snapshot" in result.output

    @pytest.mark.usefixtures("_mock_ls_data")
    def test_ls_snapshot_json_stdout(self):
        """Should output JSON to stdout with --json flag."""
        result = runner.invoke(app, ["ls-snapshot", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["total_ls_count"] == 2
        assert data["total_ls_memory_mb"] == 450.0
        assert len(data["entries"]) == 2

    @pytest.mark.usefixtures("_mock_ls_data")
    def test_ls_snapshot_save_json_file(self, tmp_path):
        """Should save JSON snapshot to specified path with --json-file."""
        json_path = tmp_path / "ls-snapshot.json"
        result = runner.invoke(app, ["ls-snapshot", "--json-file", str(json_path)])
        assert result.exit_code == 0
        assert json_path.exists()

        data = json.loads(json_path.read_text(encoding="utf-8"))
        assert data["total_ls_count"] == 2

    @pytest.mark.usefixtures("_mock_ls_data")
    def test_ls_snapshot_save_markdown(self, tmp_path):
        """Should save Markdown snapshot to specified path."""
        md_path = tmp_path / "ls-snapshot.md"
        result = runner.invoke(app, ["ls-snapshot", "--md", str(md_path)])
        assert result.exit_code == 0
        assert md_path.exists()

        content = md_path.read_text(encoding="utf-8")
        assert "# Language Server Forensic Snapshot" in content
        assert "Language Servers" in content

    @pytest.mark.usefixtures("_mock_ls_data")
    def test_ls_snapshot_save_flag(self, tmp_path, monkeypatch):
        """Should auto-save both JSON and Markdown with --save."""
        monkeypatch.setattr("surfmon.cli.DEFAULT_REPORTS_DIR", tmp_path)
        result = runner.invoke(app, ["ls-snapshot", "--save"])
        assert result.exit_code == 0

        json_files = list(tmp_path.glob("ls-snapshot-*.json"))
        md_files = list(tmp_path.glob("ls-snapshot-*.md"))
        assert len(json_files) == 1
        assert len(md_files) == 1


class TestLsSnapshotDisplay:
    """Tests for _display_ls_snapshot covering memory color branches and issues."""

    def test_display_critical_memory(self, mocker):
        """Should display red color for critical memory (>1024 MB total)."""
        from surfmon.monitor import LsSnapshot, LsSnapshotEntry

        snapshot = LsSnapshot(
            timestamp="2025-06-01T12:00:00+00:00",
            windsurf_version="2.5.0",
            windsurf_uptime_seconds=3600.0,
            total_ls_count=1,
            total_ls_memory_mb=2000.0,
            orphaned_count=1,
            entries=[
                LsSnapshotEntry(
                    pid=2000,
                    name="language_server_macos_arm",
                    language="Codeium",
                    memory_mb=2000.0,
                    memory_percent=6.0,
                    cpu_percent=10.0,
                    num_threads=8,
                    runtime_seconds=3500.0,
                    workspace="repos/surfmon",
                    orphaned=True,
                ),
            ],
            issues=["CRITICAL: language_server_macos_arm indexing non-existent workspace"],
        )

        mocker.patch("surfmon.cli.collect_process_infos", return_value=[])
        mocker.patch("surfmon.cli._extract_windsurf_version", return_value="2.5.0")
        mocker.patch("surfmon.cli._get_windsurf_uptime", return_value=3600.0)
        mocker.patch("surfmon.cli.capture_ls_snapshot", return_value=snapshot)

        result = runner.invoke(app, ["ls-snapshot"])
        assert result.exit_code == 0
        assert "Language Server Snapshot" in result.output

    def test_display_warning_memory(self, mocker):
        """Should display yellow color for warning memory (>512 MB total)."""
        from surfmon.monitor import LsSnapshot, LsSnapshotEntry

        snapshot = LsSnapshot(
            timestamp="2025-06-01T12:00:00+00:00",
            windsurf_version="",
            windsurf_uptime_seconds=0.0,
            total_ls_count=1,
            total_ls_memory_mb=600.0,
            orphaned_count=0,
            entries=[
                LsSnapshotEntry(
                    pid=3000,
                    name="node",
                    language="Python",
                    memory_mb=600.0,
                    memory_percent=1.8,
                    cpu_percent=2.0,
                    num_threads=12,
                    runtime_seconds=3400.0,
                    workspace="",
                    orphaned=False,
                ),
            ],
            issues=[],
        )

        mocker.patch("surfmon.cli.collect_process_infos", return_value=[])
        mocker.patch("surfmon.cli._extract_windsurf_version", return_value="")
        mocker.patch("surfmon.cli._get_windsurf_uptime", return_value=0.0)
        mocker.patch("surfmon.cli.capture_ls_snapshot", return_value=snapshot)

        result = runner.invoke(app, ["ls-snapshot"])
        assert result.exit_code == 0


class TestLsSnapshotMarkdownWithIssues:
    """Tests for _save_ls_snapshot_markdown with issues section."""

    def test_markdown_includes_issues(self, tmp_path):
        """Should include issues section in markdown output."""
        from surfmon.cli import _save_ls_snapshot_markdown
        from surfmon.monitor import LsSnapshot, LsSnapshotEntry

        snapshot = LsSnapshot(
            timestamp="2025-06-01T12:00:00+00:00",
            windsurf_version="2.5.0",
            windsurf_uptime_seconds=3600.0,
            total_ls_count=1,
            total_ls_memory_mb=1730.0,
            orphaned_count=1,
            entries=[
                LsSnapshotEntry(
                    pid=2000,
                    name="language_server_macos_arm",
                    language="Codeium",
                    memory_mb=1730.0,
                    memory_percent=5.0,
                    cpu_percent=10.0,
                    num_threads=8,
                    runtime_seconds=3500.0,
                    workspace="mcp/client/capabilities",
                    orphaned=True,
                ),
            ],
            issues=["CRITICAL: language_server indexing non-existent workspace 'mcp/client/capabilities'"],
        )

        md_path = tmp_path / "snapshot.md"
        _save_ls_snapshot_markdown(snapshot, md_path)

        content = md_path.read_text(encoding="utf-8")
        assert "## Issues" in content
        assert "CRITICAL" in content
        assert "ORPHANED" in content
        assert "mcp/client/capabilities" in content


class TestSaveSnapshotFiles:
    """Tests for _save_snapshot_files helper."""

    def test_saves_both_files(self, tmp_path):
        """Should save both JSON and Markdown when both paths given."""
        from surfmon.cli import _save_snapshot_files

        json_path = tmp_path / "test.json"
        md_path = tmp_path / "test.md"

        def save_json(_data, path):
            path.write_text("json", encoding="utf-8")

        def save_md(_data, path):
            path.write_text("md", encoding="utf-8")

        _save_snapshot_files(json_path, md_path, save_json, save_md, {})
        assert json_path.exists()
        assert md_path.exists()

    def test_skips_when_no_paths(self):
        """Should return immediately when no paths given."""
        from surfmon.cli import _save_snapshot_files

        _save_snapshot_files(None, None, None, None, {})

    def test_handles_json_save_error(self, tmp_path):
        """Should handle OSError when saving JSON."""
        from surfmon.cli import _save_snapshot_files

        def failing_save(_data, _path):
            msg = "Permission denied"
            raise OSError(msg)

        _save_snapshot_files(tmp_path / "test.json", None, failing_save, None, {})

    def test_handles_md_save_error(self, tmp_path):
        """Should handle OSError when saving Markdown."""
        from surfmon.cli import _save_snapshot_files

        def failing_save(_data, _path):
            msg = "Permission denied"
            raise OSError(msg)

        _save_snapshot_files(None, tmp_path / "test.md", None, failing_save, {})


class TestFormatUptime:
    """Tests for _format_uptime helper."""

    def test_format_hours(self):
        """Should format hours, minutes, seconds."""
        from surfmon.cli import _format_uptime

        assert _format_uptime(3661.0) == "1h 1m 1s"

    def test_format_minutes(self):
        """Should format minutes and seconds."""
        from surfmon.cli import _format_uptime

        assert _format_uptime(125.0) == "2m 5s"

    def test_format_seconds(self):
        """Should format seconds only."""
        from surfmon.cli import _format_uptime

        assert _format_uptime(42.0) == "42s"

    def test_format_zero(self):
        """Should return unknown for zero."""
        from surfmon.cli import _format_uptime

        assert _format_uptime(0.0) == "unknown"
