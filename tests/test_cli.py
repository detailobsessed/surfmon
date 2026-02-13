"""Tests for CLI functionality."""

import json
from unittest.mock import MagicMock

import pytest
from typer.testing import CliRunner

from surfmon.cli import app

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
        # Change to temp directory to avoid cluttering repo
        monkeypatch.chdir(tmp_path)

        mock_json = mocker.patch("surfmon.cli.save_report_json")
        mock_md = mocker.patch("surfmon.cli.save_report_markdown")
        mock_display = mocker.patch("surfmon.cli.display_report")

        result = runner.invoke(app, ["check", "--save"])

        assert result.exit_code == 0
        assert mock_json.called
        assert mock_md.called

        # Check that paths were auto-generated with timestamp
        json_path = mock_json.call_args[0][1]
        md_path = mock_md.call_args[0][1]
        assert json_path.name.startswith("surfmon-")
        assert json_path.name.endswith(".json")
        assert md_path.name.startswith("surfmon-")
        assert md_path.name.endswith(".md")

        # Check that verbose was enabled
        assert mock_display.call_args[1]["verbose"] is True

    def test_check_with_save_short_form(self, mock_generate_report, mock_display_report, tmp_path, monkeypatch, mocker):
        """Should save both reports with -s short form."""
        monkeypatch.chdir(tmp_path)

        mock_json = mocker.patch("surfmon.cli.save_report_json")
        mock_md = mocker.patch("surfmon.cli.save_report_markdown")

        result = runner.invoke(app, ["check", "-s"])

        assert result.exit_code == 0
        assert mock_json.called
        assert mock_md.called

    def test_check_with_explicit_json_path(
        self,
        mock_generate_report,
        mock_display_report,
        tmp_path,
        mocker,
    ):
        """Should save JSON to explicit path."""
        json_file = tmp_path / "test.json"

        mock_save = mocker.patch("surfmon.cli.save_report_json")
        result = runner.invoke(app, ["check", "--json", str(json_file)])

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

        result = runner.invoke(app, ["check", "--json", str(json_file), "--md", str(md_file)])

        assert result.exit_code == 0
        assert mock_json.called
        assert mock_md.called

    def test_check_rejects_json_without_path(self, mock_generate_report, mock_display_report):
        """Should reject --json without a path argument."""
        result = runner.invoke(app, ["check", "--json", "--md"])

        assert result.exit_code == 1
        assert "Error: --json requires a file path" in result.stdout

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
    """Tests for target option."""

    def test_target_stable(self, mock_generate_report, mock_display_report):
        """Should accept stable target."""
        result = runner.invoke(app, ["check", "--target", "stable"])
        assert result.exit_code == 0

    def test_target_next(self, mock_generate_report, mock_display_report):
        """Should accept next target."""
        result = runner.invoke(app, ["check", "--target", "next"])
        assert result.exit_code == 0

    def test_target_invalid(self):
        """Should reject invalid target."""
        result = runner.invoke(app, ["check", "--target", "invalid"])
        assert result.exit_code != 0
        assert "Invalid target" in result.stdout


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
