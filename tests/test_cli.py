"""Tests for CLI functionality."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from surfmon.cli import app

runner = CliRunner()


@pytest.fixture
def mock_generate_report():
    """Mock generate_report to avoid actual system calls."""
    with patch("surfmon.cli.generate_report") as mock:
        # Create a minimal mock report
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
        mock.return_value = mock_report
        yield mock


@pytest.fixture
def mock_display_report():
    """Mock display_report to avoid terminal output."""
    with patch("surfmon.cli.display_report"):
        yield


class TestCheckCommand:
    """Tests for the check command."""

    def test_check_basic(self, mock_generate_report, mock_display_report):
        """Should run check command successfully."""
        result = runner.invoke(app, ["check"])
        assert result.exit_code == 0

    def test_check_with_save_flag(
        self, mock_generate_report, mock_display_report, tmp_path, monkeypatch
    ):
        """Should save both JSON and Markdown with --save flag and enable verbose."""
        # Change to temp directory to avoid cluttering repo
        monkeypatch.chdir(tmp_path)

        with (
            patch("surfmon.cli.save_report_json") as mock_json,
            patch("surfmon.cli.save_report_markdown") as mock_md,
            patch("surfmon.cli.display_report") as mock_display,
        ):
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

    def test_check_with_save_short_form(
        self, mock_generate_report, mock_display_report, tmp_path, monkeypatch
    ):
        """Should save both reports with -s short form."""
        monkeypatch.chdir(tmp_path)

        with (
            patch("surfmon.cli.save_report_json") as mock_json,
            patch("surfmon.cli.save_report_markdown") as mock_md,
        ):
            result = runner.invoke(app, ["check", "-s"])

            assert result.exit_code == 0
            assert mock_json.called
            assert mock_md.called

    def test_check_with_explicit_json_path(
        self, mock_generate_report, mock_display_report, tmp_path
    ):
        """Should save JSON to explicit path."""
        json_file = tmp_path / "test.json"

        with patch("surfmon.cli.save_report_json") as mock_save:
            result = runner.invoke(app, ["check", "--json", str(json_file)])

            assert result.exit_code == 0
            assert mock_save.called
            # Check that absolute path was used
            saved_path = mock_save.call_args[0][1]
            assert saved_path.is_absolute()

    def test_check_with_explicit_md_path(
        self, mock_generate_report, mock_display_report, tmp_path
    ):
        """Should save Markdown to explicit path."""
        md_file = tmp_path / "test.md"

        with patch("surfmon.cli.save_report_markdown") as mock_save:
            result = runner.invoke(app, ["check", "--md", str(md_file)])

            assert result.exit_code == 0
            assert mock_save.called
            saved_path = mock_save.call_args[0][1]
            assert saved_path.is_absolute()

    def test_check_with_both_explicit_paths(
        self, mock_generate_report, mock_display_report, tmp_path
    ):
        """Should save both formats to explicit paths."""
        json_file = tmp_path / "test.json"
        md_file = tmp_path / "test.md"

        with (
            patch("surfmon.cli.save_report_json") as mock_json,
            patch("surfmon.cli.save_report_markdown") as mock_md,
        ):
            result = runner.invoke(
                app, ["check", "--json", str(json_file), "--md", str(md_file)]
            )

            assert result.exit_code == 0
            assert mock_json.called
            assert mock_md.called

    def test_check_rejects_json_without_path(
        self, mock_generate_report, mock_display_report
    ):
        """Should reject --json without a path argument."""
        result = runner.invoke(app, ["check", "--json", "--md"])

        assert result.exit_code == 1
        assert "Error: --json requires a file path" in result.stdout

    def test_check_rejects_md_without_path(
        self, mock_generate_report, mock_display_report
    ):
        """Should reject --md without a path argument."""
        result = runner.invoke(app, ["check", "--md", "--verbose"])

        assert result.exit_code == 1
        assert "Error: --md requires a file path" in result.stdout

    def test_check_verbose_flag(self, mock_generate_report, mock_display_report):
        """Should accept verbose flag."""
        with patch("surfmon.cli.display_report") as mock_display:
            result = runner.invoke(app, ["check", "--verbose"])

            assert result.exit_code == 0
            # Check that verbose was passed
            assert mock_display.call_args[1]["verbose"] is True

    def test_check_exits_with_error_on_issues(
        self, mock_generate_report, mock_display_report
    ):
        """Should exit with code 1 when critical issues detected."""
        # Mock report with issues
        mock_generate_report.return_value.log_issues = ["Critical error"]

        result = runner.invoke(app, ["check"])

        assert result.exit_code == 1
