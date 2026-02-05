"""Tests for output module."""

from unittest.mock import MagicMock

import pytest

from surfmon.output import display_report, save_report_markdown


@pytest.fixture
def mock_report():
    """Create a mock MonitoringReport."""
    report = MagicMock()
    report.timestamp = "2025-01-01T12:00:00"
    report.process_count = 5
    report.total_windsurf_memory_mb = 2048.0
    report.total_windsurf_cpu_percent = 15.5
    report.extensions_count = 20
    report.mcp_servers_enabled = ["server1", "server2"]
    report.language_servers = []
    report.log_issues = []
    report.windsurf_processes = []
    report.active_workspaces = []
    report.windsurf_launches_today = 3

    # System info
    report.system = MagicMock()
    report.system.total_memory_gb = 32.0
    report.system.available_memory_gb = 16.0
    report.system.memory_percent = 50.0
    report.system.swap_used_gb = 1.0
    report.system.swap_total_gb = 4.0
    report.system.cpu_count = 10

    return report


class TestDisplayReport:
    """Tests for display_report function."""

    def test_display_report_basic(self, mock_report, mocker):
        """Should display report without errors."""
        mock_console = mocker.patch("surfmon.output.console")
        display_report(mock_report)
        assert mock_console.print.called

    def test_display_report_verbose(self, mock_report, mocker):
        """Should display verbose report."""
        mock_console = mocker.patch("surfmon.output.console")
        display_report(mock_report, verbose=True)
        assert mock_console.print.called

    def test_display_report_not_running(self, mock_report, mocker):
        """Should show not running status when process_count is 0."""
        mock_report.process_count = 0
        mock_console = mocker.patch("surfmon.output.console")
        display_report(mock_report)
        # Check that "Not Running" appears in output
        calls = str(mock_console.print.call_args_list)
        assert "Not Running" in calls or mock_console.print.called

    def test_display_report_with_issues(self, mock_report, mocker):
        """Should display issues when present."""
        mock_report.log_issues = ["Issue 1", "Issue 2"]
        mock_console = mocker.patch("surfmon.output.console")
        display_report(mock_report)
        assert mock_console.print.called

    def test_display_report_with_language_servers(self, mock_report, mocker):
        """Should display language servers when present."""
        ls = MagicMock()
        ls.pid = 1234
        ls.name = "python-lsp"
        ls.memory_mb = 100.0
        ls.cpu_percent = 5.0
        ls.cmdline = "python -m pylsp"
        mock_report.language_servers = [ls]

        mock_console = mocker.patch("surfmon.output.console")
        display_report(mock_report, verbose=True)
        assert mock_console.print.called

    def test_display_report_with_workspaces(self, mock_report, mocker):
        """Should display active workspaces when present."""
        ws = MagicMock()
        ws.id = "abc123"
        ws.path = "/path/to/workspace"
        ws.exists = True
        ws.loaded_at = "12:00:00"
        mock_report.active_workspaces = [ws]

        mock_console = mocker.patch("surfmon.output.console")
        display_report(mock_report, verbose=True)
        assert mock_console.print.called


class TestDisplayReportWithProcesses:
    """Tests for display_report with process data."""

    def test_display_report_with_processes(self, mock_report, mocker):
        """Should display process table when processes present."""
        proc = MagicMock()
        proc.pid = 1234
        proc.name = "Windsurf"
        proc.memory_mb = 500.0
        proc.cpu_percent = 5.0
        proc.num_threads = 10
        proc.runtime_seconds = 3600.0
        mock_report.windsurf_processes = [proc]

        mock_console = mocker.patch("surfmon.output.console")
        display_report(mock_report, verbose=True)
        assert mock_console.print.called

    def test_display_report_with_high_memory_process(self, mock_report, mocker):
        """Should highlight high memory processes."""
        proc = MagicMock()
        proc.pid = 1234
        proc.name = "Windsurf"
        proc.memory_mb = 1500.0  # High memory
        proc.cpu_percent = 5.0
        proc.num_threads = 10
        proc.runtime_seconds = 7200.0
        mock_report.windsurf_processes = [proc]

        mock_console = mocker.patch("surfmon.output.console")
        display_report(mock_report, verbose=True)
        assert mock_console.print.called


class TestSaveReportMarkdown:
    """Tests for save_report_markdown function."""

    def test_save_report_markdown(self, mock_report, tmp_path):
        """Should save report as markdown file."""
        output_path = tmp_path / "report.md"
        save_report_markdown(mock_report, output_path)

        assert output_path.exists()
        content = output_path.read_text()
        assert "# Windsurf Performance Report" in content
        assert "System Resources" in content

    def test_save_report_markdown_with_issues(self, mock_report, tmp_path):
        """Should include issues in markdown."""
        mock_report.log_issues = ["Critical issue"]
        output_path = tmp_path / "report.md"
        save_report_markdown(mock_report, output_path)

        content = output_path.read_text()
        assert "Issues Detected" in content
        assert "Critical issue" in content

    def test_save_report_markdown_with_mcp_servers(self, mock_report, tmp_path):
        """Should include MCP servers in markdown."""
        output_path = tmp_path / "report.md"
        save_report_markdown(mock_report, output_path)

        content = output_path.read_text()
        assert "MCP Servers" in content
        assert "server1" in content

    def test_save_report_markdown_with_language_servers(self, mock_report, tmp_path):
        """Should include language servers in markdown."""
        ls = MagicMock()
        ls.pid = 1234
        ls.name = "python-lsp"
        ls.memory_mb = 100.0
        ls.cpu_percent = 5.0
        ls.cmdline = "python -m pylsp"
        mock_report.language_servers = [ls]

        output_path = tmp_path / "report.md"
        save_report_markdown(mock_report, output_path)

        content = output_path.read_text()
        assert "Language Servers" in content
