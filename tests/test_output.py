"""Tests for output module."""

from unittest.mock import MagicMock

import pytest

from surfmon.output import display_report, save_report_markdown

_P_CONSOLE = "surfmon.output.console"
_REPORT_MD = "report.md"


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
    report.pty_info = None
    report.ls_snapshot = None

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
        mock_console = mocker.patch(_P_CONSOLE)
        display_report(mock_report)
        assert mock_console.print.called

    def test_display_report_verbose(self, mock_report, mocker):
        """Should display verbose report."""
        mock_console = mocker.patch(_P_CONSOLE)
        display_report(mock_report, verbose=True)
        assert mock_console.print.called

    def test_display_report_not_running(self, mock_report, mocker):
        """Should split into Runtime and Configuration tables when not running."""
        from rich.table import Table

        mock_report.process_count = 0
        mock_console = mocker.patch(_P_CONSOLE)
        display_report(mock_report)
        table_titles = [
            arg.args[0].title
            for arg in mock_console.print.call_args_list
            if arg.args and isinstance(arg.args[0], Table) and hasattr(arg.args[0], "title")
        ]
        assert "Windsurf Runtime" in table_titles
        assert "Windsurf Configuration" in table_titles

    def test_display_report_not_running_no_config(self, mock_report, mocker):
        """Should skip Configuration table when nothing is configured."""
        from rich.table import Table

        mock_report.process_count = 0
        mock_report.extensions_count = 0
        mock_report.mcp_servers_enabled = []
        mock_report.active_workspaces = []
        mock_console = mocker.patch(_P_CONSOLE)
        display_report(mock_report)
        table_titles = [
            arg.args[0].title
            for arg in mock_console.print.call_args_list
            if arg.args and isinstance(arg.args[0], Table) and hasattr(arg.args[0], "title")
        ]
        assert "Windsurf Runtime" in table_titles
        assert "Windsurf Configuration" not in table_titles

    def test_display_report_with_issues(self, mock_report, mocker):
        """Should display issues when present."""
        mock_report.log_issues = ["Issue 1", "Issue 2"]
        mock_console = mocker.patch(_P_CONSOLE)
        display_report(mock_report)
        assert mock_console.print.called

    def test_display_report_with_language_servers(self, mock_report, mocker):
        """Should display language servers table via ls_snapshot."""
        from surfmon.monitor import LsSnapshot, LsSnapshotEntry

        entry = LsSnapshotEntry(
            pid=1234,
            name="python-lsp",
            language="Python",
            memory_mb=100.0,
            memory_percent=0.3,
            cpu_percent=5.0,
            num_threads=4,
            runtime_seconds=600.0,
            workspace="/home/user/project",
            orphaned=False,
            stale=False,
        )
        mock_report.ls_snapshot = LsSnapshot(
            timestamp="2025-01-01T12:00:00",
            windsurf_version="2.5.0",
            windsurf_uptime_seconds=3600.0,
            total_ls_count=1,
            total_ls_memory_mb=100.0,
            orphaned_count=0,
            stale_count=0,
            entries=[entry],
            orphan_issues=[],
            stale_issues=[],
        )

        mock_console = mocker.patch(_P_CONSOLE)
        display_report(mock_report, verbose=True)
        # Verify the LS snapshot table was rendered (console.print called with a Table)
        from rich.table import Table

        table_args = [call.args[0] for call in mock_console.print.call_args_list if call.args and isinstance(call.args[0], Table)]
        ls_tables = [t for t in table_args if t.title and "Language Servers" in t.title]
        assert ls_tables, "Expected a 'Language Servers' table to be printed"

    def test_display_report_with_workspaces(self, mock_report, mocker):
        """Should display active workspaces when present."""
        ws = MagicMock()
        ws.id = "abc123"
        ws.path = "/path/to/workspace"
        ws.exists = True
        ws.loaded_at = "12:00:00"
        mock_report.active_workspaces = [ws]

        mock_console = mocker.patch(_P_CONSOLE)
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

        mock_console = mocker.patch(_P_CONSOLE)
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

        mock_console = mocker.patch(_P_CONSOLE)
        display_report(mock_report, verbose=True)
        assert mock_console.print.called


class TestSaveReportMarkdown:
    """Tests for save_report_markdown function."""

    def test_save_report_markdown(self, mock_report, tmp_path):
        """Should save report as markdown file."""
        output_path = tmp_path / _REPORT_MD
        save_report_markdown(mock_report, output_path)

        assert output_path.exists()
        content = output_path.read_text(encoding="utf-8")
        assert "# Windsurf Performance Report" in content
        assert "System Resources" in content

    def test_save_report_markdown_with_issues(self, mock_report, tmp_path):
        """Should include issues in markdown."""
        mock_report.log_issues = ["Critical issue"]
        output_path = tmp_path / _REPORT_MD
        save_report_markdown(mock_report, output_path)

        content = output_path.read_text(encoding="utf-8")
        assert "Issues Detected" in content
        assert "Critical issue" in content

    def test_save_report_markdown_with_mcp_servers(self, mock_report, tmp_path):
        """Should include MCP servers in markdown."""
        output_path = tmp_path / _REPORT_MD
        save_report_markdown(mock_report, output_path)

        content = output_path.read_text(encoding="utf-8")
        assert "MCP Servers" in content
        assert "server1" in content

    def test_save_report_markdown_with_language_servers(self, mock_report, tmp_path):
        """Should include language servers table in markdown via ls_snapshot."""
        from surfmon.monitor import LsSnapshot, LsSnapshotEntry

        ls = MagicMock()
        ls.pid = 1234
        ls.name = "python-lsp"
        ls.memory_mb = 100.0
        ls.cpu_percent = 5.0
        ls.cmdline = "python -m pylsp"
        mock_report.language_servers = [ls]

        output_path = tmp_path / _REPORT_MD
        save_report_markdown(mock_report, output_path)

        content = output_path.read_text(encoding="utf-8")
        assert "## Language Servers" in content
        assert "python-lsp" not in content  # table uses entry.language, not name
        assert "Python" in content
        assert "/home/user/project" in content
