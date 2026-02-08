"""Regression tests for bugs found in code review.

Bug #1: ZeroDivisionError when system total_memory_gb is 0
Bug #4: Operator precedence in process name simplification (latent, masked by guard)
Bug #5: Late-appearing processes have misaligned memory history in plots
"""

from unittest.mock import MagicMock

import pytest


class TestZeroDivisionWithZeroMemory:
    """Bug #1: ZeroDivisionError when total_memory_gb is 0.

    output.py:64, output.py:241, cli.py:110 all divide by
    report.system.total_memory_gb without guarding against zero.
    """

    @pytest.fixture
    def zero_memory_report(self):
        """Report where system total_memory_gb is 0 (edge case)."""
        report = MagicMock()
        report.timestamp = "2025-01-01T12:00:00"
        report.process_count = 5
        report.total_windsurf_memory_mb = 1000.0
        report.total_windsurf_cpu_percent = 10.0
        report.extensions_count = 10
        report.mcp_servers_enabled = []
        report.language_servers = []
        report.log_issues = []
        report.windsurf_processes = []
        report.active_workspaces = []
        report.windsurf_launches_today = 1
        report.pty_info = None
        report.system = MagicMock()
        report.system.total_memory_gb = 0.0
        report.system.available_memory_gb = 0.0
        report.system.memory_percent = 0.0
        report.system.swap_used_gb = 0.0
        report.system.swap_total_gb = 0.0
        report.system.cpu_count = 4
        return report

    def test_display_report_zero_total_memory(self, zero_memory_report, mocker):
        """display_report should handle zero total_memory_gb without ZeroDivisionError."""
        from surfmon.output import display_report

        mocker.patch("surfmon.output.console")
        display_report(zero_memory_report)

    def test_save_markdown_zero_total_memory(self, zero_memory_report, tmp_path):
        """save_report_markdown should handle zero total_memory_gb without ZeroDivisionError."""
        from surfmon.output import save_report_markdown

        output_path = tmp_path / "report.md"
        save_report_markdown(zero_memory_report, output_path)

    def test_create_summary_table_zero_total_memory(self, zero_memory_report):
        """create_summary_table should handle zero total_memory_gb without ZeroDivisionError."""
        from surfmon.cli import create_summary_table

        table = create_summary_table(zero_memory_report)
        assert table is not None


class TestProcessNameSimplification:
    """Bug #4: Operator precedence in process name simplification.

    cli.py:796 has a ternary with wrong precedence. Currently masked
    by the outer if guard, but the redundant ternary should be removed
    and the logic extracted for testability.
    """

    def test_helper_with_gpu_type(self):
        """'Windsurf Helper (GPU)' → 'Windsurf Helper GPU'."""
        from surfmon.cli import simplify_process_name

        assert simplify_process_name("Windsurf Helper (GPU)") == "Windsurf Helper GPU"

    def test_helper_with_renderer_type(self):
        """'Windsurf Helper (Renderer)' → 'Windsurf Helper Renderer'."""
        from surfmon.cli import simplify_process_name

        assert simplify_process_name("Windsurf Helper (Renderer)") == "Windsurf Helper Renderer"

    def test_helper_without_parens_unchanged(self):
        """'Windsurf Helper' should not be mangled."""
        from surfmon.cli import simplify_process_name

        result = simplify_process_name("Windsurf Helper")
        assert result == "Windsurf Helper"

    def test_non_helper_unchanged(self):
        """Non-helper names pass through unchanged."""
        from surfmon.cli import simplify_process_name

        assert simplify_process_name("Windsurf") == "Windsurf"
        assert simplify_process_name("Electron") == "Electron"


class TestProcessMemoryHistory:
    """Bug #5: Late-appearing processes have misaligned memory history.

    cli.py:800-807 doesn't insert leading zeros for processes that first
    appear in later reports. Their data gets shifted left in plots.
    """

    def test_late_process_has_leading_zeros(self):
        """Process appearing only in report 3 should have [0, 0, value]."""
        from surfmon.cli import build_process_memory_history

        reports = [
            {"windsurf_processes": [{"name": "Windsurf", "memory_mb": 500}]},
            {"windsurf_processes": [{"name": "Windsurf", "memory_mb": 600}]},
            {
                "windsurf_processes": [
                    {"name": "Windsurf", "memory_mb": 700},
                    {"name": "NewProc", "memory_mb": 200},
                ]
            },
        ]

        history = build_process_memory_history(reports)
        assert history["NewProc"] == [0, 0, 200]

    def test_all_histories_match_report_count(self):
        """Every process history length should equal number of reports."""
        from surfmon.cli import build_process_memory_history

        reports = [
            {"windsurf_processes": [{"name": "A", "memory_mb": 100}]},
            {"windsurf_processes": [{"name": "B", "memory_mb": 200}]},
            {
                "windsurf_processes": [
                    {"name": "A", "memory_mb": 150},
                    {"name": "C", "memory_mb": 300},
                ]
            },
        ]

        history = build_process_memory_history(reports)
        for name, mem_list in history.items():
            assert len(mem_list) == len(reports), f"'{name}' has {len(mem_list)} entries, expected {len(reports)}"

    def test_consistent_process_tracked_correctly(self):
        """Process present in all reports should have correct values throughout."""
        from surfmon.cli import build_process_memory_history

        reports = [
            {"windsurf_processes": [{"name": "Windsurf", "memory_mb": 500}]},
            {"windsurf_processes": [{"name": "Windsurf", "memory_mb": 600}]},
            {"windsurf_processes": [{"name": "Windsurf", "memory_mb": 700}]},
        ]

        history = build_process_memory_history(reports)
        assert history["Windsurf"] == [500, 600, 700]

    def test_disappearing_process_gets_trailing_zeros(self):
        """Process that stops appearing should get trailing zeros."""
        from surfmon.cli import build_process_memory_history

        reports = [
            {
                "windsurf_processes": [
                    {"name": "Windsurf", "memory_mb": 500},
                    {"name": "TempProc", "memory_mb": 100},
                ]
            },
            {"windsurf_processes": [{"name": "Windsurf", "memory_mb": 600}]},
            {"windsurf_processes": [{"name": "Windsurf", "memory_mb": 700}]},
        ]

        history = build_process_memory_history(reports)
        assert history["TempProc"] == [100, 0, 0]
