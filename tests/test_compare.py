"""Tests for compare module."""

import json

import pytest

from surfmon.compare import format_diff, format_memory, load_report


class TestFormatMemory:
    """Tests for format_memory function."""

    def test_format_memory_mb(self):
        """Should format small values as MB."""
        assert format_memory(500) == "500 MB"
        assert format_memory(100) == "100 MB"
        assert format_memory(1023) == "1023 MB"

    def test_format_memory_gb(self):
        """Should format large values as GB."""
        assert format_memory(1024) == "1.00 GB"
        assert format_memory(2048) == "2.00 GB"
        assert format_memory(1536) == "1.50 GB"


class TestFormatDiff:
    """Tests for format_diff function."""

    def test_format_diff_decrease(self):
        """Should show green for decrease (improvement)."""
        result = format_diff(100, 80)
        assert "[green]" in result
        assert "↓" in result
        assert "-20.0%" in result

    def test_format_diff_increase(self):
        """Should show red for increase (worse)."""
        result = format_diff(100, 120)
        assert "[red]" in result
        assert "↑" in result
        assert "+20.0%" in result

    def test_format_diff_no_change(self):
        """Should show dim for no change."""
        result = format_diff(100, 100)
        assert "[dim]" in result
        assert "→" in result

    def test_format_diff_reverse(self):
        """Should reverse colors when reverse=True."""
        # Increase is good when reversed
        result = format_diff(100, 120, reverse=True)
        assert "[green]" in result
        assert "↑" in result

        # Decrease is bad when reversed
        result = format_diff(100, 80, reverse=True)
        assert "[red]" in result
        assert "↓" in result

    def test_format_diff_memory(self):
        """Should format as memory when is_memory=True."""
        result = format_diff(1000, 2024, is_memory=True)
        assert "GB" in result or "MB" in result

    def test_format_diff_zero_old(self):
        """Should handle zero old value."""
        result = format_diff(0, 100)
        assert "0.0%" in result  # No division by zero


class TestLoadReport:
    """Tests for load_report function."""

    def test_load_report(self, tmp_path):
        """Should load JSON report from file."""
        report_data = {"timestamp": "2025-01-01", "process_count": 5}
        report_file = tmp_path / "report.json"
        report_file.write_text(json.dumps(report_data), encoding="utf-8")

        result = load_report(report_file)
        assert result == report_data

    def test_load_report_file_not_found(self, tmp_path):
        """Should raise error for missing file."""
        with pytest.raises(FileNotFoundError):
            load_report(tmp_path / "nonexistent.json")


class TestCompareReports:
    """Tests for compare_reports function."""

    def test_compare_reports_basic(self, tmp_path, mocker):
        """Should compare two reports successfully."""
        from surfmon.compare import compare_reports

        old_report = {
            "timestamp": "2025-01-01T10:00:00",
            "process_count": 5,
            "total_windsurf_memory_mb": 1000,
            "total_windsurf_cpu_percent": 10.0,
            "extensions_count": 20,
            "language_servers": [],
            "log_issues": [],
            "mcp_servers_enabled": [],
            "system": {
                "total_memory_gb": 32.0,
                "available_memory_gb": 16.0,
                "memory_percent": 50.0,
                "swap_used_gb": 1.0,
                "swap_total_gb": 4.0,
            },
            "windsurf_processes": [],
        }
        new_report = {
            "timestamp": "2025-01-01T12:00:00",
            "process_count": 7,
            "total_windsurf_memory_mb": 1500,
            "total_windsurf_cpu_percent": 15.0,
            "extensions_count": 22,
            "language_servers": [],
            "log_issues": [],
            "mcp_servers_enabled": [],
            "system": {
                "total_memory_gb": 32.0,
                "available_memory_gb": 14.0,
                "memory_percent": 56.0,
                "swap_used_gb": 1.5,
                "swap_total_gb": 4.0,
            },
            "windsurf_processes": [],
        }

        old_file = tmp_path / "old.json"
        new_file = tmp_path / "new.json"
        old_file.write_text(json.dumps(old_report), encoding="utf-8")
        new_file.write_text(json.dumps(new_report), encoding="utf-8")

        mocker.patch("surfmon.compare.console")
        compare_reports(old_file, new_file)

    def test_compare_reports_with_processes(self, tmp_path, mocker):
        """Should compare reports with process details."""
        from surfmon.compare import compare_reports

        old_report = {
            "timestamp": "2025-01-01T10:00:00",
            "process_count": 2,
            "total_windsurf_memory_mb": 500,
            "total_windsurf_cpu_percent": 5.0,
            "extensions_count": 10,
            "language_servers": [],
            "log_issues": [],
            "mcp_servers_enabled": [],
            "system": {
                "total_memory_gb": 32.0,
                "available_memory_gb": 20.0,
                "memory_percent": 37.5,
                "swap_used_gb": 0.5,
                "swap_total_gb": 4.0,
            },
            "windsurf_processes": [
                {"name": "Windsurf", "memory_mb": 300, "cpu_percent": 3.0},
                {"name": "Helper", "memory_mb": 200, "cpu_percent": 2.0},
            ],
        }
        new_report = {
            "timestamp": "2025-01-01T12:00:00",
            "process_count": 3,
            "total_windsurf_memory_mb": 800,
            "total_windsurf_cpu_percent": 8.0,
            "extensions_count": 12,
            "language_servers": [],
            "log_issues": [],
            "mcp_servers_enabled": [],
            "system": {
                "total_memory_gb": 32.0,
                "available_memory_gb": 18.0,
                "memory_percent": 43.75,
                "swap_used_gb": 0.8,
                "swap_total_gb": 4.0,
            },
            "windsurf_processes": [
                {"name": "Windsurf", "memory_mb": 400, "cpu_percent": 4.0},
                {"name": "Helper", "memory_mb": 250, "cpu_percent": 2.5},
                {"name": "Renderer", "memory_mb": 150, "cpu_percent": 1.5},
            ],
        }

        old_file = tmp_path / "old.json"
        new_file = tmp_path / "new.json"
        old_file.write_text(json.dumps(old_report), encoding="utf-8")
        new_file.write_text(json.dumps(new_report), encoding="utf-8")

        mocker.patch("surfmon.compare.console")
        compare_reports(old_file, new_file)

    def test_compare_reports_with_issues(self, tmp_path, mocker):
        """Should compare reports with issues."""
        from surfmon.compare import compare_reports

        old_report = {
            "timestamp": "2025-01-01T10:00:00",
            "process_count": 5,
            "total_windsurf_memory_mb": 1000,
            "total_windsurf_cpu_percent": 10.0,
            "extensions_count": 20,
            "language_servers": [],
            "log_issues": ["Old issue"],
            "mcp_servers_enabled": [],
            "system": {
                "total_memory_gb": 32.0,
                "available_memory_gb": 16.0,
                "memory_percent": 50.0,
                "swap_used_gb": 1.0,
                "swap_total_gb": 4.0,
            },
            "windsurf_processes": [],
        }
        new_report = {
            "timestamp": "2025-01-01T12:00:00",
            "process_count": 5,
            "total_windsurf_memory_mb": 1000,
            "total_windsurf_cpu_percent": 10.0,
            "extensions_count": 20,
            "language_servers": [],
            "log_issues": ["New issue 1", "New issue 2"],
            "mcp_servers_enabled": [],
            "system": {
                "total_memory_gb": 32.0,
                "available_memory_gb": 16.0,
                "memory_percent": 50.0,
                "swap_used_gb": 1.0,
                "swap_total_gb": 4.0,
            },
            "windsurf_processes": [],
        }

        old_file = tmp_path / "old.json"
        new_file = tmp_path / "new.json"
        old_file.write_text(json.dumps(old_report), encoding="utf-8")
        new_file.write_text(json.dumps(new_report), encoding="utf-8")

        mocker.patch("surfmon.compare.console")
        compare_reports(old_file, new_file)


class TestCompareReportsWithLanguageServers:
    """Tests for compare_reports with language server data."""

    def test_compare_reports_with_language_servers(self, tmp_path, mocker):
        """Should compare reports with language server changes."""
        from surfmon.compare import compare_reports

        old_report = {
            "timestamp": "2025-01-01T10:00:00",
            "process_count": 5,
            "total_windsurf_memory_mb": 1000,
            "total_windsurf_cpu_percent": 10.0,
            "extensions_count": 20,
            "language_servers": [
                {"pid": 1001, "name": "python-lsp", "memory_mb": 100, "cpu_percent": 2.0},
            ],
            "log_issues": [],
            "mcp_servers_enabled": [],
            "system": {
                "total_memory_gb": 32.0,
                "available_memory_gb": 16.0,
                "memory_percent": 50.0,
                "swap_used_gb": 1.0,
                "swap_total_gb": 4.0,
            },
            "windsurf_processes": [],
        }
        new_report = {
            "timestamp": "2025-01-01T12:00:00",
            "process_count": 5,
            "total_windsurf_memory_mb": 1000,
            "total_windsurf_cpu_percent": 10.0,
            "extensions_count": 20,
            "language_servers": [
                {"pid": 1001, "name": "python-lsp", "memory_mb": 150, "cpu_percent": 3.0},
                {"pid": 1002, "name": "rust-analyzer", "memory_mb": 200, "cpu_percent": 4.0},
            ],
            "log_issues": [],
            "mcp_servers_enabled": [],
            "system": {
                "total_memory_gb": 32.0,
                "available_memory_gb": 16.0,
                "memory_percent": 50.0,
                "swap_used_gb": 1.0,
                "swap_total_gb": 4.0,
            },
            "windsurf_processes": [],
        }

        old_file = tmp_path / "old_ls.json"
        new_file = tmp_path / "new_ls.json"
        old_file.write_text(json.dumps(old_report), encoding="utf-8")
        new_file.write_text(json.dumps(new_report), encoding="utf-8")

        mocker.patch("surfmon.compare.console")
        compare_reports(old_file, new_file)
