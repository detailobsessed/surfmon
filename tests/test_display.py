"""Tests for surfmon.display — pure helper functions and formatters."""

from surfmon.display import (
    _fmt_gb,
    _fmt_or_dash,
    _fmt_styled_count,
    _format_change,
    _format_elapsed,
    _format_history_row,
    _ls_entry_status,
    _ls_mem_style,
    build_process_memory_history,
    simplify_process_name,
)
from surfmon.monitor import LsSnapshotEntry

# ---------------------------------------------------------------------------
# simplify_process_name
# ---------------------------------------------------------------------------


class TestSimplifyProcessName:
    def test_helper_with_parens(self):
        """Should extract type from 'Windsurf Helper (GPU)' → 'Windsurf Helper GPU'."""
        assert simplify_process_name("Windsurf Helper (GPU)") == "Windsurf Helper GPU"

    def test_helper_renderer(self):
        assert simplify_process_name("Windsurf Helper (Renderer)") == "Windsurf Helper Renderer"

    def test_no_parens_passthrough(self):
        """Non-helper names pass through unchanged."""
        assert simplify_process_name("Windsurf") == "Windsurf"

    def test_helper_without_parens(self):
        """'Helper' without parens passes through unchanged."""
        assert simplify_process_name("Windsurf Helper") == "Windsurf Helper"


# ---------------------------------------------------------------------------
# _fmt_gb
# ---------------------------------------------------------------------------


class TestFmtGb:
    def test_none_returns_dash(self):
        assert _fmt_gb(None) == "—"

    def test_zero_formats_as_zero(self):
        """0.0 MB should format as '0.00 GB', not '—'."""
        assert _fmt_gb(0.0) == "0.00 GB"

    def test_1024_mb_is_1_gb(self):
        assert _fmt_gb(1024.0) == "1.00 GB"

    def test_fractional(self):
        assert _fmt_gb(512.0) == "0.50 GB"


# ---------------------------------------------------------------------------
# _fmt_or_dash
# ---------------------------------------------------------------------------


class TestFmtOrDash:
    def test_truthy_value(self):
        assert _fmt_or_dash(42) == "42"

    def test_none_returns_dash(self):
        assert _fmt_or_dash(None) == "—"

    def test_empty_string_returns_dash(self):
        assert _fmt_or_dash("") == "—"

    def test_zero_returns_dash(self):
        assert _fmt_or_dash(0) == "—"

    def test_string_value(self):
        assert _fmt_or_dash("hello") == "hello"


# ---------------------------------------------------------------------------
# _fmt_styled_count
# ---------------------------------------------------------------------------


class TestFmtStyledCount:
    def test_none_returns_dash(self):
        assert _fmt_styled_count(None) == "—"

    def test_positive_wraps_in_bad_color(self):
        assert _fmt_styled_count(3) == "[red]3[/red]"

    def test_zero_with_good_color(self):
        assert _fmt_styled_count(0, good_color="green") == "[green]0[/green]"

    def test_zero_no_good_color_returns_dash(self):
        assert _fmt_styled_count(0) == "—"

    def test_custom_bad_color(self):
        assert _fmt_styled_count(5, bad_color="yellow") == "[yellow]5[/yellow]"


# ---------------------------------------------------------------------------
# _format_change
# ---------------------------------------------------------------------------


class TestFormatChange:
    def test_zero_diff_returns_empty(self):
        assert not _format_change(0.0)

    def test_below_threshold_returns_empty(self):
        assert not _format_change(0.005, threshold=0.01)

    def test_positive_diff_is_red_up_arrow(self):
        result = _format_change(3)
        assert "↑" in result
        assert "red" in result

    def test_negative_diff_is_green_down_arrow(self):
        result = _format_change(-2)
        assert "↓" in result
        assert "green" in result

    def test_fmt_and_suffix(self):
        result = _format_change(1.5, fmt=".1f", suffix="GB")
        assert "1.5GB" in result

    def test_at_threshold_boundary_returns_empty(self):
        assert not _format_change(0.01, threshold=0.01)

    def test_just_above_threshold(self):
        result = _format_change(0.011, threshold=0.01, fmt=".3f")
        assert result


# ---------------------------------------------------------------------------
# _format_elapsed
# ---------------------------------------------------------------------------


class TestFormatElapsed:
    def test_seconds_only(self):
        assert _format_elapsed(45) == "0:45"

    def test_minutes_and_seconds(self):
        assert _format_elapsed(125) == "2:05"

    def test_hours_minutes_seconds(self):
        assert _format_elapsed(3661) == "1:01:01"

    def test_zero(self):
        assert _format_elapsed(0) == "0:00"


# ---------------------------------------------------------------------------
# _format_history_row
# ---------------------------------------------------------------------------

_HISTORY_ROW = {
    "timestamp": "2025-01-01T10:00:00+00:00",
    "command": "check",
    "windsurf_version": "1.0.0",
    "total_memory_mb": 2048.0,
    "process_count": 5,
    "ls_count": 2,
    "ls_memory_mb": 512.0,
    "orphaned_count": 0,
    "pty_count": 3,
    "issue_count": 1,
}


class TestFormatHistoryRow:
    def test_timestamp_truncated_to_19_chars(self):
        result = _format_history_row(_HISTORY_ROW)
        assert result[0] == "2025-01-01T10:00:00"

    def test_command_passthrough(self):
        assert _format_history_row(_HISTORY_ROW)[1] == "check"

    def test_memory_formatted_as_gb(self):
        assert _format_history_row(_HISTORY_ROW)[3] == "2.00 GB"

    def test_null_timestamp(self):
        row = {**_HISTORY_ROW, "timestamp": None}
        assert not _format_history_row(row)[0]

    def test_null_pty_count(self):
        row = {**_HISTORY_ROW, "pty_count": None}
        assert _format_history_row(row)[8] == "—"


# ---------------------------------------------------------------------------
# build_process_memory_history
# ---------------------------------------------------------------------------


class TestBuildProcessMemoryHistory:
    def test_empty_reports(self):
        assert build_process_memory_history([]) == {}

    def test_single_report(self):
        reports = [{"windsurf_processes": [{"name": "Windsurf", "memory_mb": 100.0}]}]
        result = build_process_memory_history(reports)
        assert result == {"Windsurf": [100.0]}

    def test_process_missing_from_second_report_gets_zero(self):
        reports = [
            {"windsurf_processes": [{"name": "Windsurf", "memory_mb": 100.0}]},
            {"windsurf_processes": []},
        ]
        result = build_process_memory_history(reports)
        assert result["Windsurf"] == [100.0, 0]

    def test_new_process_in_second_report_pads_leading_zero(self):
        reports = [
            {"windsurf_processes": []},
            {"windsurf_processes": [{"name": "Windsurf", "memory_mb": 50.0}]},
        ]
        result = build_process_memory_history(reports)
        assert result["Windsurf"] == [0.0, 50.0]

    def test_aggregates_multiple_procs_with_same_name(self):
        reports = [
            {
                "windsurf_processes": [
                    {"name": "Windsurf", "memory_mb": 100.0},
                    {"name": "Windsurf", "memory_mb": 50.0},
                ]
            }
        ]
        result = build_process_memory_history(reports)
        assert result["Windsurf"] == [150.0]

    def test_simplifies_helper_names(self):
        reports = [{"windsurf_processes": [{"name": "Windsurf Helper (GPU)", "memory_mb": 80.0}]}]
        result = build_process_memory_history(reports)
        assert "Windsurf Helper GPU" in result


# ---------------------------------------------------------------------------
# _ls_entry_status
# ---------------------------------------------------------------------------


def _make_ls_entry(*, orphaned: bool = False, stale: bool = False) -> LsSnapshotEntry:
    return LsSnapshotEntry(
        pid=1234,
        name="language_server_macos_arm",
        language="python",
        memory_mb=100.0,
        memory_percent=1.0,
        cpu_percent=0.5,
        num_threads=4,
        runtime_seconds=60.0,
        workspace="/Users/test/project",
        orphaned=orphaned,
        stale=stale,
    )


class TestLsEntryStatus:
    def test_orphaned(self):
        assert _ls_entry_status(_make_ls_entry(orphaned=True)) == "[red]ORPHANED[/red]"

    def test_stale(self):
        assert _ls_entry_status(_make_ls_entry(stale=True)) == "[yellow]STALE[/yellow]"

    def test_ok(self):
        assert _ls_entry_status(_make_ls_entry()) == "[green]ok[/green]"


# ---------------------------------------------------------------------------
# _ls_mem_style
# ---------------------------------------------------------------------------


class TestLsMemStyle:
    def test_critical_above_500(self):
        assert _ls_mem_style(501.0) == "red"

    def test_warning_above_200(self):
        assert _ls_mem_style(300.0) == "yellow"

    def test_ok_below_200(self):
        assert _ls_mem_style(100.0) == "green"

    def test_exactly_at_critical_threshold(self):
        assert _ls_mem_style(500.0) == "yellow"
