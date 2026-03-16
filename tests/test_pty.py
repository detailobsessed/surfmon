"""Tests for PTY leak detection and forensic analysis."""

from unittest.mock import Mock

from surfmon.monitor import ProcessInfo
from surfmon.pty import (
    PtyFdEntry,
    PtyInfo,
    _classify_pty_issues,
    _get_system_pty_limit,
    _group_entries_by_pid,
    _parse_lsof_line,
    check_pty_leak,
)

_P_SUBPROCESS_RUN = "surfmon.pty.subprocess.run"
_WINDSURF_NAME = "Windsurf"
_LSOF_HEADER = "COMMAND     PID  USER   FD   TYPE DEVICE SIZE/OFF NODE NAME"


class TestCheckPtyLeak:
    """Tests for check_pty_leak."""

    def test_returns_pty_info(self, mocker):
        """Should return PtyInfo with counts."""
        mock_run = mocker.patch(_P_SUBPROCESS_RUN)

        # Mock sysctl
        sysctl_result = Mock()
        sysctl_result.returncode = 0
        sysctl_result.stdout = "511\n"

        # Mock lsof - simulate Windsurf holding many PTYs
        lsof_lines = [
            _LSOF_HEADER,
            *[f"Windsurf  75486 ismar   {32 + i}u   CHR   15,{i}      0t0  605 /dev/ptmx" for i in range(504)],
            "preview   50510 ismar   55u   CHR   15,5 0t222204  605 /dev/ptmx",
        ]

        lsof_result = Mock()
        lsof_result.returncode = 0
        lsof_result.stdout = "\n".join(lsof_lines)

        mock_run.side_effect = [sysctl_result, lsof_result]

        result = check_pty_leak()

        assert isinstance(result, PtyInfo)
        assert result.windsurf_pty_count == 504
        assert result.system_pty_limit == 511
        assert result.system_pty_used == 505  # 504 Windsurf + 1 preview

    def test_handles_sysctl_failure(self, mocker):
        """Should use default limit when sysctl fails."""
        mock_run = mocker.patch(_P_SUBPROCESS_RUN)

        sysctl_result = Mock()
        sysctl_result.returncode = 1
        sysctl_result.stdout = ""

        lsof_result = Mock()
        lsof_result.returncode = 0
        lsof_result.stdout = "COMMAND     PID  USER   FD   TYPE\n"

        mock_run.side_effect = [sysctl_result, lsof_result]

        result = check_pty_leak()

        assert result.system_pty_limit == 511  # Default

    def test_handles_lsof_failure(self, mocker):
        """Should return zero counts when lsof fails."""
        mock_run = mocker.patch(_P_SUBPROCESS_RUN)

        sysctl_result = Mock()
        sysctl_result.returncode = 0
        sysctl_result.stdout = "511\n"

        lsof_result = Mock()
        lsof_result.returncode = 1
        lsof_result.stdout = ""

        mock_run.side_effect = [sysctl_result, lsof_result]

        result = check_pty_leak()

        assert result.windsurf_pty_count == 0
        assert result.system_pty_used == 0

    def test_handles_timeout(self, mocker):
        """Should handle subprocess timeout gracefully."""
        import subprocess

        mock_run = mocker.patch(_P_SUBPROCESS_RUN)
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="lsof", timeout=10)

        result = check_pty_leak()

        assert result.windsurf_pty_count == 0
        assert result.system_pty_limit == 511

    def test_no_windsurf_ptys(self, mocker):
        """Should correctly count zero Windsurf PTYs when only other apps use them."""
        mock_run = mocker.patch(_P_SUBPROCESS_RUN)

        sysctl_result = Mock()
        sysctl_result.returncode = 0
        sysctl_result.stdout = "511\n"

        lsof_result = Mock()
        lsof_result.returncode = 0
        lsof_result.stdout = (
            "COMMAND     PID  USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n"
            "preview   50510 ismar   55u   CHR   15,5 0t222204  605 /dev/ptmx\n"
            "Terminal  12345 ismar   10u   CHR   15,6      0t0  605 /dev/ptmx\n"
        )

        mock_run.side_effect = [sysctl_result, lsof_result]

        result = check_pty_leak()

        assert result.windsurf_pty_count == 0
        assert result.system_pty_used == 2


class TestClassifyPtyIssues:
    """Tests for _classify_pty_issues helper."""

    def test_no_ptys_no_issues(self):
        assert _classify_pty_issues(0, 0, 511) == []

    def test_below_warning_threshold_no_issues(self):
        assert _classify_pty_issues(10, 20, 511) == []

    def test_warning_threshold(self):
        issues = _classify_pty_issues(50, 60, 511)
        assert len(issues) == 1
        assert "PTY leak" in issues[0].message
        assert issues[0].severity.marker == "\u26a0"

    def test_critical_by_count(self):
        issues = _classify_pty_issues(200, 210, 511)
        assert len(issues) == 1
        assert issues[0].severity.value == "critical"
        assert issues[0].severity.marker == "\u2716"

    def test_critical_by_usage_percent(self):
        issues = _classify_pty_issues(50, 420, 511)
        assert len(issues) == 1
        assert issues[0].severity.value == "critical"

    def test_zero_pty_limit_no_crash(self):
        assert _classify_pty_issues(0, 0, 0) == []


class TestParseLsofLine:
    """Tests for _parse_lsof_line."""

    def test_parses_valid_line(self):
        """Should parse a standard lsof output line into PtyFdEntry."""
        line = "Windsurf  75486 ismar   33u   CHR   15,0      0t0  605 /dev/ptmx"
        result = _parse_lsof_line(line)

        assert result is not None
        assert result.command == "Windsurf"
        assert result.pid == 75486
        assert result.fd == "33u"
        assert result.device == "15,0"
        assert result.size_off == "0t0"

    def test_parses_active_line_with_offset(self):
        """Should parse a line with non-zero offset."""
        line = "preview   50510 ismar   55u   CHR   15,5 0t222204  605 /dev/ptmx"
        result = _parse_lsof_line(line)

        assert result is not None
        assert result.command == "preview"
        assert result.pid == 50510
        assert result.size_off == "0t222204"

    def test_returns_none_for_short_line(self):
        """Should return None if line has fewer than LSOF_MIN_FIELDS fields."""
        result = _parse_lsof_line("too few fields")
        assert result is None

    def test_returns_none_for_empty_line(self):
        """Should return None for empty string."""
        result = _parse_lsof_line("")
        assert result is None

    def test_returns_none_for_non_integer_pid(self):
        """Should return None if PID field is not a valid integer."""
        line = "WARNING  notapid ismar   33u   CHR   15,0      0t0  605 /dev/ptmx"
        result = _parse_lsof_line(line)
        assert result is None


class TestGroupEntriesByPid:
    """Tests for _group_entries_by_pid."""

    def test_groups_entries_correctly(self):
        """Should group entries by PID and count them."""
        entries = [
            PtyFdEntry(command="Windsurf", pid=100, fd="33u", device="15,0", size_off="0t0"),
            PtyFdEntry(command="Windsurf", pid=100, fd="34u", device="15,1", size_off="0t0"),
            PtyFdEntry(command="Windsurf", pid=100, fd="35u", device="15,2", size_off="0t100"),
            PtyFdEntry(command="Windsurf", pid=200, fd="10u", device="15,3", size_off="0t0"),
        ]
        result = _group_entries_by_pid(entries)

        assert len(result) == 2
        # Sorted by count descending
        assert result[0].pid == 100
        assert result[0].pty_count == 3
        assert result[0].fds == ["33u", "34u", "35u"]
        assert result[1].pid == 200
        assert result[1].pty_count == 1

    def test_returns_empty_for_no_entries(self):
        """Should return empty list for no entries."""
        result = _group_entries_by_pid([])
        assert result == []

    def test_single_entry(self):
        """Should handle a single entry."""
        entries = [PtyFdEntry(command="App", pid=42, fd="5u", device="15,0", size_off="0t0")]
        result = _group_entries_by_pid(entries)

        assert len(result) == 1
        assert result[0].pid == 42
        assert result[0].name == "App"
        assert result[0].pty_count == 1


class TestGetSystemPtyLimit:
    """Tests for _get_system_pty_limit."""

    def test_returns_limit_from_sysctl(self, mocker):
        """Should return the parsed sysctl value."""
        mock_run = mocker.patch(_P_SUBPROCESS_RUN)
        result_mock = Mock()
        result_mock.returncode = 0
        result_mock.stdout = "1024\n"
        mock_run.return_value = result_mock

        assert _get_system_pty_limit() == 1024

    def test_returns_default_on_failure(self, mocker):
        """Should return 511 when sysctl fails."""
        mock_run = mocker.patch(_P_SUBPROCESS_RUN)
        result_mock = Mock()
        result_mock.returncode = 1
        result_mock.stdout = ""
        mock_run.return_value = result_mock

        assert _get_system_pty_limit() == 511


class TestCheckPtyLeakForensic:
    """Tests for check_pty_leak forensic data collection."""

    def test_populates_per_process_detail(self, mocker):
        """Should populate per_process with per-PID breakdown."""
        mock_run = mocker.patch(_P_SUBPROCESS_RUN)

        sysctl_result = Mock()
        sysctl_result.returncode = 0
        sysctl_result.stdout = "511\n"

        lsof_lines = [
            _LSOF_HEADER,
            "Windsurf  1000 ismar   33u   CHR   15,0      0t0  605 /dev/ptmx",
            "Windsurf  1000 ismar   34u   CHR   15,1 0t100000  605 /dev/ptmx",
            "Windsurf  2000 ismar   10u   CHR   15,2      0t0  605 /dev/ptmx",
            "Terminal  3000 ismar   5u    CHR   15,3 0t500000  605 /dev/ptmx",
        ]
        lsof_result = Mock()
        lsof_result.returncode = 0
        lsof_result.stdout = "\n".join(lsof_lines)

        mock_run.side_effect = [sysctl_result, lsof_result]

        result = check_pty_leak()

        assert result.windsurf_pty_count == 3
        assert result.system_pty_used == 4

        # Per-process detail
        assert result.per_process is not None
        assert len(result.per_process) == 2
        assert result.per_process[0].pid == 1000
        assert result.per_process[0].pty_count == 2
        assert result.per_process[1].pid == 2000
        assert result.per_process[1].pty_count == 1

        # FD entries
        assert result.fd_entries is not None
        assert len(result.fd_entries) == 3

        # Non-Windsurf holders
        assert result.non_windsurf_holders is not None
        assert len(result.non_windsurf_holders) == 1
        assert result.non_windsurf_holders[0].pid == 3000
        assert result.non_windsurf_holders[0].name == "Terminal"

        # Raw lsof preserved
        assert result.raw_lsof
        assert "Windsurf" in result.raw_lsof

    def test_extracts_version_and_uptime(self, mocker):
        """Should extract version and uptime when process list is provided."""
        mock_run = mocker.patch(_P_SUBPROCESS_RUN)

        sysctl_result = Mock()
        sysctl_result.returncode = 0
        sysctl_result.stdout = "511\n"

        lsof_result = Mock()
        lsof_result.returncode = 0
        lsof_result.stdout = "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"

        mock_run.side_effect = [sysctl_result, lsof_result]

        procs = [
            ProcessInfo(
                pid=1,
                name="Windsurf",
                cpu_percent=0.0,
                memory_mb=100.0,
                memory_percent=1.0,
                num_threads=10,
                runtime_seconds=7200.0,
                cmdline="/path/Windsurf --windsurf_version 2.5.0",
            ),
        ]
        result = check_pty_leak(windsurf_processes=procs)

        assert result.windsurf_version == "2.5.0"
        assert result.windsurf_uptime_seconds == 7200.0

    def test_backwards_compatible_without_processes(self, mocker):
        """Should work without process list (backwards-compatible)."""
        mock_run = mocker.patch(_P_SUBPROCESS_RUN)

        sysctl_result = Mock()
        sysctl_result.returncode = 0
        sysctl_result.stdout = "511\n"

        lsof_result = Mock()
        lsof_result.returncode = 0
        lsof_result.stdout = "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"

        mock_run.side_effect = [sysctl_result, lsof_result]

        result = check_pty_leak()

        assert not result.windsurf_version
        assert result.windsurf_uptime_seconds == 0.0
        assert result.per_process == []
        assert result.fd_entries == []

    def test_fd_detail_captures_offset(self, mocker):
        """Should capture offset values for active/idle FD classification."""
        mock_run = mocker.patch(_P_SUBPROCESS_RUN)

        sysctl_result = Mock()
        sysctl_result.returncode = 0
        sysctl_result.stdout = "511\n"

        lsof_lines = [
            _LSOF_HEADER,
            "Windsurf  1000 ismar   33u   CHR   15,0      0t0  605 /dev/ptmx",
            "Windsurf  1000 ismar   34u   CHR   15,1 0t999999  605 /dev/ptmx",
        ]
        lsof_result = Mock()
        lsof_result.returncode = 0
        lsof_result.stdout = "\n".join(lsof_lines)

        mock_run.side_effect = [sysctl_result, lsof_result]

        result = check_pty_leak()

        assert result.fd_entries is not None
        assert len(result.fd_entries) == 2
        idle_fds = [e for e in result.fd_entries if e.size_off == "0t0"]
        active_fds = [e for e in result.fd_entries if e.size_off != "0t0"]
        assert len(idle_fds) == 1
        assert len(active_fds) == 1
