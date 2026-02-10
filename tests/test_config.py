"""Tests for surfmon.config target detection and auto-detection."""

from unittest.mock import Mock

import psutil
import pytest

from surfmon.config import (
    WindsurfTarget,
    _detect_running_target,
    get_target,
    reset_target,
    set_target,
)


@pytest.fixture(autouse=True)
def _clean_target():
    """Reset target override before and after each test."""
    reset_target()
    yield
    reset_target()


class TestDetectRunningTarget:
    """Tests for _detect_running_target auto-detection."""

    def test_detects_next_when_running(self, mocker):
        """Should detect Windsurf Next from process exe path."""
        mock_proc = Mock()
        mock_proc.info = {
            "exe": "/Applications/Windsurf - Next.app/Contents/MacOS/Electron",
            "cmdline": ["/Applications/Windsurf - Next.app/Contents/MacOS/Electron"],
        }
        mocker.patch("psutil.process_iter", return_value=[mock_proc])

        result = _detect_running_target()

        assert result == WindsurfTarget.NEXT

    def test_detects_stable_when_running(self, mocker):
        """Should detect Windsurf Stable from process exe path."""
        mock_proc = Mock()
        mock_proc.info = {
            "exe": "/Applications/Windsurf.app/Contents/MacOS/Windsurf",
            "cmdline": ["/Applications/Windsurf.app/Contents/MacOS/Windsurf"],
        }
        mocker.patch("psutil.process_iter", return_value=[mock_proc])

        result = _detect_running_target()

        assert result == WindsurfTarget.STABLE

    def test_prefers_next_when_both_running(self, mocker):
        """Should prefer NEXT over STABLE when both are running."""
        stable_proc = Mock()
        stable_proc.info = {
            "exe": "/Applications/Windsurf.app/Contents/MacOS/Windsurf",
            "cmdline": ["/Applications/Windsurf.app/Contents/MacOS/Windsurf"],
        }
        next_proc = Mock()
        next_proc.info = {
            "exe": "/Applications/Windsurf - Next.app/Contents/MacOS/Electron",
            "cmdline": ["/Applications/Windsurf - Next.app/Contents/MacOS/Electron"],
        }
        mocker.patch("psutil.process_iter", return_value=[stable_proc, next_proc])

        result = _detect_running_target()

        assert result == WindsurfTarget.NEXT

    def test_returns_none_when_nothing_running(self, mocker):
        """Should return None when no Windsurf processes are found."""
        unrelated_proc = Mock()
        unrelated_proc.info = {
            "exe": "/usr/bin/python3",
            "cmdline": ["python3", "some_script.py"],
        }
        mocker.patch("psutil.process_iter", return_value=[unrelated_proc])

        result = _detect_running_target()

        assert result is None

    def test_returns_none_with_empty_process_list(self, mocker):
        """Should return None when no processes are enumerated."""
        mocker.patch("psutil.process_iter", return_value=[])

        result = _detect_running_target()

        assert result is None

    def test_handles_access_denied(self, mocker):
        """Should skip processes that raise AccessDenied."""
        good_proc = Mock()
        good_proc.info = {
            "exe": "/Applications/Windsurf - Next.app/Contents/MacOS/Electron",
            "cmdline": ["/Applications/Windsurf - Next.app/Contents/MacOS/Electron"],
        }
        bad_proc = Mock()
        bad_proc.info.__getitem__ = Mock(side_effect=psutil.AccessDenied())

        mocker.patch("psutil.process_iter", return_value=[bad_proc, good_proc])

        result = _detect_running_target()

        assert result == WindsurfTarget.NEXT

    def test_handles_no_such_process(self, mocker):
        """Should skip processes that raise NoSuchProcess."""
        bad_proc = Mock()
        bad_proc.info.__getitem__ = Mock(side_effect=psutil.NoSuchProcess(pid=999))

        mocker.patch("psutil.process_iter", return_value=[bad_proc])

        result = _detect_running_target()

        assert result is None

    def test_detects_from_cmdline(self, mocker):
        """Should detect target from cmdline when exe is empty."""
        helper_path = (
            "/Applications/Windsurf - Next.app/Contents/Frameworks/"
            "Windsurf - Next Helper (Plugin).app/Contents/MacOS/"
            "Windsurf - Next Helper (Plugin)"
        )
        mock_proc = Mock()
        mock_proc.info = {
            "exe": "",
            "cmdline": [helper_path],
        }
        mocker.patch("psutil.process_iter", return_value=[mock_proc])

        result = _detect_running_target()

        assert result == WindsurfTarget.NEXT


class TestGetTarget:
    """Tests for get_target with auto-detection fallback."""

    def test_programmatic_override_takes_priority(self, mocker):
        """Programmatic set_target should override everything."""
        mocker.patch("surfmon.config.config", return_value="next")
        mocker.patch("surfmon.config._detect_running_target", return_value=WindsurfTarget.STABLE)

        set_target(WindsurfTarget.STABLE)
        result = get_target()

        assert result == WindsurfTarget.STABLE

    def test_env_var_next_overrides_detection(self, mocker):
        """Explicit SURFMON_TARGET=next should override auto-detection."""
        mocker.patch("surfmon.config.config", return_value="next")
        mock_detect = mocker.patch("surfmon.config._detect_running_target")

        result = get_target()

        assert result == WindsurfTarget.NEXT
        mock_detect.assert_not_called()

    def test_env_var_stable_overrides_detection(self, mocker):
        """Explicit SURFMON_TARGET=stable should override auto-detection."""
        mocker.patch("surfmon.config.config", return_value="stable")
        mock_detect = mocker.patch("surfmon.config._detect_running_target")

        result = get_target()

        assert result == WindsurfTarget.STABLE
        mock_detect.assert_not_called()

    def test_auto_detects_when_no_env_var(self, mocker):
        """Should auto-detect target when SURFMON_TARGET is not set."""
        mocker.patch("surfmon.config.config", return_value="")
        mocker.patch("surfmon.config._detect_running_target", return_value=WindsurfTarget.NEXT)

        result = get_target()

        assert result == WindsurfTarget.NEXT

    def test_falls_back_to_stable_when_nothing_detected(self, mocker):
        """Should default to STABLE when no env var and no processes detected."""
        mocker.patch("surfmon.config.config", return_value="")
        mocker.patch("surfmon.config._detect_running_target", return_value=None)

        result = get_target()

        assert result == WindsurfTarget.STABLE
