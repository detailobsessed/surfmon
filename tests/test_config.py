"""Tests for surfmon.config target detection and auto-detection."""

from unittest.mock import Mock

import psutil
import pytest

from surfmon.config import (
    TargetNotSetError,
    WindsurfTarget,
    _detect_running_target,
    get_target,
    reset_target,
    set_target,
)

_P_PROC_ITER = "psutil.process_iter"
_P_CONFIG = "surfmon.config.config"
_NEXT_EXE = "/Applications/Windsurf - Next.app/Contents/MacOS/Electron"
_INSIDERS_EXE = "/Applications/Windsurf - Insiders.app/Contents/MacOS/Electron"
_STABLE_EXE = "/Applications/Windsurf.app/Contents/MacOS/Windsurf"


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
            "exe": _NEXT_EXE,
            "cmdline": [_NEXT_EXE],
        }
        mocker.patch(_P_PROC_ITER, return_value=[mock_proc])

        result = _detect_running_target()

        assert result == WindsurfTarget.NEXT

    def test_detects_insiders_when_running(self, mocker):
        """Should detect Windsurf Insiders from process exe path."""
        mock_proc = Mock()
        mock_proc.info = {
            "exe": _INSIDERS_EXE,
            "cmdline": [_INSIDERS_EXE],
        }
        mocker.patch(_P_PROC_ITER, return_value=[mock_proc])

        result = _detect_running_target()

        assert result == WindsurfTarget.INSIDERS

    def test_detects_stable_when_running(self, mocker):
        """Should detect Windsurf Stable from process exe path."""
        mock_proc = Mock()
        mock_proc.info = {
            "exe": _STABLE_EXE,
            "cmdline": [_STABLE_EXE],
        }
        mocker.patch(_P_PROC_ITER, return_value=[mock_proc])

        result = _detect_running_target()

        assert result == WindsurfTarget.STABLE

    def test_prefers_next_when_both_running(self, mocker):
        """Should prefer NEXT over STABLE when both are running."""
        stable_proc = Mock()
        stable_proc.info = {
            "exe": _STABLE_EXE,
            "cmdline": [_STABLE_EXE],
        }
        next_proc = Mock()
        next_proc.info = {
            "exe": _NEXT_EXE,
            "cmdline": [_NEXT_EXE],
        }
        mocker.patch(_P_PROC_ITER, return_value=[stable_proc, next_proc])

        result = _detect_running_target()

        assert result == WindsurfTarget.NEXT

    def test_prefers_next_when_next_and_insiders_running(self, mocker):
        """Should prefer NEXT over INSIDERS when multiple are running."""
        insiders_proc = Mock()
        insiders_proc.info = {
            "exe": _INSIDERS_EXE,
            "cmdline": [_INSIDERS_EXE],
        }
        next_proc = Mock()
        next_proc.info = {
            "exe": _NEXT_EXE,
            "cmdline": [_NEXT_EXE],
        }
        mocker.patch(_P_PROC_ITER, return_value=[insiders_proc, next_proc])

        result = _detect_running_target()

        assert result == WindsurfTarget.NEXT

    def test_returns_none_when_nothing_running(self, mocker):
        """Should return None when no Windsurf processes are found."""
        unrelated_proc = Mock()
        unrelated_proc.info = {
            "exe": "/usr/bin/python3",
            "cmdline": ["python3", "some_script.py"],
        }
        mocker.patch(_P_PROC_ITER, return_value=[unrelated_proc])

        result = _detect_running_target()

        assert result is None

    def test_returns_none_with_empty_process_list(self, mocker):
        """Should return None when no processes are enumerated."""
        mocker.patch(_P_PROC_ITER, return_value=[])

        result = _detect_running_target()

        assert result is None

    def test_handles_access_denied(self, mocker):
        """Should skip processes that raise AccessDenied."""
        good_proc = Mock()
        good_proc.info = {
            "exe": _NEXT_EXE,
            "cmdline": [_NEXT_EXE],
        }
        bad_proc = Mock()
        bad_proc.info.__getitem__ = Mock(side_effect=psutil.AccessDenied())

        mocker.patch(_P_PROC_ITER, return_value=[bad_proc, good_proc])

        result = _detect_running_target()

        assert result == WindsurfTarget.NEXT

    def test_handles_no_such_process(self, mocker):
        """Should skip processes that raise NoSuchProcess."""
        bad_proc = Mock()
        bad_proc.info.__getitem__ = Mock(side_effect=psutil.NoSuchProcess(pid=999))

        mocker.patch(_P_PROC_ITER, return_value=[bad_proc])

        result = _detect_running_target()

        assert result is None

    def test_ignores_orphaned_crashpad_handler(self, mocker):
        """Should ignore crashpad handlers so orphaned ones don't influence detection."""
        crashpad_proc = Mock()
        crashpad_proc.info = {
            "exe": "/Applications/Windsurf - Next.app/Contents/Frameworks/Electron Framework.framework/Helpers/chrome_crashpad_handler",
            "cmdline": [
                "/Applications/Windsurf - Next.app/Contents/Frameworks/Electron Framework.framework/Helpers/chrome_crashpad_handler",
                "--no-rate-limit",
            ],
        }
        insiders_proc = Mock()
        insiders_proc.info = {
            "exe": _INSIDERS_EXE,
            "cmdline": [_INSIDERS_EXE],
        }
        mocker.patch(_P_PROC_ITER, return_value=[crashpad_proc, insiders_proc])

        result = _detect_running_target()

        assert result == WindsurfTarget.INSIDERS

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
        mocker.patch(_P_PROC_ITER, return_value=[mock_proc])

        result = _detect_running_target()

        assert result == WindsurfTarget.NEXT


class TestGetTarget:
    """Tests for get_target with explicit target requirement."""

    def test_programmatic_override_takes_priority(self, mocker):
        """Programmatic set_target should override everything."""
        mocker.patch(_P_CONFIG, return_value="next")

        set_target(WindsurfTarget.STABLE)
        result = get_target()

        assert result == WindsurfTarget.STABLE

    def test_env_var_next(self, mocker):
        """Explicit SURFMON_TARGET=next should work."""
        mocker.patch(_P_CONFIG, return_value="next")

        result = get_target()

        assert result == WindsurfTarget.NEXT

    def test_env_var_insiders(self, mocker):
        """Explicit SURFMON_TARGET=insiders should work."""
        mocker.patch(_P_CONFIG, return_value="insiders")

        result = get_target()

        assert result == WindsurfTarget.INSIDERS

    def test_env_var_stable(self, mocker):
        """Explicit SURFMON_TARGET=stable should work."""
        mocker.patch(_P_CONFIG, return_value="stable")

        result = get_target()

        assert result == WindsurfTarget.STABLE

    def test_raises_when_no_target_configured(self, mocker):
        """Should raise TargetNotSetError when no target is set."""
        mocker.patch(_P_CONFIG, return_value="")

        with pytest.raises(TargetNotSetError):
            get_target()
