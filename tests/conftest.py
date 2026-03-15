"""Shared pytest fixtures for surfmon tests."""

import json
from datetime import datetime
from unittest.mock import MagicMock, Mock

import psutil
import pytest

from surfmon.config import WindsurfTarget, reset_target, set_target


@pytest.fixture(autouse=True)
def _default_target():
    """Set a default target for all tests so code calling get_target() doesn't fail."""
    set_target(WindsurfTarget.STABLE)
    yield
    reset_target()


@pytest.fixture(autouse=True)
def _mock_db_writes(monkeypatch):
    """Prevent CLI commands from opening real DB connections during tests."""
    monkeypatch.setattr("surfmon.cli._store_to_db", lambda *_args, **_kwargs: None)


@pytest.fixture
def mock_process():
    """Create a mock psutil.Process."""
    proc = Mock(spec=psutil.Process)
    proc.pid = 1234
    proc.name.return_value = "Windsurf Helper"
    proc.cmdline.return_value = ["/path/to/windsurf", "--arg"]
    proc.cpu_percent.return_value = 5.0
    proc.memory_info.return_value = Mock(rss=100 * 1024 * 1024)  # 100 MB
    proc.memory_percent.return_value = 1.5
    proc.num_threads.return_value = 10
    proc.create_time.return_value = 1000.0
    # Make oneshot() a context manager
    proc.oneshot.return_value.__enter__ = Mock(return_value=proc)
    proc.oneshot.return_value.__exit__ = Mock(return_value=False)
    return proc


@pytest.fixture
def mock_system_info():
    """Create mock system info."""
    mem = Mock()
    mem.total = 32 * 1024 * 1024 * 1024  # 32 GB
    mem.available = 16 * 1024 * 1024 * 1024  # 16 GB
    mem.percent = 50.0

    swap = Mock()
    swap.total = 4 * 1024 * 1024 * 1024  # 4 GB
    swap.used = 1 * 1024 * 1024 * 1024  # 1 GB

    return mem, swap


@pytest.fixture
def mock_monitoring_report():
    """Create a mock MonitoringReport with realistic data."""
    report = MagicMock()
    report.timestamp = datetime.now().isoformat()
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


@pytest.fixture
def sample_report_data():
    """Return sample report data as a dictionary."""
    return {
        "timestamp": datetime.now().isoformat(),
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
        "windsurf_processes": [
            {"name": "Windsurf", "memory_mb": 500, "cpu_percent": 5.0, "num_threads": 10},
            {"name": "Helper", "memory_mb": 300, "cpu_percent": 3.0, "num_threads": 5},
        ],
    }


@pytest.fixture
def report_file(tmp_path, sample_report_data):
    """Create a temporary report JSON file."""
    file_path = tmp_path / "report.json"
    file_path.write_text(json.dumps(sample_report_data), encoding="utf-8")
    return file_path


@pytest.fixture
def reports_directory(tmp_path, sample_report_data):
    """Create a directory with multiple report files."""
    for i in range(3):
        data = sample_report_data.copy()
        data["timestamp"] = f"2025-01-0{i + 1}T12:00:00"
        data["process_count"] = 5 + i
        (tmp_path / f"report_{i}.json").write_text(json.dumps(data), encoding="utf-8")
    return tmp_path
