"""Shared constants used across surfmon modules.

Extracted to break circular imports between monitor.py and submodules.
"""

from dataclasses import dataclass
from enum import StrEnum


class IssueSeverity(StrEnum):
    """Severity level for detected issues."""

    CRITICAL = "critical"
    WARNING = "warning"

    @property
    def marker(self) -> str:
        """Return the display marker character for this severity."""
        return "\u2716" if self == IssueSeverity.CRITICAL else "\u26a0"

    @property
    def color(self) -> str:
        """Return the Rich color name for this severity."""
        return "red" if self == IssueSeverity.CRITICAL else "yellow"


@dataclass(slots=True, frozen=True)
class Issue:
    """A detected issue with explicit severity."""

    severity: IssueSeverity
    message: str

    def __str__(self) -> str:
        return f"{self.severity.marker}  {self.message}"


# Monitoring thresholds
CMDLINE_TRUNCATE_LEN = 200
PATH_COMPONENTS_SHORT = 3
MAX_DISPLAY_ITEMS = 3
TELEMETRY_ERROR_THRESHOLD = 5
EXTENSION_ERROR_LINES_THRESHOLD = 10
SECONDS_PER_MINUTE = 60
SECONDS_PER_HOUR = 3600
SECONDS_PER_DAY = 86400
LSOF_MIN_FIELDS = 8
PTY_CRITICAL_COUNT = 200
PTY_WARNING_COUNT = 50
PTY_USAGE_CRITICAL_PERCENT = 80
LOG_TAIL_BYTES = 50000
SHARED_LOG_TAIL_BYTES = 30000

# Exit codes for the check command
EXIT_OK = 0
EXIT_WARNING = 1
EXIT_CRITICAL = 2
