"""Configuration for Windsurf target selection.

Uses python-decouple for settings management. Configuration is read from:
1. Environment variables (highest priority)
2. .env file in current directory
3. Default values

Settings:
    SURFMON_TARGET: "stable" or "next" (default: "stable")
"""

from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from decouple import config


class WindsurfTarget(Enum):
    """Windsurf installation target."""

    STABLE = "stable"
    NEXT = "next"


@dataclass(frozen=True)
class WindsurfPaths:
    """Paths for a specific Windsurf installation."""

    app_name: str  # e.g., "Windsurf.app" or "Windsurf - Next.app"
    app_support_dir: str  # e.g., "Windsurf" or "Windsurf - Next"
    dotfile_dir: str  # e.g., ".windsurf" or ".windsurf-next"

    @property
    def logs_dir(self) -> Path:
        """Path to logs directory."""
        return Path.home() / "Library" / "Application Support" / self.app_support_dir / "logs"

    @property
    def extensions_dir(self) -> Path:
        """Path to extensions directory."""
        return Path.home() / self.dotfile_dir / "extensions"

    @property
    def codeium_dir(self) -> str:
        """Codeium directory name (windsurf or windsurf-next)."""
        # Maps to .codeium/windsurf or .codeium/windsurf-next
        if self.dotfile_dir == ".windsurf":
            return "windsurf"
        return "windsurf-next"

    @property
    def mcp_config_path(self) -> Path:
        """Path to MCP configuration file."""
        return Path.home() / ".codeium" / self.codeium_dir / "mcp_config.json"


# Path configurations for each target
WINDSURF_PATHS = {
    WindsurfTarget.STABLE: WindsurfPaths(
        app_name="Windsurf.app",
        app_support_dir="Windsurf",
        dotfile_dir=".windsurf",
    ),
    WindsurfTarget.NEXT: WindsurfPaths(
        app_name="Windsurf - Next.app",
        app_support_dir="Windsurf - Next",
        dotfile_dir=".windsurf-next",
    ),
}

# Global override for programmatic target setting
_target_override: WindsurfTarget | None = None


def get_target() -> WindsurfTarget:
    """Get the current Windsurf target.

    Priority:
    1. Programmatically set target (via set_target)
    2. SURFMON_TARGET from env var or .env file
    3. Default to STABLE
    """
    if _target_override is not None:
        return _target_override

    target_str = config("SURFMON_TARGET", default="stable").lower()
    if target_str == "next":
        return WindsurfTarget.NEXT
    return WindsurfTarget.STABLE


def set_target(target: WindsurfTarget) -> None:
    """Set the Windsurf target programmatically (overrides env/config)."""
    global _target_override
    _target_override = target


def reset_target() -> None:
    """Reset to use env/config-based target selection."""
    global _target_override
    _target_override = None


def get_paths() -> WindsurfPaths:
    """Get paths for the current Windsurf target."""
    return WINDSURF_PATHS[get_target()]


def get_target_display_name() -> str:
    """Get display name for current target."""
    target = get_target()
    if target == WindsurfTarget.NEXT:
        return "Windsurf Next"
    return "Windsurf"
