"""Configuration for Windsurf target selection.

Uses python-decouple for settings management. Configuration is read from:
1. Environment variables (highest priority)
2. .env file in current directory
3. Default values

Settings:
    SURFMON_TARGET: "stable", "next", or "insiders" (required if --target not passed)
"""

from dataclasses import dataclass
from enum import Enum
from pathlib import Path

import psutil
from decouple import config


class WindsurfTarget(Enum):
    """Windsurf installation target."""

    STABLE = "stable"
    NEXT = "next"
    INSIDERS = "insiders"


@dataclass(frozen=True)
class WindsurfPaths:
    """Paths for a specific Windsurf installation."""

    app_name: str  # e.g., "Windsurf.app" or "Windsurf - Next.app"
    app_support_dir: str  # e.g., "Windsurf" or "Windsurf - Next"
    dotfile_dir: str  # e.g., ".windsurf" or ".windsurf-next"
    codeium_dir: str

    @property
    def logs_dir(self) -> Path:
        """Path to logs directory."""
        return Path.home() / "Library" / "Application Support" / self.app_support_dir / "logs"

    @property
    def extensions_dir(self) -> Path:
        """Path to extensions directory."""
        return Path.home() / self.dotfile_dir / "extensions"

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
        codeium_dir="windsurf",
    ),
    WindsurfTarget.NEXT: WindsurfPaths(
        app_name="Windsurf - Next.app",
        app_support_dir="Windsurf - Next",
        dotfile_dir=".windsurf-next",
        codeium_dir="windsurf-next",
    ),
    WindsurfTarget.INSIDERS: WindsurfPaths(
        app_name="Windsurf - Insiders.app",
        app_support_dir="Windsurf - Insiders",
        dotfile_dir=".windsurf-insiders",
        codeium_dir="windsurf-insiders",
    ),
}

# Mutable state container (avoids global statements)
_state: dict[str, WindsurfTarget | None] = {"target_override": None}


def _detect_running_target() -> WindsurfTarget | None:
    """Auto-detect which Windsurf installation is currently running.

    Checks for processes matching each target's app_name.
    Returns the first target found running, preferring NEXT over STABLE
    if both are running. Returns None if neither is detected.
    """
    running: set[WindsurfTarget] = set()

    for proc in psutil.process_iter(["exe", "cmdline"]):
        try:
            exe = proc.info["exe"] or ""
            cmdline = " ".join(proc.info["cmdline"] or [])

            # Skip orphaned crashpad handlers — they linger after the main
            # app exits and shouldn't influence target detection.
            if "crashpad" in exe.lower() or "crashpad" in cmdline.lower():
                continue

            for target, paths in WINDSURF_PATHS.items():
                if paths.app_name in exe or paths.app_name in cmdline:
                    running.add(target)

        except psutil.NoSuchProcess, psutil.AccessDenied:
            pass

    if not running:
        return None
    # Prefer NEXT if both are running (it's the active development channel)
    if WindsurfTarget.NEXT in running:
        return WindsurfTarget.NEXT
    if WindsurfTarget.INSIDERS in running:
        return WindsurfTarget.INSIDERS
    return WindsurfTarget.STABLE


class TargetNotSetError(Exception):
    """Raised when no Windsurf target has been configured."""


def get_target() -> WindsurfTarget:
    """Get the current Windsurf target.

    Priority:
    1. Programmatically set target (via set_target)
    2. SURFMON_TARGET from env var or .env file

    Raises TargetNotSetError if no target is explicitly configured.
    """
    if _state["target_override"] is not None:
        return _state["target_override"]

    target_str = config("SURFMON_TARGET", default="").lower()
    if target_str == "next":
        return WindsurfTarget.NEXT
    if target_str == "stable":
        return WindsurfTarget.STABLE
    if target_str == "insiders":
        return WindsurfTarget.INSIDERS

    raise TargetNotSetError


def set_target(target: WindsurfTarget) -> None:
    """Set the Windsurf target programmatically (overrides env/config)."""
    _state["target_override"] = target


def reset_target() -> None:
    """Reset to use env/config-based target selection."""
    _state["target_override"] = None


def get_paths() -> WindsurfPaths:
    """Get paths for the current Windsurf target."""
    return WINDSURF_PATHS[get_target()]


def get_target_display_name() -> str:
    """Get display name for current target."""
    target = get_target()
    if target == WindsurfTarget.NEXT:
        return "Windsurf Next"
    if target == WindsurfTarget.INSIDERS:
        return "Windsurf Insiders"
    return "Windsurf"
