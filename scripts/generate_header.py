"""Generate an animated ocean wave GIF header for the README."""

from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

# Dimensions
WIDTH = 800
HEIGHT = 200
FRAMES = 40
DURATION = 80  # ms per frame

# Colors — Catppuccin Mocha inspired
SKY_TOP = (30, 30, 46)  # Crust
SKY_BOTTOM = (49, 50, 68)  # Surface0
WAVE_COLORS = [
    (137, 180, 250),  # Blue
    (116, 199, 236),  # Sapphire
    (94, 218, 214),  # Teal
    (148, 226, 213),  # Green (foam)
]
TEXT_COLOR = (205, 214, 244)  # Text
SUBTITLE_COLOR = (166, 173, 200)  # Subtext0


def lerp_color(c1: tuple[int, int, int], c2: tuple[int, int, int], t: float) -> tuple[int, int, int]:
    return (
        int(c1[0] + (c2[0] - c1[0]) * t),
        int(c1[1] + (c2[1] - c1[1]) * t),
        int(c1[2] + (c2[2] - c1[2]) * t),
    )


def draw_gradient_bg(draw: ImageDraw.ImageDraw) -> None:
    for y in range(HEIGHT):
        t = y / HEIGHT
        color = lerp_color(SKY_TOP, SKY_BOTTOM, t)
        draw.line([(0, y), (WIDTH, y)], fill=color)


@dataclass
class WaveConfig:
    y_base: int
    amplitude: float
    frequency: float
    speed: float
    color: tuple[int, int, int]
    alpha: int = 180


def draw_wave_layer(
    draw: ImageDraw.ImageDraw,
    frame: int,
    wave: WaveConfig,
) -> None:
    y_base = wave.y_base
    amplitude = wave.amplitude
    frequency = wave.frequency
    speed = wave.speed
    color = wave.color
    alpha = wave.alpha
    phase = (frame / FRAMES) * 2 * math.pi * speed
    points = []
    for x in range(WIDTH + 1):
        y = y_base + amplitude * math.sin(frequency * x / WIDTH * 2 * math.pi + phase)
        # Secondary and tertiary harmonics for choppy, violent seas
        y += (amplitude * 0.5) * math.sin(frequency * 2.3 * x / WIDTH * 2 * math.pi + phase * 1.7)
        y += (amplitude * 0.25) * math.sin(frequency * 3.7 * x / WIDTH * 2 * math.pi - phase * 2.1)
        points.append((x, y))

    # Close polygon at bottom
    points.extend(((WIDTH, HEIGHT), (0, HEIGHT)))

    # Blend color with alpha
    blended = lerp_color(SKY_BOTTOM, color, alpha / 255)
    draw.polygon(points, fill=blended)


def draw_text(draw: ImageDraw.ImageDraw) -> None:
    # Try to use a nice font, fall back to default
    title = "surfmon"
    subtitle = "Surface Monitor for Windsurf IDE"

    try:
        title_font = ImageFont.truetype("/System/Library/Fonts/SFCompact.ttf", 48)
    except OSError:
        try:
            title_font = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 48)
        except OSError:
            title_font = ImageFont.load_default(size=48)

    try:
        sub_font = ImageFont.truetype("/System/Library/Fonts/SFCompact.ttf", 20)
    except OSError:
        try:
            sub_font = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 20)
        except OSError:
            sub_font = ImageFont.load_default(size=20)

    # Center title
    bbox = draw.textbbox((0, 0), title, font=title_font)
    tw = bbox[2] - bbox[0]
    draw.text(((WIDTH - tw) / 2, 40), title, fill=TEXT_COLOR, font=title_font)

    # Center subtitle
    bbox = draw.textbbox((0, 0), subtitle, font=sub_font)
    sw = bbox[2] - bbox[0]
    draw.text(((WIDTH - sw) / 2, 100), subtitle, fill=SUBTITLE_COLOR, font=sub_font)


def generate() -> None:
    frames: list[Image.Image] = []

    for f in range(FRAMES):
        img = Image.new("RGB", (WIDTH, HEIGHT))
        draw = ImageDraw.Draw(img)

        draw_gradient_bg(draw)

        # Draw wave layers back-to-front
        waves = [
            WaveConfig(y_base=150, amplitude=15, frequency=1.4, speed=1.0, color=WAVE_COLORS[0], alpha=100),
            WaveConfig(y_base=160, amplitude=18, frequency=1.8, speed=1.4, color=WAVE_COLORS[1], alpha=130),
            WaveConfig(y_base=170, amplitude=12, frequency=2.5, speed=1.8, color=WAVE_COLORS[2], alpha=160),
            WaveConfig(y_base=178, amplitude=8, frequency=3.2, speed=2.3, color=WAVE_COLORS[3], alpha=200),
        ]

        for wave in waves:
            draw_wave_layer(draw, f, wave)

        draw_text(draw)
        frames.append(img)

    out = Path("docs/screenshots/header.gif")
    out.parent.mkdir(parents=True, exist_ok=True)
    frames[0].save(
        out,
        save_all=True,
        append_images=frames[1:],
        duration=DURATION,
        loop=0,
        optimize=True,
    )
    print(f"Generated {out} ({out.stat().st_size / 1024:.1f} KB, {FRAMES} frames)")


if __name__ == "__main__":
    generate()
