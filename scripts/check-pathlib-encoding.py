#!/usr/bin/env python3
"""Check that pathlib .read_text() / .write_text() calls specify encoding=.

Workaround for ruff PLW1514 false negatives on indirect Path objects.
See: https://github.com/astral-sh/ruff/issues/19294

Remove this hook once ruff handles indirect pathlib paths.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

METHODS = {"read_text", "write_text"}


def check_file(path: Path) -> list[str]:
    """Return list of error messages for the given file."""
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
    except SyntaxError, UnicodeDecodeError:
        return []

    errors: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute):
            continue
        if func.attr not in METHODS:
            continue
        # Check if encoding= is among keyword arguments
        if any(kw.arg == "encoding" for kw in node.keywords):
            continue
        errors.append(f"{path}:{node.lineno}: `{func.attr}` without explicit `encoding` argument")
    return errors


def main() -> int:
    files = [Path(f) for f in sys.argv[1:] if f.endswith(".py")]
    exit_code = 0
    for path in files:
        for error in check_file(path):
            sys.stderr.write(error + "\n")
            exit_code = 1
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
