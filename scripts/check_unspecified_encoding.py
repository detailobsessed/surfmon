#!/usr/bin/env python3
"""Pre-commit hook: flag .write_text() / .read_text() calls missing encoding=.

Ruff PLW1514 catches open() and direct Path(...).write_text() but loses
type tracking through the ``/`` operator (e.g. ``tmp_path / "f.txt"``),
which is the most common pattern in tests.  This AST-based script fills
that gap by flagging *every* ``.write_text()`` / ``.read_text()`` call
that lacks an ``encoding`` keyword argument — regardless of receiver type.

Exit codes:
  0 — all clear
  1 — violations found (prints file:line details to stderr)
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

METHODS = frozenset({"write_text", "read_text"})


def _check_file(path: Path) -> list[str]:
    """Return a list of ``file:line: message`` strings for violations."""
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
    except SyntaxError, UnicodeDecodeError:
        return []

    violations: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (isinstance(func, ast.Attribute) and func.attr in METHODS):
            continue
        if any(kw.arg == "encoding" for kw in node.keywords):
            continue
        violations.append(f"{path}:{node.lineno}: `{func.attr}()` without explicit `encoding` argument")
    return violations


def main(argv: list[str] | None = None) -> int:
    paths = argv if argv is not None else sys.argv[1:]
    if not paths:
        return 0

    all_violations: list[str] = []
    for p in paths:
        all_violations.extend(_check_file(Path(p)))

    for v in all_violations:
        print(v, file=sys.stderr)

    return 1 if all_violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
