#!/usr/bin/env python3
"""AST audit script for surfmon — tracks code quality metrics over time.

Run periodically to verify refactoring progress:
    python scripts/ast_audit.py
"""

from __future__ import annotations

import ast
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "surfmon"
TESTS = ROOT / "tests"

# Thresholds
MAX_FUNC_LINES = 50
MAX_CC = 10
MAX_DEPTH = 3
MAX_LOCALS_GOD = 10
MAX_CC_GOD = 8
MAX_FUNC_LINES_GOD = 40
MAX_FILE_LINES = 500
MIN_DUP_STRING_LEN = 10
MIN_DUP_STRING_COUNT = 3


def _is_elif(parent: ast.AST, child: ast.AST) -> bool:
    """Return True if child is an elif branch (sole If in parent's orelse)."""
    if not isinstance(parent, ast.If) or not isinstance(child, ast.If):
        return False
    return parent.orelse == [child]


def _max_depth(node: ast.AST, current: int = 0) -> int:
    children_depths = []
    for child in ast.iter_child_nodes(node):
        if _is_elif(node, child):
            # elif is flat, not nested — keep same depth
            children_depths.append(_max_depth(child, current))
        elif isinstance(child, ast.If | ast.For | ast.While | ast.With | ast.Try | ast.ExceptHandler):
            children_depths.append(_max_depth(child, current + 1))
        else:
            children_depths.append(_max_depth(child, current))
    return max(children_depths) if children_depths else current


def _cyclomatic_complexity(node: ast.AST) -> int:
    complexity = 1
    for child in ast.walk(node):
        if isinstance(child, ast.If | ast.IfExp | ast.For | ast.While | ast.ExceptHandler | ast.Assert):
            complexity += 1
        elif isinstance(child, ast.BoolOp):
            complexity += len(child.values) - 1
    return complexity


def _collect_assign_names(child: ast.Assign) -> set[str]:
    names: set[str] = set()
    for target in child.targets:
        if isinstance(target, ast.Name):
            names.add(target.id)
        elif isinstance(target, ast.Tuple):
            names.update(elt.id for elt in target.elts if isinstance(elt, ast.Name))
    return names


def _count_locals(node: ast.AST) -> int:
    names: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Assign):
            names.update(_collect_assign_names(child))
        elif isinstance(child, ast.AnnAssign) and isinstance(child.target, ast.Name):
            names.add(child.target.id)
    return len(names)


def _analyze_file(filepath: Path, rel: str, results: dict[str, list[dict]]) -> None:
    source = filepath.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(filepath))
    lines = source.splitlines()

    if len(lines) > MAX_FILE_LINES:
        results["long_files"].append({"file": rel, "lines": len(lines)})

    _collect_duplicate_strings(tree, rel, results)
    _analyze_functions(_collect_func_nodes(tree, rel), results)


def _collect_duplicate_strings(tree: ast.Module, rel: str, results: dict[str, list[dict]]) -> None:
    strings: dict[str, list[int]] = defaultdict(list)
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and len(node.value) > MIN_DUP_STRING_LEN:
            strings[node.value].append(node.lineno)
    for s, locs in strings.items():
        if len(locs) >= MIN_DUP_STRING_COUNT:
            results["duplicate_strings"].append({"file": rel, "string": s[:60], "count": len(locs)})


def _collect_func_nodes(tree: ast.Module, rel: str) -> list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, str]]:
    func_nodes: list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, str]] = []
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            func_nodes.append((node, rel))
        elif isinstance(node, ast.ClassDef):
            func_nodes.extend(
                (child, rel) for child in ast.iter_child_nodes(node) if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef)
            )
    return func_nodes


def _analyze_functions(func_nodes: list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, str]], results: dict[str, list[dict]]) -> None:
    for func, frel in func_nodes:
        end = getattr(func, "end_lineno", func.lineno)
        func_lines = end - func.lineno + 1
        cc = _cyclomatic_complexity(func)
        depth = _max_depth(func)
        locals_count = _count_locals(func)

        if func_lines > MAX_FUNC_LINES:
            results["large_functions"].append({"func": func.name, "file": frel, "lines": func_lines})
        if cc > MAX_CC:
            results["high_complexity"].append({"func": func.name, "file": frel, "cc": cc})
        if depth > MAX_DEPTH:
            results["deep_nesting"].append({"func": func.name, "file": frel, "depth": depth})
        if locals_count > MAX_LOCALS_GOD and cc > MAX_CC_GOD and func_lines > MAX_FUNC_LINES_GOD:
            results["god_functions"].append({"func": func.name, "file": frel, "locals": locals_count, "cc": cc, "lines": func_lines})


def analyze() -> dict[str, list[dict]]:
    results: dict[str, list[dict]] = defaultdict(list)
    py_files = sorted([*SRC.rglob("*.py"), *TESTS.rglob("*.py")])
    for filepath in py_files:
        _analyze_file(filepath, str(filepath.relative_to(ROOT)), results)
    return dict(results)


def print_report(results: dict[str, list[dict]]) -> int:
    categories = [
        ("god_functions", "God Functions", "red"),
        ("high_complexity", "High Complexity (CC > 10)", "yellow"),
        ("deep_nesting", "Deep Nesting (depth > 3)", "yellow"),
        ("large_functions", "Large Functions (> 50 lines)", "default"),
        ("long_files", "Long Files (> 500 lines)", "default"),
        ("duplicate_strings", "Duplicate Strings (3+)", "default"),
    ]

    total_issues = 0
    print("=" * 60)
    print("  surfmon AST Audit")
    print("=" * 60)

    for key, label, _color in categories:
        items = results.get(key, [])
        count = len(items)
        total_issues += count
        marker = "✓" if count == 0 else "✗"
        print(f"\n  {marker} {label}: {count}")
        if items:
            # Sort by most egregious first
            sort_key = "cc" if "cc" in items[0] else "lines" if "lines" in items[0] else "depth" if "depth" in items[0] else "count"
            for item in sorted(items, key=lambda x: x.get(sort_key, 0), reverse=True)[:8]:
                detail = ", ".join(f"{k}={v}" for k, v in item.items() if k not in {"file", "func", "string"})
                name = item.get("func", item.get("file", item.get("string", "?")[:40]))
                file_info = f" ({item['file']})" if "file" in item and "func" in item else ""
                print(f"      {name}{file_info} — {detail}")

    print(f"\n{'=' * 60}")
    print(f"  Total issues: {total_issues}")
    print("=" * 60)

    return total_issues


def main() -> int:
    results = analyze()
    total_issues = print_report(results)
    return 1 if total_issues > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
