#!/usr/bin/env python3
"""AST audit script for surfmon — tracks code quality metrics over time.

Run periodically to verify refactoring progress:
    python scripts/ast_audit.py

Generates both terminal output and an HTML dashboard at:
    ~/.agent/diagrams/surfmon-ast-audit.html
"""

from __future__ import annotations

import ast
import operator
import sys
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "surfmon"
TESTS = ROOT / "tests"
HTML_OUT = Path.home() / ".agent" / "diagrams" / "surfmon-ast-audit.html"

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

# KPI color thresholds for HTML dashboard
KPI_TEAL_MAX = 3
KPI_ORANGE_MAX = 8


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
    # Pre-collect IDs of docstring nodes to exclude from magic-string detection.
    docstring_ids: set[int] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef | ast.Module)
            and node.body
            and isinstance(node.body[0], ast.Expr)
        ):
            expr_val = node.body[0].value
            if isinstance(expr_val, ast.Constant) and isinstance(expr_val.value, str):
                docstring_ids.add(id(expr_val))

    strings: dict[str, list[int]] = defaultdict(list)
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and len(node.value) >= MIN_DUP_STRING_LEN
            and id(node) not in docstring_ids
        ):
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


# ---------------------------------------------------------------------------
# HTML report generation
# ---------------------------------------------------------------------------

_CSS = """\
:root {
  --font-body: 'Bricolage Grotesque', system-ui, sans-serif;
  --font-mono: 'Fragment Mono', 'SF Mono', Consolas, monospace;
  --bg: #faf8f5; --surface: #ffffff; --surface2: #f4f1ec;
  --surface-elevated: #fffefa;
  --border: rgba(0,0,0,0.07); --border-bright: rgba(0,0,0,0.14);
  --text: #1c1917; --text-dim: #78716c;
  --accent: #0369a1; --accent-dim: rgba(3,105,161,0.06);
  --red: #b91c1c; --red-dim: rgba(185,28,28,0.06);
  --orange: #b45309; --orange-dim: rgba(180,83,9,0.07);
  --green: #15803d; --green-dim: rgba(21,128,61,0.07);
  --teal: #0e7490; --teal-dim: rgba(14,116,144,0.07);
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #121110; --surface: #1c1a17; --surface2: #252320;
    --surface-elevated: #2a2724;
    --border: rgba(255,255,255,0.06); --border-bright: rgba(255,255,255,0.12);
    --text: #ede8e3; --text-dim: #a8a29e;
    --accent: #38bdf8; --accent-dim: rgba(56,189,248,0.1);
    --red: #f87171; --red-dim: rgba(248,113,113,0.08);
    --orange: #fbbf24; --orange-dim: rgba(251,191,36,0.08);
    --green: #4ade80; --green-dim: rgba(74,222,128,0.08);
    --teal: #22d3ee; --teal-dim: rgba(34,211,238,0.08);
  }
}
* { margin:0; padding:0; box-sizing:border-box; }
body {
  background: var(--bg);
  background-image:
    radial-gradient(ellipse at 20% 0%, var(--accent-dim) 0%, transparent 50%),
    radial-gradient(ellipse at 80% 100%, var(--teal-dim) 0%, transparent 40%);
  color: var(--text); font-family: var(--font-body);
  min-height: 100vh; padding: 40px;
}
@keyframes fadeUp {
  from { opacity:0; transform:translateY(12px); }
  to { opacity:1; transform:translateY(0); }
}
.animate { animation: fadeUp 0.35s ease-out both; animation-delay: calc(var(--i,0) * 0.04s); }
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation-duration:0.01ms!important; animation-delay:0ms!important; transition-duration:0.01ms!important; }
}
.wrap { max-width:1200px; margin:0 auto; display:grid; grid-template-columns:160px 1fr; gap:0 36px; }
.main { min-width:0; }
.toc { position:sticky; top:24px; align-self:start; padding:14px 0; grid-row:1/-1; max-height:calc(100dvh - 48px); overflow-y:auto; }
.toc::-webkit-scrollbar { width:3px; }
.toc::-webkit-scrollbar-thumb { background:var(--surface-elevated); border-radius:2px; }
.toc-title {
  font-family:var(--font-mono); font-size:9px; font-weight:700;
  text-transform:uppercase; letter-spacing:2px; color:var(--text-dim);
  padding:0 0 10px; margin-bottom:8px; border-bottom:1px solid var(--border);
}
.toc a {
  display:block; font-size:11px; color:var(--text-dim); text-decoration:none;
  padding:4px 8px; border-radius:5px; border-left:2px solid transparent;
  transition:all 0.15s; line-height:1.4; margin-bottom:1px;
}
.toc a:hover { color:var(--text); background:var(--surface2); }
.toc a.active { color:var(--text); border-left-color:var(--accent); }
@media (max-width:900px) {
  .wrap { grid-template-columns:1fr; padding-top:0; }
  body { padding:16px; padding-top:0; }
  .toc {
    position:sticky; top:0; z-index:200; max-height:none;
    display:flex; gap:4px; align-items:center;
    overflow-x:auto; -webkit-overflow-scrolling:touch;
    background:var(--bg); border-bottom:1px solid var(--border);
    padding:10px 0; margin:0 -16px;
    padding-left:16px; padding-right:16px; grid-row:auto;
  }
  .toc::-webkit-scrollbar { display:none; }
  .toc-title { display:none; }
  .toc a {
    white-space:nowrap; flex-shrink:0; border-left:none;
    border-bottom:2px solid transparent; border-radius:4px 4px 0 0;
    padding:6px 10px; font-size:10px;
  }
  .toc a.active { border-left:none; border-bottom-color:var(--accent); background:var(--surface); }
  .main { padding-top:20px; }
  .sec-head { scroll-margin-top:52px; }
}
h1 { font-size:28px; font-weight:700; letter-spacing:-0.3px; margin-bottom:4px; }
.subtitle { color:var(--text-dim); font-family:var(--font-mono); font-size:11px; margin-bottom:28px; }
.sec-head {
  font-family:var(--font-mono); font-size:11px; font-weight:700;
  text-transform:uppercase; letter-spacing:1.5px; color:var(--accent);
  padding:20px 0 12px; margin-top:8px; display:flex; align-items:center; gap:8px;
}
.sec-head::before { content:''; width:8px; height:8px; border-radius:50%; background:currentColor; }
.kpi-row { display:grid; grid-template-columns:repeat(auto-fit,minmax(120px,1fr)); gap:12px; margin-bottom:24px; }
.kpi-card {
  background:var(--surface-elevated); border:1px solid var(--border);
  border-radius:10px; padding:16px; box-shadow:0 2px 8px rgba(0,0,0,0.04);
}
.kpi-card__value { font-size:28px; font-weight:700; line-height:1.1; font-variant-numeric:tabular-nums; }
.kpi-card__label {
  font-family:var(--font-mono); font-size:9px; font-weight:700;
  text-transform:uppercase; letter-spacing:1.2px;
  color:var(--text-dim); margin-top:4px;
}
.table-wrap { background:var(--surface); border:1px solid var(--border); border-radius:10px; overflow:hidden; margin-bottom:20px; }
.table-scroll { overflow-x:auto; -webkit-overflow-scrolling:touch; }
.data-table { width:100%; border-collapse:collapse; font-size:13px; line-height:1.5; }
.data-table thead { position:sticky; top:0; z-index:2; }
.data-table th {
  background:var(--surface2); font-family:var(--font-mono); font-size:9px;
  font-weight:700; text-transform:uppercase; letter-spacing:1.2px;
  color:var(--text-dim); text-align:left; padding:12px 14px;
  border-bottom:2px solid var(--border-bright); white-space:nowrap;
}
.data-table td { padding:10px 14px; border-bottom:1px solid var(--border); vertical-align:top; }
.data-table tbody tr:last-child td { border-bottom:none; }
.data-table tbody tr:nth-child(even) { background:var(--accent-dim); }
.data-table tbody tr { transition:background 0.15s ease; animation:fadeUp 0.3s ease-out both; animation-delay:calc(var(--i,0)*0.03s); }
.data-table tbody tr:hover { background:var(--border); }
.data-table code {
  font-family:var(--font-mono); font-size:11px;
  background:var(--accent-dim); color:var(--accent);
  padding:1px 5px; border-radius:3px;
}
.data-table small { display:block; color:var(--text-dim); font-size:11px; margin-top:2px; }
.data-table .num { text-align:right; font-variant-numeric:tabular-nums; font-family:var(--font-mono); font-size:12px; }
.data-table tfoot td {
  background:var(--surface2); font-weight:700; font-family:var(--font-mono);
  font-size:11px; border-top:2px solid var(--border-bright);
  border-bottom:none; padding:12px 14px;
}
.sev {
  display:inline-flex; align-items:center; gap:4px;
  font-family:var(--font-mono); font-size:10px; font-weight:700;
  padding:2px 8px; border-radius:5px; white-space:nowrap; letter-spacing:0.3px;
}
.sev::before { content:''; width:6px; height:6px; border-radius:50%; background:currentColor; }
.sev--high { background:var(--red-dim); color:var(--red); }
.sev--med  { background:var(--orange-dim); color:var(--orange); }
.sev--low  { background:var(--green-dim); color:var(--green); }
.sev--info { background:var(--teal-dim); color:var(--teal); }
details.coll { border:1px solid var(--border); border-radius:10px; overflow:hidden; margin-bottom:16px; }
details.coll summary {
  padding:12px 18px; background:var(--surface);
  font-family:var(--font-mono); font-size:12px; font-weight:700;
  cursor:pointer; list-style:none; display:flex;
  align-items:center; gap:8px; color:var(--text);
  transition:background 0.15s ease;
}
details.coll summary:hover { background:var(--surface-elevated); }
details.coll summary::-webkit-details-marker { display:none; }
details.coll summary::before { content:'\25B8'; font-size:11px; color:var(--text-dim); transition:transform 0.15s ease; }
details.coll[open] summary::before { transform:rotate(90deg); }
details.coll .coll__body { padding:14px 18px; border-top:1px solid var(--border); font-size:13px; line-height:1.6; color:var(--text-dim); }
details.coll .coll__body strong { color:var(--text); }
details.coll .coll__body code {
  font-family:var(--font-mono); font-size:11px;
  background:var(--accent-dim); color:var(--accent);
  padding:1px 5px; border-radius:3px;
}
details.coll .coll__body ul { margin:8px 0 8px 20px; }
details.coll .coll__body li { margin-bottom:4px; }
@media (max-width:768px) {
  body { padding:16px; }
  h1 { font-size:22px; }
  .data-table th, .data-table td { padding:8px 10px; }
  .kpi-row { grid-template-columns:repeat(3,1fr); }
}
"""

_JS = """\
(function() {
  const toc = document.getElementById('toc');
  const links = toc.querySelectorAll('a');
  const sections = [];
  links.forEach(link => {
    const id = link.getAttribute('href').slice(1);
    const el = document.getElementById(id);
    if (el) sections.push({ id, el, link });
  });
  const observer = new IntersectionObserver(entries => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        links.forEach(l => l.classList.remove('active'));
        const match = sections.find(s => s.el === entry.target);
        if (match) {
          match.link.classList.add('active');
          if (window.innerWidth <= 900) {
            match.link.scrollIntoView({ behavior:'smooth', block:'nearest', inline:'center' });
          }
        }
      }
    });
  }, { rootMargin: '-10% 0px -80% 0px' });
  sections.forEach(s => observer.observe(s.el));
  links.forEach(link => {
    link.addEventListener('click', e => {
      e.preventDefault();
      const id = link.getAttribute('href').slice(1);
      const el = document.getElementById(id);
      if (el) {
        el.scrollIntoView({ behavior:'smooth', block:'start' });
        history.replaceState(null, '', '#' + id);
      }
    });
  });
})();
"""


def _sev_class(value: int, thresholds: tuple[int, int]) -> str:
    """Return CSS severity class based on value vs (high, med) thresholds."""
    high, med = thresholds
    if value >= high:
        return "sev--high"
    if value >= med:
        return "sev--med"
    return "sev--low"


def _sev_label(value: int, thresholds: tuple[int, int]) -> str:
    high, med = thresholds
    if value >= high:
        return "High"
    if value >= med:
        return "Med"
    return "Low"


def _kpi_color(count: int) -> str:
    if count == 0:
        return "var(--green)"
    if count <= KPI_TEAL_MAX:
        return "var(--teal)"
    if count <= KPI_ORANGE_MAX:
        return "var(--orange)"
    return "var(--red)"


def _e(text: str) -> str:
    """HTML-escape a string."""
    return escape(text)


def _build_kpi_row(results: dict[str, list[dict]]) -> str:
    kpis = [
        ("god_functions", "God Functions"),
        ("high_complexity", "High Complexity"),
        ("deep_nesting", "Deep Nesting"),
        ("large_functions", "Large Functions"),
        ("long_files", "Long Files"),
        ("duplicate_strings", "Dup Strings"),
    ]
    cards = []
    for key, label in kpis:
        count = len(results.get(key, []))
        color = _kpi_color(count)
        cards.append(
            f'  <div class="kpi-card">\n'
            f'    <div class="kpi-card__value" style="color:{color}">{count}</div>\n'
            f'    <div class="kpi-card__label">{label}</div>\n'
            f"  </div>"
        )
    return "\n".join(cards)


def _build_god_functions_table(items: list[dict]) -> str:
    if not items:
        return '<p style="color:var(--green); font-size:13px;">\xe2\x9c\x93 No god functions found.</p>'
    rows = []
    for i, item in enumerate(sorted(items, key=lambda x: x.get("cc", 0), reverse=True)):
        sev_cls = _sev_class(item["cc"], (15, 10))
        sev_lbl = _sev_label(item["cc"], (15, 10))
        rows.append(
            f'        <tr style="--i:{i}">'
            f"<td><code>{_e(item['func'])}</code></td>"
            f"<td><code>{_e(item['file'])}</code></td>"
            f'<td class="num">{item["lines"]}</td>'
            f'<td class="num">{item["cc"]}</td>'
            f'<td class="num">{item["locals"]}</td>'
            f'<td><span class="sev {sev_cls}">{sev_lbl}</span></td></tr>'
        )
    return (
        '<div class="table-wrap"><div class="table-scroll"><table class="data-table">\n'
        '      <thead><tr><th>Function</th><th>File</th><th class="num">Lines</th>'
        '<th class="num">CC</th><th class="num">Locals</th><th>Severity</th></tr></thead>\n'
        "      <tbody>\n" + "\n".join(rows) + "\n      </tbody>\n"
        f'      <tfoot><tr><td colspan="4">{len(items)} god function(s)</td><td></td><td></td></tr></tfoot>\n'
        "    </table></div></div>"
    )


def _build_complexity_table(items: list[dict]) -> str:
    if not items:
        return f'<p style="color:var(--green); font-size:13px;">\xe2\x9c\x93 All functions below CC {MAX_CC}.</p>'
    rows = []
    for i, item in enumerate(sorted(items, key=lambda x: x.get("cc", 0), reverse=True)):
        sev_cls = _sev_class(item["cc"], (15, 12))
        sev_lbl = _sev_label(item["cc"], (15, 12))
        rows.append(
            f'        <tr style="--i:{i}">'
            f"<td><code>{_e(item['func'])}</code></td>"
            f"<td><code>{_e(item['file'])}</code></td>"
            f'<td class="num">{item["cc"]}</td>'
            f'<td><span class="sev {sev_cls}">{sev_lbl}</span></td></tr>'
        )
    return (
        '<div class="table-wrap"><div class="table-scroll"><table class="data-table">\n'
        '      <thead><tr><th>Function</th><th>File</th><th class="num">CC</th><th>Severity</th></tr></thead>\n'
        "      <tbody>\n" + "\n".join(rows) + "\n      </tbody>\n"
        f'      <tfoot><tr><td colspan="2">{len(items)} function(s) above CC {MAX_CC}</td><td></td><td></td></tr></tfoot>\n'
        "    </table></div></div>"
    )


def _build_nesting_table(items: list[dict]) -> str:
    if not items:
        return f'<p style="color:var(--green); font-size:13px;">\xe2\x9c\x93 All functions within depth {MAX_DEPTH}.</p>'
    rows = []
    for i, item in enumerate(sorted(items, key=lambda x: x.get("depth", 0), reverse=True)):
        sev_cls = _sev_class(item["depth"], (6, 4))
        sev_lbl = _sev_label(item["depth"], (6, 4))
        rows.append(
            f'        <tr style="--i:{i}">'
            f"<td><code>{_e(item['func'])}</code></td>"
            f"<td><code>{_e(item['file'])}</code></td>"
            f'<td class="num">{item["depth"]}</td>'
            f'<td><span class="sev {sev_cls}">{sev_lbl}</span></td></tr>'
        )
    return (
        '<div class="table-wrap"><div class="table-scroll"><table class="data-table">\n'
        '      <thead><tr><th>Function</th><th>File</th><th class="num">Depth</th><th>Severity</th></tr></thead>\n'
        "      <tbody>\n" + "\n".join(rows) + "\n      </tbody>\n"
        f'      <tfoot><tr><td colspan="2">{len(items)} function(s) above depth {MAX_DEPTH}</td><td></td><td></td></tr></tfoot>\n'
        "    </table></div></div>"
    )


def _build_large_functions_table(items: list[dict]) -> str:
    if not items:
        return f'<p style="color:var(--green); font-size:13px;">\xe2\x9c\x93 All functions under {MAX_FUNC_LINES} lines.</p>'
    rows = [
        f"        <tr><td><code>{_e(item['func'])}</code></td>"
        f"<td><code>{_e(item['file'])}</code></td>"
        f'<td class="num">{item["lines"]}</td></tr>'
        for item in sorted(items, key=lambda x: x.get("lines", 0), reverse=True)
    ]
    return (
        f'<details class="coll"><summary>{len(items)} functions exceeding {MAX_FUNC_LINES} lines (click to expand)</summary>\n'
        '<div class="coll__body"><table class="data-table">\n'
        '      <thead><tr><th>Function</th><th>File</th><th class="num">Lines</th></tr></thead>\n'
        "      <tbody>\n" + "\n".join(rows) + "\n      </tbody>\n"
        "    </table></div></details>"
    )


def _build_long_files_table(items: list[dict]) -> str:
    if not items:
        return f'<p style="color:var(--green); font-size:13px;">\xe2\x9c\x93 All files under {MAX_FILE_LINES} lines.</p>'
    rows = []
    for i, item in enumerate(sorted(items, key=lambda x: x.get("lines", 0), reverse=True)):
        sev_cls = _sev_class(item["lines"], (2000, 800))
        sev_lbl = _sev_label(item["lines"], (2000, 800))
        rows.append(
            f'        <tr style="--i:{i}">'
            f"<td><code>{_e(item['file'])}</code></td>"
            f'<td class="num">{item["lines"]:,}</td>'
            f'<td><span class="sev {sev_cls}">{sev_lbl}</span></td></tr>'
        )
    return (
        '<div class="table-wrap"><div class="table-scroll"><table class="data-table">\n'
        '      <thead><tr><th>File</th><th class="num">Lines</th><th>Severity</th></tr></thead>\n'
        "      <tbody>\n" + "\n".join(rows) + "\n      </tbody>\n"
        "    </table></div></div>"
    )


def _build_dup_strings_section(items: list[dict]) -> str:
    count = len(items)
    src_items = [it for it in items if not it["file"].startswith("tests/")]
    test_items = [it for it in items if it["file"].startswith("tests/")]
    summary = f"{count} string literals repeated 3+ times across the codebase"
    if src_items:
        summary += f" ({len(src_items)} in src/, {len(test_items)} in tests/)"
    else:
        summary += " (all in tests/ — expected)"

    top_src = sorted(src_items, key=operator.itemgetter("count"), reverse=True)[:10]
    top_test = sorted(test_items, key=operator.itemgetter("count"), reverse=True)[:5]

    body_parts = [f"<p>{_e(summary)}.</p>"]
    if top_src:
        rows = "".join(
            f'<tr><td><code>{_e(it["string"])}</code></td><td><code>{_e(it["file"])}</code></td><td class="num">{it["count"]}</td></tr>'
            for it in top_src
        )
        body_parts.append(
            '<p style="margin-top:8px;"><strong>Top src/ duplicates:</strong></p>'
            '<table class="data-table"><thead><tr><th>String</th><th>File</th><th class="num">Count</th></tr></thead>'
            f"<tbody>{rows}</tbody></table>"
        )
    if top_test:
        rows = "".join(
            f'<tr><td><code>{_e(it["string"])}</code></td><td><code>{_e(it["file"])}</code></td><td class="num">{it["count"]}</td></tr>'
            for it in top_test
        )
        body_parts.append(
            '<p style="margin-top:12px;"><strong>Top test/ duplicates:</strong></p>'
            '<table class="data-table"><thead><tr><th>String</th><th>File</th><th class="num">Count</th></tr></thead>'
            f"<tbody>{rows}</tbody></table>"
        )

    return (
        f'<details class="coll"><summary>{count} repeated string literals (click to expand)</summary>\n'
        f'<div class="coll__body">{"\n".join(body_parts)}</div></details>'
    )


def generate_html_report(results: dict[str, list[dict]]) -> str:
    """Generate the full HTML audit dashboard from analysis results."""
    now = datetime.now(tz=UTC).strftime("%b %d %Y %H:%M UTC")
    anim_i = 0

    def ai() -> int:
        nonlocal anim_i
        anim_i += 1
        return anim_i - 1

    sections = [
        ("s0", "Overview"),
        ("s1", "God Functions"),
        ("s2", "Complexity"),
        ("s3", "Deep Nesting"),
        ("s4", "Large Functions"),
        ("s5", "Long Files"),
        ("s6", "Magic Strings"),
    ]
    toc_links = "\n  ".join(f'<a href="#{sid}">{label}</a>' for sid, label in sections)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>surfmon AST Audit</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:wght@400;600;700&amp;family=Fragment+Mono:wght@400&amp;display=swap"
  rel="stylesheet">
<style>
{_CSS}</style>
</head>
<body>
<div class="wrap">

<nav class="toc" id="toc">
  <div class="toc-title">Sections</div>
  {toc_links}
</nav>

<div class="main">

<h1 class="animate" style="--i:{ai()}">surfmon AST Audit</h1>
<p class="subtitle animate" style="--i:{ai()}">Static analysis via Python ast &mdash; src/surfmon + tests &mdash; {_e(now)}</p>

<div id="s0" class="sec-head animate" style="--i:{ai()}">Overview</div>
<div class="kpi-row animate" style="--i:{ai()}">
{_build_kpi_row(results)}
</div>

<div id="s1" class="sec-head animate" style="--i:{ai()}">1 &mdash; God Functions</div>
<p class="animate" style="--i:{ai()}; color: var(--text-dim); font-size: 13px; margin-bottom: 12px;">
  Functions with &gt;{MAX_LOCALS_GOD} locals, &gt;{MAX_CC_GOD} CC, and &gt;{MAX_FUNC_LINES_GOD} lines.
</p>
<div class="animate" style="--i:{ai()}">
{_build_god_functions_table(results.get("god_functions", []))}
</div>

<div id="s2" class="sec-head animate" style="--i:{ai()}">2 &mdash; High Cyclomatic Complexity</div>
<p class="animate" style="--i:{ai()}; color: var(--text-dim); font-size: 13px; margin-bottom: 12px;">
  Functions with CC &gt; {MAX_CC}.
</p>
<div class="animate" style="--i:{ai()}">
{_build_complexity_table(results.get("high_complexity", []))}
</div>

<div id="s3" class="sec-head animate" style="--i:{ai()}">3 &mdash; Deep Nesting</div>
<p class="animate" style="--i:{ai()}; color: var(--text-dim); font-size: 13px; margin-bottom: 12px;">
  Functions with nesting depth &ge; {MAX_DEPTH + 1}.
</p>
<div class="animate" style="--i:{ai()}">
{_build_nesting_table(results.get("deep_nesting", []))}
</div>

<div id="s4" class="sec-head animate" style="--i:{ai()}">4 &mdash; Large Functions</div>
<div class="animate" style="--i:{ai()}">
{_build_large_functions_table(results.get("large_functions", []))}
</div>

<div id="s5" class="sec-head animate" style="--i:{ai()}">5 &mdash; Long Files</div>
<div class="animate" style="--i:{ai()}">
{_build_long_files_table(results.get("long_files", []))}
</div>

<div id="s6" class="sec-head animate" style="--i:{ai()}">6 &mdash; Repeated Magic Strings</div>
<div class="animate" style="--i:{ai()}">
{_build_dup_strings_section(results.get("duplicate_strings", []))}
</div>

</div>
</div>

<script>
{_JS}</script>
</body>
</html>
"""


def main() -> int:
    results = analyze()
    total_issues = print_report(results)

    # Auto-generate HTML dashboard
    HTML_OUT.parent.mkdir(parents=True, exist_ok=True)
    html = generate_html_report(results)
    HTML_OUT.write_text(html, encoding="utf-8")
    print(f"\n  HTML report: {HTML_OUT}")

    return 1 if total_issues > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
