"""Rewrite README image paths for mkdocs compatibility.

README.md uses paths like ``docs/screenshots/...`` (relative to repo root for GitHub).
When included in ``docs/index.md`` via pymdownx.snippets, mkdocs resolves paths relative
to ``docs/``, so we strip the ``docs/`` prefix.

This hook runs at ``on_page_markdown`` — before pymdownx.snippets expands the
``--8<-- "README.md"`` directive. We manually inline the README with adjusted paths
so that link validation sees the correct references.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mkdocs.structure.pages import Page

SNIPPET_DIRECTIVE = '--8<-- "README.md"'

# Only rewrite docs/screenshots/ in markdown image syntax and HTML img tags,
# not inside fenced code blocks where paths are literal bash commands.
_IMAGE_PATH_RE = re.compile(
    r'(\!\[.*?\]\()docs/screenshots/|(<img\s+[^>]*src=")docs/screenshots/',
)


def _rewrite_match(m: re.Match[str]) -> str:
    return (m.group(1) or m.group(2)) + "screenshots/"


def on_page_markdown(markdown: str, page: Page, **_kwargs: object) -> str:
    if page.file.src_path == "index.md" and SNIPPET_DIRECTIVE in markdown:
        readme = Path("README.md").read_text(encoding="utf-8")
        adjusted = _IMAGE_PATH_RE.sub(_rewrite_match, readme)
        return markdown.replace(SNIPPET_DIRECTIVE, adjusted)
    return markdown
