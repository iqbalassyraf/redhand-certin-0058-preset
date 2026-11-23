"""Phase 5 B: the documentation site is generated, deterministic and has no dead links."""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("build_docs", ROOT / "scripts" / "build_docs.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["build_docs"] = mod
    spec.loader.exec_module(mod)
    return mod


build_docs = _load()


def _convert(md: str) -> str:
    return str(build_docs.Converter(lambda href: href).convert(md))


def test_headings_get_unique_ids() -> None:
    out = _convert("# Title\n\n## Same\n\n## Same\n")
    assert '<h1 id="title">Title</h1>' in out
    assert 'id="same"' in out and 'id="same-2"' in out


def test_inline_markup_and_escaping() -> None:
    out = _convert("A **bold** and *it* with `a<b` and [x](y.md) <script>\n")
    assert "<strong>bold</strong>" in out and "<em>it</em>" in out
    assert "<code>a&lt;b</code>" in out and '<a href="y.md">x</a>' in out
    assert "<script>" not in out and "&lt;script&gt;" in out


def test_code_fence_is_escaped_and_not_interpreted() -> None:
    out = _convert("```python\nx = '<b>' * 2  # **no**\n```\n")
    assert '<pre class="lang-python">' in out
    assert "&lt;b&gt;" in out and "<strong>" not in out


def test_nested_lists_and_ordered() -> None:
    out = _convert("1. one\n   - sub a\n   - sub b\n2. two\n")
    assert out.count("<ol>") == 1 and out.count("<ul>") == 1
    assert "<li>one<ul><li>sub a</li><li>sub b</li></ul></li>" in out


def test_table_keeps_pipes_inside_code_and_br() -> None:
    out = _convert("| a | b |\n|---|---|\n| `x|y` | l1<br>l2 |\n")
    assert "<code>x|y</code>" in out and "l1<br>l2" in out
    assert out.count("<td>") == 2 and out.count("<th>") == 2


def test_svg_block_passes_through() -> None:
    out = _convert('<svg viewBox="0 0 1 1">\n<rect/>\n</svg>\n\nafter\n')
    assert '<div class="figure"><svg' in out and "<p>after</p>" in out


def test_build_is_deterministic() -> None:
    assert build_docs.build() == build_docs.build()


def test_committed_site_matches_fresh_build() -> None:
    assert build_docs.main(["--check"]) == 0, "run: python scripts/build_docs.py"


def test_every_page_is_linked_from_the_nav_and_has_content() -> None:
    outputs = build_docs.build()
    for page in build_docs.PAGES:
        html = outputs[f"{page.slug}.html"].decode()
        assert f'href="{page.slug}.html"' in html
        assert re.search(r"<h1 id=", html), page.slug
        assert "<script" not in html


def test_missing_link_target_is_a_build_error() -> None:
    resolve = build_docs._make_resolver(build_docs.PAGES[0], {}, {})
    with pytest.raises(SystemExit, match="missing file"):
        resolve("no-such-file.md")


def test_non_page_repo_links_become_github_urls() -> None:
    resolve = build_docs._make_resolver(build_docs.PAGES[0], {}, {})
    assert resolve("../CONTRIBUTING.md").startswith(build_docs.REPO_URL + "/blob/main/")
    assert resolve("../schemas").startswith(build_docs.REPO_URL + "/tree/main/")
