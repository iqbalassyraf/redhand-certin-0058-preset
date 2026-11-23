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
        allowed = {f'<script src="{n}"></script>' for n in page.scripts}
        assert set(re.findall(r"<script[^>]*></script>", html)) == allowed, page.slug


def test_missing_link_target_is_a_build_error() -> None:
    resolve = build_docs._make_resolver(build_docs.PAGES[0], {}, {})
    with pytest.raises(SystemExit, match="missing file"):
        resolve("no-such-file.md")


def test_non_page_repo_links_become_github_urls() -> None:
    resolve = build_docs._make_resolver(build_docs.PAGES[0], {}, {})
    assert resolve("../CONTRIBUTING.md").startswith(build_docs.REPO_URL + "/blob/main/")
    assert resolve("../schemas").startswith(build_docs.REPO_URL + "/tree/main/")


def test_disallowed_script_is_a_build_error() -> None:
    page = build_docs.PAGES[0]
    outputs = {"x.html": b'<a href="x.html">ok</a><script>alert(1)</script>'}
    with pytest.raises(SystemExit, match="disallowed script"):
        build_docs._validate(outputs, {"x.html": []})
    assert page.slug == "index"


def test_transcript_tail_and_headline_numbers() -> None:
    text = (ROOT / "docs" / "demo" / "crafty_falcon.txt").read_text("utf-8")
    assert "Malicious steps stopped" in text and "$0.50" in text and "$54,503.50" in text
    assert "chain OK: 34 records" in text and "chain BROKEN" in text
    assert "\x1b" not in text and "/tmp/crafty_falcon_" not in text


def test_cast_is_valid_asciicast_v2() -> None:
    import json

    lines = (ROOT / "docs" / "demo" / "crafty_falcon.cast").read_text("utf-8").splitlines()
    header = json.loads(lines[0])
    assert header["version"] == 2 and header["width"] == 100 and header["height"] > 0
    events = [json.loads(line) for line in lines[1:]]
    assert len(events) > 20
    times = [e[0] for e in events]
    assert times == sorted(times) and all(e[1] == "o" and isinstance(e[2], str) for e in events)
    assert "/tmp/crafty_falcon_" not in "".join(e[2] for e in events)


def test_site_copies_match_the_recording() -> None:
    site = ROOT / "docs" / "site"
    demo = ROOT / "docs" / "demo"
    assert (site / "crafty_falcon.cast").read_bytes() == (demo / "crafty_falcon.cast").read_bytes()
    assert (site / "player.js").read_bytes() == (demo / "player.js").read_bytes()
    html = (site / "demo.html").read_text("utf-8")
    assert "chain BROKEN" in html  # the transcript fallback is embedded in the page


def test_player_makes_no_network_calls() -> None:
    js = (ROOT / "docs" / "demo" / "player.js").read_text("utf-8")
    for needle in ("fetch(", "XMLHttpRequest", "WebSocket", "http://", "https://", "eval("):
        assert needle not in js, needle
