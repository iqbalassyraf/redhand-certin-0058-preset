#!/usr/bin/env python3
"""Build the static documentation site from the repository's Markdown (stdlib only).

``python scripts/build_docs.py``         write ``docs/site/`` and ``docs/index.html``
``python scripts/build_docs.py --check`` fail if the committed site differs from a fresh build

The converter handles exactly the Markdown subset these docs use: headings, paragraphs, nested
bullet and numbered lists, tables, fenced code, block quotes, rules, raw ``<svg>`` blocks, inline
code, bold, italics and links. Output is deterministic (no timestamps), offline, and script-free.
Link targets that are not pages become GitHub URLs; a target that does not exist is a build error.
"""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "docs" / "site"
REPO_URL = "https://github.com/iqbalassyraf/redhand-certin-0058-preset"


@dataclass(frozen=True)
class Page:
    slug: str
    title: str
    source: str  # repo-relative path
    section: str | None = None  # if set, only this "## heading" section of the source
    scripts: tuple[str, ...] = ()  # local script files (names in the site) to load on this page


# Repo files that are copied into the site verbatim; links to them point at the copy.
SITE_ASSETS = {
    "docs/demo/crafty_falcon.cast": "crafty_falcon.cast",
    "docs/demo/crafty_falcon.txt": "crafty_falcon.txt",
}

# One table: later steps append here.
PAGES: tuple[Page, ...] = (
    Page("index", "Home", "docs/home.md"),
    Page("quickstart", "Quickstart", "docs/quickstart.md"),
    Page("architecture", "Architecture", "docs/architecture.md"),
    Page("demo", "Demo", "docs/demo.md", scripts=("cast.js", "player.js")),
    Page("threat-model", "Threat model", "docs/threat-model.md"),
    Page("rules", "Rule catalog", "docs/rules.md"),
    Page(
        "integration",
        "Integration",
        "README.md",
        "Integrating with a host application",
    ),
    Page("detection-results", "Detection results", "docs/detection-results.md"),
)

# ---------------------------------------------------------------------------------------------
# Markdown subset -> HTML
# ---------------------------------------------------------------------------------------------


def slugify(text: str) -> str:
    text = re.sub(r"`|\*\*|\[|\]|\([^)]*\)", "", text).lower()
    return re.sub(r"[^a-z0-9]+", "-", text).strip("-") or "section"


class Converter:
    def __init__(self, resolve_link: Callable[[str], str]) -> None:
        self._resolve = resolve_link
        self.ids: dict[str, int] = {}
        self.anchors: list[str] = []

    # -- inline -------------------------------------------------------------------------------
    def inline(self, text: str) -> str:
        parts = re.split(r"(`[^`]+`)", text)
        out: list[str] = []
        for part in parts:
            if part.startswith("`") and part.endswith("`") and len(part) > 1:
                out.append(f"<code>{html.escape(part[1:-1])}</code>")
                continue
            esc = html.escape(part, quote=False).replace("&lt;br&gt;", "<br>")
            esc = re.sub(
                r"\[([^\]]+)\]\(([^)\s]+)\)",
                lambda m: f'<a href="{html.escape(self._resolve(m[2]), quote=True)}">{m[1]}</a>',
                esc,
            )
            esc = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", esc)
            esc = re.sub(r"(?<![*\w])\*(?!\s)([^*]+?)(?<!\s)\*(?![*\w])", r"<em>\1</em>", esc)
            out.append(esc)
        return "".join(out)

    # -- blocks -------------------------------------------------------------------------------
    def convert(self, md: str) -> str:
        lines = md.replace("\r\n", "\n").split("\n")
        out: list[str] = []
        i = 0
        while i < len(lines):
            line = lines[i]
            if not line.strip():
                i += 1
            elif line.startswith("```"):
                lang = line[3:].strip().split()[0] if line[3:].strip() else ""
                i += 1
                body: list[str] = []
                while i < len(lines) and not lines[i].startswith("```"):
                    body.append(lines[i])
                    i += 1
                i += 1
                cls = f' class="lang-{html.escape(lang)}"' if lang else ""
                out.append(f"<pre{cls}><code>{html.escape(chr(10).join(body))}</code></pre>")
            elif line.startswith("<div"):
                body = []
                while i < len(lines) and lines[i].strip():
                    body.append(lines[i])
                    i += 1
                out.append("\n".join(body))
            elif line.startswith("<svg"):
                body = []
                while i < len(lines):
                    body.append(lines[i])
                    i += 1
                    if "</svg>" in body[-1]:
                        break
                out.append('<div class="figure">' + "\n".join(body) + "</div>")
            elif m := re.match(r"(#{1,4}) (.+)$", line):
                level = len(m[1])
                ident = self._unique(slugify(m[2]))
                self.anchors.append(ident)
                out.append(f'<h{level} id="{ident}">{self.inline(m[2])}</h{level}>')
                i += 1
            elif re.match(r"-{3,}$", line.strip()):
                out.append("<hr>")
                i += 1
            elif (
                line.startswith("|")
                and i + 1 < len(lines)
                and re.match(r"\|[\s:|-]+\|?$", lines[i + 1])
            ):
                rows = []
                while i < len(lines) and lines[i].startswith("|"):
                    rows.append(lines[i])
                    i += 1
                out.append(self._table(rows))
            elif line.startswith(">"):
                body = []
                while i < len(lines) and lines[i].startswith(">"):
                    body.append(lines[i][1:].strip())
                    i += 1
                out.append(f"<blockquote><p>{self.inline(' '.join(body))}</p></blockquote>")
            elif re.match(r"\s*([-*]|\d+\.) ", line):
                block: list[str] = []
                while i < len(lines) and (
                    re.match(r"\s*([-*]|\d+\.) ", lines[i])
                    or (lines[i].startswith("  ") and lines[i].strip() and block)
                    or (
                        not lines[i].strip()
                        and i + 1 < len(lines)
                        and re.match(r"\s+([-*]|\d+\.) ", lines[i + 1])
                    )
                ):
                    block.append(lines[i])
                    i += 1
                out.append(self._list(block))
            else:
                para = []
                while i < len(lines) and lines[i].strip() and not self._starts_block(lines[i]):
                    para.append(lines[i].strip())
                    i += 1
                out.append(f"<p>{self.inline(' '.join(para))}</p>")
        return "\n".join(out)

    @staticmethod
    def _starts_block(line: str) -> bool:
        return bool(
            line.startswith(("```", "|", ">", "<svg", "<div"))
            or re.match(r"(#{1,4}) ", line)
            or re.match(r"\s*([-*]|\d+\.) ", line)
        )

    def _unique(self, base: str) -> str:
        n = self.ids.get(base, 0)
        self.ids[base] = n + 1
        return base if n == 0 else f"{base}-{n + 1}"

    def _table(self, rows: list[str]) -> str:
        def cells(row: str) -> list[str]:
            row = row.strip()
            row = row[1:] if row.startswith("|") else row
            row = row[:-1] if row.endswith("|") else row
            # split on unescaped pipes outside code spans
            parts, cur, in_code = [], "", False
            for ch in row:
                if ch == "`":
                    in_code = not in_code
                if ch == "|" and not in_code:
                    parts.append(cur.strip())
                    cur = ""
                else:
                    cur += ch
            parts.append(cur.strip())
            return parts

        head = cells(rows[0])
        body = [cells(r) for r in rows[2:]]
        th = "".join(f"<th>{self.inline(c)}</th>" for c in head)
        trs = "".join(
            "<tr>" + "".join(f"<td>{self.inline(c)}</td>" for c in r) + "</tr>" for r in body
        )
        return f'<div class="tablewrap"><table><thead><tr>{th}</tr></thead><tbody>{trs}</tbody></table></div>'

    def _list(self, block: list[str]) -> str:
        items: list[tuple[int, bool, str]] = []  # indent, ordered, text
        for raw in block:
            if not raw.strip():
                continue
            if m := re.match(r"(\s*)([-*]|\d+\.) (.*)$", raw):
                items.append((len(m[1]), m[2][0].isdigit(), m[3].strip()))
            else:
                ind, ordered, text = items[-1]
                items[-1] = (ind, ordered, f"{text} {raw.strip()}")
        return self._render_items(items, 0)[0]

    def _render_items(self, items: list[tuple[int, bool, str]], pos: int) -> tuple[str, int]:
        base = items[pos][0]
        tag = "ol" if items[pos][1] else "ul"
        out = [f"<{tag}>"]
        while pos < len(items) and items[pos][0] >= base:
            ind, _ordered, text = items[pos]
            if ind > base:  # deeper than expected without a parent: treat as sibling
                ind = base
            pos += 1
            li = self.inline(text)
            if pos < len(items) and items[pos][0] > base:
                sub, pos = self._render_items(items, pos)
                li += sub
            out.append(f"<li>{li}</li>")
        out.append(f"</{tag}>")
        return "".join(out), pos


# ---------------------------------------------------------------------------------------------
# Site assembly
# ---------------------------------------------------------------------------------------------

CSS = """\
:root{--bg:#fff;--fg:#1b1f24;--muted:#57606a;--line:#d0d7de;--code:#f6f8fa;--link:#0b5cad;--accent:#0b5cad;--ok:#1a7f37;--bad:#cf222e}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--muted:#9198a1;--line:#30363d;--code:#161b22;--link:#58a6ff;--accent:#58a6ff;--ok:#3fb950;--bad:#f85149}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif}
a{color:var(--link)}
header.top{border-bottom:1px solid var(--line);padding:12px 16px}
header.top .brand{font-weight:700;margin-right:16px}
nav a{margin-right:14px;text-decoration:none;white-space:nowrap;display:inline-block;padding:2px 0}
nav a[aria-current=page]{border-bottom:2px solid var(--accent);font-weight:600}
main{max-width:900px;margin:0 auto;padding:16px 16px 64px}
h1,h2,h3{line-height:1.25}
h2{margin-top:2em;border-bottom:1px solid var(--line);padding-bottom:4px}
code{background:var(--code);padding:1px 5px;border-radius:4px;font:0.9em ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere}
pre{background:var(--code);border:1px solid var(--line);border-radius:6px;padding:12px;overflow-x:auto}
pre code{background:none;padding:0;overflow-wrap:normal}
.tablewrap{overflow-x:auto;margin:1em 0}
table{border-collapse:collapse;min-width:100%}
th,td{border:1px solid var(--line);padding:6px 10px;text-align:left;vertical-align:top}
th{background:var(--code)}
blockquote{margin:1em 0;padding:0 1em;border-left:4px solid var(--line);color:var(--muted)}
.player{margin:1.5em 0;border:1px solid var(--line);border-radius:8px;overflow:hidden}
.player .term{background:#0d1117;color:#e6edf3;font:13px/1.2 ui-monospace,SFMono-Regular,Menlo,monospace;white-space:pre;height:30em;max-height:70vh;overflow:auto;padding:12px;margin:0}
.player .controls{display:flex;flex-wrap:wrap;gap:10px;align-items:center;padding:8px 12px;background:var(--code)}
.player .controls input[type=range]{flex:1;min-width:120px}
.player button,.player select{font:inherit;padding:2px 10px}
.player [data-clock]{color:var(--muted);font-variant-numeric:tabular-nums}
.figure{margin:1.5em 0;overflow-x:auto}
.figure svg{width:100%;height:auto;min-width:560px}
.figure .box{fill:var(--code);stroke:var(--line);stroke-width:1.5}
.figure .core{fill:none;stroke:var(--accent);stroke-width:2;stroke-dasharray:6 4}
.figure .ok{fill:var(--code);stroke:var(--ok);stroke-width:2}
.figure .bad{fill:var(--code);stroke:var(--bad);stroke-width:2}
.figure .ln{stroke:var(--muted);stroke-width:2;fill:none}
.figure .ah{fill:var(--muted)}
.figure .t{fill:var(--fg);font:600 14px system-ui,sans-serif}
.figure .s{fill:var(--muted);font:12px system-ui,sans-serif}
footer{max-width:900px;margin:0 auto;padding:16px;color:var(--muted);font-size:14px}
"""

TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} · redhand-certin-0058-preset</title>
<link rel="stylesheet" href="style.css">
</head>
<body>
<header class="top"><span class="brand">redhand-certin-0058-preset</span><nav>{nav}</nav></header>
<main>
{body}
</main>
<footer>Generated from the repository's Markdown by <code>scripts/build_docs.py</code>. Source: <a href="{repo}">{repo}</a></footer>
{scripts}</body>
</html>
"""


def _section(md: str, heading: str) -> str:
    lines = md.split("\n")
    start = next(i for i, ln in enumerate(lines) if ln == f"## {heading}")
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")), len(lines))
    return "\n".join(lines[start + 1 : end])


def _make_resolver(
    page: Page, page_by_source: dict[str, Page], aliases: dict[str, Page]
) -> Callable[[str], str]:
    base = (ROOT / page.source).parent

    def resolve(href: str) -> str:
        if re.match(r"[a-z][a-z0-9+.-]*:", href):
            return href
        path, _, frag = href.partition("#")
        suffix = f"#{frag}" if frag else ""
        if not path:
            return href
        target = (base / path).resolve()
        try:
            rel = target.relative_to(ROOT).as_posix()
        except ValueError as exc:
            raise SystemExit(f"{page.source}: link escapes the repository: {href}") from exc
        if (asset := SITE_ASSETS.get(rel)) is not None:
            return asset
        if (alias := aliases.get(f"{rel}#{frag}")) is not None:
            return f"{alias.slug}.html"
        if (dest := page_by_source.get(rel)) is not None:
            return f"{dest.slug}.html{suffix}"
        if target.is_dir():
            return f"{REPO_URL}/tree/main/{rel}"
        if target.exists():
            return f"{REPO_URL}/blob/main/{rel}{suffix}"
        raise SystemExit(f"{page.source}: link to missing file: {href}")

    return resolve


def build() -> dict[str, bytes]:
    page_by_source = {p.source: p for p in PAGES if p.section is None}
    aliases = {f"{p.source}#{slugify(p.section)}": p for p in PAGES if p.section is not None}
    outputs: dict[str, bytes] = {"style.css": CSS.encode()}
    demo = ROOT / "docs" / "demo"
    cast_lines = (demo / "crafty_falcon.cast").read_text("utf-8").splitlines()
    events = [json.loads(line) for line in cast_lines[1:]]
    outputs["cast.js"] = (
        "window.CRAFTY_FALCON_CAST = " + json.dumps(events, ensure_ascii=False) + ";\n"
    ).encode()
    outputs["player.js"] = (demo / "player.js").read_bytes()
    outputs["crafty_falcon.cast"] = (demo / "crafty_falcon.cast").read_bytes()
    transcript = (demo / "crafty_falcon.txt").read_text("utf-8")
    outputs["crafty_falcon.txt"] = transcript.encode()
    page_anchors: dict[str, list[str]] = {}
    for page in PAGES:
        md = (ROOT / page.source).read_text("utf-8")
        if page.section is not None:
            md = f"# {page.title}\n\n" + _section(md, page.section)
        md = md.replace("{{TRANSCRIPT}}", "```text\n" + transcript + "```")
        conv = Converter(_make_resolver(page, page_by_source, aliases))
        body = conv.convert(md)
        current = ' aria-current="page"'
        nav = "".join(
            f'<a href="{p.slug}.html"{current if p is page else ""}>{html.escape(p.title)}</a>'
            for p in PAGES
        )
        outputs[f"{page.slug}.html"] = TEMPLATE.format(
            title=html.escape(page.title),
            nav=nav,
            body=body,
            repo=REPO_URL,
            scripts="".join(f'<script src="{name}"></script>\n' for name in page.scripts),
        ).encode()
        page_anchors[f"{page.slug}.html"] = conv.anchors
    _validate(outputs, page_anchors)
    return outputs


def _validate(outputs: dict[str, bytes], anchors: dict[str, list[str]]) -> None:
    problems: list[str] = []
    for name, data in outputs.items():
        if not name.endswith(".html"):
            continue
        text = data.decode()
        for href in re.findall(r'href="([^"]+)"', text):
            if re.match(r"[a-z][a-z0-9+.-]*:", href):
                continue
            path, _, frag = href.partition("#")
            if path and path not in outputs:
                problems.append(f"{name}: dead link {href}")
            elif frag:
                target = path or name
                if frag not in anchors.get(target, []):
                    problems.append(f"{name}: missing anchor {href}")
        scripts = re.findall(r"<script\b[^>]*>", text)
        for tag in scripts:
            m = re.fullmatch(r'<script src="([A-Za-z0-9_.-]+\.js)">', tag)
            if m is None or m[1] not in outputs:
                problems.append(f"{name}: disallowed script tag {tag}")
        if re.search(r"https?://fonts\.|<link[^>]+href=\"https?:", text):
            problems.append(f"{name}: external or script resource")
    if problems:
        raise SystemExit("docs site problems:\n  " + "\n  ".join(problems))


REDIRECT = (
    '<!doctype html>\n<meta charset="utf-8">\n'
    '<meta http-equiv="refresh" content="0; url=site/index.html">\n'
    "<title>redhand-certin-0058-preset docs</title>\n"
    '<a href="site/index.html">Documentation</a>\n'
)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--check", action="store_true", help="fail if the committed site is stale")
    args = ap.parse_args(argv)
    outputs = {f"site/{k}": v for k, v in build().items()}
    outputs["index.html"] = REDIRECT.encode()
    outputs[".nojekyll"] = b""
    docs = ROOT / "docs"
    if args.check:
        stale = [
            k for k, v in outputs.items() if not (docs / k).exists() or (docs / k).read_bytes() != v
        ]
        extra = [
            p.relative_to(docs).as_posix()
            for p in SITE.glob("*")
            if p.relative_to(docs).as_posix() not in outputs
        ]
        if stale or extra:
            print(
                "docs site is stale; run: python scripts/build_docs.py", *stale, *extra, sep="\n  "
            )
            return 1
        print(f"docs site up to date ({len(outputs)} files)")
        return 0
    SITE.mkdir(parents=True, exist_ok=True)
    for stale_file in SITE.glob("*"):
        if stale_file.relative_to(docs).as_posix() not in outputs:
            stale_file.unlink()
    for name, data in outputs.items():
        (docs / name).write_bytes(data)
    print(f"wrote {len(outputs)} files under docs/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
