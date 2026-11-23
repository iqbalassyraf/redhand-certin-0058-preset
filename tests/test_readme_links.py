"""The README is the PyPI page: its links must work outside a checkout."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = "https://github.com/iqbalassyraf/redhand-certin-0058-preset"
LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")


def _links() -> list[str]:
    text = (ROOT / "README.md").read_text("utf-8")
    text = re.sub(r"```.*?```", "", text, flags=re.S)
    return LINK.findall(text)


def test_readme_has_links() -> None:
    assert len(_links()) > 5


def test_no_relative_links_that_break_on_pypi() -> None:
    bad = [u for u in _links() if not u.startswith(("http://", "https://", "#", "mailto:"))]
    assert not bad, f"relative README links do not work on PyPI: {bad}"


def test_repository_links_point_at_files_that_exist() -> None:
    for url in _links():
        for kind in ("blob", "tree"):
            prefix = f"{REPO}/{kind}/main/"
            if url.startswith(prefix):
                path = url[len(prefix) :].split("#")[0]
                assert (ROOT / path).exists(), f"README links to a missing path: {path}"


def test_project_urls_are_declared() -> None:
    import tomllib

    urls = tomllib.loads((ROOT / "pyproject.toml").read_text("utf-8"))["project"]["urls"]
    assert {"Homepage", "Repository", "Issues", "Changelog", "Documentation"} <= set(urls)
    assert all(v.startswith(REPO) for v in urls.values())
