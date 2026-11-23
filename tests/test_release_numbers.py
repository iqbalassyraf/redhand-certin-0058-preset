"""Phase 5 E: every number in the announcement is reproducible from the repository."""

from __future__ import annotations

import importlib.util
import json
import os
import re
import sys
from pathlib import Path
from types import ModuleType

import pytest

import redhand_fintech_shield as package

ROOT = Path(__file__).resolve().parents[1]


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "release_numbers", ROOT / "scripts" / "release_numbers.py"
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["release_numbers"] = mod
    spec.loader.exec_module(mod)
    return mod


rn = _load()


def test_exact_numbers_match_the_generated_detection_results() -> None:
    nums = rn.exact()
    text = (ROOT / "docs" / "detection-results.md").read_text("utf-8")
    assert f"| Scenarios | {nums['scenarios']} |" in text
    assert f"| Attack scenarios the preset should catch | {nums['attacks']} |" in text
    assert f"| Benign scenarios checked | {nums['benign']} |" in text
    assert f"| Documented gaps (attacks not caught, by design) | {nums['gaps']} |" in text
    assert f"| Documented false positives | {nums['false_positives']} |" in text
    assert f"{nums['attacks_stopped']} ({nums['detection_pct']}%)" in text
    assert nums["corpus_policy_fingerprint"] in text and nums["corpus_sha"] in text
    assert nums["package_version"] == package.__version__


measuring = pytest.mark.skipif(
    bool(os.environ.get("REDHAND_RELEASE_MEASURING")),
    reason="--measure is recording the numbers these gates compare against",
)


@measuring
def test_committed_announcement_matches_a_fresh_render() -> None:
    assert rn.main(["--render", "--check"]) == 0, "run: python scripts/release_numbers.py --render"


def test_render_check_fails_when_the_announcement_is_stale(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stale = tmp_path / "announcement.md"
    stale.write_text("old numbers", "utf-8")
    monkeypatch.setattr(rn, "ANNOUNCEMENT", stale)
    assert rn.main(["--render", "--check"]) == 1


def test_unknown_placeholder_is_an_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    tpl = tmp_path / "t.md"
    tpl.write_text("{{nope}}", "utf-8")
    monkeypatch.setattr(rn, "TEMPLATE", tpl)
    with pytest.raises(SystemExit, match="unknown numbers: nope"):
        rn.render({"x": "1"})


def test_template_contains_no_hand_typed_numbers() -> None:
    text = (ROOT / "docs" / "announcement.template.md").read_text("utf-8")
    text = re.sub(r"```.*?```", "", text, flags=re.S)
    text = re.sub(r"`[^`]*`", "", text)
    text = re.sub(r"\{\{[a-z0-9_]+\}\}", "", text)
    allowed_patterns = (
        r"redhand-certin-0058-preset",
        r"CIAD-\d{4}-\d{4}",
        r"M\d\.\d",
        r"\bp\d\d\b",
        r"SHA-256",
        r"sha256",
        r"Ed25519",
    )
    for allowed in allowed_patterns:
        text = re.sub(allowed, "", text)
    leftovers = re.findall(r"\d+", text)
    assert not leftovers, f"hand-typed numbers in the announcement template: {leftovers}"


def test_every_placeholder_is_known_and_filled() -> None:
    template = (ROOT / "docs" / "announcement.template.md").read_text("utf-8")
    keys = set(rn.PLACEHOLDER.findall(template))
    known = set(rn.exact()) | set(rn.load_measurements())
    assert keys <= known, sorted(keys - known)
    assert "{{" not in (ROOT / "docs" / "announcement.md").read_text("utf-8")


@measuring
def test_measurements_were_recorded_for_this_version() -> None:
    data = json.loads(rn.MEASUREMENTS.read_text("utf-8"))
    assert data["recorded_for_version"] == package.__version__, (
        "re-run: python scripts/release_numbers.py --measure && "
        "python scripts/release_numbers.py --render"
    )
    assert int(data["tests_passed"]) > 0 and float(data["coverage_pct"]) >= 97.0
    for key in ("bench_command", "test_command", "python", "platform"):
        assert data[key]


def test_announcement_labels_measurements_and_lists_commands() -> None:
    text = " ".join((ROOT / "docs" / "announcement.md").read_text("utf-8").split())
    assert "depend on the machine" in text and "not guarantees" in text
    assert "synthetic" in text and "regression check" in text
    for cmd in (
        "redhand-shield replay",
        "redhand-shield manifest",
        "redhand-shield api",
        "python benchmarks/bench_latency.py",
        "pytest -q",
        "python scripts/release_numbers.py --render --check",
    ):
        assert cmd in text, cmd


def test_documented_gaps_are_stated_not_hidden() -> None:
    text = " ".join((ROOT / "docs" / "announcement.md").read_text("utf-8").split())
    nums = rn.exact()
    assert f"{nums['gaps']} attacks are documented gaps" in text
    assert f"{nums['false_positives']} benign cases are documented false positives" in text
