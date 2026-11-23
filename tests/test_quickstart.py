"""Phase 5 A: the quickstart is executable documentation.

Every ``python`` block runs, in order, as one script in an empty directory; every ``bash run``
block runs its ``redhand-shield`` lines through the installed module. The expected-output block
must match what the script printed, so the page cannot rot.
"""

# ruff: noqa: S603
from __future__ import annotations

import re
import shlex
import subprocess
import sys
from pathlib import Path

DOC = Path(__file__).resolve().parents[1] / "docs" / "quickstart.md"
_FENCE = re.compile(r"^```(?P<info>[^\n]*)\n(?P<body>.*?)^```$", re.S | re.M)


def _blocks(info: str) -> list[str]:
    return [m["body"] for m in _FENCE.finditer(DOC.read_text("utf-8")) if m["info"].strip() == info]


def test_quickstart_has_blocks() -> None:
    assert _blocks("python")
    assert _blocks("bash run")
    assert len(_blocks("text")) == 1


def test_quickstart_runs_and_prints_what_it_claims(tmp_path: Path) -> None:
    script = tmp_path / "quickstart.py"
    script.write_text("\n".join(_blocks("python")), "utf-8")
    run = subprocess.run(
        [sys.executable, "-I", str(script)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert run.returncode == 0, run.stderr
    assert run.stdout.strip() == _blocks("text")[0].strip()
    assert (tmp_path / "audit.jsonl").exists()


def test_quickstart_cli_steps_verify_the_chain(tmp_path: Path) -> None:
    script = tmp_path / "quickstart.py"
    script.write_text("\n".join(_blocks("python")), "utf-8")
    subprocess.run([sys.executable, "-I", str(script)], cwd=tmp_path, check=True, timeout=60)
    ran = 0
    for block in _blocks("bash run"):
        for line in block.splitlines():
            argv = shlex.split(line)
            if not argv:
                continue
            assert argv[0] == "redhand-shield"
            done = subprocess.run(
                [sys.executable, "-I", "-m", "redhand_fintech_shield", *argv[1:]],
                cwd=tmp_path,
                capture_output=True,
                text=True,
                timeout=60,
            )
            assert done.returncode == 0, (line, done.stderr)
            ran += 1
    assert ran >= 2


def test_quickstart_tamper_claim_is_true(tmp_path: Path) -> None:
    script = tmp_path / "quickstart.py"
    script.write_text("\n".join(_blocks("python")), "utf-8")
    subprocess.run([sys.executable, "-I", str(script)], cwd=tmp_path, check=True, timeout=60)
    log = tmp_path / "audit.jsonl"
    lines = log.read_text("utf-8").splitlines()
    lines[0] = lines[0].replace("settle_merchant", "settle_merchan7", 1)
    log.write_text("\n".join(lines) + "\n", "utf-8")
    done = subprocess.run(
        [sys.executable, "-I", "-m", "redhand_fintech_shield", "verify-audit", str(log)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert done.returncode != 0
    assert "BROKEN" in done.stdout + done.stderr
