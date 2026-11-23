#!/usr/bin/env python3
"""Run docs/quickstart.md against an installed package, exactly as a new user would.

``python scripts/run_quickstart.py [--python PATH]`` extracts the ``python`` blocks (run in order as
one script, in an empty directory), checks the output against the page's expected-output block,
then runs each ``bash run`` line with ``redhand-shield`` mapped to ``PATH -m redhand_fintech_shield``.
CI runs it with the Python of a clean virtualenv that holds only the built wheel.
"""

from __future__ import annotations

import argparse
import re
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

DOC = Path(__file__).resolve().parents[1] / "docs" / "quickstart.md"
_FENCE = re.compile(r"^```(?P<info>[^\n]*)\n(?P<body>.*?)^```$", re.S | re.M)


def blocks(info: str) -> list[str]:
    return [m["body"] for m in _FENCE.finditer(DOC.read_text("utf-8")) if m["info"].strip() == info]


def run(python: str) -> int:
    expected = blocks("text")
    if not blocks("python") or not blocks("bash run") or len(expected) != 1:
        print("quickstart.md is missing its python, bash run or expected-output block")
        return 1
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        script = work / "quickstart.py"
        script.write_text("\n".join(blocks("python")), "utf-8")
        done = subprocess.run(  # noqa: S603
            [python, "-I", str(script)], cwd=work, capture_output=True, text=True, timeout=120
        )
        if done.returncode != 0:
            print(done.stdout + done.stderr)
            return 1
        if done.stdout.strip() != expected[0].strip():
            print(
                f"output differs from the page:\n--- got\n{done.stdout}\n--- expected\n{expected[0]}"
            )
            return 1
        for block in blocks("bash run"):
            for line in filter(None, (ln.strip() for ln in block.splitlines())):
                argv = shlex.split(line)
                if argv[0] != "redhand-shield":
                    print(f"unexpected command in a bash run block: {line}")
                    return 1
                step = subprocess.run(  # noqa: S603
                    [python, "-I", "-m", "redhand_fintech_shield", *argv[1:]],
                    cwd=work,
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                if step.returncode != 0:
                    print(f"`{line}` failed:\n{step.stdout}{step.stderr}")
                    return 1
    print("quickstart OK")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument(
        "--python", default=sys.executable, help="interpreter with the package installed"
    )
    return run(ap.parse_args(argv).python)


if __name__ == "__main__":
    sys.exit(main())
