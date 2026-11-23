#!/usr/bin/env python3
"""Record the CRAFTY FALCON simulation as an asciicast v2 file plus a plain-text transcript.

``python scripts/record_demo.py`` runs ``examples/simulate_crafty_falcon.py`` under a real
pseudo-terminal (fixed 100x30), so colours and box drawing come out exactly as a user sees them,
and writes ``docs/demo/crafty_falcon.cast`` and ``docs/demo/crafty_falcon.txt``.

Recording needs the ``demo`` extra (rich). The timings printed by the simulation are real
measurements from the machine that recorded it, so a re-recording changes those digits; the
committed site is rebuilt from the committed recording by ``scripts/build_docs.py``.
POSIX only (uses ``pty``).
"""

# ruff: noqa: S108  (the /tmp path is text being scrubbed from output, not a file we open)
from __future__ import annotations

import codecs
import fcntl
import json
import os
import pty
import re
import select
import struct
import subprocess
import sys
import termios
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "demo"
WIDTH, HEIGHT = 100, 30
DELAY = "0.25"
TMP_PATH = re.compile(r"/tmp/crafty_falcon_[A-Za-z0-9_]+")
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def record() -> tuple[list[tuple[float, str]], int]:
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", HEIGHT, WIDTH, 0, 0))
    env = {
        **os.environ,
        "TERM": "xterm-256color",
        "COLUMNS": str(WIDTH),
        "LINES": str(HEIGHT),
        "PYTHONUNBUFFERED": "1",
        "PYTHONIOENCODING": "utf-8",
    }
    env.pop("NO_COLOR", None)
    cmd = [
        sys.executable,
        str(ROOT / "examples" / "simulate_crafty_falcon.py"),
        "--mode",
        "both",
        "--delay",
        DELAY,
    ]
    proc = subprocess.Popen(  # noqa: S603
        cmd, stdin=slave, stdout=slave, stderr=slave, env=env, cwd=ROOT, close_fds=True
    )
    os.close(slave)
    decoder = codecs.getincrementaldecoder("utf-8")("replace")
    events: list[tuple[float, str]] = []
    start = time.monotonic()
    while True:
        ready, _, _ = select.select([master], [], [], 0.1)
        if ready:
            try:
                data = os.read(master, 4096)
            except OSError:  # pty closed on Linux once the child exits
                break
            if not data:
                break
            text = decoder.decode(data)
            if text:
                events.append((round(time.monotonic() - start, 3), text))
        elif proc.poll() is not None:
            break
    os.close(master)
    return events, proc.wait()


def clean(text: str) -> str:
    return TMP_PATH.sub("/tmp/crafty_falcon", text)


def write(events: list[tuple[float, str]]) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    header = {
        "version": 2,
        "width": WIDTH,
        "height": HEIGHT,
        "title": "CRAFTY FALCON: enforce vs observe-only",
        "env": {"TERM": "xterm-256color", "SHELL": "/bin/bash"},
    }
    lines = [json.dumps(header, separators=(",", ":"))]
    for t, text in events:
        lines.append(json.dumps([t, "o", clean(text)], ensure_ascii=False, separators=(",", ":")))
    (OUT / "crafty_falcon.cast").write_text("\n".join(lines) + "\n", "utf-8")
    plain = ANSI.sub("", clean("".join(text for _, text in events))).replace("\r\n", "\n")
    (OUT / "crafty_falcon.txt").write_text(plain.rstrip() + "\n", "utf-8")


def main() -> int:
    events, code = record()
    if code != 0 or not events:
        print(f"simulation exited {code}; not writing a recording", file=sys.stderr)
        return 1
    write(events)
    print(f"recorded {len(events)} events, {events[-1][0]:.1f}s -> {OUT.relative_to(ROOT)}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
