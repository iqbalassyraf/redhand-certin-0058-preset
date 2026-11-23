"""Revoking agent tokens: by token id, by subject, or by agent run.

A short-lived run token cannot be recalled, so an operator who learns that one leaked needs a way
to stop it before it expires. Revocations are journaled (one JSON line each) and the registry
re-reads the journal at most once per ``poll_seconds``, so ``redhand-shield revoke`` takes effect
in a running shield without a restart.

A ``jti`` *replay cache* is deliberately not offered: a run token is meant to be presented on every
call of its run, so rejecting a second use would break normal operation. Revocation is the control
that answers a stolen token.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Literal

from .crypto import utcnow

_log = logging.getLogger(__name__)
Kind = Literal["jti", "subject", "run"]
KINDS: tuple[Kind, ...] = ("jti", "subject", "run")


class RevocationRegistry:
    """In-memory revocations with an optional journal shared with other processes."""

    def __init__(
        self,
        journal_path: Path | None = None,
        *,
        clock: Callable[[], datetime] = utcnow,
        poll_seconds: float = 1.0,
        poll_clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._path = journal_path
        self._clock = clock
        self._poll = poll_seconds
        self._poll_clock = poll_clock
        self._lock = threading.Lock()
        self._entries: dict[tuple[str, str], tuple[str, int | None]] = {}
        self._offset = 0
        self._next_poll = 0.0
        with self._lock:
            self._refresh(force=True)

    def _now(self) -> int:
        return int(self._clock().timestamp())

    def _refresh(self, *, force: bool = False) -> None:
        """Read complete journal lines appended since the last read (lock held)."""
        if self._path is None:
            return
        tick = self._poll_clock()
        if not force and tick < self._next_poll:
            return
        self._next_poll = tick + self._poll
        try:
            size = self._path.stat().st_size
        except OSError:
            return
        if size < self._offset:  # truncated or replaced: start again from the top
            self._offset = 0
            self._entries.clear()
        if size == self._offset:
            return
        with self._path.open("rb") as fh:
            fh.seek(self._offset)
            data = fh.read(size - self._offset)
        end = data.rfind(b"\n")
        if end == -1:  # a line another process is still writing
            return
        for raw in data[: end + 1].splitlines():
            if not raw.strip():
                continue
            try:
                entry = json.loads(raw)
                kind, value = str(entry["kind"]), str(entry["value"])
                expires = entry.get("expires_at")
                self._entries[(kind, value)] = (
                    str(entry["reason"]),
                    None if expires is None else int(expires),
                )
            except (ValueError, KeyError, TypeError):
                _log.warning("ignoring unreadable revocation journal line in %s", self._path)
        self._offset += end + 1

    def reason(self, jti: str, subject: str, agent_run_id: str) -> str | None:
        """Why this token is revoked, or None. Expired revocations no longer apply."""
        with self._lock:
            self._refresh()
            now = self._now()
            for kind, value in (("jti", jti), ("subject", subject), ("run", agent_run_id)):
                found = self._entries.get((kind, value))
                if found is not None and (found[1] is None or found[1] > now):
                    return f"{kind} {value!r} revoked: {found[0]}"
        return None

    def revoke(self, kind: Kind, value: str, reason: str, expires_at: int | None = None) -> bool:
        """Revoke ``value``. Returns False if it is already revoked."""
        if kind not in KINDS:
            raise ValueError(f"kind must be one of {KINDS}")
        if not value.strip() or not reason.strip():
            raise ValueError("a revocation needs a value and a reason")
        with self._lock:
            self._refresh(force=True)
            existing = self._entries.get((kind, value))
            if existing is not None and (existing[1] is None or existing[1] > self._now()):
                return False
            if self._path is not None:
                line = json.dumps(
                    {
                        "kind": kind,
                        "value": value,
                        "reason": reason,
                        "expires_at": expires_at,
                        "ts": self._clock().isoformat(),
                    },
                    separators=(",", ":"),
                )
                self._path.parent.mkdir(parents=True, exist_ok=True)
                lead = ""
                if self._path.exists() and self._path.stat().st_size:
                    with self._path.open("rb") as fh:
                        fh.seek(-1, 2)
                        lead = "" if fh.read(1) == b"\n" else "\n"  # never glue onto a torn line
                with self._path.open("a", encoding="utf-8") as fh:
                    fh.write(lead + line + "\n")
            self._entries[(kind, value)] = (reason, expires_at)
            return True
