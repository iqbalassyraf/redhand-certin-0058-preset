"""SHA-256 hash-chained, tamper-evident JSONL audit log.

Chain formula (see README, "Audit log specification")::

    canonical(x)  = json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    record_hash_n = SHA256( canonical(record_n without "record_hash") )   # includes prev_hash
    prev_hash_n   = record_hash_{n-1}        prev_hash_0 = "0" * 64

Tamper-EVIDENT, not tamper-proof: an attacker with write access can rewrite the whole file with a
consistent chain. Anchor ``tail_hash`` externally (WORM storage, SIEM, notary) to close that gap;
:meth:`HashChainedAuditLog.verify_chain` accepts ``expected_tail_hash`` for exactly that check.
A single process must own a log file at a time.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Self

from .exceptions import AuditChainError
from .models import AuditRecord

GENESIS_HASH = "0" * 64
_CONTINUATION = "chain_continuation"


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def compute_record_hash(body: dict[str, Any]) -> str:
    """Hash of a record body (which must already contain ``prev_hash``)."""
    return sha256_hex(canonical_json({k: v for k, v in body.items() if k != "record_hash"}))


@dataclass(frozen=True, slots=True)
class ChainVerificationReport:
    ok: bool
    files_checked: int
    records_checked: int
    tail_hash: str
    anchored_to: str | None = None  # prev_hash of a leading continuation header, if any
    failure_file: str | None = None
    failure_line: int | None = None
    failure_reason: str | None = None

    def __str__(self) -> str:
        if self.ok:
            return (
                f"chain OK: {self.records_checked} records in {self.files_checked} file(s), "
                f"tail {self.tail_hash[:16]}..."
            )
        return (
            f"chain BROKEN at {self.failure_file}:{self.failure_line}: {self.failure_reason} "
            f"({self.records_checked} records verified before the break)"
        )


class HashChainedAuditLog:
    """Append-only writer. Thread-safe; ``append`` serializes chain computation and the write."""

    def __init__(
        self, path: str | Path, *, fsync: bool = False, rotate_bytes: int | None = None
    ) -> None:
        self._path = Path(path)
        self._fsync = fsync
        self._rotate_bytes = rotate_bytes
        self._lock = threading.Lock()
        self._prev_hash, self._next_seq = self._load_tail(self._path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self._open(self._path)

    # -- lifecycle ---------------------------------------------------------------------

    @staticmethod
    def _open(path: Path) -> Any:
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        return os.fdopen(fd, "a", encoding="utf-8", newline="\n")

    def close(self) -> None:
        with self._lock:
            if not self._fh.closed:
                self._fh.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @property
    def path(self) -> Path:
        return self._path

    @property
    def tail_hash(self) -> str:
        return self._prev_hash

    # -- tail recovery -----------------------------------------------------------------

    @staticmethod
    def _last_line(path: Path) -> str | None:
        with path.open("rb") as fh:
            fh.seek(0, os.SEEK_END)
            end = fh.tell()
            block = 4096
            data = b""
            while end > 0:
                start = max(0, end - block)
                fh.seek(start)
                data = fh.read(end - start) + data
                stripped = data.rstrip(b"\n")
                if b"\n" in stripped or start == 0:
                    lines = stripped.split(b"\n")
                    return lines[-1].decode("utf-8") if stripped else None
                end = start
            return None

    @classmethod
    def _load_tail(cls, path: Path) -> tuple[str, int]:
        if not path.exists() or path.stat().st_size == 0:
            return GENESIS_HASH, 0
        line = cls._last_line(path)
        if line is None:
            return GENESIS_HASH, 0
        try:
            entry = json.loads(line)
            if entry.get("type") == _CONTINUATION:
                return str(entry["prev_hash"]), int(entry["next_seq"])
            if compute_record_hash(entry) != entry["record_hash"]:
                raise AuditChainError(f"audit log {path} tail record fails its own hash")
            return str(entry["record_hash"]), int(entry["seq"]) + 1
        except (ValueError, KeyError, TypeError) as exc:
            # Fail closed: never silently restart the chain over a damaged log.
            raise AuditChainError(f"audit log {path} has an unreadable tail: {exc}") from exc

    # -- writing -----------------------------------------------------------------------

    def append(self, body: dict[str, Any]) -> AuditRecord:
        """Chain and write one record. ``body`` must be JSON-mode data without chain fields."""
        with self._lock:
            full = dict(body)
            full["seq"] = self._next_seq
            full["prev_hash"] = self._prev_hash
            full["record_hash"] = compute_record_hash(full)
            self._write_line(canonical_json(full))
            self._prev_hash = full["record_hash"]
            self._next_seq += 1
            if self._rotate_bytes is not None and self._fh.tell() >= self._rotate_bytes:
                self._rotate_locked()
        return AuditRecord.model_validate(full)

    def _write_line(self, line: str) -> None:
        self._fh.write(line + "\n")
        self._fh.flush()
        if self._fsync:
            os.fsync(self._fh.fileno())

    def rotate(self) -> Path:
        """Archive the current file and start a new one that continues the same hash chain."""
        with self._lock:
            return self._rotate_locked()

    def _rotate_locked(self) -> Path:
        self._fh.close()
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        archived = self._path.with_name(f"{self._path.stem}.{stamp}{self._path.suffix}")
        os.replace(self._path, archived)
        self._fh = self._open(self._path)
        header = {"type": _CONTINUATION, "prev_hash": self._prev_hash, "next_seq": self._next_seq}
        self._write_line(canonical_json(header))
        return archived

    # -- verification ------------------------------------------------------------------

    @staticmethod
    def verify_chain(
        paths: str | Path | Sequence[str | Path], *, expected_tail_hash: str | None = None
    ) -> ChainVerificationReport:
        """Recompute every hash. ``paths`` may be several files, oldest first (after rotation)."""
        files = [Path(paths)] if isinstance(paths, str | Path) else [Path(p) for p in paths]
        prev = GENESIS_HASH
        seq = 0
        checked = 0
        anchored: str | None = None

        def fail(file: Path, line: int, why: str) -> ChainVerificationReport:
            return ChainVerificationReport(
                False, len(files), checked, prev, anchored, str(file), line, why
            )

        for file_index, file in enumerate(files):
            try:
                text = file.read_text(encoding="utf-8")
            except OSError as exc:
                return fail(file, 0, f"unreadable: {exc}")
            for lineno, line in enumerate(text.splitlines(), start=1):
                if not line.strip():
                    return fail(file, lineno, "blank line inside log")
                try:
                    entry = json.loads(line)
                    if not isinstance(entry, dict):
                        raise TypeError("record is not an object")
                except (ValueError, TypeError) as exc:
                    return fail(file, lineno, f"unparseable record: {exc}")

                if entry.get("type") == _CONTINUATION:
                    if lineno != 1:
                        return fail(file, lineno, "continuation header not on first line")
                    if file_index == 0:
                        prev, seq = str(entry.get("prev_hash")), int(entry.get("next_seq", 0))
                        anchored = prev
                    elif entry.get("prev_hash") != prev or entry.get("next_seq") != seq:
                        return fail(
                            file, lineno, "continuation header does not match previous file"
                        )
                    continue
                if file_index > 0 and lineno == 1:
                    return fail(file, lineno, "rotated file lacks a continuation header")

                if entry.get("seq") != seq:
                    return fail(
                        file, lineno, f"sequence gap: expected {seq}, found {entry.get('seq')}"
                    )
                if entry.get("prev_hash") != prev:
                    return fail(file, lineno, "prev_hash does not match the previous record")
                if entry.get("record_hash") != compute_record_hash(entry):
                    return fail(file, lineno, "record_hash mismatch (record was modified)")
                prev = entry["record_hash"]
                seq += 1
                checked += 1

        if expected_tail_hash is not None and expected_tail_hash != prev:
            return ChainVerificationReport(
                False,
                len(files),
                checked,
                prev,
                anchored,
                str(files[-1]) if files else None,
                None,
                "tail hash differs from the externally anchored value (truncation or rewrite)",
            )
        return ChainVerificationReport(True, len(files), checked, prev, anchored)


# Ergonomic alias conforming to protocol naming
AuditLog = HashChainedAuditLog
