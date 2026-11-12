from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

from redhand_fintech_shield import AuditChainError, HashChainedAuditLog
from redhand_fintech_shield.audit import GENESIS_HASH, canonical_json, compute_record_hash


def body(n: int) -> dict[str, Any]:
    return {
        "ts": "2026-11-11T05:30:00+00:00",
        "mode": "enforce",
        "context": {
            "agent_run_id": f"r{n}",
            "tool_name": "t",
            "target_env": "prod",
            "token": "sha256:abc",
            "amount": None,
            "currency": None,
            "timestamp": None,
            "metadata": {},
        },
        "decision": "allow",
        "findings": [],
        "latency_us": 10,
        "tool_outcome": "executed",
    }


def write_log(path: Path, n: int = 5) -> HashChainedAuditLog:
    log = HashChainedAuditLog(path)
    for i in range(n):
        log.append(body(i))
    return log


def test_canonical_json_is_sorted_compact_and_unicode_stable() -> None:
    assert canonical_json({"b": 1, "a": "é"}) == '{"a":"é","b":1}'


def test_chain_links_and_genesis(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    log = write_log(path, 3)
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    assert rows[0]["prev_hash"] == GENESIS_HASH
    assert rows[1]["prev_hash"] == rows[0]["record_hash"]
    assert [r["seq"] for r in rows] == [0, 1, 2]
    assert rows[2]["record_hash"] == log.tail_hash == compute_record_hash(rows[2])
    assert HashChainedAuditLog.verify_chain(path).ok


def test_record_hash_formula_is_reproducible_independently(tmp_path: Path) -> None:
    import hashlib

    path = tmp_path / "a.jsonl"
    write_log(path, 1)
    row = json.loads(path.read_text())
    stripped = {k: v for k, v in row.items() if k != "record_hash"}
    text = json.dumps(stripped, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    assert hashlib.sha256(text.encode()).hexdigest() == row["record_hash"]


def test_modified_record_detected(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    write_log(path)
    lines = path.read_text().splitlines()
    lines[2] = lines[2].replace('"allow"', '"block"')
    path.write_text("\n".join(lines) + "\n")
    report = HashChainedAuditLog.verify_chain(path)
    assert (
        not report.ok and report.failure_line == 3 and "modified" in (report.failure_reason or "")
    )


def test_deleted_record_detected(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    write_log(path)
    lines = path.read_text().splitlines()
    del lines[1]
    path.write_text("\n".join(lines) + "\n")
    report = HashChainedAuditLog.verify_chain(path)
    assert not report.ok and report.failure_line == 2


def test_reordered_records_detected(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    write_log(path)
    lines = path.read_text().splitlines()
    lines[1], lines[2] = lines[2], lines[1]
    path.write_text("\n".join(lines) + "\n")
    assert not HashChainedAuditLog.verify_chain(path).ok


def test_recomputed_forgery_still_breaks_next_link(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    write_log(path)
    lines = path.read_text().splitlines()
    row = json.loads(lines[1])
    row["decision"] = "block"
    row["record_hash"] = compute_record_hash(row)  # attacker fixes the hash of the edited line
    lines[1] = canonical_json(row)
    path.write_text("\n".join(lines) + "\n")
    report = HashChainedAuditLog.verify_chain(path)
    assert not report.ok and report.failure_line == 3


def test_tail_truncation_needs_external_anchor(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    log = write_log(path)
    anchor = log.tail_hash
    lines = path.read_text().splitlines()
    path.write_text("\n".join(lines[:-2]) + "\n")
    assert HashChainedAuditLog.verify_chain(path).ok  # internally consistent...
    assert not HashChainedAuditLog.verify_chain(path, expected_tail_hash=anchor).ok  # ...but caught


def test_unparseable_and_blank_lines_detected(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    write_log(path, 2)
    path.write_text(path.read_text() + "{not json\n")
    assert not HashChainedAuditLog.verify_chain(path).ok
    path.write_text(path.read_text().replace("{not json\n", "\n"))
    assert not HashChainedAuditLog.verify_chain(path).ok


def test_reopen_continues_chain(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    log = write_log(path, 3)
    log.close()
    log2 = HashChainedAuditLog(path)
    rec = log2.append(body(3))
    assert rec.seq == 3
    assert HashChainedAuditLog.verify_chain(path).records_checked == 4


def test_corrupt_tail_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    write_log(path, 2).close()
    with path.open("a") as fh:
        fh.write('{"half a rec')
    with pytest.raises(AuditChainError):
        HashChainedAuditLog(path)


def test_tampered_tail_fails_closed_on_open(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    write_log(path, 2).close()
    path.write_text(path.read_text().replace('"allow"', '"block"'))
    with pytest.raises(AuditChainError):
        HashChainedAuditLog(path)


def test_long_record_tail_recovery(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    log = HashChainedAuditLog(path)
    big = body(0)
    big["context"]["metadata"] = {"blob": "x" * 20000}
    log.append(big)
    log.close()
    assert HashChainedAuditLog(path).tail_hash == log.tail_hash


def test_rotation_preserves_chain_across_files(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    log = write_log(path, 2)
    archived = log.rotate()
    log.append(body(2))
    log.append(body(3))
    assert HashChainedAuditLog.verify_chain([archived, path]).ok
    report = HashChainedAuditLog.verify_chain([archived, path])
    assert report.files_checked == 2 and report.records_checked == 4
    # the new file alone verifies as anchored to the previous tail
    solo = HashChainedAuditLog.verify_chain(path)
    assert solo.ok and solo.anchored_to is not None
    # a gap (missing archive) is caught
    assert not HashChainedAuditLog.verify_chain([path, archived]).ok


def test_reopen_after_rotation_continues(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    log = write_log(path, 2)
    archived = log.rotate()
    log.close()
    log2 = HashChainedAuditLog(path)  # file holds only the continuation header
    assert log2.append(body(2)).seq == 2
    assert HashChainedAuditLog.verify_chain([archived, path]).ok


def test_auto_rotation_by_size(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    log = HashChainedAuditLog(path, rotate_bytes=800)
    for i in range(10):
        log.append(body(i))
    archives = sorted(tmp_path.glob("a.*.jsonl"))
    assert archives
    assert HashChainedAuditLog.verify_chain([*archives, path]).records_checked == 10


@pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX permissions (0o600) not supported on Windows"
)
def test_log_file_is_private(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    write_log(path, 1)
    assert (path.stat().st_mode & 0o777) == 0o600
