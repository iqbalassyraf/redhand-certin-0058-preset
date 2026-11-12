from __future__ import annotations

import sys
from pathlib import Path

import pytest

from redhand_fintech_shield import HashChainedAuditLog
from redhand_fintech_shield.__main__ import main

from .test_audit import body


def test_keygen_creates_private_key_and_refuses_overwrite(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["keygen", str(tmp_path / "k")]) == 0
    if sys.platform != "win32":
        assert (tmp_path / "k" / "redhand_ed25519_private.pem").stat().st_mode & 0o777 == 0o600
    assert main(["keygen", str(tmp_path / "k")]) == 2
    assert "refusing to overwrite" in capsys.readouterr().err


def test_verify_audit_ok_tampered_and_anchored(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "a.jsonl"
    log = HashChainedAuditLog(path)
    for i in range(3):
        log.append(body(i))
    assert main(["verify-audit", str(path), "--expected-tail", log.tail_hash]) == 0
    assert main(["verify-audit", str(path), "--expected-tail", "0" * 64]) == 1
    path.write_text(path.read_text().replace('"allow"', '"block"'))
    assert main(["verify-audit", str(path)]) == 1
    assert "BROKEN" in capsys.readouterr().out


def test_show_policy_default_and_bad_path(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["show-policy"]) == 0
    assert "certin_ciad_2026_0058" in capsys.readouterr().out
    assert main(["show-policy", str(tmp_path / "missing.yaml")]) == 2
