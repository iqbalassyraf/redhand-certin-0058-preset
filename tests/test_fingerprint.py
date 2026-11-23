"""Phase 3.5 A: policy fingerprint, schema/preset versions, and audit stamping.

Rationale: a host that reads an audit log must be able to tell which policy decided each record,
and a preset change must never go unnoticed. The fingerprint covers the rules in force and nothing
else, so it moves when (and only when) behaviour can move.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from redhand_fintech_shield import (
    Decision,
    Env,
    Mode,
    PolicyConfig,
    Shield,
    ToolCallContext,
    load_policy,
)
from redhand_fintech_shield.__main__ import main
from redhand_fintech_shield.audit import HashChainedAuditLog
from redhand_fintech_shield.detectors import R_STRUCTURING
from redhand_fintech_shield.fingerprint import fingerprint_document, policy_fingerprint
from redhand_fintech_shield.models import (
    SUPPORTED_SCHEMA_VERSION,
    AuditRecord,
    Exemption,
    ExemptionMatch,
    RuleOverride,
)
from tests.conftest import PRESET, FakeClock

GOLDEN = Path(__file__).parent / "golden" / "preset_fingerprint.json"


def with_updates(**updates: Any) -> PolicyConfig:
    return PolicyConfig.from_yaml(PRESET).model_copy(update=updates)


# --------------------------------------------------------------------------------------
# What moves the fingerprint, and what must not
# --------------------------------------------------------------------------------------


def test_fingerprint_is_a_stable_sha256() -> None:
    base = PolicyConfig.from_yaml(PRESET)
    assert len(base.fingerprint()) == 64
    assert base.fingerprint() == policy_fingerprint(PolicyConfig.from_yaml(PRESET))


def test_decimal_spelling_and_order_do_not_change_it() -> None:
    a = PolicyConfig.model_validate({"hitl": {"thresholds": {"USD": "10000.00", "INR": "900000"}}})
    b = PolicyConfig.model_validate({"hitl": {"thresholds": {"INR": "900000.0", "USD": "10000"}}})
    assert a.fingerprint() == b.fingerprint()
    sets_a = PolicyConfig.model_validate({"hitl": {"protected_tools": ["a", "b", "c"]}})
    sets_b = PolicyConfig.model_validate({"hitl": {"protected_tools": ["c", "a", "b"]}})
    assert sets_a.fingerprint() == sets_b.fingerprint()


@pytest.mark.parametrize(
    "updates",
    [
        {"audit_path": Path("elsewhere.jsonl")},
        {"quarantine_journal_path": Path("q2.jsonl")},
        {"issuer": "someone-else"},
        {"preset_id": "my_overlay"},
        {"preset_version": "9.9.9"},
        {"verifier_public_key_path": Path("k.pem")},
    ],
)
def test_deployment_settings_do_not_change_it(updates: dict[str, Any]) -> None:
    assert with_updates(**updates).fingerprint() == PolicyConfig.from_yaml(PRESET).fingerprint()


def test_provenance_does_not_change_it() -> None:
    loaded = PolicyConfig.from_yaml(PRESET)
    assert loaded.provenance is not None
    rebuilt = PolicyConfig.model_validate(loaded.model_dump(exclude={"provenance"}))
    assert rebuilt.provenance is None and rebuilt.fingerprint() == loaded.fingerprint()


def test_any_limit_rule_or_exemption_changes_it() -> None:
    base = PolicyConfig.from_yaml(PRESET)
    changed = [
        base.model_copy(
            update={"hitl": base.hitl.model_copy(update={"thresholds": {"USD": Decimal("1")}})}
        ),
        base.model_copy(update={"mode": Mode.OBSERVE_ONLY}),
        base.model_copy(update={"rules": {R_STRUCTURING: RuleOverride(enabled=False)}}),
        base.model_copy(update={"quarantine_on_block": False}),
        base.model_copy(
            update={
                "exemptions": (
                    Exemption(
                        id="e",
                        rules=frozenset({"CIAD-2026-0058.R3.hitl_required"}),
                        reason="Sample exemption for the test",
                        approved_by="x",
                        starts_at="2026-01-01T00:00:00Z",  # type: ignore[arg-type]
                        expires_at="2026-02-01T00:00:00Z",  # type: ignore[arg-type]
                        match=ExemptionMatch(tools=frozenset({"t"})),
                    ),
                )
            }
        ),
    ]
    prints = {p.fingerprint() for p in changed} | {base.fingerprint()}
    assert len(prints) == len(changed) + 1


def test_the_document_excludes_free_fields_and_provenance() -> None:
    doc = fingerprint_document(PolicyConfig.from_yaml(PRESET))
    for gone in ("audit_path", "issuer", "preset_id", "preset_version", "provenance"):
        assert gone not in doc
    assert "hitl" in doc and "audit_path" not in str(doc.get("approval"))
    assert "nonce_journal_path" not in doc["approval"]


# --------------------------------------------------------------------------------------
# Versions
# --------------------------------------------------------------------------------------


def test_schema_and_preset_versions() -> None:
    cfg = PolicyConfig.from_yaml(PRESET)
    assert cfg.schema_version == SUPPORTED_SCHEMA_VERSION == 1
    assert cfg.preset_version is not None
    with pytest.raises(ValidationError, match="newer than this package supports"):
        PolicyConfig(schema_version=SUPPORTED_SCHEMA_VERSION + 1)
    with pytest.raises(ValidationError):
        PolicyConfig(schema_version=0)


# --------------------------------------------------------------------------------------
# Stamping and verification
# --------------------------------------------------------------------------------------


def _old_body() -> dict[str, Any]:
    """A record body in the format written before policy fingerprints existed."""
    return {
        "ts": "2026-11-11T00:00:00+00:00",
        "mode": "enforce",
        "context": {
            "agent_run_id": "r",
            "tool_name": "t",
            "target_env": "prod",
            "token": "sha256:" + "0" * 64,
        },
        "decision": "allow",
        "findings": [],
        "latency_us": 1,
        "tool_outcome": "executed",
    }


def _blocked_call(
    shield: Shield, issuer: Any, clock: FakeClock
) -> tuple[Callable[..., Any], ToolCallContext]:
    token = issuer.mint(
        subject="svc",
        agent_run_id="run-1",
        env=Env.PROD,
        allowed_tools=("settle_merchant",),
        now=clock.now(),
    )
    ctx = ToolCallContext(
        agent_run_id="run-1",
        tool_name="settle_merchant",
        target_env=Env.PROD,
        token=token,
        amount=Decimal("15000"),
        currency="USD",
        beneficiary="acct-1",
    )
    return shield.guard(lambda **kw: "paid"), ctx


def test_every_finding_and_audit_record_carries_the_fingerprint(
    shield: Shield, issuer: Any, clock: FakeClock
) -> None:
    guarded, ctx = _blocked_call(shield, issuer, clock)
    assert shield.evaluate(ctx).decision is Decision.HITL_REQUIRED
    with pytest.raises(Exception):  # noqa: B017 - any shield error; the audit write is the point
        guarded(ctx=ctx)
    shield.close()
    lines = [
        json.loads(x) for x in Path(shield.policy.audit_path).read_text().splitlines() if x.strip()
    ]
    assert lines and all(r["policy_sha256"] == shield.policy_fingerprint for r in lines)
    assert all(
        f["policy_sha256"] == shield.policy_fingerprint for r in lines for f in r["findings"]
    )
    assert shield.evaluate(ctx).findings[0].policy_sha256 == shield.policy_fingerprint
    assert shield.policy_fingerprint == shield.policy.fingerprint()


def test_logs_written_before_fingerprints_still_verify(tmp_path: Path) -> None:
    log = HashChainedAuditLog(tmp_path / "old.jsonl")
    record = log.append(_old_body())
    log.close()
    assert isinstance(record, AuditRecord) and record.policy_sha256 is None
    report = HashChainedAuditLog.verify_chain(tmp_path / "old.jsonl")
    assert report.ok and report.unstamped_records == 1 and report.policy_fingerprints == ()


def test_verify_audit_reports_and_checks_the_expected_policy(
    shield: Shield, issuer: Any, clock: FakeClock, capsys: pytest.CaptureFixture[str]
) -> None:
    guarded, ctx = _blocked_call(shield, issuer, clock)
    with pytest.raises(Exception):  # noqa: B017
        guarded(ctx=ctx)
    shield.close()
    audit = str(shield.policy.audit_path)
    assert main(["verify-audit", audit]) == 0
    assert f"policy_sha256 {shield.policy_fingerprint}" in capsys.readouterr().out
    assert main(["verify-audit", audit, "--expect-policy", shield.policy_fingerprint]) == 0
    capsys.readouterr()
    assert main(["verify-audit", audit, "--expect-policy", "0" * 64]) == 1
    assert "not all decided under policy" in capsys.readouterr().err


def test_verify_audit_expectation_fails_when_records_are_unstamped(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    log = HashChainedAuditLog(tmp_path / "mixed.jsonl")
    log.append(_old_body())  # written before fingerprints existed
    log.close()
    assert main(["verify-audit", str(tmp_path / "mixed.jsonl")]) == 0
    assert "carry no policy fingerprint" in capsys.readouterr().out
    assert main(["verify-audit", str(tmp_path / "mixed.jsonl"), "--expect-policy", "a" * 64]) == 1


def test_a_broken_chain_still_reports_failure_first(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "broken.jsonl"
    path.write_text('{"seq": 5}\n', encoding="utf-8")
    assert main(["verify-audit", str(path), "--expect-policy", "a" * 64]) == 1


def test_fingerprint_command_matches_the_policy(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["fingerprint"]) == 0
    assert capsys.readouterr().out.strip() == load_policy().fingerprint()
    assert main(["fingerprint", str(PRESET)]) == 0


# --------------------------------------------------------------------------------------
# Golden: the preset cannot change without a version bump
# --------------------------------------------------------------------------------------


def test_preset_content_change_requires_a_version_bump() -> None:
    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
    cfg = PolicyConfig.from_yaml(PRESET)
    update = (
        f"update {GOLDEN.name} with preset_version {cfg.preset_version!r} and "
        f"policy_sha256 {cfg.fingerprint()!r}"
    )
    if cfg.preset_version == golden["preset_version"]:
        assert cfg.fingerprint() == golden["policy_sha256"], (
            "the preset's rules changed but preset_version did not: bump preset_version in "
            f"the preset (and note it in CHANGELOG.md), then {update}"
        )
    else:
        pytest.fail(f"preset_version changed: {update}")
