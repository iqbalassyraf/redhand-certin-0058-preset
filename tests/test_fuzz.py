"""Phase 4: seeded fuzzing and property tests over every parser an attacker can reach.

Rationale: tokens, policies, audit logs, tool arguments and JSON-RPC messages are all inputs that
someone other than the operator can influence. For each parser the properties are the same: it
never fails in an unplanned way (only the documented exception type escapes), and it never accepts
something it should reject (a mutated token, a tampered log). The fuzzers are deterministic (a
fixed seed, so a failure reproduces) and use only the standard library. Set
``REDHAND_FUZZ_ITERATIONS`` to run longer, ``REDHAND_FUZZ_SEED`` to explore a different stream.
"""

# ruff: noqa: RUF001 - the look-alike and full-width characters below are the test input

from __future__ import annotations

import asyncio
import base64
import json
import os
import random
import string
import unicodedata
from collections.abc import Callable
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from redhand_fintech_shield import (
    AgentTokenIssuer,
    AgentTokenVerifier,
    ApprovalIssuer,
    ApprovalVerifier,
    Env,
    MCPGateway,
    PolicyConfig,
    PolicyLoadError,
    Shield,
    TokenInvalidError,
    ToolCallContext,
    load_policy,
)
from redhand_fintech_shield.approvals import binding_mismatch
from redhand_fintech_shield.audit import HashChainedAuditLog
from redhand_fintech_shield.bindings import resolve_path
from redhand_fintech_shield.context import extract_tool_call_context
from redhand_fintech_shield.models import ApprovalRequest, ToolBinding, ToolBindingsPolicy
from redhand_fintech_shield.normalize import canonical_beneficiary
from tests.conftest import PRESET, FakeClock

ITERATIONS = int(os.environ.get("REDHAND_FUZZ_ITERATIONS", "300"))
SEED = int(os.environ.get("REDHAND_FUZZ_SEED", "20261123"))
B64 = string.ascii_letters + string.digits + "-_"


def rng_for(name: str) -> random.Random:
    return random.Random(f"{SEED}:{name}")  # noqa: S311 - a reproducible test stream, not crypto


# --------------------------------------------------------------------------------------
# Token and approval parsers
# --------------------------------------------------------------------------------------


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def mutate_jws(rng: random.Random, token: str) -> str:
    """One random corruption of a compact JWS."""
    head, body, sig = token.split(".")
    op = rng.randrange(14)
    parts = [head, body, sig]
    if op == 0:  # flip one character somewhere
        i = rng.randrange(len(token))
        return token[:i] + rng.choice(B64) + token[i + 1 :]
    if op == 1:  # delete a character
        i = rng.randrange(len(token))
        return token[:i] + token[i + 1 :]
    if op == 2:  # insert junk
        i = rng.randrange(len(token) + 1)
        return (
            token[:i]
            + "".join(rng.choice(B64 + ".=+/ ") for _ in range(rng.randrange(1, 9)))
            + token[i:]
        )
    if op == 3:
        return token[: rng.randrange(len(token))]  # truncate
    if op == 4:
        rng.shuffle(parts)  # reorder segments
        return ".".join(parts)
    if op == 5:
        return ".".join(parts[:2])  # drop the signature
    if op == 6:
        return ".".join([*parts, rng.choice(parts)])  # extra segment
    if op == 7:  # replace one segment with random base64
        parts[rng.randrange(3)] = "".join(rng.choice(B64) for _ in range(rng.randrange(0, 90)))
        return ".".join(parts)
    if op == 8:  # tamper with the payload and keep the original signature
        claims = json.loads(_unb64(body))
        key = rng.choice(list(claims))
        claims[key] = rng.choice([None, "x", 0, -1, 10**20, [], {}, True, "prod", "staging", ["*"]])
        parts[1] = _b64(json.dumps(claims).encode())
        return ".".join(parts)
    if op == 9:  # change the algorithm header
        header = json.loads(_unb64(head))
        header["alg"] = rng.choice(["none", "HS256", "RS256", "ES256", "", None, "EdDSA "])
        parts[0] = _b64(json.dumps(header).encode())
        return ".".join(parts)
    if op == 10:  # alg=none with an empty signature, the classic bypass
        header = {"alg": "none", "typ": "JWT"}
        parts[0], parts[2] = _b64(json.dumps(header).encode()), ""
        return ".".join(parts)
    if op == 11:
        return token + rng.choice(["\n", " ", "\x00", "​", "﻿"])  # trailing junk
    if op == 12:
        return rng.choice(["", ".", "..", "a.b.c", "💥", "\x00" * 8, " " * 5, "e" * 100_000])
    return "".join(chr(rng.randrange(1, 0x2FFF)) for _ in range(rng.randrange(1, 300)))  # noise


def _healthy_token(issuer: AgentTokenIssuer, clock: FakeClock) -> str:
    return issuer.mint(
        subject="svc",
        agent_run_id="run-1",
        env=Env.PROD,
        allowed_tools=("charge_card", "settle_merchant"),
        now=clock.now(),
    )


def test_a_mutated_token_is_refused_or_identical(
    issuer: AgentTokenIssuer, verifier: AgentTokenVerifier, clock: FakeClock
) -> None:
    rng = rng_for("token")
    token = _healthy_token(issuer, clock)
    original = verifier.verify(token)
    accepted = 0
    for case in range(ITERATIONS * 3):
        mutant = mutate_jws(rng, token)
        try:
            claims = verifier.verify(mutant)
        except TokenInvalidError:
            continue
        except Exception as exc:
            pytest.fail(
                f"case {case}: verify raised {type(exc).__name__}: {exc!r} for {mutant[:80]!r}"
            )
        accepted += 1
        assert claims == original, f"case {case}: a changed token verified with different claims"
    assert accepted < ITERATIONS * 3  # most mutations must be refused, not shrugged off


def test_a_token_signed_by_another_key_never_verifies(
    verifier: AgentTokenVerifier, clock: FakeClock
) -> None:
    rng = rng_for("foreign-token")
    for _ in range(ITERATIONS // 3):
        other = AgentTokenIssuer(Ed25519PrivateKey.generate(), kid=rng.choice([None, "a", "b"]))
        token = other.mint(
            subject=f"s{rng.randrange(99)}",
            agent_run_id=f"r{rng.randrange(99)}",
            env=rng.choice(list(Env)),
            allowed_tools=[f"t{i}" for i in range(rng.randrange(1, 5))],
            now=clock.now(),
        )
        with pytest.raises(TokenInvalidError):
            verifier.verify(token)


def test_random_garbage_never_crashes_the_token_verifier(verifier: AgentTokenVerifier) -> None:
    rng = rng_for("token-garbage")
    for case in range(ITERATIONS * 2):
        text = "".join(
            chr(rng.choice([rng.randrange(0x20, 0x7F), rng.randrange(0, 0x2FFF)]))
            for _ in range(rng.randrange(0, 400))
        )
        try:
            verifier.verify(text)
        except TokenInvalidError:
            continue
        except Exception as exc:
            pytest.fail(f"case {case}: {type(exc).__name__}: {exc!r}")
        pytest.fail(f"case {case}: garbage verified: {text[:60]!r}")


def _approval_pair(clock: FakeClock) -> tuple[ApprovalVerifier, str, ApprovalRequest]:
    key = Ed25519PrivateKey.generate()
    request = ApprovalRequest(
        request_id="req-1",
        agent_run_id="run-1",
        tool_name="settle_merchant",
        target_env=Env.PROD,
        amount=Decimal("15000"),
        currency="USD",
        beneficiaries=("acct-1",),
        arguments_digest="a" * 64,
        requested_at=clock.now(),
    )
    grant = ApprovalIssuer(key).grant(request, approver="alice", now=clock.now())
    return ApprovalVerifier(key.public_key(), clock=clock.now), grant, request


def test_a_mutated_approval_is_refused_or_identical(clock: FakeClock) -> None:
    rng = rng_for("approval")
    verifier, grant, _ = _approval_pair(clock)
    original = verifier.verify(grant)
    for case in range(ITERATIONS * 3):
        mutant = mutate_jws(rng, grant)
        try:
            claims = verifier.verify(mutant)
        except ValueError:
            continue
        except Exception as exc:
            pytest.fail(f"case {case}: {type(exc).__name__}: {exc!r}")
        assert claims == original, f"case {case}: a changed approval verified with other claims"


def test_an_approval_binds_every_field_of_the_transaction(clock: FakeClock) -> None:
    """Property: change any bound field of the call and the approval no longer matches."""
    rng = rng_for("approval-binding")
    verifier, grant, _ = _approval_pair(clock)
    claims = verifier.verify(grant)
    base = ToolCallContext(
        agent_run_id="run-1",
        tool_name="settle_merchant",
        target_env=Env.PROD,
        token="t",
        amount=Decimal("15000"),
        currency="USD",
        beneficiary="acct-1",
        arguments_digest="a" * 64,
    )
    assert binding_mismatch(claims, base) is None
    changes: list[dict[str, Any]] = [
        {"agent_run_id": "run-2"},
        {"tool_name": "bulk_payout"},
        {"target_env": Env.STAGING},
        {"currency": "INR"},
        {"beneficiary": "acct-2"},
        {"beneficiaries": ("acct-1", "acct-9")},
        {"arguments_digest": "b" * 64},
        {"arguments_digest": None},
    ]
    for _ in range(ITERATIONS):
        change = dict(rng.choice(changes))
        change["amount"] = rng.choice(
            [Decimal("15000"), Decimal("15000.01"), Decimal("1"), Decimal("14999.99"), None]
        )
        mutated = base.model_copy(update=change)
        different = change["amount"] != Decimal("15000") or any(k != "amount" for k in change)
        if different:
            assert binding_mismatch(claims, mutated) is not None, change


# --------------------------------------------------------------------------------------
# Policy loader
# --------------------------------------------------------------------------------------

WEIRD_SCALARS = [
    "null", "~", "[]", "{}", "[1, [2, [3]]]", "{a: b}", "NaN", ".inf", "-.inf", "1e999999999",
    "-1", "0", "99999999999999999999999999", "'x'", "true", "false", "'\\u0000'", "'💥'", "''",
    "2026-13-45", "2026-01-01T00:00:00Z", "!!python/object:os.system x", "&a [*a]", "0x10",
    "'1.5'", "1.5", "[a, b]", "'  '", "|\n  block", "? complex\n: key",
]  # fmt: skip


def mutate_yaml(rng: random.Random, text: str) -> str | bytes:
    lines = text.splitlines()
    op = rng.randrange(12)
    if op == 0 and lines:  # delete some lines
        for _ in range(rng.randrange(1, 6)):
            lines.pop(rng.randrange(len(lines))) if lines else None
    elif op == 1 and lines:  # duplicate a line
        i = rng.randrange(len(lines))
        lines.insert(i, lines[i])
    elif op == 2 and len(lines) > 2:  # swap two lines
        i, j = rng.randrange(len(lines)), rng.randrange(len(lines))
        lines[i], lines[j] = lines[j], lines[i]
    elif op in (3, 4, 5) and lines:  # replace a value with something strange
        candidates = [
            i for i, ln in enumerate(lines) if ": " in ln and not ln.lstrip().startswith("#")
        ]
        for i in rng.sample(candidates, k=min(len(candidates), rng.randrange(1, 4))):
            key = lines[i].split(": ", 1)[0]
            lines[i] = f"{key}: {rng.choice(WEIRD_SCALARS)}"
    elif op == 6:  # an unknown key at a random indent
        lines.insert(rng.randrange(len(lines) + 1), " " * rng.choice([0, 2, 4]) + "surprise: 1")
    elif op == 7:  # shift indentation
        i = rng.randrange(len(lines))
        lines[i] = rng.choice([" ", "\t", "    "]) + lines[i]
    elif op == 8:  # truncate mid-way
        return "\n".join(lines)[: rng.randrange(len(text))]
    elif op == 9:  # pathological structure
        return rng.choice(
            [
                "[" * 3_000,
                "a: " + "[" * 2_000 + "]" * 2_000,
                "{a: " * 1_500,
                "a: &x [*x]\n",
                "&a {b: *a}\n",
                "- " * 1_500,
                "key: " + "x" * 200_000,
                "﻿" + text,
                text.replace("\n", "\r\n"),
                ("a: &a [x, x]\n" + "".join(f"b{i}: &b{i} [*a, *a]\n" for i in range(30))),
            ]
        )
    elif op == 10:  # raw bytes that are not UTF-8
        return bytes(rng.randrange(256) for _ in range(rng.randrange(1, 400)))
    else:  # random text
        return "".join(rng.choice(string.printable) for _ in range(rng.randrange(0, 600)))
    return "\n".join(lines) + "\n"


def test_the_policy_loader_only_ever_raises_policy_load_error(tmp_path: Path) -> None:
    rng = rng_for("policy-yaml")
    base = PRESET.read_text(encoding="utf-8")
    path = tmp_path / "fuzz.yaml"
    loaded = 0
    for case in range(ITERATIONS * 2):
        mutant = mutate_yaml(rng, base)
        path.write_bytes(mutant if isinstance(mutant, bytes) else mutant.encode("utf-8"))
        try:
            policy = load_policy(path)
        except PolicyLoadError:
            continue
        except Exception as exc:
            head = mutant[:120] if isinstance(mutant, str) else mutant[:40]
            pytest.fail(
                f"case {case}: load_policy raised {type(exc).__name__}: {exc!r} for {head!r}"
            )
        loaded += 1
        assert isinstance(policy, PolicyConfig)
        assert len(policy.fingerprint()) == 64  # anything that loads is usable
    assert loaded < ITERATIONS * 2  # and plenty must be refused


def test_overlays_with_random_content_only_raise_policy_load_error(tmp_path: Path) -> None:
    rng = rng_for("policy-overlay")
    fields = [
        *PolicyConfig.model_fields,
        "surprise",
        "extends",
        "loosen",
        "locked",
        "hitl.thresholds",
    ]
    path = tmp_path / "overlay.yaml"
    for case in range(ITERATIONS // 2):
        lines = ["extends: certin_ciad_2026_0058"]
        for _ in range(rng.randrange(1, 5)):
            key = rng.choice(fields)
            lines.append(f"{key}: {rng.choice(WEIRD_SCALARS)}")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        try:
            load_policy(path)
        except PolicyLoadError:
            continue
        except Exception as exc:
            pytest.fail(f"case {case}: {type(exc).__name__}: {exc!r} for {lines!r}")


def test_model_validation_only_raises_validation_errors() -> None:
    rng = rng_for("policy-model")
    base = PolicyConfig.from_yaml(PRESET).model_dump(mode="json")

    def corrupt(node: Any, depth: int = 0) -> Any:
        if isinstance(node, dict) and node:
            out = dict(node)
            key = rng.choice(list(out))
            out[key] = corrupt(out[key], depth + 1)
            return out
        if isinstance(node, list) and node and rng.random() < 0.5:
            items = list(node)
            items[rng.randrange(len(items))] = corrupt(items[0], depth + 1)
            return items
        return rng.choice(
            [
                None,
                "",
                "x",
                -1,
                0,
                10**30,
                1.5,
                float("nan"),
                float("inf"),
                True,
                [],
                {},
                [None],
                {"a": 1},
                "1e999999999",
                "NaN",
                "2026-02-30",
            ]
        )

    for case in range(ITERATIONS * 2):
        doc = corrupt(corrupt(base))
        try:
            PolicyConfig.model_validate(doc)
        except ValidationError:
            continue
        except Exception as exc:
            pytest.fail(f"case {case}: {type(exc).__name__}: {exc!r}")


# --------------------------------------------------------------------------------------
# Audit verifier
# --------------------------------------------------------------------------------------


def _record_body(rng: random.Random) -> dict[str, Any]:
    return {
        "ts": f"2026-11-11T05:{rng.randrange(60):02d}:00+00:00",
        "mode": "enforce",
        "context": {
            "agent_run_id": f"run-{rng.randrange(5)}",
            "tool_name": rng.choice(["charge_card", "settle_merchant"]),
            "target_env": "prod",
            "token": "sha256:" + "0" * 64,
        },
        "decision": rng.choice(["allow", "block"]),
        "findings": [],
        "latency_us": rng.randrange(1000),
        "tool_outcome": rng.choice(["executed", "blocked"]),
    }


def _make_log(rng: random.Random, directory: Path, rotate: bool) -> tuple[list[Path], str]:
    path = directory / "audit.jsonl"
    log = HashChainedAuditLog(path)
    count = rng.randrange(3, 14)
    archived: list[Path] = []
    for i in range(count):
        log.append(_record_body(rng))
        if rotate and i == count // 2:
            archived.append(log.rotate())
    tail = log.tail_hash
    log.close()
    return [*archived, path], tail


def _semantic(paths: list[Path]) -> list[Any] | None:
    try:
        return [
            json.loads(line)
            for p in paths
            for line in p.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except (ValueError, OSError):
        return None


def mutate_log(rng: random.Random, data: bytes) -> bytes:
    lines = data.split(b"\n")
    op = rng.randrange(13)
    if op == 0 and data:  # flip one byte
        i = rng.randrange(len(data))
        return data[:i] + bytes([data[i] ^ (1 << rng.randrange(8))]) + data[i + 1 :]
    if op == 1 and data:  # delete a byte range
        i = rng.randrange(len(data))
        return data[:i] + data[i + rng.randrange(1, 40) :]
    if op == 2:  # insert random bytes
        i = rng.randrange(len(data) + 1)
        return data[:i] + bytes(rng.randrange(256) for _ in range(rng.randrange(1, 20))) + data[i:]
    if op == 3 and len(lines) > 1:  # delete a line
        lines.pop(rng.randrange(len(lines) - 1))
        return b"\n".join(lines)
    if op == 4 and len(lines) > 1:  # duplicate a line
        i = rng.randrange(len(lines) - 1)
        lines.insert(i, lines[i])
        return b"\n".join(lines)
    if op == 5 and len(lines) > 2:  # swap two lines
        i, j = rng.sample(range(len(lines) - 1), 2)
        lines[i], lines[j] = lines[j], lines[i]
        return b"\n".join(lines)
    if op == 6 and data:  # truncate
        return data[: rng.randrange(len(data))]
    if op == 7:
        return data + bytes(rng.randrange(256) for _ in range(rng.randrange(1, 60)))
    if op == 8 and len(lines) > 1:  # edit a field but keep the stored hash
        i = rng.randrange(len(lines) - 1)
        try:
            entry = json.loads(lines[i])
            key = rng.choice([k for k in entry if k != "record_hash"] or ["x"])
            entry[key] = rng.choice([None, "tampered", 0, [], {}, 10**20, "allow", "block"])
            lines[i] = json.dumps(entry).encode()
        except ValueError:
            pass
        return b"\n".join(lines)
    if op == 9 and len(lines) > 1:  # a blank line in the middle
        lines.insert(rng.randrange(len(lines) - 1), b"")
        return b"\n".join(lines)
    if op == 10:  # a record that is valid JSON but not an object
        lines.insert(rng.randrange(len(lines)), rng.choice([b"[]", b"null", b"3", b'"s"', b"{}"]))
        return b"\n".join(lines)
    if op == 11 and data:  # invalid UTF-8
        i = rng.randrange(len(data))
        return data[:i] + b"\xff\xfe\xc3\x28" + data[i:]
    return data.replace(b"\n", b"\r\n")  # equivalent text: allowed to still verify


def test_a_tampered_audit_log_never_verifies_and_never_crashes(tmp_path: Path) -> None:
    rng = rng_for("audit")
    for case in range(ITERATIONS):
        workdir = tmp_path / f"c{case}"
        workdir.mkdir()
        paths, tail = _make_log(rng, workdir, rotate=rng.random() < 0.4)
        original = _semantic(paths)
        victim = rng.choice(paths)
        before = victim.read_bytes()
        victim.write_bytes(mutate_log(rng, before))
        try:
            report = HashChainedAuditLog.verify_chain(paths, expected_tail_hash=tail)
        except Exception as exc:
            pytest.fail(f"case {case}: verify_chain raised {type(exc).__name__}: {exc!r}")
        if report.ok:
            # anything that still verifies, against the anchored tail, must say the same thing
            assert _semantic(paths) == original, f"case {case}: a changed log verified"
            assert report.tail_hash == tail


def test_arbitrary_bytes_are_not_a_valid_log_and_do_not_crash_the_verifier(tmp_path: Path) -> None:
    rng = rng_for("audit-garbage")
    path = tmp_path / "junk.jsonl"
    for case in range(ITERATIONS):
        path.write_bytes(bytes(rng.randrange(256) for _ in range(rng.randrange(0, 300))))
        try:
            report = HashChainedAuditLog.verify_chain(path)
        except Exception as exc:
            pytest.fail(f"case {case}: {type(exc).__name__}: {exc!r}")
        assert report.ok is (path.stat().st_size == 0)  # an empty file is an empty, valid chain


def test_continuation_headers_with_hostile_fields_do_not_crash(tmp_path: Path) -> None:
    path = tmp_path / "cont.jsonl"
    for header in (
        {"type": "chain_continuation", "prev_hash": "x", "next_seq": "not-a-number"},
        {"type": "chain_continuation", "prev_hash": None, "next_seq": None},
        {"type": "chain_continuation", "prev_hash": [], "next_seq": {}},
        {"type": "chain_continuation", "next_seq": 1e400},
        {"type": "chain_continuation", "prev_hash": "0" * 64, "next_seq": 10**400},
    ):
        path.write_text(json.dumps(header) + "\n", encoding="utf-8")
        report = HashChainedAuditLog.verify_chain(path)
        assert isinstance(report.ok, bool)


def test_hostile_policy_documents_are_refused_quickly(tmp_path: Path) -> None:
    """A crafted file must fail fast, not burn CPU (alias bombs expand exponentially)."""
    import time

    levels = [
        f"{chr(98 + i)}: &{chr(98 + i)} [" + ",".join([f"*{chr(97 + i)}"] * 9) + "]\n"
        for i in range(8)
    ]
    bomb = "a: &a [x,x,x,x,x,x,x,x,x]\n" + "".join(levels)
    hostile = {
        "alias bomb": bomb,
        "self-referential alias": "a: &x [*x]\n",
        "deep nesting": "a: " + "[" * 200 + "]" * 200,
        "huge scalar": "key: " + "x" * 2_000_000,
        "wide": "\n".join(f"k{i}: {i}" for i in range(150_000)),
    }
    for name, text in hostile.items():
        path = tmp_path / "hostile.yaml"
        path.write_text(text, encoding="utf-8")
        started = time.perf_counter()
        with pytest.raises(PolicyLoadError):
            load_policy(path)
        assert time.perf_counter() - started < 3.0, f"{name} took too long to refuse"


def test_the_alias_bomb_is_refused_for_its_size_not_its_content(tmp_path: Path) -> None:
    path = tmp_path / "bomb.yaml"
    levels = [
        f"{chr(98 + i)}: &{chr(98 + i)} [" + ",".join([f"*{chr(97 + i)}"] * 9) + "]\n"
        for i in range(8)
    ]
    path.write_text("a: &a [x,x,x,x,x,x,x,x,x]\n" + "".join(levels), encoding="utf-8")
    with pytest.raises(PolicyLoadError, match="more than 100000 nodes"):
        load_policy(path)
    path.write_text("a: " + "[" * 200 + "]" * 200, encoding="utf-8")
    with pytest.raises(PolicyLoadError, match="nested deeper than 64"):
        load_policy(path)
    path.write_text("key: " + "x" * 2_000_000, encoding="utf-8")
    with pytest.raises(PolicyLoadError, match="larger than 1048576 bytes"):
        load_policy(path)


def test_the_shipped_preset_and_example_overlay_are_far_below_the_limits() -> None:
    from redhand_fintech_shield.layers import MAX_NODES, MAX_POLICY_BYTES

    assert PRESET.stat().st_size < MAX_POLICY_BYTES // 20
    assert (
        len(json.dumps(yaml.safe_load(PRESET.read_text(encoding="utf-8")), default=str)) < MAX_NODES
    )


# --------------------------------------------------------------------------------------
# Beneficiary normaliser
# --------------------------------------------------------------------------------------

UNICODE_POOL = (
    string.ascii_letters
    + string.digits
    + " \t\n-_.:/@"
    + "​‌‍﻿⁠­"  # zero-width and soft hyphen (format characters)
    + "\u0000\u0007\u001b\u007f"  # control characters
    + "é́Ａａ＠① 　 "  # accents, full-width, spaces
    + "аοі"  # Cyrillic/Greek look-alikes
    + "\U0001f4a5\U0001d400"  # astral characters
    + "\u00df\u0130\u01c6\ufb01\u1e9e\u2126\u212b"  # case-folding and compatibility traps
)


def _random_text(rng: random.Random, limit: int = 40) -> str:
    return "".join(rng.choice(UNICODE_POOL) for _ in range(rng.randrange(0, limit)))


def _iban(rng: random.Random) -> str:
    country = "".join(rng.choice(string.ascii_uppercase) for _ in range(2))
    bban = "".join(
        rng.choice(string.digits + string.ascii_uppercase) for _ in range(rng.randrange(11, 24))
    )
    digits = "".join(str(int(c, 36)) for c in bban + country + "00")
    return f"{country}{98 - int(digits) % 97:02d}{bban}"


def test_the_normaliser_is_total_idempotent_and_clean() -> None:
    rng = rng_for("normalise")
    for case in range(ITERATIONS * 4):
        raw = _random_text(rng)
        out = canonical_beneficiary(raw)
        assert canonical_beneficiary(out) == out, f"case {case}: not idempotent for {raw!r}"
        assert out == out.strip() and "  " not in out, f"case {case}: stray whitespace in {out!r}"
        assert not any(unicodedata.category(c) in ("Cc", "Cf") for c in out), (
            f"case {case}: control or format character survived in {out!r}"
        )


def test_the_same_upi_address_in_any_spelling_is_one_payee() -> None:
    rng = rng_for("normalise-vpa")
    for _ in range(ITERATIONS):
        local = "".join(
            rng.choice(string.ascii_letters + string.digits + "._-")
            for _ in range(rng.randrange(1, 12))
        )
        handle = "".join(rng.choice(string.ascii_letters) for _ in range(rng.randrange(2, 9)))
        variants = {
            f"{local}@{handle}",
            f"  {local.upper()}@{handle.lower()}  ",
            f"{local.lower()}@{handle.upper()}",
            f"​{local}@{handle}‍",
        }
        assert len({canonical_beneficiary(v) for v in variants}) == 1, variants


def test_the_same_iban_in_any_spelling_is_one_payee_and_a_bad_checksum_is_not_folded() -> None:
    rng = rng_for("normalise-iban")
    for _ in range(ITERATIONS):
        iban = _iban(rng)
        spaced = " ".join(iban[i : i + 4] for i in range(0, len(iban), 4))
        variants = {iban, iban.lower(), spaced, spaced.lower(), "-".join(spaced.split())}
        assert {canonical_beneficiary(v) for v in variants} == {iban}
        # break the checksum: it is no longer an IBAN, so its case must be preserved
        broken = iban[:2] + f"{(int(iban[2:4]) + 1) % 100:02d}" + iban[4:]
        folded = {canonical_beneficiary(broken.lower()), canonical_beneficiary(broken.upper())}
        assert len(folded) == 2 or broken.lower() == broken.upper()


def test_generic_ids_that_differ_only_by_case_are_never_merged() -> None:
    """Merging case-distinct ids could make an unknown payee look like a known one."""
    rng = rng_for("normalise-generic")
    for _ in range(ITERATIONS):
        text = "".join(
            rng.choice(string.ascii_letters + string.digits) for _ in range(rng.randrange(3, 14))
        )
        generic = f"Vendor-{text}"
        swapped = generic.swapcase()
        if swapped != generic:
            assert canonical_beneficiary(generic) != canonical_beneficiary(swapped)


# --------------------------------------------------------------------------------------
# Binding resolver and context extraction
# --------------------------------------------------------------------------------------


def _random_json(rng: random.Random, depth: int = 0) -> Any:
    kinds = ["none", "bool", "int", "str", "float", "amount"]
    if depth < 3:
        kinds += ["list", "dict", "dict"]
    kind = rng.choice(kinds)
    if kind == "none":
        return None
    if kind == "bool":
        return rng.random() < 0.5
    if kind == "int":
        return rng.choice([0, 1, -1, 100, 10**18, -(10**18)])
    if kind == "float":
        return rng.choice([0.0, 1.5, -2.5, 1e308, float("inf"), float("nan")])
    if kind == "amount":
        return rng.choice(
            [
                "0",
                "1",
                "100.50",
                "-5",
                "NaN",
                "sNaN",
                "Infinity",
                "1E+999999",
                "abc",
                "",
                " 7 ",
                "1e3",
            ]
        )
    if kind == "str":
        return _random_text(rng, 12)
    if kind == "list":
        return [_random_json(rng, depth + 1) for _ in range(rng.randrange(0, 5))]
    keys = [
        "amount",
        "currency",
        "beneficiary",
        "payee",
        "value",
        "items",
        "payments",
        "a",
        "b",
        "_meta",
        "token",
    ]
    return {rng.choice(keys): _random_json(rng, depth + 1) for _ in range(rng.randrange(0, 5))}


def _random_path(rng: random.Random) -> str:
    segments = []
    for _ in range(rng.randrange(1, 4)):
        seg = rng.choice(["amount", "payee", "a", "b", "items", "payments", "currency", "value"])
        seg += rng.choice(["", "", "[*]", "[0]", "[1]", "[7]"])
        segments.append(seg)
    return ".".join(segments)


def test_path_resolution_never_fails_in_an_unplanned_way() -> None:
    rng = rng_for("paths")
    for case in range(ITERATIONS * 3):
        doc = _random_json(rng)
        path = _random_path(rng)
        try:
            values, complete = resolve_path(doc, path, max_items=rng.choice([1, 3, 50]))
        except ValueError:
            continue
        except Exception as exc:
            pytest.fail(f"case {case}: {type(exc).__name__}: {exc!r} for {path!r}")
        assert isinstance(values, list) and isinstance(complete, bool)
        assert all(v is not None for v in values)  # a null is incomplete, never a value


def test_extraction_with_hostile_arguments_only_raises_value_errors() -> None:
    rng = rng_for("extract")
    for case in range(ITERATIONS * 3):
        args = {
            "token": "t",
            **{
                rng.choice(
                    ["amount", "currency", "beneficiary", "value", "payee", "payments", "items"]
                ): _random_json(rng)
                for _ in range(rng.randrange(0, 5))
            },
        }
        binding = ToolBinding(
            amount=rng.choice(
                [None, "amount", "value", "payments[*].amount", "items[0].amount", "a.b"]
            ),
            currency=rng.choice([None, "currency", "payments[*].currency"]),
            beneficiary=rng.choice([None, "beneficiary", "payee", "payments[*].payee"]),
            fixed_currency=None,
            max_items=rng.choice([1, 3, 20]),
        )
        bindings = rng.choice(
            [
                None,
                ToolBindingsPolicy(tools={"pay": binding}),
                ToolBindingsPolicy(tools={"pay": binding}, legacy_fallback=False),
            ]
        )
        try:
            ctx = extract_tool_call_context("pay", args, bindings=bindings)
        except ValueError:  # includes pydantic's ValidationError
            continue
        except Exception as exc:
            pytest.fail(f"case {case}: {type(exc).__name__}: {exc!r} for {args!r}")
        assert ctx.amount is None or (ctx.amount.is_finite() and ctx.amount >= 0)
        assert ctx.currency is None or len(ctx.currency) == 3
        assert all(b == canonical_beneficiary(b) and b for b in ctx.beneficiaries)


def _payments(
    rng: random.Random, count: int, spell: Callable[[Decimal], Any]
) -> tuple[list[dict[str, Any]], Decimal]:
    amounts = [
        Decimal(rng.randrange(1, 10**9)) / Decimal(10 ** rng.randrange(0, 4)) for _ in range(count)
    ]
    rows = [
        {"amount": spell(a), "currency": "usd", "payee": f"p{i % 3}"} for i, a in enumerate(amounts)
    ]
    return rows, sum(amounts, Decimal(0))


BULK = ToolBindingsPolicy(
    tools={
        "bulk": ToolBinding(
            amount="payments[*].amount",
            currency="payments[*].currency",
            beneficiary="payments[*].payee",
            max_items=40,
        )
    }
)


def test_a_bulk_amount_is_always_the_exact_sum_of_its_items() -> None:
    rng = rng_for("bulk-sum")
    spellings: list[Callable[[Decimal], Any]] = [str, lambda d: str(d).upper()]
    for case in range(ITERATIONS):
        rows, expected = _payments(rng, rng.randrange(1, 30), rng.choice(spellings))
        ctx = extract_tool_call_context("bulk", {"payments": rows, "token": "t"}, bindings=BULK)
        assert ctx.amount == expected, f"case {case}"
        assert ctx.currency == "USD"
        assert set(ctx.beneficiaries) == {f"p{i % 3}" for i in range(len(rows))}


def test_a_negative_or_boolean_or_nonfinite_item_can_never_be_netted_away() -> None:
    rng = rng_for("bulk-hostile")
    poison: list[Any] = [
        "-1",
        "-0.01",
        -5,
        "NaN",
        "Infinity",
        "-Infinity",
        True,
        False,
        {"x": 1},
        [1],
        "abc",
        "1E+999999999",
    ]
    for _ in range(ITERATIONS):
        rows, _ = _payments(rng, rng.randrange(1, 12), str)
        rows[rng.randrange(len(rows))]["amount"] = rng.choice(poison)
        rows.insert(0, {"amount": "1000000", "currency": "usd", "payee": "p0"})  # a large payment
        with pytest.raises(ValueError):
            extract_tool_call_context("bulk", {"payments": rows, "token": "t"}, bindings=BULK)


def test_lists_over_the_limit_and_mixed_currencies_fail_closed() -> None:
    rng = rng_for("bulk-limits")
    for _ in range(ITERATIONS // 3):
        rows, _ = _payments(rng, rng.randrange(41, 80), str)
        with pytest.raises(ValueError):
            extract_tool_call_context("bulk", {"payments": rows, "token": "t"}, bindings=BULK)
        rows, _ = _payments(rng, rng.randrange(2, 20), str)
        rows[rng.randrange(len(rows))]["currency"] = rng.choice(["inr", "EUR", "SGD"])
        ctx = extract_tool_call_context("bulk", {"payments": rows, "token": "t"}, bindings=BULK)
        assert ctx.currency is None  # unknown, so the detectors fail closed


# --------------------------------------------------------------------------------------
# Gateway JSON-RPC
# --------------------------------------------------------------------------------------


class _Executor:
    def execute(self, tool_name: str, arguments: dict[str, Any], context: Any = None) -> Any:
        return "ok"

    async def aexecute(self, tool_name: str, arguments: dict[str, Any], context: Any = None) -> Any:
        return "ok"


def test_the_gateway_answers_any_message_without_raising(shield: Shield) -> None:
    rng = rng_for("gateway")
    gateway = MCPGateway(shield=shield, executor=_Executor(), default_env=Env.PROD)
    methods = [
        "initialize",
        "ping",
        "tools/list",
        "tools/call",
        "notifications/initialized",
        "resources/list",
        "",
        "x" * 300,
        None,
        7,
    ]

    def message() -> Any:
        kind = rng.randrange(6)
        if kind == 0:
            return _random_json(rng)
        if kind == 1:
            return json.dumps(_random_json(rng))
        if kind == 2:
            return "".join(
                rng.choice('{}[]",: \n0123456789abcdefnrtu\\') for _ in range(rng.randrange(0, 80))
            )
        params = {
            "name": rng.choice(["charge_card", "settle_merchant", "", None, 5, "x" * 100]),
            "arguments": rng.choice(
                [{}, _random_json(rng), json.dumps(_random_json(rng)), "{not json", None, [1, 2]]
            ),
            "_meta": rng.choice(
                [
                    None,
                    {},
                    _random_json(rng),
                    "str",
                    {"token": 5, "agent_run_id": ["x"], "target_env": "mars"},
                ]
            ),
        }
        return {
            "jsonrpc": rng.choice(["2.0", "1.0", None, 2]),
            "id": rng.choice([1, "a", None, 1.5, [], {"x": 1}, True]),
            "method": rng.choice(methods),
            "params": rng.choice([params, params, _random_json(rng), None, [], "x"]),
        }

    async def run() -> None:
        for case in range(ITERATIONS * 2):
            msg = message()
            try:
                response = await gateway.handle_message(msg)
            except Exception as exc:
                pytest.fail(
                    f"case {case}: handle_message raised {type(exc).__name__}: {exc!r} "
                    f"for {str(msg)[:200]!r}"
                )
            assert response is None or isinstance(response, dict)

    asyncio.run(run())


def test_a_control_character_cannot_split_one_payee_into_two() -> None:
    """Regression for a fuzzer finding: a control character between a letter and its accent."""
    assert canonical_beneficiary("O\x07\u0301") == canonical_beneficiary("\u00d3") == "\u00d3"
    assert canonical_beneficiary("e\u200b\u0301") == canonical_beneficiary("\u00e9")
    assert canonical_beneficiary("A\u00ad\u030a") == canonical_beneficiary("\u00c5")
    # and the casefolding traps stay a fixed point
    for text in ("\u00dfAnk@Bank", "\u0130@x", "\ufb01n@pay"):
        once = canonical_beneficiary(text)
        assert canonical_beneficiary(once) == once
