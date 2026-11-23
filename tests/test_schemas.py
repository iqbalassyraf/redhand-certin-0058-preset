"""Phase 3.5 C: JSON Schema export.

Rationale: the schemas are the contract with the host application. They are committed, so any
change to a model is a visible diff, and a stale schema file fails the build instead of reaching a
consumer. Structural checks keep the documents usable; sample instances keep them honest.
"""

from __future__ import annotations

import hashlib
import json
import sys
import tomllib
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from redhand_fintech_shield import (
    AgentTokenIssuer,
    Env,
    PolicyConfig,
    Shield,
    ToolCallContext,
)
from redhand_fintech_shield import schemas as schemas_module
from redhand_fintech_shield.__main__ import main
from redhand_fintech_shield.exceptions import PolicyLoadError
from redhand_fintech_shield.manifest import get_manifest
from redhand_fintech_shield.models import SUPPORTED_SCHEMA_VERSION
from redhand_fintech_shield.schemas import (
    INDEX_NAME,
    JSON_SCHEMA_DIALECT,
    SCHEMAS,
    all_files,
    check_schemas,
    default_schema_dir,
    schema_document,
    write_schemas,
)

ROOT = Path(__file__).resolve().parent.parent


def _ok(**kw: Any) -> str:
    return "x"


# --------------------------------------------------------------------------------------
# The committed files are the contract
# --------------------------------------------------------------------------------------


def test_committed_schemas_match_the_models() -> None:
    problems = check_schemas(ROOT / "schemas")
    assert problems == [], (
        f"{problems}: a model changed, regenerate with `redhand-shield schema --out schemas` "
        "and review the diff (bump the document version if it is not backwards compatible)"
    )


def test_index_lists_every_schema_with_its_hash() -> None:
    index = json.loads((ROOT / "schemas" / INDEX_NAME).read_text(encoding="utf-8"))
    assert [e["name"] for e in index["schemas"]] == list(SCHEMAS)
    for entry in index["schemas"]:
        blob = (ROOT / "schemas" / entry["file"]).read_bytes()
        assert hashlib.sha256(blob).hexdigest() == entry["sha256"]
        assert entry["id"] == schema_document(entry["name"])["$id"]


def test_regeneration_is_deterministic() -> None:
    assert all_files() == all_files()


# --------------------------------------------------------------------------------------
# Structure
# --------------------------------------------------------------------------------------


def _refs(node: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "$ref" and isinstance(value, str):
                found.add(value)
            else:
                found |= _refs(value)
    elif isinstance(node, list):
        for item in node:
            found |= _refs(item)
    return found


@pytest.mark.parametrize("name", list(SCHEMAS))
def test_each_schema_is_self_consistent(name: str) -> None:
    doc = schema_document(name)
    assert doc["$schema"] == JSON_SCHEMA_DIALECT
    assert doc["$id"] == f"urn:redhand:shield:{name}:v{SCHEMAS[name][1]}"
    assert doc["type"] == "object" and doc["properties"]
    defs = doc.get("$defs", {})
    for ref in _refs(doc):
        assert ref.startswith("#/$defs/") and ref.removeprefix("#/$defs/") in defs, ref


def test_ids_are_unique_and_the_policy_version_tracks_the_policy_schema() -> None:
    ids = [schema_document(n)["$id"] for n in SCHEMAS]
    assert len(ids) == len(set(ids))
    assert SCHEMAS["policy"][1] == SUPPORTED_SCHEMA_VERSION


def test_money_fields_accept_strings_never_only_floats() -> None:
    props = schema_document("tool_call_context")["properties"]
    amount = json.dumps(props["amount"])
    assert '"string"' in amount  # amounts are exchanged as strings (Decimal), not floats


# --------------------------------------------------------------------------------------
# Sample documents satisfy their schema
# --------------------------------------------------------------------------------------


def check_instance(name: str, instance: dict[str, Any]) -> None:
    """Top-level contract check: required keys present, no keys the schema does not know."""
    doc = schema_document(name)
    missing = set(doc.get("required", [])) - set(instance)
    assert not missing, f"{name}: missing {missing}"
    if doc.get("additionalProperties") is False:
        unknown = set(instance) - set(doc["properties"])
        assert not unknown, f"{name}: unknown keys {unknown}"


def test_real_documents_satisfy_their_schemas(
    shield: Shield, issuer: AgentTokenIssuer, clock: Any
) -> None:
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
    evaluation = shield.evaluate(ctx)
    guarded = shield.guard(_ok)
    with pytest.raises(Exception):  # noqa: B017 - the audit write is what we want
        guarded(ctx=ctx)
    shield.close()
    audit_line = json.loads(Path(shield.policy.audit_path).read_text().splitlines()[0])

    check_instance("finding", evaluation.findings[0].model_dump(mode="json"))
    assert evaluation.approval_request is not None
    check_instance("approval_request", evaluation.approval_request.model_dump(mode="json"))
    check_instance("audit_record", audit_line)
    check_instance("tool_call_context", ctx.model_dump(mode="json"))
    check_instance(
        "policy",
        PolicyConfig.from_yaml(ROOT / "presets" / "certin_ciad_2026_0058.yaml").model_dump(
            mode="json"
        ),
    )
    check_instance("preset_manifest", get_manifest().model_dump(mode="json"))
    claims = {
        "iss": "redhand", "sub": "svc", "agent_run_id": "r", "env": "prod",
        "allowed_tools": ["t"], "hitl_step_up": False, "iat": 1, "exp": 2, "jti": "j",
    }  # fmt: skip
    check_instance("token_claims", claims)
    check_instance("approval_claims", {
        "iss": "a", "sub": "b", "request_id": "r", "agent_run_id": "r", "tool_name": "t",
        "target_env": "prod", "nonce": "n", "iat": 1, "exp": 2,
    })  # fmt: skip


# --------------------------------------------------------------------------------------
# CLI and packaging
# --------------------------------------------------------------------------------------


def test_cli_writes_checks_and_detects_drift(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["schema", "--out", str(tmp_path)]) == 0
    assert "wrote" in capsys.readouterr().out
    assert main(["schema", "--check", "--out", str(tmp_path)]) == 0
    assert "schemas OK" in capsys.readouterr().out

    (tmp_path / "policy.schema.json").write_text("{}\n", encoding="utf-8")
    (tmp_path / "finding.schema.json").unlink()
    (tmp_path / "stray.json").write_text("{}", encoding="utf-8")
    assert main(["schema", "--check", "--out", str(tmp_path)]) == 1
    err = capsys.readouterr().err
    assert "out of date: policy.schema.json" in err
    assert "missing: finding.schema.json" in err
    assert "unexpected: stray.json" in err
    assert "regenerate" in err


def test_cli_without_arguments_prints_every_document(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["schema"]) == 0
    printed = json.loads(capsys.readouterr().out)
    assert set(printed) == {f"{n}.schema.json" for n in SCHEMAS} | {INDEX_NAME}


def test_default_check_uses_the_committed_directory(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["schema", "--check"]) == 0


def test_check_of_a_missing_directory_reports_every_file(tmp_path: Path) -> None:
    problems = check_schemas(tmp_path / "nowhere")
    assert len(problems) == len(SCHEMAS) + 1 and all(p.startswith("missing") for p in problems)


def test_write_schemas_returns_the_written_paths(tmp_path: Path) -> None:
    written = write_schemas(tmp_path / "new")
    assert len(written) == len(SCHEMAS) + 1 and all(p.is_file() for p in written)


def test_default_schema_dir_checks_the_installed_layout_then_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_module = tmp_path / "pkg" / "a" / "b" / "schemas.py"
    monkeypatch.setattr(schemas_module, "__file__", str(fake_module))
    monkeypatch.setattr(sys, "prefix", str(tmp_path / "prefix"))
    with pytest.raises(PolicyLoadError, match="bundled schemas not found"):
        default_schema_dir()
    shared = tmp_path / "prefix" / "share" / "redhand-certin-0058-preset" / "schemas"
    shared.mkdir(parents=True)
    assert default_schema_dir() == shared


def test_schemas_ship_in_the_wheel() -> None:
    meta = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    shared = meta["tool"]["hatch"]["build"]["targets"]["wheel"]["shared-data"]
    assert shared["schemas"] == "share/redhand-certin-0058-preset/schemas"
