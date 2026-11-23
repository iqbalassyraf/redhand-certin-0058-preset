"""Command line: ``python -m redhand_fintech_shield {keygen,verify-audit,show-policy,gateway}``."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from . import Env, MCPGateway, Mode, Shield, __version__, default_preset_path, load_policy
from .approvals import ApprovalIssuer
from .audit import HashChainedAuditLog
from .crypto import (
    AgentTokenIssuer,
    AgentTokenVerifier,
    load_public_key_pem,
    private_key_to_pem,
    public_key_to_pem,
)
from .exceptions import PolicyLoadError, ShieldError
from .models import ApprovalRequest
from .revocations import RevocationRegistry


def _keygen(out: Path, name: str = "redhand", kid: str | None = None) -> int:
    out.mkdir(parents=True, exist_ok=True)
    private, public = AgentTokenIssuer.generate_keypair()
    priv_path, pub_path = out / f"{name}_ed25519_private.pem", out / f"{name}_ed25519_public.pem"
    for path in (priv_path, pub_path):
        if path.exists():
            print(f"refusing to overwrite {path}", file=sys.stderr)
            return 2
    priv_path.write_bytes(private_key_to_pem(private))
    priv_path.chmod(0o600)
    pub_path.write_bytes(public_key_to_pem(public))
    print(f"private key (signer only, keep secret): {priv_path}")
    print(f"public key  (set policy.verifier_public_key_path): {pub_path}")
    if name != "redhand":
        print("for an approver key, set policy.approval.verifier_public_key_path instead")
    if kid is not None:
        print("add to the policy so tokens signed with AgentTokenIssuer(key, kid=...) verify:")
        print(f"token_keys:\n  - kid: {kid}\n    public_key_path: {pub_path}")
    return 0


def _approve(args: argparse.Namespace) -> int:
    """Sign an approval for one ApprovalRequest (JSON from the shield) and print it."""
    try:
        request = ApprovalRequest.model_validate_json(args.request.read_text(encoding="utf-8"))
        key = serialization.load_pem_private_key(args.key.read_bytes(), password=None)
    except (OSError, ValueError, ValidationError) as exc:
        raise PolicyLoadError(f"cannot read approval request or key: {exc}") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise PolicyLoadError(f"{args.key} is not an Ed25519 private key")
    print(
        ApprovalIssuer(key, args.issuer).grant(
            request, approver=args.approver, ttl_seconds=args.ttl
        )
    )
    return 0


def _verify(files: list[Path], expected_tail: str | None, expect_policy: str | None) -> int:
    report = HashChainedAuditLog.verify_chain(files, expected_tail_hash=expected_tail)
    print(report)
    if not report.ok:
        return 1
    print(f"tail_hash {report.tail_hash}  (anchor this value externally)")
    for fingerprint in report.policy_fingerprints:
        print(f"policy_sha256 {fingerprint}")
    if report.unstamped_records:
        print(f"{report.unstamped_records} record(s) carry no policy fingerprint")
    if expect_policy is not None and (
        report.policy_fingerprints != (expect_policy,) or report.unstamped_records
    ):
        print(f"error: records were not all decided under policy {expect_policy}", file=sys.stderr)
        return 1
    return 0


def _revoke(args: argparse.Namespace) -> int:
    kind, value = next(
        (k, getattr(args, k)) for k in ("jti", "subject", "run") if getattr(args, k) is not None
    )
    expires = None if args.expires_in is None else int(time.time()) + args.expires_in
    registry = RevocationRegistry(args.journal)
    if registry.revoke(kind, value, args.reason, expires):  # type: ignore[arg-type]
        print(f"revoked {kind} {value!r} (a running shield picks it up within a second)")
    else:
        print(f"{kind} {value!r} was already revoked")
    return 0


def _manifest(markdown: bool) -> int:
    from .manifest import get_manifest, render_rules_markdown

    manifest = get_manifest()
    print(render_rules_markdown(manifest) if markdown else manifest.model_dump_json(indent=2))
    return 0


def _schema(out: Path | None, check: bool) -> int:
    from .schemas import all_files, check_schemas, default_schema_dir, write_schemas

    if check:
        directory = out if out is not None else default_schema_dir()
        problems = check_schemas(directory)
        for problem in problems:
            print(f"schema {problem}", file=sys.stderr)
        if problems:
            print(
                f"error: regenerate with `redhand-shield schema --out {directory}`", file=sys.stderr
            )
            return 1
        print(f"schemas OK ({directory})")
        return 0
    if out is None:
        print(json.dumps({name: json.loads(text) for name, text in all_files().items()}, indent=2))
        return 0
    for path in write_schemas(out):
        print(f"wrote {path}")
    return 0


def _api(out: Path | None, check: bool) -> int:
    from .api_snapshot import default_snapshot_path, diff, render, snapshot

    live = snapshot()
    target = out if out is not None else default_snapshot_path()
    if check:
        try:
            committed = json.loads(target.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            print(f"error: cannot read {target}: {exc}", file=sys.stderr)
            return 1
        changes = diff(committed, live)
        for change in changes:
            print(f"public API {change}", file=sys.stderr)
        if changes:
            print(
                f"error: update with `redhand-shield api --out {target}` and record the change "
                "in CHANGELOG.md (Added/Changed/Deprecated/Removed)",
                file=sys.stderr,
            )
            return 1
        print(f"public API OK ({target})")
        return 0
    if out is None:
        print(render(live), end="")
    else:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(render(live), encoding="utf-8", newline="\n")
        print(f"wrote {out}")
    return 0


def _fingerprint(path: Path | None) -> int:
    print(load_policy(path).fingerprint())
    return 0


def _gateway(args: argparse.Namespace) -> int:
    policy = load_policy(args.policy)
    updates: dict[str, Any] = {}
    if args.audit_path is not None:
        updates["audit_path"] = args.audit_path
    if args.quarantine_journal is not None:
        updates["quarantine_journal_path"] = args.quarantine_journal
    if args.mode is not None:
        updates["mode"] = Mode(args.mode)
    if args.public_key is not None:
        updates["verifier_public_key_path"] = args.public_key
    if updates:
        policy = policy.model_copy(update=updates)

    verifier: AgentTokenVerifier | None = None
    if args.public_key is not None:
        verifier = AgentTokenVerifier(
            load_public_key_pem(args.public_key),
            issuer=policy.issuer,
            max_ttl_seconds=policy.max_token_ttl_seconds,
            audience=policy.audience,
        )

    shield = Shield(policy, verifier)
    gateway = MCPGateway(shield=shield, default_env=Env(args.target_env))
    asyncio.run(gateway.serve_stdio())
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="redhand_fintech_shield", description=__doc__)
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    kg = sub.add_parser("keygen", help="generate an Ed25519 signing keypair (PEM)")
    kg.add_argument("out", type=Path, nargs="?", default=Path("keys"))
    kg.add_argument("--kid", help="key id; prints the policy token_keys entry for this key")
    kg.add_argument("--name", default="redhand", help="file prefix, e.g. 'approver' for approvals")
    ap_ = sub.add_parser("approve", help="sign a per-transaction approval for an approval request")
    ap_.add_argument("request", type=Path, help="ApprovalRequest JSON (from the shield's response)")
    ap_.add_argument("--key", type=Path, required=True, help="approver Ed25519 private key PEM")
    ap_.add_argument(
        "--approver", required=True, help="who is approving (recorded in the audit log)"
    )
    ap_.add_argument("--ttl", type=int, default=120, help="approval lifetime in seconds")
    ap_.add_argument("--issuer", default="redhand-approver")
    va = sub.add_parser("verify-audit", help="verify audit hash chain(s), oldest file first")
    va.add_argument("files", type=Path, nargs="+")
    va.add_argument("--expected-tail", help="externally anchored tail hash (detects truncation)")
    va.add_argument(
        "--expect-policy",
        help="fail unless every record was decided under this policy fingerprint",
    )
    rv = sub.add_parser("revoke", help="revoke an agent token, subject or run (journaled)")
    rv.add_argument("journal", type=Path, help="the policy's revocation_journal_path")
    which = rv.add_mutually_exclusive_group(required=True)
    which.add_argument("--jti", help="revoke one token by its jti")
    which.add_argument("--subject", help="revoke every token of this subject")
    which.add_argument("--run", help="revoke every token of this agent run")
    rv.add_argument("--reason", required=True)
    rv.add_argument(
        "--expires-in", type=int, help="forget the revocation after N seconds (>= token TTL)"
    )
    mf = sub.add_parser("manifest", help="print the preset manifest (JSON) or rule catalog")
    mf.add_argument("--markdown", action="store_true", help="render the rule catalog as Markdown")
    sc = sub.add_parser("schema", help="print, write (--out) or verify (--check) the JSON Schemas")
    sc.add_argument("--out", type=Path, help="directory to write to, or to check against")
    sc.add_argument("--check", action="store_true", help="exit 1 if the schemas are out of date")
    ap2 = sub.add_parser(
        "api", help="print, write (--out) or verify (--check) the public API snapshot"
    )
    ap2.add_argument("--out", type=Path, help="file to write, or to check against")
    ap2.add_argument("--check", action="store_true", help="exit 1 if the public API changed")
    fp = sub.add_parser("fingerprint", help="print the fingerprint of a policy's rules in force")
    fp.add_argument("path", type=Path, nargs="?")
    sp = sub.add_parser("show-policy", help="validate and print a policy (default: bundled preset)")
    sp.add_argument("path", type=Path, nargs="?")

    gw = sub.add_parser("gateway", help="run out-of-process Model Context Protocol (MCP) gateway")
    gw.add_argument("--policy", type=Path, help="path to policy YAML (default: bundled preset)")
    gw.add_argument("--public-key", type=Path, help="path to Ed25519 public key PEM")
    gw.add_argument(
        "--target-env",
        choices=["prod", "staging", "test", "dev"],
        default="prod",
        help="default target environment (default: prod)",
    )
    gw.add_argument("--audit-path", type=Path, help="path to audit log JSONL file")
    gw.add_argument("--quarantine-journal", type=Path, help="path to quarantine journal JSONL file")
    gw.add_argument(
        "--mode",
        choices=["enforce", "observe_only"],
        help="override enforcement mode (default: from policy)",
    )
    gw.add_argument(
        "--transport",
        choices=["stdio"],
        default="stdio",
        help="transport type (default: stdio)",
    )

    args = ap.parse_args(argv)

    try:
        if args.cmd == "keygen":
            return _keygen(args.out, args.name, args.kid)
        if args.cmd == "approve":
            return _approve(args)
        if args.cmd == "verify-audit":
            return _verify(args.files, args.expected_tail, args.expect_policy)
        if args.cmd == "revoke":
            return _revoke(args)
        if args.cmd == "api":
            return _api(args.out, args.check)
        if args.cmd == "schema":
            return _schema(args.out, args.check)
        if args.cmd == "manifest":
            return _manifest(args.markdown)
        if args.cmd == "fingerprint":
            return _fingerprint(args.path)
        if args.cmd == "gateway":
            return _gateway(args)
        policy = load_policy(args.path)
        print(f"# source: {args.path or default_preset_path()}")
        print(policy.model_dump_json(indent=2))
        return 0
    except ShieldError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
