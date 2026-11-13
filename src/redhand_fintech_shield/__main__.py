"""Command line: ``python -m redhand_fintech_shield {keygen,verify-audit,show-policy,gateway}``."""

from __future__ import annotations

import argparse
import asyncio
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from . import Env, MCPGateway, Mode, Shield, __version__, default_preset_path, load_policy
from .audit import HashChainedAuditLog
from .crypto import (
    AgentTokenIssuer,
    AgentTokenVerifier,
    load_public_key_pem,
    private_key_to_pem,
    public_key_to_pem,
)
from .exceptions import PolicyLoadError, ShieldError


def _keygen(out: Path) -> int:
    out.mkdir(parents=True, exist_ok=True)
    private, public = AgentTokenIssuer.generate_keypair()
    priv_path, pub_path = out / "redhand_ed25519_private.pem", out / "redhand_ed25519_public.pem"
    for path in (priv_path, pub_path):
        if path.exists():
            print(f"refusing to overwrite {path}", file=sys.stderr)
            return 2
    priv_path.write_bytes(private_key_to_pem(private))
    priv_path.chmod(0o600)
    pub_path.write_bytes(public_key_to_pem(public))
    print(f"private key (signer only, keep secret): {priv_path}")
    print(f"public key  (set policy.verifier_public_key_path): {pub_path}")
    return 0


def _verify(files: list[Path], expected_tail: str | None) -> int:
    report = HashChainedAuditLog.verify_chain(files, expected_tail_hash=expected_tail)
    print(report)
    if report.ok:
        print(f"tail_hash {report.tail_hash}  (anchor this value externally)")
    return 0 if report.ok else 1


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

    if args.public_key is not None:
        public_key = load_public_key_pem(args.public_key)
        verifier = AgentTokenVerifier(
            public_key,
            issuer=policy.issuer,
            max_ttl_seconds=policy.max_token_ttl_seconds,
        )
    elif policy.verifier_public_key_path is not None:
        public_key = load_public_key_pem(policy.verifier_public_key_path)
        verifier = AgentTokenVerifier(
            public_key,
            issuer=policy.issuer,
            max_ttl_seconds=policy.max_token_ttl_seconds,
        )
    else:
        raise PolicyLoadError("no verifier supplied and policy.verifier_public_key_path is not set")

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
    va = sub.add_parser("verify-audit", help="verify audit hash chain(s), oldest file first")
    va.add_argument("files", type=Path, nargs="+")
    va.add_argument("--expected-tail", help="externally anchored tail hash (detects truncation)")
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
            return _keygen(args.out)
        if args.cmd == "verify-audit":
            return _verify(args.files, args.expected_tail)
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
