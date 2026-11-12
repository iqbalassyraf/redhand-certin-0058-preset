#!/usr/bin/env python3
"""CRAFTY FALCON kill-chain simulation against the real redhand-certin-0058 shield.

Every "attack" below is a synthetic function call against in-process stub tools: no network
traffic, no real payment rail, nothing leaves this process. The shield, token verification,
detectors, quarantine and hash-chained audit log are the genuine production code paths.

    uv run python examples/simulate_crafty_falcon.py                 # both modes, cinematic
    uv run python examples/simulate_crafty_falcon.py --mode enforce  # defended run only
    uv run python examples/simulate_crafty_falcon.py --delay 0       # instant (CI / tests)
"""

from __future__ import annotations

import argparse
import json
import shutil
import statistics
import tempfile
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from redhand_fintech_shield import (
    AgentTokenIssuer,
    AgentTokenVerifier,
    Env,
    HashChainedAuditLog,
    Mode,
    Shield,
    ShieldError,
    ToolCallContext,
    load_policy,
    redhand_guard,
)

TOOLS = ("charge_card", "list_merchants", "settle_merchant", "initiate_disbursement")
WEEKDAY = datetime(2026, 11, 11, 5, 30, tzinfo=UTC)  # Wed 11:00 IST
SATURDAY_0210_IST = datetime(2026, 11, 13, 20, 40, tzinfo=UTC)  # Sat 02:10 IST


class SimClock:
    """Wall + monotonic clock under the demo's control (no real sleeping needed for windows)."""

    def __init__(self, start: datetime) -> None:
        self.wall = start
        self.mono = 5000.0

    def now(self) -> datetime:
        return self.wall

    def monotonic(self) -> float:
        return self.mono

    def advance(self, seconds: float) -> None:
        self.wall += timedelta(seconds=seconds)
        self.mono += seconds


@dataclass
class Step:
    stage: int
    label: str
    malicious: bool
    executed: bool
    rule: str | None
    amount: Decimal = Decimal(0)
    latency_us: int = 0


@dataclass
class RunResult:
    mode: Mode
    steps: list[Step] = field(default_factory=list)
    audit_path: Path = Path()
    quarantined: dict[str, str] = field(default_factory=dict)

    @property
    def attack_steps(self) -> list[Step]:
        return [s for s in self.steps if s.malicious]

    @property
    def stopped(self) -> int:
        return sum(1 for s in self.attack_steps if not s.executed)

    @property
    def leaked(self) -> Decimal:
        return sum((s.amount for s in self.attack_steps if s.executed), Decimal(0))


class Simulation:
    def __init__(self, console: Console, mode: Mode, workdir: Path, delay: float) -> None:
        self.c = console
        self.mode = mode
        self.delay = delay
        self.clock = SimClock(WEEKDAY)
        priv, pub = AgentTokenIssuer.generate_keypair()
        self.issuer = AgentTokenIssuer(priv)
        policy = load_policy().model_copy(
            update={
                "mode": mode,
                "audit_path": workdir / "audit_trail.jsonl",
                "quarantine_journal_path": workdir / "quarantine.jsonl",
            }
        )
        verifier = AgentTokenVerifier(
            pub, policy.issuer, max_ttl_seconds=policy.max_token_ttl_seconds, clock=self.clock.now
        )
        self.shield = Shield(policy, verifier, clock=self.clock.now, monotonic=self.clock.monotonic)
        self.result = RunResult(mode, audit_path=policy.audit_path)
        # Stub tools: the "payment rail". Guarded exactly like a real agent tool would be.
        self.tools: dict[str, Callable[..., str]] = {
            name: redhand_guard(self.shield)(self._stub(name)) for name in TOOLS
        }

    @staticmethod
    def _stub(name: str) -> Callable[..., str]:
        def tool(*, ctx: ToolCallContext) -> str:
            return f"{name}: ok"

        tool.__name__ = name
        return tool

    # -- helpers -----------------------------------------------------------------------

    def _pause(self, factor: float = 1.0) -> None:
        if self.delay > 0:
            time.sleep(self.delay * factor)

    def ctx(
        self,
        run: str,
        tool: str,
        *,
        token_env: Env = Env.PROD,
        target: Env = Env.PROD,
        allowed: Sequence[str] = TOOLS,
        hitl: bool = False,
        amount: str | None = None,
        currency: str = "USD",
    ) -> ToolCallContext:
        token = self.issuer.mint(
            subject="svc-payments-agent",
            agent_run_id=run,
            env=token_env,
            allowed_tools=allowed,
            hitl_step_up=hitl,
            now=self.clock.now(),
        )
        return ToolCallContext(
            agent_run_id=run,
            tool_name=tool,
            target_env=target,
            token=token,
            amount=Decimal(amount) if amount else None,
            currency=currency if amount else None,
        )

    def _last_audit(self) -> dict[str, Any]:
        last = self.result.audit_path.read_text(encoding="utf-8").splitlines()[-1]
        row: dict[str, Any] = json.loads(last)
        return row

    def attempt(
        self, stage: int, label: str, ctx: ToolCallContext, *, malicious: bool = True
    ) -> Step:
        """Fire one tool call through the shield and render the outcome."""
        who = "ATTACKER" if malicious else "OPERATOR"
        amount = f" ${ctx.amount:,.2f} {ctx.currency}" if ctx.amount is not None else ""
        self.c.print(
            Text.assemble(
                ("  > ", "bold red" if malicious else "bold green"),
                (f"{who:<8} ", "bold"),
                f"{ctx.tool_name}{amount}  ",
                (label, "dim"),
            )
        )
        self._pause(0.6)
        executed = True
        err: ShieldError | None = None
        try:
            self.tools[ctx.tool_name](ctx=ctx)
        except ShieldError as exc:
            executed, err = False, exc
        row = self._last_audit()
        flagged = [f for f in row["findings"] if f["would_have_blocked"]]
        rule = flagged[0]["rule_id"].split(".", 2)[-1] if flagged else None
        latency = int(row["latency_us"])
        step = Step(stage, label, malicious, executed, rule, ctx.amount or Decimal(0), latency)
        self.result.steps.append(step)

        timing = f"  [{latency / 1000:.2f} ms]"
        if err is not None:
            self.c.print(
                Text.assemble(
                    ("      BLOCKED  ", "bold white on red"),
                    f" {type(err).__name__}: ",
                    (str(err).split("] ", 1)[-1], "red"),
                    (timing, "dim"),
                )
            )
        elif flagged:
            self.c.print(
                Text.assemble(
                    ("      EXECUTED ", "bold black on yellow"),
                    (f" observe_only would have blocked: {rule}", "yellow"),
                    (timing, "dim"),
                )
            )
        else:
            style = "green" if not malicious else "bold red"
            note = "human-approved step-up accepted" if not malicious else "allowed (by design)"
            self.c.print(
                Text.assemble(
                    ("      EXECUTED ", f"bold black on {style}"), f" {note}", (timing, "dim")
                )
            )
        self._pause()
        return step

    def stage_header(self, n: int, title: str, blurb: str) -> None:
        self.c.print()
        self.c.print(Rule(Text(f" STAGE {n}: {title} ", style="bold cyan"), style="cyan"))
        self.c.print(Text(blurb, style="italic dim"))
        self._pause(1.2)

    # -- the kill chain ----------------------------------------------------------------

    def run(self) -> RunResult:
        self.c.print()
        title = "ENFORCE" if self.mode is Mode.ENFORCE else "OBSERVE-ONLY (RedHand M4.3)"
        colour = "green" if self.mode is Mode.ENFORCE else "yellow"
        self.c.print(
            Panel(
                Text(
                    f"Replaying CRAFTY FALCON  |  mode = {title}",
                    justify="center",
                    style=f"bold {colour}",
                ),
                border_style=colour,
                box=box.DOUBLE,
            )
        )

        self.stage_header(
            1,
            "STAGING-TO-PROD TOKEN PIVOT",
            "A credential harvested from a CI/staging job is replayed against production.",
        )
        self.attempt(
            1,
            "staging-minted token -> PROD API",
            self.ctx("falcon-stg", "charge_card", token_env=Env.STAGING, amount="100.00"),
        )

        self.stage_header(
            2,
            "MICRO-TRANSACTION PROBING LOOP",
            "Tiny payments verify that stolen instruments can move funds, then enumerate.",
        )
        for amt in ("0.50", "1.00", "1.00"):
            self.clock.advance(4)
            self.attempt(
                2, "probe within 60s window", self.ctx("falcon-probe", "charge_card", amount=amt)
            )
        self._burst()

        self.stage_header(
            3,
            "SETTLEMENT / DISBURSEMENT API ABUSE",
            "High-value endpoints: tool pinning and HITL step-up are cryptographic.",
        )
        self.attempt(
            3,
            "tool absent from token's pinned allowed_tools",
            self.ctx(
                "falcon-pay",
                "initiate_disbursement",
                allowed=("settle_merchant",),
                amount="5000.00",
            ),
        )
        self.attempt(
            3,
            "above $10,000 with no human co-signature",
            self.ctx("falcon-pay2", "settle_merchant", amount="48500.00"),
        )
        self.attempt(
            3,
            "same amount, token carries hitl_step_up=true",
            self.ctx("ops-run-77", "settle_merchant", hitl=True, amount="48500.00"),
            malicious=False,
        )

        self.clock.wall = SATURDAY_0210_IST
        self.stage_header(
            4,
            "LOW-MONITORING WINDOW",
            "Saturday 02:10 IST. Thresholds tighten and HITL becomes mandatory.",
        )
        self.attempt(
            4,
            "small settlement, weekend, no HITL",
            self.ctx("falcon-wknd", "settle_merchant", amount="900.00"),
        )
        self.attempt(
            4,
            "first micro-probe on a weekend trips the breaker",
            self.ctx("falcon-wknd2", "charge_card", amount="1.00"),
        )

        self.result.quarantined = self.shield.quarantine.snapshot()
        self.shield.close()
        return self.result

    def _burst(self) -> None:
        """25 enumeration calls, 1 ms apart: machine speed, summarized in one line."""
        self.c.print(
            Text.assemble(
                ("  > ", "bold red"),
                ("ATTACKER ", "bold"),
                "list_merchants x25 in 25 ms  ",
                ("enumeration burst", "dim"),
            )
        )
        self._pause(0.6)
        ok = 0
        rule: str | None = None
        latencies: list[int] = []
        ctx = self.ctx("falcon-enum", "list_merchants")
        for _ in range(25):
            self.clock.advance(0.001)
            try:
                self.tools["list_merchants"](ctx=ctx)
                ok += 1
            except ShieldError:
                pass
            row = self._last_audit()
            latencies.append(int(row["latency_us"]))
            hits = [f for f in row["findings"] if f["would_have_blocked"]]
            rule = rule or (hits[0]["rule_id"].split(".", 2)[-1] if hits else None)
        stopped = 25 - ok
        flagged_only = rule is not None and stopped == 0
        self.result.steps.append(
            Step(
                2,
                "enumeration burst",
                True,
                executed=stopped == 0,
                rule=rule,
                latency_us=max(latencies),
            )
        )
        if stopped:
            self.c.print(
                Text.assemble(
                    ("      BLOCKED  ", "bold white on red"),
                    f" VelocityExceededError after {ok} calls; {stopped} refused,"
                    " agent quarantined",
                )
            )
        elif flagged_only:
            self.c.print(
                Text.assemble(
                    ("      EXECUTED ", "bold black on yellow"),
                    f" all 25 ran; observe_only would have blocked: {rule}",
                )
            )
        else:
            self.c.print(Text.assemble(("      EXECUTED ", "bold black on red"), " all 25 ran"))
        self._pause()


# -- reporting -------------------------------------------------------------------------


def summary_table(results: list[RunResult]) -> Table:
    t = Table(title="Outcome", box=box.ROUNDED, header_style="bold")
    t.add_column("Metric")
    for r in results:
        t.add_column("ENFORCE" if r.mode is Mode.ENFORCE else "OBSERVE-ONLY", justify="right")
    t.add_row("Malicious steps attempted", *(str(len(r.attack_steps)) for r in results))
    t.add_row(
        "Malicious steps stopped",
        *(
            f"[bold green]{r.stopped}[/]" if r.mode is Mode.ENFORCE else f"[yellow]{r.stopped}[/]"
            for r in results
        ),
    )
    t.add_row("Funds moved by attacker", *(f"${r.leaked:,.2f}" for r in results))
    t.add_row("Agent runs quarantined", *(str(len(r.quarantined)) for r in results))
    return t


def latency_table(result: RunResult) -> Table:
    rows = result.audit_path.read_text(encoding="utf-8").splitlines()
    us = [int(json.loads(r)["latency_us"]) for r in rows]
    t = Table(title="Decision latency (zero LLM calls)", box=box.ROUNDED, header_style="bold")
    for col in ("calls", "median", "p99", "max", "budget"):
        t.add_column(col, justify="right")
    p99 = statistics.quantiles(us, n=100)[98] if len(us) >= 2 else max(us)
    t.add_row(
        str(len(us)),
        f"{statistics.median(us) / 1000:.3f} ms",
        f"{p99 / 1000:.3f} ms",
        f"{max(us) / 1000:.3f} ms",
        "2.000 ms",
    )
    return t


def verify_and_tamper(console: Console, result: RunResult, workdir: Path) -> bool:
    console.print()
    console.print(
        Rule(Text(" EVIDENCE: HASH-CHAINED AUDIT TRAIL ", style="bold magenta"), style="magenta")
    )
    report = HashChainedAuditLog.verify_chain(result.audit_path)
    console.print(
        Text.assemble(("  verify  ", "bold"), (str(report), "green" if report.ok else "red"))
    )
    forged = workdir / "forged_audit_trail.jsonl"
    shutil.copy(result.audit_path, forged)
    lines = forged.read_text(encoding="utf-8").splitlines()
    idx = next((i for i, ln in enumerate(lines) if '"decision":"block"' in ln), None)
    if idx is None:
        return report.ok
    lines[idx] = lines[idx].replace('"decision":"block"', '"decision":"allow"', 1)
    forged.write_text("\n".join(lines) + "\n", encoding="utf-8")
    console.print(Text(f"  attacker rewrites line {idx + 1}: block -> allow", style="dim"))
    bad = HashChainedAuditLog.verify_chain(forged)
    console.print(
        Text.assemble(("  verify  ", "bold"), (str(bad), "bold red" if not bad.ok else "green"))
    )
    return report.ok and not bad.ok


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--mode", choices=("enforce", "observe", "both"), default="both")
    ap.add_argument(
        "--delay", type=float, default=0.45, help="cinematic pause in seconds (0 = off)"
    )
    ap.add_argument(
        "--keep", type=Path, help="write audit trails under this directory and keep them"
    )
    args = ap.parse_args(argv)

    console = Console()
    console.print(
        Panel.fit(
            Text.assemble(
                ("CRAFTY FALCON\n", "bold red"),
                (
                    "CERT-In CIAD-2026-0058 / CIAD-2026-0049  -  redhand-certin-0058-preset\n",
                    "bold",
                ),
                (
                    "PentAGI | ARTEX | CyberStrikeAI | Cairn  -  offensive agents, machine speed\n",
                    "dim",
                ),
                (
                    "Synthetic simulation: stub tools only, nothing leaves this process.",
                    "dim italic",
                ),
                justify="center",
            ),
            border_style="red",
            box=box.HEAVY,
        )
    )

    modes = {
        "enforce": [Mode.ENFORCE],
        "observe": [Mode.OBSERVE_ONLY],
        "both": [Mode.OBSERVE_ONLY, Mode.ENFORCE],
    }[args.mode]
    root = args.keep or Path(tempfile.mkdtemp(prefix="crafty_falcon_"))
    root.mkdir(parents=True, exist_ok=True)
    results: list[RunResult] = []
    for mode in modes:
        workdir = root / mode.value
        workdir.mkdir(parents=True, exist_ok=True)
        results.append(Simulation(console, mode, workdir, args.delay).run())

    console.print()
    console.print(summary_table(results))
    enforced = next((r for r in results if r.mode is Mode.ENFORCE), None)
    ok = True
    if enforced is not None:
        console.print(latency_table(enforced))
        ok = verify_and_tamper(console, enforced, root / enforced.mode.value)
        # The only attacker step allowed through enforce mode is the first probe, by design.
        ok = ok and enforced.stopped == len(enforced.attack_steps) - 1
        console.print(
            Text(
                "\n  Note: the first micro-probe ($0.50) cannot be distinguished from a legitimate "
                "small payment; the breaker trips on the 2nd, as CIAD-2026-0058 specifies.",
                style="dim",
            )
        )
    if args.keep is None:
        shutil.rmtree(root, ignore_errors=True)
    console.print(
        Text("\n  RESULT: " + ("PASS" if ok else "FAIL"), style="bold green" if ok else "bold red")
    )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
