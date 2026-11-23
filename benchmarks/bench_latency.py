"""Automated latency benchmark suite for redhand-certin-0058-preset.

Measures end-to-end execution latency across:
1. Decision Core (``Shield.evaluate``)
2. In-Process Guarded Call (``@redhand_guard`` + noop tool + SHA-256 JSONL audit append)
3. Out-of-Process MCP Gateway (``MCPGateway`` ``tools/call`` over loopback JSON-RPC stream
   vs raw async noop baseline)
4. Multi-Cloud & Framework Adapters:
   - ``BedrockConverseAdapter.handle_tool_use_block``
   - ``AzureOpenAIAdapter.handle_tool_call``
   - ``GoogleGenAIAdapter.handle_function_call``
   - ``RedHandGuardedTool.run`` (sync)
   - ``RedHandGuardedTool.arun`` (async)

Usage:
    uv run python benchmarks/bench_latency.py --iterations 1000 --json bench.json
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import math
import platform
import statistics
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

from redhand_fintech_shield import (
    AgentTokenIssuer,
    AgentTokenVerifier,
    Decision,
    Env,
    MCPGateway,
    Mode,
    Shield,
    ToolCallContext,
    load_policy,
    redhand_guard,
)
from redhand_fintech_shield.adapters import (
    AzureOpenAIAdapter,
    BedrockConverseAdapter,
    GoogleGenAIAdapter,
    RedHandGuardedTool,
)

BUSINESS_HOURS_UTC = datetime(2026, 11, 11, 5, 30, tzinfo=UTC)
IN_PROCESS_BUDGET_MS = 2.0
GATEWAY_SLA_MS = 5.0


@dataclass(frozen=True, slots=True)
class LatencyStats:
    """Summary latency statistics in milliseconds and microseconds."""

    name: str
    iterations: int
    warmup: int
    min_ms: float
    max_ms: float
    mean_ms: float
    stddev_ms: float
    p50_ms: float
    p90_ms: float
    p95_ms: float
    p99_ms: float
    min_us: float
    max_us: float
    mean_us: float
    stddev_us: float
    p50_us: float
    p90_us: float
    p95_us: float
    p99_us: float


class BenchClock:
    """Deterministic clock advancing 0.1s per call (10 calls/s, below 20/s velocity limit)."""

    def __init__(self, start: datetime = BUSINESS_HOURS_UTC) -> None:
        self.wall = start
        self.mono = 1000.0

    def now(self) -> datetime:
        return self.wall

    def monotonic(self) -> float:
        return self.mono

    def advance(self, seconds: float = 0.1) -> None:
        self.wall += timedelta(seconds=seconds)
        self.mono += seconds


class NoopExecutor:
    """Zero-overhead ToolExecutor for isolating Shield + adapter/gateway latency."""

    def execute(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> dict[str, str]:
        return {"status": "ok", "tool": tool_name}

    async def aexecute(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> dict[str, str]:
        return {"status": "ok", "tool": tool_name}


class NoopLangChainTool:
    """Minimal duck-typed BaseTool for benchmarking RedHandGuardedTool."""

    name = "charge_card"
    description = "No-op card charge tool"

    def _run(self, *args: Any, **kwargs: Any) -> dict[str, str]:
        return {"status": "ok"}

    async def _arun(self, *args: Any, **kwargs: Any) -> dict[str, str]:
        return {"status": "ok"}


def _percentile(sorted_values: list[float], pct: float) -> float:
    """Compute linear-interpolated percentile (0 <= pct <= 100) from sorted values."""
    if not sorted_values:
        raise ValueError("Cannot compute percentile of empty sample list")
    if len(sorted_values) == 1:
        return sorted_values[0]
    rank = (pct / 100.0) * (len(sorted_values) - 1)
    low = math.floor(rank)
    high = math.ceil(rank)
    if low == high:
        return sorted_values[low]
    weight = rank - low
    return sorted_values[low] * (1.0 - weight) + sorted_values[high] * weight


def compute_stats(
    name: str,
    samples_ms: list[float],
    *,
    iterations: int,
    warmup: int,
) -> LatencyStats:
    """Compute min/max/mean/stddev/percentiles in ms and us from raw ms samples."""
    ordered = sorted(samples_ms)
    min_ms = ordered[0]
    max_ms = ordered[-1]
    mean_ms = statistics.mean(ordered)
    stddev_ms = statistics.stdev(ordered) if len(ordered) > 1 else 0.0
    p50_ms = _percentile(ordered, 50.0)
    p90_ms = _percentile(ordered, 90.0)
    p95_ms = _percentile(ordered, 95.0)
    p99_ms = _percentile(ordered, 99.0)

    return LatencyStats(
        name=name,
        iterations=iterations,
        warmup=warmup,
        min_ms=round(min_ms, 4),
        max_ms=round(max_ms, 4),
        mean_ms=round(mean_ms, 4),
        stddev_ms=round(stddev_ms, 4),
        p50_ms=round(p50_ms, 4),
        p90_ms=round(p90_ms, 4),
        p95_ms=round(p95_ms, 4),
        p99_ms=round(p99_ms, 4),
        min_us=round(min_ms * 1000.0, 2),
        max_us=round(max_ms * 1000.0, 2),
        mean_us=round(mean_ms * 1000.0, 2),
        stddev_us=round(stddev_ms * 1000.0, 2),
        p50_us=round(p50_ms * 1000.0, 2),
        p90_us=round(p90_ms * 1000.0, 2),
        p95_us=round(p95_ms * 1000.0, 2),
        p99_us=round(p99_ms * 1000.0, 2),
    )


def _create_shield(
    tmp_dir: Path,
    pub_key: Ed25519PublicKey,
    clock: BenchClock,
    suffix: str,
) -> Shield:
    policy = load_policy().model_copy(
        update={
            "mode": Mode.ENFORCE,
            "audit_path": tmp_dir / f"audit_{suffix}.jsonl",
            "audit_fsync": False,
            "quarantine_journal_path": tmp_dir / f"quarantine_{suffix}.jsonl",
        }
    )
    verifier = AgentTokenVerifier(pub_key, clock=clock.now)
    return Shield(policy, verifier, clock=clock.now, monotonic=clock.monotonic)


def _mint_bench_token(
    issuer: AgentTokenIssuer,
    *,
    run_id: str,
    clock: BenchClock,
) -> str:
    return issuer.mint(
        subject="bench-agent",
        agent_run_id=run_id,
        env=Env.PROD,
        allowed_tools=("charge_card",),
        ttl_seconds=3600,
        now=clock.now(),
    )


def _bench_decision_core(
    tmp_dir: Path,
    priv_key: Ed25519PrivateKey,
    pub_key: Ed25519PublicKey,
    iterations: int,
    warmup: int,
) -> LatencyStats:
    clock = BenchClock()
    shield = _create_shield(tmp_dir, pub_key, clock, "core")
    issuer = AgentTokenIssuer(priv_key)
    try:
        run_id = "bench-core"
        jwt_str = _mint_bench_token(issuer, run_id=run_id, clock=clock)
        ctx = ToolCallContext(
            agent_run_id=run_id,
            tool_name="charge_card",
            target_env=Env.PROD,
            token=jwt_str,
            amount=Decimal("100.00"),
            currency="USD",
        )
        samples: list[float] = []
        total = warmup + iterations
        for idx in range(total):
            if idx > 0 and idx % 30000 == 0:
                jwt_str = _mint_bench_token(issuer, run_id=run_id, clock=clock)
                ctx = ToolCallContext(
                    agent_run_id=run_id,
                    tool_name="charge_card",
                    target_env=Env.PROD,
                    token=jwt_str,
                    amount=Decimal("100.00"),
                    currency="USD",
                )
            clock.advance(0.1)
            t0 = time.perf_counter()
            ev = shield.evaluate(ctx)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            if ev.decision != Decision.ALLOW:
                raise RuntimeError(f"Expected ALLOW in decision_core, got {ev.decision}")
            if idx >= warmup:
                samples.append(elapsed_ms)
        return compute_stats("decision_core", samples, iterations=iterations, warmup=warmup)
    finally:
        shield.close()


def _bench_decision_core_protected(
    tmp_dir: Path,
    priv_key: Ed25519PrivateKey,
    pub_key: Ed25519PublicKey,
    iterations: int,
    warmup: int,
) -> LatencyStats:
    """Decision core on a PROTECTED tool, so every window and gate of the preset is exercised.

    ``settle_merchant`` runs the HITL gate, new-beneficiary gate, structuring (run, subject and
    payee scopes, cross-currency conversion), the cumulative caps, velocity (per tool and total),
    micro-probe and sequence detectors. Run, subject and payee rotate every 500 calls so the
    benign traffic never trips a window however many iterations are requested.
    """
    clock = BenchClock()
    shield = _create_shield(tmp_dir, pub_key, clock, "protected")
    issuer = AgentTokenIssuer(priv_key)
    tool = "settle_merchant"

    def make_ctx(batch: int) -> ToolCallContext:
        run_id = f"bench-protected-{batch}"
        token = issuer.mint(
            subject=f"bench-agent-{batch}",
            agent_run_id=run_id,
            env=Env.PROD,
            allowed_tools=(tool,),
            ttl_seconds=3600,
            now=clock.now(),
        )
        return ToolCallContext(
            agent_run_id=run_id,
            tool_name=tool,
            target_env=Env.PROD,
            token=token,
            amount=Decimal("6.00"),
            currency="USD",
            beneficiary=f"bench-payee-{batch}",
        )

    try:
        samples: list[float] = []
        ctx = make_ctx(0)
        for idx in range(warmup + iterations):
            if idx > 0 and idx % 500 == 0:
                ctx = make_ctx(idx // 500)
            clock.advance(0.1)
            t0 = time.perf_counter()
            ev = shield.evaluate(ctx)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            if ev.decision != Decision.ALLOW:
                raise RuntimeError(f"Expected ALLOW in decision_core_protected, got {ev.decision}")
            if idx >= warmup:
                samples.append(elapsed_ms)
        return compute_stats(
            "decision_core_protected", samples, iterations=iterations, warmup=warmup
        )
    finally:
        shield.close()


def _bench_in_process_guarded(
    tmp_dir: Path,
    priv_key: Ed25519PrivateKey,
    pub_key: Ed25519PublicKey,
    iterations: int,
    warmup: int,
) -> LatencyStats:
    clock = BenchClock()
    shield = _create_shield(tmp_dir, pub_key, clock, "guarded")
    issuer = AgentTokenIssuer(priv_key)
    try:
        run_id = "bench-guarded"
        jwt_str = _mint_bench_token(issuer, run_id=run_id, clock=clock)
        ctx = ToolCallContext(
            agent_run_id=run_id,
            tool_name="charge_card",
            target_env=Env.PROD,
            token=jwt_str,
            amount=Decimal("100.00"),
            currency="USD",
        )

        @redhand_guard(shield)
        def charge_card(*, ctx: ToolCallContext) -> str:
            return "ok"

        samples: list[float] = []
        total = warmup + iterations
        for idx in range(total):
            if idx > 0 and idx % 30000 == 0:
                jwt_str = _mint_bench_token(issuer, run_id=run_id, clock=clock)
                ctx = ToolCallContext(
                    agent_run_id=run_id,
                    tool_name="charge_card",
                    target_env=Env.PROD,
                    token=jwt_str,
                    amount=Decimal("100.00"),
                    currency="USD",
                )
            clock.advance(0.1)
            t0 = time.perf_counter()
            res = charge_card(ctx=ctx)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            if res != "ok":
                raise RuntimeError(f"Unexpected guarded tool output: {res}")
            if idx >= warmup:
                samples.append(elapsed_ms)
        return compute_stats("in_process_guarded", samples, iterations=iterations, warmup=warmup)
    finally:
        shield.close()


async def _bench_gateway_async(
    tmp_dir: Path,
    priv_key: Ed25519PrivateKey,
    pub_key: Ed25519PublicKey,
    iterations: int,
    warmup: int,
) -> tuple[LatencyStats, LatencyStats]:
    clock = BenchClock()
    shield = _create_shield(tmp_dir, pub_key, clock, "gateway")
    issuer = AgentTokenIssuer(priv_key)
    executor = NoopExecutor()
    gateway = MCPGateway(shield=shield, executor=executor, default_env=Env.PROD)

    raw_samples: list[float] = []
    gw_samples: list[float] = []
    try:
        # 1. Raw async noop baseline
        total = warmup + iterations
        for idx in range(total):
            t0 = time.perf_counter()
            raw_res = await executor.aexecute(
                "charge_card",
                {"amount": "100.00", "currency": "USD"},
            )
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            if raw_res["status"] != "ok":
                raise RuntimeError("Unexpected raw noop result")
            if idx >= warmup:
                raw_samples.append(elapsed_ms)

        # 2. Out-of-process MCP Gateway loopback stream roundtrip
        server = await asyncio.start_server(gateway.serve_streams, "127.0.0.1", 0)
        sockets = server.sockets
        if not sockets:
            raise RuntimeError("Loopback gateway server failed to bind")
        port = sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            run_id = "bench-gateway"
            jwt_str = _mint_bench_token(issuer, run_id=run_id, clock=clock)
            for idx in range(total):
                if idx > 0 and idx % 30000 == 0:
                    jwt_str = _mint_bench_token(issuer, run_id=run_id, clock=clock)
                payload = {
                    "jsonrpc": "2.0",
                    "id": idx + 1,
                    "method": "tools/call",
                    "params": {
                        "name": "charge_card",
                        "arguments": {"amount": "100.00", "currency": "USD"},
                        "_meta": {
                            "token": jwt_str,
                            "agent_run_id": run_id,
                            "target_env": "prod",
                        },
                    },
                }
                line = (json.dumps(payload) + "\n").encode("utf-8")
                clock.advance(0.1)
                t0 = time.perf_counter()
                writer.write(line)
                await writer.drain()
                resp_line = await reader.readline()
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                if not resp_line:
                    raise RuntimeError("Gateway stream closed unexpectedly")
                resp = cast(dict[str, Any], json.loads(resp_line.decode("utf-8")))
                if resp.get("result", {}).get("isError") is not False:
                    raise RuntimeError(f"Gateway call failed: {resp}")
                if idx >= warmup:
                    gw_samples.append(elapsed_ms)
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            if hasattr(server, "close_clients"):
                server.close_clients()
            server.close()
            await server.wait_closed()

        return (
            compute_stats("raw_async_noop", raw_samples, iterations=iterations, warmup=warmup),
            compute_stats("mcp_gateway_loopback", gw_samples, iterations=iterations, warmup=warmup),
        )
    finally:
        shield.close()


def _bench_bedrock(
    tmp_dir: Path,
    priv_key: Ed25519PrivateKey,
    pub_key: Ed25519PublicKey,
    iterations: int,
    warmup: int,
) -> LatencyStats:
    clock = BenchClock()
    shield = _create_shield(tmp_dir, pub_key, clock, "bedrock")
    issuer = AgentTokenIssuer(priv_key)
    adapter = BedrockConverseAdapter(shield, NoopExecutor())
    try:
        run_id = "bench-bedrock"
        jwt_str = _mint_bench_token(issuer, run_id=run_id, clock=clock)
        samples: list[float] = []
        total = warmup + iterations
        for idx in range(total):
            if idx > 0 and idx % 30000 == 0:
                jwt_str = _mint_bench_token(issuer, run_id=run_id, clock=clock)
            tool_use: dict[str, Any] = {
                "toolUse": {
                    "toolUseId": f"tu_{idx}",
                    "name": "charge_card",
                    "input": {
                        "amount": "100.00",
                        "currency": "USD",
                        "token": jwt_str,
                        "target_env": "prod",
                        "agent_run_id": run_id,
                    },
                }
            }
            clock.advance(0.1)
            t0 = time.perf_counter()
            res = adapter.handle_tool_use_block(tool_use)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            if res["toolResult"]["status"] != "success":
                raise RuntimeError(f"Bedrock adapter blocked: {res}")
            if idx >= warmup:
                samples.append(elapsed_ms)
        return compute_stats("adapter_bedrock", samples, iterations=iterations, warmup=warmup)
    finally:
        shield.close()


def _bench_azure_openai(
    tmp_dir: Path,
    priv_key: Ed25519PrivateKey,
    pub_key: Ed25519PublicKey,
    iterations: int,
    warmup: int,
) -> LatencyStats:
    clock = BenchClock()
    shield = _create_shield(tmp_dir, pub_key, clock, "azure")
    issuer = AgentTokenIssuer(priv_key)
    adapter = AzureOpenAIAdapter(shield, NoopExecutor())
    try:
        run_id = "bench-azure"
        jwt_str = _mint_bench_token(issuer, run_id=run_id, clock=clock)
        samples: list[float] = []
        total = warmup + iterations
        for idx in range(total):
            if idx > 0 and idx % 30000 == 0:
                jwt_str = _mint_bench_token(issuer, run_id=run_id, clock=clock)
            tool_call: dict[str, Any] = {
                "id": f"call_{idx}",
                "type": "function",
                "function": {
                    "name": "charge_card",
                    "arguments": {
                        "amount": "100.00",
                        "currency": "USD",
                        "token": jwt_str,
                        "target_env": "prod",
                        "agent_run_id": run_id,
                    },
                },
            }
            clock.advance(0.1)
            t0 = time.perf_counter()
            res = adapter.handle_tool_call(tool_call)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            if res["role"] != "tool":
                raise RuntimeError(f"Azure OpenAI adapter failed: {res}")
            if idx >= warmup:
                samples.append(elapsed_ms)
        return compute_stats("adapter_azure_openai", samples, iterations=iterations, warmup=warmup)
    finally:
        shield.close()


def _bench_google_genai(
    tmp_dir: Path,
    priv_key: Ed25519PrivateKey,
    pub_key: Ed25519PublicKey,
    iterations: int,
    warmup: int,
) -> LatencyStats:
    clock = BenchClock()
    shield = _create_shield(tmp_dir, pub_key, clock, "google")
    issuer = AgentTokenIssuer(priv_key)
    adapter = GoogleGenAIAdapter(shield, NoopExecutor())
    try:
        run_id = "bench-google"
        jwt_str = _mint_bench_token(issuer, run_id=run_id, clock=clock)
        samples: list[float] = []
        total = warmup + iterations
        for idx in range(total):
            if idx > 0 and idx % 30000 == 0:
                jwt_str = _mint_bench_token(issuer, run_id=run_id, clock=clock)
            fn_call: dict[str, Any] = {
                "function_call": {
                    "name": "charge_card",
                    "args": {
                        "amount": "100.00",
                        "currency": "USD",
                        "token": jwt_str,
                        "target_env": "prod",
                        "agent_run_id": run_id,
                    },
                    "id": f"fn_{idx}",
                }
            }
            clock.advance(0.1)
            t0 = time.perf_counter()
            res = adapter.handle_function_call(fn_call)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            if res["function_response"]["response"]["result"]["status"] != "ok":
                raise RuntimeError(f"Google GenAI adapter failed: {res}")
            if idx >= warmup:
                samples.append(elapsed_ms)
        return compute_stats("adapter_google_genai", samples, iterations=iterations, warmup=warmup)
    finally:
        shield.close()


def _bench_langchain_sync(
    tmp_dir: Path,
    priv_key: Ed25519PrivateKey,
    pub_key: Ed25519PublicKey,
    iterations: int,
    warmup: int,
) -> LatencyStats:
    clock = BenchClock()
    shield = _create_shield(tmp_dir, pub_key, clock, "lc_sync")
    issuer = AgentTokenIssuer(priv_key)
    guarded = RedHandGuardedTool(NoopLangChainTool(), shield)
    try:
        run_id = "bench-lc-sync"
        jwt_str = _mint_bench_token(issuer, run_id=run_id, clock=clock)
        samples: list[float] = []
        total = warmup + iterations
        for idx in range(total):
            if idx > 0 and idx % 30000 == 0:
                jwt_str = _mint_bench_token(issuer, run_id=run_id, clock=clock)
            clock.advance(0.1)
            t0 = time.perf_counter()
            res = guarded.run(
                amount="100.00",
                currency="USD",
                token=jwt_str,
                target_env="prod",
                agent_run_id=run_id,
            )
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            if res["status"] != "ok":
                raise RuntimeError(f"LangChain sync adapter failed: {res}")
            if idx >= warmup:
                samples.append(elapsed_ms)
        return compute_stats(
            "adapter_langchain_sync", samples, iterations=iterations, warmup=warmup
        )
    finally:
        shield.close()


async def _bench_langchain_async(
    tmp_dir: Path,
    priv_key: Ed25519PrivateKey,
    pub_key: Ed25519PublicKey,
    iterations: int,
    warmup: int,
) -> LatencyStats:
    clock = BenchClock()
    shield = _create_shield(tmp_dir, pub_key, clock, "lc_async")
    issuer = AgentTokenIssuer(priv_key)
    guarded = RedHandGuardedTool(NoopLangChainTool(), shield)
    try:
        run_id = "bench-lc-async"
        jwt_str = _mint_bench_token(issuer, run_id=run_id, clock=clock)
        samples: list[float] = []
        total = warmup + iterations
        for idx in range(total):
            if idx > 0 and idx % 30000 == 0:
                jwt_str = _mint_bench_token(issuer, run_id=run_id, clock=clock)
            clock.advance(0.1)
            t0 = time.perf_counter()
            res = await guarded.arun(
                amount="100.00",
                currency="USD",
                token=jwt_str,
                target_env="prod",
                agent_run_id=run_id,
            )
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            if res["status"] != "ok":
                raise RuntimeError(f"LangChain async adapter failed: {res}")
            if idx >= warmup:
                samples.append(elapsed_ms)
        return compute_stats(
            "adapter_langchain_async", samples, iterations=iterations, warmup=warmup
        )
    finally:
        shield.close()


def run_suite(*, iterations: int = 1000, warmup: int = 100) -> dict[str, Any]:
    """Run all latency benchmarks and return structured results."""
    priv_pem, pub_pem = AgentTokenIssuer.generate_keypair()

    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        core_stats = _bench_decision_core(tmp_dir, priv_pem, pub_pem, iterations, warmup)
        protected_stats = _bench_decision_core_protected(
            tmp_dir, priv_pem, pub_pem, iterations, warmup
        )
        guarded_stats = _bench_in_process_guarded(tmp_dir, priv_pem, pub_pem, iterations, warmup)
        raw_noop_stats, gateway_stats = asyncio.run(
            _bench_gateway_async(tmp_dir, priv_pem, pub_pem, iterations, warmup)
        )
        bedrock_stats = _bench_bedrock(tmp_dir, priv_pem, pub_pem, iterations, warmup)
        azure_stats = _bench_azure_openai(tmp_dir, priv_pem, pub_pem, iterations, warmup)
        google_stats = _bench_google_genai(tmp_dir, priv_pem, pub_pem, iterations, warmup)
        lc_sync_stats = _bench_langchain_sync(tmp_dir, priv_pem, pub_pem, iterations, warmup)
        lc_async_stats = asyncio.run(
            _bench_langchain_async(tmp_dir, priv_pem, pub_pem, iterations, warmup)
        )

    all_stats = [
        core_stats,
        protected_stats,
        guarded_stats,
        raw_noop_stats,
        gateway_stats,
        bedrock_stats,
        azure_stats,
        google_stats,
        lc_sync_stats,
        lc_async_stats,
    ]
    gateway_overhead_p50_ms = round(max(0.0, gateway_stats.p50_ms - raw_noop_stats.p50_ms), 4)
    gateway_overhead_p95_ms = round(max(0.0, gateway_stats.p95_ms - raw_noop_stats.p95_ms), 4)
    gateway_overhead_p99_ms = round(max(0.0, gateway_stats.p99_ms - raw_noop_stats.p99_ms), 4)

    in_process_targets = [
        core_stats,
        protected_stats,
        guarded_stats,
        bedrock_stats,
        azure_stats,
        google_stats,
        lc_sync_stats,
        lc_async_stats,
    ]
    in_process_pass = all(s.p95_ms < IN_PROCESS_BUDGET_MS for s in in_process_targets)
    gateway_pass = gateway_stats.p95_ms < GATEWAY_SLA_MS

    return {
        "metadata": {
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "iterations": iterations,
            "warmup": warmup,
        },
        "sla": {
            "in_process_budget_ms": IN_PROCESS_BUDGET_MS,
            "gateway_sla_ms": GATEWAY_SLA_MS,
            "in_process_pass": in_process_pass,
            "gateway_pass": gateway_pass,
            "gateway_overhead_p50_ms": gateway_overhead_p50_ms,
            "gateway_overhead_p95_ms": gateway_overhead_p95_ms,
            "gateway_overhead_p99_ms": gateway_overhead_p99_ms,
        },
        "benchmarks": [asdict(s) for s in all_stats],
    }


def _print_table(report: dict[str, Any]) -> None:
    meta = report["metadata"]
    sla = report["sla"]
    print(
        f"RedHand Latency Benchmark "
        f"(iterations={meta['iterations']}, warmup={meta['warmup']}, "
        f"python={meta['python_version']})"
    )
    header = (
        f"{'Benchmark':<24} {'min(ms)':>8} {'mean(ms)':>9} {'std(ms)':>8} "
        f"{'p50(ms)':>8} {'p90(ms)':>8} {'p95(ms)':>8} {'p99(ms)':>8} {'max(ms)':>8}"
    )
    print(header)
    print("-" * len(header))
    for row in report["benchmarks"]:
        print(
            f"{row['name']:<24} "
            f"{row['min_ms']:>8.4f} {row['mean_ms']:>9.4f} {row['stddev_ms']:>8.4f} "
            f"{row['p50_ms']:>8.4f} {row['p90_ms']:>8.4f} {row['p95_ms']:>8.4f} "
            f"{row['p99_ms']:>8.4f} {row['max_ms']:>8.4f}"
        )
    print(
        f"\nGateway overhead vs raw async noop: "
        f"p50={sla['gateway_overhead_p50_ms']:.4f} ms, "
        f"p95={sla['gateway_overhead_p95_ms']:.4f} ms, "
        f"p99={sla['gateway_overhead_p99_ms']:.4f} ms"
    )
    print(
        f"SLA check: in-process p95 < {sla['in_process_budget_ms']} ms -> "
        f"{'PASS' if sla['in_process_pass'] else 'FAIL'} | "
        f"gateway p95 < {sla['gateway_sla_ms']} ms -> "
        f"{'PASS' if sla['gateway_pass'] else 'FAIL'}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="RedHand FINTECH Shield latency benchmark suite")
    parser.add_argument("--iterations", type=int, default=1000, help="Measured iterations per test")
    parser.add_argument("--warmup", type=int, default=100, help="Warm-up iterations per test")
    parser.add_argument("--json", type=Path, default=None, help="Optional JSON output file path")
    parser.add_argument(
        "--no-check-sla",
        action="store_true",
        help="Do not exit non-zero if p95 SLA thresholds are exceeded",
    )
    args = parser.parse_args(argv)

    if args.iterations < 1 or args.warmup < 0:
        parser.error("--iterations must be >= 1 and --warmup must be >= 0")

    report = run_suite(iterations=args.iterations, warmup=args.warmup)
    _print_table(report)

    if args.json is not None:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    if not args.no_check_sla and (
        not report["sla"]["in_process_pass"] or not report["sla"]["gateway_pass"]
    ):
        print("ERROR: Latency SLA threshold exceeded.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
