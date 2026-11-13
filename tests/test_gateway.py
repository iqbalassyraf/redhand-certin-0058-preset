"""Tests for Model Context Protocol (MCP) gateway, transports, and security enforcement."""

from __future__ import annotations

import asyncio
import contextlib
import gc
import json
import statistics
import sys
import time
import types
from collections.abc import AsyncGenerator
from decimal import Decimal
from pathlib import Path
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from redhand_fintech_shield import (
    Env,
    HashChainedAuditLog,
    MCPGateway,
    Mode,
    PolicyConfig,
    Shield,
    ToolDefinition,
)
from redhand_fintech_shield.__main__ import main
from redhand_fintech_shield.crypto import AgentTokenIssuer, AgentTokenVerifier, public_key_to_pem
from redhand_fintech_shield.detectors import (
    R_ENV_PIVOT,
    R_HITL,
    R_MICRO_TX,
    R_QUARANTINED,
    R_TOOL_NOT_PINNED,
)
from redhand_fintech_shield.gateway import (
    INVALID_PARAMS,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    PARSE_ERROR,
    POLICY_VIOLATION,
    extract_tool_call_context,
    sanitize_arguments,
)

from .conftest import FakeClock


class MockToolExecutor:
    """Mock implementation of ToolExecutor protocol recording invocations."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any], dict[str, Any] | None]] = []

    def execute(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> Any:
        self.calls.append((tool_name, arguments, context))
        return f"result:{tool_name}"

    async def aexecute(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> Any:
        self.calls.append((tool_name, arguments, context))
        return f"result:{tool_name}"


class GatewayClient:
    """Helper client for communicating with an MCP gateway over stream connections."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.reader = reader
        self.writer = writer
        self._seq = 0

    async def send_raw(self, line: str) -> None:
        raw = line if line.endswith("\n") else line + "\n"
        self.writer.write(raw.encode("utf-8"))
        await self.writer.drain()

    async def read_response(self) -> dict[str, Any]:
        line = await self.reader.readline()
        assert line, "Gateway stream closed unexpectedly"
        return cast(dict[str, Any], json.loads(line.decode("utf-8")))

    async def request(
        self, method: str, params: dict[str, Any] | None = None, req_id: Any = None
    ) -> dict[str, Any]:
        if req_id is None:
            self._seq += 1
            req_id = self._seq
        payload: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": method,
            "params": params if params is not None else {},
        }
        await self.send_raw(json.dumps(payload))
        return await self.read_response()

    async def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        payload: dict[str, Any] = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params if params is not None else {},
        }
        await self.send_raw(json.dumps(payload))


@contextlib.asynccontextmanager
async def run_gateway_server(gateway: MCPGateway) -> AsyncGenerator[GatewayClient, None]:
    """Start an in-process MCPGateway stream server and yield a connected client."""
    server = await asyncio.start_server(gateway.serve_streams, "127.0.0.1", 0)
    sockets = server.sockets
    assert sockets, "Server started without sockets"
    port = sockets[0].getsockname()[1]

    client_reader, client_writer = await asyncio.open_connection("127.0.0.1", port)
    client = GatewayClient(client_reader, client_writer)
    try:
        yield client
    finally:
        client_writer.close()
        with contextlib.suppress(Exception):
            await client_writer.wait_closed()
        if hasattr(server, "close_clients"):
            server.close_clients()
        server.close()
        await server.wait_closed()


@pytest.fixture
def mock_executor() -> MockToolExecutor:
    return MockToolExecutor()


@pytest.fixture
def standard_tools() -> list[ToolDefinition]:
    return [
        ToolDefinition(
            name="charge_card",
            description="Authorize and capture payment on a credit card.",
            inputSchema={
                "type": "object",
                "properties": {
                    "amount": {"type": "string"},
                    "currency": {"type": "string"},
                    "card_token": {"type": "string"},
                },
                "required": ["amount", "currency", "card_token"],
            },
        ),
        ToolDefinition(
            name="settle_merchant",
            description="Settle pending merchant payout balance.",
            inputSchema={
                "type": "object",
                "properties": {
                    "merchant_id": {"type": "string"},
                    "amount": {"type": "string"},
                    "currency": {"type": "string"},
                },
                "required": ["merchant_id", "amount", "currency"],
            },
        ),
        ToolDefinition(
            name="list_merchants",
            description="List active registered merchant identifiers.",
            inputSchema={"type": "object", "properties": {}},
        ),
    ]


# -----------------------------------------------------------------------------
# 1. Unmodified Client End-to-End Lifecycle & Allowed Call
# -----------------------------------------------------------------------------


def test_unmodified_client_clean_lifecycle_and_allowed_call(
    shield: Shield,
    issuer: AgentTokenIssuer,
    policy: PolicyConfig,
    mock_executor: MockToolExecutor,
    standard_tools: list[ToolDefinition],
    clock: FakeClock,
) -> None:
    async def scenario() -> None:
        gateway = MCPGateway(
            shield=shield,
            executor=mock_executor,
            tools=standard_tools,
            default_env=Env.PROD,
        )

        async with run_gateway_server(gateway) as client:
            # 1. initialize
            init_res = await client.request(
                "initialize",
                {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "test-agent", "version": "1.0.0"},
                },
            )
            assert init_res["result"]["protocolVersion"] == "2024-11-05"
            assert "tools" in init_res["result"]["capabilities"]
            assert init_res["result"]["serverInfo"]["name"] == "redhand-fintech-shield-gateway"

            # 2. notifications/initialized
            await client.notify("notifications/initialized")

            # 3. ping
            ping_res = await client.request("ping")
            assert ping_res["result"] == {}
            assert gateway._initialized is True

            # 4. tools/list
            list_res = await client.request("tools/list")
            tools = list_res["result"]["tools"]
            assert len(tools) == 3
            tool_names = [t["name"] for t in tools]
            assert "charge_card" in tool_names
            assert "settle_merchant" in tool_names

            # 5. tools/call (clean allowed call)
            token = issuer.mint(
                subject="agent-alpha",
                agent_run_id="run-001",
                env=Env.PROD,
                allowed_tools=("charge_card", "list_merchants"),
                now=clock.now(),
            )
            call_res = await client.request(
                "tools/call",
                {
                    "name": "charge_card",
                    "arguments": {
                        "amount": "10.00",
                        "currency": "USD",
                        "card_token": "tok_visa_4242",
                    },
                    "_meta": {
                        "token": token,
                        "agent_run_id": "run-001",
                        "target_env": "prod",
                    },
                },
            )
            assert call_res["result"]["isError"] is False
            assert call_res["result"]["content"][0]["text"] == "result:charge_card"
            assert call_res["result"]["_meta"]["latency_us"] > 0
            assert call_res["result"]["_meta"]["decision"] == "allow"

            # Assert executor was called exactly once with sanitized arguments
            assert len(mock_executor.calls) == 1
            call_name, call_args, call_ctx = mock_executor.calls[0]
            assert call_name == "charge_card"
            assert call_args == {
                "amount": "10.00",
                "currency": "USD",
                "card_token": "tok_visa_4242",
            }
            assert "_meta" not in call_args
            assert "token" not in call_args
            assert call_ctx is not None
            assert call_ctx["target_env"] == "prod"

    asyncio.run(scenario())

    # Assert audit log verification
    report = HashChainedAuditLog.verify_chain([policy.audit_path])
    assert report.ok is True
    assert report.records_checked == 1


# -----------------------------------------------------------------------------
# 2. Staging-to-Prod Pivot Blocked at Gateway Without Invoking Raw Tool
# -----------------------------------------------------------------------------


def test_staging_to_prod_pivot_blocked_without_invoking_tool(
    shield: Shield,
    issuer: AgentTokenIssuer,
    policy: PolicyConfig,
    mock_executor: MockToolExecutor,
    standard_tools: list[ToolDefinition],
    clock: FakeClock,
) -> None:
    async def scenario() -> None:
        gateway = MCPGateway(
            shield=shield,
            executor=mock_executor,
            tools=standard_tools,
            default_env=Env.PROD,
        )

        async with run_gateway_server(gateway) as client:
            # Token minted for STAGING, used against target PROD
            staging_token = issuer.mint(
                subject="agent-pivot",
                agent_run_id="run-pivot-99",
                env=Env.STAGING,
                allowed_tools=("settle_merchant",),
                now=clock.now(),
            )

            call_res = await client.request(
                "tools/call",
                {
                    "name": "settle_merchant",
                    "arguments": {
                        "merchant_id": "m_12345",
                        "amount": "500.00",
                        "currency": "USD",
                    },
                    "_meta": {
                        "token": staging_token,
                        "agent_run_id": "run-pivot-99",
                        "target_env": "prod",
                    },
                },
            )

            # 1. Raw tool execution is BLOCKED
            assert len(mock_executor.calls) == 0

            # 2. MCP Error response carries M4.2 finding metadata
            result = call_res.get("result", {})
            assert result.get("isError") is True
            text = result["content"][0]["text"]
            assert R_ENV_PIVOT in text
            assert "'staging' credential used against 'prod'" in text

            meta = result["_meta"]
            assert meta["rule_id"] == R_ENV_PIVOT
            assert meta["severity"] == "critical"
            assert meta["stage"] == 1
            assert meta["decision"] == "block"
            assert meta["finding"]["agent_run_id"] == "run-pivot-99"

    asyncio.run(scenario())

    # 3. Blocked event recorded in audit trail
    report = HashChainedAuditLog.verify_chain([policy.audit_path])
    assert report.ok is True
    assert report.records_checked == 1

    audit_lines = policy.audit_path.read_text().strip().split("\n")
    audit_entry = json.loads(audit_lines[0])
    assert audit_entry["decision"] == "block"
    assert audit_entry["tool_outcome"] == "blocked"
    assert audit_entry["context"]["token"].startswith("sha256:")

    # 4. Quarantine journal contains agent run ID
    assert policy.quarantine_journal_path is not None
    assert policy.quarantine_journal_path.exists()
    journal_lines = policy.quarantine_journal_path.read_text().strip().split("\n")
    journal_entry = json.loads(journal_lines[0])
    assert journal_entry["agent_run_id"] == "run-pivot-99"
    assert "staging" in journal_entry["reason"]


# -----------------------------------------------------------------------------
# 3. Micro-Tx Probe Blocked and Quarantined at Gateway
# -----------------------------------------------------------------------------


def test_micro_tx_probe_blocked_and_quarantined(
    shield: Shield,
    issuer: AgentTokenIssuer,
    mock_executor: MockToolExecutor,
    standard_tools: list[ToolDefinition],
    clock: FakeClock,
) -> None:
    async def scenario() -> None:
        gateway = MCPGateway(
            shield=shield,
            executor=mock_executor,
            tools=standard_tools,
            default_env=Env.PROD,
        )

        async with run_gateway_server(gateway) as client:
            token = issuer.mint(
                subject="agent-probe",
                agent_run_id="run-probe-42",
                env=Env.PROD,
                allowed_tools=("charge_card", "list_merchants"),
                now=clock.now(),
            )

            meta = {
                "token": token,
                "agent_run_id": "run-probe-42",
                "target_env": "prod",
            }

            # Call 1: Micro-transaction 1 ($1.00 <= $5.00 ceiling) -> ALLOWED
            res1 = await client.request(
                "tools/call",
                {
                    "name": "charge_card",
                    "arguments": {"amount": "1.00", "currency": "USD", "card_token": "c1"},
                    "_meta": meta,
                },
            )
            assert res1["result"]["isError"] is False
            assert len(mock_executor.calls) == 1

            # Call 2: Micro-transaction 2 ($2.00 <= $5.00 ceiling, max_probes=2) -> BLOCKED
            res2 = await client.request(
                "tools/call",
                {
                    "name": "charge_card",
                    "arguments": {"amount": "2.00", "currency": "USD", "card_token": "c2"},
                    "_meta": meta,
                },
            )
            assert res2["result"]["isError"] is True
            assert R_MICRO_TX in res2["result"]["content"][0]["text"]
            assert res2["result"]["_meta"]["rule_id"] == R_MICRO_TX
            assert len(mock_executor.calls) == 1  # Tool not touched for probe 2!

            # Call 3: Subsequent call with same agent_run_id -> Immediately Refused via Quarantine
            res3 = await client.request(
                "tools/call",
                {
                    "name": "list_merchants",
                    "arguments": {},
                    "_meta": meta,
                },
            )
            assert res3["result"]["isError"] is True
            assert R_QUARANTINED in res3["result"]["content"][0]["text"]
            assert res3["result"]["_meta"]["rule_id"] == R_QUARANTINED
            assert len(mock_executor.calls) == 1  # Tool still not touched!

    asyncio.run(scenario())


# -----------------------------------------------------------------------------
# 4. Agent Holds Zero Reference to Raw Tool (Process / GC Verification)
# -----------------------------------------------------------------------------


def test_agent_holds_no_reference_to_raw_tool(
    shield: Shield,
    mock_executor: MockToolExecutor,
    keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey],
) -> None:
    """Verify client communicating across gateway IPC/stream boundary holds no object references."""

    async def scenario() -> None:
        dummy_reader = asyncio.StreamReader()
        dummy_writer = cast(asyncio.StreamWriter, object())
        client = GatewayClient(dummy_reader, dummy_writer)

        forbidden_objects = [
            shield,
            mock_executor,
            keypair[0],  # Private key
            shield.audit,
            shield.quarantine,
        ]

        # 1. Attribute inspection of client
        for attr in dir(client):
            with contextlib.suppress(Exception):
                val = getattr(client, attr)
                for forbidden in forbidden_objects:
                    assert val is not forbidden, (
                        f"Client directly holds reference via attribute {attr}"
                    )

        # 2. GC Referents inspection
        visited: set[int] = set()
        queue: list[tuple[Any, int]] = [(client, 0)]
        max_depth = 5

        while queue:
            current, depth = queue.pop(0)
            c_id = id(current)
            if c_id in visited or depth > max_depth:
                continue
            visited.add(c_id)

            for forbidden in forbidden_objects:
                assert current is not forbidden, (
                    f"Client reachable object graph contains forbidden object {type(forbidden)}"
                )

            # Explore referents
            referents = gc.get_referents(current)
            for ref in referents:
                if id(ref) not in visited and not isinstance(ref, (type, types.ModuleType)):
                    queue.append((ref, depth + 1))

    asyncio.run(scenario())


# -----------------------------------------------------------------------------
# 5. Gateway Latency Overhead Benchmark (<5ms p99 SLA)
# -----------------------------------------------------------------------------


def test_gateway_latency_overhead_benchmark(
    shield: Shield,
    issuer: AgentTokenIssuer,
    mock_executor: MockToolExecutor,
    standard_tools: list[ToolDefinition],
    clock: FakeClock,
) -> None:
    async def scenario() -> None:
        gateway = MCPGateway(
            shield=shield,
            executor=mock_executor,
            tools=standard_tools,
            default_env=Env.PROD,
        )

        async with run_gateway_server(gateway) as client:
            token = issuer.mint(
                subject="agent-perf",
                agent_run_id="run-perf",
                env=Env.PROD,
                allowed_tools=("list_merchants",),
                now=clock.now(),
            )

            call_params = {
                "name": "list_merchants",
                "arguments": {},
                "_meta": {
                    "token": token,
                    "agent_run_id": "run-perf",
                    "target_env": "prod",
                },
            }

            # 1. Warm-up
            for _ in range(15):
                clock.advance(0.1)
                await client.request("tools/call", call_params)

            iterations = 80
            raw_times_ms: list[float] = []
            for _ in range(iterations):
                t0 = time.perf_counter()
                await mock_executor.aexecute("list_merchants", {}, context={"target_env": "prod"})
                raw_times_ms.append((time.perf_counter() - t0) * 1000)

            gw_times_ms: list[float] = []
            for _ in range(iterations):
                clock.advance(0.1)
                t0 = time.perf_counter()
                res = await client.request("tools/call", call_params)
                assert res["result"]["isError"] is False
                gw_times_ms.append((time.perf_counter() - t0) * 1000)

            overheads_ms = [gw - raw for gw, raw in zip(gw_times_ms, raw_times_ms, strict=True)]
            p50_overhead = statistics.median(overheads_ms)
            p95_overhead = statistics.quantiles(overheads_ms, n=20)[18]
            p99_overhead = statistics.quantiles(overheads_ms, n=100)[98]

            # Verify strictly meets < 5.0ms SLA
            assert p99_overhead < 5.0, (
                f"Gateway p99 latency overhead ({p99_overhead:.3f}ms) exceeded 5.0ms SLA! "
                f"(p50={p50_overhead:.3f}ms, p95={p95_overhead:.3f}ms)"
            )

    asyncio.run(scenario())


# -----------------------------------------------------------------------------
# 6. JSON-RPC Protocol Errors & Edge Cases
# -----------------------------------------------------------------------------


def test_protocol_error_parse_error(
    shield: Shield,
    mock_executor: MockToolExecutor,
    standard_tools: list[ToolDefinition],
) -> None:
    async def scenario() -> None:
        gateway = MCPGateway(shield=shield, executor=mock_executor, tools=standard_tools)
        async with run_gateway_server(gateway) as client:
            await client.send_raw("not a valid json string {")
            resp = await client.read_response()
            assert resp["error"]["code"] == PARSE_ERROR
            assert "Parse error" in resp["error"]["message"]

    asyncio.run(scenario())


def test_protocol_error_invalid_request(
    shield: Shield,
    mock_executor: MockToolExecutor,
    standard_tools: list[ToolDefinition],
) -> None:
    async def scenario() -> None:
        gateway = MCPGateway(shield=shield, executor=mock_executor, tools=standard_tools)
        async with run_gateway_server(gateway) as client:
            # Array payload
            await client.send_raw(json.dumps([1, 2, 3]))
            resp = await client.read_response()
            assert resp["error"]["code"] == INVALID_REQUEST

            # Bad jsonrpc version
            await client.send_raw(json.dumps({"jsonrpc": "1.0", "id": 10, "method": "ping"}))
            resp = await client.read_response()
            assert resp["error"]["code"] == INVALID_REQUEST

            # Missing method
            await client.send_raw(json.dumps({"jsonrpc": "2.0", "id": 11}))
            resp = await client.read_response()
            assert resp["error"]["code"] == INVALID_REQUEST

    asyncio.run(scenario())


def test_protocol_error_method_not_found(
    shield: Shield,
    mock_executor: MockToolExecutor,
    standard_tools: list[ToolDefinition],
) -> None:
    async def scenario() -> None:
        gateway = MCPGateway(shield=shield, executor=mock_executor, tools=standard_tools)
        async with run_gateway_server(gateway) as client:
            resp = await client.request("unsupported/method")
            assert resp["error"]["code"] == METHOD_NOT_FOUND
            assert "Method 'unsupported/method' not found" in resp["error"]["message"]

    asyncio.run(scenario())


def test_protocol_error_invalid_params(
    shield: Shield,
    mock_executor: MockToolExecutor,
    standard_tools: list[ToolDefinition],
) -> None:
    async def scenario() -> None:
        gateway = MCPGateway(shield=shield, executor=mock_executor, tools=standard_tools)
        async with run_gateway_server(gateway) as client:
            # Non-dict params
            await client.send_raw(
                json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": "string"})
            )
            resp = await client.read_response()
            assert resp["error"]["code"] == INVALID_PARAMS

            # Missing name in tools/call
            resp = await client.request("tools/call", {})
            assert resp["error"]["code"] == INVALID_PARAMS

            # Non-dict arguments in tools/call
            resp = await client.request("tools/call", {"name": "charge_card", "arguments": "bad"})
            assert resp["error"]["code"] == INVALID_PARAMS

            # Non-dict _meta in tools/call
            resp = await client.request(
                "tools/call", {"name": "charge_card", "arguments": {}, "_meta": "bad"}
            )
            assert resp["error"]["code"] == INVALID_PARAMS

            # Float amount in tools/call rejected
            resp = await client.request(
                "tools/call",
                {
                    "name": "charge_card",
                    "arguments": {"amount": 12.34, "currency": "USD"},
                    "_meta": {"token": "t", "agent_run_id": "r"},
                },
            )
            assert resp["error"]["code"] == INVALID_PARAMS
            assert "monetary values must be str, int or Decimal" in resp["error"]["message"]

            # Invalid decimal amount string
            resp = await client.request(
                "tools/call",
                {
                    "name": "charge_card",
                    "arguments": {"amount": "not-a-number", "currency": "USD"},
                    "_meta": {"token": "t", "agent_run_id": "r"},
                },
            )
            assert resp["error"]["code"] == INVALID_PARAMS

    asyncio.run(scenario())


def test_tool_not_pinned_and_hitl_required(
    shield: Shield,
    issuer: AgentTokenIssuer,
    mock_executor: MockToolExecutor,
    standard_tools: list[ToolDefinition],
    clock: FakeClock,
) -> None:
    async def scenario() -> None:
        gateway = MCPGateway(shield=shield, executor=mock_executor, tools=standard_tools)
        async with run_gateway_server(gateway) as client:
            # 1. Tool not pinned
            token_limited = issuer.mint(
                subject="agent",
                agent_run_id="run-lim",
                env=Env.PROD,
                allowed_tools=("list_merchants",),  # settle_merchant not allowed
                now=clock.now(),
            )
            res = await client.request(
                "tools/call",
                {
                    "name": "settle_merchant",
                    "arguments": {"merchant_id": "m1"},
                    "_meta": {"token": token_limited, "agent_run_id": "run-lim"},
                },
            )
            assert res["result"]["isError"] is True
            assert R_TOOL_NOT_PINNED in res["result"]["content"][0]["text"]
            assert len(mock_executor.calls) == 0

            # 2. High-value HITL required ($15,000 > $10,000 threshold without hitl_step_up)
            token_no_hitl = issuer.mint(
                subject="agent",
                agent_run_id="run-hitl",
                env=Env.PROD,
                allowed_tools=("settle_merchant",),
                hitl_step_up=False,
                now=clock.now(),
            )
            res_hitl = await client.request(
                "tools/call",
                {
                    "name": "settle_merchant",
                    "arguments": {"merchant_id": "m1", "amount": "15000.00", "currency": "USD"},
                    "_meta": {"token": token_no_hitl, "agent_run_id": "run-hitl"},
                },
            )
            assert res_hitl["result"]["isError"] is True
            assert R_HITL in res_hitl["result"]["content"][0]["text"]
            assert len(mock_executor.calls) == 0

    asyncio.run(scenario())


def test_tool_execution_error_recorded_in_audit(
    shield: Shield,
    issuer: AgentTokenIssuer,
    standard_tools: list[ToolDefinition],
    clock: FakeClock,
) -> None:
    """Test downstream tool exception writes tool_error audit record."""

    async def failing_tool(**kwargs: Any) -> Any:
        raise RuntimeError("database connection lost")

    gateway = MCPGateway(
        shield=shield,
        executor={"charge_card": failing_tool},
        tools=standard_tools,
    )

    token = issuer.mint(
        subject="agent",
        agent_run_id="run-err",
        env=Env.PROD,
        allowed_tools=("charge_card",),
        now=clock.now(),
    )

    async def scenario() -> None:
        resp = await gateway.handle_message(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": "charge_card",
                        "arguments": {"amount": "10.00", "currency": "USD"},
                        "_meta": {"token": token, "agent_run_id": "run-err"},
                    },
                }
            )
        )
        assert resp is not None
        assert resp["result"]["isError"] is True
        assert "database connection lost" in resp["result"]["content"][0]["text"]

    asyncio.run(scenario())

    # Verify audit record has tool_outcome == "tool_error"
    audit_lines = shield.policy.audit_path.read_text().strip().split("\n")
    audit_entry = json.loads(audit_lines[-1])
    assert audit_entry["tool_outcome"] == "tool_error"


def test_strict_jsonrpc_error_mode(
    shield: Shield,
    issuer: AgentTokenIssuer,
    mock_executor: MockToolExecutor,
) -> None:
    gateway = MCPGateway(
        shield=shield,
        executor=mock_executor,
        error_mode="jsonrpc",
    )

    async def scenario() -> None:
        # Missing token -> policy violation in jsonrpc error mode
        resp = await gateway.handle_message(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 42,
                    "method": "tools/call",
                    "params": {
                        "name": "charge_card",
                        "arguments": {"amount": "10.00", "currency": "USD"},
                    },
                }
            )
        )
        assert resp is not None
        assert "error" in resp
        assert resp["error"]["code"] == POLICY_VIOLATION
        assert "data" in resp["error"]
        assert resp["error"]["data"]["rule_id"] == "CIAD-2026-0058.R1.token_invalid"

    asyncio.run(scenario())


def test_lsp_content_length_framing(
    shield: Shield,
    mock_executor: MockToolExecutor,
    standard_tools: list[ToolDefinition],
) -> None:
    async def scenario() -> None:
        gateway = MCPGateway(shield=shield, executor=mock_executor, tools=standard_tools)
        async with run_gateway_server(gateway) as client:
            payload = json.dumps({"jsonrpc": "2.0", "id": 99, "method": "ping"})
            raw_lsp = f"Content-Length: {len(payload)}\r\n\r\n{payload}"
            await client.send_raw(raw_lsp)
            resp = await client.read_response()
            assert resp["id"] == 99
            assert resp["result"] == {}

    asyncio.run(scenario())


def test_observe_only_mode_allows_execution_with_findings(
    policy: PolicyConfig,
    verifier: AgentTokenVerifier,
    clock: FakeClock,
    issuer: AgentTokenIssuer,
    mock_executor: MockToolExecutor,
) -> None:
    obs_policy = policy.model_copy(update={"mode": Mode.OBSERVE_ONLY})
    obs_shield = Shield(obs_policy, verifier, clock=clock.now, monotonic=clock.monotonic)
    gateway = MCPGateway(shield=obs_shield, executor=mock_executor)

    # Staging token against prod in observe-only mode
    staging_token = issuer.mint(
        subject="agent-obs",
        agent_run_id="run-obs",
        env=Env.STAGING,
        allowed_tools=("charge_card",),
        now=clock.now(),
    )

    async def scenario() -> None:
        resp = await gateway.handle_message(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": "charge_card",
                        "arguments": {"amount": "10.00", "currency": "USD"},
                        "_meta": {
                            "token": staging_token,
                            "agent_run_id": "run-obs",
                            "target_env": "prod",
                        },
                    },
                }
            )
        )
        assert resp is not None
        assert resp["result"]["isError"] is False
        assert len(mock_executor.calls) == 1
        # Findings recorded in metadata
        assert len(resp["result"]["_meta"]["findings"]) > 0

    asyncio.run(scenario())


def test_register_tool_dynamic_registration(shield: Shield) -> None:
    gateway = MCPGateway(shield=shield)

    def custom_echo(msg: str) -> dict[str, Any]:
        return {"content": [{"type": "text", "text": f"echo:{msg}"}]}

    gateway.register_tool(
        tool="echo_tool",
        handler=custom_echo,
        description="Echo string",
        input_schema={"type": "object", "properties": {"msg": {"type": "string"}}},
    )

    assert len(gateway.tools) == 1
    assert gateway.tools[0].name == "echo_tool"

    async def scenario() -> None:
        list_resp = await gateway.dispatch_request("tools/list", {}, 1)
        assert list_resp is not None
        assert list_resp["result"]["tools"][0]["name"] == "echo_tool"

    asyncio.run(scenario())


def test_extract_tool_call_context_edge_cases() -> None:
    # 1. Token from arguments
    ctx1 = extract_tool_call_context(
        tool_name="test_tool",
        arguments={"token": "arg_tok", "agent_run_id": "arg_run", "target_env": "staging"},
    )
    assert ctx1.token == "arg_tok"
    assert ctx1.agent_run_id == "arg_run"
    assert ctx1.target_env == Env.STAGING

    # 2. Token from _token and extra metadata
    ctx2 = extract_tool_call_context(
        tool_name="test_tool",
        arguments={"_token": "arg_tok_2", "amount": 100, "currency": "usd"},
        meta={"custom_header": "value42"},
    )
    assert ctx2.token == "arg_tok_2"
    assert ctx2.amount == Decimal("100")
    assert ctx2.currency == "USD"
    assert ctx2.metadata["custom_header"] == "value42"

    # 3. Currency without amount raises ValueError
    with pytest.raises(ValueError, match="currency given without amount"):
        extract_tool_call_context(
            tool_name="test_tool",
            arguments={"currency": "USD"},
        )


def test_sanitize_arguments() -> None:
    args = {
        "card_token": "abc",
        "amount": "10.00",
        "_meta": {"token": "secret"},
        "token": "secret",
        "_token": "secret",
        "target_env": "prod",
        "agent_run_id": "run-1",
    }
    sanitized = sanitize_arguments(args)
    assert sanitized == {"card_token": "abc", "amount": "10.00"}


# -----------------------------------------------------------------------------
# 7. CLI gateway subcommand tests
# -----------------------------------------------------------------------------


def test_cli_gateway_missing_public_key() -> None:
    # Missing public key when policy has no key path
    res = main(["gateway", "--target-env", "staging"])
    assert res == 2


@pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")
def test_cli_gateway_with_public_key(tmp_path: Path) -> None:
    _, pub = AgentTokenIssuer.generate_keypair()
    pub_file = tmp_path / "pub.pem"
    pub_file.write_bytes(public_key_to_pem(pub))

    audit_file = tmp_path / "cli_audit.jsonl"
    journal_file = tmp_path / "cli_journal.jsonl"

    import io
    import sys

    old_stdin = sys.stdin
    sys.stdin = io.StringIO("")
    try:
        res = main(
            [
                "gateway",
                "--public-key",
                str(pub_file),
                "--audit-path",
                str(audit_file),
                "--quarantine-journal",
                str(journal_file),
                "--mode",
                "enforce",
            ]
        )
        assert res == 0
    finally:
        sys.stdin = old_stdin


def test_subprocess_stdio_out_of_process_execution(tmp_path: Path) -> None:
    """Test gateway running as a true OS subprocess over stdio pipes."""

    async def scenario() -> None:
        keypair = AgentTokenIssuer.generate_keypair()
        pub_file = tmp_path / "pub.pem"
        pub_file.write_bytes(public_key_to_pem(keypair[1]))

        audit_file = tmp_path / "subp_audit.jsonl"
        journal_file = tmp_path / "subp_journal.jsonl"

        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "redhand_fintech_shield",
            "gateway",
            "--public-key",
            str(pub_file),
            "--audit-path",
            str(audit_file),
            "--quarantine-journal",
            str(journal_file),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        assert proc.stdin is not None
        assert proc.stdout is not None

        # Send initialize request
        req = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}) + "\n"
        proc.stdin.write(req.encode("utf-8"))
        await proc.stdin.drain()

        line = await proc.stdout.readline()
        resp = json.loads(line.decode("utf-8"))
        assert resp["id"] == 1
        assert resp["result"]["protocolVersion"] == "2024-11-05"

        # Close stdin to trigger EOF and clean exit
        proc.stdin.close()
        with contextlib.suppress(Exception):
            await proc.stdin.wait_closed()
        try:
            await asyncio.wait_for(proc.wait(), timeout=5.0)
        except TimeoutError:
            proc.kill()
            await proc.wait()
        assert proc.returncode == 0

    asyncio.run(scenario())


class CustomToolExecutor:
    """ToolExecutor implementing both execute() and aexecute()."""

    def __init__(self) -> None:
        self.called = False

    def execute(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> Any:
        self.called = True
        return f"custom-sync:{tool_name}"

    async def aexecute(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> Any:
        self.called = True
        return f"custom-async:{tool_name}"


def test_custom_tool_executor_path(
    shield: Shield, issuer: AgentTokenIssuer, clock: FakeClock
) -> None:
    executor = CustomToolExecutor()
    gateway = MCPGateway(shield=shield, executor=executor)

    token = issuer.mint(
        subject="agent",
        agent_run_id="run-custom",
        env=Env.PROD,
        allowed_tools=("charge_card",),
        now=clock.now(),
    )

    async def scenario() -> None:
        resp = await gateway.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "charge_card",
                    "arguments": {"amount": "10.00", "currency": "USD"},
                    "_meta": {"token": token, "agent_run_id": "run-custom"},
                },
            }
        )
        assert resp is not None
        assert resp["result"]["content"][0]["text"] == "custom-async:charge_card"
        assert executor.called is True

    asyncio.run(scenario())


def test_tool_call_dict_content_and_non_string_result(
    shield: Shield, issuer: AgentTokenIssuer, clock: FakeClock
) -> None:
    def content_tool(msg: str) -> dict[str, Any]:
        return {"content": [{"type": "text", "text": f"formatted:{msg}"}]}

    def number_tool() -> int:
        return 4242

    gateway = MCPGateway(
        shield=shield,
        executor={"content_tool": content_tool, "number_tool": number_tool},
    )

    token = issuer.mint(
        subject="agent",
        agent_run_id="run-types",
        env=Env.PROD,
        allowed_tools=("content_tool", "number_tool"),
        now=clock.now(),
    )

    async def scenario() -> None:
        # 1. Content dict
        r1 = await gateway.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "content_tool",
                    "arguments": {"msg": "hello"},
                    "_meta": {"token": token, "agent_run_id": "run-types"},
                },
            }
        )
        assert r1 is not None
        assert r1["result"]["content"][0]["text"] == "formatted:hello"

        # 2. Non-string integer return
        r2 = await gateway.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "number_tool",
                    "arguments": {},
                    "_meta": {"token": token, "agent_run_id": "run-types"},
                },
            }
        )
        assert r2 is not None
        assert r2["result"]["content"][0]["text"] == "4242"

    asyncio.run(scenario())


def test_tool_call_handler_with_context_parameter(
    shield: Shield, issuer: AgentTokenIssuer, clock: FakeClock
) -> None:
    received_ctx: dict[str, Any] = {}

    def context_aware_tool(amount: str, *, context: dict[str, Any]) -> str:
        received_ctx.update(context)
        return f"amount:{amount}"

    gateway = MCPGateway(shield=shield, executor={"ctx_tool": context_aware_tool})

    token = issuer.mint(
        subject="agent",
        agent_run_id="run-ctx",
        env=Env.PROD,
        allowed_tools=("ctx_tool",),
        now=clock.now(),
    )

    async def scenario() -> None:
        res = await gateway.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "ctx_tool",
                    "arguments": {"amount": "99.00"},
                    "_meta": {"token": token, "agent_run_id": "run-ctx"},
                },
            }
        )
        assert res is not None
        assert res["result"]["content"][0]["text"] == "amount:99.00"
        assert received_ctx["target_env"] == "prod"

    asyncio.run(scenario())


def test_tool_call_not_found_error(
    shield: Shield, issuer: AgentTokenIssuer, clock: FakeClock
) -> None:
    gateway = MCPGateway(shield=shield, executor={})
    token = issuer.mint(
        subject="agent",
        agent_run_id="run-missing",
        env=Env.PROD,
        allowed_tools=("nonexistent_tool",),
        now=clock.now(),
    )

    async def scenario() -> None:
        res = await gateway.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "nonexistent_tool",
                    "arguments": {},
                    "_meta": {"token": token, "agent_run_id": "run-missing"},
                },
            }
        )
        assert res is not None
        assert res["result"]["isError"] is True
        assert "Tool 'nonexistent_tool' not found" in res["result"]["content"][0]["text"]

    asyncio.run(scenario())


def test_tool_execution_failed_jsonrpc_error_mode(
    shield: Shield, issuer: AgentTokenIssuer, clock: FakeClock
) -> None:
    def failing_fn() -> None:
        raise ValueError("failing tool exploded")

    gateway = MCPGateway(
        shield=shield,
        executor={"failing_fn": failing_fn},
        error_mode="jsonrpc",
    )
    token = issuer.mint(
        subject="agent",
        agent_run_id="run-fail-jsonrpc",
        env=Env.PROD,
        allowed_tools=("failing_fn",),
        now=clock.now(),
    )

    async def scenario() -> None:
        res = await gateway.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 10,
                "method": "tools/call",
                "params": {
                    "name": "failing_fn",
                    "arguments": {},
                    "_meta": {"token": token, "agent_run_id": "run-fail-jsonrpc"},
                },
            }
        )
        assert res is not None
        assert res["error"]["code"] == -32603
        assert "Tool execution failed" in res["error"]["message"]

    asyncio.run(scenario())


def test_notifications_handling_and_dispatch_errors(shield: Shield) -> None:
    gateway = MCPGateway(shield=shield)

    async def scenario() -> None:
        # notifications/cancelled
        res1 = await gateway.handle_message(
            {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 1}}
        )
        assert res1 is None

        # Unknown notification without id
        res2 = await gateway.handle_message(
            {"jsonrpc": "2.0", "method": "some/unknown_notification"}
        )
        assert res2 is None

        # Invalid method type (not string)
        res3 = await gateway.handle_message({"jsonrpc": "2.0", "id": 1, "method": 12345})
        assert res3 is not None
        assert res3["error"]["code"] == -32600

        # Shield error during dispatch
        from redhand_fintech_shield.exceptions import ShieldError

        async def bad_dispatch(*args: Any) -> Any:
            raise ShieldError("simulated shield error")

        gateway.dispatch_request = bad_dispatch  # type: ignore[assignment]

        res4 = await gateway.handle_message({"jsonrpc": "2.0", "id": 2, "method": "ping"})
        assert res4 is not None
        assert res4["error"]["code"] == -32000
        assert "simulated shield error" in res4["error"]["message"]

        # Notification when ShieldError raised
        res5 = await gateway.handle_message({"jsonrpc": "2.0", "method": "ping"})
        assert res5 is None

        # Generic exception during dispatch
        async def err_dispatch(*args: Any) -> Any:
            raise RuntimeError("simulated dispatch crash")

        gateway.dispatch_request = err_dispatch  # type: ignore[assignment]

        res6 = await gateway.handle_message({"jsonrpc": "2.0", "id": 3, "method": "ping"})
        assert res6 is not None
        assert res6["error"]["code"] == -32603

        res7 = await gateway.handle_message({"jsonrpc": "2.0", "method": "ping"})
        assert res7 is None

    asyncio.run(scenario())


def test_serve_stdio_explicit_streams_and_fallback(shield: Shield) -> None:
    gateway = MCPGateway(shield=shield)

    async def scenario() -> None:
        server = await asyncio.start_server(gateway.serve_streams, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)

        # Call serve_stdio passing explicit reader and writer
        task = asyncio.create_task(gateway.serve_stdio(reader, writer))

        # Close writer to finish stream
        writer.close()
        await writer.wait_closed()
        await task
        server.close()
        await server.wait_closed()

    asyncio.run(scenario())


def test_serve_stdio_fallback_loop(shield: Shield) -> None:
    gateway = MCPGateway(shield=shield)

    import io
    import sys

    old_stdin = sys.stdin
    old_stdout = sys.stdout
    sys.stdin = io.StringIO('{"jsonrpc": "2.0", "id": 1, "method": "ping"}\n\n')
    sys.stdout = io.StringIO()

    try:

        async def scenario() -> None:
            await gateway._serve_stdio_fallback()

        asyncio.run(scenario())
        output = sys.stdout.getvalue()
        assert '"result":{}' in output or '"result": {}' in output
    finally:
        sys.stdin = old_stdin
        sys.stdout = old_stdout


def test_token_unverified_claims_and_decode_error() -> None:
    import jwt

    # Token with agent_run_id in claims
    token_with_claim = jwt.encode(
        {"agent_run_id": "run-auto-extracted"}, "a" * 32, algorithm="HS256"
    )
    ctx = extract_tool_call_context(
        tool_name="test_tool",
        arguments={},
        meta={"token": token_with_claim},
    )
    assert ctx.agent_run_id == "run-auto-extracted"

    # Token with invalid JWT string (triggers jwt.PyJWTError in decode fallback)
    ctx_bad = extract_tool_call_context(
        tool_name="test_tool",
        arguments={},
        meta={"token": "not.a.valid.jwt"},
    )
    assert ctx_bad.agent_run_id == "anonymous"


@pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")
def test_cli_gateway_with_policy_verifier_path(tmp_path: Path, policy: PolicyConfig) -> None:
    _, pub = AgentTokenIssuer.generate_keypair()
    pub_file = tmp_path / "policy_pub.pem"
    pub_file.write_bytes(public_key_to_pem(pub))

    policy_file = tmp_path / "custom_policy.yaml"
    policy_with_pub = policy.model_copy(
        update={
            "verifier_public_key_path": pub_file,
            "audit_path": tmp_path / "pol_audit.jsonl",
            "quarantine_journal_path": tmp_path / "pol_journal.jsonl",
        }
    )
    policy_file.write_text(policy_with_pub.model_dump_json())

    import io
    import sys

    old_stdin = sys.stdin
    sys.stdin = io.StringIO("")
    try:
        res = main(["gateway", "--policy", str(policy_file)])
        assert res == 0
    finally:
        sys.stdin = old_stdin


def test_registered_tool_call_without_arguments_key(
    shield: Shield, issuer: AgentTokenIssuer, clock: FakeClock
) -> None:
    gateway = MCPGateway(shield=shield)

    def simple_action() -> str:
        return "action-done"

    gateway.register_tool("simple_action", simple_action)

    token = issuer.mint(
        subject="agent",
        agent_run_id="run-action",
        env=Env.PROD,
        allowed_tools=("simple_action",),
        now=clock.now(),
    )

    async def scenario() -> None:
        # params without "arguments" key (tests lines 238-240 and line 276)
        res = await gateway.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "simple_action",
                    "_meta": {"token": token, "agent_run_id": "run-action"},
                },
            }
        )
        assert res is not None
        assert res["result"]["content"][0]["text"] == "action-done"

    asyncio.run(scenario())


def test_serve_streams_incomplete_read_and_writer_error(shield: Shield) -> None:
    gateway = MCPGateway(shield=shield)

    async def scenario() -> None:
        reader = asyncio.StreamReader()
        # Feed Content-Length 50 but only 10 bytes then EOF
        reader.feed_data(b"Content-Length: 50\r\n\r\n1234567890")
        reader.feed_eof()

        class FaultyWriter:
            def write(self, data: bytes) -> None:
                raise ConnectionResetError("broken pipe")

            async def drain(self) -> None:
                pass

        writer = cast(asyncio.StreamWriter, FaultyWriter())
        # Should gracefully handle IncompleteReadError and break without crashing
        await gateway.serve_streams(reader, writer)

        # Also test broken pipe when writing response
        r2 = asyncio.StreamReader()
        r2.feed_data(b'{"jsonrpc": "2.0", "id": 1, "method": "ping"}\n')
        r2.feed_eof()
        await gateway.serve_streams(r2, writer)

    asyncio.run(scenario())


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="connect_read_pipe not used on Windows ProactorEventLoop",
)
def test_serve_stdio_connect_pipe_coverage(shield: Shield, monkeypatch: pytest.MonkeyPatch) -> None:
    gateway = MCPGateway(shield=shield)

    async def scenario() -> None:
        loop = asyncio.get_running_loop()
        monkeypatch.setattr(sys.stdin, "fileno", lambda: 0, raising=False)

        async def fake_connect_read_pipe(protocol_factory: Any, pipe: Any) -> tuple[Any, Any]:
            protocol = protocol_factory()
            if hasattr(protocol, "_stream_reader") and protocol._stream_reader is not None:
                protocol._stream_reader.feed_eof()
            return object(), protocol

        async def fake_connect_write_pipe(protocol_factory: Any, pipe: Any) -> tuple[Any, Any]:
            class DummyTransport:
                def is_closing(self) -> bool:
                    return False

                def close(self) -> None:
                    pass

            return DummyTransport(), protocol_factory()

        monkeypatch.setattr(loop, "connect_read_pipe", fake_connect_read_pipe)
        monkeypatch.setattr(loop, "connect_write_pipe", fake_connect_write_pipe)

        # Call serve_stdio, hits connect_read_pipe and connect_write_pipe path in-process
        await gateway.serve_stdio()

    asyncio.run(scenario())


def test_serve_streams_read_exception_handling(shield: Shield) -> None:
    gateway = MCPGateway(shield=shield)

    async def scenario() -> None:
        class CrashingReader:
            async def readline(self) -> bytes:
                raise OSError("network card crashed")

        class CapturingWriter:
            def __init__(self) -> None:
                self.data = bytearray()
                self._calls = 0

            def write(self, data: bytes) -> None:
                self.data.extend(data)

            async def drain(self) -> None:
                self._calls += 1
                if self._calls >= 2:
                    raise ConnectionResetError("close")

        writer_impl = CapturingWriter()
        reader = cast(asyncio.StreamReader, CrashingReader())
        writer = cast(asyncio.StreamWriter, writer_impl)
        await gateway.serve_streams(reader, writer)
        assert b"Stream read error" in writer_impl.data

    asyncio.run(scenario())
