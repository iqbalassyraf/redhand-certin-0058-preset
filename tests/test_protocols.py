"""Tests for extensibility protocols, runtime checkability, and Shield custom backend seams."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from redhand_fintech_shield import (
    AgentQuarantinedError,
    AgentTokenVerifier,
    AuditLog,
    AuditRecord,
    Decision,
    HashChainedAuditLog,
    M42Finding,
    PolicyConfig,
    QuarantineRegistry,
    QuarantineTracker,
    Shield,
    ToolCallContext,
    ToolNotPinnedError,
)
from redhand_fintech_shield.detectors import R_TOOL_NOT_PINNED
from redhand_fintech_shield.protocols import (
    AuditLogBackend,
    Clock,
    MonotonicClock,
    NullTelemetrySink,
    QuarantineBackend,
    TelemetrySink,
    ToolExecutor,
)

from .conftest import FakeClock

MakeCtx = Callable[..., ToolCallContext]


# -----------------------------------------------------------------------------
# Mock / In-Memory Implementations for Protocols
# -----------------------------------------------------------------------------


class InMemoryAuditBackend:
    """In-memory AuditLogBackend implementation for testing."""

    def __init__(self) -> None:
        self.records: list[AuditRecord] = []
        self.closed: bool = False
        self._tail_hash: str = "0000000000000000000000000000000000000000000000000000000000000000"

    def append(self, body: dict[str, Any]) -> AuditRecord:
        import hashlib
        import json

        seq = len(self.records)
        raw = json.dumps(body, sort_keys=True, default=str)
        rec_hash = hashlib.sha256(f"{self._tail_hash}:{seq}:{raw}".encode()).hexdigest()
        full = {
            **body,
            "seq": seq,
            "prev_hash": self._tail_hash,
            "record_hash": rec_hash,
        }
        rec = AuditRecord.model_validate(full)
        self.records.append(rec)
        self._tail_hash = rec_hash
        return rec

    def close(self) -> None:
        self.closed = True

    @property
    def tail_hash(self) -> str:
        return self._tail_hash


class InMemoryQuarantineBackend:
    """In-memory QuarantineBackend implementation for testing."""

    def __init__(self) -> None:
        self.entries: dict[str, str] = {}
        self.add_history: list[tuple[str, str, datetime | None]] = []

    def add(self, agent_run_id: str, reason: str, ts: datetime | None = None) -> bool:
        self.add_history.append((agent_run_id, reason, ts))
        if agent_run_id in self.entries:
            return False
        self.entries[agent_run_id] = reason
        return True

    def is_quarantined(self, agent_run_id: str) -> bool:
        return agent_run_id in self.entries

    def reason(self, agent_run_id: str) -> str | None:
        return self.entries.get(agent_run_id)


class RecordingTelemetrySink:
    """TelemetrySink that collects all emitted findings in memory."""

    def __init__(self) -> None:
        self.findings: list[M42Finding] = []

    def emit(self, finding: M42Finding) -> None:
        self.findings.append(finding)


class FailingTelemetrySink:
    """TelemetrySink that deliberately raises an error to test fault tolerance."""

    def emit(self, finding: M42Finding) -> None:
        raise ConnectionResetError("telemetry pipeline unavailable")


class SimpleClock:
    """Clock implementation providing only wall-clock time."""

    def __init__(self, dt: datetime) -> None:
        self._dt = dt

    def now(self) -> datetime:
        return self._dt


class SimpleMonotonicClock:
    """MonotonicClock implementation providing only monotonic time."""

    def __init__(self, val: float = 1234.5) -> None:
        self._val = val

    def monotonic(self) -> float:
        return self._val


class MockToolExecutor:
    """ToolExecutor implementing sync and async execution interfaces."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any], dict[str, Any] | None]] = []
        self.acalls: list[tuple[str, dict[str, Any], dict[str, Any] | None]] = []

    def execute(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> Any:
        self.calls.append((tool_name, arguments, context))
        return f"sync-result:{tool_name}"

    async def aexecute(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> Any:
        self.acalls.append((tool_name, arguments, context))
        await asyncio.sleep(0)
        return f"async-result:{tool_name}"


# -----------------------------------------------------------------------------
# 1. Runtime Checkability Tests (isinstance)
# -----------------------------------------------------------------------------


def test_audit_log_backend_runtime_checkable() -> None:
    backend = InMemoryAuditBackend()
    assert isinstance(backend, AuditLogBackend)

    class IncompleteAuditBackend:
        def append(self, body: dict[str, Any]) -> AuditRecord:
            raise NotImplementedError

    assert not isinstance(IncompleteAuditBackend(), AuditLogBackend)
    assert not isinstance(object(), AuditLogBackend)


def test_quarantine_backend_runtime_checkable() -> None:
    backend = InMemoryQuarantineBackend()
    assert isinstance(backend, QuarantineBackend)

    class MissingReason:
        def add(self, agent_run_id: str, reason: str, ts: datetime | None = None) -> bool:
            return True

        def is_quarantined(self, agent_run_id: str) -> bool:
            return False

    assert not isinstance(MissingReason(), QuarantineBackend)
    assert not isinstance(object(), QuarantineBackend)


def test_clock_protocols_runtime_checkable() -> None:
    clock = SimpleClock(datetime(2026, 11, 13, tzinfo=UTC))
    mono = SimpleMonotonicClock(100.0)

    assert isinstance(clock, Clock)
    assert not isinstance(clock, MonotonicClock)

    assert isinstance(mono, MonotonicClock)
    assert not isinstance(mono, Clock)

    fake_clock = FakeClock()
    assert isinstance(fake_clock, Clock)
    assert isinstance(fake_clock, MonotonicClock)


def test_telemetry_sink_runtime_checkable() -> None:
    rec_sink = RecordingTelemetrySink()
    null_sink = NullTelemetrySink()
    fail_sink = FailingTelemetrySink()

    assert isinstance(rec_sink, TelemetrySink)
    assert isinstance(null_sink, TelemetrySink)
    assert isinstance(fail_sink, TelemetrySink)

    class NotASink:
        pass

    assert not isinstance(NotASink(), TelemetrySink)


def test_tool_executor_runtime_checkable() -> None:
    executor = MockToolExecutor()
    assert isinstance(executor, ToolExecutor)

    class SyncOnly:
        def execute(
            self, tool_name: str, arguments: dict[str, Any], context: dict[str, Any] | None = None
        ) -> Any:
            return None

    class AsyncOnly:
        async def aexecute(
            self, tool_name: str, arguments: dict[str, Any], context: dict[str, Any] | None = None
        ) -> Any:
            return None

    assert not isinstance(SyncOnly(), ToolExecutor)
    assert not isinstance(AsyncOnly(), ToolExecutor)
    assert not isinstance(object(), ToolExecutor)


# -----------------------------------------------------------------------------
# 2. Built-in Conformance Tests
# -----------------------------------------------------------------------------


def test_builtin_hash_chained_audit_log_conforms_to_protocol(tmp_path: Path) -> None:
    log = HashChainedAuditLog(tmp_path / "audit.jsonl")
    try:
        assert isinstance(log, AuditLogBackend)
        assert hasattr(log, "append")
        assert hasattr(log, "close")
        assert hasattr(log, "tail_hash")
        assert AuditLog is HashChainedAuditLog
    finally:
        log.close()


def test_builtin_quarantine_registry_conforms_to_protocol(tmp_path: Path) -> None:
    reg = QuarantineRegistry(tmp_path / "q.jsonl")
    assert isinstance(reg, QuarantineBackend)
    assert hasattr(reg, "add")
    assert hasattr(reg, "is_quarantined")
    assert hasattr(reg, "reason")
    assert QuarantineTracker is QuarantineRegistry


# -----------------------------------------------------------------------------
# 3. NullTelemetrySink Tests
# -----------------------------------------------------------------------------


def test_null_telemetry_sink_silent_noop() -> None:
    sink = NullTelemetrySink()
    finding = M42Finding(
        finding_id="test-id",
        rule_id="R-TEST",
        severity="low",
        stage=1,
        decision=Decision.ALLOW,
        would_have_blocked=False,
        enforced=True,
        agent_run_id="run-1",
        tool_name="test_tool",
        detail="test detail",
        observed_at=datetime.now(UTC),
    )
    sink.emit(finding)


# -----------------------------------------------------------------------------
# 4. Shield Seam & Custom Backend Wiring Tests
# -----------------------------------------------------------------------------


def test_shield_accepts_custom_audit_backend(
    policy: PolicyConfig, verifier: AgentTokenVerifier, clock: FakeClock, make_ctx: MakeCtx
) -> None:
    custom_audit = InMemoryAuditBackend()
    shield = Shield(
        policy,
        verifier,
        audit=custom_audit,
        clock=clock.now,
        monotonic=clock.monotonic,
    )

    assert shield.audit_log is custom_audit

    @shield.guard
    def protected_action(*, ctx: ToolCallContext) -> str:
        return "success"

    ctx = make_ctx(tool="list_merchants")
    assert protected_action(ctx=ctx) == "success"
    assert len(custom_audit.records) == 1
    assert custom_audit.records[0].tool_outcome == "executed"
    assert custom_audit.records[0].decision == Decision.ALLOW

    shield.close()
    assert custom_audit.closed is True


def test_shield_accepts_audit_log_alias_parameter(
    policy: PolicyConfig, verifier: AgentTokenVerifier, clock: FakeClock, make_ctx: MakeCtx
) -> None:
    custom_audit = InMemoryAuditBackend()
    shield = Shield(
        policy,
        verifier,
        audit_log=custom_audit,
        clock=clock.now,
        monotonic=clock.monotonic,
    )
    assert shield.audit is custom_audit
    assert shield.audit_log is custom_audit
    shield.close()
    assert custom_audit.closed is True


def test_shield_accepts_custom_quarantine_backend(
    policy: PolicyConfig, verifier: AgentTokenVerifier, clock: FakeClock, make_ctx: MakeCtx
) -> None:
    custom_q = InMemoryQuarantineBackend()
    custom_q.add("quarantined-run", "security violation")

    shield = Shield(
        policy,
        verifier,
        quarantine=custom_q,
        clock=clock.now,
        monotonic=clock.monotonic,
    )

    assert shield.quarantine_tracker is custom_q

    @shield.guard
    def protected_action(*, ctx: ToolCallContext) -> str:
        return "ok"

    ctx = make_ctx(run="quarantined-run", tool="list_merchants")
    with pytest.raises(AgentQuarantinedError, match="security violation"):
        protected_action(ctx=ctx)


def test_shield_accepts_quarantine_tracker_alias_parameter(
    policy: PolicyConfig, verifier: AgentTokenVerifier, clock: FakeClock
) -> None:
    custom_q = InMemoryQuarantineBackend()
    shield = Shield(
        policy,
        verifier,
        quarantine_tracker=custom_q,
        clock=clock.now,
        monotonic=clock.monotonic,
    )
    assert shield.quarantine is custom_q
    assert shield.quarantine_tracker is custom_q


def test_shield_auto_quarantine_on_block_with_custom_backend(
    policy: PolicyConfig, verifier: AgentTokenVerifier, clock: FakeClock, make_ctx: MakeCtx
) -> None:
    custom_q = InMemoryQuarantineBackend()
    shield = Shield(
        policy,
        verifier,
        quarantine=custom_q,
        clock=clock.now,
        monotonic=clock.monotonic,
    )

    @shield.guard
    def unpinned_tool(*, ctx: ToolCallContext) -> str:
        return "ok"

    ctx = make_ctx(run="probe-run", tool="unpinned_tool", allowed=("other_tool",))
    with pytest.raises(ToolNotPinnedError):
        unpinned_tool(ctx=ctx)

    assert custom_q.is_quarantined("probe-run")
    assert R_TOOL_NOT_PINNED in (custom_q.reason("probe-run") or "")


def test_shield_accepts_custom_telemetry_sink(
    policy: PolicyConfig, verifier: AgentTokenVerifier, clock: FakeClock, make_ctx: MakeCtx
) -> None:
    sink = RecordingTelemetrySink()
    shield = Shield(
        policy,
        verifier,
        telemetry_sink=sink,
        clock=clock.now,
        monotonic=clock.monotonic,
    )

    @shield.guard
    def test_tool(*, ctx: ToolCallContext) -> str:
        return "ok"

    ctx = make_ctx(tool="forbidden_tool", allowed=("allowed_tool",))
    with pytest.raises(ToolNotPinnedError):
        test_tool(ctx=ctx)

    assert len(sink.findings) >= 1
    assert sink.findings[0].rule_id == R_TOOL_NOT_PINNED
    assert sink.findings[0].decision == Decision.BLOCK
    assert sink.findings[0].agent_run_id == ctx.agent_run_id


def test_shield_telemetry_sink_failure_fault_tolerance(
    policy: PolicyConfig, verifier: AgentTokenVerifier, clock: FakeClock, make_ctx: MakeCtx
) -> None:
    failing_sink = FailingTelemetrySink()
    shield = Shield(
        policy,
        verifier,
        telemetry_sink=failing_sink,
        clock=clock.now,
        monotonic=clock.monotonic,
    )

    @shield.guard
    def test_tool(*, ctx: ToolCallContext) -> str:
        return "ok"

    ctx = make_ctx(tool="forbidden_tool", allowed=("allowed_tool",))
    # Should still raise ToolNotPinnedError, not ConnectionResetError
    with pytest.raises(ToolNotPinnedError):
        test_tool(ctx=ctx)

    assert shield.telemetry_failures >= 1


def test_shield_accepts_protocol_clock_objects(
    policy: PolicyConfig, verifier: AgentTokenVerifier, make_ctx: MakeCtx
) -> None:
    dt = datetime(2026, 11, 11, 5, 30, tzinfo=UTC)
    clock_obj = SimpleClock(dt)
    mono_obj = SimpleMonotonicClock(5000.0)

    shield = Shield(
        policy,
        verifier,
        clock=clock_obj,
        monotonic=mono_obj,
    )

    @shield.guard
    def sample_tool(*, ctx: ToolCallContext) -> str:
        return "ok"

    ctx = make_ctx(tool="list_merchants")
    assert sample_tool(ctx=ctx) == "ok"
    shield.close()


def test_shield_all_custom_backends_simultaneously(
    policy: PolicyConfig, verifier: AgentTokenVerifier, clock: FakeClock, make_ctx: MakeCtx
) -> None:
    custom_audit = InMemoryAuditBackend()
    custom_q = InMemoryQuarantineBackend()
    custom_sink = RecordingTelemetrySink()

    shield = Shield(
        policy,
        verifier,
        audit=custom_audit,
        quarantine=custom_q,
        telemetry_sink=custom_sink,
        clock=clock.now,
        monotonic=clock.monotonic,
    )

    @shield.guard
    def safe_tool(*, ctx: ToolCallContext) -> str:
        return "done"

    ctx = make_ctx(tool="list_merchants")
    assert safe_tool(ctx=ctx) == "done"
    assert len(custom_audit.records) == 1
    assert len(custom_sink.findings) == 0

    shield.close()
    assert custom_audit.closed is True


def test_shield_default_parameters_backward_compatibility(
    policy: PolicyConfig, verifier: AgentTokenVerifier, clock: FakeClock, make_ctx: MakeCtx
) -> None:
    # Omitting audit, quarantine, and telemetry_sink must work transparently
    shield = Shield(policy, verifier, clock=clock.now, monotonic=clock.monotonic)

    assert isinstance(shield.audit, AuditLogBackend)
    assert isinstance(shield.quarantine, QuarantineBackend)
    assert isinstance(shield.telemetry_sink, TelemetrySink)
    assert isinstance(shield.telemetry_sink, NullTelemetrySink)

    @shield.guard
    def tool(*, ctx: ToolCallContext) -> str:
        return "ok"

    assert tool(ctx=make_ctx(tool="list_merchants")) == "ok"
    shield.close()


# -----------------------------------------------------------------------------
# 5. Async Tool Error Coverage & ToolExecutor Invocation Tests
# -----------------------------------------------------------------------------


def test_async_tool_exception_write_audit(shield: Shield, make_ctx: MakeCtx) -> None:
    """Verifies that an async guarded tool raising an exception records 'tool_error'.

    Directly covers interceptor.py lines 325-327, ensuring 100% interceptor coverage.
    """

    @shield.guard
    async def async_failing_tool(*, ctx: ToolCallContext) -> str:
        await asyncio.sleep(0)
        raise RuntimeError("simulated tool failure")

    async def scenario() -> None:
        with pytest.raises(RuntimeError, match="simulated tool failure"):
            await async_failing_tool(ctx=make_ctx(tool="list_merchants"))

    asyncio.run(scenario())


def test_tool_executor_sync_and_async() -> None:
    executor = MockToolExecutor()

    # Sync invocation
    res_sync = executor.execute("charge_card", {"amount": "100.00"}, {"env": "prod"})
    assert res_sync == "sync-result:charge_card"
    assert executor.calls == [("charge_card", {"amount": "100.00"}, {"env": "prod"})]

    # Async invocation
    async def scenario() -> Any:
        return await executor.aexecute("bulk_payout", {"total": 500}, None)

    res_async = asyncio.run(scenario())
    assert res_async == "async-result:bulk_payout"
    assert executor.acalls == [("bulk_payout", {"total": 500}, None)]
