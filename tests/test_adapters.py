"""Comprehensive test suite for multi-cloud platform and framework adapters.

Tests Bedrock, Azure OpenAI, Semantic Kernel, Google GenAI, LangChain, and GenericToolRunner
across happy path, pivot blocking, micro-tx probing, HITL step-up, off-hours, observe mode,
error auditing, sanitization, async, and soft imports without vendor SDK lock-in.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from typing import Any

import pytest

from redhand_fintech_shield import (
    Env,
    HITLRequiredError,
    MicroTxProbeError,
    Mode,
    Shield,
    TokenPivotError,
    ToolCallContext,
    ToolExecutor,
    adapters,
)
from redhand_fintech_shield.adapters import (
    AzureOpenAIAdapter,
    BedrockConverseAdapter,
    GenericToolRunner,
    GoogleGenAIAdapter,
    RedHandGuardedTool,
    RedHandSemanticKernelFilter,
    check_module_available,
    extract_tool_call_context,
    format_violation_payload,
    guard_langchain_tool,
    require_module,
)
from redhand_fintech_shield.crypto import AgentTokenIssuer
from tests.conftest import FakeClock


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
        return {"status": "success", "tool": tool_name, "tx_id": "tx_mock_123"}

    async def aexecute(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> Any:
        self.calls.append((tool_name, arguments, context))
        return {"status": "success", "tool": tool_name, "tx_id": "tx_mock_async_123"}


class MockSemanticKernelContext:
    """Duck-typed context for Semantic Kernel function invocation filter."""

    def __init__(self, name: str, arguments: dict[str, Any]) -> None:
        self.function = type("SKFunction", (), {"name": name})()
        self.arguments = dict(arguments)
        self.result: Any = None
        self.function_result: Any = None
        self.terminate: bool = False


class MockGooglePart:
    """Duck-typed object representing a Google GenAI Part with function_call."""

    def __init__(self, name: str, args: dict[str, Any], call_id: str | None = None) -> None:
        self.name = name
        self.args = args
        self.id = call_id


class MockLangChainTool:
    """Duck-typed tool conforming to LangChain BaseTool interface."""

    def __init__(self, name: str = "charge_card", description: str = "Card charger") -> None:
        self.name = name
        self.description = description
        self.args_schema = None
        self.return_direct = True
        self.calls: list[dict[str, Any]] = []

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        return {"status": "success", "tool": self.name}

    async def _arun(self, *args: Any, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        return {"status": "success", "tool": self.name}


# ======================================================================================
# SUITE 1: AWS Amazon Bedrock Converse Adapter (`bedrock.py`)
# ======================================================================================


def test_bedrock_converse_happy_path_sync(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    token = issuer.mint(
        subject="svc-agent",
        agent_run_id="run-b1",
        env=Env.PROD,
        allowed_tools=("charge_card",),
        hitl_step_up=False,
        now=clock.now(),
    )
    mock = MockToolExecutor()
    adapter = BedrockConverseAdapter(shield, mock)

    tool_use = {
        "toolUse": {
            "toolUseId": "tooluse_k98dfj23_01",
            "name": "charge_card",
            "input": {
                "amount": "100.00",
                "currency": "USD",
                "token": token,
                "target_env": "prod",
                "agent_run_id": "run-b1",
            },
        }
    }

    result = adapter.handle_tool_use_block(tool_use)
    assert result["toolResult"]["toolUseId"] == "tooluse_k98dfj23_01"
    assert result["toolResult"]["status"] == "success"
    assert result["toolResult"]["content"][0]["json"]["status"] == "success"
    assert len(mock.calls) == 1
    assert mock.calls[0][0] == "charge_card"


def test_bedrock_converse_staging_to_prod_pivot_block(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    staging_token = issuer.mint(
        subject="svc-agent",
        agent_run_id="run-b2",
        env=Env.STAGING,
        allowed_tools=("charge_card",),
        hitl_step_up=False,
        now=clock.now(),
    )
    mock = MockToolExecutor()
    adapter = BedrockConverseAdapter(shield, mock)

    tool_use = {
        "toolUse": {
            "toolUseId": "tooluse_pivot_01",
            "name": "charge_card",
            "input": {
                "amount": "100.00",
                "currency": "USD",
                "token": staging_token,
                "target_env": "prod",
                "agent_run_id": "run-b2",
            },
        }
    }

    result = adapter.handle_tool_use_block(tool_use)
    assert result["toolResult"]["toolUseId"] == "tooluse_pivot_01"
    assert result["toolResult"]["status"] == "error"
    error_json = result["toolResult"]["content"][0]["json"]
    assert error_json["rule_id"] == "CIAD-2026-0058.R1.staging_to_prod_pivot"
    assert error_json["decision"] == "block"
    assert len(mock.calls) == 0
    assert shield.quarantine.is_quarantined("run-b2")


def test_bedrock_converse_micro_probe_block(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    token = issuer.mint(
        subject="svc-agent",
        agent_run_id="run-b3",
        env=Env.PROD,
        allowed_tools=("charge_card",),
        hitl_step_up=False,
        now=clock.now(),
    )
    mock = MockToolExecutor()
    adapter = BedrockConverseAdapter(shield, mock)

    tool_use = {
        "toolUse": {
            "toolUseId": "tooluse_probe_1",
            "name": "charge_card",
            "input": {
                "amount": "1.00",
                "currency": "USD",
                "token": token,
                "target_env": "prod",
                "agent_run_id": "run-b3",
            },
        }
    }

    # 1st probe succeeds
    res1 = adapter.handle_tool_use_block(tool_use)
    assert res1["toolResult"]["status"] == "success"
    assert len(mock.calls) == 1

    # 2nd probe trips micro-tx probe ceiling
    tool_use["toolUse"]["toolUseId"] = "tooluse_probe_2"
    res2 = adapter.handle_tool_use_block(tool_use)
    assert res2["toolResult"]["status"] == "error"
    error_json = res2["toolResult"]["content"][0]["json"]
    assert error_json["rule_id"] == "CIAD-2026-0058.R2.micro_tx_probe"
    assert len(mock.calls) == 1
    assert shield.quarantine.is_quarantined("run-b3")


def test_bedrock_converse_hitl_step_up_rejected(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    unstepped_token = issuer.mint(
        subject="svc-agent",
        agent_run_id="run-b4",
        env=Env.PROD,
        allowed_tools=("settle_merchant",),
        hitl_step_up=False,
        now=clock.now(),
    )
    mock = MockToolExecutor()
    adapter = BedrockConverseAdapter(shield, mock)

    tool_use = {
        "toolUse": {
            "toolUseId": "tooluse_hitl_01",
            "name": "settle_merchant",
            "input": {
                "amount": "25000.00",
                "currency": "USD",
                "token": unstepped_token,
                "target_env": "prod",
                "agent_run_id": "run-b4",
            },
        }
    }

    res = adapter.handle_tool_use_block(tool_use)
    assert res["toolResult"]["status"] == "error"
    error_json = res["toolResult"]["content"][0]["json"]
    assert error_json["rule_id"] == "CIAD-2026-0058.R3.hitl_required"
    assert error_json["decision"] == "hitl_required"
    assert len(mock.calls) == 0
    assert not shield.quarantine.is_quarantined("run-b4")


def test_bedrock_converse_hitl_step_up_allowed(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    stepped_token = issuer.mint(
        subject="svc-agent",
        agent_run_id="run-b5",
        env=Env.PROD,
        allowed_tools=("settle_merchant",),
        hitl_step_up=True,
        now=clock.now(),
    )
    mock = MockToolExecutor()
    adapter = BedrockConverseAdapter(shield, mock)

    tool_use = {
        "toolUse": {
            "toolUseId": "tooluse_hitl_02",
            "name": "settle_merchant",
            "input": {
                "amount": "25000.00",
                "currency": "USD",
                "token": stepped_token,
                "target_env": "prod",
                "agent_run_id": "run-b5",
            },
        }
    }

    res = adapter.handle_tool_use_block(tool_use)
    assert res["toolResult"]["status"] == "success"
    assert len(mock.calls) == 1


def test_bedrock_converse_unpinned_tool_block(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    token = issuer.mint(
        subject="svc-agent",
        agent_run_id="run-b6",
        env=Env.PROD,
        allowed_tools=("list_merchants",),
        hitl_step_up=False,
        now=clock.now(),
    )
    mock = MockToolExecutor()
    adapter = BedrockConverseAdapter(shield, mock)

    tool_use = {
        "toolUse": {
            "toolUseId": "tooluse_unpinned",
            "name": "charge_card",
            "input": {
                "token": token,
                "target_env": "prod",
                "agent_run_id": "run-b6",
            },
        }
    }

    res = adapter.handle_tool_use_block(tool_use)
    assert res["toolResult"]["status"] == "error"
    error_json = res["toolResult"]["content"][0]["json"]
    assert error_json["rule_id"] == "CIAD-2026-0058.R3.tool_not_pinned"
    assert len(mock.calls) == 0
    assert shield.quarantine.is_quarantined("run-b6")


def test_bedrock_converse_observe_only_mode(
    make_shield: Callable[..., Shield],
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    shield = make_shield(mode=Mode.OBSERVE_ONLY)
    staging_token = issuer.mint(
        subject="svc-agent",
        agent_run_id="run-b7",
        env=Env.STAGING,
        allowed_tools=("charge_card",),
        hitl_step_up=False,
        now=clock.now(),
    )
    mock = MockToolExecutor()
    adapter = BedrockConverseAdapter(shield, mock)

    tool_use = {
        "toolUse": {
            "toolUseId": "tooluse_obs",
            "name": "charge_card",
            "input": {
                "amount": "100.00",
                "currency": "USD",
                "token": staging_token,
                "target_env": "prod",
                "agent_run_id": "run-b7",
            },
        }
    }

    res = adapter.handle_tool_use_block(tool_use)
    assert res["toolResult"]["status"] == "success"
    assert len(mock.calls) == 1


def test_bedrock_converse_tool_exception_audited(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    token = issuer.mint(
        subject="svc-agent",
        agent_run_id="run-b8",
        env=Env.PROD,
        allowed_tools=("charge_card",),
        hitl_step_up=False,
        now=clock.now(),
    )

    def failing_handler(**kwargs: Any) -> Any:
        raise RuntimeError("Core banking settlement timeout")

    adapter = BedrockConverseAdapter(shield, failing_handler)

    tool_use = {
        "toolUse": {
            "toolUseId": "tooluse_fail",
            "name": "charge_card",
            "input": {
                "token": token,
                "target_env": "prod",
                "agent_run_id": "run-b8",
            },
        }
    }

    res = adapter.handle_tool_use_block(tool_use)
    assert res["toolResult"]["status"] == "error"
    assert "Core banking settlement timeout" in res["toolResult"]["content"][0]["json"]["error"]


def test_bedrock_converse_argument_sanitization(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    token = issuer.mint(
        subject="svc-agent",
        agent_run_id="run-b9",
        env=Env.PROD,
        allowed_tools=("charge_card",),
        hitl_step_up=False,
        now=clock.now(),
    )
    received_args: dict[str, Any] = {}

    def handler(**kwargs: Any) -> Any:
        received_args.update(kwargs)
        return "ok"

    adapter = BedrockConverseAdapter(shield, handler)

    tool_use = {
        "toolUse": {
            "toolUseId": "tooluse_sanitize",
            "name": "charge_card",
            "input": {
                "amount": "50.00",
                "currency": "USD",
                "token": token,
                "_token": "secret",
                "target_env": "prod",
                "agent_run_id": "run-b9",
                "_meta": {"internal": "true"},
            },
        }
    }

    res = adapter.handle_tool_use_block(tool_use)
    assert res["toolResult"]["status"] == "success"
    assert "token" not in received_args
    assert "_token" not in received_args
    assert "target_env" not in received_args
    assert "agent_run_id" not in received_args
    assert "_meta" not in received_args
    assert received_args["amount"] == "50.00"
    assert received_args["currency"] == "USD"


def test_bedrock_converse_multi_tool_use_batch(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    token = issuer.mint(
        subject="svc-agent",
        agent_run_id="run-b10",
        env=Env.PROD,
        allowed_tools=("charge_card",),
        hitl_step_up=False,
        now=clock.now(),
    )
    mock = MockToolExecutor()
    adapter = BedrockConverseAdapter(shield, mock)

    batch_input = [
        {
            "toolUse": {
                "toolUseId": "use_1",
                "name": "charge_card",
                "input": {"token": token, "amount": "10.00", "currency": "USD"},
            }
        },
        {
            "toolUse": {
                "toolUseId": "use_2",
                "name": "charge_card",
                "input": {"token": token, "amount": "20.00", "currency": "USD"},
            }
        },
    ]

    results = adapter.handle_converse_messages(batch_input)
    assert len(results) == 2
    assert results[0]["toolResult"]["toolUseId"] == "use_1"
    assert results[1]["toolResult"]["toolUseId"] == "use_2"
    assert results[0]["toolResult"]["status"] == "success"
    assert results[1]["toolResult"]["status"] == "success"


def test_bedrock_converse_async_execution(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    async def scenario() -> None:
        token = issuer.mint(
            subject="svc-agent",
            agent_run_id="run-b11",
            env=Env.PROD,
            allowed_tools=("charge_card",),
            hitl_step_up=False,
            now=clock.now(),
        )
        mock = MockToolExecutor()
        adapter = BedrockConverseAdapter(shield, mock)

        tool_use = {
            "toolUse": {
                "toolUseId": "async_use_1",
                "name": "charge_card",
                "input": {
                    "amount": "100.00",
                    "currency": "USD",
                    "token": token,
                    "target_env": "prod",
                    "agent_run_id": "run-b11",
                },
            }
        }

        res = await adapter.ahandle_tool_use_block(tool_use)
        assert res["toolResult"]["toolUseId"] == "async_use_1"
        assert res["toolResult"]["status"] == "success"

    asyncio.run(scenario())


# ======================================================================================
# SUITE 2: Microsoft Azure OpenAI & Semantic Kernel Adapter (`azure_openai.py`)
# ======================================================================================


def test_azure_openai_happy_path_dict_arguments(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    token = issuer.mint(
        subject="svc-agent",
        agent_run_id="run-az1",
        env=Env.PROD,
        allowed_tools=("charge_card",),
        hitl_step_up=False,
        now=clock.now(),
    )
    mock = MockToolExecutor()
    adapter = AzureOpenAIAdapter(shield, mock)

    call = {
        "id": "call_123",
        "type": "function",
        "function": {
            "name": "charge_card",
            "arguments": {
                "amount": "50.00",
                "currency": "USD",
                "token": token,
                "target_env": "prod",
                "agent_run_id": "run-az1",
            },
        },
    }

    res = adapter.handle_tool_call(call)
    assert res["role"] == "tool"
    assert res["tool_call_id"] == "call_123"
    assert res["name"] == "charge_card"
    parsed_content = json.loads(res["content"])
    assert parsed_content["status"] == "success"
    assert len(mock.calls) == 1


def test_azure_openai_happy_path_json_string_arguments(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    token = issuer.mint(
        subject="svc-agent",
        agent_run_id="run-az2",
        env=Env.PROD,
        allowed_tools=("charge_card",),
        hitl_step_up=False,
        now=clock.now(),
    )
    mock = MockToolExecutor()
    adapter = AzureOpenAIAdapter(shield, mock)

    call = {
        "id": "call_str_1",
        "type": "function",
        "function": {
            "name": "charge_card",
            "arguments": json.dumps(
                {
                    "amount": "75.00",
                    "currency": "USD",
                    "token": token,
                    "target_env": "prod",
                    "agent_run_id": "run-az2",
                }
            ),
        },
    }

    res = adapter.handle_tool_call(call)
    assert res["role"] == "tool"
    assert res["tool_call_id"] == "call_str_1"
    parsed = json.loads(res["content"])
    assert parsed["status"] == "success"


def test_azure_openai_staging_to_prod_pivot_block(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    staging_token = issuer.mint(
        subject="svc-agent",
        agent_run_id="run-az3",
        env=Env.STAGING,
        allowed_tools=("charge_card",),
        hitl_step_up=False,
        now=clock.now(),
    )
    mock = MockToolExecutor()
    adapter = AzureOpenAIAdapter(shield, mock)

    call = {
        "id": "call_pivot",
        "type": "function",
        "function": {
            "name": "charge_card",
            "arguments": {
                "amount": "100.00",
                "currency": "USD",
                "token": staging_token,
                "target_env": "prod",
                "agent_run_id": "run-az3",
            },
        },
    }

    res = adapter.handle_tool_call(call)
    assert res["role"] == "tool"
    payload = json.loads(res["content"])
    assert payload["rule_id"] == "CIAD-2026-0058.R1.staging_to_prod_pivot"
    assert payload["decision"] == "block"
    assert len(mock.calls) == 0
    assert shield.quarantine.is_quarantined("run-az3")


def test_azure_openai_micro_probe_block(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    token = issuer.mint(
        subject="svc-agent",
        agent_run_id="run-az4",
        env=Env.PROD,
        allowed_tools=("charge_card",),
        hitl_step_up=False,
        now=clock.now(),
    )
    mock = MockToolExecutor()
    adapter = AzureOpenAIAdapter(shield, mock)

    call1 = {
        "id": "probe_1",
        "type": "function",
        "function": {
            "name": "charge_card",
            "arguments": {
                "amount": "2.00",
                "currency": "USD",
                "token": token,
                "target_env": "prod",
                "agent_run_id": "run-az4",
            },
        },
    }
    call2 = {
        "id": "probe_2",
        "type": "function",
        "function": {
            "name": "charge_card",
            "arguments": {
                "amount": "2.00",
                "currency": "USD",
                "token": token,
                "target_env": "prod",
                "agent_run_id": "run-az4",
            },
        },
    }

    res1 = adapter.handle_tool_call(call1)
    assert json.loads(res1["content"])["status"] == "success"

    res2 = adapter.handle_tool_call(call2)
    payload2 = json.loads(res2["content"])
    assert payload2["rule_id"] == "CIAD-2026-0058.R2.micro_tx_probe"
    assert len(mock.calls) == 1
    assert shield.quarantine.is_quarantined("run-az4")


def test_azure_openai_hitl_step_up_rejected_and_allowed(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    unstepped = issuer.mint(
        subject="svc-agent",
        agent_run_id="run-az5",
        env=Env.PROD,
        allowed_tools=("settle_merchant",),
        hitl_step_up=False,
        now=clock.now(),
    )
    stepped = issuer.mint(
        subject="svc-agent",
        agent_run_id="run-az5",
        env=Env.PROD,
        allowed_tools=("settle_merchant",),
        hitl_step_up=True,
        now=clock.now(),
    )
    mock = MockToolExecutor()
    adapter = AzureOpenAIAdapter(shield, mock)

    call_unstepped = {
        "id": "c_hitl_1",
        "function": {
            "name": "settle_merchant",
            "arguments": {
                "amount": "30000.00",
                "currency": "USD",
                "token": unstepped,
                "target_env": "prod",
                "agent_run_id": "run-az5",
            },
        },
    }
    call_stepped = {
        "id": "c_hitl_2",
        "function": {
            "name": "settle_merchant",
            "arguments": {
                "amount": "30000.00",
                "currency": "USD",
                "token": stepped,
                "target_env": "prod",
                "agent_run_id": "run-az5",
            },
        },
    }

    res_unstepped = adapter.handle_tool_call(call_unstepped)
    payload_unstepped = json.loads(res_unstepped["content"])
    assert payload_unstepped["rule_id"] == "CIAD-2026-0058.R3.hitl_required"
    assert len(mock.calls) == 0

    res_stepped = adapter.handle_tool_call(call_stepped)
    payload_stepped = json.loads(res_stepped["content"])
    assert payload_stepped["status"] == "success"
    assert len(mock.calls) == 1


def test_azure_openai_malformed_json_arguments(
    shield: Shield,
) -> None:
    adapter = AzureOpenAIAdapter(shield)
    call = {
        "id": "bad_json_1",
        "function": {"name": "charge_card", "arguments": "NOT_VALID_JSON{}"},
    }
    res = adapter.handle_tool_call(call)
    payload = json.loads(res["content"])
    assert "Invalid JSON in function arguments" in payload["error"]


def test_azure_openai_tool_exception_audited(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    token = issuer.mint(
        subject="svc-agent",
        agent_run_id="run-az7",
        env=Env.PROD,
        allowed_tools=("charge_card",),
        hitl_step_up=False,
        now=clock.now(),
    )

    def failing_tool(**kwargs: Any) -> Any:
        raise ValueError("Invalid merchant account status")

    adapter = AzureOpenAIAdapter(shield, failing_tool)
    call = {
        "id": "exc_1",
        "function": {
            "name": "charge_card",
            "arguments": {
                "amount": "100.00",
                "currency": "USD",
                "token": token,
                "target_env": "prod",
                "agent_run_id": "run-az7",
            },
        },
    }
    res = adapter.handle_tool_call(call)
    payload = json.loads(res["content"])
    assert "Invalid merchant account status" in payload["error"]


def test_azure_openai_batch_tool_calls(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    token = issuer.mint(
        subject="svc-agent",
        agent_run_id="run-az8",
        env=Env.PROD,
        allowed_tools=("charge_card",),
        hitl_step_up=False,
        now=clock.now(),
    )
    mock = MockToolExecutor()
    adapter = AzureOpenAIAdapter(shield, mock)

    calls = [
        {"id": "b1", "function": {"name": "charge_card", "arguments": {"token": token}}},
        {"id": "b2", "function": {"name": "charge_card", "arguments": {"token": token}}},
    ]
    results = adapter.handle_tool_calls(calls)
    assert len(results) == 2
    assert results[0]["tool_call_id"] == "b1"
    assert results[1]["tool_call_id"] == "b2"


def test_semantic_kernel_filter_happy_path(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    async def scenario() -> None:
        token = issuer.mint(
            subject="svc-agent",
            agent_run_id="run-sk1",
            env=Env.PROD,
            allowed_tools=("charge_card",),
            hitl_step_up=False,
            now=clock.now(),
        )
        sk_filter = RedHandSemanticKernelFilter(shield)

        context = MockSemanticKernelContext(
            "charge_card",
            {
                "amount": "50.00",
                "currency": "USD",
                "token": token,
                "target_env": "prod",
                "agent_run_id": "run-sk1",
            },
        )

        next_called = False

        async def mock_next(ctx: Any) -> None:
            nonlocal next_called
            next_called = True
            ctx.result = "payment_processed"

        await sk_filter(context, mock_next)
        assert next_called is True
        assert context.result == "payment_processed"
        assert context.terminate is False

    asyncio.run(scenario())


def test_semantic_kernel_filter_pivot_block(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    async def scenario() -> None:
        staging_token = issuer.mint(
            subject="svc-agent",
            agent_run_id="run-sk2",
            env=Env.STAGING,
            allowed_tools=("charge_card",),
            hitl_step_up=False,
            now=clock.now(),
        )
        sk_filter = RedHandSemanticKernelFilter(shield)

        context = MockSemanticKernelContext(
            "charge_card",
            {
                "amount": "100.00",
                "currency": "USD",
                "token": staging_token,
                "target_env": "prod",
                "agent_run_id": "run-sk2",
            },
        )

        next_called = False

        async def mock_next(ctx: Any) -> None:
            nonlocal next_called
            next_called = True

        await sk_filter(context, mock_next)
        assert next_called is False
        assert context.terminate is True
        assert isinstance(context.result, dict)
        assert context.result["rule_id"] == "CIAD-2026-0058.R1.staging_to_prod_pivot"
        assert shield.quarantine.is_quarantined("run-sk2")

    asyncio.run(scenario())


def test_semantic_kernel_filter_micro_probe_block(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    async def scenario() -> None:
        token = issuer.mint(
            subject="svc-agent",
            agent_run_id="run-sk3",
            env=Env.PROD,
            allowed_tools=("charge_card",),
            hitl_step_up=False,
            now=clock.now(),
        )
        sk_filter = RedHandSemanticKernelFilter(shield)

        ctx1 = MockSemanticKernelContext(
            "charge_card",
            {"amount": "1.00", "currency": "USD", "token": token, "agent_run_id": "run-sk3"},
        )
        ctx2 = MockSemanticKernelContext(
            "charge_card",
            {"amount": "1.00", "currency": "USD", "token": token, "agent_run_id": "run-sk3"},
        )

        c1_called = False

        async def next1(ctx: Any) -> None:
            nonlocal c1_called
            c1_called = True

        await sk_filter(ctx1, next1)
        assert c1_called is True

        c2_called = False

        async def next2(ctx: Any) -> None:
            nonlocal c2_called
            c2_called = True

        await sk_filter(ctx2, next2)
        assert c2_called is False
        assert ctx2.terminate is True
        assert ctx2.result["rule_id"] == "CIAD-2026-0058.R2.micro_tx_probe"
        assert shield.quarantine.is_quarantined("run-sk3")

    asyncio.run(scenario())


def test_semantic_kernel_filter_hitl_step_up(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    async def scenario() -> None:
        unstepped = issuer.mint(
            subject="svc-agent",
            agent_run_id="run-sk4",
            env=Env.PROD,
            allowed_tools=("settle_merchant",),
            hitl_step_up=False,
            now=clock.now(),
        )
        stepped = issuer.mint(
            subject="svc-agent",
            agent_run_id="run-sk4",
            env=Env.PROD,
            allowed_tools=("settle_merchant",),
            hitl_step_up=True,
            now=clock.now(),
        )
        sk_filter = RedHandSemanticKernelFilter(shield)

        ctx_unstepped = MockSemanticKernelContext(
            "settle_merchant",
            {
                "amount": "20000.00",
                "currency": "USD",
                "token": unstepped,
                "agent_run_id": "run-sk4",
            },
        )
        ctx_stepped = MockSemanticKernelContext(
            "settle_merchant",
            {"amount": "20000.00", "currency": "USD", "token": stepped, "agent_run_id": "run-sk4"},
        )

        called = False

        async def next_fn(ctx: Any) -> None:
            nonlocal called
            called = True

        await sk_filter(ctx_unstepped, next_fn)
        assert called is False
        assert ctx_unstepped.terminate is True
        assert ctx_unstepped.result["rule_id"] == "CIAD-2026-0058.R3.hitl_required"

        called = False
        await sk_filter(ctx_stepped, next_fn)
        assert called is True
        assert ctx_stepped.terminate is False

    asyncio.run(scenario())


# ======================================================================================
# SUITE 3: Google Cloud Vertex AI & Google GenAI SDK (`google_genai.py`)
# ======================================================================================


def test_google_genai_happy_path_sync(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    token = issuer.mint(
        subject="svc-agent",
        agent_run_id="run-g1",
        env=Env.PROD,
        allowed_tools=("charge_card",),
        hitl_step_up=False,
        now=clock.now(),
    )
    mock = MockToolExecutor()
    adapter = GoogleGenAIAdapter(shield, mock)

    call = {
        "function_call": {
            "name": "charge_card",
            "args": {
                "amount": "100.00",
                "currency": "USD",
                "token": token,
                "target_env": "prod",
                "agent_run_id": "run-g1",
            },
            "id": "call_gemini_1",
        }
    }

    res = adapter.handle_function_call(call)
    fr = res["function_response"]
    assert fr["name"] == "charge_card"
    assert fr["id"] == "call_gemini_1"
    assert fr["response"]["result"]["status"] == "success"
    assert len(mock.calls) == 1


def test_google_genai_staging_to_prod_pivot_block(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    staging_token = issuer.mint(
        subject="svc-agent",
        agent_run_id="run-g2",
        env=Env.STAGING,
        allowed_tools=("charge_card",),
        hitl_step_up=False,
        now=clock.now(),
    )
    mock = MockToolExecutor()
    adapter = GoogleGenAIAdapter(shield, mock)

    call = {
        "name": "charge_card",
        "args": {
            "amount": "100.00",
            "currency": "USD",
            "token": staging_token,
            "target_env": "prod",
            "agent_run_id": "run-g2",
        },
    }

    res = adapter.handle_function_call(call)
    fr = res["function_response"]
    assert fr["name"] == "charge_card"
    assert fr["response"]["rule_id"] == "CIAD-2026-0058.R1.staging_to_prod_pivot"
    assert len(mock.calls) == 0
    assert shield.quarantine.is_quarantined("run-g2")


def test_google_genai_micro_probe_block(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    token = issuer.mint(
        subject="svc-agent",
        agent_run_id="run-g3",
        env=Env.PROD,
        allowed_tools=("charge_card",),
        hitl_step_up=False,
        now=clock.now(),
    )
    mock = MockToolExecutor()
    adapter = GoogleGenAIAdapter(shield, mock)

    call = {
        "name": "charge_card",
        "args": {
            "amount": "1.00",
            "currency": "USD",
            "token": token,
            "agent_run_id": "run-g3",
        },
    }

    res1 = adapter.handle_function_call(call)
    assert "result" in res1["function_response"]["response"]

    res2 = adapter.handle_function_call(call)
    assert res2["function_response"]["response"]["rule_id"] == "CIAD-2026-0058.R2.micro_tx_probe"
    assert len(mock.calls) == 1
    assert shield.quarantine.is_quarantined("run-g3")


def test_google_genai_hitl_step_up_rejected_and_allowed(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    unstepped = issuer.mint(
        subject="svc-agent",
        agent_run_id="run-g4",
        env=Env.PROD,
        allowed_tools=("settle_merchant",),
        hitl_step_up=False,
        now=clock.now(),
    )
    stepped = issuer.mint(
        subject="svc-agent",
        agent_run_id="run-g4",
        env=Env.PROD,
        allowed_tools=("settle_merchant",),
        hitl_step_up=True,
        now=clock.now(),
    )
    mock = MockToolExecutor()
    adapter = GoogleGenAIAdapter(shield, mock)

    call_unstepped = {
        "name": "settle_merchant",
        "args": {"amount": "15000.00", "currency": "USD", "token": unstepped},
    }
    call_stepped = {
        "name": "settle_merchant",
        "args": {"amount": "15000.00", "currency": "USD", "token": stepped},
    }

    res_unstepped = adapter.handle_function_call(call_unstepped)
    assert (
        res_unstepped["function_response"]["response"]["rule_id"]
        == "CIAD-2026-0058.R3.hitl_required"
    )

    res_stepped = adapter.handle_function_call(call_stepped)
    assert "result" in res_stepped["function_response"]["response"]


def test_google_genai_tool_error_audited(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    token = issuer.mint(
        subject="svc-agent",
        agent_run_id="run-g5",
        env=Env.PROD,
        allowed_tools=("charge_card",),
        hitl_step_up=False,
        now=clock.now(),
    )

    def failing_tool(**kwargs: Any) -> Any:
        raise ConnectionResetError("Payment gateway network disconnect")

    adapter = GoogleGenAIAdapter(shield, failing_tool)
    call = {
        "name": "charge_card",
        "args": {"amount": "10.00", "currency": "USD", "token": token},
    }
    res = adapter.handle_function_call(call)
    assert "Payment gateway network disconnect" in res["function_response"]["response"]["error"]


def test_google_genai_argument_sanitization(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    token = issuer.mint(
        subject="svc-agent",
        agent_run_id="run-g6",
        env=Env.PROD,
        allowed_tools=("charge_card",),
        hitl_step_up=False,
        now=clock.now(),
    )
    captured: dict[str, Any] = {}

    def handler(**kwargs: Any) -> Any:
        captured.update(kwargs)
        return "cleared"

    adapter = GoogleGenAIAdapter(shield, handler)
    call = {
        "name": "charge_card",
        "args": {
            "amount": "25.00",
            "currency": "USD",
            "token": token,
            "target_env": "prod",
            "agent_run_id": "run-g6",
        },
    }
    res = adapter.handle_function_call(call)
    assert res["function_response"]["response"]["result"] == "cleared"
    assert "token" not in captured
    assert "agent_run_id" not in captured
    assert captured["amount"] == "25.00"


def test_google_genai_observe_only_mode(
    make_shield: Callable[..., Shield],
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    shield = make_shield(mode=Mode.OBSERVE_ONLY)
    staging_token = issuer.mint(
        subject="svc-agent",
        agent_run_id="run-g7",
        env=Env.STAGING,
        allowed_tools=("charge_card",),
        hitl_step_up=False,
        now=clock.now(),
    )
    mock = MockToolExecutor()
    adapter = GoogleGenAIAdapter(shield, mock)

    call = {
        "name": "charge_card",
        "args": {"amount": "100.00", "currency": "USD", "token": staging_token},
    }
    res = adapter.handle_function_call(call)
    assert "result" in res["function_response"]["response"]
    assert len(mock.calls) == 1


def test_google_genai_async_function_call(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    async def scenario() -> None:
        token = issuer.mint(
            subject="svc-agent",
            agent_run_id="run-g8",
            env=Env.PROD,
            allowed_tools=("charge_card",),
            hitl_step_up=False,
            now=clock.now(),
        )
        mock = MockToolExecutor()
        adapter = GoogleGenAIAdapter(shield, mock)

        part = MockGooglePart(
            "charge_card",
            {"amount": "50.00", "currency": "USD", "token": token},
            call_id="call_async_gemini",
        )
        res = await adapter.ahandle_function_call(part)
        assert res["function_response"]["id"] == "call_async_gemini"
        assert res["function_response"]["response"]["result"]["status"] == "success"

    asyncio.run(scenario())


# ======================================================================================
# SUITE 4: LangChain / LangGraph BaseTool Adapter (`langchain.py`)
# ======================================================================================


def test_langchain_sync_run_happy_path(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    token = issuer.mint(
        subject="svc-agent",
        agent_run_id="run-lc1",
        env=Env.PROD,
        allowed_tools=("charge_card",),
        hitl_step_up=False,
        now=clock.now(),
    )
    mock_tool = MockLangChainTool()
    guarded = RedHandGuardedTool(mock_tool, shield)

    res = guarded._run(amount="100.00", currency="USD", token=token, target_env="prod")
    assert res["status"] == "success"
    assert len(mock_tool.calls) == 1
    assert "token" not in mock_tool.calls[0]


def test_langchain_sync_run_pivot_block(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    staging_token_strict = issuer.mint(
        subject="svc-agent",
        agent_run_id="run-lc2-strict",
        env=Env.STAGING,
        allowed_tools=("charge_card",),
        hitl_step_up=False,
        now=clock.now(),
    )
    staging_token_soft = issuer.mint(
        subject="svc-agent",
        agent_run_id="run-lc2-soft",
        env=Env.STAGING,
        allowed_tools=("charge_card",),
        hitl_step_up=False,
        now=clock.now(),
    )
    mock_tool = MockLangChainTool()

    # With raise_on_block=True
    guarded_strict = RedHandGuardedTool(mock_tool, shield, raise_on_block=True)
    with pytest.raises(TokenPivotError) as exc_info:
        guarded_strict._run(amount="100.00", currency="USD", token=staging_token_strict)
    assert "staging_to_prod_pivot" in str(exc_info.value)
    assert len(mock_tool.calls) == 0

    # With raise_on_block=False
    guarded_soft = RedHandGuardedTool(mock_tool, shield, raise_on_block=False)
    err = guarded_soft._run(amount="100.00", currency="USD", token=staging_token_soft)
    assert err["rule_id"] == "CIAD-2026-0058.R1.staging_to_prod_pivot"


def test_langchain_sync_run_micro_probe_block(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    token = issuer.mint(
        subject="svc-agent",
        agent_run_id="run-lc3",
        env=Env.PROD,
        allowed_tools=("charge_card",),
        hitl_step_up=False,
        now=clock.now(),
    )
    mock_tool = MockLangChainTool()
    guarded = RedHandGuardedTool(mock_tool, shield, raise_on_block=True)

    res1 = guarded._run(
        amount="1.00", currency="USD", token=token, agent_run_id="run-lc3", target_env="prod"
    )
    assert res1["status"] == "success"

    with pytest.raises(MicroTxProbeError):
        guarded._run(
            amount="1.00", currency="USD", token=token, agent_run_id="run-lc3", target_env="prod"
        )
    assert shield.quarantine.is_quarantined("run-lc3")


def test_langchain_sync_run_hitl_step_up_rejected_and_allowed(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    unstepped = issuer.mint(
        subject="svc-agent",
        agent_run_id="run-lc4",
        env=Env.PROD,
        allowed_tools=("settle_merchant",),
        hitl_step_up=False,
        now=clock.now(),
    )
    stepped = issuer.mint(
        subject="svc-agent",
        agent_run_id="run-lc4",
        env=Env.PROD,
        allowed_tools=("settle_merchant",),
        hitl_step_up=True,
        now=clock.now(),
    )
    mock_tool = MockLangChainTool(name="settle_merchant")
    guarded = RedHandGuardedTool(mock_tool, shield, raise_on_block=True)

    with pytest.raises(HITLRequiredError):
        guarded._run(amount="20000.00", currency="USD", token=unstepped)

    res = guarded._run(amount="20000.00", currency="USD", token=stepped)
    assert res["status"] == "success"


def test_langchain_async_arun_happy_path(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    async def scenario() -> None:
        token = issuer.mint(
            subject="svc-agent",
            agent_run_id="run-lc5",
            env=Env.PROD,
            allowed_tools=("charge_card",),
            hitl_step_up=False,
            now=clock.now(),
        )
        mock_tool = MockLangChainTool()
        guarded = RedHandGuardedTool(mock_tool, shield)

        res = await guarded._arun(amount="50.00", currency="USD", token=token)
        assert res["status"] == "success"
        assert len(mock_tool.calls) == 1

    asyncio.run(scenario())


def test_langchain_async_arun_pivot_block(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    async def scenario() -> None:
        staging_token = issuer.mint(
            subject="svc-agent",
            agent_run_id="run-lc6",
            env=Env.STAGING,
            allowed_tools=("charge_card",),
            hitl_step_up=False,
            now=clock.now(),
        )
        mock_tool = MockLangChainTool()
        guarded = RedHandGuardedTool(mock_tool, shield, raise_on_block=True)

        with pytest.raises(TokenPivotError):
            await guarded._arun(amount="100.00", currency="USD", token=staging_token)
        assert len(mock_tool.calls) == 0

    asyncio.run(scenario())


def test_langchain_async_arun_micro_probe_block(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    async def scenario() -> None:
        token = issuer.mint(
            subject="svc-agent",
            agent_run_id="run-lc7",
            env=Env.PROD,
            allowed_tools=("charge_card",),
            hitl_step_up=False,
            now=clock.now(),
        )
        mock_tool = MockLangChainTool()
        guarded = RedHandGuardedTool(mock_tool, shield, raise_on_block=True)

        await guarded._arun(amount="1.00", currency="USD", token=token, agent_run_id="run-lc7")
        with pytest.raises(MicroTxProbeError):
            await guarded._arun(amount="1.00", currency="USD", token=token, agent_run_id="run-lc7")

    asyncio.run(scenario())


def test_langchain_async_arun_hitl_step_up(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    async def scenario() -> None:
        unstepped = issuer.mint(
            subject="svc-agent",
            agent_run_id="run-lc8",
            env=Env.PROD,
            allowed_tools=("settle_merchant",),
            hitl_step_up=False,
            now=clock.now(),
        )
        stepped = issuer.mint(
            subject="svc-agent",
            agent_run_id="run-lc8",
            env=Env.PROD,
            allowed_tools=("settle_merchant",),
            hitl_step_up=True,
            now=clock.now(),
        )
        mock_tool = MockLangChainTool(name="settle_merchant")
        guarded = RedHandGuardedTool(mock_tool, shield, raise_on_block=True)

        with pytest.raises(HITLRequiredError):
            await guarded._arun(amount="20000.00", currency="USD", token=unstepped)

        res = await guarded._arun(amount="20000.00", currency="USD", token=stepped)
        assert res["status"] == "success"

    asyncio.run(scenario())


def test_langchain_tool_metadata_preserved(
    shield: Shield,
) -> None:
    mock_tool = MockLangChainTool(name="payout_processor", description="Processes payouts")
    guarded = RedHandGuardedTool(mock_tool, shield)

    assert guarded.name == "payout_processor"
    assert guarded.description == "Processes payouts"
    assert guarded.args_schema is None
    assert guarded.return_direct is True


def test_langchain_guard_decorator_factory(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    token = issuer.mint(
        subject="svc-agent",
        agent_run_id="run-lc10",
        env=Env.PROD,
        allowed_tools=("charge_card", "charge_card_kw"),
        hitl_step_up=False,
        now=clock.now(),
    )

    # Style 1: guard_langchain_tool(shield) as decorator
    @guard_langchain_tool(shield)
    def charge_card(amount: str, currency: str) -> str:
        return f"Charged {amount} {currency}"

    res = charge_card._run(amount="100.00", currency="USD", token=token)
    assert res == "Charged 100.00 USD"

    # Style 2: guard_langchain_tool(shield=shield)
    @guard_langchain_tool(shield=shield)
    def charge_card_kw(amount: str, currency: str) -> str:
        return f"Charged kw {amount} {currency}"

    res_kw = charge_card_kw(amount="200.00", currency="USD", token=token)
    assert res_kw == "Charged kw 200.00 USD"


def test_langchain_tool_exception_audited(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    token = issuer.mint(
        subject="svc-agent",
        agent_run_id="run-lc11",
        env=Env.PROD,
        allowed_tools=("charge_card",),
        hitl_step_up=False,
        now=clock.now(),
    )

    def charge_card(**kwargs: Any) -> Any:
        raise ArithmeticError("Division by zero in fee calculation")

    guarded = guard_langchain_tool(charge_card, shield)
    with pytest.raises(ArithmeticError):
        guarded._run(amount="10.00", currency="USD", token=token)


# ======================================================================================
# SUITE 5: Framework-Agnostic GenericToolRunner (`generic.py`)
# ======================================================================================


def test_generic_runner_sync_happy_path(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    token = issuer.mint(
        subject="svc-agent",
        agent_run_id="run-g1",
        env=Env.PROD,
        allowed_tools=("charge_card",),
        hitl_step_up=False,
        now=clock.now(),
    )
    runner = GenericToolRunner(shield)

    def charge(amount: str, currency: str) -> dict[str, str]:
        return {"status": "success", "amount": amount, "currency": currency}

    runner.register_tool("charge_card", charge)

    res = runner.run("charge_card", {"amount": "100.00", "currency": "USD", "token": token})
    assert res["status"] == "success"
    assert res["amount"] == "100.00"


def test_generic_runner_sync_pivot_block(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    staging_token_strict = issuer.mint(
        subject="svc-agent",
        agent_run_id="run-g2-strict",
        env=Env.STAGING,
        allowed_tools=("charge_card",),
        hitl_step_up=False,
        now=clock.now(),
    )
    staging_token_soft = issuer.mint(
        subject="svc-agent",
        agent_run_id="run-g2-soft",
        env=Env.STAGING,
        allowed_tools=("charge_card",),
        hitl_step_up=False,
        now=clock.now(),
    )
    runner_strict = GenericToolRunner(shield, raise_on_block=True)
    runner_soft = GenericToolRunner(shield, raise_on_block=False)

    def charge(amount: str, currency: str) -> str:
        return "ok"

    runner_strict.register_tool("charge_card", charge)
    runner_soft.register_tool("charge_card", charge)

    with pytest.raises(TokenPivotError):
        runner_strict.run("charge_card", {"token": staging_token_strict})

    err = runner_soft.run("charge_card", {"token": staging_token_soft})
    assert err["rule_id"] == "CIAD-2026-0058.R1.staging_to_prod_pivot"


def test_generic_runner_sync_micro_probe_block(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    token = issuer.mint(
        subject="svc-agent",
        agent_run_id="run-g3",
        env=Env.PROD,
        allowed_tools=("charge_card",),
        hitl_step_up=False,
        now=clock.now(),
    )
    runner = GenericToolRunner(shield, raise_on_block=True)
    runner.register_tool("charge_card", lambda **kwargs: "ok")

    runner.run(
        "charge_card",
        {"amount": "1.00", "currency": "USD", "token": token, "agent_run_id": "run-g3"},
    )
    with pytest.raises(MicroTxProbeError):
        runner.run(
            "charge_card",
            {"amount": "1.00", "currency": "USD", "token": token, "agent_run_id": "run-g3"},
        )
    assert shield.quarantine.is_quarantined("run-g3")


def test_generic_runner_sync_hitl_step_up(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    unstepped = issuer.mint(
        subject="svc-agent",
        agent_run_id="run-g4",
        env=Env.PROD,
        allowed_tools=("settle_merchant",),
        hitl_step_up=False,
        now=clock.now(),
    )
    stepped = issuer.mint(
        subject="svc-agent",
        agent_run_id="run-g4",
        env=Env.PROD,
        allowed_tools=("settle_merchant",),
        hitl_step_up=True,
        now=clock.now(),
    )
    runner = GenericToolRunner(shield, raise_on_block=True)
    runner.register_tool("settle_merchant", lambda **kwargs: "ok")

    with pytest.raises(HITLRequiredError):
        runner.run("settle_merchant", {"amount": "25000.00", "currency": "USD", "token": unstepped})

    res = runner.run("settle_merchant", {"amount": "25000.00", "currency": "USD", "token": stepped})
    assert res == "ok"


def test_generic_runner_async_happy_path(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    async def scenario() -> None:
        token = issuer.mint(
            subject="svc-agent",
            agent_run_id="run-g5",
            env=Env.PROD,
            allowed_tools=("charge_card",),
            hitl_step_up=False,
            now=clock.now(),
        )
        runner = GenericToolRunner(shield)

        async def async_charge(amount: str, currency: str) -> dict[str, str]:
            await asyncio.sleep(0.001)
            return {"status": "success", "amount": amount}

        runner.register_tool("charge_card", async_charge)

        res = await runner.arun(
            "charge_card", {"amount": "70.00", "currency": "USD", "token": token}
        )
        assert res["status"] == "success"
        assert res["amount"] == "70.00"

    asyncio.run(scenario())


def test_generic_runner_async_pivot_block(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    async def scenario() -> None:
        staging_token = issuer.mint(
            subject="svc-agent",
            agent_run_id="run-g6",
            env=Env.STAGING,
            allowed_tools=("charge_card",),
            hitl_step_up=False,
            now=clock.now(),
        )
        runner = GenericToolRunner(shield, raise_on_block=True)
        runner.register_tool("charge_card", lambda **kw: "ok")

        with pytest.raises(TokenPivotError):
            await runner.arun("charge_card", {"token": staging_token})

    asyncio.run(scenario())


def test_generic_runner_tool_executor_protocol_conformance(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    runner = GenericToolRunner(shield)
    assert isinstance(runner, ToolExecutor)

    token = issuer.mint(
        subject="svc-agent",
        agent_run_id="run-g7",
        env=Env.PROD,
        allowed_tools=("charge_card",),
        hitl_step_up=False,
        now=clock.now(),
    )
    runner.register_tool("charge_card", lambda card_id: f"charged:{card_id}")

    res = runner.execute(
        "charge_card", {"card_id": "c123", "amount": "50.00", "currency": "USD", "token": token}
    )
    assert res == "charged:c123"


def test_generic_runner_unregistered_tool(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    token = issuer.mint(
        subject="svc-agent",
        agent_run_id="run-g8",
        env=Env.PROD,
        allowed_tools=("unknown_tool",),
        hitl_step_up=False,
        now=clock.now(),
    )
    runner = GenericToolRunner(shield)

    with pytest.raises(KeyError) as exc_info:
        runner.run("unknown_tool", {"token": token})
    assert "not registered in GenericToolRunner" in str(exc_info.value)


def test_generic_runner_argument_sanitization(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    token = issuer.mint(
        subject="svc-agent",
        agent_run_id="run-g9",
        env=Env.PROD,
        allowed_tools=("charge_card",),
        hitl_step_up=False,
        now=clock.now(),
    )
    runner = GenericToolRunner(shield)
    received: dict[str, Any] = {}

    def tool(amount: str, currency: str) -> str:
        received["amount"] = amount
        received["currency"] = currency
        return "success"

    runner.register_tool("charge_card", tool)
    runner.run(
        "charge_card",
        {
            "amount": "99.00",
            "currency": "USD",
            "token": token,
            "target_env": "prod",
            "agent_run_id": "run-g9",
        },
    )
    assert received == {"amount": "99.00", "currency": "USD"}


# ======================================================================================
# SUITE 6: Soft Imports & Module Exports (`__init__.py`)
# ======================================================================================


def test_adapters_import_without_third_party_sdks() -> None:
    # Importing from adapters works cleanly without boto3, google.genai, azure, langchain
    from redhand_fintech_shield.adapters import (
        AzureOpenAIAdapter,
        BedrockConverseAdapter,
        GenericToolRunner,
        GoogleGenAIAdapter,
        RedHandGuardedTool,
        RedHandSemanticKernelFilter,
    )

    assert BedrockConverseAdapter is not None
    assert AzureOpenAIAdapter is not None
    assert RedHandSemanticKernelFilter is not None
    assert GoogleGenAIAdapter is not None
    assert RedHandGuardedTool is not None
    assert GenericToolRunner is not None


def test_adapters_all_exported_symbols() -> None:
    expected = [
        "AzureOpenAIAdapter",
        "BedrockConverseAdapter",
        "GenericToolRunner",
        "GoogleGenAIAdapter",
        "RedHandGuardedTool",
        "RedHandSemanticKernelFilter",
        "check_module_available",
        "extract_tool_call_context",
        "format_violation_payload",
        "guard_langchain_tool",
        "require_module",
        "sanitize_arguments",
    ]
    for symbol in expected:
        assert hasattr(adapters, symbol)


def test_top_level_package_adapters_export() -> None:
    from redhand_fintech_shield import adapters as top_adapters

    assert top_adapters is adapters


def test_soft_import_missing_sdk_error_clarity() -> None:
    with pytest.raises(ImportError) as exc_info:
        require_module("nonexistent_cloud_sdk_xyz")
    assert "The 'nonexistent_cloud_sdk_xyz' package is required" in str(exc_info.value)
    assert "pip install nonexistent_cloud_sdk_xyz" in str(exc_info.value)


def test_check_module_available() -> None:
    assert check_module_available("sys") is True
    assert check_module_available("totally_nonexistent_sdk_abc") is False


# ======================================================================================
# SUITE 7: Additional Strict Coverage Tests (Edge cases, protocols, float validation)
# ======================================================================================


def test_adapters_float_amount_strictly_rejected(
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    token = issuer.mint(
        subject="svc-agent",
        agent_run_id="run-f1",
        env=Env.PROD,
        allowed_tools=("charge_card",),
        hitl_step_up=False,
        now=clock.now(),
    )
    with pytest.raises(
        ValueError, match="monetary values must be str, int or Decimal, never float"
    ):
        extract_tool_call_context(
            "charge_card",
            {"amount": 10.5, "currency": "USD", "token": token},
        )


def test_adapters_invalid_decimal_string_rejected() -> None:
    with pytest.raises(ValueError, match="invalid decimal amount"):
        extract_tool_call_context(
            "charge_card",
            {"amount": "not_a_number", "currency": "USD", "token": "tok"},
        )


def test_format_violation_payload_fallbacks() -> None:
    payload = format_violation_payload(None, None)
    assert payload["rule_id"] == "UNKNOWN"
    assert payload["decision"] == "block"
    assert payload["finding"] is None


def test_execute_tool_none_raises() -> None:
    from redhand_fintech_shield.adapters._common import execute_tool

    ctx = ToolCallContext(
        agent_run_id="run-1",
        tool_name="tool",
        target_env=Env.PROD,
        token="tok",
    )
    with pytest.raises(ValueError, match="No executor or handler configured"):
        execute_tool(None, "tool", {}, ctx)


def test_execute_tool_unsupported_raises() -> None:
    from redhand_fintech_shield.adapters._common import execute_tool

    ctx = ToolCallContext(
        agent_run_id="run-1",
        tool_name="tool",
        target_env=Env.PROD,
        token="tok",
    )
    with pytest.raises(TypeError, match="Unsupported tool executor type"):
        execute_tool(12345, "tool", {}, ctx)  # type: ignore[arg-type]


def test_guard_langchain_tool_missing_args() -> None:
    with pytest.raises(ValueError, match="guard_langchain_tool requires both a tool and a shield"):
        guard_langchain_tool()  # type: ignore[call-overload]


def test_langchain_direct_run_and_call(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    token = issuer.mint(
        subject="svc-agent",
        agent_run_id="run-lc-call",
        env=Env.PROD,
        allowed_tools=("charge_card",),
        hitl_step_up=False,
        now=clock.now(),
    )
    mock_tool = MockLangChainTool()
    guarded = RedHandGuardedTool(mock_tool, shield)

    # test .run()
    res1 = guarded.run(amount="10.00", currency="USD", token=token)
    assert res1["status"] == "success"

    # test __call__()
    res2 = guarded(amount="20.00", currency="USD", token=token)
    assert res2["status"] == "success"


def test_langchain_direct_arun(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    async def scenario() -> None:
        token = issuer.mint(
            subject="svc-agent",
            agent_run_id="run-lc-arun",
            env=Env.PROD,
            allowed_tools=("charge_card",),
            hitl_step_up=False,
            now=clock.now(),
        )
        mock_tool = MockLangChainTool()
        guarded = RedHandGuardedTool(mock_tool, shield)

        res = await guarded.arun(amount="30.00", currency="USD", token=token)
        assert res["status"] == "success"

    asyncio.run(scenario())


def test_generic_runner_with_context_injection(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    token = issuer.mint(
        subject="svc-agent",
        agent_run_id="run-ginj",
        env=Env.PROD,
        allowed_tools=("charge_card",),
        hitl_step_up=False,
        now=clock.now(),
    )
    runner = GenericToolRunner(shield)

    captured_ctx: Any = None

    def tool_with_ctx(amount: str, ctx: ToolCallContext) -> str:
        nonlocal captured_ctx
        captured_ctx = ctx
        return f"amount:{amount}"

    runner.register_tool("charge_card", tool_with_ctx)
    res = runner.run("charge_card", {"amount": "80.00", "currency": "USD", "token": token})
    assert res == "amount:80.00"
    assert captured_ctx is not None
    assert captured_ctx.agent_run_id == "run-ginj"


# ======================================================================================
# SUITE 8: Exhaustive Branch Coverage Tests
# ======================================================================================


def test_azure_openai_async_tool_calls_and_edge_args(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    async def scenario() -> None:
        token = issuer.mint(
            subject="svc-agent",
            agent_run_id="run-az-async",
            env=Env.PROD,
            allowed_tools=("charge_card",),
            hitl_step_up=False,
            now=clock.now(),
        )
        staging_token = issuer.mint(
            subject="svc-agent",
            agent_run_id="run-az-staging",
            env=Env.STAGING,
            allowed_tools=("charge_card",),
            hitl_step_up=False,
            now=clock.now(),
        )

        mock = MockToolExecutor()
        adapter = AzureOpenAIAdapter(shield, mock)

        # 1. Success ahandle_tool_call
        call_ok = {
            "id": "c1",
            "function": {"name": "charge_card", "arguments": {"amount": "5.00", "token": token}},
        }
        res_ok = await adapter.ahandle_tool_call(call_ok)
        assert res_ok["role"] == "tool"

        # 2. Blocked ahandle_tool_call
        call_blk = {
            "id": "c2",
            "function": {"name": "charge_card", "arguments": {"token": staging_token}},
        }
        res_blk = await adapter.ahandle_tool_call(call_blk)
        assert "CIAD-2026-0058" in res_blk["content"]

        # 3. Invalid JSON in ahandle_tool_call
        call_bad = {
            "id": "c3",
            "function": {"name": "charge_card", "arguments": "{invalid json"},
        }
        res_bad = await adapter.ahandle_tool_call(call_bad)
        assert "Invalid JSON" in res_bad["content"]

        # 4. Tool exception in ahandle_tool_call
        def failing(**kw: Any) -> Any:
            raise RuntimeError("async tool failed")

        failing_adapter = AzureOpenAIAdapter(shield, failing)
        call_err = {
            "id": "c4",
            "function": {
                "name": "charge_card",
                "arguments": {"amount": "50.00", "currency": "USD", "token": token},
            },
        }
        res_err = await failing_adapter.ahandle_tool_call(call_err)
        assert "async tool failed" in res_err["content"]

        # 5. ahandle_tool_calls batch
        batch = [call_ok, call_bad]
        batch_res = await adapter.ahandle_tool_calls(batch)
        assert len(batch_res) == 2

        # 6. Non-dict JSON arguments: parsed JSON is not a dict
        call_non_dict_json = {
            "id": "c6",
            "function": {"name": "charge_card", "arguments": '"just a string"'},
        }
        res_nd = adapter.handle_tool_call(call_non_dict_json)
        assert "JSON arguments must be an object" in res_nd["content"]

        # 7. Non-str, non-dict raw arguments (e.g. integer or None)
        call_int_args = {
            "id": "c7",
            "function": {"name": "charge_card", "arguments": 12345},
        }
        res_int = adapter.handle_tool_call(call_int_args)
        assert res_int["role"] == "tool"

    asyncio.run(scenario())


def test_bedrock_converse_async_branches_and_dict_response(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    async def scenario() -> None:
        token = issuer.mint(
            subject="svc-agent",
            agent_run_id="run-bed-async",
            env=Env.PROD,
            allowed_tools=("charge_card",),
            hitl_step_up=False,
            now=clock.now(),
        )
        staging_token = issuer.mint(
            subject="svc-agent",
            agent_run_id="run-bed-stg",
            env=Env.STAGING,
            allowed_tools=("charge_card",),
            hitl_step_up=False,
            now=clock.now(),
        )

        mock = MockToolExecutor()
        adapter = BedrockConverseAdapter(shield, mock)

        # 1. ahandle_tool_use_block blocked
        blk_block = {
            "toolUse": {
                "toolUseId": "u_blk",
                "name": "charge_card",
                "input": {"token": staging_token},
            }
        }
        res_blk = await adapter.ahandle_tool_use_block(blk_block)
        assert res_blk["toolResult"]["status"] == "error"

        # 2. ahandle_tool_use_block tool exception
        def failing(**kw: Any) -> Any:
            raise ValueError("bedrock execution failed")

        failing_adapter = BedrockConverseAdapter(shield, failing)
        ok_block = {
            "toolUse": {
                "toolUseId": "u_ok",
                "name": "charge_card",
                "input": {"token": token, "amount": "50.00", "currency": "USD"},
            }
        }
        res_err = await failing_adapter.ahandle_tool_use_block(ok_block)
        assert res_err["toolResult"]["status"] == "error"
        assert "bedrock execution failed" in res_err["toolResult"]["content"][0]["json"]["error"]

        # 3. ahandle_converse_messages batch
        batch_res = await adapter.ahandle_converse_messages([ok_block, blk_block])
        assert len(batch_res) == 2

        # 4. handle_converse_messages with full Converse response dictionary
        converse_response = {
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [
                        {
                            "toolUse": {
                                "toolUseId": "u_dict_1",
                                "name": "charge_card",
                                "input": {"token": token, "amount": "10.00", "currency": "USD"},
                            }
                        }
                    ],
                }
            }
        }
        resp = adapter.handle_converse_messages(converse_response)
        assert len(resp) == 1
        assert resp[0]["toolResult"]["toolUseId"] == "u_dict_1"

    asyncio.run(scenario())


def test_google_genai_async_branches_and_batching(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    async def scenario() -> None:
        token = issuer.mint(
            subject="svc-agent",
            agent_run_id="run-g-async",
            env=Env.PROD,
            allowed_tools=("charge_card",),
            hitl_step_up=False,
            now=clock.now(),
        )
        staging_token = issuer.mint(
            subject="svc-agent",
            agent_run_id="run-g-stg",
            env=Env.STAGING,
            allowed_tools=("charge_card",),
            hitl_step_up=False,
            now=clock.now(),
        )

        mock = MockToolExecutor()
        adapter = GoogleGenAIAdapter(shield, mock)

        # 1. ahandle_function_call blocked
        fc_blk = {"name": "charge_card", "args": {"token": staging_token}}
        res_blk = await adapter.ahandle_function_call(fc_blk)
        assert "rule_id" in res_blk["function_response"]["response"]

        # 2. ahandle_function_call tool exception
        def failing(**kw: Any) -> Any:
            raise KeyError("missing account")

        failing_adapter = GoogleGenAIAdapter(shield, failing)
        fc_ok = {
            "name": "charge_card",
            "args": {"token": token, "amount": "20.00", "currency": "USD"},
        }
        res_err = await failing_adapter.ahandle_function_call(fc_ok)
        assert "Tool execution failed" in res_err["function_response"]["response"]["error"]

        # 3. handle_function_calls sync batch
        sync_batch = adapter.handle_function_calls([fc_ok, fc_blk])
        assert len(sync_batch) == 2

        # 4. ahandle_function_calls async batch
        async_batch = await adapter.ahandle_function_calls([fc_ok, fc_blk])
        assert len(async_batch) == 2

    asyncio.run(scenario())


def test_langchain_edge_branches_and_positional_args(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    async def scenario() -> None:
        token = issuer.mint(
            subject="svc-agent",
            agent_run_id="run-lc-edge",
            env=Env.PROD,
            allowed_tools=("charge_card", "settle_merchant", "failing", "simple_callable"),
            hitl_step_up=False,
            now=clock.now(),
        )
        staging_token = issuer.mint(
            subject="svc-agent",
            agent_run_id="run-lc-edge-stg",
            env=Env.STAGING,
            allowed_tools=("charge_card",),
            hitl_step_up=False,
            now=clock.now(),
        )

        mock_tool = MockLangChainTool()
        mock_tool.custom_property = "custom_val"  # type: ignore[attr-defined]
        guarded = RedHandGuardedTool(mock_tool, shield)

        # 1. __getattr__ delegation
        assert guarded.custom_property == "custom_val"

        # 2. Positional dict argument in _run
        res_dict_pos = guarded._run({"amount": "50.00", "currency": "USD", "token": token})
        assert res_dict_pos["status"] == "success"

        # 3. Positional string query argument in _run
        res_str_pos = guarded._run("search for balance", token=token)
        assert res_str_pos["status"] == "success"

        # 4. _arun with raise_on_block=False
        guarded_soft = RedHandGuardedTool(mock_tool, shield, raise_on_block=False)
        soft_err = await guarded_soft._arun(token=staging_token)
        assert soft_err["rule_id"] == "CIAD-2026-0058.R1.staging_to_prod_pivot"

        # 5. _arun when tool raises exception
        def failing(**kw: Any) -> Any:
            raise OverflowError("amount too large")

        failing_guarded = RedHandGuardedTool(failing, shield)
        with pytest.raises(OverflowError):
            await failing_guarded._arun(amount="10.00", currency="USD", token=token)

        # 6. _arun when tool has _run but not _arun
        class SyncOnlyTool:
            name = "charge_card"

            def _run(self, *args: Any, **kwargs: Any) -> str:
                return "sync_result"

        sync_guarded = RedHandGuardedTool(SyncOnlyTool(), shield)
        sync_arun_res = await sync_guarded._arun(amount="10.00", currency="USD", token=token)
        assert sync_arun_res == "sync_result"

        # 7. _arun when tool is regular callable
        def simple_callable(amount: str = "10.00", **kw: Any) -> str:
            return f"simple:{amount}"

        callable_guarded = RedHandGuardedTool(simple_callable, shield)
        res_call = await callable_guarded._arun(amount="15.00", currency="USD", token=token)
        assert res_call == "simple:15.00"

        # 8. _run and _arun when tool is neither callable nor has _run/_arun
        invalid_tool = type("InvalidTool", (), {"name": "charge_card"})()
        inv_guarded = RedHandGuardedTool(invalid_tool, shield)
        with pytest.raises(ValueError, match="is not callable"):
            inv_guarded._run(amount="10.00", currency="USD", token=token)
        with pytest.raises(ValueError, match="is not callable"):
            await inv_guarded._arun(amount="10.00", currency="USD", token=token)

    asyncio.run(scenario())


def test_generic_runner_edge_branches(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    async def scenario() -> None:
        token = issuer.mint(
            subject="svc-agent",
            agent_run_id="run-gen-edge",
            env=Env.PROD,
            allowed_tools=("charge_card", "fail_card", "unregistered_tool"),
            hitl_step_up=False,
            now=clock.now(),
        )
        staging_token = issuer.mint(
            subject="svc-agent",
            agent_run_id="run-gen-stg",
            env=Env.STAGING,
            allowed_tools=("charge_card",),
            hitl_step_up=False,
            now=clock.now(),
        )

        runner = GenericToolRunner(shield)

        def tool(amount: str, **kw: Any) -> str:
            return f"done:{amount}"

        def failing_tool(**kw: Any) -> Any:
            raise KeyError("missing account id")

        runner.register_tool("charge_card", tool)
        runner.register_tool("fail_card", failing_tool)

        # 1. run passing direct ToolCallContext in context parameter
        ctx_direct = extract_tool_call_context(
            "charge_card", {"amount": "10.00", "currency": "USD", "token": token}
        )
        res_ctx = runner.run("charge_card", {"amount": "10.00"}, context=ctx_direct)
        assert res_ctx == "done:10.00"

        # 2. arun passing direct ToolCallContext in context parameter
        res_actx = await runner.arun("charge_card", {"amount": "12.00"}, context=ctx_direct)
        assert res_actx == "done:12.00"

        # 3. Tool exception in run
        with pytest.raises(KeyError, match="missing account id"):
            runner.run("fail_card", {"token": token})

        # 4. Tool exception in arun
        with pytest.raises(KeyError, match="missing account id"):
            await runner.arun("fail_card", {"token": token})

        # 5. arun unregistered tool
        with pytest.raises(KeyError, match="not registered in GenericToolRunner"):
            await runner.arun("unregistered_tool", {"token": token})

        # 6. arun with raise_on_block=False
        soft_runner = GenericToolRunner(shield, raise_on_block=False)
        soft_err = await soft_runner.arun("charge_card", {"token": staging_token})
        assert soft_err["rule_id"] == "CIAD-2026-0058.R1.staging_to_prod_pivot"

        # 7. aexecute with context dict containing 'ctx'
        aexec_res = await runner.aexecute(
            "charge_card",
            {"amount": "50.00"},
            context={"ctx": ctx_direct},
        )
        assert aexec_res == "done:50.00"

        # 8. aexecute with generic dict context
        aexec_res2 = await runner.aexecute(
            "charge_card",
            {"amount": "60.00", "token": token, "currency": "USD"},
        )
        assert aexec_res2 == "done:60.00"

    asyncio.run(scenario())


def test_common_aexecute_unsupported_type() -> None:
    async def scenario() -> None:
        from redhand_fintech_shield.adapters._common import aexecute_tool

        ctx = ToolCallContext(
            agent_run_id="run-1",
            tool_name="charge_card",
            target_env=Env.PROD,
            token="tok",
        )
        with pytest.raises(TypeError, match="Unsupported tool executor type"):
            await aexecute_tool(12345, "charge_card", {}, ctx)  # type: ignore[arg-type]

    asyncio.run(scenario())


def test_bedrock_converse_messages_nested_content(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    token = issuer.mint(
        subject="svc-agent",
        agent_run_id="run-bed-nest",
        env=Env.PROD,
        allowed_tools=("charge_card",),
        hitl_step_up=False,
        now=clock.now(),
    )
    mock = MockToolExecutor()
    adapter = BedrockConverseAdapter(shield, mock)

    mixed_messages: list[Any] = [
        "not-a-dict-item",
        {
            "role": "assistant",
            "content": [
                {
                    "toolUse": {
                        "toolUseId": "u_nest_1",
                        "name": "charge_card",
                        "input": {"token": token, "amount": "10.00", "currency": "USD"},
                    }
                }
            ],
        },
    ]
    results = adapter.handle_converse_messages(mixed_messages)
    assert len(results) == 1
    assert results[0]["toolResult"]["toolUseId"] == "u_nest_1"


def test_generic_runner_execute_with_ctx_in_context(
    shield: Shield,
    issuer: AgentTokenIssuer,
    clock: FakeClock,
) -> None:
    token = issuer.mint(
        subject="svc-agent",
        agent_run_id="run-gen-ctx-obj",
        env=Env.PROD,
        allowed_tools=("charge_card",),
        hitl_step_up=False,
        now=clock.now(),
    )
    runner = GenericToolRunner(shield)
    runner.register_tool("charge_card", lambda amount, **kw: f"charged:{amount}")

    ctx = extract_tool_call_context(
        "charge_card", {"amount": "25.00", "currency": "USD", "token": token}
    )
    res = runner.execute("charge_card", {"amount": "25.00"}, context={"ctx": ctx})
    assert res == "charged:25.00"


def test_execute_tool_async_handler_in_sync_context() -> None:
    from redhand_fintech_shield.adapters._common import execute_tool

    async def async_handler(amount: str) -> str:
        return f"async_ran:{amount}"

    ctx = ToolCallContext(
        agent_run_id="run-1",
        tool_name="charge_card",
        target_env=Env.PROD,
        token="tok",
    )
    res = execute_tool(async_handler, "charge_card", {"amount": "50.00"}, ctx)
    assert res == "async_ran:50.00"
