"""Phase 3 Milestone 2 tests: per-tool argument bindings.

Rationale: the money rules are only as good as the amount, currency and beneficiary they are
shown. These tests prove that a tool using other field names, or paying a list of beneficiaries,
is judged the same way as a tool using the conventional names, and that every ambiguous or
incomplete binding fails closed instead of being guessed at.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from decimal import Decimal
from typing import Any

import pytest
from pydantic import ValidationError

from redhand_fintech_shield import (
    AgentTokenIssuer,
    Decision,
    Env,
    HITLRequiredError,
    PolicyConfig,
    Shield,
    ToolCallContext,
)
from redhand_fintech_shield.adapters.generic import GenericToolRunner
from redhand_fintech_shield.bindings import resolve_money_fields, resolve_path
from redhand_fintech_shield.context import extract_tool_call_context
from redhand_fintech_shield.detectors import R_HITL, R_NEW_BENEFICIARY
from redhand_fintech_shield.gateway import MCPGateway
from redhand_fintech_shield.models import ToolBinding, ToolBindingsPolicy
from tests.conftest import PRESET, FakeClock

BINDINGS = ToolBindingsPolicy(
    tools={
        "pay_vendor": ToolBinding(amount="value", currency="ccy", beneficiary="payee.vpa"),
        "upi_send": ToolBinding(amount="amt", fixed_currency="INR", beneficiary="vpa"),
        "bulk_payout": ToolBinding(
            amount="payments[*].amount",
            currency="payments[*].currency",
            beneficiary="payments[*].payee",
            max_items=5,
        ),
    }
)


def _ctx(tool: str, args: dict[str, Any], bindings: ToolBindingsPolicy | None = BINDINGS) -> Any:
    return extract_tool_call_context(tool, {"token": "t", **args}, bindings=bindings)


# --------------------------------------------------------------------------------------
# Path resolver
# --------------------------------------------------------------------------------------


def test_resolve_path_plain_nested_index_and_wildcard() -> None:
    doc = {"a": {"b": "x"}, "items": [{"v": 1}, {"v": 2}, {"v": 3}]}
    assert resolve_path(doc, "a.b", 10) == (["x"], True)
    assert resolve_path(doc, "items[1].v", 10) == ([2], True)
    assert resolve_path(doc, "items[*].v", 10) == ([1, 2, 3], True)


@pytest.mark.parametrize(
    "path",
    ["nope", "a.nope", "items[9].v", "a[*]", "items[*].missing", "a.b.c"],
)
def test_resolve_path_marks_missing_or_wrong_shape_incomplete(path: str) -> None:
    doc = {"a": {"b": "x"}, "items": [{"v": 1}, {"v": 2}]}
    values, complete = resolve_path(doc, path, 10)
    assert complete is False
    assert len(values) <= 1


def test_resolve_path_partial_list_and_null_are_incomplete() -> None:
    values, complete = resolve_path({"p": [{"v": 1}, {}]}, "p[*].v", 10)
    assert (values, complete) == ([1], False)
    values, complete = resolve_path({"v": None}, "v", 10)
    assert (values, complete) == ([], False)


def test_resolve_path_caps_list_size() -> None:
    with pytest.raises(ValueError, match="more than 3"):
        resolve_path({"p": [{"v": i} for i in range(4)]}, "p[*].v", 3)
    # Nested wildcards that multiply past the cap are caught too.
    nested = {"o": [{"i": [1, 2, 3]}, {"i": [1, 2, 3]}]}
    with pytest.raises(ValueError, match="expands to more than 4"):
        resolve_path(nested, "o[*].i[*]", 4)


# --------------------------------------------------------------------------------------
# Policy models
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    ["$.amount", "a..b", "a[", "a[-1]", "a[*", "1abc", "a.b[x]", "", "a b", "a" * 300],
)
def test_binding_rejects_malformed_paths(path: str) -> None:
    with pytest.raises(ValidationError):
        ToolBinding(amount=path)


def test_binding_rejects_both_currency_sources_and_unknown_keys() -> None:
    with pytest.raises(ValidationError, match="either currency or fixed_currency"):
        ToolBinding(amount="a", currency="c", fixed_currency="USD")
    with pytest.raises(ValidationError):
        ToolBinding(amount="a", surprise="x")  # type: ignore[call-arg]


def test_require_for_protected_refuses_policy_with_unbound_protected_tool() -> None:
    base = PolicyConfig.from_yaml(PRESET)
    strict = ToolBindingsPolicy(
        require_for_protected=True,
        tools={"settle_merchant": ToolBinding(amount="amount")},
    )
    with pytest.raises(ValidationError, match="bulk_payout, initiate_disbursement"):
        PolicyConfig.model_validate({**base.model_dump(), "tool_bindings": strict.model_dump()})


def test_shipped_preset_binds_every_protected_tool() -> None:
    policy = PolicyConfig.from_yaml(PRESET)
    assert policy.tool_bindings.require_for_protected is True
    assert policy.protected_tools <= set(policy.tool_bindings.tools)


# --------------------------------------------------------------------------------------
# Extraction
# --------------------------------------------------------------------------------------


def test_bound_tool_with_other_field_names_is_resolved() -> None:
    ctx = _ctx("pay_vendor", {"value": "2500.50", "ccy": "usd", "payee": {"vpa": "a@bank"}})
    assert (ctx.amount, ctx.currency, ctx.beneficiary) == (Decimal("2500.50"), "USD", "a@bank")
    assert ctx.beneficiaries == ("a@bank",)
    assert "binding_note" not in ctx.metadata


def test_decoy_conventional_fields_are_ignored_on_a_bound_tool() -> None:
    ctx = _ctx(
        "pay_vendor",
        {"value": "90000", "ccy": "USD", "payee": {"vpa": "x"}, "amount": "1", "beneficiary": "k"},
    )
    assert ctx.amount == Decimal("90000")
    assert ctx.beneficiary == "x"


def test_fixed_currency_for_tools_without_a_currency_argument() -> None:
    ctx = _ctx("upi_send", {"amt": "100", "vpa": "a@upi"})
    assert ctx.currency == "INR"


def test_bulk_call_sums_amounts_and_collects_distinct_payees() -> None:
    ctx = _ctx(
        "bulk_payout",
        {
            "payments": [
                {"amount": "4000", "currency": "usd", "payee": "p1"},
                {"amount": "4000.50", "currency": "USD", "payee": "p2"},
                {"amount": "1", "currency": "USD", "payee": "p1"},
            ]
        },
    )
    assert ctx.amount == Decimal("8001.50")
    assert ctx.currency == "USD"
    assert ctx.beneficiaries == ("p1", "p2")
    assert ctx.beneficiary == "p1"


def test_bulk_negative_element_is_rejected_not_netted() -> None:
    args = {
        "payments": [
            {"amount": "1000000", "currency": "USD", "payee": "p1"},
            {"amount": "-999999", "currency": "USD", "payee": "p2"},
        ]
    }
    with pytest.raises(ValueError, match="negative amount"):
        _ctx("bulk_payout", args)


def test_bulk_mixed_currency_is_unknown_and_noted() -> None:
    ctx = _ctx(
        "bulk_payout",
        {
            "payments": [
                {"amount": "10", "currency": "USD", "payee": "p1"},
                {"amount": "10", "currency": "INR", "payee": "p2"},
            ]
        },
    )
    assert ctx.amount == Decimal("20")
    assert ctx.currency is None
    assert "currency path" in ctx.metadata["binding_note"]


@pytest.mark.parametrize(
    "args",
    [
        {},  # nothing at all
        {"payments": []},  # empty list
        {"payments": [{"amount": "5", "currency": "USD", "payee": "p1"}, {"currency": "USD"}]},
        {"payments": [{"amount": None, "currency": "USD", "payee": "p1"}]},
    ],
)
def test_missing_or_incomplete_amount_is_unresolved(args: dict[str, Any]) -> None:
    ctx = _ctx("bulk_payout", args)
    assert ctx.amount is None
    assert "amount path" in ctx.metadata["binding_note"]


def test_incomplete_beneficiary_list_is_unresolved() -> None:
    ctx = _ctx(
        "bulk_payout",
        {
            "payments": [
                {"amount": "5", "currency": "USD", "payee": "p1"},
                {"amount": "5", "currency": "USD", "payee": "  "},
            ]
        },
    )
    assert ctx.beneficiary is None
    assert ctx.beneficiaries == ()
    assert "beneficiary path" in ctx.metadata["binding_note"]


def test_bulk_list_over_max_items_is_rejected() -> None:
    payments = [{"amount": "1", "currency": "USD", "payee": f"p{i}"} for i in range(6)]
    with pytest.raises(ValueError, match="more than 5"):
        _ctx("bulk_payout", {"payments": payments})


@pytest.mark.parametrize(
    ("value", "error"),
    [
        (True, ValueError),
        ({"x": 1}, ValueError),
        ("abc", ValueError),
        ("NaN", ValueError),
        ("sNaN", ValueError),
        ("Infinity", ValueError),
        ("1E+9999999999", ValueError),  # out of Decimal range once summed
        (12.5, ValidationError),  # floats are forwarded and refused by ToolCallContext
    ],
)
def test_hostile_amount_values_fail_closed(value: Any, error: type[Exception]) -> None:
    with pytest.raises(error):
        _ctx("pay_vendor", {"value": value, "ccy": "USD", "payee": {"vpa": "a"}})


def test_unbound_tool_uses_conventional_names_when_fallback_is_on() -> None:
    ctx = _ctx("charge_card", {"amount": "7", "currency": "USD", "beneficiary": " b "})
    assert (ctx.amount, ctx.currency, ctx.beneficiary) == (Decimal("7"), "USD", "b")


def test_unbound_tool_resolves_nothing_when_fallback_is_off() -> None:
    strict = ToolBindingsPolicy(tools=BINDINGS.tools, legacy_fallback=False)
    ctx = _ctx("charge_card", {"amount": "7", "currency": "USD"}, strict)
    assert ctx.amount is None
    assert "legacy_fallback is off" in ctx.metadata["binding_note"]


def test_no_bindings_object_behaves_like_before() -> None:
    ctx = _ctx("pay_vendor", {"amount": "7", "currency": "USD"}, None)
    assert ctx.amount == Decimal("7")
    fields = resolve_money_fields("pay_vendor", {"amount": "7"}, {}, {}, None)
    assert fields.amount == Decimal("7")


# --------------------------------------------------------------------------------------
# End to end: decisions
# --------------------------------------------------------------------------------------


@pytest.fixture
def bound_shield(make_shield: Callable[..., Shield]) -> Shield:
    base = PolicyConfig.from_yaml(PRESET)
    hitl = base.hitl.model_copy(
        update={"protected_tools": base.hitl.protected_tools | {"pay_vendor", "bulk_payout"}}
    )
    return make_shield(hitl=hitl, tool_bindings=BINDINGS)


def _token(issuer: AgentTokenIssuer, clock: FakeClock, run: str = "run-b") -> str:
    return issuer.mint(
        subject="svc",
        agent_run_id=run,
        env=Env.PROD,
        allowed_tools=("pay_vendor", "bulk_payout", "settle_merchant", "upi_send"),
        now=clock.now(),
    )


def _evaluate(shield: Shield, tool: str, args: dict[str, Any], token: str) -> Any:
    ctx = extract_tool_call_context(
        tool,
        {"token": token, "agent_run_id": "run-b", **args},
        bindings=shield.policy.tool_bindings,
    )
    return shield.evaluate(ctx)


def test_renamed_fields_no_longer_bypass_the_high_value_gate(
    bound_shield: Shield, issuer: AgentTokenIssuer, clock: FakeClock
) -> None:
    tok = _token(issuer, clock)
    ev = _evaluate(
        bound_shield,
        "pay_vendor",
        {"value": "15000", "ccy": "USD", "payee": {"vpa": "unknown"}},
        tok,
    )
    assert ev.decision is Decision.HITL_REQUIRED
    assert R_HITL in {f.rule_id for f in ev.findings}


def test_bulk_total_over_threshold_needs_step_up_even_if_each_item_is_small(
    bound_shield: Shield, issuer: AgentTokenIssuer, clock: FakeClock
) -> None:
    tok = _token(issuer, clock)
    payments = [{"amount": "2500", "currency": "USD", "payee": "p1"} for _ in range(5)]
    ev = _evaluate(bound_shield, "bulk_payout", {"payments": payments}, tok)
    assert ev.decision is Decision.HITL_REQUIRED
    assert any("12500" in f.detail for f in ev.findings if f.rule_id == R_HITL)


def test_one_unknown_payee_in_a_bulk_call_is_flagged(
    make_shield: Callable[..., Shield], issuer: AgentTokenIssuer, clock: FakeClock
) -> None:
    base = PolicyConfig.from_yaml(PRESET)
    nb = base.new_beneficiary.model_copy(
        update={"known_beneficiaries": frozenset({"p1", "p2"}), "action": "block"}
    )
    shield = make_shield(tool_bindings=BINDINGS, new_beneficiary=nb)
    tok = _token(issuer, clock)
    payments = [
        {"amount": "600", "currency": "USD", "payee": "p1"},
        {"amount": "600", "currency": "USD", "payee": "p2"},
        {"amount": "600", "currency": "USD", "payee": "mule-9"},
    ]
    ev = _evaluate(shield, "bulk_payout", {"payments": payments}, tok)
    nb_findings = [f for f in ev.findings if f.rule_id == R_NEW_BENEFICIARY]
    assert nb_findings and "'mule-9'" in nb_findings[0].detail
    assert ev.decision is Decision.BLOCK


def test_all_known_payees_pass_the_beneficiary_gate(
    make_shield: Callable[..., Shield], issuer: AgentTokenIssuer, clock: FakeClock
) -> None:
    base = PolicyConfig.from_yaml(PRESET)
    nb = base.new_beneficiary.model_copy(update={"known_beneficiaries": frozenset({"p1", "p2"})})
    shield = make_shield(tool_bindings=BINDINGS, new_beneficiary=nb)
    tok = _token(issuer, clock)
    payments = [
        {"amount": "600", "currency": "USD", "payee": "p1"},
        {"amount": "600", "currency": "USD", "payee": "p2"},
    ]
    ev = _evaluate(shield, "bulk_payout", {"payments": payments}, tok)
    assert R_NEW_BENEFICIARY not in {f.rule_id for f in ev.findings}


def test_several_unknown_payees_are_summarised(
    make_shield: Callable[..., Shield], issuer: AgentTokenIssuer, clock: FakeClock
) -> None:
    shield = make_shield(tool_bindings=BINDINGS)
    tok = _token(issuer, clock)
    payments = [{"amount": "600", "currency": "USD", "payee": f"new-{i}"} for i in range(3)]
    ev = _evaluate(shield, "bulk_payout", {"payments": payments}, tok)
    detail = next(f.detail for f in ev.findings if f.rule_id == R_NEW_BENEFICIARY)
    assert "(+2 more new)" in detail


def test_unresolved_bulk_amount_on_protected_tool_fails_closed(
    bound_shield: Shield, issuer: AgentTokenIssuer, clock: FakeClock
) -> None:
    tok = _token(issuer, clock)
    ev = _evaluate(bound_shield, "bulk_payout", {"payments": [{"payee": "p1"}]}, tok)
    assert ev.decision is Decision.HITL_REQUIRED
    assert any("without an amount" in f.detail for f in ev.findings)


def test_detector_accepts_beneficiaries_without_primary(
    make_shield: Callable[..., Shield], issuer: AgentTokenIssuer, clock: FakeClock
) -> None:
    shield = make_shield()
    ctx = ToolCallContext(
        agent_run_id="run-b",
        tool_name="settle_merchant",
        target_env=Env.PROD,
        token=_token(issuer, clock),
        amount=Decimal("2000"),
        currency="USD",
        beneficiaries=("only-in-list",),
    )
    assert any(f.rule_id == R_NEW_BENEFICIARY for f in shield.evaluate(ctx).findings)


# --------------------------------------------------------------------------------------
# Every entry point passes the policy's bindings
# --------------------------------------------------------------------------------------


def test_generic_runner_uses_policy_bindings(
    bound_shield: Shield, issuer: AgentTokenIssuer, clock: FakeClock
) -> None:
    runner = GenericToolRunner(bound_shield, raise_on_block=True)
    runner.register_tool("pay_vendor", lambda **kw: "ok")
    with pytest.raises(HITLRequiredError):
        runner.run(
            "pay_vendor",
            {
                "value": "15000",
                "ccy": "USD",
                "payee": {"vpa": "a@b"},
                "token": _token(issuer, clock),
                "agent_run_id": "run-b",
            },
        )


def test_gateway_uses_policy_bindings(
    make_shield: Callable[..., Shield], issuer: AgentTokenIssuer, clock: FakeClock
) -> None:
    base = PolicyConfig.from_yaml(PRESET)
    nb = base.new_beneficiary.model_copy(update={"action": "block"})
    hitl = base.hitl.model_copy(
        update={"protected_tools": base.hitl.protected_tools | {"upi_send"}}
    )
    shield = make_shield(tool_bindings=BINDINGS, new_beneficiary=nb, hitl=hitl)

    class Executor:
        def execute(self, tool_name: str, arguments: dict[str, Any], context: Any = None) -> Any:
            return "ok"

        async def aexecute(
            self, tool_name: str, arguments: dict[str, Any], context: Any = None
        ) -> Any:
            return "ok"

    gateway = MCPGateway(shield=shield, executor=Executor(), default_env=Env.PROD)
    # INR 5,000 to an unknown VPA through a tool that calls its fields amt / vpa and has no
    # currency argument: invisible before bindings, a block now.
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "upi_send",
            "arguments": {"amt": "95000", "vpa": "stranger@upi"},
            "_meta": {
                "token": _token(issuer, clock),
                "agent_run_id": "run-b",
                "target_env": "prod",
            },
        },
    }
    response = asyncio.run(gateway.handle_message(request))
    assert response is not None
    assert response["result"]["isError"] is True
    assert R_NEW_BENEFICIARY in str(response["result"])
