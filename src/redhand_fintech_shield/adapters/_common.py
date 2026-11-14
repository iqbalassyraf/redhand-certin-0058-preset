"""Shared context extraction, argument sanitization, and soft-import utilities."""

from __future__ import annotations

import asyncio
import inspect
import os
from collections.abc import Callable
from decimal import Decimal, InvalidOperation
from typing import Any

import jwt

from ..interceptor import Evaluation
from ..models import Env, M42Finding, ToolCallContext
from ..protocols import ToolExecutor


def sanitize_arguments(arguments: dict[str, Any]) -> dict[str, Any]:
    """Strip internal security tokens and envelope metadata from arguments."""
    return {
        k: v
        for k, v in arguments.items()
        if k not in ("_meta", "token", "_token", "target_env", "agent_run_id")
    }


def extract_tool_call_context(
    tool_name: str,
    arguments: dict[str, Any],
    meta: dict[str, Any] | None = None,
    default_env: Env = Env.PROD,
) -> ToolCallContext:
    """Extract ToolCallContext from tool parameters with zero-trust fallbacks.

    Extracts token, agent_run_id, target_env, amount, and currency.
    Enforces strict monetary float validation by forwarding float values
    directly to ToolCallContext for rejection.
    """
    meta_dict: dict[str, Any] = meta if isinstance(meta, dict) else {}
    raw_arg_meta = arguments.get("_meta")
    arg_meta: dict[str, Any] = raw_arg_meta if isinstance(raw_arg_meta, dict) else {}

    # 1. Token extraction
    token_candidate = (
        meta_dict.get("token")
        or arg_meta.get("token")
        or arguments.get("token")
        or arguments.get("_token")
        or os.environ.get("REDHAND_AGENT_TOKEN", "")
    )
    token = str(token_candidate).strip() if token_candidate is not None else ""

    # 2. Agent run ID extraction
    run_id_candidate = (
        meta_dict.get("agent_run_id")
        or arg_meta.get("agent_run_id")
        or arguments.get("agent_run_id")
    )
    run_id = str(run_id_candidate).strip() if run_id_candidate is not None else ""

    # If run_id is missing, inspect unverified token payload claims as fallback
    if not run_id and token:
        try:
            unverified = jwt.decode(token, options={"verify_signature": False})
            if isinstance(unverified, dict):
                run_id = str(unverified.get("agent_run_id", "")).strip()
        except Exception:  # noqa: S110
            pass

    if not run_id:
        run_id = "anonymous"

    # 3. Target environment extraction
    env_candidate = (
        meta_dict.get("target_env")
        or arg_meta.get("target_env")
        or arguments.get("target_env")
        or default_env.value
    )
    target_env = Env(env_candidate)

    # 4. Monetary attributes extraction
    raw_amount = arguments.get("amount")
    amount: Decimal | float | None
    if raw_amount is None:
        amount = None
    elif isinstance(raw_amount, float):
        # Forward float directly so ToolCallContext validator raises strict ValueError
        amount = raw_amount
    else:
        try:
            amount = Decimal(str(raw_amount))
        except (InvalidOperation, ValueError) as exc:
            raise ValueError(f"invalid decimal amount: {raw_amount}") from exc

    raw_currency = arguments.get("currency")
    currency = str(raw_currency).upper() if raw_currency is not None else None

    # 5. Metadata extraction
    metadata: dict[str, str] = {}
    for source in (meta_dict, arg_meta):
        for k, v in source.items():
            if k not in ("token", "agent_run_id", "target_env") and isinstance(v, (str, int, bool)):
                metadata[str(k)] = str(v)

    return ToolCallContext(
        agent_run_id=run_id,
        tool_name=tool_name,
        target_env=target_env,
        token=token,
        amount=amount,  # type: ignore[arg-type]
        currency=currency,
        metadata=metadata,
    )


def format_violation_payload(
    finding: M42Finding | None,
    evaluation: Evaluation | None = None,
) -> dict[str, Any]:
    """Format an M42Finding into a standard violation payload dictionary."""
    rule_id = finding.rule_id if finding else "UNKNOWN"
    detail = finding.detail if finding else "Security policy violation"
    stage = finding.stage if finding else 0
    severity = finding.severity if finding else "critical"
    decision = (
        evaluation.decision.value
        if evaluation
        else (finding.decision.value if finding else "block")
    )

    payload: dict[str, Any] = {
        "error": f"SECURITY POLICY VIOLATION [{rule_id}]: {detail}",
        "rule_id": rule_id,
        "stage": stage,
        "severity": severity,
        "decision": decision,
        "finding": finding.model_dump(mode="json") if finding else None,
    }
    if evaluation is not None:
        payload["latency_us"] = evaluation.latency_us
    return payload


def _prepare_callable_kwargs(
    handler: Callable[..., Any],
    arguments: dict[str, Any],
    ctx: ToolCallContext,
    context: dict[str, Any],
) -> dict[str, Any]:
    """Prepare keyword arguments for invoking a handler based on its signature."""
    sig = inspect.signature(handler)
    has_varkw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values())

    kwargs: dict[str, Any] = {}
    if has_varkw:
        kwargs.update(arguments)
        if "ctx" in sig.parameters and "ctx" not in kwargs:
            kwargs["ctx"] = ctx
        if "context" in sig.parameters and "context" not in kwargs:
            kwargs["context"] = context
    else:
        for k, v in arguments.items():
            if k in sig.parameters:
                kwargs[k] = v
        if "ctx" in sig.parameters and "ctx" not in kwargs:
            kwargs["ctx"] = ctx
        if "context" in sig.parameters and "context" not in kwargs:
            kwargs["context"] = context
    return kwargs


async def _run_awaitable(awaitable: Any) -> Any:
    return await awaitable


def execute_tool(
    executor: ToolExecutor | Callable[..., Any] | dict[str, Callable[..., Any]] | None,
    tool_name: str,
    arguments: dict[str, Any],
    ctx: ToolCallContext,
) -> Any:
    """Synchronously execute a tool via ToolExecutor, dict of handlers, or single callable."""
    if executor is None:
        raise ValueError(f"No executor or handler configured for tool '{tool_name}'")

    context = {"ctx": ctx, "target_env": ctx.target_env.value}

    if isinstance(executor, ToolExecutor):
        return executor.execute(tool_name, arguments, context=context)

    if isinstance(executor, dict):
        if tool_name not in executor:
            raise KeyError(f"Tool '{tool_name}' not found in registered handlers")
        handler = executor[tool_name]
        kwargs = _prepare_callable_kwargs(handler, arguments, ctx, context)
        res = handler(**kwargs)
        if inspect.isawaitable(res):
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None
            if loop is not None and loop.is_running():
                msg = (
                    f"Tool '{tool_name}' is async; use async execution method when "
                    "event loop is running"
                )
                raise RuntimeError(msg)
            return asyncio.run(_run_awaitable(res))
        return res

    if callable(executor):
        kwargs = _prepare_callable_kwargs(executor, arguments, ctx, context)
        res = executor(**kwargs)
        if inspect.isawaitable(res):
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None
            if loop is not None and loop.is_running():
                msg = (
                    f"Tool '{tool_name}' is async; use async execution method when "
                    "event loop is running"
                )
                raise RuntimeError(msg)
            return asyncio.run(_run_awaitable(res))
        return res

    raise TypeError(f"Unsupported tool executor type: {type(executor)}")


async def aexecute_tool(
    executor: ToolExecutor | Callable[..., Any] | dict[str, Callable[..., Any]] | None,
    tool_name: str,
    arguments: dict[str, Any],
    ctx: ToolCallContext,
) -> Any:
    """Asynchronously execute a tool via ToolExecutor, dict of handlers, or single callable."""
    if executor is None:
        raise ValueError(f"No executor or handler configured for tool '{tool_name}'")

    context = {"ctx": ctx, "target_env": ctx.target_env.value}

    if isinstance(executor, ToolExecutor):
        return await executor.aexecute(tool_name, arguments, context=context)

    if isinstance(executor, dict):
        if tool_name not in executor:
            raise KeyError(f"Tool '{tool_name}' not found in registered handlers")
        handler = executor[tool_name]
        kwargs = _prepare_callable_kwargs(handler, arguments, ctx, context)
        res = handler(**kwargs)
        if inspect.isawaitable(res):
            return await res
        return res

    if callable(executor):
        kwargs = _prepare_callable_kwargs(executor, arguments, ctx, context)
        res = executor(**kwargs)
        if inspect.isawaitable(res):
            return await res
        return res

    raise TypeError(f"Unsupported tool executor type: {type(executor)}")


def check_module_available(module_name: str) -> bool:
    """Check if an optional third-party module is installed and importable."""
    import importlib.util

    return importlib.util.find_spec(module_name) is not None


def require_module(module_name: str, package_name: str | None = None) -> Any:
    """Import an optional module or raise a clear, actionable ImportError."""
    pkg = package_name or module_name
    try:
        import importlib

        return importlib.import_module(module_name)
    except ImportError as exc:
        raise ImportError(
            f"The '{pkg}' package is required to use this feature. "
            f"Please install it with 'pip install {pkg}'."
        ) from exc
