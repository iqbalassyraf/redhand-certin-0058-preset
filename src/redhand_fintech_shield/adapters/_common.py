"""Shared context extraction, argument sanitization, and soft-import utilities."""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Callable
from typing import Any

from ..context import extract_tool_call_context as extract_tool_call_context
from ..context import sanitize_arguments as sanitize_arguments
from ..interceptor import Evaluation
from ..models import M42Finding, ToolCallContext
from ..protocols import ToolExecutor


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
        if evaluation.approval_request is not None:
            payload["approval_request"] = evaluation.approval_request.model_dump(mode="json")
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
