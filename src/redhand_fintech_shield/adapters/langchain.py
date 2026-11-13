"""LangChain and LangGraph BaseTool adapter.

Provides RedHandGuardedTool wrapper and guard_langchain_tool decorator
with sync (_run) and async (_arun) interception and zero vendor lock-in.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import Any, TypeVar, overload

from ..interceptor import Shield
from ..models import Decision, Env, Mode
from ._common import (
    extract_tool_call_context,
    format_violation_payload,
    sanitize_arguments,
)


class RedHandGuardedTool:
    """Wrapper for LangChain / LangGraph BaseTool instances.

    Intercepts _run and _arun invocations, validates execution context against
    RedHand Shield, audits every outcome, and protects against unauthorized calls.
    """

    def __init__(
        self,
        tool: Any,
        shield: Shield,
        *,
        raise_on_block: bool = True,
        default_env: Env = Env.PROD,
    ) -> None:
        self.tool = tool
        self.shield = shield
        self.raise_on_block = raise_on_block
        self.default_env = default_env

    @property
    def name(self) -> str:
        """Preserve underlying tool name."""
        return str(getattr(self.tool, "name", getattr(self.tool, "__name__", "guarded_tool")))

    @property
    def description(self) -> str:
        """Preserve underlying tool description."""
        return str(getattr(self.tool, "description", getattr(self.tool, "__doc__", "")))

    @property
    def args_schema(self) -> Any:
        """Preserve underlying tool argument schema if present."""
        return getattr(self.tool, "args_schema", None)

    @property
    def return_direct(self) -> bool:
        """Preserve underlying tool return_direct flag."""
        return bool(getattr(self.tool, "return_direct", False))

    def __getattr__(self, item: str) -> Any:
        """Delegate attribute access to underlying tool."""
        return getattr(self.tool, item)

    def _extract_all_arguments(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        """Normalize positional and keyword arguments into a single dictionary."""
        all_args: dict[str, Any] = dict(kwargs)
        if args:
            if len(args) == 1 and isinstance(args[0], dict):
                all_args.update(args[0])
            elif len(args) == 1 and isinstance(args[0], str):
                all_args.setdefault("query", args[0])
        return all_args

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        """Synchronous tool execution hook intercepted by RedHand Shield."""
        all_args = self._extract_all_arguments(*args, **kwargs)
        ctx = extract_tool_call_context(
            tool_name=self.name, arguments=all_args, default_env=self.default_env
        )

        evaluation = self.shield.evaluate(ctx)
        is_blocked = (
            self.shield.policy.mode is Mode.ENFORCE and evaluation.decision is not Decision.ALLOW
        )

        if is_blocked:
            self.shield._write_audit(ctx, evaluation, "blocked")
            if self.raise_on_block:
                self.shield._raise_for(evaluation)
            finding = next(
                (f for f in evaluation.findings if f.decision is not Decision.ALLOW),
                evaluation.findings[0] if evaluation.findings else None,
            )
            return format_violation_payload(finding, evaluation)

        sanitized_kwargs = sanitize_arguments(kwargs)
        try:
            if hasattr(self.tool, "_run"):
                result = self.tool._run(*args, **sanitized_kwargs)
            elif callable(self.tool):
                result = self.tool(*args, **sanitized_kwargs)
            else:
                raise ValueError(f"Tool '{self.name}' has no _run method and is not callable")

            self.shield._write_audit(ctx, evaluation, "executed")
            return result
        except Exception:
            self.shield._write_audit(ctx, evaluation, "tool_error")
            raise

    async def _arun(self, *args: Any, **kwargs: Any) -> Any:
        """Asynchronous tool execution hook intercepted by RedHand Shield."""
        all_args = self._extract_all_arguments(*args, **kwargs)
        ctx = extract_tool_call_context(
            tool_name=self.name, arguments=all_args, default_env=self.default_env
        )

        evaluation = self.shield.evaluate(ctx)
        is_blocked = (
            self.shield.policy.mode is Mode.ENFORCE and evaluation.decision is not Decision.ALLOW
        )

        if is_blocked:
            self.shield._write_audit(ctx, evaluation, "blocked")
            if self.raise_on_block:
                self.shield._raise_for(evaluation)
            finding = next(
                (f for f in evaluation.findings if f.decision is not Decision.ALLOW),
                evaluation.findings[0] if evaluation.findings else None,
            )
            return format_violation_payload(finding, evaluation)

        sanitized_kwargs = sanitize_arguments(kwargs)
        try:
            if hasattr(self.tool, "_arun"):
                res = self.tool._arun(*args, **sanitized_kwargs)
                result = await res if inspect.isawaitable(res) else res
            elif hasattr(self.tool, "_run"):
                res = self.tool._run(*args, **sanitized_kwargs)
                result = await res if inspect.isawaitable(res) else res
            elif callable(self.tool):
                res = self.tool(*args, **sanitized_kwargs)
                result = await res if inspect.isawaitable(res) else res
            else:
                msg = f"Tool '{self.name}' has no _arun or _run method and is not callable"
                raise ValueError(msg)

            self.shield._write_audit(ctx, evaluation, "executed")
            return result
        except Exception:
            self.shield._write_audit(ctx, evaluation, "tool_error")
            raise

    def run(self, *args: Any, **kwargs: Any) -> Any:
        """Public run method delegating to intercepted _run."""
        return self._run(*args, **kwargs)

    async def arun(self, *args: Any, **kwargs: Any) -> Any:
        """Public arun method delegating to intercepted _arun."""
        return await self._arun(*args, **kwargs)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        """Callable invocation delegating to _run."""
        return self._run(*args, **kwargs)


F = TypeVar("F", bound=Callable[..., Any])


@overload
def guard_langchain_tool(
    tool: Shield,
    shield: None = None,
    *,
    raise_on_block: bool = True,
    default_env: Env = Env.PROD,
) -> Callable[[F], RedHandGuardedTool]: ...


@overload
def guard_langchain_tool(
    tool: None = None,
    *,
    shield: Shield,
    raise_on_block: bool = True,
    default_env: Env = Env.PROD,
) -> Callable[[F], RedHandGuardedTool]: ...


@overload
def guard_langchain_tool(
    tool: Any,
    shield: Shield,
    *,
    raise_on_block: bool = True,
    default_env: Env = Env.PROD,
) -> RedHandGuardedTool: ...


def guard_langchain_tool(
    tool: Any | None = None,
    shield: Shield | None = None,
    *,
    raise_on_block: bool = True,
    default_env: Env = Env.PROD,
) -> Any:
    """Wrap a tool with RedHandGuardedTool, usable either directly or as a decorator.

    Usage examples:
        guarded = guard_langchain_tool(tool, shield)
        @guard_langchain_tool(shield)
        def my_tool(...): ...
    """
    # If first argument is a Shield instance: @guard_langchain_tool(shield)
    if isinstance(tool, Shield) and shield is None:
        target_shield = tool

        def decorator(t: Any) -> RedHandGuardedTool:
            return RedHandGuardedTool(
                t, target_shield, raise_on_block=raise_on_block, default_env=default_env
            )

        return decorator

    # If used as @guard_langchain_tool(shield=shield)
    if tool is None and shield is not None:

        def decorator(t: Any) -> RedHandGuardedTool:
            return RedHandGuardedTool(
                t, shield, raise_on_block=raise_on_block, default_env=default_env
            )

        return decorator

    # Direct function invocation: guard_langchain_tool(tool, shield)
    if tool is not None and shield is not None:
        return RedHandGuardedTool(
            tool, shield, raise_on_block=raise_on_block, default_env=default_env
        )

    raise ValueError("guard_langchain_tool requires both a tool and a shield")
