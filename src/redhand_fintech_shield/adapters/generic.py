"""Framework-agnostic GenericToolRunner implementing the ToolExecutor protocol.

Enables secure tool execution in custom agent loops, state machines, and lightweight
orchestrators while enforcing RedHand Shield policy evaluations and audit integrity.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ..interceptor import Shield
from ..models import Decision, Env, Mode, ToolCallContext
from ..protocols import ToolExecutor
from ._common import (
    aexecute_tool,
    execute_tool,
    extract_tool_call_context,
    format_violation_payload,
    sanitize_arguments,
)


class GenericToolRunner(ToolExecutor):
    """Framework-agnostic tool runner implementing the ToolExecutor protocol.

    Provides synchronous and asynchronous tool execution, parameter sanitization,
    context injection, and deterministic kill-chain evaluation with zero vendor lock-in.
    """

    def __init__(
        self,
        shield: Shield,
        tools: dict[str, Callable[..., Any]] | None = None,
        *,
        raise_on_block: bool = True,
        default_env: Env = Env.PROD,
    ) -> None:
        self.shield = shield
        self.tools: dict[str, Callable[..., Any]] = dict(tools) if tools is not None else {}
        self.raise_on_block = raise_on_block
        self.default_env = default_env

    def register_tool(self, name: str, handler: Callable[..., Any]) -> None:
        """Register a named tool callable handler."""
        self.tools[name] = handler

    def run(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        context: ToolCallContext | dict[str, Any] | None = None,
    ) -> Any:
        """Synchronously execute a registered tool under RedHand Shield governance."""
        if isinstance(context, ToolCallContext):
            ctx = context
        else:
            meta = context if isinstance(context, dict) else None
            ctx = extract_tool_call_context(
                tool_name, arguments, meta=meta, default_env=self.default_env
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

        if tool_name not in self.tools:
            raise KeyError(f"Tool '{tool_name}' not registered in GenericToolRunner")

        sanitized = sanitize_arguments(arguments)
        handler = self.tools[tool_name]
        try:
            result = execute_tool(handler, tool_name, sanitized, ctx)
            self.shield._write_audit(ctx, evaluation, "executed")
            return result
        except Exception:
            self.shield._write_audit(ctx, evaluation, "tool_error")
            raise

    async def arun(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        context: ToolCallContext | dict[str, Any] | None = None,
    ) -> Any:
        """Asynchronously execute a registered tool under RedHand Shield governance."""
        if isinstance(context, ToolCallContext):
            ctx = context
        else:
            meta = context if isinstance(context, dict) else None
            ctx = extract_tool_call_context(
                tool_name, arguments, meta=meta, default_env=self.default_env
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

        if tool_name not in self.tools:
            raise KeyError(f"Tool '{tool_name}' not registered in GenericToolRunner")

        sanitized = sanitize_arguments(arguments)
        handler = self.tools[tool_name]
        try:
            result = await aexecute_tool(handler, tool_name, sanitized, ctx)
            self.shield._write_audit(ctx, evaluation, "executed")
            return result
        except Exception:
            self.shield._write_audit(ctx, evaluation, "tool_error")
            raise

    def execute(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> Any:
        """Conform to the synchronous ToolExecutor protocol."""
        ctx_obj: ToolCallContext | None = None
        if context and "ctx" in context and isinstance(context["ctx"], ToolCallContext):
            ctx_obj = context["ctx"]
        return self.run(tool_name, arguments, context=ctx_obj or context)

    async def aexecute(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> Any:
        """Conform to the asynchronous ToolExecutor protocol."""
        ctx_obj: ToolCallContext | None = None
        if context and "ctx" in context and isinstance(context["ctx"], ToolCallContext):
            ctx_obj = context["ctx"]
        return await self.arun(tool_name, arguments, context=ctx_obj or context)
