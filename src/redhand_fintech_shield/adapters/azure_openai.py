"""Microsoft Azure OpenAI and Semantic Kernel Python adapters.

Provides Azure OpenAI tool/function call interception and Semantic Kernel Python
invocation filter with zero vendor lock-in.
"""

from __future__ import annotations

import contextlib
import inspect
import json
from collections.abc import Callable, Mapping
from typing import Any

from ..interceptor import Evaluation, Shield
from ..models import Decision, Env, Mode
from ..protocols import ToolExecutor
from ._common import (
    aexecute_tool,
    execute_tool,
    extract_tool_call_context,
    format_violation_payload,
    sanitize_arguments,
)


class AzureOpenAIAdapter:
    """Microsoft Azure OpenAI tool calling adapter.

    Translates between OpenAI / Azure tool_calls dictionary representations and
    role='tool' messages, validating each call against RedHand Shield.
    """

    def __init__(
        self,
        shield: Shield,
        tool_executor: (
            ToolExecutor | Callable[..., Any] | dict[str, Callable[..., Any]] | None
        ) = None,
        *,
        default_env: Env = Env.PROD,
    ) -> None:
        self.shield = shield
        self.tool_executor = tool_executor
        self.default_env = default_env

    def _parse_tool_call(
        self, tool_call: dict[str, Any]
    ) -> tuple[str, str, dict[str, Any], str | None]:
        """Extract tool_call_id, function name, and deserialized arguments dict.

        Returns (tool_call_id, tool_name, arguments_dict, error_message).
        """
        tool_call_id = str(tool_call.get("id") or "unknown_call_id")
        func = tool_call.get("function", tool_call)
        tool_name = str(func.get("name") or "")

        raw_args = func.get("arguments", {})
        if isinstance(raw_args, str):
            try:
                parsed = json.loads(raw_args)
                if not isinstance(parsed, dict):
                    err_msg = f"JSON arguments must be an object: {raw_args}"
                    return tool_call_id, tool_name, {}, err_msg
                return tool_call_id, tool_name, parsed, None
            except Exception as exc:
                return tool_call_id, tool_name, {}, f"Invalid JSON in function arguments: {exc}"
        elif isinstance(raw_args, dict):
            return tool_call_id, tool_name, dict(raw_args), None
        return tool_call_id, tool_name, {}, None

    def _build_tool_message(
        self,
        tool_call_id: str,
        name: str,
        content: Any,
    ) -> dict[str, Any]:
        """Build a compliant Azure OpenAI tool response message."""
        content_str = (
            json.dumps(content)
            if isinstance(content, (dict, list, int, float, bool))
            else (content if isinstance(content, str) else json.dumps(str(content)))
        )
        return {
            "role": "tool",
            "tool_call_id": tool_call_id,
            "name": name,
            "content": content_str,
        }

    def _build_block_message(
        self,
        tool_call_id: str,
        name: str,
        evaluation: Evaluation,
    ) -> dict[str, Any]:
        """Build an Azure OpenAI error tool message containing M42Finding details."""
        finding = next(
            (f for f in evaluation.findings if f.decision is not Decision.ALLOW),
            evaluation.findings[0] if evaluation.findings else None,
        )
        payload = format_violation_payload(finding, evaluation)
        return self._build_tool_message(tool_call_id, name, payload)

    def handle_tool_call(self, tool_call: dict[str, Any]) -> dict[str, Any]:
        """Process a single Azure OpenAI tool call synchronously."""
        tool_call_id, tool_name, args_dict, parse_err = self._parse_tool_call(tool_call)
        if parse_err is not None:
            return self._build_tool_message(tool_call_id, tool_name, {"error": parse_err})

        ctx = extract_tool_call_context(tool_name, args_dict, default_env=self.default_env)
        evaluation = self.shield.evaluate(ctx)

        is_blocked = (
            self.shield.policy.mode is Mode.ENFORCE and evaluation.decision is not Decision.ALLOW
        )

        if is_blocked:
            self.shield._write_audit(ctx, evaluation, "blocked")
            return self._build_block_message(tool_call_id, tool_name, evaluation)

        sanitized = sanitize_arguments(args_dict)
        try:
            result = execute_tool(self.tool_executor, tool_name, sanitized, ctx)
        except Exception as exc:
            self.shield._write_audit(ctx, evaluation, "tool_error")
            return self._build_tool_message(
                tool_call_id, tool_name, {"error": f"Tool execution failed: {exc}"}
            )

        self.shield._write_audit(ctx, evaluation, "executed")
        return self._build_tool_message(tool_call_id, tool_name, result)

    async def ahandle_tool_call(self, tool_call: dict[str, Any]) -> dict[str, Any]:
        """Process a single Azure OpenAI tool call asynchronously."""
        tool_call_id, tool_name, args_dict, parse_err = self._parse_tool_call(tool_call)
        if parse_err is not None:
            return self._build_tool_message(tool_call_id, tool_name, {"error": parse_err})

        ctx = extract_tool_call_context(tool_name, args_dict, default_env=self.default_env)
        evaluation = self.shield.evaluate(ctx)

        is_blocked = (
            self.shield.policy.mode is Mode.ENFORCE and evaluation.decision is not Decision.ALLOW
        )

        if is_blocked:
            self.shield._write_audit(ctx, evaluation, "blocked")
            return self._build_block_message(tool_call_id, tool_name, evaluation)

        sanitized = sanitize_arguments(args_dict)
        try:
            result = await aexecute_tool(self.tool_executor, tool_name, sanitized, ctx)
        except Exception as exc:
            self.shield._write_audit(ctx, evaluation, "tool_error")
            return self._build_tool_message(
                tool_call_id, tool_name, {"error": f"Tool execution failed: {exc}"}
            )

        self.shield._write_audit(ctx, evaluation, "executed")
        return self._build_tool_message(tool_call_id, tool_name, result)

    def handle_tool_calls(self, tool_calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Process a batch of Azure OpenAI tool calls synchronously."""
        return [self.handle_tool_call(tc) for tc in tool_calls]

    async def ahandle_tool_calls(self, tool_calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Process a batch of Azure OpenAI tool calls asynchronously."""
        results: list[dict[str, Any]] = []
        for tc in tool_calls:
            res = await self.ahandle_tool_call(tc)
            results.append(res)
        return results


class RedHandSemanticKernelFilter:
    """Semantic Kernel Python invocation filter.

    Intercepts function invocation before next(), extracts context, validates
    against RedHand Shield, and halts agent loops on security violations.
    """

    def __init__(
        self,
        shield: Shield,
        *,
        raise_on_block: bool = False,
        default_env: Env = Env.PROD,
    ) -> None:
        self.shield = shield
        self.raise_on_block = raise_on_block
        self.default_env = default_env

    def _extract_name_and_args(self, context: Any) -> tuple[str, dict[str, Any]]:
        """Extract function name and arguments mapping from Semantic Kernel context."""
        func = getattr(context, "function", None)
        tool_name = str(
            getattr(func, "name", None) or getattr(context, "function_name", "unknown_function")
        )

        raw_args = getattr(context, "arguments", {})
        args_dict = dict(raw_args) if isinstance(raw_args, Mapping) else {}

        return tool_name, args_dict

    async def __call__(
        self,
        context: Any,
        next_filter: Callable[..., Any],
    ) -> None:
        """Filter invocation hook compatible with Semantic Kernel function invocation pipeline."""
        tool_name, args_dict = self._extract_name_and_args(context)
        ctx = extract_tool_call_context(tool_name, args_dict, default_env=self.default_env)

        evaluation = self.shield.evaluate(ctx)
        is_blocked = (
            self.shield.policy.mode is Mode.ENFORCE and evaluation.decision is not Decision.ALLOW
        )

        if is_blocked:
            self.shield._write_audit(ctx, evaluation, "blocked")
            finding = next(
                (f for f in evaluation.findings if f.decision is not Decision.ALLOW),
                evaluation.findings[0] if evaluation.findings else None,
            )
            payload = format_violation_payload(finding, evaluation)

            # Halt further loop progression and override result
            with contextlib.suppress(AttributeError):
                context.terminate = True

            with contextlib.suppress(AttributeError):
                context.result = payload

            if hasattr(context, "function_result"):
                with contextlib.suppress(AttributeError):
                    context.function_result = payload

            if self.raise_on_block:
                self.shield._raise_for(evaluation)
            return

        try:
            res = next_filter(context)
            if inspect.isawaitable(res):
                await res
        except Exception:
            self.shield._write_audit(ctx, evaluation, "tool_error")
            raise

        self.shield._write_audit(ctx, evaluation, "executed")
