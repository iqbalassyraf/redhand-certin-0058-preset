"""Google Cloud Vertex AI and Google GenAI SDK adapter.

Intercepts Google GenAI / Vertex AI FunctionCall representations and emits
compliant FunctionResponse objects or dictionaries with M42Finding error payloads.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ..interceptor import Shield
from ..models import Decision, Env, Mode
from ..protocols import ToolExecutor
from ._common import (
    aexecute_tool,
    execute_tool,
    extract_tool_call_context,
    format_violation_payload,
    sanitize_arguments,
)


class GoogleGenAIAdapter:
    """Google GenAI and Vertex AI FunctionCall security adapter.

    Converts between FunctionCall and FunctionResponse structures, enforcing
    deterministic kill-chain evaluation without requiring Google SDK installations.
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

    def _parse_function_call(
        self, function_call: dict[str, Any] | Any
    ) -> tuple[str, dict[str, Any], str | None]:
        """Extract tool_name, args_dict, and optional id from FunctionCall."""
        if isinstance(function_call, dict):
            fc = function_call.get("function_call", function_call)
            tool_name = str(fc.get("name") or "")
            raw_args = fc.get("args", {})
            args_dict = dict(raw_args) if isinstance(raw_args, dict) else {}
            call_id = fc.get("id")
            return tool_name, args_dict, str(call_id) if call_id is not None else None

        # Duck-typed object (e.g. types.FunctionCall or protobuf)
        tool_name = str(getattr(function_call, "name", ""))
        raw_args = getattr(function_call, "args", {})
        args_dict = dict(raw_args) if isinstance(raw_args, dict) else {}
        call_id = getattr(function_call, "id", None)
        return tool_name, args_dict, str(call_id) if call_id is not None else None

    def _build_response(
        self,
        name: str,
        response_data: dict[str, Any],
        call_id: str | None,
    ) -> dict[str, Any]:
        """Build a compliant Google GenAI FunctionResponse dictionary."""
        fr: dict[str, Any] = {
            "name": name,
            "response": response_data,
        }
        if call_id is not None:
            fr["id"] = call_id
        return {"function_response": fr}

    def handle_function_call(self, function_call: dict[str, Any] | Any) -> dict[str, Any]:
        """Process a single Google GenAI FunctionCall synchronously."""
        tool_name, args_dict, call_id = self._parse_function_call(function_call)
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
            return self._build_response(tool_name, payload, call_id)

        sanitized = sanitize_arguments(args_dict)
        try:
            result = execute_tool(self.tool_executor, tool_name, sanitized, ctx)
        except Exception as exc:
            self.shield._write_audit(ctx, evaluation, "tool_error")
            return self._build_response(
                tool_name, {"error": f"Tool execution failed: {exc}"}, call_id
            )

        self.shield._write_audit(ctx, evaluation, "executed")
        return self._build_response(tool_name, {"result": result}, call_id)

    async def ahandle_function_call(self, function_call: dict[str, Any] | Any) -> dict[str, Any]:
        """Process a single Google GenAI FunctionCall asynchronously."""
        tool_name, args_dict, call_id = self._parse_function_call(function_call)
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
            return self._build_response(tool_name, payload, call_id)

        sanitized = sanitize_arguments(args_dict)
        try:
            result = await aexecute_tool(self.tool_executor, tool_name, sanitized, ctx)
        except Exception as exc:
            self.shield._write_audit(ctx, evaluation, "tool_error")
            return self._build_response(
                tool_name, {"error": f"Tool execution failed: {exc}"}, call_id
            )

        self.shield._write_audit(ctx, evaluation, "executed")
        return self._build_response(tool_name, {"result": result}, call_id)

    def handle_function_calls(self, function_calls: list[Any]) -> list[dict[str, Any]]:
        """Process a batch of Google GenAI FunctionCalls synchronously."""
        return [self.handle_function_call(fc) for fc in function_calls]

    async def ahandle_function_calls(self, function_calls: list[Any]) -> list[dict[str, Any]]:
        """Process a batch of Google GenAI FunctionCalls asynchronously."""
        results: list[dict[str, Any]] = []
        for fc in function_calls:
            res = await self.ahandle_function_call(fc)
            results.append(res)
        return results
