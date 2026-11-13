"""AWS Amazon Bedrock Converse API adapter.

Intercepts Converse API toolUse content blocks, validates against RedHand Shield,
and returns compliant toolResult blocks with status 'success' or 'error'.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ..interceptor import Evaluation, Shield
from ..models import Decision, Env, Mode
from ..protocols import ToolExecutor
from ._common import (
    aexecute_tool,
    execute_tool,
    extract_tool_call_context,
    sanitize_arguments,
)


class BedrockConverseAdapter:
    """AWS Amazon Bedrock Converse API security adapter.

    Translates between Bedrock Converse toolUse blocks and toolResult blocks,
    enforcing deterministic kill-chain evaluation without third-party SDK lock-in.
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

    def _parse_tool_use_payload(self, tool_use: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
        """Extract toolUseId, name, and input dictionary from toolUse block."""
        inner = tool_use.get("toolUse", tool_use)
        tool_use_id = str(inner.get("toolUseId") or inner.get("tool_use_id") or "unknown_tool_use")
        tool_name = str(inner.get("name") or inner.get("tool_name") or "")
        raw_input = inner.get("input")
        input_args = raw_input if isinstance(raw_input, dict) else {}
        return tool_use_id, tool_name, input_args

    def _build_block_response(
        self,
        tool_use_id: str,
        evaluation: Evaluation,
    ) -> dict[str, Any]:
        """Build a Bedrock Converse toolResult error block from evaluation findings."""
        finding = next(
            (f for f in evaluation.findings if f.decision is not Decision.ALLOW),
            evaluation.findings[0] if evaluation.findings else None,
        )
        rule_id = finding.rule_id if finding else "UNKNOWN"
        detail = finding.detail if finding else "Security policy violation"

        return {
            "toolResult": {
                "toolUseId": tool_use_id,
                "status": "error",
                "content": [
                    {
                        "json": {
                            "error": f"SECURITY POLICY VIOLATION [{rule_id}]: {detail}",
                            "rule_id": rule_id,
                            "stage": finding.stage if finding else 0,
                            "severity": finding.severity if finding else "critical",
                            "decision": evaluation.decision.value,
                            "finding": finding.model_dump(mode="json") if finding else None,
                        }
                    }
                ],
            }
        }

    def _build_success_response(
        self,
        tool_use_id: str,
        result: Any,
    ) -> dict[str, Any]:
        """Build a Bedrock Converse toolResult success block."""
        content_item: dict[str, Any]
        if isinstance(result, dict):
            content_item = {"json": result}
        else:
            content_item = {"json": {"result": result}}

        return {
            "toolResult": {
                "toolUseId": tool_use_id,
                "status": "success",
                "content": [content_item],
            }
        }

    def _build_error_response(
        self,
        tool_use_id: str,
        message: str,
    ) -> dict[str, Any]:
        """Build a Bedrock Converse toolResult error block for exceptions."""
        return {
            "toolResult": {
                "toolUseId": tool_use_id,
                "status": "error",
                "content": [{"json": {"error": message}}],
            }
        }

    def handle_tool_use_block(self, tool_use: dict[str, Any]) -> dict[str, Any]:
        """Process a single Bedrock Converse toolUse block synchronously."""
        tool_use_id, tool_name, input_args = self._parse_tool_use_payload(tool_use)
        ctx = extract_tool_call_context(tool_name, input_args, default_env=self.default_env)

        evaluation = self.shield.evaluate(ctx)
        is_blocked = (
            self.shield.policy.mode is Mode.ENFORCE and evaluation.decision is not Decision.ALLOW
        )

        if is_blocked:
            self.shield._write_audit(ctx, evaluation, "blocked")
            return self._build_block_response(tool_use_id, evaluation)

        sanitized = sanitize_arguments(input_args)
        try:
            result = execute_tool(self.tool_executor, tool_name, sanitized, ctx)
        except Exception as exc:
            self.shield._write_audit(ctx, evaluation, "tool_error")
            return self._build_error_response(tool_use_id, f"Tool execution failed: {exc}")

        self.shield._write_audit(ctx, evaluation, "executed")
        return self._build_success_response(tool_use_id, result)

    async def ahandle_tool_use_block(self, tool_use: dict[str, Any]) -> dict[str, Any]:
        """Process a single Bedrock Converse toolUse block asynchronously."""
        tool_use_id, tool_name, input_args = self._parse_tool_use_payload(tool_use)
        ctx = extract_tool_call_context(tool_name, input_args, default_env=self.default_env)

        evaluation = self.shield.evaluate(ctx)
        is_blocked = (
            self.shield.policy.mode is Mode.ENFORCE and evaluation.decision is not Decision.ALLOW
        )

        if is_blocked:
            self.shield._write_audit(ctx, evaluation, "blocked")
            return self._build_block_response(tool_use_id, evaluation)

        sanitized = sanitize_arguments(input_args)
        try:
            result = await aexecute_tool(self.tool_executor, tool_name, sanitized, ctx)
        except Exception as exc:
            self.shield._write_audit(ctx, evaluation, "tool_error")
            return self._build_error_response(tool_use_id, f"Tool execution failed: {exc}")

        self.shield._write_audit(ctx, evaluation, "executed")
        return self._build_success_response(tool_use_id, result)

    def _extract_blocks(self, messages: list[Any] | dict[str, Any]) -> list[dict[str, Any]]:
        """Normalize messages or response dictionaries into a list of toolUse blocks."""
        blocks: list[dict[str, Any]] = []
        if isinstance(messages, dict):
            # Check for Converse response format: {"output": {"message": {"content": [...]}}}
            output = messages.get("output", {})
            message = output.get("message", messages) if isinstance(output, dict) else messages
            content = message.get("content", []) if isinstance(message, dict) else []
            if isinstance(content, list):
                for item in content:
                    if isinstance(item, dict) and ("toolUse" in item or "toolUseId" in item):
                        blocks.append(item)
            return blocks

        for item in messages:
            if not isinstance(item, dict):
                continue
            if "toolUse" in item or "toolUseId" in item:
                blocks.append(item)
            elif "content" in item and isinstance(item["content"], list):
                for c in item["content"]:
                    if isinstance(c, dict) and ("toolUse" in c or "toolUseId" in c):
                        blocks.append(c)
        return blocks

    def handle_converse_messages(
        self, messages: list[Any] | dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Process a batch of Bedrock Converse messages or toolUse blocks synchronously."""
        blocks = self._extract_blocks(messages)
        return [self.handle_tool_use_block(b) for b in blocks]

    async def ahandle_converse_messages(
        self, messages: list[Any] | dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Process a batch of Bedrock Converse messages or toolUse blocks asynchronously."""
        blocks = self._extract_blocks(messages)
        results: list[dict[str, Any]] = []
        for b in blocks:
            res = await self.ahandle_tool_use_block(b)
            results.append(res)
        return results
