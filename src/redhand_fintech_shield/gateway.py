"""Out-of-process Model Context Protocol (MCP) security gateway.

Provides JSON-RPC 2.0 message dispatching, dual stream and stdio transports,
context and Ed25519 token extraction, deterministic Shield evaluation,
and tamper-evident audit logging for fintech tool execution.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import os
import re
import sys
from collections.abc import Callable, Sequence
from decimal import Decimal, InvalidOperation
from typing import Any, Literal

import jwt
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .exceptions import ShieldError
from .interceptor import Shield
from .models import Decision, Env, Mode, ToolCallContext
from .protocols import ToolExecutor

# JSON-RPC 2.0 standard error codes
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

# RedHand Shield policy error code
POLICY_VIOLATION = -32000

# Supported MCP protocol versions
SUPPORTED_PROTOCOL_VERSIONS = (
    "2024-11-05",
    "2025-03-26",
    "2025-06-18",
    "2025-11-25",
    "2026-07-28",
)
DEFAULT_PROTOCOL_VERSION = "2024-11-05"


class ToolDefinition(BaseModel):
    """MCP tool definition schema for tool discovery."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    description: str = ""
    inputSchema: dict[str, Any] = Field(
        default_factory=lambda: {"type": "object", "properties": {}}
    )


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
    """Extract ToolCallContext from MCP tools/call parameters.

    Extracts token, agent_run_id, target_env, amount, and currency with
    strict zero-trust fallbacks.
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


class MCPGateway:
    """Out-of-process Model Context Protocol security gateway.

    Intercepts JSON-RPC tool calls, extracts security credentials, evaluates
    policies against RedHand Shield, enforces isolation, and logs to
    hash-chained audit trails.
    """

    def __init__(
        self,
        shield: Shield,
        executor: ToolExecutor | dict[str, Callable[..., Any]] | None = None,
        tools: Sequence[ToolDefinition] | None = None,
        *,
        default_env: Env = Env.PROD,
        server_name: str = "redhand-fintech-shield-gateway",
        server_version: str = "0.1.0",
        error_mode: Literal["mcp", "jsonrpc"] = "mcp",
    ) -> None:
        self.shield = shield
        self.executor = executor
        self.tools: list[ToolDefinition] = list(tools) if tools is not None else []
        self.default_env = default_env
        self.server_name = server_name
        self.server_version = server_version
        self.error_mode = error_mode
        self._initialized = False
        self._tool_handlers: dict[str, Callable[..., Any]] = {}

    def register_tool(
        self,
        tool: ToolDefinition | str,
        handler: Callable[..., Any] | None = None,
        *,
        description: str = "",
        input_schema: dict[str, Any] | None = None,
    ) -> None:
        """Register a tool definition and its execution handler."""
        if isinstance(tool, str):
            tool_def = ToolDefinition(
                name=tool,
                description=description,
                inputSchema=input_schema or {"type": "object", "properties": {}},
            )
        else:
            tool_def = tool

        self.tools = [t for t in self.tools if t.name != tool_def.name] + [tool_def]
        if handler is not None:
            self._tool_handlers[tool_def.name] = handler

    def _format_error(
        self, req_id: Any, code: int, message: str, data: Any = None
    ) -> dict[str, Any]:
        err: dict[str, Any] = {"code": code, "message": message}
        if data is not None:
            err["data"] = data
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": err,
        }

    async def _execute_tool(
        self, tool_name: str, arguments: dict[str, Any], ctx: ToolCallContext
    ) -> Any:
        """Execute downstream tool via ToolExecutor or registered callable handler."""
        context = {"ctx": ctx, "target_env": ctx.target_env.value}

        # 1. ToolExecutor protocol implementation
        if self.executor is not None and isinstance(self.executor, ToolExecutor):
            return await self.executor.aexecute(tool_name, arguments, context=context)

        # 2. Dictionary of tool callables
        if isinstance(self.executor, dict) and tool_name in self.executor:
            handler = self.executor[tool_name]
            return await self._invoke_callable(handler, arguments, context)

        # 3. Tool handlers registered via register_tool
        if tool_name in self._tool_handlers:
            handler = self._tool_handlers[tool_name]
            return await self._invoke_callable(handler, arguments, context)

        raise ValueError(f"Tool '{tool_name}' not found")

    async def _invoke_callable(
        self,
        handler: Callable[..., Any],
        arguments: dict[str, Any],
        context: dict[str, Any],
    ) -> Any:
        sig = inspect.signature(handler)
        has_varkw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values())

        if has_varkw:
            kwargs = dict(arguments)
            if "context" in sig.parameters:
                kwargs["context"] = context
        else:
            kwargs = {k: v for k, v in arguments.items() if k in sig.parameters}
            if "context" in sig.parameters:
                kwargs["context"] = context

        if inspect.iscoroutinefunction(handler):
            return await handler(**kwargs)
        return handler(**kwargs)

    async def _handle_tools_call(self, params: dict[str, Any], req_id: Any) -> dict[str, Any]:
        """Intercept, evaluate via Shield, and dispatch tools/call request."""
        tool_name = params.get("name")
        if not tool_name or not isinstance(tool_name, str):
            return self._format_error(
                req_id, INVALID_PARAMS, "Missing or invalid 'name' parameter in tools/call"
            )

        raw_arguments = params.get("arguments")
        if raw_arguments is None:
            arguments: dict[str, Any] = {}
        elif not isinstance(raw_arguments, dict):
            return self._format_error(
                req_id, INVALID_PARAMS, "'arguments' parameter must be a JSON object"
            )
        else:
            arguments = raw_arguments

        raw_meta = params.get("_meta")
        if raw_meta is not None and not isinstance(raw_meta, dict):
            return self._format_error(
                req_id, INVALID_PARAMS, "'_meta' parameter must be a JSON object"
            )

        try:
            ctx = extract_tool_call_context(
                tool_name=tool_name,
                arguments=arguments,
                meta=raw_meta,
                default_env=self.default_env,
            )
        except (ValueError, ValidationError) as exc:
            return self._format_error(
                req_id, INVALID_PARAMS, f"Failed to extract tool call context: {exc}"
            )

        # Evaluate against RedHand Shield
        evaluation = self.shield.evaluate(ctx)

        # Enforce policy block
        is_blocked = (
            self.shield.policy.mode is Mode.ENFORCE and evaluation.decision is not Decision.ALLOW
        )

        if is_blocked:
            # Crucial: write blocked audit event and return error WITHOUT invoking raw tool
            self.shield._write_audit(ctx, evaluation, "blocked")

            finding = next(
                (f for f in evaluation.findings if f.decision is not Decision.ALLOW),
                evaluation.findings[0] if evaluation.findings else None,
            )
            rule_id = finding.rule_id if finding else "UNKNOWN"
            detail = finding.detail if finding else "Security policy violation"

            if self.error_mode == "jsonrpc":
                return self._format_error(
                    req_id,
                    POLICY_VIOLATION,
                    f"SECURITY POLICY VIOLATION [{rule_id}]: {detail}",
                    data={
                        "rule_id": rule_id,
                        "stage": finding.stage if finding else 0,
                        "severity": finding.severity if finding else "critical",
                        "decision": evaluation.decision.value,
                        "findings": [f.model_dump(mode="json") for f in evaluation.findings],
                        "finding": finding.model_dump(mode="json") if finding else None,
                        "latency_us": evaluation.latency_us,
                    },
                )

            # Standard MCP error response with M4.2 finding metadata
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": f"SECURITY POLICY VIOLATION [{rule_id}]: {detail}",
                        }
                    ],
                    "isError": True,
                    "_meta": {
                        "rule_id": rule_id,
                        "stage": finding.stage if finding else 0,
                        "severity": finding.severity if finding else "critical",
                        "decision": evaluation.decision.value,
                        "findings": [f.model_dump(mode="json") for f in evaluation.findings],
                        "finding": finding.model_dump(mode="json") if finding else None,
                        "latency_us": evaluation.latency_us,
                    },
                },
            }

        # Tool execution is allowed!
        sanitized_args = sanitize_arguments(arguments)

        try:
            res = await self._execute_tool(tool_name, sanitized_args, ctx)
        except Exception as exc:
            self.shield._write_audit(ctx, evaluation, "tool_error")
            if self.error_mode == "jsonrpc":
                return self._format_error(
                    req_id,
                    INTERNAL_ERROR,
                    f"Tool execution failed: {exc}",
                )
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": f"Tool execution failed: {exc}"}],
                    "isError": True,
                    "_meta": {
                        "latency_us": evaluation.latency_us,
                    },
                },
            }

        # Write executed audit record
        self.shield._write_audit(ctx, evaluation, "executed")

        # Format CallToolResult
        content: list[dict[str, Any]]
        if isinstance(res, dict) and "content" in res and isinstance(res["content"], list):
            content = res["content"]
        elif isinstance(res, str):
            content = [{"type": "text", "text": res}]
        else:
            content = [{"type": "text", "text": json.dumps(res, default=str)}]

        result_payload: dict[str, Any] = {
            "content": content,
            "isError": False,
            "_meta": {
                "latency_us": evaluation.latency_us,
                "decision": evaluation.decision.value,
            },
        }
        if evaluation.findings:
            result_payload["_meta"]["findings"] = [
                f.model_dump(mode="json") for f in evaluation.findings
            ]

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": result_payload,
        }

    async def dispatch_request(
        self, method: str, params: dict[str, Any], req_id: Any
    ) -> dict[str, Any] | None:
        """Route and execute a JSON-RPC request method."""
        if method == "initialize":
            client_version = params.get("protocolVersion")
            proto_version = (
                client_version
                if client_version in SUPPORTED_PROTOCOL_VERSIONS
                else DEFAULT_PROTOCOL_VERSION
            )
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": proto_version,
                    "capabilities": {
                        "tools": {
                            "listChanged": False,
                        }
                    },
                    "serverInfo": {
                        "name": self.server_name,
                        "version": self.server_version,
                    },
                },
            }

        if method == "notifications/initialized":
            self._initialized = True
            return None

        if method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}

        if method == "notifications/cancelled":
            return None

        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": [t.model_dump(mode="json") for t in self.tools],
                    "nextCursor": None,
                },
            }

        if method == "tools/call":
            return await self._handle_tools_call(params, req_id)

        return self._format_error(req_id, METHOD_NOT_FOUND, f"Method '{method}' not found")

    async def handle_message(self, message: str | dict[str, Any]) -> dict[str, Any] | None:
        """Parse and process a single JSON-RPC message.

        Returns response dictionary or None for notifications.
        """
        if isinstance(message, str):
            try:
                payload = json.loads(message)
            except Exception as exc:
                return self._format_error(None, PARSE_ERROR, f"Parse error: {exc}")
        else:
            payload = message

        if not isinstance(payload, dict):
            return self._format_error(None, INVALID_REQUEST, "JSON-RPC payload must be an object")

        if payload.get("jsonrpc") != "2.0":
            return self._format_error(
                payload.get("id"),
                INVALID_REQUEST,
                "Invalid or missing jsonrpc version, expected '2.0'",
            )

        method = payload.get("method")
        if not method or not isinstance(method, str):
            return self._format_error(
                payload.get("id"), INVALID_REQUEST, "Missing or invalid 'method' in request"
            )

        params = payload.get("params", {})
        if not isinstance(params, dict):
            return self._format_error(
                payload.get("id"), INVALID_PARAMS, "'params' must be an object if provided"
            )

        is_notification = "id" not in payload
        req_id = payload.get("id")

        try:
            response = await self.dispatch_request(method, params, req_id)
            if is_notification:
                return None
            return response
        except ShieldError as exc:
            if is_notification:
                return None
            return self._format_error(req_id, POLICY_VIOLATION, f"Shield error: {exc}")
        except Exception as exc:
            if is_notification:
                return None
            return self._format_error(req_id, INTERNAL_ERROR, f"Internal error: {exc}")

    @staticmethod
    async def _read_message(reader: asyncio.StreamReader) -> str | None:
        """Read a message from stream, supporting both NDJSON and LSP Content-Length framing."""
        while True:
            line = await reader.readline()
            if not line:
                return None
            line_str = line.decode("utf-8")
            stripped = line_str.strip()
            if not stripped:
                continue

            match = re.match(r"^Content-Length:\s*(\d+)", stripped, re.IGNORECASE)
            if match:
                length = int(match.group(1))
                while True:
                    hdr = await reader.readline()
                    if not hdr or hdr.strip() == b"":
                        break
                body = await reader.readexactly(length)
                return body.decode("utf-8")

            return stripped

    async def serve_streams(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Serve JSON-RPC requests over an async stream reader/writer until EOF."""
        while True:
            try:
                msg_str = await self._read_message(reader)
            except asyncio.IncompleteReadError:
                break
            except Exception as exc:
                err = self._format_error(None, PARSE_ERROR, f"Stream read error: {exc}")
                try:
                    writer.write((json.dumps(err) + "\n").encode("utf-8"))
                    await writer.drain()
                except Exception:
                    break
                continue

            if msg_str is None:
                break

            resp = await self.handle_message(msg_str)
            if resp is not None:
                try:
                    writer.write((json.dumps(resp, ensure_ascii=False) + "\n").encode("utf-8"))
                    await writer.drain()
                except Exception:
                    break

    async def serve_stdio(
        self,
        reader: asyncio.StreamReader | None = None,
        writer: asyncio.StreamWriter | None = None,
    ) -> None:
        """Serve JSON-RPC requests over stdin / stdout until EOF."""
        if reader is not None and writer is not None:
            await self.serve_streams(reader, writer)
            return

        if sys.platform == "win32" or not hasattr(sys.stdin, "fileno"):
            await self._serve_stdio_fallback()
            return

        loop = asyncio.get_running_loop()
        try:
            r = asyncio.StreamReader()
            protocol = asyncio.StreamReaderProtocol(r)
            await loop.connect_read_pipe(lambda: protocol, sys.stdin)
            w_transport, w_protocol = await loop.connect_write_pipe(
                asyncio.streams.FlowControlMixin, sys.stdout
            )
            w = asyncio.StreamWriter(w_transport, w_protocol, r, loop)
            await self.serve_streams(r, w)
        except (OSError, ValueError, AttributeError, NotImplementedError):
            # Fallback for regular files, Windows, or non-pipe descriptor inputs
            await self._serve_stdio_fallback()

    async def _serve_stdio_fallback(self) -> None:
        """Fallback synchronous reader loop for non-pipe stdio redirection."""
        loop = asyncio.get_running_loop()
        while True:
            line = await loop.run_in_executor(None, sys.stdin.readline)
            if not line:
                break
            line_str = line.strip()
            if not line_str:
                continue

            resp = await self.handle_message(line_str)
            if resp is not None:
                sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
                sys.stdout.flush()


__all__ = [
    "DEFAULT_PROTOCOL_VERSION",
    "INTERNAL_ERROR",
    "INVALID_PARAMS",
    "INVALID_REQUEST",
    "METHOD_NOT_FOUND",
    "PARSE_ERROR",
    "POLICY_VIOLATION",
    "SUPPORTED_PROTOCOL_VERSIONS",
    "MCPGateway",
    "ToolDefinition",
    "extract_tool_call_context",
    "sanitize_arguments",
]
