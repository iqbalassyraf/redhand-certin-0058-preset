"""Build a :class:`ToolCallContext` from raw tool-call parameters.

One implementation shared by the MCP gateway and every framework adapter, so a tool is judged the
same way wherever it is called from.
"""

from __future__ import annotations

import os
from typing import Any

import jwt

from .bindings import resolve_money_fields
from .models import Env, ToolBindingsPolicy, ToolCallContext


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
    bindings: ToolBindingsPolicy | None = None,
) -> ToolCallContext:
    """Extract a ``ToolCallContext`` from tool parameters with zero-trust fallbacks.

    ``bindings`` (normally ``shield.policy.tool_bindings``) says where each tool keeps its amount,
    currency and beneficiary. Without it the conventional argument names are used. Float amounts
    are forwarded unchanged so ``ToolCallContext`` rejects them.
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

    # 4. Monetary attributes (bound per tool, or by conventional name)
    money = resolve_money_fields(tool_name, arguments, meta_dict, arg_meta, bindings)

    # 5. Metadata extraction
    metadata: dict[str, str] = {}
    for source in (meta_dict, arg_meta):
        for k, v in source.items():
            if k not in ("token", "agent_run_id", "target_env") and isinstance(v, (str, int, bool)):
                metadata[str(k)] = str(v)
    if money.notes:
        metadata["binding_note"] = "; ".join(money.notes)

    return ToolCallContext(
        agent_run_id=run_id,
        tool_name=tool_name,
        target_env=target_env,
        token=token,
        amount=money.amount,  # type: ignore[arg-type]
        currency=money.currency,
        beneficiary=money.beneficiary,
        beneficiaries=money.beneficiaries,
        metadata=metadata,
    )
