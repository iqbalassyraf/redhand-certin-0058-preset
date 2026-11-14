"""Platform and framework adapters for RedHand FinTech Shield.

Provides zero vendor lock-in adapters for AWS Bedrock, Microsoft Azure OpenAI,
Semantic Kernel Python, Google GenAI / Vertex AI, LangChain / LangGraph, and
framework-agnostic custom agent loops.
"""

from __future__ import annotations

from ._common import (
    check_module_available,
    extract_tool_call_context,
    format_violation_payload,
    require_module,
    sanitize_arguments,
)
from .azure_openai import AzureOpenAIAdapter, RedHandSemanticKernelFilter
from .bedrock import BedrockConverseAdapter
from .generic import GenericToolRunner
from .google_genai import GoogleGenAIAdapter
from .langchain import RedHandGuardedTool, guard_langchain_tool

__all__ = [
    "AzureOpenAIAdapter",
    "BedrockConverseAdapter",
    "GenericToolRunner",
    "GoogleGenAIAdapter",
    "RedHandGuardedTool",
    "RedHandSemanticKernelFilter",
    "check_module_available",
    "extract_tool_call_context",
    "format_violation_payload",
    "guard_langchain_tool",
    "require_module",
    "sanitize_arguments",
]
