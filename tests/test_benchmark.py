"""Smoke test for benchmarks/bench_latency.py."""

from __future__ import annotations

import json
import math
import subprocess
import sys
from pathlib import Path

EXPECTED_BENCHMARKS = {
    "decision_core",
    "decision_core_protected",
    "decision_core_layered",
    "in_process_guarded",
    "raw_async_noop",
    "mcp_gateway_loopback",
    "adapter_bedrock",
    "adapter_azure_openai",
    "adapter_google_genai",
    "adapter_langchain_sync",
    "adapter_langchain_async",
}

METRIC_KEYS = (
    "min_ms",
    "max_ms",
    "mean_ms",
    "stddev_ms",
    "p50_ms",
    "p90_ms",
    "p95_ms",
    "p99_ms",
    "min_us",
    "max_us",
    "mean_us",
    "stddev_us",
    "p50_us",
    "p90_us",
    "p95_us",
    "p99_us",
)


def test_latency_benchmark_smoke(tmp_path: Path) -> None:
    """Run a 10-iteration smoke benchmark and verify JSON schema and finite metrics."""
    repo_root = Path(__file__).resolve().parents[1]
    script_path = repo_root / "benchmarks" / "bench_latency.py"
    out_json = tmp_path / "bench_smoke.json"

    proc = subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(script_path),
            "--iterations",
            "10",
            "--warmup",
            "2",
            "--json",
            str(out_json),
            "--no-check-sla",
        ],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )
    assert "RedHand Latency Benchmark" in proc.stdout
    assert out_json.exists()

    payload = json.loads(out_json.read_text(encoding="utf-8"))
    assert payload["metadata"]["iterations"] == 10
    assert payload["metadata"]["warmup"] == 2
    assert isinstance(payload["metadata"]["python_version"], str)

    sla = payload["sla"]
    assert sla["in_process_budget_ms"] == 2.0
    assert sla["gateway_sla_ms"] == 5.0
    assert isinstance(sla["in_process_pass"], bool)
    assert isinstance(sla["gateway_pass"], bool)

    rows = {row["name"]: row for row in payload["benchmarks"]}
    assert set(rows.keys()) == EXPECTED_BENCHMARKS

    for name, row in rows.items():
        assert row["iterations"] == 10, name
        assert row["warmup"] == 2, name
        for key in METRIC_KEYS:
            val = float(row[key])
            assert math.isfinite(val), f"{name}.{key} not finite: {val}"
            assert val >= 0.0, f"{name}.{key} negative: {val}"
        assert row["mean_ms"] > 0.0, name
        assert row["p50_ms"] > 0.0, name
        assert (
            row["min_ms"]
            <= row["p50_ms"]
            <= row["p90_ms"]
            <= row["p95_ms"]
            <= row["p99_ms"]
            <= row["max_ms"]
        ), name
