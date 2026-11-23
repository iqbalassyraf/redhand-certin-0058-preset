#!/usr/bin/env python3
"""Compute every number the release announcement quotes, and render the announcement from them.

Two classes of number, kept apart on purpose:

* **Exact** numbers are pure functions of the repository (replay corpus results, rule count,
  fingerprint, versions, public API size). They are recomputed on demand, and a test fails if the
  committed announcement differs.
* **Measured** numbers depend on the machine (latency, coverage, test count). ``--measure`` runs the
  commands, and writes ``docs/release_measurements.json`` with the machine and the commands used.
  They are quoted as measurements, never as guarantees, and a test only checks that they were
  recorded for the current package version.

``python scripts/release_numbers.py``            print the exact numbers (table)
``python scripts/release_numbers.py --json``     the same as JSON
``python scripts/release_numbers.py --measure``  re-measure latency, coverage, tests (slow, ~2 min)
``python scripts/release_numbers.py --render``   write docs/announcement.md
``python scripts/release_numbers.py --render --check``  fail if docs/announcement.md is stale
"""

from __future__ import annotations

import argparse
import json
import platform
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
TEMPLATE = DOCS / "announcement.template.md"
ANNOUNCEMENT = DOCS / "announcement.md"
MEASUREMENTS = DOCS / "release_measurements.json"
BENCH_ITERATIONS = 1000
BENCH_WARMUP = 100
BENCH_CMD = f"python benchmarks/bench_latency.py --iterations {BENCH_ITERATIONS} --json bench.json"
TEST_CMD = "pytest -q"

# Benchmarks quoted in the announcement, by the name used in bench_latency.py's JSON.
QUOTED_BENCHES = {
    "decision_core": "core",
    "in_process_guarded": "guarded",
    "mcp_gateway_loopback": "gateway",
}


def exact() -> dict[str, str]:
    import redhand_fintech_shield as pkg
    from redhand_fintech_shield.manifest import get_manifest
    from redhand_fintech_shield.replay import load_corpus, run_corpus

    corpus = load_corpus()
    policy = pkg.load_policy(corpus.policy_path)
    report = run_corpus(corpus, policy, pkg.__version__)
    manifest = get_manifest()
    pct = f"{report.detection_rate * 100:.1f}"
    return {
        "package_version": pkg.__version__,
        "preset_version": manifest.preset_version,
        "preset_fingerprint": manifest.policy_sha256[:16],
        "corpus_policy_fingerprint": report.policy_sha256[:16],
        "corpus_version": report.corpus_version,
        "corpus_sha": report.corpus_sha256[:16],
        "scenarios": str(report.scenarios),
        "attacks": str(report.attacks_detectable),
        "attacks_stopped": str(report.attacks_stopped),
        "detection_pct": pct,
        "benign": str(report.benign_checked),
        "benign_flagged": str(report.benign_flagged),
        "gaps": str(len(report.known_gaps)),
        "false_positives": str(len(report.documented_false_positives)),
        "rules": str(len(manifest.rules)),
        "public_api_names": str(len(pkg.__all__)),
    }


def _run(cmd: list[str], **kw: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, check=False, **kw)  # type: ignore[call-overload, no-any-return]  # noqa: S603


def measure() -> dict[str, object]:
    out: dict[str, object] = {}
    with tempfile.TemporaryDirectory() as tmp:
        bench_json = Path(tmp) / "bench.json"
        run = _run(
            [
                sys.executable,
                "benchmarks/bench_latency.py",
                "--iterations",
                str(BENCH_ITERATIONS),
                "--warmup",
                str(BENCH_WARMUP),
                "--json",
                str(bench_json),
            ]
        )
        if not bench_json.exists():
            raise SystemExit(f"benchmark failed:\n{run.stdout[-2000:]}\n{run.stderr[-2000:]}")
        doc = json.loads(bench_json.read_text("utf-8"))
    by_name = {b["name"]: b for b in doc["benchmarks"]}
    for name, key in QUOTED_BENCHES.items():
        b = by_name[name]
        out[f"{key}_p50_ms"] = f"{b['p50_ms']:.2f}"
        out[f"{key}_p95_ms"] = f"{b['p95_ms']:.2f}"
        out[f"{key}_p99_ms"] = f"{b['p99_ms']:.2f}"
    out["bench_iterations"] = str(doc["metadata"]["iterations"])
    test = _run([sys.executable, "-m", "pytest", "-q"])
    tail = test.stdout
    passed = re.search(r"(\d+) passed", tail)
    cov = re.search(r"Total coverage: ([\d.]+)%", tail)
    if test.returncode != 0 or not passed or not cov:
        raise SystemExit(f"test run failed:\n{tail[-2000:]}")
    out["tests_passed"] = passed[1]
    out["coverage_pct"] = cov[1]
    import redhand_fintech_shield as pkg

    out["recorded_for_version"] = pkg.__version__
    out["python"] = platform.python_version()
    out["platform"] = f"{platform.system()} {platform.machine()}"
    out["bench_command"] = BENCH_CMD
    out["test_command"] = TEST_CMD
    return out


def load_measurements() -> dict[str, str]:
    data = json.loads(MEASUREMENTS.read_text("utf-8"))
    return {k: str(v) for k, v in data.items()}


PLACEHOLDER = re.compile(r"\{\{([a-z0-9_]+)\}\}")


def render(values: dict[str, str] | None = None) -> str:
    vals = values if values is not None else {**exact(), **load_measurements()}
    template = TEMPLATE.read_text("utf-8")
    missing = sorted({k for k in PLACEHOLDER.findall(template) if k not in vals})
    if missing:
        raise SystemExit(f"announcement template uses unknown numbers: {', '.join(missing)}")
    body = PLACEHOLDER.sub(lambda m: vals[m[1]], template)
    return (
        "<!-- Generated by scripts/release_numbers.py --render from "
        "docs/announcement.template.md; do not edit by hand. -->\n\n" + body
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--json", action="store_true", help="print the exact numbers as JSON")
    ap.add_argument("--measure", action="store_true", help="re-measure and write the JSON file")
    ap.add_argument("--render", action="store_true", help="write docs/announcement.md")
    ap.add_argument("--check", action="store_true", help="with --render: fail if stale")
    args = ap.parse_args(argv)

    if args.measure:
        data = measure()
        MEASUREMENTS.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", "utf-8")
        print(f"wrote {MEASUREMENTS.relative_to(ROOT)}")
        return 0
    if args.render:
        text = render()
        if args.check:
            current = ANNOUNCEMENT.read_text("utf-8") if ANNOUNCEMENT.exists() else ""
            if current != text:
                print(
                    "docs/announcement.md is stale; run: python scripts/release_numbers.py --render"
                )
                return 1
            print("docs/announcement.md is up to date")
            return 0
        ANNOUNCEMENT.write_text(text, "utf-8", newline="\n")
        print(f"wrote {ANNOUNCEMENT.relative_to(ROOT)}")
        return 0
    numbers = exact()
    if args.json:
        print(json.dumps(numbers, indent=2, sort_keys=True))
    else:
        for key, value in numbers.items():
            print(f"{key:20} {value}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
