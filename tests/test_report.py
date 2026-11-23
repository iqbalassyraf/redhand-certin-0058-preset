"""Phase 4: the HTML evidence report.

Rationale: the report is what an auditor reads, so it must be true (the chain result and the counts
come from the log), safe (every string in a log can be chosen by an attacker, so nothing is
trusted as markup), and self-contained (it renders offline from a single file, and the same log
gives the same page). It is built here from the demo's own audit trail, as the roadmap requires.
"""

from __future__ import annotations

import importlib.util
import random
import re
import shutil
import sys
from html.parser import HTMLParser
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from redhand_fintech_shield import load_policy
from redhand_fintech_shield.__main__ import main
from redhand_fintech_shield.audit import HashChainedAuditLog
from redhand_fintech_shield.exceptions import AuditChainError
from redhand_fintech_shield.report import (
    CONTROL_MAP,
    MAX_TIMELINE_ROWS,
    _clip,
    _when,
    esc,
    read_logs,
    render_html,
)
from redhand_fintech_shield.rules import (
    R_APPROVAL_ACCEPTED,
    R_EXEMPTION_APPLIED,
    R_LEGACY_STEP_UP,
    R_MICRO_TX,
    R_STRUCTURING,
    RULE_CATALOG,
)

SCRIPT = Path(__file__).resolve().parent.parent / "examples" / "simulate_crafty_falcon.py"


@pytest.fixture(scope="module")
def demo_logs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    spec = importlib.util.spec_from_file_location("simulate_for_report", SCRIPT)
    assert spec is not None and spec.loader is not None
    module: ModuleType = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    root = tmp_path_factory.mktemp("demo")
    assert module.main(["--mode", "enforce", "--delay", "0", "--keep", str(root)]) == 0
    return root / "enforce"


class _Tags(HTMLParser):
    """Collects every tag and attribute so tests can look for scripts and external references."""

    def __init__(self) -> None:
        super().__init__()
        self.tags: list[str] = []
        self.attrs: list[tuple[str, str | None]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag)
        self.attrs.extend(attrs)

    handle_startendtag = handle_starttag


def parse(page: str) -> _Tags:
    parser = _Tags()
    parser.feed(page)
    return parser


def record(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "ts": "2026-11-11T05:30:00+00:00",
        "mode": "enforce",
        "context": {
            "agent_run_id": "run-1",
            "tool_name": "charge_card",
            "target_env": "prod",
            "token": "sha256:" + "0" * 64,
            "amount": "100",
            "currency": "USD",
        },
        "decision": "allow",
        "findings": [],
        "latency_us": 10,
        "tool_outcome": "executed",
    }
    body.update(overrides)
    return body


def finding(rule: str, decision: str = "block", **kw: Any) -> dict[str, Any]:
    base = {
        "finding_id": "f",
        "rule_id": rule,
        "severity": "high",
        "stage": 2,
        "decision": decision,
        "would_have_blocked": decision != "allow",
        "enforced": True,
        "agent_run_id": "run-1",
        "tool_name": "charge_card",
        "detail": "something happened",
        "observed_at": "2026-11-11T05:30:00+00:00",
    }
    base.update(kw)
    return base


def make_forged_log(
    tmp_path: Path, bodies: list[dict[str, Any]], name: str = "forged.jsonl"
) -> Path:
    """A log with a perfectly valid hash chain whose content the writer would have refused.

    Anyone who can write the file can do this, so the report must survive it.
    """
    from redhand_fintech_shield.audit import GENESIS_HASH, canonical_json, compute_record_hash

    prev, lines = GENESIS_HASH, []
    for seq, body in enumerate(bodies):
        full = {**body, "seq": seq, "prev_hash": prev}
        full["record_hash"] = compute_record_hash(full)
        prev = full["record_hash"]
        lines.append(canonical_json(full))
    path = tmp_path / name
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def make_log(tmp_path: Path, bodies: list[dict[str, Any]], name: str = "audit.jsonl") -> Path:
    path = tmp_path / name
    log = HashChainedAuditLog(path)
    for body in bodies:
        log.append(body)
    log.close()
    return path


# --------------------------------------------------------------------------------------
# From the demo's audit trail
# --------------------------------------------------------------------------------------


def test_the_report_renders_from_the_demos_audit_log(demo_logs: Path) -> None:
    page = render_html([demo_logs / "audit_trail.jsonl"])
    assert page.startswith("<!doctype html>") and page.rstrip().endswith("</html>")
    assert "chain verified" in page and "chain BROKEN" not in page
    for heading in (
        "Integrity of the log",
        "Advisory stage, control and logged evidence",
        "Timeline of blocked and held calls",
        "Approvals, exemptions and deprecated paths",
    ):
        assert f"<h2>{heading}</h2>" in page
    # what the demo's attack does shows up as evidence, by rule
    for rule in (
        "staging_to_prod_pivot",
        "micro_tx_probe",
        "velocity_burst",
        "structuring",
        "tool_not_pinned",
        "hitl_required",
        "agent_quarantined",
    ):
        assert rule in page, rule
    assert "<svg" in page and "stage 3" in page  # the timeline


def test_it_is_a_single_offline_file(demo_logs: Path) -> None:
    page = render_html([demo_logs / "audit_trail.jsonl"])
    tags = parse(page)
    assert "script" not in tags.tags and "iframe" not in tags.tags and "link" not in tags.tags
    assert not [v for k, v in tags.attrs if k in ("src", "href", "action", "data") and v]
    assert not re.search(r"https?://", page)
    assert "default-src 'none'" in page  # a CSP that forbids anything external or scripted
    assert not [v for k, v in tags.attrs if k.startswith("on")]  # no inline event handlers


def test_it_is_deterministic_and_uses_no_wall_clock(demo_logs: Path) -> None:
    log = demo_logs / "audit_trail.jsonl"
    assert render_html([log]) == render_html([log])
    assert "2026-11-11" in render_html([log])  # the period is the log's, not today's


def test_a_forged_log_is_reported_broken(demo_logs: Path) -> None:
    forged = demo_logs / "forged_audit_trail.jsonl"
    page = render_html([forged])
    assert "chain BROKEN" in page and "chain verified" not in page
    assert "Failure" in page and ".jsonl:" in page


def test_a_truncated_log_is_caught_only_by_the_anchor(demo_logs: Path, tmp_path: Path) -> None:
    lines = (demo_logs / "audit_trail.jsonl").read_text(encoding="utf-8").splitlines()
    anchor = HashChainedAuditLog.verify_chain(demo_logs / "audit_trail.jsonl").tail_hash
    cut = tmp_path / "cut.jsonl"
    cut.write_text("\n".join(lines[:-3]) + "\n", encoding="utf-8")
    assert "chain verified" in render_html([cut])  # honest: a clean prefix is a valid chain
    anchored = render_html([cut], expected_tail=anchor)
    assert "chain BROKEN" in anchored and "externally anchored" in anchored
    assert anchor in anchored


def test_the_counts_come_from_the_log(demo_logs: Path) -> None:
    data = read_logs([demo_logs / "audit_trail.jsonl"])
    assert data.records == 34 and data.decisions["block"] + data.decisions["hitl_required"] == 13
    assert R_MICRO_TX in data.rules and R_STRUCTURING in data.rules
    page = render_html([demo_logs / "audit_trail.jsonl"])
    assert re.search(r"<b>34</b>records", page) and re.search(r"<b>13</b>blocked or held", page)


def test_the_cli_writes_the_file(
    demo_logs: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "r.html"
    assert (
        main(
            [
                "report",
                str(demo_logs / "audit_trail.jsonl"),
                "--out",
                str(out),
                "--title",
                "Q4 <review>",
            ]
        )
        == 0
    )
    assert "wrote" in capsys.readouterr().out
    text = out.read_text(encoding="utf-8")
    assert "Q4 &lt;review&gt;" in text and "Q4 <review>" not in text  # the title is escaped too
    assert main(["report", str(tmp_path / "missing.jsonl"), "--out", str(out)]) == 2
    assert "cannot read audit log" in capsys.readouterr().err


# --------------------------------------------------------------------------------------
# Hostile content
# --------------------------------------------------------------------------------------

HOSTILE = [
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "'; DROP TABLE audit; --",
    "</td></tr></table><h1>owned</h1>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "&lt;already&amp;escaped&gt;",
    "‮⁦reversed⁩",
    "x" * 5000,
]


@pytest.mark.parametrize("payload", HOSTILE)
def test_nothing_from_the_log_is_ever_treated_as_markup(tmp_path: Path, payload: str) -> None:
    body = record(
        decision="block",
        tool_outcome="blocked",
        context={
            **record()["context"],
            "agent_run_id": payload,
            "tool_name": payload,
            "target_env": payload,
        },
        findings=[
            finding(R_MICRO_TX, detail=payload, tool_name=payload),
            finding(R_APPROVAL_ACCEPTED, "allow", detail=f"approved by '{payload[:50]}'"),
            finding(R_EXEMPTION_APPLIED, "allow", detail=f"exemption '{payload[:50]}' waived x"),
        ],
    )
    path = make_forged_log(tmp_path, [body])
    assert HashChainedAuditLog.verify_chain(
        path
    ).ok  # the chain is valid: only the content is hostile
    page = render_html([path])
    tags = parse(page)
    assert "script" not in tags.tags and "img" not in tags.tags
    assert not [k for k, _ in tags.attrs if k.startswith("on")]
    assert "<h1>owned</h1>" not in page and "<svg onload" not in page
    assert page.count("<h1>") == 1  # only the report's own title
    if "<" in payload:
        assert esc(payload[:20]) in page or "&lt;" in page
    assert len(page) < 200_000  # a 5,000-character value is clipped, not copied everywhere


def test_long_identifiers_are_clipped_and_short_ones_are_not() -> None:
    assert _clip("x" * 500) == "x" * 59 + "…"
    assert _clip("charge_card") == "charge_card"


def test_a_log_with_garbage_lines_still_renders(tmp_path: Path) -> None:
    path = make_log(tmp_path, [record()])
    with path.open("ab") as fh:
        fh.write(b"{not json\n\xff\xfe\n[1,2]\n")
    page = render_html([path])
    assert "chain BROKEN" in page and "Unreadable lines" in page


def test_random_corruption_never_crashes_the_report(demo_logs: Path, tmp_path: Path) -> None:
    rng = random.Random("report-fuzz")  # noqa: S311 - a reproducible test stream
    original = (demo_logs / "audit_trail.jsonl").read_bytes()
    for case in range(80):
        data = bytearray(original)
        for _ in range(rng.randrange(1, 6)):
            data[rng.randrange(len(data))] = rng.randrange(256)
        if case % 5 == 0:
            data = data[: rng.randrange(len(data))]
        path = tmp_path / f"c{case}.jsonl"
        path.write_bytes(bytes(data))
        page = render_html([path])
        assert page.startswith("<!doctype html>"), case
        assert "script" not in parse(page).tags, case


def test_an_empty_log_renders(tmp_path: Path) -> None:
    empty = tmp_path / "empty.jsonl"
    empty.write_text("", encoding="utf-8")
    page = render_html([empty])
    assert "no records" in page and "chain verified" in page
    assert "No blocked or held calls in this log." in page


# --------------------------------------------------------------------------------------
# Content rules
# --------------------------------------------------------------------------------------


def test_every_control_row_names_a_real_rule_and_the_map_covers_the_catalog() -> None:
    catalog = {r.id for r in RULE_CATALOG}
    mapped = {rule for _, _, rules in CONTROL_MAP for rule in rules}
    assert mapped <= catalog
    assert {r.id for r in RULE_CATALOG if r.decision != "allow"} <= mapped, (
        "a stopping rule has no row"
    )


def test_no_events_is_never_presented_as_compliance(tmp_path: Path) -> None:
    page = render_html([make_log(tmp_path, [record()])])
    assert page.count("no events logged") == len(CONTROL_MAP)
    assert "does not show that the control was tested" in page
    assert "not a certification or a compliance attestation" in page
    assert "tamper-<em>evident</em>, not tamper-proof" in page


def test_approvers_exemptions_and_the_legacy_claim_are_listed(tmp_path: Path) -> None:
    bodies = [
        record(
            findings=[
                finding(
                    R_APPROVAL_ACCEPTED, "allow", detail="accepted (request r approved by 'alice')"
                )
            ]
        ),
        record(
            findings=[
                finding(
                    R_APPROVAL_ACCEPTED, "allow", detail="accepted (request r approved by 'alice')"
                )
            ]
        ),
        record(
            findings=[
                finding(R_EXEMPTION_APPLIED, "allow", detail="exemption 'q4-batch' waived hitl")
            ]
        ),
        record(findings=[finding(R_LEGACY_STEP_UP, "allow", detail="legacy used")]),
    ]
    page = render_html([make_log(tmp_path, bodies)])
    assert re.search(r"<td>alice</td><td>2</td>", page)
    assert re.search(r"<td>q4-batch</td><td>1</td>", page)
    assert "deprecated run-wide step-up claim satisfied a requirement 1 time" in page


def test_observe_only_records_are_called_out(tmp_path: Path) -> None:
    body = record(
        mode="observe_only", decision="block", findings=[finding(R_MICRO_TX, enforced=False)]
    )
    page = render_html([make_log(tmp_path, [body])])
    assert "written in observe-only mode" in page and "reported, not enforced" in page


def test_the_timeline_is_capped_but_says_so(tmp_path: Path) -> None:
    bodies = [
        record(
            ts=f"2026-11-11T05:{(i // 60) % 60:02d}:{i % 60:02d}+00:00",
            decision="block",
            tool_outcome="blocked",
            findings=[finding(R_MICRO_TX)],
        )
        for i in range(MAX_TIMELINE_ROWS + 25)
    ]
    page = render_html([make_log(tmp_path, bodies)])
    assert "25 more events not shown" in page
    assert page.count("<tr>") < MAX_TIMELINE_ROWS + 60


def test_rotated_logs_are_read_in_order(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = HashChainedAuditLog(path)
    log.append(record())
    archived = log.rotate()
    log.append(record(decision="block", findings=[finding(R_MICRO_TX)]))
    log.close()
    page = render_html([archived, path])
    assert "chain verified" in page and "2 file(s)" in page


def test_the_policy_in_force_is_identified(tmp_path: Path, shield: Any) -> None:
    from decimal import Decimal

    from redhand_fintech_shield import Env, ToolCallContext

    ctx = ToolCallContext(
        agent_run_id="r",
        tool_name="charge_card",
        target_env=Env.PROD,
        token="t",
        amount=Decimal("100"),
        currency="USD",
    )
    guarded = shield.guard(lambda **kw: "ok")
    with pytest.raises(Exception):  # noqa: B017 - the token is invalid; the audit write is the point
        guarded(ctx=ctx)
    shield.close()
    log = Path(shield.policy.audit_path)
    page = render_html([log])
    assert shield.policy_fingerprint in page and "bundled preset certin_ciad_2026_0058" in page
    bare = make_log(tmp_path, [record()], "old.jsonl")
    assert "written before policy fingerprints existed" in render_html([bare])
    other = shutil.copy(log, tmp_path / "copy.jsonl")
    assert "supplied policy" in render_html([Path(other)], policy=load_policy())


def test_timestamps_are_shown_compactly_and_never_invented() -> None:
    assert _when("2026-11-11T05:30:12.021000+00:00") == "2026-11-11 05:30:12 UTC"
    assert _when("2026-11-11T05:30:12+05:30") == "2026-11-11 05:30:12 +0530"
    assert _when("2026-11-11T05:30:12") == "2026-11-11 05:30:12"
    assert _when("not a time") == "not a time" and _when(None) == "-" and _when("") == "-"


def test_an_unreadable_input_is_a_clean_error(tmp_path: Path) -> None:
    with pytest.raises(AuditChainError, match="cannot read audit log"):
        render_html([tmp_path / "nope.jsonl"])
