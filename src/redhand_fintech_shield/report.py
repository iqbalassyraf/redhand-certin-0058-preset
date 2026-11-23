"""A self-contained HTML evidence report built from an audit log.

``redhand-shield report audit_trail.jsonl --out report.html`` verifies the log's hash chain, maps
each advisory stage to the control that addresses it and to the evidence the log holds for it, and
draws a timeline of what was blocked. The page is a single file: inline CSS and SVG, no scripts,
no external requests, and a CSP that forbids both, so it renders offline and can be archived.

Everything read from the log is treated as hostile (tool names, details and run ids can be chosen
by an attacker) and HTML-escaped. The report is deterministic: it carries no wall-clock time, only
the period the log covers, so the same log gives the same page.

It summarises what the shield logged. It is not a compliance attestation: "no events" means
nothing triggered in the period, not that the control was tested or the system is compliant.
"""

# ruff: noqa: E501 - HTML and SVG template strings are clearer unwrapped

from __future__ import annotations

import hashlib
import html
import json
import re
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from .audit import ChainVerificationReport, HashChainedAuditLog
from .exceptions import AuditChainError, PolicyLoadError
from .models import PolicyConfig
from .rules import (
    R_APPROVAL_ACCEPTED,
    R_APPROVAL_REJECTED,
    R_CUMULATIVE_CAP,
    R_ENV_PIVOT,
    R_EXEMPTION_APPLIED,
    R_HITL,
    R_LEGACY_STEP_UP,
    R_MICRO_TX,
    R_NEW_BENEFICIARY,
    R_OFF_HOURS,
    R_OFF_HOURS_HITL,
    R_QUARANTINED,
    R_SEQUENCE,
    R_STRUCTURING,
    R_TOKEN_INVALID,
    R_TOOL_NOT_PINNED,
    R_VELOCITY,
    RULE_CATALOG,
)

MAX_TIMELINE_ROWS = 500
MAX_MARKERS = 2000
_APPROVER = re.compile(r"approved by '([^']{1,120})'")
_EXEMPTION = re.compile(r"exemption '([^']{1,120})'")

# (advisory stage or clause, what the preset does about it, rules that carry the evidence)
CONTROL_MAP: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    (
        "CIAD-2026-0058 Stage 1: credential pivot",
        "Tokens are bound to one environment and verified before any decision.",
        (R_ENV_PIVOT, R_TOKEN_INVALID),
    ),
    (
        "CIAD-2026-0058 Stage 2: micro-transaction probing",
        "A second micro-payment inside the window trips a circuit breaker.",
        (R_MICRO_TX,),
    ),
    (
        "CIAD-2026-0049 §3: machine-speed enumeration",
        "Call velocity is limited per tool and per run across all tools.",
        (R_VELOCITY,),
    ),
    (
        "CIAD-2026-0058 Stage 2: split transactions and slow drain",
        "Payments are added up per run, subject and payee, with a rolling cap.",
        (R_STRUCTURING, R_CUMULATIVE_CAP),
    ),
    (
        "CIAD-2026-0058 Stage 2: reconnaissance then payment",
        "Recon calls followed by a payment inside a window are blocked.",
        (R_SEQUENCE,),
    ),
    (
        "CIAD-2026-0058 Stage 3: tool scope expansion",
        "A run may call only the tools its signed token pins.",
        (R_TOOL_NOT_PINNED,),
    ),
    (
        "CIAD-2026-0058 Stage 3: high-value disbursement",
        "High-value and new-payee payments need human step-up.",
        (R_HITL, R_NEW_BENEFICIARY, R_APPROVAL_ACCEPTED, R_APPROVAL_REJECTED),
    ),
    (
        "CIAD-2026-0058 Stage 4: low-monitoring windows",
        "Limits tighten and step-up is mandatory off-hours.",
        (R_OFF_HOURS_HITL, R_OFF_HOURS),
    ),
    (
        "CIAD-2026-0049 containment",
        "A run (or its subject) that trips a blocking rule is quarantined.",
        (R_QUARANTINED,),
    ),
    (
        "Waivers and deprecated paths",
        "Exemptions and the run-wide step-up claim are named and logged on every use.",
        (R_EXEMPTION_APPLIED, R_LEGACY_STEP_UP),
    ),
)

_STAGE_SHAPE = {0: "x", 1: "circle", 2: "square", 3: "triangle", 4: "diamond"}


def esc(value: Any) -> str:
    """HTML-escape anything that came from a log."""
    return html.escape(str(value), quote=True)


def _short(rule_id: str) -> str:
    return rule_id.rsplit(".", 1)[-1]


def _clip(text: str, limit: int = 60) -> str:
    """Shorten an attacker-controlled identifier so one value cannot widen the page."""
    return text if len(text) <= limit else text[: limit - 1] + "\u2026"


def _rule_cell(rule_id: str) -> str:
    """A rule name that may wrap at its underscores, never mid-word."""
    return "<code>" + esc(_short(rule_id)).replace("_", "_<wbr>") + "</code>"


@dataclass
class RuleEvidence:
    findings: int = 0  # findings of this rule that were not "allow"
    informational: int = 0  # allow-decision findings (accepted approvals, exemptions, ...)
    calls: set[int] = field(default_factory=set)
    first: str | None = None
    last: str | None = None
    seqs: list[int] = field(default_factory=list)


@dataclass(frozen=True)
class Event:
    seq: int
    ts: str
    run: str
    tool: str
    env: str
    money: str
    decision: str
    outcome: str
    rules: tuple[str, ...]
    stage: int
    detail: str
    enforced: bool


@dataclass
class LogData:
    files: list[tuple[str, str, int]] = field(default_factory=list)  # name, sha256, size
    records: int = 0
    unreadable: int = 0
    decisions: Counter[str] = field(default_factory=Counter)
    outcomes: Counter[str] = field(default_factory=Counter)
    modes: Counter[str] = field(default_factory=Counter)
    runs: set[str] = field(default_factory=set)
    tools: Counter[str] = field(default_factory=Counter)
    fingerprints: Counter[str] = field(default_factory=Counter)
    unstamped: int = 0
    rules: dict[str, RuleEvidence] = field(default_factory=dict)
    events: list[Event] = field(default_factory=list)
    approvers: Counter[str] = field(default_factory=Counter)
    exemptions: Counter[str] = field(default_factory=Counter)
    first_ts: str | None = None
    last_ts: str | None = None


def _money(ctx: dict[str, Any]) -> str:
    amount, currency = ctx.get("amount"), ctx.get("currency")
    return "" if amount is None else f"{amount} {currency or '?'}"


def read_logs(paths: Sequence[Path]) -> LogData:
    """Extract what the report needs. Chain verification is separate; this never raises on bad lines."""
    data = LogData()
    for path in paths:
        try:
            blob = path.read_bytes()
        except OSError as exc:
            raise AuditChainError(f"cannot read audit log {path}: {exc}") from exc
        data.files.append((path.name, hashlib.sha256(blob).hexdigest(), len(blob)))
        for raw in blob.decode("utf-8", errors="replace").splitlines():
            if not raw.strip():
                continue
            try:
                rec = json.loads(raw)
            except ValueError:
                data.unreadable += 1
                continue
            if not isinstance(rec, dict) or rec.get("type") == "chain_continuation":
                continue
            _add_record(data, rec)
    data.events.sort(key=lambda e: (e.ts, e.seq))
    return data


def _add_record(data: LogData, rec: dict[str, Any]) -> None:
    raw_ctx = rec.get("context")
    ctx: dict[str, Any] = raw_ctx if isinstance(raw_ctx, dict) else {}
    raw_seq = rec.get("seq")
    seq = raw_seq if isinstance(raw_seq, int) else -1
    ts = str(rec.get("ts", ""))
    decision = str(rec.get("decision", "?"))
    data.records += 1
    data.decisions[decision] += 1
    data.outcomes[str(rec.get("tool_outcome", "?"))] += 1
    data.modes[str(rec.get("mode", "?"))] += 1
    data.runs.add(str(ctx.get("agent_run_id", "?")))
    data.tools[str(ctx.get("tool_name", "?"))] += 1
    stamp = rec.get("policy_sha256")
    if isinstance(stamp, str):
        data.fingerprints[stamp] += 1
    else:
        data.unstamped += 1
    if ts:
        data.first_ts = min(data.first_ts or ts, ts)
        data.last_ts = max(data.last_ts or ts, ts)

    findings = (
        [f for f in rec.get("findings", []) if isinstance(f, dict)]
        if isinstance(rec.get("findings"), list)
        else []
    )
    blocking = [f for f in findings if f.get("decision") != "allow"]
    for f in findings:
        rule = str(f.get("rule_id", "?"))
        ev = data.rules.setdefault(rule, RuleEvidence())
        if f.get("decision") == "allow":
            ev.informational += 1
        else:
            ev.findings += 1
        ev.calls.add(seq)
        ev.first = min(ev.first or ts, ts) if ts else ev.first
        ev.last = max(ev.last or ts, ts) if ts else ev.last
        if len(ev.seqs) < 5:
            ev.seqs.append(seq)
        detail = str(f.get("detail", ""))
        if rule == R_APPROVAL_ACCEPTED and (m := _APPROVER.search(detail)):
            data.approvers[m.group(1)] += 1
        if rule == R_EXEMPTION_APPLIED and (m := _EXEMPTION.search(detail)):
            data.exemptions[m.group(1)] += 1
    if decision != "allow" or blocking:
        primary = blocking[0] if blocking else {}
        data.events.append(
            Event(
                seq=seq,
                ts=ts,
                run=str(ctx.get("agent_run_id", "?")),
                tool=str(ctx.get("tool_name", "?")),
                env=str(ctx.get("target_env", "?")),
                money=_money(ctx),
                decision=decision,
                outcome=str(rec.get("tool_outcome", "?")),
                rules=tuple(dict.fromkeys(str(f.get("rule_id", "?")) for f in blocking)),
                stage=stage if isinstance(stage := primary.get("stage"), int) else 0,
                detail=str(primary.get("detail", ""))[:240],
                enforced=bool(primary.get("enforced", True)),
            )
        )


# --------------------------------------------------------------------------------------
# HTML
# --------------------------------------------------------------------------------------

CSS = """
:root{--bg:#fff;--fg:#1b1f24;--muted:#57606a;--line:#d0d7de;--accent:#0b5cad;--ok:#1a7f37;--bad:#b42318;--warn:#9a6700;--card:#f6f8fa}
@media (prefers-color-scheme: dark){:root{--bg:#0d1117;--fg:#e6edf3;--muted:#9da7b3;--line:#30363d;--accent:#58a6ff;--ok:#3fb950;--bad:#ff7b72;--warn:#d29922;--card:#161b22}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px 64px}h1{font-size:1.6rem;margin:.2em 0}h2{font-size:1.2rem;margin:2em 0 .5em;border-bottom:1px solid var(--line);padding-bottom:.2em}
.meta,.note{color:var(--muted)}.badge{display:inline-block;padding:.1em .6em;border-radius:1em;font-weight:600;border:1px solid currentColor;white-space:nowrap}
.nw{white-space:nowrap}.scroll{overflow-x:auto}
.ok{color:var(--ok)}.bad{color:var(--bad)}.warn{color:var(--warn)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 14px}.card b{display:block;font-size:1.5rem}
table{border-collapse:collapse;width:100%;font-size:.9rem}th,td{border:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top;word-break:break-word}th{background:var(--card)}
code{font-family:ui-monospace,monospace;font-size:.85em}svg{max-width:100%;height:auto;border:1px solid var(--line);border-radius:8px;background:var(--card)}
.s0{fill:#6e7781;stroke:#6e7781}.s1{fill:#0969da;stroke:#0969da}.s2{fill:#cf222e;stroke:#cf222e}.s3{fill:#bf8700;stroke:#bf8700}.s4{fill:#8250df;stroke:#8250df}
@media print{body{background:#fff;color:#000}}
"""


def _table(
    headers: Sequence[str], rows: Sequence[Sequence[str]], nowrap: Sequence[int] = ()
) -> str:
    """A table; columns listed in ``nowrap`` keep short values on one line."""

    def cls(i: int) -> str:
        return ' class="nw"' if i in nowrap else ""

    head = "".join(f"<th{cls(i)}>{esc(h)}</th>" for i, h in enumerate(headers))
    body = "".join(
        "<tr>" + "".join(f"<td{cls(i)}>{c}</td>" for i, c in enumerate(row)) + "</tr>"
        for row in rows
    )
    return f'<div class="scroll"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def _when(ts: str | None) -> str:
    """Compact display form of an ISO timestamp (the log keeps the exact one)."""
    if not ts:
        return "-"
    try:
        moment = datetime.fromisoformat(ts)
    except ValueError:
        return ts  # show what the log says rather than guess
    offset = moment.utcoffset()
    zone = "" if offset is None else " UTC" if not offset else f" {moment.strftime('%z')}"
    return moment.strftime("%Y-%m-%d %H:%M:%S") + zone


def _integrity(report: ChainVerificationReport, data: LogData, expected_tail: str | None) -> str:
    verdict = (
        '<span class="badge ok">chain verified</span>'
        if report.ok
        else '<span class="badge bad">chain BROKEN</span>'
    )
    parts = [f"<p>{verdict} {esc(report)}</p>"]
    rows = [
        ["Files", esc(", ".join(f"{n} ({s} bytes)" for n, _, s in data.files))],
        ["Records verified", esc(report.records_checked)],
        ["Tail hash", f"<code>{esc(report.tail_hash)}</code>"],
    ]
    if report.anchored_to:
        rows.append(["Continues from", f"<code>{esc(report.anchored_to)}</code>"])
    if expected_tail:
        rows.append(["Expected tail (external anchor)", f"<code>{esc(expected_tail)}</code>"])
    if not report.ok:
        rows.append(
            [
                "Failure",
                esc(f"{report.failure_file}:{report.failure_line}: {report.failure_reason}"),
            ]
        )
    if data.unreadable:
        rows.append(["Unreadable lines", esc(data.unreadable)])
    parts.append(_table(["Check", "Result"], rows))
    parts.append(
        '<p class="note">A hash chain is tamper-<em>evident</em>, not tamper-proof: someone who can '
        "rewrite the whole file can forge a consistent chain, and a truncated tail is invisible "
        "without an externally anchored tail hash. Store the tail hash somewhere write-once.</p>"
    )
    return "\n".join(parts)


def _policy_block(data: LogData, policy: PolicyConfig | None) -> str:
    from . import load_policy  # lazy: package init imports this module's siblings

    known: dict[str, str] = {}
    try:
        preset = load_policy()
        known[preset.fingerprint()] = f"bundled preset {preset.preset_id} {preset.preset_version}"
    except PolicyLoadError:
        pass  # the preset is not on disk (an unusual install); the report still renders
    if policy is not None:
        known[policy.fingerprint()] = (
            f"supplied policy {policy.preset_id} {policy.preset_version or ''}".strip()
        )
    rows = [
        [
            f"<code>{esc(fp)}</code>",
            esc(count),
            esc(known.get(fp, "not identified (pass --policy)")),
        ]
        for fp, count in data.fingerprints.most_common()
    ]
    if data.unstamped:
        rows.append(
            ["<em>none</em>", esc(data.unstamped), "written before policy fingerprints existed"]
        )
    return _table(["Policy fingerprint", "Records", "Identified as"], rows or [["-", "0", "-"]])


def _evidence_rows(data: LogData) -> list[list[str]]:
    catalog = {r.id: r for r in RULE_CATALOG}
    rows: list[list[str]] = []
    for requirement, control, rule_ids in CONTROL_MAP:
        seen = [r for r in rule_ids if r in data.rules]
        blocked = sum(data.rules[r].findings for r in seen)
        info = sum(data.rules[r].informational for r in seen)
        first = min((data.rules[r].first or "" for r in seen), default="") or "-"
        last = max((data.rules[r].last or "" for r in seen), default="") or "-"
        status = (
            f'<span class="badge warn">{blocked} stopped or held</span>'
            if blocked
            else f'<span class="badge ok">{info} recorded</span>'
            if info
            else '<span class="note">no events logged</span>'
        )
        rule_cells = "<br>".join(
            f"<code>{esc(_short(r))}</code> {esc(catalog[r].summary) if r in catalog else ''}"
            for r in rule_ids
        )
        examples = ", ".join(str(s) for r in seen for s in data.rules[r].seqs[:3]) or "-"
        rows.append(
            [
                esc(requirement),
                esc(control),
                rule_cells,
                status,
                esc(_when(first if first != "-" else None)),
                esc(_when(last if last != "-" else None)),
                esc(examples),
            ]
        )
    return rows


def _timeline_svg(events: Sequence[Event], first: str | None, last: str | None) -> str:
    if not events:
        return '<p class="note">No blocked or held calls in this log.</p>'
    width, lane, left, top = 940, 30, 70, 14
    height = top + lane * 5 + 26

    def parse(ts: str) -> float:
        try:
            return datetime.fromisoformat(ts).timestamp()
        except ValueError:
            return 0.0

    t0, t1 = parse(first or events[0].ts), parse(last or events[-1].ts)
    span = max(t1 - t0, 1.0)
    out = [
        f'<svg viewBox="0 0 {width} {height}" role="img" aria-label="Timeline of blocked or held '
        f'calls by kill-chain stage; the table below lists every event">'
    ]
    for stage in range(5):
        y = top + stage * lane + lane / 2
        out.append(
            f'<line x1="{left}" y1="{y}" x2="{width - 10}" y2="{y}" stroke="currentColor" opacity=".15"/>'
        )
        out.append(
            f'<text x="6" y="{y + 4}" font-size="11" fill="currentColor">stage {stage}</text>'
        )
    for ev in events[:MAX_MARKERS]:
        x = left + (parse(ev.ts) - t0) / span * (width - left - 14) if ev.ts else left
        y = top + min(max(ev.stage, 0), 4) * lane + lane / 2
        shape = _STAGE_SHAPE.get(ev.stage, "circle")
        title = (
            f"seq {ev.seq} {ev.ts} {ev.tool} {ev.decision} {', '.join(_short(r) for r in ev.rules)}"
        )
        cls = f"s{min(max(ev.stage, 0), 4)}"
        mark = {
            "circle": f'<circle cx="{x:.1f}" cy="{y}" r="5" class="{cls}">',
            "square": f'<rect x="{x - 4.5:.1f}" y="{y - 4.5}" width="9" height="9" class="{cls}">',
            "triangle": f'<polygon points="{x:.1f},{y - 6} {x - 5.5:.1f},{y + 4.5} {x + 5.5:.1f},{y + 4.5}" class="{cls}">',
            "diamond": f'<polygon points="{x:.1f},{y - 6} {x + 5.5:.1f},{y} {x:.1f},{y + 6} {x - 5.5:.1f},{y}" class="{cls}">',
            "x": f'<path d="M{x - 4:.1f} {y - 4} l8 8 m0 -8 l-8 8" class="{cls}" fill="none" stroke-width="2">',
        }[shape]
        closing = {
            "circle": "</circle>",
            "square": "</rect>",
            "triangle": "</polygon>",
            "diamond": "</polygon>",
            "x": "</path>",
        }[shape]
        out.append(f"{mark}<title>{esc(title)}</title>{closing}")
    out.append(
        f'<text x="{left}" y="{height - 6}" font-size="11" fill="currentColor">{esc(first or "")}</text>'
        f'<text x="{width - 10}" y="{height - 6}" font-size="11" text-anchor="end" fill="currentColor">{esc(last or "")}</text>'
    )
    out.append("</svg>")
    return "".join(out)


def _events_table(events: Sequence[Event]) -> str:
    rows = [
        [
            esc(_when(e.ts)),
            esc(e.seq),
            esc(_clip(e.run)),
            esc(_clip(e.tool)),
            esc(e.env),
            esc(e.money or "-"),
            esc(e.decision) + ("" if e.enforced else " (reported, not enforced)"),
            "<br>".join(_rule_cell(r) for r in e.rules) or "-",
            esc(e.detail),
        ]
        for e in events[:MAX_TIMELINE_ROWS]
    ]
    more = (
        f'<p class="note">{len(events) - MAX_TIMELINE_ROWS} more events not shown.</p>'
        if len(events) > MAX_TIMELINE_ROWS
        else ""
    )
    return (
        _table(
            ["Time", "Seq", "Run", "Tool", "Env", "Amount", "Decision", "Rules", "Detail"],
            rows,
            nowrap=(0, 1, 2, 3, 4, 5, 6),
        )
        + more
    )


def render_html(
    paths: Sequence[Path],
    *,
    policy: PolicyConfig | None = None,
    expected_tail: str | None = None,
    title: str = "Agent tool-call evidence report",
) -> str:
    """Build the report. ``paths`` are the audit files, oldest first (after rotation)."""
    from . import __version__

    data = read_logs(paths)
    chain = HashChainedAuditLog.verify_chain(list(paths), expected_tail_hash=expected_tail)
    stopped = data.decisions.get("block", 0) + data.decisions.get("hitl_required", 0)
    period = f"{data.first_ts} to {data.last_ts}" if data.first_ts else "no records"
    cards = "".join(
        f'<div class="card"><b>{esc(v)}</b>{esc(k)}</div>'
        for k, v in (
            ("records", data.records),
            ("blocked or held", stopped),
            ("tool executed", data.outcomes.get("executed", 0)),
            ("agent runs", len(data.runs)),
            ("tools called", len(data.tools)),
        )
    )
    approvals = (
        _table(
            ["Approver", "Approvals accepted"],
            [[esc(a), esc(n)] for a, n in data.approvers.most_common()],
        )
        if data.approvers
        else '<p class="note">No per-transaction approvals were accepted in this log.</p>'
    )
    exemptions = (
        _table(
            ["Exemption", "Times applied"],
            [[esc(a), esc(n)] for a, n in data.exemptions.most_common()],
        )
        if data.exemptions
        else '<p class="note">No exemptions were applied in this log.</p>'
    )
    legacy = data.rules.get(R_LEGACY_STEP_UP)
    legacy_note = (
        f'<p class="warn">The deprecated run-wide step-up claim satisfied a requirement '
        f"{legacy.informational} time(s).</p>"
        if legacy
        else ""
    )
    observe = data.modes.get("observe_only", 0)
    mode_note = (
        f'<p class="warn">{observe} record(s) were written in observe-only mode: those decisions '
        "were reported but not enforced.</p>"
        if observe
        else ""
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<title>{esc(title)}</title><style>{CSS}</style></head><body><main>
<h1>{esc(title)}</h1>
<p class="meta">Period covered: {esc(period)}. Generated by redhand-certin-0058-preset {esc(__version__)} from the audit log only (no network, no clock).</p>
<p class="note">This report summarises what the shield logged and maps it to the controls that address the CERT-In advisories CIAD-2026-0058 and CIAD-2026-0049. It is not a certification or a compliance attestation.</p>

<h2>Integrity of the log</h2>
{_integrity(chain, data, expected_tail)}

<h2>Summary</h2>
<div class="cards">{cards}</div>
{mode_note}

<h2>Policy in force</h2>
{_policy_block(data, policy)}

<h2>Advisory stage, control and logged evidence</h2>
{_table(["Advisory stage", "What the preset does", "Rules", "Evidence in this log", "First", "Last", "Example records (seq)"], _evidence_rows(data), nowrap=(3, 4, 5))}
<p class="note">"No events logged" means nothing triggered in this period. It does not show that the control was tested or that the system is compliant.</p>

<h2>Timeline of blocked and held calls</h2>
{_timeline_svg(data.events, data.first_ts, data.last_ts)}
{_events_table(data.events)}

<h2>Approvals, exemptions and deprecated paths</h2>
{approvals}
{exemptions}
{legacy_note}

<h2>Inputs</h2>
{_table(["File", "SHA-256", "Bytes"], [[esc(n), f"<code>{esc(h)}</code>", esc(s)] for n, h, s in data.files])}
<p class="note">Limits: the report reflects only calls the shield evaluated; a tool called outside the shield, or a log that was truncated without an external anchor, does not appear.</p>
</main></body></html>
"""
