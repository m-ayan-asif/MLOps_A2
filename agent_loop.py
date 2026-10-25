"""The agent loop: Observe -> Reason -> Select tool -> Execute -> Interpret -> Report.

The LLM decides every tool call. The loop only (1) executes calls safely, (2) feeds results
back, (3) keeps the context bounded, (4) writes an auditable trace, and (5) nudges the model
(at most config.MAX_COVERAGE_NUDGES times per run) when it tries to finish without having looked
at the obvious places. After that the model's report is accepted as submitted. The loop never
creates findings itself and never dictates which files to open.
"""
from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path
from typing import Any, Optional

import config
import prompts
from errors import AgentError
from redact import redact_obj
from tool_schemas import INSPECTION_TOOLS, SUBMIT, SUBMIT_REPORT, TOOL_DECLARATIONS

_MANIFESTS = {
    "pyproject.toml", "setup.py", "setup.cfg", "pipfile", "package.json", "go.mod", "cargo.toml",
    "pom.xml", "build.gradle", "build.gradle.kts", "gemfile", "composer.json", "environment.yml",
}
_DOC_FILENAMES = {"readme", "license", "changelog", "contributing", "code_of_conduct"}
_SECRET_SEARCH_TERMS = (
    "password", "passwd", "secret", "token", "credential", "privatekey", "apikey",
    "accesskey", "authorization", "bearer", "awsaccesskey",
)


class TraceLogger:
    """Writes one JSON object per line (JSONL) and optionally echoes progress to stderr."""

    def __init__(self, path: Optional[str] = None, echo: bool = True):
        self.echo = echo
        self._fh = None
        if path:
            try:
                p = Path(path)
                p.parent.mkdir(parents=True, exist_ok=True)
                self._fh = open(p, "w", encoding="utf-8")
            except OSError as e:
                print(f"warning: cannot write trace file {path}: {e}", file=sys.stderr)

    def log(self, **record: Any) -> None:
        if self._fh:
            rec = redact_obj({"ts": round(time.time(), 3), **record})
            self._fh.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
            self._fh.flush()

    def say(self, msg: str) -> None:
        if self.echo:
            print(redact_obj(msg), file=sys.stderr)

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None


def _norm(path: Any) -> str:
    p = str(path or "").replace("\\", "/").strip()
    return p[2:] if p.startswith("./") else p


def _coverage_gaps(tools, used: list[tuple[str, dict]]) -> list[str]:
    """Generic 'have you looked?' hints used to nudge the LLM before it finishes.

    This never emits findings and never names files to open because of their *names*: the LLM
    still chooses tools, interprets their output, and supplies every report item.
    """
    paths = tools.list_paths()
    if not paths:
        return []
    read = {_norm(a.get("path")) for n, a in used if n == "read_file"}
    gaps: list[str] = []
    substantive_reads = {
        p for p in read
        if p in paths
        and p.rsplit("/", 1)[-1].rsplit(".", 1)[0].lower() not in _DOC_FILENAMES
        and not p.lower().startswith(("docs/", "doc/"))
    }
    if not substantive_reads:
        gaps.append(
            "you have read no source or configuration file; README and other documentation alone "
            "are not enough to support an empty report"
        )
    workflows = [p for p in paths if p.startswith(".github/workflows/") and p.endswith((".yml", ".yaml"))]
    unread = [w for w in workflows if w not in read]
    if unread:
        gaps.append("workflow file(s) not read yet: " + ", ".join(unread[:6]))
    manifests = [
        p for p in paths
        if p.rsplit("/", 1)[-1].lower() in _MANIFESTS
        or (p.rsplit("/", 1)[-1].lower().startswith("requirements") and p.endswith(".txt"))
    ]
    if manifests and not any(m in read for m in manifests):
        gaps.append("dependency manifest(s) not read yet: " + ", ".join(manifests[:6]))
    secret_search = False
    for name, args in used:
        if name != "search_code":
            continue
        compact = re.sub(r"[^a-z0-9]", "", str(args.get("pattern") or "").lower())
        if not compact or compact in {"s", "d", "w"}:
            continue
        if any(term in compact for term in _SECRET_SEARCH_TERMS):
            secret_search = True
            break
    if not secret_search:
        gaps.append(
            "you have not run a targeted search for hardcoded credentials "
            "(a match-all pattern such as .* is capped and does not count)"
        )
    return gaps


_MASKED_CREDENTIAL_ASSIGNMENT = re.compile(
    r"(?i)\b([A-Za-z0-9_.-]*(?:password|passwd|secret|token|api[_-]?key|"
    r"access[_-]?key|credential|private[_-]?key)[A-Za-z0-9_.-]*)\b"
    r"\s*[:=]\s*(?:['\"])?\[REDACTED(?:_[A-Z0-9_-]+)?\]"
)


_FILE_HEADER = re.compile(r"^File: (.+) \(\d+\+? lines\)$")
_SEARCH_HIT = re.compile(r"^(.+?):(\d+):\s*(.*)$")
_READ_LINE = re.compile(r"^\s*(\d+)\|\s*(.*)$")
_BENIGN_CREDENTIAL_PATH = re.compile(
    r"(?:^|/)(?:tests?|fixtures?|examples?)(?:/|$)"
    r"|(?:^|/)(?:test|example|sample)[^/]*$"
    r"|(?:^|/)[^/]*(?:_test|\.test|_spec)\.[^/]+$",
    re.IGNORECASE,
)


def _masked_credential_evidence(observed: list[tuple[str, str]]) -> list[tuple[str, int, str]]:
    """Return masked credential assignments with their repository locations."""
    evidence = []
    for tool_name, result in observed:
        if tool_name not in {"read_file", "search_code"}:
            continue
        current_file = ""
        for line in result.splitlines():
            header = _FILE_HEADER.match(line)
            if header:
                current_file = header.group(1)
                continue
            if tool_name == "search_code":
                hit = _SEARCH_HIT.match(line)
                if not hit:
                    continue
                file_path, line_number, content = hit.groups()
            else:
                hit = _READ_LINE.match(line)
                if not hit:
                    continue
                line_number, content = hit.groups()
                file_path = current_file
            if file_path and _MASKED_CREDENTIAL_ASSIGNMENT.search(content):
                evidence.append((file_path, int(line_number), content.strip()))
    return list(dict.fromkeys(evidence))


def _unresolved_credential_evidence(observed: list[tuple[str, str]]) -> list[tuple[str, int]]:
    """Find non-fixture credential evidence that an empty report must not discard."""
    return [
        (file_path, line_number)
        for file_path, line_number, _ in _masked_credential_evidence(observed)
        if not _BENIGN_CREDENTIAL_PATH.search(file_path.replace("\\", "/"))
    ]


def _empty_report_evidence_gaps(observed: list[tuple[str, str]]) -> list[str]:
    """Catch a common false negative: an empty report despite seeing masked literals."""
    evidence = [
        item for item in _masked_credential_evidence(observed)
        if not _BENIGN_CREDENTIAL_PATH.search(item[0].replace("\\", "/"))
    ]
    if not evidence:
        return []
    examples = "; ".join(
        f"{file_path}:{line_number}: {content}"
        for file_path, line_number, content in evidence[:5]
    )
    return [
        "you are submitting an empty report, but you observed masked credential literals: "
        + examples
        + ". Report concrete credentials outside test, fixture, or example paths with their file "
        + "and line, without the value; an empty report is only appropriate when every match is "
        + "clearly benign test/example data"
    ]


def _compact(messages: list[dict]) -> None:
    """Collapse the oldest tool outputs once the context grows past the budget."""
    idx = [i for i, m in enumerate(messages) if m["role"] == "tool" and not m.get("compacted")]
    total = sum(len(messages[i]["content"]) for i in idx)
    if total <= config.CONTEXT_CHAR_BUDGET:
        return
    for i in idx[: -config.KEEP_RECENT_TOOL_RESULTS]:
        if total <= config.CONTEXT_CHAR_BUDGET:
            break
        old = len(messages[i]["content"])
        messages[i]["content"] = (
            f"[earlier output omitted to save context ({old} chars); call the tool again if needed]"
        )
        messages[i]["compacted"] = True
        total -= old - len(messages[i]["content"])


def _fmt_args(args: dict) -> str:
    return ", ".join(f"{k}={str(v)[:60]!r}" for k, v in args.items())


def run_agent(
    repo_url: str,
    tools,
    llm,
    max_steps: int = config.MAX_STEPS,
    trace: Optional[TraceLogger] = None,
    system_prompt: str = prompts.SYSTEM_PROMPT,
    coverage_guard: bool = True,
) -> list[dict]:
    """Run the investigation and return the raw violations the model submitted."""
    trace = trace or TraceLogger(None, echo=False)
    messages: list[dict] = [{"role": "user", "content": prompts.initial_message(repo_url)}]
    used: list[tuple[str, dict]] = []
    observed: list[tuple[str, str]] = []
    nudges = 0

    for step in range(1, max_steps + 1):
        _compact(messages)
        resp = llm.chat(messages, system_prompt, TOOL_DECLARATIONS)
        messages.append(resp.to_message())
        if resp.text:
            trace.log(step=step, event="thought", text=resp.text[:1000])
        if not resp.tool_calls:
            trace.log(step=step, event="no_tool_call")
            trace.say(f"[step {step}] model returned no tool call; nudging")
            messages.append({"role": "user", "content": prompts.NUDGE_CONTINUE})
            continue

        contents: dict[int, str] = {}
        calls = list(enumerate(resp.tool_calls))
        # Pass 1: inspection tools (so the guard below sees everything done this turn).
        for idx, call in calls:
            if call.name == SUBMIT:
                continue
            args = dict(call.args) if isinstance(call.args, dict) else {}
            reason = args.pop("reason", None)
            if idx >= config.MAX_CALLS_PER_STEP:
                contents[idx] = f"ERROR: skipped; at most {config.MAX_CALLS_PER_STEP} tool calls per step"
                continue
            result = tools.dispatch(call.name, args)
            used.append((call.name, args))
            contents[idx] = result
            observed.append((call.name, result))
            trace.log(
                step=step, event="tool_call", tool=call.name, args=args, reason=reason,
                result_chars=len(result), result_preview=result[:300],
            )
            trace.say(f"[step {step}] {call.name}({_fmt_args(args)})" + (f"  # {reason}" if reason else ""))

        # Pass 2: submit_report.
        accepted: Optional[list] = None
        for idx, call in calls:
            if call.name != SUBMIT:
                continue
            violations = call.args.get("violations") if isinstance(call.args, dict) else None
            if accepted is not None:
                contents[idx] = "Ignored: a report was already accepted in this turn."
            elif not isinstance(violations, list):
                contents[idx] = "ERROR: 'violations' must be an array of finding objects (use [] if none)."
            else:
                gaps = _coverage_gaps(tools, used) if coverage_guard else []
                if coverage_guard and not violations:
                    gaps.extend(_empty_report_evidence_gaps(observed))
                if gaps and nudges < config.MAX_COVERAGE_NUDGES:
                    nudges += 1
                    contents[idx] = prompts.coverage_nudge(gaps)
                    trace.log(step=step, event="coverage_nudge", gaps=gaps, nudge=nudges)
                    trace.say(
                        f"[step {step}] submit_report held back ({nudges}/{config.MAX_COVERAGE_NUDGES}): "
                        f"{len(gaps)} gap(s)"
                    )
                elif gaps and not violations:
                    trace.log(
                        step=step, event="empty_report_rejected",
                        coverage_gaps=gaps,
                    )
                    raise AgentError(
                        "refusing to accept an empty report because required inspection is "
                        "incomplete: " + "; ".join(gaps)
                    )
                else:
                    unresolved = (
                        _unresolved_credential_evidence(observed)
                        if coverage_guard and not violations else []
                    )
                    if unresolved:
                        locations = ", ".join(
                            f"{file_path}:{line_number}" for file_path, line_number in unresolved[:10]
                        )
                        trace.log(
                            step=step, event="empty_report_rejected",
                            evidence_locations=locations,
                        )
                        raise AgentError(
                            "refusing to accept an empty report despite observed masked credential "
                            f"assignments at {locations}; review the evidence and report verified "
                            "findings, or inspect the files to establish that they are benign"
                        )
                    accepted = violations
                    contents[idx] = "Report accepted."

        if accepted is not None:
            trace.log(step=step, event="submit", findings=len(accepted))
            trace.say(f"[step {step}] submit_report: {len(accepted)} finding(s)")
            return accepted

        tool_msgs = [
            {"role": "tool", "tool_call_id": c.id, "name": c.name, "content": contents[i]}
            for i, c in calls
        ]
        remaining = max_steps - step
        if 0 < remaining <= config.STEP_WARNING_THRESHOLD:
            tool_msgs[-1]["content"] += "\n\n" + prompts.step_warning(remaining)
        messages.extend(tool_msgs)

    # Step budget exhausted: ask for the report with only submit_report available.
    trace.log(event="step_limit_reached")
    trace.say("[agent] step limit reached; requesting final report")
    blocked_locations: list[str] = []
    for _ in range(2):
        messages.append({"role": "user", "content": prompts.FORCE_SUBMIT})
        resp = llm.chat(messages, system_prompt, [SUBMIT_REPORT])
        messages.append(resp.to_message())
        for call in resp.tool_calls:
            violations = call.args.get("violations") if isinstance(call.args, dict) else None
            if call.name == SUBMIT and isinstance(violations, list):
                gaps = _coverage_gaps(tools, used) if coverage_guard and not violations else []
                if not violations:
                    gaps.extend(_empty_report_evidence_gaps(observed))
                if gaps:
                    trace.log(
                        event="empty_report_rejected", forced=True,
                        coverage_gaps=gaps,
                    )
                    raise AgentError(
                        "refusing to accept an empty report at the step limit because required "
                        "inspection is incomplete: " + "; ".join(gaps)
                    )
                unresolved = (
                    _unresolved_credential_evidence(observed)
                    if coverage_guard and not violations else []
                )
                if unresolved:
                    locations = ", ".join(
                        f"{file_path}:{line_number}" for file_path, line_number in unresolved[:10]
                    )
                    blocked_locations.append(locations)
                    trace.log(
                        event="empty_report_rejected", forced=True,
                        evidence_locations=locations,
                    )
                    messages.append({
                        "role": "tool", "tool_call_id": call.id, "name": call.name,
                        "content": (
                            "ERROR: an empty report is not accepted while masked credential "
                            f"assignments remain unresolved at {locations}. Submit verified findings "
                            "or establish through inspection that the evidence is benign."
                        ),
                    })
                    continue
                trace.log(event="submit", findings=len(violations), forced=True)
                return violations
        # Any unanswered function calls must receive a response before the next user turn.
        for c in resp.tool_calls:
            messages.append(
                {"role": "tool", "tool_call_id": c.id, "name": c.name,
                 "content": "ERROR: only submit_report is available now."}
            )
    if blocked_locations:
        raise AgentError(
            "the model did not resolve observed masked credential assignments at "
            + "; ".join(dict.fromkeys(blocked_locations))
        )
    raise AgentError("the model did not submit a report within the step limit")
