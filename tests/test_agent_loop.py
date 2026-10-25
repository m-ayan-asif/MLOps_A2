import json

import pytest

import config
import prompts
from agent_loop import TraceLogger, _compact, _unresolved_credential_evidence, run_agent
from conftest import FAKE_AWS
from errors import AgentError
from helpers import FakeLLM, SpyTools, call, resp
from tools import RepoTools

VIOLATION = {
    "rule_id": "SEC-001", "category": "security", "severity": "high", "file": "config.py",
    "line": 3, "description": "d", "evidence": "e", "recommendation": "r",
}


@pytest.fixture
def tools(sample_repo):
    return SpyTools(RepoTools(sample_repo))


def run(llm, tools, **kw):
    kw.setdefault("coverage_guard", False)
    return run_agent("https://github.com/o/r", tools, llm, **kw)


def tool_msgs(llm_call):
    return [m for m in llm_call["messages"] if m["role"] == "tool"]


def test_happy_path_dispatch_order_and_result(tools):
    llm = FakeLLM([
        resp(call("list_files", reason="start")),
        resp(call("read_file", path="config.py", reason="look at config")),
        resp(call("search_code", pattern="password", reason="sweep")),
        resp(call("submit_report", violations=[VIOLATION])),
    ])
    assert run(llm, tools) == [VIOLATION]
    assert [n for n, _ in tools.dispatched] == ["list_files", "read_file", "search_code"]
    # the model really sees tool results, including line-numbered content
    assert any("DB_PASSWORD" in m["content"] for m in tool_msgs(llm.calls[2]))


def test_reason_is_stripped_before_dispatch_but_traced(tools, tmp_path):
    trace_path = tmp_path / "t.jsonl"
    trace = TraceLogger(str(trace_path), echo=False)
    llm = FakeLLM([resp(call("list_files", reason="because")), resp(call("submit_report", violations=[]))])
    run(llm, tools, trace=trace)
    trace.close()
    assert tools.dispatched[0][1] == {}
    events = [json.loads(line) for line in trace_path.read_text().splitlines()]
    tc = next(e for e in events if e["event"] == "tool_call")
    assert tc["tool"] == "list_files" and tc["reason"] == "because"
    assert events[-1]["event"] == "submit"


def test_tool_error_does_not_crash_and_is_fed_back(tools):
    llm = FakeLLM([
        resp(call("read_file", path="nope.txt", reason="x")),
        resp(call("bogus_tool", reason="x")),
        resp(call("submit_report", violations=[])),
    ])
    assert run(llm, tools) == []
    assert tool_msgs(llm.calls[1])[-1]["content"].startswith("ERROR: path not found")
    assert "unknown tool" in tool_msgs(llm.calls[2])[-1]["content"]


def test_no_tool_call_gets_nudged(tools):
    llm = FakeLLM([resp(text="hmm"), resp(call("submit_report", violations=[]))])
    run(llm, tools)
    last = llm.calls[1]["messages"][-1]
    assert last == {"role": "user", "content": prompts.NUDGE_CONTINUE}


def test_invalid_submit_payload_is_rejected_then_retry(tools):
    llm = FakeLLM([
        resp(call("submit_report", violations="oops")),
        resp(call("submit_report", violations=[VIOLATION])),
    ])
    assert run(llm, tools) == [VIOLATION]
    assert "must be an array" in tool_msgs(llm.calls[1])[-1]["content"]


COVERED = lambda final: [
    resp(call("list_files", reason="x")),
    resp(call("read_file", path=".github/workflows/ci.yml", reason="x")),
    resp(call("read_file", path="requirements.txt", reason="x")),
    resp(call("search_code", pattern="password|secret|token", reason="x")),
    resp(call("submit_report", violations=final)),
]


def test_guard_rejects_empty_report_when_coverage_is_incomplete(tools):
    llm = FakeLLM([
        resp(call("list_files", reason="x")),
        resp(call("submit_report", violations=[])),   # held back (1)
        resp(call("submit_report", violations=[])),   # held back (2)
        resp(call("submit_report", violations=[])),   # budget spent: fail closed
    ])
    with pytest.raises(AgentError, match="required inspection is incomplete"):
        run(llm, tools, coverage_guard=True)
    nudge = tool_msgs(llm.calls[2])[-1]["content"]
    assert "Not submitted yet" in nudge
    assert ".github/workflows/ci.yml" in nudge and "requirements.txt" in nudge
    assert "targeted search" in nudge and "source or configuration" in nudge
    assert llm.script == []


def test_documentation_and_match_all_search_cannot_pass_empty_report_guard(healthy_repo):
    t = SpyTools(RepoTools(healthy_repo))
    llm = FakeLLM([
        resp(call("list_files", reason="inspect repository structure")),
        resp(call("git_log", n=5, reason="check repository history")),
        resp(call("search_code", pattern="workflow|github/workflows", reason="find CI")),
        resp(call("search_code", pattern=".*", glob="*.md", reason="read documentation")),
        resp(call("read_file", path="README.md", reason="understand the project")),
        resp(call("submit_report", violations=[])),
        resp(call("submit_report", violations=[])),
        resp(call("submit_report", violations=[])),
    ])
    with pytest.raises(AgentError, match="required inspection is incomplete"):
        run(llm, t, coverage_guard=True)
    assert "match-all" in tool_msgs(llm.calls[6])[-1]["content"]


def test_guard_never_dictates_files_by_name(tools):
    llm = FakeLLM([
        resp(call("list_files", reason="x")),
        resp(call("submit_report", violations=[])),
        resp(call("submit_report", violations=[])),
        resp(call("submit_report", violations=[])),
    ])
    with pytest.raises(AgentError, match="required inspection is incomplete"):
        run(llm, tools, coverage_guard=True)
    nudges = [m["content"] for c in llm.calls for m in tool_msgs(c) if "Not submitted yet" in m["content"]]
    assert nudges, "expected at least one nudge"
    assert all("server.pem" not in n and "config.py" not in n for n in nudges)


def test_guard_silent_when_covered_on_healthy_repo(sample_repo, healthy_repo):
    t = SpyTools(RepoTools(healthy_repo))
    llm = FakeLLM(COVERED([]))
    assert run(llm, t, coverage_guard=True) == []
    assert llm.script == []
    assert not any("Not submitted yet" in m["content"] for c in llm.calls for m in tool_msgs(c))


def test_submit_in_same_turn_as_inspection_sees_that_inspection(healthy_repo):
    t = SpyTools(RepoTools(healthy_repo))
    llm = FakeLLM([resp(
        call("submit_report", violations=[]),
        call("read_file", path=".github/workflows/ci.yml", reason="x"),
        call("read_file", path="requirements.txt", reason="x"),
        call("search_code", pattern="secret|password|token", reason="x"),
    )])
    assert run(llm, t, coverage_guard=True) == []


def test_documentation_only_reads_do_not_count_as_coverage(healthy_repo):
    t = SpyTools(RepoTools(healthy_repo))
    llm = FakeLLM([
        resp(call("read_file", path="README.md", reason="x")),
        resp(call("submit_report", violations=[])),
        resp(call("submit_report", violations=[])),
        resp(call("submit_report", violations=[])),
    ])
    with pytest.raises(AgentError, match="required inspection is incomplete"):
        run(llm, t, coverage_guard=True)
    assert "README and other documentation alone" in tool_msgs(llm.calls[2])[-1]["content"]


def test_empty_report_with_production_credential_evidence_is_rejected(sample_repo):
    t = SpyTools(RepoTools(sample_repo))
    llm = FakeLLM([
        resp(call("read_file", path="config.py", reason="x"),
             call("read_file", path=".github/workflows/ci.yml", reason="x"),
             call("read_file", path="requirements.txt", reason="x"),
             call("search_code", pattern="password", reason="x")),
        resp(call("submit_report", violations=[])),   # nudged: masked literals were seen
        resp(call("submit_report", violations=[])),   # nudged again (budget 2)
        resp(call("submit_report", violations=[])),   # rejected: evidence remains unresolved
    ])
    with pytest.raises(AgentError, match=r"config.py:2"):
        run(llm, t, coverage_guard=True)
    assert "masked credential literals" in tool_msgs(llm.calls[2])[-1]["content"]


def test_search_evidence_blocks_empty_report_but_ignores_test_fixture():
    observed = [(
        "search_code",
        "2 match(es) in 2 file(s):\n"
        ".bash_profile:11: export AWS_ACCESS_KEY_ID=[REDACTED]\n"
        "tests/test_config.py:4: TEST_PASSWORD = '[REDACTED]'",
    )]
    assert _unresolved_credential_evidence(observed) == [(".bash_profile", 11)]


def test_step_limit_does_not_accept_empty_report_with_credential_evidence(sample_repo):
    t = SpyTools(RepoTools(sample_repo))
    llm = FakeLLM([
        resp(call("read_file", path="config.py", reason="inspect configuration"),
             call("search_code", pattern="password", reason="search credentials")),
        resp(call("submit_report", violations=[])),
        resp(call("submit_report", violations=[])),
    ])
    with pytest.raises(AgentError, match=r"config.py:2"):
        run(llm, t, max_steps=1, coverage_guard=True)


def test_nudge_lets_the_model_report_after_reconsidering(sample_repo):
    t = SpyTools(RepoTools(sample_repo))
    llm = FakeLLM([
        resp(call("read_file", path="config.py", reason="x"),
             call("read_file", path=".github/workflows/ci.yml", reason="x"),
             call("read_file", path="requirements.txt", reason="x"),
             call("search_code", pattern="password", reason="x")),
        resp(call("submit_report", violations=[])),
        resp(call("submit_report", violations=[VIOLATION])),
    ])
    assert run(llm, t, coverage_guard=True) == [VIOLATION]


def test_healthy_repo_with_test_fixture_credential_is_accepted_not_crashed(fixture_only_repo):
    """Regression: a hard guard used to reject empty reports forever and exit with AgentError."""
    t = SpyTools(RepoTools(fixture_only_repo))
    llm = FakeLLM([
        resp(call("list_files", reason="x")),
        resp(call("read_file", path=".github/workflows/ci.yml", reason="x"),
             call("read_file", path="pyproject.toml", reason="x"),
             call("read_file", path="src/lib.py", reason="x"),
             call("read_file", path="tests/test_lib.py", reason="x"),
             call("search_code", pattern="password|secret|token", reason="x")),
        resp(call("submit_report", violations=[])),
        resp(call("submit_report", violations=[])),
        resp(call("submit_report", violations=[])),
    ])
    assert run(llm, t, coverage_guard=True) == []


def test_step_limit_with_coverage_gaps_does_not_raise(tools):
    llm = FakeLLM([
        resp(call("list_files", reason="start")),
        resp(call("submit_report", violations=[VIOLATION])),   # forced phase
    ])
    assert run(llm, tools, max_steps=1, coverage_guard=True) == [VIOLATION]


def test_step_limit_rejects_empty_report_with_coverage_gaps(tools):
    llm = FakeLLM([
        resp(call("list_files", reason="start")),
        resp(call("submit_report", violations=[])),   # forced phase
    ])
    with pytest.raises(AgentError, match="required inspection is incomplete"):
        run(llm, tools, max_steps=1, coverage_guard=True)


def test_step_limit_forces_submit_with_only_submit_tool(tools):
    llm = FakeLLM([
        resp(call("list_files", reason="x")),
        resp(call("list_files", reason="x")),
        resp(call("list_files", reason="x")),
        resp(call("submit_report", violations=[VIOLATION])),
    ])
    assert run(llm, tools, max_steps=3) == [VIOLATION]
    assert llm.calls[-1]["tools"] == ["submit_report"]
    assert llm.calls[0]["tools"][-1] == "submit_report" and len(llm.calls[0]["tools"]) == 5
    # the model is warned as the budget runs low
    assert "System note" in tool_msgs(llm.calls[1])[-1]["content"]


def test_step_limit_without_report_raises(tools):
    llm = FakeLLM([resp(call("list_files", reason="x"))] + [resp(text="no")] * 2)
    with pytest.raises(AgentError):
        run(llm, tools, max_steps=1)


def test_forced_phase_answers_stray_tool_calls(tools):
    llm = FakeLLM([
        resp(call("list_files", reason="x")),
        resp(call("list_files", reason="x")),                      # forced attempt 1: wrong tool
        resp(call("submit_report", violations=[])),                # forced attempt 2
    ])
    assert run(llm, tools, max_steps=1) == []
    msgs = llm.calls[-1]["messages"]
    assert any(m["role"] == "tool" and "only submit_report" in m["content"] for m in msgs)


def test_parallel_call_cap(tools):
    n = config.MAX_CALLS_PER_STEP + 2
    llm = FakeLLM([
        resp(*[call("list_files", reason="x") for _ in range(n)]),
        resp(call("submit_report", violations=[])),
    ])
    run(llm, tools)
    assert len(tools.dispatched) == config.MAX_CALLS_PER_STEP
    contents = [m["content"] for m in tool_msgs(llm.calls[1])]
    assert len(contents) == n and sum("skipped" in c for c in contents) == 2


def test_llm_errors_propagate(tools):
    from errors import LLMError
    with pytest.raises(LLMError):
        run(FakeLLM([LLMError("boom")]), tools)


def test_trace_never_contains_secret_values(tools, tmp_path):
    trace_path = tmp_path / "t.jsonl"
    trace = TraceLogger(str(trace_path), echo=False)
    llm = FakeLLM([
        resp(call("search_code", pattern="AKIA[0-9A-Z]{16}", reason="find keys")),
        resp(call("submit_report", violations=[])),
    ])
    run(llm, tools, trace=trace)
    trace.close()
    text = trace_path.read_text()
    assert "config.py" in text and FAKE_AWS not in text
    assert all(FAKE_AWS not in json.dumps(m) for c in llm.calls for m in c["messages"])


def test_compaction_collapses_old_tool_outputs(monkeypatch):
    monkeypatch.setattr(config, "CONTEXT_CHAR_BUDGET", 1000)
    monkeypatch.setattr(config, "KEEP_RECENT_TOOL_RESULTS", 2)
    msgs = [{"role": "tool", "name": "x", "tool_call_id": str(i), "content": "a" * 600} for i in range(5)]
    _compact(msgs)
    assert msgs[0].get("compacted") and msgs[1].get("compacted")
    assert not msgs[-1].get("compacted") and not msgs[-2].get("compacted")
    assert "omitted" in msgs[0]["content"]


def test_trace_logger_survives_unwritable_path(tmp_path, capsys):
    t = TraceLogger(str(tmp_path), echo=False)   # a directory, cannot open as file
    t.log(event="x")
    t.close()
    assert "cannot write trace file" in capsys.readouterr().err
