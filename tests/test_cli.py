import json
from contextlib import contextmanager

import pytest

import agent
import config
from errors import CloneError, LLMError
from helpers import FakeLLM, call, resp
from report import validate_report
from conftest import FAKE_PW

URL = "https://github.com/octo/demo"
FINDING = {
    "rule_id": "SEC-001", "category": "security", "severity": "critical", "file": "config.py",
    "line": 3, "description": "Hardcoded database password",
    "evidence": f'`DB_PASSWORD = "{FAKE_PW}"` is assigned in source', "recommendation": "Use env vars",
}


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setattr(config, "load_env", lambda: None)
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")


def patch_clone(monkeypatch, repo_path):
    @contextmanager
    def fake_clone(url):
        yield repo_path
    monkeypatch.setattr(agent, "clone_repo", fake_clone)


def patch_llm(monkeypatch, script):
    fake = FakeLLM(script)
    monkeypatch.setattr(agent, "LLMClient", lambda key, model: fake)
    return fake


def cli(tmp_path, repo=URL):
    return ["--repo", repo, "--output", str(tmp_path / "report.json"), "--trace", str(tmp_path / "trace.jsonl")]


def full_run(final, inspect_private_key=True):
    script = [
        resp(call("list_files", reason="start")),
        resp(call("read_file", path=".github/workflows/ci.yml", reason="ci")),
        resp(call("read_file", path="requirements.txt", reason="deps")),
        resp(call("read_file", path="config.py", reason="config")),
    ]
    if inspect_private_key:
        script.append(resp(call("read_file", path="keys/server.pem", reason="inspect tracked private-key file")))
    script.extend([
        resp(call("search_code", pattern="password", reason="sweep")),
        resp(call("submit_report", violations=final)),
    ])
    return script


def test_full_run_writes_valid_report_and_trace(monkeypatch, tmp_path, sample_repo, capsys):
    patch_clone(monkeypatch, sample_repo)
    patch_llm(monkeypatch, full_run([FINDING]))
    assert agent.main(cli(tmp_path)) == 0
    data = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert validate_report(data) == [] and data["repository"] == URL
    assert data["violations"][0]["file"] == "config.py" and data["violations"][0]["line"] == 3
    assert FAKE_PW not in json.dumps(data)                       # redacted before writing
    trace = [json.loads(l) for l in (tmp_path / "trace.jsonl").read_text().splitlines()]
    assert [e["tool"] for e in trace if e["event"] == "tool_call"][0] == "list_files"
    assert "Done: 1 violation" in capsys.readouterr().err


def test_unverified_finding_fails_without_writing_report(monkeypatch, tmp_path, sample_repo, capsys):
    patch_clone(monkeypatch, sample_repo)
    finding = {**FINDING, "evidence": "`import os`"}
    patch_llm(monkeypatch, full_run([finding]))
    assert agent.main(cli(tmp_path)) == 1
    assert "does not quote text found on that line" in capsys.readouterr().err
    assert not (tmp_path / "report.json").exists()


def test_healthy_repo_gives_empty_but_valid_report(monkeypatch, tmp_path, healthy_repo, capsys):
    patch_clone(monkeypatch, healthy_repo)
    patch_llm(monkeypatch, full_run([], inspect_private_key=False))
    assert agent.main(cli(tmp_path)) == 0
    assert "Healthy repo: no violations found" in capsys.readouterr().err
    assert json.loads((tmp_path / "report.json").read_text()) == {"repository": URL, "violations": []}


def test_url_normalised_in_report(monkeypatch, tmp_path, healthy_repo):
    patch_clone(monkeypatch, healthy_repo)
    patch_llm(monkeypatch, full_run([], inspect_private_key=False))
    assert agent.main(cli(tmp_path, repo=URL + ".git/")) == 0
    assert json.loads((tmp_path / "report.json").read_text())["repository"] == URL


@pytest.mark.parametrize("bad", ["not-a-url", "http://github.com/a/b", "https://gitlab.com/a/b"])
def test_bad_url_exits_nonzero(tmp_path, capsys, bad):
    assert agent.main(cli(tmp_path, repo=bad)) == 1
    err = capsys.readouterr().err
    assert err.startswith("error:") and "invalid repository URL" in err
    assert not (tmp_path / "report.json").exists()


def test_missing_api_key_exits_nonzero(monkeypatch, tmp_path, capsys):
    monkeypatch.delenv("GEMINI_API_KEY")
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    assert agent.main(cli(tmp_path)) == 1
    assert "GEMINI_API_KEY" in capsys.readouterr().err


def test_clone_failure_exits_nonzero(monkeypatch, tmp_path, capsys):
    @contextmanager
    def failing(url):
        raise CloneError("repository not found or not public")
        yield
    monkeypatch.setattr(agent, "clone_repo", failing)
    patch_llm(monkeypatch, [])
    assert agent.main(cli(tmp_path)) == 1
    assert "not found or not public" in capsys.readouterr().err
    assert not (tmp_path / "report.json").exists()


def test_llm_failure_exits_nonzero_without_report(monkeypatch, tmp_path, sample_repo, capsys):
    patch_clone(monkeypatch, sample_repo)
    patch_llm(monkeypatch, [LLMError("Gemini API error: quota")])
    assert agent.main(cli(tmp_path)) == 1
    assert "quota" in capsys.readouterr().err
    assert not (tmp_path / "report.json").exists()


def test_unexpected_exception_is_caught(monkeypatch, tmp_path, sample_repo, capsys):
    patch_clone(monkeypatch, sample_repo)
    patch_llm(monkeypatch, [RuntimeError("kaboom")])
    assert agent.main(cli(tmp_path)) == 1
    assert "unexpected RuntimeError" in capsys.readouterr().err


def test_output_path_is_directory_fails_before_any_llm_call(monkeypatch, tmp_path, capsys):
    patch_llm(monkeypatch, [])
    argv = ["--repo", URL, "--output", str(tmp_path), "--trace", str(tmp_path / "t.jsonl")]
    assert agent.main(argv) == 1
    assert "directory" in capsys.readouterr().err


def test_argparse_requires_repo(capsys):
    with pytest.raises(SystemExit) as e:
        agent.main([])
    assert e.value.code != 0


def test_output_defaults_to_sample_report_json(monkeypatch, tmp_path, healthy_repo):
    monkeypatch.chdir(tmp_path)
    patch_clone(monkeypatch, healthy_repo)
    patch_llm(monkeypatch, full_run([], inspect_private_key=False))
    assert agent.main(["--repo", URL, "--trace", str(tmp_path / "t.jsonl")]) == 0
    assert (tmp_path / "sample_report.json").exists()
