import subprocess
from pathlib import Path

import pytest

import repo
from errors import CloneError, InvalidRepoURL


@pytest.mark.parametrize("url,expected", [
    ("https://github.com/octo/demo", ("octo", "demo")),
    ("https://github.com/octo/demo/", ("octo", "demo")),
    ("https://github.com/octo/demo.git", ("octo", "demo")),
    ("https://github.com/Octo-Cat/my.repo_1", ("Octo-Cat", "my.repo_1")),
])
def test_valid_urls(url, expected):
    assert repo.validate_github_url(url) == expected


@pytest.mark.parametrize("url", [
    "", "http://github.com/a/b", "https://gitlab.com/a/b", "https://github.com/a",
    "https://github.com/a/b/c", "git@github.com:a/b.git", "https://github.com/a/b?x=1",
    "https://github.com/../b", "https://github.com/a/..", "ftp://github.com/a/b", "a/b",
    "https://github.com/a b/c",
])
def test_invalid_urls(url):
    with pytest.raises(InvalidRepoURL):
        repo.validate_github_url(url)


def test_canonical_url():
    assert repo.canonical_url("https://github.com/o/r.git/") == "https://github.com/o/r"


def _patch_tmp(monkeypatch, tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.setattr(repo.tempfile, "mkdtemp", lambda prefix="": str(work))
    return work


def test_clone_success_uses_safe_flags_and_cleans_up(monkeypatch, tmp_path):
    work = _patch_tmp(monkeypatch, tmp_path)
    seen = {}

    def fake_run(cmd, **kw):
        seen["cmd"], seen["env"] = cmd, kw["env"]
        Path(cmd[-1]).mkdir(parents=True)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(repo.subprocess, "run", fake_run)
    with repo.clone_repo("https://github.com/o/r") as root:
        assert root.exists() and root.parent == work
    assert not work.exists()
    joined = " ".join(seen["cmd"])
    assert "core.hooksPath=" in joined and "--depth" in seen["cmd"] and "--" in seen["cmd"]
    assert seen["cmd"][-2] == "https://github.com/o/r.git"
    assert seen["env"]["GIT_TERMINAL_PROMPT"] == "0"


def test_clone_failure_not_found(monkeypatch, tmp_path):
    work = _patch_tmp(monkeypatch, tmp_path)
    monkeypatch.setattr(
        repo.subprocess, "run",
        lambda cmd, **kw: subprocess.CompletedProcess(cmd, 128, "", "fatal: repository 'x' not found"),
    )
    with pytest.raises(CloneError, match="not found or not public"):
        with repo.clone_repo("https://github.com/o/r"):
            pass
    assert not work.exists()


def test_clone_timeout_and_missing_git(monkeypatch, tmp_path):
    work = _patch_tmp(monkeypatch, tmp_path)

    def boom_timeout(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, 1)

    monkeypatch.setattr(repo.subprocess, "run", boom_timeout)
    with pytest.raises(CloneError, match="timed out"):
        with repo.clone_repo("https://github.com/o/r"):
            pass

    work.mkdir(exist_ok=True)

    def no_git(cmd, **kw):
        raise FileNotFoundError()

    monkeypatch.setattr(repo.subprocess, "run", no_git)
    with pytest.raises(CloneError, match="git is not installed"):
        with repo.clone_repo("https://github.com/o/r"):
            pass


def test_invalid_url_never_reaches_git(monkeypatch):
    monkeypatch.setattr(repo.subprocess, "run", lambda *a, **k: pytest.fail("git must not run"))
    with pytest.raises(InvalidRepoURL):
        with repo.clone_repo("https://evil.example/a/b"):
            pass
