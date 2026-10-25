"""URL validation and safe cloning.

Safety properties:
  * only https://github.com/<owner>/<repo> URLs are accepted;
  * git hooks are disabled and no credentials prompt can block the run;
  * the clone lives in a fresh temp dir that is always removed afterwards;
  * nothing from the cloned repository is ever executed.
"""
from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

import config
from errors import CloneError, InvalidRepoURL

_URL_RE = re.compile(
    r"^https://github\.com/(?P<owner>[A-Za-z0-9_.\-]+)/(?P<name>[A-Za-z0-9_.\-]+?)(?:\.git)?/?$"
)


def validate_github_url(url: str) -> tuple[str, str]:
    """Return (owner, repo) or raise InvalidRepoURL."""
    if not isinstance(url, str):
        raise InvalidRepoURL("repository URL must be a string")
    m = _URL_RE.match(url.strip())
    if not m or m.group("owner") in (".", "..") or m.group("name") in (".", ".."):
        raise InvalidRepoURL(
            f"invalid repository URL {url!r}; expected https://github.com/<owner>/<repo>"
        )
    return m.group("owner"), m.group("name")


def canonical_url(url: str) -> str:
    owner, name = validate_github_url(url)
    return f"https://github.com/{owner}/{name}"


def _rmtree(path: str) -> None:
    """rmtree that also removes read-only files (git objects on Windows)."""

    def _fix(func, p, _exc):
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except OSError:
            pass

    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=_fix)
    else:  # pragma: no cover
        shutil.rmtree(path, onerror=_fix)


@contextmanager
def clone_repo(url: str, timeout: int = config.CLONE_TIMEOUT) -> Iterator[Path]:
    """Shallow-clone `url` into a temp dir, yield its path, always clean up."""
    owner, name = validate_github_url(url)
    tmp = tempfile.mkdtemp(prefix="devops-audit-")
    dest = Path(tmp) / "repo"
    try:
        cmd = [
            "git",
            "-c", f"core.hooksPath={os.devnull}",
            "-c", "protocol.file.allow=never",
            "-c", "protocol.ext.allow=never",
            "clone",
            "--depth", str(config.CLONE_DEPTH),
            "--no-tags",
            "--single-branch",
            "--",
            f"https://github.com/{owner}/{name}.git",
            str(dest),
        ]
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=timeout, env=env,
            )
        except FileNotFoundError:
            raise CloneError("git is not installed or not on PATH") from None
        except subprocess.TimeoutExpired:
            raise CloneError(f"git clone timed out after {timeout}s") from None
        if proc.returncode != 0:
            err = (proc.stderr or "").strip()
            low = err.lower()
            if "not found" in low or "could not read username" in low or "authentication" in low:
                raise CloneError(
                    f"could not clone {owner}/{name}: repository not found or not public"
                )
            raise CloneError(f"git clone failed: {err[:500] or 'unknown error'}")
        if not dest.exists():
            raise CloneError("git clone reported success but produced no directory")
        yield dest
    finally:
        _rmtree(tmp)
