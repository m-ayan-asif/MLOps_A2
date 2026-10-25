"""Inspection tools the LLM can call.

Contract for every tool: take simple args, return a *string*, never raise, never write to the
repository, and never return an unredacted secret. All paths are confined to the repo root.
"""
from __future__ import annotations

import fnmatch
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any, Optional

import config
from redact import mask_private_keys, redact


def _as_int(value: Any, default: int, lo: int, hi: int) -> int:
    try:
        n = int(float(value))
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, n))


def _as_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() not in ("false", "0", "no", "")
    return default


def _fmt_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / (1024 * 1024):.1f} MB"


class RepoTools:
    def __init__(self, root: Path):
        self.root = Path(root).resolve()
        self._tools = {
            "list_files": self.list_files,
            "read_file": self.read_file,
            "search_code": self.search_code,
            "git_log": self.git_log,
        }

    # ------------------------------------------------------------------ helpers
    def _rel(self, path: Path) -> str:
        return path.relative_to(self.root).as_posix()

    def _iter_files(self, base: Optional[Path] = None):
        for dirpath, dirnames, filenames in os.walk(base or self.root, followlinks=False):
            dirnames[:] = sorted(d for d in dirnames if d != ".git")
            for name in sorted(filenames):
                yield Path(dirpath) / name

    def _resolve(self, rel: Any) -> tuple[Optional[Path], Optional[str]]:
        """Resolve `rel` inside the repo. Returns (path, None) or (None, error message)."""
        if not isinstance(rel, str) or not rel.strip() or "\x00" in rel:
            return None, "ERROR: path must be a non-empty string"
        try:
            resolved = (self.root / rel).resolve(strict=True)
        except (OSError, RuntimeError, ValueError):
            return None, f"ERROR: path not found: {rel}"
        try:
            parts = resolved.relative_to(self.root).parts
        except ValueError:
            return None, "ERROR: path is outside the repository"
        if ".git" in parts:
            return None, "ERROR: .git internals are not readable; use git_log for history"
        return resolved, None

    def _read_text(self, path: Path) -> Optional[str]:
        """Text of a regular file, or None if binary / too large / unreadable."""
        try:
            if path.stat().st_size > config.MAX_FILE_BYTES:
                return None
            with open(path, "rb") as fh:
                data = fh.read(config.MAX_FILE_BYTES)
        except OSError:
            return None
        if b"\x00" in data[:8192]:
            return None
        return data.decode("utf-8", errors="replace")

    def list_paths(self, limit: int = config.MAX_WALK_FILES) -> list[str]:
        """All tracked file paths (posix, relative). Internal helper, not an LLM tool."""
        out: list[str] = []
        for f in self._iter_files():
            out.append(self._rel(f))
            if len(out) >= limit:
                break
        return out

    # -------------------------------------------------------------------- tools
    def list_files(self, directory: str = "") -> str:
        base = self.root
        if isinstance(directory, str) and directory.strip() not in ("", ".", "/"):
            resolved, err = self._resolve(directory)
            if err:
                return err
            if not resolved.is_dir():
                return f"ERROR: '{directory}' is not a directory"
            base = resolved

        entries: list[tuple[str, int, bool]] = []
        capped = False
        for f in self._iter_files(base):
            try:
                size = f.stat().st_size
            except OSError:
                size = 0
            entries.append((self._rel(f), size, f.is_symlink()))
            if len(entries) >= config.MAX_WALK_FILES:
                capped = True
                break
        if not entries:
            return "No files found."

        base_rel = "" if base == self.root else self._rel(base) + "/"
        counts: dict[str, int] = {}
        for rel, _, _ in entries:
            tail = rel[len(base_rel):]
            top = tail.split("/", 1)[0] + "/" if "/" in tail else "(files here)"
            counts[top] = counts.get(top, 0) + 1

        entries.sort(key=lambda e: (e[0].count("/"), e[0].lower()))
        shown = entries[: config.MAX_LIST_ENTRIES]

        lines = [
            f"{len(entries)}{'+' if capped else ''} file(s) under '{base_rel or '.'}' "
            f"(shallowest first; .git excluded; the clone contains only git-tracked files)"
        ]
        top_counts = sorted(counts.items(), key=lambda kv: -kv[1])[:15]
        lines.append("Counts by top-level entry: " + ", ".join(f"{k} {v}" for k, v in top_counts))
        for rel, size, is_link in shown:
            lines.append(f"{rel} ({_fmt_size(size)}){' [symlink]' if is_link else ''}")
        if len(entries) > len(shown):
            lines.append(
                f"[{len(entries) - len(shown)} more file(s) not shown; "
                f"call list_files with a subdirectory to see them]"
            )
        return "\n".join(lines)

    def read_file(self, path: str, start_line: int = 1) -> str:
        target, err = self._resolve(path)
        if err:
            return err
        if target.is_dir():
            return f"ERROR: '{path}' is a directory; use list_files(directory=...)"
        rel = self._rel(target)
        try:
            size = target.stat().st_size
            with open(target, "rb") as fh:
                data = fh.read(config.MAX_FILE_BYTES + 1)
        except OSError as e:
            return f"ERROR: cannot read {rel}: {e.strerror or e}"
        if b"\x00" in data[:8192]:
            return f"ERROR: {rel} looks like a binary file ({_fmt_size(size)}); contents not shown"
        file_truncated = len(data) > config.MAX_FILE_BYTES
        text = mask_private_keys(data[: config.MAX_FILE_BYTES].decode("utf-8", errors="replace"))
        lines = [ln.rstrip("\r") for ln in text.split("\n")]
        if lines and lines[-1] == "":
            lines.pop()
        total = len(lines)
        if total == 0:
            return f"File: {rel} (empty)"
        start = _as_int(start_line, 1, 1, 10**9)
        if start > total:
            return f"ERROR: start_line {start} is beyond the end of {rel} ({total} lines)"

        out: list[str] = []
        used = 0
        for i in range(start - 1, min(total, start - 1 + config.MAX_READ_LINES)):
            shown = redact(lines[i])
            if len(shown) > config.MAX_LINE_CHARS:
                shown = shown[: config.MAX_LINE_CHARS] + " ...[line truncated]"
            entry = f"{i + 1:>5}| {shown}"
            if used + len(entry) > config.MAX_READ_BYTES and out:
                break
            out.append(entry)
            used += len(entry) + 1
        last = start + len(out) - 1
        header = f"File: {rel} ({total}{'+' if file_truncated else ''} lines)"
        footer = ""
        if last < total:
            footer = (
                f"\n[truncated: showing lines {start}-{last} of {total}; "
                f"call read_file again with start_line={last + 1} to continue]"
            )
        elif file_truncated:
            footer = f"\n[file is {_fmt_size(size)}; only the first {_fmt_size(config.MAX_FILE_BYTES)} were read]"
        return header + "\n" + "\n".join(out) + footer

    def search_code(self, pattern: str, glob: str = "", ignore_case: bool = True) -> str:
        if not isinstance(pattern, str) or not pattern.strip():
            return "ERROR: pattern must be a non-empty string"
        flags = re.IGNORECASE if _as_bool(ignore_case, True) else 0
        try:
            rx = re.compile(pattern, flags)
        except re.error as e:
            return f"ERROR: invalid regular expression: {e}"
        glob = glob.strip() if isinstance(glob, str) else ""

        deadline = time.monotonic() + config.SEARCH_TIME_BUDGET
        hits: list[str] = []
        total_hits = files_with_hits = skipped = 0
        timed_out = False
        for f in self._iter_files():
            if time.monotonic() > deadline:
                timed_out = True
                break
            if f.is_symlink():
                continue
            rel = self._rel(f)
            if glob and not (fnmatch.fnmatch(rel, glob) or fnmatch.fnmatch(f.name, glob)):
                continue
            text = self._read_text(f)
            if text is None:
                skipped += 1
                continue
            text = mask_private_keys(text)
            file_hits = 0
            for lineno, line in enumerate(text.split("\n"), 1):
                line = line.rstrip("\r")[:2000]
                if rx.search(line):
                    total_hits += 1
                    file_hits += 1
                    if file_hits <= config.MAX_HITS_PER_FILE and len(hits) < config.MAX_SEARCH_HITS:
                        hits.append(f"{rel}:{lineno}: {redact(line).strip()[:200]}")
            if file_hits:
                files_with_hits += 1

        scope = f" in files matching '{glob}'" if glob else ""
        if not total_hits:
            msg = f"No matches for /{pattern}/{scope}."
        else:
            msg = (
                f"{total_hits} match(es) in {files_with_hits} file(s) for /{pattern}/{scope} "
                f"(showing {len(hits)}):\n" + "\n".join(hits)
            )
            if total_hits > len(hits):
                msg += "\n[more matches exist; narrow the pattern or use the glob argument]"
        if skipped:
            msg += f"\n[{skipped} binary or oversized file(s) skipped]"
        if timed_out:
            msg += "\n[search stopped early: time budget exceeded]"
        return msg

    def git_log(self, n: int = 20) -> str:
        n = _as_int(n, 20, 1, 100)
        cmd = [
            "git", "-C", str(self.root), "log", f"-n{n}",
            "--date=short", "--format=%h %ad %an: %s",
        ]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=config.GIT_TIMEOUT, env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
            )
        except FileNotFoundError:
            return "ERROR: git executable not found"
        except subprocess.TimeoutExpired:
            return "ERROR: git log timed out"
        if proc.returncode != 0:
            return "ERROR: git log failed: " + (proc.stderr or "").strip()[:300]
        lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
        if not lines:
            return "No commits found."
        return (
            f"{len(lines)} most recent commit(s) (hash date author: subject); "
            f"history is a shallow clone limited to {config.CLONE_DEPTH} commits:\n"
            + "\n".join(lines)
        )

    # ----------------------------------------------------------------- dispatch
    def dispatch(self, name: str, args: Optional[dict]) -> str:
        """Single entry point used by the agent loop. Never raises."""
        fn = self._tools.get(name)
        if fn is None:
            return f"ERROR: unknown tool '{name}'. Available: {', '.join(self._tools)}"
        clean = {k: v for k, v in (args or {}).items() if k != "reason"} if isinstance(args, dict) else {}
        try:
            result = fn(**clean)
        except TypeError as e:
            return f"ERROR: invalid arguments for {name}: {e}"
        except Exception as e:  # noqa: BLE001 - tools must never crash the loop
            return f"ERROR: {name} failed: {type(e).__name__}: {e}"
        if not isinstance(result, str):
            result = str(result)
        if len(result) > config.MAX_TOOL_OUTPUT_CHARS:
            result = result[: config.MAX_TOOL_OUTPUT_CHARS] + "\n[output truncated]"
        return redact(result)  # belt and braces: every tool result is masked once more
