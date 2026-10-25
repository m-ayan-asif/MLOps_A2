"""Turn the model's raw findings into a validated, verified, de-duplicated, redacted report."""
from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Callable, Optional

import config
from errors import AuditError
from redact import mask_private_keys, redact, redact_obj

REQUIRED_FIELDS = (
    "rule_id", "category", "severity", "file", "line",
    "description", "evidence", "recommendation",
)
_SEVERITY_ALIASES = {"severe": "critical", "major": "high", "moderate": "medium", "minor": "low"}
_CATEGORY_ALIASES = {
    "ci": "ci_cd", "cicd": "ci_cd", "github_actions": "ci_cd", "github_actions_ci": "ci_cd",
    "repository": "repository_hygiene", "hygiene": "repository_hygiene",
    "dependencies": "dependency_management", "dependency": "dependency_management",
    "tests": "testing", "test": "testing", "build": "build_release", "release": "build_release",
    "quality": "code_quality", "config": "configuration",
}
_PREFIX = {
    "repository_hygiene": "REPO", "dependency_management": "DEP", "code_quality": "QUAL",
    "testing": "TEST", "ci_cd": "CI", "security": "SEC", "configuration": "CFG",
    "collaboration": "COLLAB", "build_release": "BUILD",
}
# A finding about something that is *missing* may legitimately name a file that does not exist.
_ABSENCE = re.compile(
    r"\b(missing|absent|absence|no|not (?:found|present|exist)|lacks?|lacking|without|"
    r"does not exist|doesn't exist|never)\b",
    re.IGNORECASE,
)


def _norm_text(s: str) -> str:
    return re.sub(r"\W+", " ", s.lower()).strip()


def _locate(root: Path, rel: str) -> Optional[Path]:
    try:
        p = (root / rel).resolve(strict=True)
        p.relative_to(root.resolve())
    except (OSError, ValueError, RuntimeError):
        return None
    return p


def _line_count(path: Path) -> Optional[int]:
    try:
        with open(path, "rb") as fh:
            data = fh.read(config.MAX_FILE_BYTES)
    except OSError:
        return None
    if b"\x00" in data[:8192]:
        return None
    n = data.count(b"\n") + (0 if data.endswith(b"\n") or not data else 1)
    return n


def _line_text(path: Path, line: int) -> Optional[str]:
    try:
        if path.stat().st_size > config.MAX_FILE_BYTES:
            return None
        with open(path, "rb") as fh:
            data = fh.read(config.MAX_FILE_BYTES)
    except OSError:
        return None
    if b"\x00" in data[:8192]:
        return None
    lines = mask_private_keys(data.decode("utf-8", errors="replace")).split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    if line > len(lines):
        return None
    return redact(lines[line - 1].rstrip("\r"))


def _evidence_quotes_line(evidence: str, source_line: str) -> bool:
    excerpts = re.findall(r"`([^`]+)`", redact(evidence))
    redacted_value = re.compile(r"\[REDACTED(?:_[A-Z0-9_-]+)?\]")
    for excerpt in excerpts:
        parts = redacted_value.split(excerpt)
        placeholders = redacted_value.findall(excerpt)
        pattern = "".join(
            re.escape(part) + (r"\[REDACTED(?:_[A-Z0-9_-]+)?\]" if index < len(placeholders) else "")
            for index, part in enumerate(parts)
        )
        if re.search(pattern, source_line):
            return True
    return False


def _coerce_line(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    try:
        n = int(float(value))
    except (TypeError, ValueError):
        return None
    return n if n > 0 else None


def _str(value: Any) -> str:
    return value.strip()[: config.MAX_FIELD_CHARS] if isinstance(value, str) else ""


def finalize(
    raw: list,
    repo_root: Path,
    repo_url: str,
    warn: Callable[[str], None] = lambda _m: None,
) -> dict:
    """Validate and clean `raw` findings. The returned dict always satisfies validate_report()."""
    root = Path(repo_root)
    counters: dict[str, int] = {}
    seen: set = set()
    out: list[dict] = []

    for item in raw if isinstance(raw, list) else []:
        if not isinstance(item, dict):
            warn("dropped a finding that was not an object")
            continue
        description, evidence, recommendation = (
            _str(item.get("description")), _str(item.get("evidence")), _str(item.get("recommendation"))
        )
        if not (description and evidence and recommendation):
            warn(f"dropped finding {item.get('rule_id')!r}: missing description/evidence/recommendation")
            continue

        sev = _str(item.get("severity")).lower()
        sev = _SEVERITY_ALIASES.get(sev, sev)
        if sev not in config.ALLOWED_SEVERITIES:
            sev = "medium"
        cat = re.sub(r"[\s/\-]+", "_", _str(item.get("category")).lower())
        cat = _CATEGORY_ALIASES.get(cat, cat) or "configuration"

        rule_id = _str(item.get("rule_id")).upper()
        # Some models append a field label or punctuation to an otherwise valid ID.
        rule_id = re.split(r"[,;\s]", rule_id, maxsplit=1)[0]
        if rule_id and not re.fullmatch(r"[A-Z][A-Z0-9_-]*", rule_id):
            rule_id = ""
        if not rule_id:
            prefix = _PREFIX.get(cat, "GEN")
            counters[prefix] = counters.get(prefix, 0) + 1
            rule_id = f"{prefix}-{counters[prefix]:03d}"

        file_ = _str(item.get("file")).replace("\\", "/")
        file_ = file_[2:] if file_.startswith("./") else file_
        file_ = file_ or None
        line = _coerce_line(item.get("line"))
        if file_ is None:
            line = None
        else:
            target = _locate(root, file_)
            if target is None:
                if _ABSENCE.search(description):
                    file_, line = None, None  # a 'missing X' finding: the file is legitimately absent
                else:
                    warn(f"dropped {rule_id}: file {file_!r} does not exist in the repository")
                    continue
            elif target.is_dir():
                line = None
            elif line is not None:
                n = _line_count(target)
                if n is None or line > n:
                    line = None
                else:
                    source_line = _line_text(target, line)
                    if source_line is None or not _evidence_quotes_line(evidence, source_line):
                        raise AuditError(
                            f"{rule_id} cites {file_}:{line}, but its evidence does not quote "
                            "text found on that line; include an exact, secret-masked excerpt "
                            "from the cited line"
                        )

        keys = [
            (file_, rule_id, line),
            (file_, _norm_text(description)),
        ]
        if line is not None:
            keys.append((file_, line, cat))
        if any(k in seen for k in keys):
            warn(f"dropped duplicate finding {rule_id}")
            continue
        seen.update(keys)

        out.append({
            "rule_id": rule_id, "category": cat, "severity": sev, "file": file_, "line": line,
            "description": description, "evidence": evidence, "recommendation": recommendation,
        })

    rank = {s: i for i, s in enumerate(config.ALLOWED_SEVERITIES)}
    out.sort(key=lambda v: rank[v["severity"]])
    return redact_obj({"repository": repo_url, "violations": out})


def validate_report(report: Any) -> list[str]:
    """Return a list of problems (empty list = valid)."""
    problems: list[str] = []
    if not isinstance(report, dict):
        return ["report is not an object"]
    if not isinstance(report.get("repository"), str):
        problems.append("repository must be a string")
    vs = report.get("violations")
    if not isinstance(vs, list):
        return problems + ["violations must be an array"]
    for i, v in enumerate(vs):
        if not isinstance(v, dict):
            problems.append(f"violations[{i}] is not an object")
            continue
        for f in REQUIRED_FIELDS:
            if f not in v:
                problems.append(f"violations[{i}] missing field {f}")
        if v.get("severity") not in config.ALLOWED_SEVERITIES:
            problems.append(f"violations[{i}] has invalid severity")
        if v.get("file") is not None and not isinstance(v.get("file"), str):
            problems.append(f"violations[{i}].file must be string or null")
        if v.get("line") is not None and (not isinstance(v.get("line"), int) or isinstance(v.get("line"), bool)):
            problems.append(f"violations[{i}].line must be integer or null")
    return problems


def write_report(path: str, report: dict) -> None:
    """Atomic write: the output file is either the complete valid report or untouched."""
    problems = validate_report(report)
    if problems:
        raise ValueError("refusing to write invalid report: " + "; ".join(problems))
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=".report-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        os.replace(tmp, target)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
