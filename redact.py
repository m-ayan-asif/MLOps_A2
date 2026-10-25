"""Secret masking. Leaf module: imports nothing from the project.

Everything the LLM sees, everything written to the trace, and everything written to the
final report passes through here, so secret *values* never leave the process. The variable
name and surrounding context are kept so the model can still tell a credential is present.

Line counts are always preserved (multi-line private keys are masked line by line) so that
line numbers reported by read_file stay accurate.
"""
from __future__ import annotations

import re
from typing import Any

REDACTED = "[REDACTED]"
MAX_LINE_CHARS = 5000  # longer lines are replaced entirely (minified bundles, blobs)

_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----.*?"
    r"-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----",
    re.DOTALL,
)

_TOKENS = [
    (re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{16}\b"), "AWS_ACCESS_KEY"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"), "GITHUB_TOKEN"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{30,}"), "GITHUB_TOKEN"),
    (re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}"), "GITLAB_TOKEN"),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}"), "GOOGLE_API_KEY"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}"), "SLACK_TOKEN"),
    (re.compile(r"\b[sr]k_(?:live|test)_[0-9a-zA-Z]{16,}"), "STRIPE_KEY"),
    (re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}"), "API_KEY"),
    (re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), "NPM_TOKEN"),
    (re.compile(r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}"), "SENDGRID_KEY"),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"), "JWT"),
]

_URL_CREDS = re.compile(
    r"(?P<pre>\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:/@\"'<>]+:)(?P<pw>[^\s@/\"'<>]+)(?P<post>@)"
)

_KEYWORDS = (
    r"(?:password|passwd|pwd|passphrase|secret|token|api[_\-]?key|apikey|access[_\-]?key|"
    r"private[_\-]?key|credentials?|auth[_\-]?key|client[_\-]?secret)"
)
# Bounded quantifiers on both sides of the keyword keep this linear-ish on long lines.
_KV = re.compile(
    r"(?P<key>[A-Za-z0-9_.\-]{0,40}" + _KEYWORDS + r"[A-Za-z0-9_.\-]{0,40})"
    r"(?P<sep>[\"']?\s*[:=]\s*)"
    r"(?:(?P<q>[\"'])(?P<qval>[^\"'\s]{4,})(?P=q)"
    r"|(?P<uval>[^\s\"'#,;()\[\]{}<>$.]{6,}))",
    re.IGNORECASE,
)
# Keys that name *where* a secret lives, not the secret itself.
_SAFE_KEY_SUFFIXES = (
    "_url", "_path", "_file", "_name", "_endpoint", "_header", "_type",
    "_length", "_expiry", "_ttl", "_env", "_var", "_field", "_dir",
)
# Values that are references or placeholders, not literals.
_SAFE_VALUE = re.compile(
    r"^(?:\$|\{\{|<|%|os\.|process\.|env\.|getenv|System\.|ENV\[|config\.|settings\.|secrets\.|"
    r"your[_\-]|x{4,}$|\*{3,}|null$|none$|true$|false$|\[REDACTED|https?://[^@]*$)",
    re.IGNORECASE,
)


def _mask_private_key(match: re.Match) -> str:
    lines = match.group(0).split("\n")
    if len(lines) == 1:
        return "[REDACTED PRIVATE KEY]"
    return "\n".join([lines[0]] + [REDACTED] * (len(lines) - 2) + [lines[-1]])


def _url_repl(m: re.Match) -> str:
    pw = m.group("pw")
    if pw.startswith(("$", "{", "[REDACTED")):
        return m.group(0)
    return m.group("pre") + REDACTED + m.group("post")


def _kv_repl(m: re.Match) -> str:
    key = m.group("key")
    if key.lower().endswith(_SAFE_KEY_SUFFIXES):
        return m.group(0)
    val = m.group("qval") or m.group("uval")
    if _SAFE_VALUE.match(val):
        return m.group(0)
    quoted = m.group("q")
    # Unquoted values only count as secrets when they contain a digit, so that plain
    # identifiers (`token = refresh_token`) are not mistaken for literals.
    if not quoted and not any(c.isdigit() for c in val):
        return m.group(0)
    if quoted:
        return f"{key}{m.group('sep')}{quoted}{REDACTED}{quoted}"
    return f"{key}{m.group('sep')}{REDACTED}"


def mask_private_keys(text: str) -> str:
    """Whole-text pass for PEM/PGP private key blocks (line count preserved)."""
    if "PRIVATE KEY" not in text:
        return text
    return _PRIVATE_KEY.sub(_mask_private_key, text)


def _redact_line(line: str) -> str:
    if len(line) > MAX_LINE_CHARS:
        return f"[line omitted: {len(line)} characters]"
    for rx, label in _TOKENS:
        line = rx.sub(f"[REDACTED_{label}]", line)
    line = _URL_CREDS.sub(_url_repl, line)
    line = _KV.sub(_kv_repl, line)
    return line


def redact(text: Any) -> Any:
    """Mask secret values in `text`. Non-strings are returned unchanged. Idempotent."""
    if not isinstance(text, str) or not text:
        return text
    text = mask_private_keys(text)
    return "\n".join(_redact_line(line) for line in text.split("\n"))


def redact_obj(obj: Any) -> Any:
    """Recursively redact every string inside dicts / lists / tuples."""
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, dict):
        return {k: redact_obj(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [redact_obj(v) for v in obj]
    return obj
