"""Tool declarations shown to the LLM (provider-neutral JSON-schema dicts).

llm.py converts these to the provider's format. `submit_report` is a *virtual* tool: it is
handled by the agent loop and ends the investigation.
"""
from __future__ import annotations

import config

SUBMIT = "submit_report"

_REASON = {
    "type": "string",
    "description": (
        "One short sentence: what you have observed so far and why you are making this call. "
        "This is logged as your reasoning trace."
    ),
}

LIST_FILES = {
    "name": "list_files",
    "description": (
        "List files in the repository (shallowest first, with sizes). The clone contains only "
        "git-tracked files, so anything listed IS committed. Call this first to understand the "
        "project; pass a subdirectory to drill into a large directory."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "directory": {
                "type": "string",
                "description": "Optional subdirectory relative to the repo root. Omit for the root.",
            },
            "reason": _REASON,
        },
        "required": ["reason"],
    },
}

READ_FILE = {
    "name": "read_file",
    "description": (
        "Read a text file with numbered lines ('  12| code'). Use the numbers for the `line` "
        "field of findings. Long files are truncated: pass start_line to continue. Secret "
        "values appear as [REDACTED...]; a masked literal means a hardcoded value exists."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "File path relative to the repo root."},
            "start_line": {"type": "integer", "description": "First line to show (default 1)."},
            "reason": _REASON,
        },
        "required": ["path", "reason"],
    },
}

SEARCH_CODE = {
    "name": "search_code",
    "description": (
        "Regex search across all text files. Returns 'path:line: snippet'. Use it to scan the "
        "whole repo for suspicious patterns (credentials, absolute paths, risky workflow "
        "settings, risky functions) instead of reading every file."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "pattern": {"type": "string", "description": "Python regular expression."},
            "glob": {
                "type": "string",
                "description": "Optional filename filter, e.g. '*.yml' or '.github/workflows/*'.",
            },
            "ignore_case": {"type": "boolean", "description": "Case-insensitive (default true)."},
            "reason": _REASON,
        },
        "required": ["pattern", "reason"],
    },
}

GIT_LOG = {
    "name": "git_log",
    "description": (
        "Show recent commits (hash, date, author, subject). Use it to judge commit hygiene, "
        "how many people contribute, and whether history hints at problems."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "n": {"type": "integer", "description": "Number of commits (1-100, default 20)."},
            "reason": _REASON,
        },
        "required": ["reason"],
    },
}

VIOLATION = {
    "type": "object",
    "properties": {
        "rule_id": {"type": "string", "description": "Short ID such as SEC-001, CI-002, DEP-001."},
        "category": {"type": "string", "enum": list(config.CATEGORIES)},
        "severity": {"type": "string", "enum": list(config.ALLOWED_SEVERITIES)},
        "file": {
            "type": "string",
            "nullable": True,
            "description": "Repo-relative path of the offending file, or null (e.g. a file that is missing).",
        },
        "line": {
            "type": "integer",
            "nullable": True,
            "description": "1-based line number from read_file/search_code output, or null.",
        },
        "description": {"type": "string", "description": "What is wrong, in one sentence."},
        "evidence": {
            "type": "string",
            "description": "What you observed and where. Never include secret values.",
        },
        "recommendation": {"type": "string", "description": "A concrete fix."},
    },
    "required": [
        "rule_id", "category", "severity", "file", "line",
        "description", "evidence", "recommendation",
    ],
}

SUBMIT_REPORT = {
    "name": SUBMIT,
    "description": (
        "Finish the audit by submitting every verified finding in ONE call. Use an empty list if "
        "the repository looks healthy. Only report what you verified through tool results."
    ),
    "parameters": {
        "type": "object",
        "properties": {"violations": {"type": "array", "items": VIOLATION}},
        "required": ["violations"],
    },
}

INSPECTION_TOOLS = [LIST_FILES, READ_FILE, SEARCH_CODE, GIT_LOG]
TOOL_DECLARATIONS = INSPECTION_TOOLS + [SUBMIT_REPORT]
