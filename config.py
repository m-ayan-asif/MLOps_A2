"""Central configuration: limits, allowed values, environment loading.

No logic lives here beyond reading environment variables.
"""
from __future__ import annotations

import os

from errors import ConfigError

# ---- LLM -------------------------------------------------------------------
# Model names churn quickly. Override with LLM_MODEL in .env if this one is retired.
DEFAULT_MODEL = "gemini-3.1-flash-lite"
LLM_TIMEOUT = 300          # seconds per API request
LLM_RETRIES = 5            # attempts per request (exponential backoff)
MAX_LLM_API_CALLS = 5      # total generate_content requests per audit, including retries

# ---- Agent loop ------------------------------------------------------------
MAX_STEPS = 30                 # LLM turns before we force a final report
MAX_CALLS_PER_STEP = 8         # tool calls honoured in a single LLM turn
STEP_WARNING_THRESHOLD = 3     # warn the model when this many steps remain
MAX_COVERAGE_NUDGES = 2        # times submit_report may be held back per run; then it is accepted
CONTEXT_CHAR_BUDGET = 150_000  # old tool outputs are collapsed beyond this
KEEP_RECENT_TOOL_RESULTS = 8

# ---- Clone / git -----------------------------------------------------------
CLONE_DEPTH = 100
CLONE_TIMEOUT = 180            # seconds
GIT_TIMEOUT = 30               # seconds for git log

# ---- Tool output limits ----------------------------------------------------
MAX_LIST_ENTRIES = 500
MAX_WALK_FILES = 20_000
MAX_READ_LINES = 300
MAX_READ_BYTES = 20_000        # characters of formatted output per read_file call
MAX_LINE_CHARS = 500
MAX_FILE_BYTES = 1_000_000     # never read more than this from one file
MAX_SEARCH_HITS = 50
MAX_HITS_PER_FILE = 8
SEARCH_TIME_BUDGET = 20.0      # seconds
MAX_TOOL_OUTPUT_CHARS = 25_000

# ---- Report ----------------------------------------------------------------
ALLOWED_SEVERITIES = ("critical", "high", "medium", "low")
CATEGORIES = (
    "repository_hygiene",
    "dependency_management",
    "code_quality",
    "testing",
    "ci_cd",
    "security",
    "configuration",
    "collaboration",
    "build_release",
)
ALLOWED_CATEGORIES = frozenset(CATEGORIES)
MAX_FIELD_CHARS = 1500


def load_env() -> None:
    """Load a .env file if python-dotenv is installed. Real env vars win."""
    try:
        from dotenv import load_dotenv
    except ImportError:  # pragma: no cover
        return
    load_dotenv()


def get_api_key() -> str:
    key = (os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY") or "").strip()
    if not key:
        raise ConfigError(
            "GEMINI_API_KEY is not set. Copy .env.example to .env and add your key, "
            "or export it in your shell."
        )
    return key


def get_model() -> str:
    return (os.environ.get("LLM_MODEL") or DEFAULT_MODEL).strip()
