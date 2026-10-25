"""Exception types. Every one of these is turned into `error: ...` + exit code 1 by agent.py."""


class AuditError(Exception):
    """Base class for all expected, user-facing failures."""


class InvalidRepoURL(AuditError):
    """The --repo value is not a public https://github.com/<owner>/<repo> URL."""


class CloneError(AuditError):
    """git clone failed (not found, private, timeout, git missing...)."""


class ConfigError(AuditError):
    """Missing or invalid configuration (e.g. no API key)."""


class LLMError(AuditError):
    """The LLM provider failed in a way retries did not fix."""


class AgentError(AuditError):
    """The agent loop could not produce a report."""
