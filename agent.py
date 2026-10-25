#!/usr/bin/env python3
"""CLI entry point:  python agent.py --repo <github_url> --output report.json"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import config
from agent_loop import TraceLogger, run_agent
from errors import AuditError
from llm import LLMClient
from redact import redact
from repo import canonical_url, clone_repo
from report import finalize, write_report
from tools import RepoTools


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="agent.py",
        description="AI agent that audits a public GitHub repository for DevOps best-practice violations.",
    )
    p.add_argument("--repo", required=True, help="public repository URL, e.g. https://github.com/owner/repo")
    p.add_argument("--output", default="report.json", help="path of the JSON report to write (default: report.json)")
    p.add_argument("--trace", default="trace.jsonl", help="path of the tool-call trace (JSONL); default trace.jsonl")
    p.add_argument("--max-steps", type=int, default=config.MAX_STEPS, help="maximum LLM turns")
    return p


def _preflight_output(path: str) -> None:
    """Fail before spending API calls if the report cannot be written."""
    p = Path(path)
    if p.is_dir():
        raise AuditError(f"output path {path!r} is a directory")
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        existed = p.exists()
        with open(p, "a", encoding="utf-8"):
            pass
        if not existed:
            p.unlink()
    except OSError as e:
        raise AuditError(f"cannot write output file {path!r}: {e.strerror or e}") from None


def _warn(msg: str) -> None:
    print(f"warning: {msg}", file=sys.stderr)


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    trace = None
    try:
        config.load_env()
        url = canonical_url(args.repo)          # validates the URL
        api_key = config.get_api_key()
        _preflight_output(args.output)
        llm = LLMClient(api_key, config.get_model())
        trace = TraceLogger(args.trace)
        with clone_repo(url) as root:
            print(f"Cloned {url}; starting audit with {config.get_model()}", file=sys.stderr)
            tools = RepoTools(root)
            raw = run_agent(url, tools, llm, max_steps=args.max_steps, trace=trace)
            report = finalize(raw, root, url, warn=_warn)
        write_report(args.output, report)
        if report["violations"]:
            print(f"Done: {len(report['violations'])} violation(s) written to {args.output}", file=sys.stderr)
        else:
            print(f"Healthy repo: no violations found (report written to {args.output})", file=sys.stderr)
        return 0
    except AuditError as e:
        print(f"error: {redact(str(e))}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("error: interrupted", file=sys.stderr)
        return 130
    except Exception as e:  # noqa: BLE001 - last-resort guard so we always exit cleanly
        print(f"error: unexpected {type(e).__name__}: {redact(str(e))}", file=sys.stderr)
        return 1
    finally:
        if trace:
            trace.close()


if __name__ == "__main__":
    sys.exit(main())
