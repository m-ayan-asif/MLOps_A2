# DevOps Repository Auditing Agent

An LLM-driven agent that inspects a public GitHub repository, decides for itself which files and
patterns to examine, and writes an evidence-based JSON report of DevOps best-practice violations.

```
python agent.py --repo https://github.com/<owner>/<repo>
```

## How it works

The agent is an explicit Python loop (no agent frameworks; the only LLM dependency is the basic
`google-genai` SDK):

```
Observe -> Reason -> Select tool -> Execute tool -> Interpret result -> ... -> Report
```

1. `agent.py` validates the URL, checks the API key, and shallow-clones the repo into a temp dir
   (git hooks disabled, no credential prompts, always cleaned up).
2. `agent_loop.py` sends the conversation to the LLM with the tool declarations. **The LLM chooses
   every tool call**, including follow-ups (e.g. spot a workflow in the listing, read it, then
   search the whole repo for related patterns). Each call carries a `reason` that is logged.
3. `tools.py` executes the call and returns a size-capped, secret-masked string. The result goes
   back to the LLM, which interprets it and decides what to do next.
4. The LLM ends the investigation by calling `submit_report`. If it tries to finish without
   having read source or configuration, applicable workflows or dependency manifests, or
   without running a targeted credential search (a match-all search does not count), the loop
   holds the submission back and lists the gaps. An empty report is also challenged if the
   model saw masked credential literals, so it can decide whether they are real defects or
   benign test fixtures. The loop nudges at most twice per run (`MAX_COVERAGE_NUDGES`). After
   that, a non-empty report may proceed, but an empty report is rejected if required inspection
   is incomplete or masked credential assignments in non-test files remain unresolved. The same
   rule applies in the max-step fallback, preventing incomplete audits from being reported as
   healthy. The loop never creates findings and never names files to open.
5. `report.py` validates every finding, checks that cited files exist and lines are in range,
   verifies that each cited line contains an exact secret-masked excerpt quoted in the evidence,
   removes duplicates, redacts secrets, and writes the JSON atomically. A mismatch fails the
   audit instead of producing a success-shaped report.

### Files

| File | Responsibility |
|---|---|
| `agent.py` | CLI, orchestration, exit codes |
| `agent_loop.py` | the agent loop, trace logging, context compaction, coverage nudge |
| `tools.py` | `list_files`, `read_file`, `search_code`, `git_log` + safe `dispatch` |
| `tool_schemas.py` | tool declarations shown to the LLM |
| `prompts.py` | system prompt and nudge messages |
| `llm.py` | Gemini wrapper: message translation, retries/budget, response parsing |
| `report.py` | validation, evidence verification, dedupe, atomic JSON write |
| `repo.py` | URL validation, safe clone, cleanup |
| `redact.py` | secret masking used on tool output, trace and report |
| `config.py`, `errors.py` | limits / env loading; exception types |

### Tools available to the LLM

| Tool | Purpose |
|---|---|
| `list_files(directory?)` | repository structure (shallowest first, with sizes) |
| `read_file(path, start_line?)` | numbered lines of a text file, truncated with a continue hint |
| `search_code(pattern, glob?, ignore_case?)` | regex search across the repo |
| `git_log(n?)` | recent commits |
| `submit_report(violations)` | ends the audit (handled by the loop) |

## Run it (TA quick start)

You need Python 3.10 or newer, Git, and a Gemini API key. From the project directory, create
and activate a virtual environment, install the dependencies, then create `.env` from the example.
Add the API key to `.env`; do not submit or commit that file.

**Windows PowerShell**

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
notepad .env
python agent.py --repo https://github.com/owner/repository
```

**macOS, Linux, or WSL**

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
nano .env
python agent.py --repo https://github.com/owner/repository
```

Replace the example URL with the public GitHub repository to audit. The command writes
`report.json` and `trace.jsonl` in the current directory. Add `--output path/to/report.json` or
`--trace path/to/trace.jsonl` to choose other paths. The trace records the agent's tool calls and
is useful for reviewing what it inspected. The audit uses Gemini 3.1 Flash-Lite by default; set
`LLM_MODEL` in `.env` to override it.
Each audit makes no more than five Gemini API requests total, including retries.

`.env` variables:

| Variable | Required | Meaning |
|---|---|---|
| `GEMINI_API_KEY` | yes | Google AI Studio API key |
| `LLM_MODEL` | no | model name; defaults to `gemini-3.1-flash-lite` |

## Usage

```bash
python agent.py --repo https://github.com/<owner>/<repo>
```

Options: `--trace PATH` (tool-call trace, default `trace.jsonl`), `--max-steps N` (default 30).

* Exit code `0`: audit completed, report written (with `"violations": []` if none found; stderr then says `Healthy repo: no violations found`).
* Exit code `1`: fatal error (bad URL, private/missing repo, missing key, API failure...). A clear
  `error: ...` message goes to stderr and no report is written.
* Progress is printed to stderr. `trace.jsonl` has one JSON line per tool call: step, tool, args,
  the model's stated reason, and a preview of the result.

### Report format

```json
{
  "repository": "https://github.com/example/demo-project",
  "violations": [
    {
      "rule_id": "SEC-001", "category": "security", "severity": "critical",
      "file": "config.py", "line": 17,
      "description": "...", "evidence": "...", "recommendation": "..."
    }
  ]
}
```

Severities: `critical`, `high`, `medium`, `low`. `file`/`line` are `null` when not applicable
(e.g. a missing file). Categories: repository_hygiene, dependency_management, code_quality,
testing, ci_cd, security, configuration, collaboration, build_release.

## Safety and precision measures

* The inspected repo is never modified and **nothing from it is ever executed** (no pytest/ruff
  runs, no scripts, git hooks disabled).
* All file access is confined to the clone: path traversal, absolute paths, symlink escapes and
  `.git` internals are rejected.
* Secret values are masked (`[REDACTED...]`) in tool output *before* the LLM sees them, in the
  trace, and in the final report. The model can still see that a literal credential exists and
  where. Variable names and `${{ secrets.X }}` / `os.environ[...]` references are left intact.
* Findings citing a file that does not exist are dropped (except "missing X" findings, whose
  file is nulled); out-of-range line numbers are nulled; quoted evidence excerpts are checked
  against cited source lines; mismatched evidence fails the audit; duplicates are removed.
* The prompt tells the model that absent optional files are not defects when equivalents exist
  (e.g. `pyproject.toml` vs `requirements.txt`, other lockfiles, linter config in `pyproject.toml`)
  and that remote settings such as branch protection cannot be inferred.
* API calls use bounded retries with exponential backoff; all tool failures are returned to the
  model as error strings instead of crashing the loop; clone and git calls have timeouts.

## Tests

```bash
pytest
```

Tests cover the tools (traversal, truncation, redaction, bad regex), URL validation and clone
safety, redaction patterns, report validation/dedupe/verification, the agent loop with a scripted
fake LLM (dispatch, error handling, step limit, nudge budget, healthy-repo acceptance, unresolved
credential-evidence rejection, parallel-call cap, trace content),
the Gemini wrapper (retries, message translation, and total API call budget), and CLI exit
behaviour. No test calls the
network or a real LLM.

## Generating `sample_report.json`

An authentic run output is included in the repository. Regenerate it with:

```bash
python agent.py --repo https://github.com/<owner>/<repo> --output sample_report.json
```

## Limitations

* Only public GitHub repositories over `https`. History is a shallow clone (100 commits).
* The audit is bounded by a step budget, tool-output size caps, and files under 1 MB.
* Findings are LLM judgements. For line-specific findings, the agent verifies the quoted
  secret-masked excerpt is present on the cited line, but cannot prove the interpretation is
  correct, confirm remote settings, or run the project's tests.
* Secret masking is pattern-based and cannot catch every possible credential format.
