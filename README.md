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

## Setup

### Requirements

- Python 3.10 or newer
- Git installed and available on `PATH` (the agent uses it to clone public repositories)
- A Gemini API key with access to the configured Gemini model

Run the commands from the directory containing `agent.py` and `requirements.txt` (the repository
root). Check that a supported Python version and Git are available:

**Windows PowerShell**

```powershell
py -3 --version
git --version
```

**macOS, Linux, or WSL**

```bash
python3 --version
git --version
```

### Install dependencies and configure the API key

Create a virtual environment, install the project dependencies, and copy the example environment
file. Put your own API key in `.env`; never commit or share that file. `.gitignore` excludes it.

**Windows PowerShell**

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env
notepad .env
```

If `py -3` selects Python older than 3.10, install a supported Python version and use its
interpreter to create the environment. Use `.\.venv\Scripts\python.exe` to run the agent and tests
without activating the environment.

**macOS, Linux, or WSL**

```bash
python3 -m venv .venv
./.venv/bin/python -m pip install -r requirements.txt
cp .env.example .env
${EDITOR:-nano} .env
```

The `.env.example` file documents the supported settings:

`.env` variables:

| Variable | Required | Meaning |
|---|---|---|
| `GEMINI_API_KEY` | yes | Google AI Studio API key |
| `LLM_MODEL` | no | model name; defaults to `gemini-3.1-flash-lite` |

The key can also be supplied as the `GEMINI_API_KEY` environment variable instead of putting it in
`.env`. The application accepts `GOOGLE_API_KEY` as a fallback. A value set in the process
environment takes precedence over the value in `.env`.

## Run an audit

**Windows PowerShell**

```powershell
.\.venv\Scripts\python.exe agent.py --repo https://github.com/owner/repository
```

**macOS, Linux, or WSL**

```bash
./.venv/bin/python agent.py --repo https://github.com/owner/repository
```

Replace `owner/repository` with the path of a **public GitHub repository**. Only HTTPS GitHub
repository URLs are accepted; private repositories and other Git hosts are not supported.

Options:

- `--output PATH`: JSON report path (default: `sample_report.json`)
- `--trace PATH`: tool-call trace path (default: `trace.jsonl`)
- `--max-steps N`: maximum LLM turns (default: 30)

For example, to choose both output paths:

**Windows PowerShell**

```powershell
.\.venv\Scripts\python.exe agent.py --repo https://github.com/owner/repository --output results\audit.json --trace results\audit.jsonl
```

**macOS, Linux, or WSL**

```bash
./.venv/bin/python agent.py --repo https://github.com/owner/repository --output results/audit.json --trace results/audit.jsonl
```

The parent directories for the report and trace are created when needed. The report is written
only after a completed audit; on a fatal error the program exits nonzero and prints an error to
stderr. Progress and the model's tool-call reasons are printed to stderr. The JSONL trace records
tool calls and result previews; it is useful for reviewing what the agent inspected. Do not share
traces without reviewing them first.

* Exit code `0`: audit completed, report written (with `"violations": []` if none found; stderr then says `Healthy repo: no violations found`).
* Exit code `1`: fatal error (bad URL, private/missing repo, missing key, API failure...). A clear
  `error: ...` message goes to stderr and no report is written.
* Exit code `130`: interrupted by the user.

The default model is Gemini 3.1 Flash-Lite. Set `LLM_MODEL` in `.env` or the process environment
to use another compatible model. Each audit makes no more than five Gemini API requests total,
including retries and, if needed, one request to discover fallback models. If the selected model
is unavailable or overloaded, the agent checks which models available to your API key support
content generation, tries flash models first, and continues with a fallback within that same
request limit. Once a fallback succeeds, it is used for the rest of the audit.

## Run the tests

Install the dependencies as above, then run the automated tests from the repository root:

**Windows PowerShell**

```powershell
.\.venv\Scripts\python.exe -m pytest
```

**macOS, Linux, or WSL**

```bash
./.venv/bin/python -m pytest
```

The tests cover the tools (traversal, truncation, redaction, bad regex), URL validation and clone
safety, report validation and evidence verification, the agent loop with a scripted fake LLM,
the Gemini wrapper, and CLI exit behaviour. They do not call the network or a real LLM.

## Report format

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

## Generating `sample_report.json`

By default, an audit writes its report to `sample_report.json`, which is included as an authentic
example output. To generate a new sample report, run:

**Windows PowerShell**

```powershell
.\.venv\Scripts\python.exe agent.py --repo https://github.com/owner/repository
```

**macOS, Linux, or WSL**

```bash
./.venv/bin/python agent.py --repo https://github.com/owner/repository
```

## Limitations

* Only public GitHub repositories over `https`. History is a shallow clone (100 commits).
* The audit is bounded by a step budget, tool-output size caps, and files under 1 MB.
* Findings are LLM judgements. For line-specific findings, the agent verifies the quoted
  secret-masked excerpt is present on the cited line, but cannot prove the interpretation is
  correct, confirm remote settings, or run the project's tests.
* Secret masking is pattern-based and cannot catch every possible credential format.
