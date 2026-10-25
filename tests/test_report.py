import json

import pytest

from conftest import FAKE_AWS, FAKE_PW
from errors import AuditError
from report import finalize, validate_report, write_report

URL = "https://github.com/o/r"


def v(**kw):
    base = {
        "rule_id": "SEC-001", "category": "security", "severity": "high", "file": "config.py",
        "line": 3, "description": "Hardcoded credential",
        "evidence": '`DB_PASSWORD = "[REDACTED]"` password literal in source',
        "recommendation": "Use an environment variable",
    }
    base.update(kw)
    return base


def test_valid_finding_passes_and_report_valid(sample_repo):
    rep = finalize([v()], sample_repo, URL)
    assert validate_report(rep) == []
    assert rep["repository"] == URL and rep["violations"][0]["line"] == 3


def test_empty_report_is_valid(sample_repo):
    rep = finalize([], sample_repo, URL)
    assert rep == {"repository": URL, "violations": []}
    assert validate_report(rep) == []


def test_non_list_input_gives_empty(sample_repo):
    assert finalize(None, sample_repo, URL)["violations"] == []


def test_missing_fields_dropped(sample_repo):
    raw = [v(evidence=""), v(rule_id="X", description=""), "junk", 5, v(rule_id="OK-1", recommendation="  ")]
    assert finalize(raw, sample_repo, URL)["violations"] == []


def test_severity_and_category_normalised(sample_repo):
    f = finalize([v(severity="MAJOR", category="GitHub Actions")], sample_repo, URL)["violations"][0]
    assert f["severity"] == "high" and f["category"] == "ci_cd"
    assert finalize([v(severity="whatever")], sample_repo, URL)["violations"][0]["severity"] == "medium"


def test_missing_rule_id_generated(sample_repo):
    f = finalize([v(rule_id="")], sample_repo, URL)["violations"][0]
    assert f["rule_id"] == "SEC-001"


def test_rule_id_trailing_model_noise_is_removed(sample_repo):
    f = finalize([v(rule_id="SEC-001,SEVERITY:")], sample_repo, URL)["violations"][0]
    assert f["rule_id"] == "SEC-001"


def test_nonexistent_file_dropped(sample_repo):
    warnings = []
    rep = finalize([v(file="ghost.py", description="Hardcoded credential in ghost")], sample_repo, URL, warnings.append)
    assert rep["violations"] == [] and any("ghost.py" in w for w in warnings)


def test_missing_file_finding_keeps_but_nulls_file(sample_repo):
    f = finalize(
        [v(rule_id="REPO-001", category="repository_hygiene", file="CONTRIBUTING.md", line=1,
           description="Missing CONTRIBUTING guide")], sample_repo, URL)["violations"][0]
    assert f["file"] is None and f["line"] is None


def test_line_out_of_range_nulled(sample_repo):
    assert finalize([v(line=9999)], sample_repo, URL)["violations"][0]["line"] is None
    assert finalize([v(line=0)], sample_repo, URL)["violations"][0]["line"] is None
    assert finalize([v(line="3")], sample_repo, URL)["violations"][0]["line"] == 3
    assert finalize([v(line=3.0)], sample_repo, URL)["violations"][0]["line"] == 3
    assert finalize([v(line=True)], sample_repo, URL)["violations"][0]["line"] is None


def test_unverified_evidence_is_rejected(sample_repo):
    with pytest.raises(AuditError, match=r"config\.py:3"):
        finalize([v(evidence="The configuration uses a hardcoded password")], sample_repo, URL)


def test_evidence_excerpt_must_match_cited_line(sample_repo):
    with pytest.raises(AuditError, match=r"config\.py:3"):
        finalize([v(evidence='`AWS_ACCESS_KEY_ID = "[REDACTED]"`')], sample_repo, URL)


def test_private_key_evidence_uses_same_masking_as_tool_output(sample_repo):
    finding = v(
        file="keys/server.pem", line=2,
        evidence="`[REDACTED]` private key material",
    )
    assert finalize([finding], sample_repo, URL)["violations"][0]["line"] == 2


def test_file_none_forces_line_none(sample_repo):
    f = finalize([v(file=None, line=5)], sample_repo, URL)["violations"][0]
    assert f["file"] is None and f["line"] is None


def test_directory_and_path_normalisation(sample_repo):
    assert finalize([v(file="src", line=3)], sample_repo, URL)["violations"][0]["line"] is None
    f = finalize([
        v(file="./.github\\workflows\\ci.yml", line=9, evidence="`- run: pytest || true`")
    ], sample_repo, URL)["violations"][0]
    assert f["file"] == ".github/workflows/ci.yml" and f["line"] == 9


def test_traversal_file_dropped(sample_repo):
    assert finalize([v(file="../../etc/passwd")], sample_repo, URL)["violations"] == []


def test_dedupe(sample_repo):
    raw = [
        v(),
        v(rule_id="SEC-009", description="HARDCODED credential!!"),           # same text
        v(rule_id="SEC-001", description="Another wording", line=3),          # same id+line
        v(rule_id="CFG-001", description="Different wording", line=3),        # same file+line+category
        v(rule_id="SEC-002", description="Different issue", line=2,
          evidence='`AWS_ACCESS_KEY_ID = "[REDACTED]"`'),
    ]
    out = finalize(raw, sample_repo, URL)["violations"]
    assert [x["line"] for x in out] == [3, 2]


def test_sorted_by_severity(sample_repo):
    raw = [
        v(rule_id="A-1", severity="low", line=1, description="a", evidence="`import os`"),
        v(rule_id="B-1", severity="critical", line=2, description="b",
          evidence='`AWS_ACCESS_KEY_ID = "[REDACTED]"`'),
    ]
    assert [x["severity"] for x in finalize(raw, sample_repo, URL)["violations"]] == ["critical", "low"]


def test_secrets_redacted_in_all_fields(sample_repo):
    rep = finalize([v(evidence=f'`DB_PASSWORD = "{FAKE_PW}"` and {FAKE_AWS}')], sample_repo, URL)
    text = json.dumps(rep)
    assert FAKE_PW not in text and FAKE_AWS not in text


def test_validate_report_catches_problems():
    assert validate_report([]) == ["report is not an object"]
    assert validate_report({"repository": "x", "violations": "no"})
    bad = {"repository": "x", "violations": [{"severity": "nope"}]}
    assert len(validate_report(bad)) > 1


def test_write_report_atomic_and_valid(tmp_path, sample_repo):
    out = tmp_path / "nested" / "report.json"
    write_report(str(out), finalize([v()], sample_repo, URL))
    assert json.loads(out.read_text(encoding="utf-8"))["violations"][0]["rule_id"] == "SEC-001"
    assert not list(out.parent.glob(".report-*"))


def test_write_report_refuses_invalid(tmp_path):
    with pytest.raises(ValueError):
        write_report(str(tmp_path / "r.json"), {"repository": "x"})
    assert not (tmp_path / "r.json").exists()
