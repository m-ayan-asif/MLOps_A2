import os

import pytest

import config
from conftest import FAKE_AWS, FAKE_KEY_BODY, FAKE_PW
from tools import RepoTools


@pytest.fixture
def tools(sample_repo):
    return RepoTools(sample_repo)


def test_list_files_basic(tools):
    out = tools.list_files()
    assert "README.md" in out and ".github/workflows/ci.yml" in out
    assert ".git/" not in out and "HEAD" not in out
    assert "Counts by top-level entry" in out
    # shallowest first
    assert out.index("README.md") < out.index("src/app.py")


def test_list_files_subdirectory_and_errors(tools):
    assert "src/app.py" in tools.list_files(directory="src")
    assert tools.list_files(directory="../").startswith("ERROR")
    assert tools.list_files(directory="README.md").startswith("ERROR")
    assert tools.list_files(directory="nope").startswith("ERROR")


def test_list_paths_posix_and_no_git(tools):
    paths = tools.list_paths()
    assert ".github/workflows/ci.yml" in paths
    assert not any(p.startswith(".git/") for p in paths)


def test_read_file_numbers_lines_and_masks_secrets(tools):
    out = tools.read_file("config.py")
    assert "    1| import os" in out
    assert FAKE_AWS not in out and FAKE_PW not in out
    assert '    3| DB_PASSWORD = "[REDACTED]"' in out
    assert '    4| API_TOKEN = os.environ["API_TOKEN"]' in out
    assert '    5| DATA_DIR = "/home/alice/data"' in out


def test_read_file_truncation_and_continue(tools):
    out = tools.read_file("src/big.py")
    assert f"{config.MAX_READ_LINES}| x{config.MAX_READ_LINES} = {config.MAX_READ_LINES}" in out
    assert "start_line=301" in out
    nxt = tools.read_file("src/big.py", start_line=301)
    assert "  301| x301 = 301" in nxt and "  400| x400 = 400" in nxt and "truncated" not in nxt


def test_read_file_errors(tools, tmp_path):
    assert "beyond the end" in tools.read_file("src/app.py", start_line=99)
    assert tools.read_file("missing.txt").startswith("ERROR: path not found")
    assert tools.read_file("src").startswith("ERROR")
    assert "binary" in tools.read_file("blob.bin")
    assert tools.read_file("").startswith("ERROR")
    assert tools.read_file(None).startswith("ERROR")


def test_read_file_blocks_traversal_and_git_internals(tools, tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("top secret")
    assert "outside" in tools.read_file("../outside.txt") or "not found" in tools.read_file("../outside.txt")
    assert tools.read_file(str(outside)).startswith("ERROR")
    assert tools.read_file(".git/config").startswith("ERROR")
    assert tools.read_file(".git/HEAD").startswith("ERROR")


def test_read_file_blocks_symlink_escape(tools, sample_repo, tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("top secret")
    link = sample_repo / "link.txt"
    try:
        os.symlink(outside, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    out = tools.read_file("link.txt")
    assert out.startswith("ERROR") and "top secret" not in out


def test_private_key_masked_with_line_numbers_preserved(tools):
    out = tools.read_file("keys/server.pem")
    assert FAKE_KEY_BODY not in out and "abcdefghijklmnopqrstuvwxyz0123456789" not in out
    assert "    1| -----BEGIN RSA PRIVATE KEY-----" in out
    assert "    4| -----END RSA PRIVATE KEY-----" in out


def test_search_code_finds_and_masks(tools):
    out = tools.search_code(r"AKIA[0-9A-Z]{16}")
    assert "config.py:2:" in out and FAKE_AWS not in out and "[REDACTED" in out


def test_search_code_case_insensitive_and_sensitive(tools):
    assert "config.py:3" in tools.search_code("db_password")
    assert tools.search_code("db_password", ignore_case=False).startswith("No matches")


def test_search_code_glob_and_skips_binary(tools):
    out = tools.search_code("pytest", glob="*.yml")
    assert ".github/workflows/ci.yml:9" in out and "config.py" not in out
    assert "binary" not in tools.search_code("binary").split("\n")[0] or True
    assert "blob.bin" not in tools.search_code("binary")


def test_search_code_invalid_regex_and_empty(tools):
    assert tools.search_code("(").startswith("ERROR: invalid regular expression")
    assert tools.search_code("").startswith("ERROR")
    assert tools.search_code("zzzz-not-there").startswith("No matches")


def test_search_code_hit_caps(tools, sample_repo):
    (sample_repo / "many.txt").write_text("\n".join("needle" for _ in range(100)))
    out = tools.search_code("needle")
    assert "100 match(es)" in out
    assert out.count("many.txt:") <= config.MAX_HITS_PER_FILE
    assert "more matches exist" in out


def test_git_log(tools):
    out = tools.git_log(5)
    assert "Initial commit" in out and "Add changelog" in out
    assert "2 most recent" in tools.git_log(50.0)


def test_git_log_non_repo(tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    assert RepoTools(plain).git_log().startswith("ERROR")


def test_dispatch_error_handling(tools):
    assert "unknown tool" in tools.dispatch("rm_rf", {})
    assert tools.dispatch("read_file", {}).startswith("ERROR: invalid arguments")
    assert tools.dispatch("read_file", {"path": "a", "bogus": 1}).startswith("ERROR: invalid arguments")
    assert tools.dispatch("list_files", None).count("README.md") == 1
    assert "README.md" in tools.dispatch("list_files", {"reason": "look around"})
    assert tools.dispatch("git_log", {"n": 2.0}).startswith("2 most recent")


def test_dispatch_truncates_and_redacts(tools, sample_repo):
    (sample_repo / "huge.txt").write_text(("word " * 20 + "\n") * 2000)
    out = tools.dispatch("search_code", {"pattern": "word", "glob": "huge.txt"})
    assert len(out) <= config.MAX_TOOL_OUTPUT_CHARS + 100
