"""Shared fixtures. Fake secrets are assembled at runtime so no scanner flags this file."""
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

FAKE_AWS = "AKIA" + "IOSFODNN7EXAMPLE"
FAKE_GH = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
FAKE_PW = "Sup3r" + "Secret99"
_BEGIN = "-----BEGIN RSA PRIVATE " + "KEY-----"
_END = "-----END RSA PRIVATE " + "KEY-----"
FAKE_KEY_BODY = "MIIEowIBAAKCAQEAfakefakefakefakefake"


def _git(cwd, *args):
    subprocess.run(
        ["git", "-c", "user.name=Test", "-c", "user.email=test@example.com",
         "-c", "commit.gpgsign=false", *args],
        cwd=cwd, check=True, capture_output=True,
    )


@pytest.fixture
def sample_repo(tmp_path):
    if shutil.which("git") is None:
        pytest.skip("git not installed")
    root = tmp_path / "repo"
    root.mkdir()
    files = {
        "README.md": "# Demo\n",
        "config.py": (
            "import os\n"
            f'AWS_ACCESS_KEY_ID = "{FAKE_AWS}"\n'
            f'DB_PASSWORD = "{FAKE_PW}"\n'
            'API_TOKEN = os.environ["API_TOKEN"]\n'
            'DATA_DIR = "/home/alice/data"\n'
        ),
        ".github/workflows/ci.yml": (
            "name: CI\n"
            "on: pull_request_target\n"
            "permissions: write-all\n"
            "jobs:\n"
            "  test:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "      - run: pytest || true\n"
        ),
        "requirements.txt": "requests\nflask>=1.0\n",
        "blob.bin": b"\x00\x01\x02binary",
        "keys/server.pem": f"{_BEGIN}\n{FAKE_KEY_BODY}\nabcdefghijklmnopqrstuvwxyz0123456789\n{_END}\n",
        "src/app.py": "def main():\n    return 1\n",
        "src/big.py": "\n".join(f"x{i} = {i}" for i in range(1, 401)) + "\n",
    }
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content if isinstance(content, bytes) else content.encode())
    _git(root, "init", "-q")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "Initial commit")
    (root / "CHANGELOG.md").write_text("changes\n")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "Add changelog")
    return root


@pytest.fixture
def healthy_repo(sample_repo, tmp_path):
    """A clean variant for checking that an empty report is accepted on healthy input."""
    root = tmp_path / "healthy-repo"
    shutil.copytree(sample_repo, root)
    (root / "config.py").write_text(
        'import os\n'
        'AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")\n'
        'DB_PASSWORD = os.environ.get("DB_PASSWORD")\n'
        'API_TOKEN = os.environ["API_TOKEN"]\n'
        'DATA_DIR = os.environ.get("DATA_DIR", "/tmp/data")\n',
        encoding="utf-8",
    )
    (root / "keys" / "server.pem").unlink()
    (root / "keys").rmdir()
    return root


@pytest.fixture
def fixture_only_repo(tmp_path):
    """Healthy project whose only credential-like literal is an obvious placeholder in tests/."""
    if shutil.which("git") is None:
        pytest.skip("git not installed")
    root = tmp_path / "fixture-repo"
    root.mkdir()
    files = {
        "README.md": "# Lib\n",
        "pyproject.toml": "[project]\nname = 'lib'\ndependencies = ['requests>=2.31,<3']\n",
        ".github/workflows/ci.yml": (
            "on: [push, pull_request]\npermissions:\n  contents: read\njobs:\n  t:\n"
            "    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"
            "      - run: pytest\n"
        ),
        "src/lib.py": "def f():\n    return 1\n",
        "tests/test_lib.py": 'TEST_PASSWORD = "test1234"\n\n\ndef test_f():\n    assert True\n',
    }
    for rel, content in files.items():
        f = root / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(content, encoding="utf-8")
    _git(root, "init", "-q")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "Initial commit")
    return root
