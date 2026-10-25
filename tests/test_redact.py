from conftest import FAKE_AWS, FAKE_GH, FAKE_PW
from redact import REDACTED, redact, redact_obj


def test_aws_and_github_tokens_masked():
    out = redact(f"key={FAKE_AWS} gh={FAKE_GH}")
    assert FAKE_AWS not in out and FAKE_GH not in out
    assert "[REDACTED_AWS_ACCESS_KEY]" in out and "[REDACTED_GITHUB_TOKEN]" in out


def test_jwt_and_stripe_masked():
    jwt = "eyJ" + "hbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0" + "." + "abcdefghijk1234567"
    stripe = "sk_" + "live_" + "a1b2c3d4e5f6g7h8i9j0"
    out = redact(f"{jwt} {stripe}")
    assert jwt not in out and stripe not in out


def test_quoted_assignment_keeps_name_masks_value():
    out = redact(f'DB_PASSWORD = "{FAKE_PW}"')
    assert out == f'DB_PASSWORD = "{REDACTED}"'


def test_unquoted_env_style_masked():
    assert redact(f"DB_PASSWORD={FAKE_PW}") == f"DB_PASSWORD={REDACTED}"


def test_json_style_masked():
    assert redact('"password": "abcd1234"') == f'"password": "{REDACTED}"'


def test_url_credentials_masked():
    assert redact("postgres://admin:hunter22xx@db:5432/app") == f"postgres://admin:{REDACTED}@db:5432/app"


def test_references_and_placeholders_untouched():
    for s in [
        "GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}",
        'api_key = os.environ["API_KEY"]',
        'password = os.getenv("PW")',
        "token = refresh_token",
        'token = "${TOKEN}"',
        'api_key = "your-api-key-here"',
        'token_url = "https://auth.example.com/token"',
        'if token == "abcdef12": pass',
        "secret_key = settings.SECRET_KEY",
    ]:
        assert redact(s) == s, s


def test_private_key_block_masked_and_line_count_preserved():
    block = "-----BEGIN RSA PRIVATE " + "KEY-----\nAAAA\nBBBB\nCCCC\n-----END RSA PRIVATE " + "KEY-----"
    text = f"before\n{block}\nafter"
    out = redact(text)
    assert "AAAA" not in out and "BBBB" not in out
    assert out.count("\n") == text.count("\n")
    assert out.startswith("before\n-----BEGIN") and out.endswith("after")


def test_very_long_line_omitted():
    assert redact("x" * 6000) == "[line omitted: 6000 characters]"


def test_idempotent():
    once = redact(f'DB_PASSWORD = "{FAKE_PW}" {FAKE_AWS}')
    assert redact(once) == once


def test_non_strings_and_nested():
    assert redact(None) is None and redact(5) == 5
    obj = {"a": [f'PASSWORD="{FAKE_PW}"', 1], "b": {"c": FAKE_AWS}}
    out = redact_obj(obj)
    assert FAKE_PW not in str(out) and FAKE_AWS not in str(out)
