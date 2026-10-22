"""Secret detector tests. Every fake secret is built at runtime by concatenation."""

import base64

import pytest

from airlock.detectors import secrets
from airlock.detectors.secrets import detect, luhn_ok, mask
from airlock.types import Category, Segment, Severity, Source

AWS = "AKIA" + "Q" * 16
GITHUB = "ghp_" + "a1" * 18
ANTHROPIC = "sk-ant-" + "api03-" + "Zx9" * 10
OPENAI = "sk-" + "proj-" + "Ab3" * 10
OPENAI_LEGACY = "sk-" + "T3st" * 9
SLACK = "xox" + "b-" + "1234567890-" + "abcdefghij"
STRIPE = "sk_" + "live_" + "Rk4" * 8
GOOGLE = "AI" + "za" + "Sy" + "B" * 33
JWT = "ey" + "JhbGciOiJIUzI1NiJ9" + "." + "ey" + "JzdWIiOiIxMjM0NTY3ODkwIn0" + "." + "c2lnbmF0dXJl"


def _seed() -> str:
    payload = bytes([18 << 3]) + bytes(range(32))
    crc = secrets._crc16_xmodem(payload)
    return base64.b32encode(payload + crc.to_bytes(2, "little")).decode()


def seg(text: str, source: Source = Source.TOOL_RESULT) -> Segment:
    return Segment(source=source, text=text, path=("messages", 0, "content"))


def ids(findings) -> list[str]:
    return [f.rule_id for f in findings]


@pytest.mark.parametrize(
    "secret,rule",
    [
        (AWS, "SEC-AWS-KEY"),
        ("ASIA" + "Z9" * 8, "SEC-AWS-KEY"),
        (GITHUB, "SEC-GITHUB-TOKEN"),
        ("github_" + "pat_" + "11AB" * 8, "SEC-GITHUB-TOKEN"),
        (ANTHROPIC, "SEC-ANTHROPIC-KEY"),
        (OPENAI, "SEC-OPENAI-KEY"),
        (OPENAI_LEGACY, "SEC-OPENAI-KEY"),
        (SLACK, "SEC-SLACK-TOKEN"),
        (STRIPE, "SEC-STRIPE-KEY"),
        (GOOGLE, "SEC-GOOGLE-API-KEY"),
        (JWT, "SEC-JWT"),
    ],
)
def test_token_rules_report_exact_span_and_masked_evidence(secret, rule):
    text = f"config loaded: {secret} (do not share)"
    findings = detect(seg(text))
    assert ids(findings) == [rule]
    f = findings[0]
    assert text[f.start : f.end] == secret
    assert f.evidence == secret[:4] + "***"
    assert secret not in f.evidence
    assert f.category is Category.SECRET


def test_severities():
    assert detect(seg(AWS))[0].severity is Severity.HIGH
    assert detect(seg(JWT))[0].severity is Severity.MEDIUM


def test_anthropic_key_not_reported_as_openai():
    assert ids(detect(seg(ANTHROPIC))) == ["SEC-ANTHROPIC-KEY"]


def test_private_key_block_is_critical_and_header_only_in_evidence():
    body = "MIIEow" + "IBAAKCAQEA" * 5
    pem = "-----BEGIN " + "RSA PRIVATE KEY-----\n" + body + "\n-----END " + "RSA PRIVATE KEY-----"
    text = "id_rsa contents:\n" + pem + "\nend"
    findings = detect(seg(text))
    assert ids(findings) == ["SEC-PRIVATE-KEY"]
    f = findings[0]
    assert f.severity is Severity.CRITICAL
    assert text[f.start : f.end] == pem
    assert body not in f.evidence
    assert "PRIVATE KEY" in f.evidence


def test_truncated_private_key_still_caught():
    text = "-----BEGIN " + "OPENSSH PRIVATE KEY-----\n" + "b3BlbnNzaC1r" * 4
    assert ids(detect(seg(text))) == ["SEC-PRIVATE-KEY"]


def test_db_url_password_spans_only_the_password():
    cred = "S3cr" + "etPw9"
    text = f"DATABASE_URL=postgres://app:{cred}@db.internal:5432/prod"
    findings = [f for f in detect(seg(text)) if f.rule_id == "SEC-DB-URL-PASSWORD"]
    assert len(findings) == 1
    f = findings[0]
    assert text[f.start : f.end] == cred
    assert cred not in f.evidence


@pytest.mark.parametrize(
    "text",
    [
        "postgres://user:" + "password@localhost/db",
        "mysql://root:${DB_PASS}@db/x",
        "redis://default:<password>@cache:6379",
    ],
)
def test_db_url_placeholders_ignored(text):
    assert "SEC-DB-URL-PASSWORD" not in ids(detect(seg(text)))


def test_stellar_seed_with_valid_checksum():
    seed = _seed()
    assert len(seed) == 56 and seed[0] == "S"
    findings = detect(seg(f"wallet seed: {seed}"))
    assert ids(findings) == ["SEC-STELLAR-SEED"]
    assert seed not in findings[0].evidence


def test_stellar_lookalike_with_bad_checksum_ignored():
    fake = "S" + "A" * 55
    assert detect(seg(fake)) == []


@pytest.mark.parametrize(
    "text",
    [
        # Split so repository secret scanners do not flag the test inputs themselves.
        "pass" + 'word = "Tr0ub4' + 'dor&3x"',
        '{"api_' + 'key": "9f8e7d6c' + '5b4a3210"}',
        "client_sec" + "ret: 'q8Wn2v" + "Lx0pRt'",
        "DB_PA" + "SSWORD=Hk29dm" + "Qp10x",
        "export GITLAB_" + "TOKEN=gl9xk2" + "LmQ8vZ",
    ],
)
def test_generic_assignment(text):
    findings = detect(seg(text))
    assert ids(findings) == ["SEC-GENERIC-ASSIGN"]
    assert findings[0].severity is Severity.MEDIUM
    assert findings[0].evidence.endswith("***")


@pytest.mark.parametrize(
    "text",
    [
        "pass" + 'word = "changeme"',
        "pass" + 'word = "xxxxxxxxxx"',
        'api_key = "<your-api-key>"',
        'token = "${GITHUB_TOKEN}"',
        "API_" + 'KEY = "your-key-here"',
        'secret = "********"',
        '"max_tokens": 1024',
        '"next_token": "abcdef' + '123456"',
        "password = os.environ['DB_PASSWORD']",
        "PASSWORD=$DB_PASSWORD",
        "AWS docs use " + "AKIA" + "IOSFODNN7" + "EXAMPLE",
        "the password must be at least 8 characters long",
    ],
)
def test_placeholders_and_code_not_flagged(text):
    assert detect(seg(text)) == []


def test_luhn():
    assert luhn_ok("4111" + "1111" * 3)
    assert not luhn_ok("4111" + "1111" * 2 + "1112")


@pytest.mark.parametrize(
    "card",
    ["4111" + " 1111" * 3, "5555" + "-5555" * 2 + "-4444", "3782" + "8224" + "6310" + "005"],
)
def test_credit_card_pii(card):
    text = f"card on file: {card} exp 12/29"
    findings = detect(seg(text))
    assert ids(findings) == ["PII-CREDIT-CARD"]
    f = findings[0]
    assert f.category is Category.PII and f.severity is Severity.MEDIUM
    assert text[f.start : f.end] == card
    assert f.evidence.endswith("***") and len(f.evidence) == 7


@pytest.mark.parametrize(
    "text",
    [
        "order 4111 1111 1111 1112 failed",  # bad Luhn
        "0000 0000 0000 0000",
        "timestamp 1700000000000",
        "call +1 415 555 0100",
    ],
)
def test_non_cards_ignored(text):
    assert "PII-CREDIT-CARD" not in ids(detect(seg(text)))


def test_multiple_secrets_in_one_segment():
    text = f"aws={AWS}\ngh={GITHUB}\n"
    assert sorted(ids(detect(seg(text)))) == ["SEC-AWS-KEY", "SEC-GITHUB-TOKEN"]


def test_finding_carries_segment_metadata():
    s = Segment(Source.USER, f"my key {AWS}", ("messages", 2, "content", 0, "text"), "x")
    f = detect(s)[0]
    assert f.source is Source.USER and f.path == s.path and f.tool_name == "x"


def test_clean_text_and_empty():
    assert detect(seg("")) == []
    assert detect(seg("Just a normal README about installing the package.")) == []


def test_mask():
    assert mask("abcdefgh") == "abcd***"
