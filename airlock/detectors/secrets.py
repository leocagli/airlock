"""Secret, credential and card-number detector.

Each finding spans the secret itself, so the sanitizer can mask exactly that
range. Evidence is always masked (first 4 chars + "***"): a finding must
never carry a full secret into logs, reports or the audit trail.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Callable
from dataclasses import dataclass

from ..types import Category, Finding, Segment, Severity

# Values that are obviously documentation placeholders, not real secrets.
_PLACEHOLDER = re.compile(
    r"example|xxxx|your[-_ ]?(?:api|key|token|secret|pass)|placeholder|changeme|change[-_]me"
    r"|replace[-_]?me|dummy|redacted|<[^>]*>|\$\{|\{\{|\*\*\*|\.\.\.",
    re.IGNORECASE,
)
_WEAK_VALUES = frozenset(
    {"password", "passwd", "pass", "secret", "pwd", "token", "admin", "none", "null", "undefined"}
)


def mask(value: str) -> str:
    """First 4 chars + "***": enough to recognise, never enough to use."""
    return value[:4] + "***"


def _real(value: str) -> bool:
    return not _PLACEHOLDER.search(value)


def _real_generic(value: str) -> bool:
    if not _real(value) or value.lower() in _WEAK_VALUES:
        return False
    if len(set(value)) < 4:  # "aaaaaaaa", "12121212"
        return False
    # Variable references and code, not literals.
    return not (value[0] in "$%@&*" or any(c in value for c in "()[]"))


def _crc16_xmodem(data: bytes) -> int:
    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else (crc << 1)
            crc &= 0xFFFF
    return crc


def _stellar_seed_ok(value: str) -> bool:
    """Strkey check: version byte 18 << 3, 32-byte payload, CRC16 checksum."""
    try:
        raw = base64.b32decode(value)
    except (binascii.Error, ValueError):
        return False
    if len(raw) != 35 or raw[0] != 18 << 3:
        return False
    return _crc16_xmodem(raw[:33]) == int.from_bytes(raw[33:], "little")


def luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


@dataclass(frozen=True)
class _Rule:
    rule_id: str
    severity: Severity
    pattern: re.Pattern[str]
    message: str
    group: str | int = 0
    valid: Callable[[str], bool] = _real
    category: Category = Category.SECRET


_RULES: tuple[_Rule, ...] = (
    _Rule(
        "SEC-PRIVATE-KEY",
        Severity.CRITICAL,
        re.compile(
            r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----[\s\S]*?"
            r"(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----|\Z)"
        ),
        "Private key block",
        valid=lambda v: True,
    ),
    _Rule(
        "SEC-AWS-KEY",
        Severity.HIGH,
        re.compile(r"(?<![A-Za-z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Za-z0-9])"),
        "AWS access key id",
    ),
    _Rule(
        "SEC-GITHUB-TOKEN",
        Severity.HIGH,
        re.compile(
            r"(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})"
        ),
        "GitHub token",
    ),
    _Rule(
        "SEC-ANTHROPIC-KEY",
        Severity.HIGH,
        re.compile(r"(?<![A-Za-z0-9_-])sk-ant-[A-Za-z0-9_-]{20,}"),
        "Anthropic API key",
    ),
    _Rule(
        "SEC-OPENAI-KEY",
        Severity.HIGH,
        re.compile(r"(?<![A-Za-z0-9_-])sk-(?:proj-[A-Za-z0-9_-]{20,}|[A-Za-z0-9]{32,})"),
        "OpenAI API key",
    ),
    _Rule(
        "SEC-SLACK-TOKEN",
        Severity.HIGH,
        re.compile(r"(?<![A-Za-z0-9])xox[baprs]-[A-Za-z0-9-]{10,}"),
        "Slack token",
    ),
    _Rule(
        "SEC-STRIPE-KEY",
        Severity.HIGH,
        re.compile(r"(?<![A-Za-z0-9])[sr]k_live_[A-Za-z0-9]{16,}"),
        "Stripe live secret key",
    ),
    _Rule(
        "SEC-GOOGLE-API-KEY",
        Severity.HIGH,
        re.compile(r"(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])"),
        "Google API key",
    ),
    _Rule(
        "SEC-JWT",
        Severity.MEDIUM,
        re.compile(
            r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*"
        ),
        "JSON Web Token",
    ),
    _Rule(
        "SEC-DB-URL-PASSWORD",
        Severity.HIGH,
        re.compile(
            r"\b[a-zA-Z][a-zA-Z0-9+.-]{1,20}://[^\s:/@'\"<>]{1,64}:"
            r"(?P<pwd>[^\s:/@'\"<>]{3,128})@[^\s/'\"<>:?#]+"
        ),
        "Password embedded in a connection URL",
        group="pwd",
        valid=lambda v: _real(v) and v.lower() not in _WEAK_VALUES and v[0] not in "${%",
    ),
    _Rule(
        "SEC-STELLAR-SEED",
        Severity.HIGH,
        re.compile(r"(?<![A-Za-z0-9])S[A-Z2-7]{55}(?![A-Za-z0-9])"),
        "Stellar secret seed",
        valid=_stellar_seed_ok,
    ),
    _Rule(
        "SEC-GENERIC-ASSIGN",
        Severity.MEDIUM,
        re.compile(
            r"(?i)(?<![A-Za-z0-9])[A-Za-z0-9_.-]*?"
            r"(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|token)"
            r"(?![A-Za-z0-9_])[\"']?\s*(?::=|=>|[:=])\s*"
            r"(?P<q>[\"'])(?P<val>[^\"'\s]{8,})(?P=q)"
        ),
        "Hard-coded credential assignment",
        group="val",
        valid=_real_generic,
    ),
    _Rule(
        "SEC-GENERIC-ASSIGN",
        Severity.MEDIUM,
        # .env style, unquoted: API_KEY=abc123...
        re.compile(
            r"(?im)^[ \t]*(?:export[ \t]+)?[A-Za-z0-9_]*"
            r"(?:PASSWORD|PASSWD|SECRET|API_?KEY|ACCESS_?KEY|TOKEN)[ \t]*=[ \t]*"
            r"(?P<val>[^\s\"'#;,]{8,})"
        ),
        "Hard-coded credential assignment",
        group="val",
        valid=lambda v: _real_generic(v)
        and bool(re.search(r"\d", v))
        and bool(re.search(r"[A-Za-z]", v)),
    ),
)

# Keys that hold tokens but are not secrets (pagination, limits, types).
_BENIGN_KEY = re.compile(r"next|page|csrf|xsrf|count|max|limit|type|usage|expir", re.I)

_CARD = re.compile(r"(?<![\w-])(?:\d[ -]?){12,18}\d(?![\w-])")


def _overlaps(start: int, end: int, taken: list[tuple[int, int]]) -> bool:
    return any(s < end and start < e for s, e in taken)


def _cards(segment: Segment) -> list[Finding]:
    out: list[Finding] = []
    for m in _CARD.finditer(segment.text):
        raw = m.group(0)
        digits = re.sub(r"\D", "", raw)
        seps = {c for c in raw if not c.isdigit()}
        if not 13 <= len(digits) <= 19 or len(seps) > 1:
            continue
        if digits[0] not in "23456" or len(set(digits)) < 2 or not luhn_ok(digits):
            continue
        out.append(
            Finding(
                rule_id="PII-CREDIT-CARD",
                category=Category.PII,
                severity=Severity.MEDIUM,
                source=segment.source,
                path=segment.path,
                start=m.start(),
                end=m.end(),
                evidence=mask(digits),
                message="Payment card number (passes Luhn check)",
                tool_name=segment.tool_name,
            )
        )
    return out


def detect(segment: Segment) -> list[Finding]:
    text = segment.text
    if not text or not isinstance(text, str):
        return []
    findings: list[Finding] = []
    taken: list[tuple[int, int]] = []
    for rule in _RULES:
        for m in rule.pattern.finditer(text):
            value = m.group(rule.group)
            if value is None or not rule.valid(value):
                continue
            if rule.rule_id == "SEC-GENERIC-ASSIGN" and _BENIGN_KEY.search(
                text[m.start() : m.start(rule.group)]
            ):
                continue
            start, end = m.span(rule.group)
            # Rules run most specific first: skip spans a stronger rule owns.
            if _overlaps(start, end, taken):
                continue
            taken.append((start, end))
            if rule.rule_id == "SEC-PRIVATE-KEY":
                parts = value.split("-----")
                evidence = (parts[1] if len(parts) > 1 else "PRIVATE KEY") + " ***"
            else:
                evidence = mask(value)
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    category=rule.category,
                    severity=rule.severity,
                    source=segment.source,
                    path=segment.path,
                    start=start,
                    end=end,
                    evidence=evidence,
                    message=rule.message,
                    tool_name=segment.tool_name,
                )
            )
    findings.extend(c for c in _cards(segment) if not _overlaps(c.start, c.end, taken))
    return findings
