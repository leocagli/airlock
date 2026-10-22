"""Hidden content detector: text a human reviewer would not see.

Invisible Unicode (tag smuggling, bidi controls, zero-width characters),
instruction-bearing HTML comments, CSS-hidden elements and base64 blobs that
decode to instructions.
"""

from __future__ import annotations

import base64
import binascii
import re

from ..types import Category, Finding, Segment, Severity, clip

TAG_RE = re.compile("[\U000e0000-\U000e007f]")
BIDI_RE = re.compile("[\u202a-\u202e\u2066-\u2069]")
ZERO_WIDTH_RE = re.compile("[\u200b\u200c\u200d\u2060\ufeff]")

_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
_COMMENT_STRONG = re.compile(
    r"\b(?:ignore|instructions?|assistant|ai|llm|agent|do\s+not\s+tell|execute|system\s+prompt|"
    r"ignora|instrucciones|instru[cç][oõ]es|asistente|assistente)\b",
    re.IGNORECASE,
)
_COMMENT_WEAK = re.compile(
    r"\b(?:must|send|system|curl|password|token|exfiltrate)\b", re.IGNORECASE
)

_STYLED_RE = re.compile(
    r"<(?P<tag>[a-z][\w-]*)\b[^>]*?\bstyle\s*=\s*(?P<q>[\"'])(?P<style>.*?)(?P=q)[^>]*>"
    r"(?P<inner>.*?)</(?P=tag)\s*>",
    re.IGNORECASE | re.DOTALL,
)
_HIDDEN_STYLE_RE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden"
    r"|font-size\s*:\s*0(?:\.0*)?(?:px|em|rem|pt|%)?\s*(?:;|!|$)"
    r"|(?<![\w-])opacity\s*:\s*0(?:\.0*)?\s*(?:;|!|$)"
    r"|(?<![\w-])color\s*:\s*(?:#fff(?:fff)?\b|white\b)",
    re.IGNORECASE,
)
_TAGS_RE = re.compile(r"<[^>]+>")

_B64_RE = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{40,}={0,2}(?![A-Za-z0-9+/=_-])")
_B64_WORDS = re.compile(
    r"\b(?:ignore|instructions?|system|assistant|send|curl|password|token|exfiltrate|execute|wget)\b",
    re.IGNORECASE,
)
_LONG_TOKEN_RE = re.compile(r"[A-Za-z0-9_\-+/]{16,}")


def _mask(text: str) -> str:
    """Hide anything token-shaped so evidence never carries a full secret."""
    return _LONG_TOKEN_RE.sub(lambda m: m.group(0)[:4] + "***", text)


def _finding(segment: Segment, rule_id: str, severity: Severity, start: int, end: int,
             evidence: str, message: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        category=Category.HIDDEN_CONTENT,
        severity=severity,
        source=segment.source,
        path=segment.path,
        start=start,
        end=end,
        evidence=clip(evidence),
        message=message,
        tool_name=segment.tool_name,
    )


def decode_tags(text: str) -> str:
    """ASCII smuggled through Unicode tag characters (U+E0020..U+E007E)."""
    out = []
    for ch in text:
        cp = ord(ch) - 0xE0000
        if 0x20 <= cp <= 0x7E:
            out.append(chr(cp))
    return "".join(out)


def _unicode(segment: Segment) -> list[Finding]:
    text = segment.text
    out: list[Finding] = []

    tags = [m.start() for m in TAG_RE.finditer(text)]
    if tags:
        decoded = decode_tags(text)
        out.append(_finding(
            segment, "HID-UNICODE-TAGS", Severity.CRITICAL, tags[0], tags[-1] + 1,
            _mask(decoded) or f"{len(tags)} tag character(s)",
            "Invisible Unicode tag characters smuggle hidden text",
        ))

    bidi = [m.start() for m in BIDI_RE.finditer(text)]
    if bidi:
        out.append(_finding(
            segment, "HID-BIDI", Severity.HIGH, bidi[0], bidi[-1] + 1,
            f"{len(bidi)} bidi control character(s)",
            "Bidirectional override characters can disguise text",
        ))

    zero = [
        m.start()
        for m in ZERO_WIDTH_RE.finditer(text)
        if not (m.start() == 0 and m.group() == "\ufeff")
    ]
    if zero:
        severity = Severity.HIGH if len(zero) >= 3 else Severity.LOW
        out.append(_finding(
            segment, "HID-ZERO-WIDTH", severity, zero[0], zero[-1] + 1,
            f"{len(zero)} zero-width character(s)",
            "Zero-width characters can hide or split words",
        ))
    return out


def _html(segment: Segment) -> list[Finding]:
    text = segment.text
    out: list[Finding] = []
    if "<!--" in text:
        for m in _COMMENT_RE.finditer(text):
            inner = m.group(1)
            strong = _COMMENT_STRONG.search(inner)
            weak = {w.lower() for w in _COMMENT_WEAK.findall(inner)}
            if strong or len(weak) >= 2:
                severity = Severity.HIGH
            elif weak:
                severity = Severity.MEDIUM
            else:
                continue
            out.append(_finding(
                segment, "HID-HTML-COMMENT", severity, m.start(), m.end(), _mask(inner),
                "HTML comment carries instructions invisible to the reader",
            ))
    if "<" in text and "style" in text.lower():
        for m in _STYLED_RE.finditer(text):
            if not _HIDDEN_STYLE_RE.search(m.group("style")):
                continue
            visible = " ".join(_TAGS_RE.sub(" ", m.group("inner")).split())
            if not visible:
                continue
            out.append(_finding(
                segment, "HID-CSS-HIDDEN", Severity.HIGH, m.start(), m.end(), _mask(visible),
                "Text hidden from humans with CSS",
            ))
    return out


def _decode_b64(blob: str) -> str | None:
    raw = blob.rstrip("=")
    raw += "=" * (-len(raw) % 4)
    try:
        if "-" in raw or "_" in raw:
            data = base64.urlsafe_b64decode(raw)
        else:
            data = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError):
        return None
    decoded = data.decode("utf-8", errors="replace")
    if not decoded:
        return None
    printable = sum(1 for c in decoded if c.isprintable() or c in "\n\r\t")
    return decoded if printable / len(decoded) >= 0.9 else None


def _base64(segment: Segment) -> list[Finding]:
    out: list[Finding] = []
    for m in _B64_RE.finditer(segment.text):
        decoded = _decode_b64(m.group(0))
        if decoded and _B64_WORDS.search(decoded):
            out.append(
                _finding(
                    segment,
                    "HID-BASE64",
                    Severity.HIGH,
                    m.start(),
                    m.end(),
                    "base64: " + _mask(decoded),
                    "Base64 blob decodes to instructions",
                )
            )
    return out


def detect(segment: Segment) -> list[Finding]:
    if not isinstance(segment.text, str) or not segment.text:
        return []
    return _unicode(segment) + _html(segment) + _base64(segment)
