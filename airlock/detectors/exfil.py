"""Exfiltration and excessive-agency detector.

Covers the ways injected text gets data out of the agent: zero-click markdown
images, known OAST / request-catcher hosts, explicit "send X to Y"
instructions, references to credential files, and (only inside tool calls the
model emitted) shell commands that pipe, upload or destroy.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit

from ..types import Category, Finding, Segment, Severity, Source, clip

# --- shared vocabulary -------------------------------------------------------

SENSITIVE_FILE = re.compile(
    r"""
    (?:~|\$HOME|/root|/home/[\w.-]+)?/?\.ssh\b(?:/(?:id_[a-z0-9]+|authorized_keys|config))?
  | \bid_(?:rsa|ed25519|ecdsa|dsa)\b
  | /etc/(?:passwd|shadow|sudoers)\b
  | (?:~/)?\.aws/credentials\b
  | \.git-credentials\b
  | (?<![\w-])\.(?:npmrc|netrc|pypirc|pgpass)\b
  | \.docker/config\.json\b
  | \.kube/config\b
  | (?<![\w-])\.env(?:\.(?:local|prod|production|dev|development|staging))?(?![\w-]|\.\w)
  | \bkeychain\b
  | \b(?:wallet\s+)?(?:seed|recovery|mnemonic)\s+phrase\b
    """,
    re.IGNORECASE | re.VERBOSE,
)

SECRET_WORDS = re.compile(
    r"\b(?:api[\s_-]?keys?|secrets?|passwords?|credentials?|private\s+keys?|access\s+tokens?"
    r"|tokens?|ssh\s+keys?|seed\s+phrase|env(?:ironment)?\s+variables)\b",
    re.IGNORECASE,
)

# Request catchers and out-of-band interaction hosts used to receive stolen data.
OAST_HOST = re.compile(
    r"(?<![\w.-])(?:[\w-]+\.)*"
    r"(?:webhook\.site|requestbin\.(?:com|net|io)|[\w-]*requestbin[\w-]*\.[a-z]{2,}"
    r"|pipedream\.net|m\.pipedream\.net|ngrok\.io|ngrok-free\.app|ngrok\.app"
    r"|burpcollaborator\.net|oastify\.com|interact\.sh|oast\.(?:fun|me|online|pro|live|site)"
    r"|pastebin\.com|transfer\.sh|hookbin\.com|beeceptor\.com)(?![\w-])",
    re.IGNORECASE,
)

# Hosts that legitimately carry long signed query strings on images.
_SIGNED_IMAGE_HOSTS = re.compile(
    r"(?:^|\.)(?:githubusercontent\.com|amazonaws\.com|googleusercontent\.com|googleapis\.com"
    r"|cloudfront\.net|blob\.core\.windows\.net|shields\.io|gravatar\.com)$",
    re.IGNORECASE,
)
_DOC_HOSTS = re.compile(r"(?:^|\.)(?:example\.(?:com|org|net)|localhost)$|^127\.0\.0\.1$", re.I)

# --- EXF-MD-IMAGE -------------------------------------------------------------

_MD_IMAGE = re.compile(r"!\[[^\]\n]{0,200}\]\(\s*<?(?P<url>https?://[^\s)>]+)", re.IGNORECASE)
_HTML_IMG = re.compile(r"<img\b[^>]*?\bsrc\s*=\s*[\"']?(?P<url>https?://[^\s\"'>]+)", re.I)
_TEMPLATE = re.compile(r"\{\{?[^}]*\}\}?|%7B|\$[A-Z_]{2,}|\$\{|%s\b|\[[A-Z_]{3,}\]", re.I)
_B64ISH = re.compile(r"^[A-Za-z0-9+/_=-]{16,}$")


def _data_query(url: str) -> str | None:
    """Return why the URL's query looks like it carries data, or None."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if not parts.query:
        return None
    host = (parts.hostname or "").lower()
    if _TEMPLATE.search(parts.query):
        return "template placeholder in query"
    if _SIGNED_IMAGE_HOSTS.search(host):
        return None
    for _, value in parse_qsl(parts.query, keep_blank_values=True):
        if len(value) >= 20:
            return "long query value"
        if _B64ISH.match(value) and re.search(r"\d", value) and re.search(r"[A-Za-z]", value):
            return "encoded query value"
    return None


# --- EXF-SEND-INSTRUCTION -----------------------------------------------------

_TARGET = (
    r"(?P<target>https?://[^\s\"'<>)\]]+|[\w.+-]+@[\w-]+(?:\.[\w-]+)+"
    r"|(?:this|that|the|my|our|an?)\s+(?:webhook|endpoint|server|url))"
)
_SEND = re.compile(
    r"(?P<verb>\b(?:send|post|upload|forward|exfiltrate|transmit|leak|e-?mail|submit|beacon"
    r"|env[ií]a|envi[aá]r|mand[aá]|sub[ií]|reenv[ií]a|envie|enviar|mande|encaminhe)\b)"
    r"(?P<obj>[^\n]{0,160}?)"
    r"\b(?:to|into|a|al|hacia|para)\b\s*:?\s*" + _TARGET,
    re.IGNORECASE,
)
_SEND_OBJECT = re.compile(
    r"\b(?:it|them|this|everything|all|contents?|data|files?|keys?|tokens?|secrets?|passwords?"
    r"|credentials?|conversation|history|chat|messages?|prompt|env|environment|output|results?"
    r"|summary|information|info|details|variables|contenido|datos|archivo|clave|conteúdo|dados"
    r"|arquivo|chave|todo|tudo)\b",
    re.IGNORECASE,
)

# --- AGY-DANGEROUS-COMMAND ----------------------------------------------------

_PIPE_TO_SHELL = re.compile(
    r"\b(?:curl|wget)\b[^\n|;]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b"
    r"|\b(?:ba|z)?sh\b\s+(?:-c\s+)?[\"']?(?:\$\(|<\()\s*(?:curl|wget)\b",
    re.IGNORECASE,
)
_UPLOAD_FILE = re.compile(
    r"\bcurl\b[^\n]*?(?:\s-d\s*|\s--data(?:-binary|-raw|-urlencode|-ascii)?[\s=]+"
    r"|\s-F\s*[\"']?[\w-]*=|\s--form\s+[\"']?[\w-]*=)[\"']?@"
    r"|\bcurl\b[^\n]*?\s(?:-T|--upload-file)\s"
    r"|\bwget\b[^\n]*?--post-file"
    r"|\b(?:env|printenv|set)\s*\|\s*(?:curl|wget|nc|ncat)\b"
    r"|\b(?:curl|wget)\b[^\n]*\$\(\s*(?:cat|env|printenv|base64)\b",
    re.IGNORECASE,
)
_RM_ROOT = re.compile(
    r"\brm\s+(?P<flags>(?:--?[\w-]+\s+)+)(?:/\*?|~/?\*?|\$HOME/?\*?)(?=$|[\s;&|\"'`)\\])"
    r"|--no-preserve-root",
)
_REVERSE_SHELL = re.compile(
    r"/dev/(?:tcp|udp)/|\b(?:nc|ncat|netcat)\b[^\n]*\s-[a-z]*[ec]\s"
    r"|\bsocat\b[^\n]*\bexec:|\bmkfifo\b[^\n]*\b(?:nc|ncat)\b",
    re.IGNORECASE,
)
_CHMOD_777 = re.compile(
    r"\bchmod\s+(?:-\w+\s+)*0?777\s+(?:/(?=$|[\s;&|\"'])|/(?:etc|usr|bin|sbin|var|root|home|boot)\b|~)"
)
_ENCODE = re.compile(r"\b(?:base64|xxd|openssl\s+(?:base64|enc))\b", re.IGNORECASE)
_READ_VERB = re.compile(
    r"\b(?:cat|less|more|head|tail|cp|scp|rsync|base64|xxd|strings|curl|wget|nc|ncat|tar|zip"
    r"|type|get-content|read|open|upload|send|post)\b",
    re.IGNORECASE,
)
_READ_TOOL = re.compile(
    r"read|view|open|cat|fetch|upload|send|bash|shell|exec|command|terminal", re.I
)


def _finding(
    segment: Segment,
    rule_id: str,
    category: Category,
    severity: Severity,
    start: int,
    end: int,
    message: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        category=category,
        severity=severity,
        source=segment.source,
        path=segment.path,
        start=start,
        end=end,
        evidence=clip(segment.text[start:end]),
        message=message,
        tool_name=segment.tool_name,
    )


def _images(segment: Segment) -> list[Finding]:
    out = []
    for pattern in (_MD_IMAGE, _HTML_IMG):
        for m in pattern.finditer(segment.text):
            why = _data_query(m.group("url"))
            if why:
                out.append(
                    _finding(
                        segment, "EXF-MD-IMAGE", Category.EXFILTRATION, Severity.CRITICAL,
                        m.start(), m.end(),
                        f"Image URL whose query carries data ({why}): zero-click exfiltration",
                    )
                )
    return out


def _oast(segment: Segment) -> list[Finding]:
    return [
        _finding(
            segment, "EXF-OAST-DOMAIN", Category.EXFILTRATION, Severity.HIGH,
            m.start(), m.end(), "Known request-catcher / OAST exfiltration host",
        )
        for m in OAST_HOST.finditer(segment.text)
    ]


def _send(segment: Segment) -> list[Finding]:
    text = segment.text
    out = []
    sensitive = bool(SENSITIVE_FILE.search(text) or SECRET_WORDS.search(text))
    for m in _SEND.finditer(text):
        target = m.group("target")
        if target.lower().startswith("http"):
            host = (urlsplit(target).hostname or "").lower()
            if _DOC_HOSTS.search(host):
                continue
        elif "@" in target and _DOC_HOSTS.search(target.split("@", 1)[1].lower()):
            continue
        if not _SEND_OBJECT.search(m.group("obj")) and not re.match(
            r"(?i)e-?mail|exfiltrate|leak", m.group("verb")
        ):
            continue
        severity = Severity.CRITICAL if sensitive else Severity.HIGH
        msg = "Instruction to send data to an external destination"
        if sensitive:
            msg += " (together with secrets or sensitive files)"
        out.append(
            _finding(
                segment, "EXF-SEND-INSTRUCTION", Category.EXFILTRATION, severity,
                m.start(), m.end(), msg,
            )
        )
    return out


def _sensitive_files(segment: Segment) -> list[Finding]:
    out = []
    escalate = segment.source is Source.TOOL_USE and bool(
        _READ_VERB.search(segment.text) or _READ_TOOL.search(segment.tool_name or "")
    )
    severity = Severity.HIGH if escalate else Severity.MEDIUM
    for m in SENSITIVE_FILE.finditer(segment.text):
        if m.end() == m.start():
            continue
        msg = "Reference to a credential or sensitive file"
        if escalate:
            msg = "Tool call reads or sends a credential or sensitive file"
        out.append(
            _finding(
                segment, "EXF-SENSITIVE-FILE", Category.EXFILTRATION, severity,
                m.start(), m.end(), msg,
            )
        )
    return out


def _commands(segment: Segment) -> list[Finding]:
    text = segment.text
    out = []

    def add(m: re.Match[str], severity: Severity, message: str) -> None:
        out.append(
            _finding(
                segment, "AGY-DANGEROUS-COMMAND", Category.EXCESSIVE_AGENCY, severity,
                m.start(), m.end(), message,
            )
        )

    for m in _PIPE_TO_SHELL.finditer(text):
        add(m, Severity.CRITICAL, "Downloads a remote script and pipes it to a shell")
    for m in _UPLOAD_FILE.finditer(text):
        add(m, Severity.CRITICAL, "Uploads a local file or environment to a remote host")
    for m in _RM_ROOT.finditer(text):
        flags = m.group("flags") or ""
        if m.group(0) == "--no-preserve-root" or re.search(r"-\w*[rR]|--recursive", flags):
            add(m, Severity.CRITICAL, "Recursive delete of the root or home directory")
    for m in _REVERSE_SHELL.finditer(text):
        add(m, Severity.CRITICAL, "Reverse shell")
    for m in _CHMOD_777.finditer(text):
        add(m, Severity.HIGH, "World-writable permissions on a system path")
    for line_match in re.finditer(r"[^\n]+", text):
        line = line_match.group(0)
        enc = _ENCODE.search(line)
        if enc and SENSITIVE_FILE.search(line):
            start = line_match.start()
            out.append(
                _finding(
                    segment, "AGY-DANGEROUS-COMMAND", Category.EXCESSIVE_AGENCY, Severity.HIGH,
                    start, line_match.end(), "Encodes a sensitive file (staging for exfiltration)",
                )
            )
    return out


def detect(segment: Segment) -> list[Finding]:
    if not segment.text or not isinstance(segment.text, str):
        return []
    findings = _images(segment) + _oast(segment) + _send(segment) + _sensitive_files(segment)
    if segment.source is Source.TOOL_USE:
        findings += _commands(segment)
    return findings
