"""Prompt injection detector (OWASP LLM01), English / Spanish / Portuguese.

Reports intrinsic severity only; the policy decides what a match means for
each source. Patterns are anchored on attack phrasing (an override verb plus
"previous/all/your instructions", fake role delimiters, concealment from the
user) so ordinary documentation such as "run npm install" or "ignore the
warning" does not trigger the HIGH rules.
"""

from __future__ import annotations

import re
from dataclasses import replace

from ..types import Category, Finding, Segment, Severity, clip

_I = re.IGNORECASE
_IM = re.IGNORECASE | re.MULTILINE

_QUAL_EN = (
    r"(?:previous|prior|above|earlier|preceding|former|system|original|existing|developer|initial)"
)
_NOUN_EN = r"(?:instructions?|prompts?|directives?|guidelines|rules|commands|context)"

# (rule_id, severity, message, [compiled patterns])
_RULES: list[tuple[str, Severity, str, list[re.Pattern[str]]]] = [
    (
        "INJ-OVERRIDE",
        Severity.HIGH,
        "Attempts to override the agent's instructions",
        [
            re.compile(
                r"\b(?:ignore|disregard|forget|override|bypass)\s+"
                r"(?:(?:all|any|every)\s+(?:(?:of\s+)?(?:the|your|my|these|those)\s+)?(?:"
                + _QUAL_EN
                + r"\s+)?"
                r"|(?:(?:the|your|my|these|those)\s+)?" + _QUAL_EN + r"\s+"
                r"|your\s+)" + _NOUN_EN + r"\b",
                _I,
            ),
            re.compile(
                r"\b(?:ignore|disregard|forget)\s+(?:everything|all)\s+"
                r"(?:above|before|prior|previously|you\s+(?:were|have\s+been|'ve\s+been)\s+told)\b",
                _I,
            ),
            re.compile(
                r"\b(?:new|updated|revised|real|actual)\s+(?:system\s+)?instructions?\s*:", _I
            ),
            # Spanish: ignora (todas) las instrucciones anteriores / olvida todo
            re.compile(
                r"\b(?:ignora|ignore|ignorá|ignorad|ignoren|olvida|olvidá|olvide|olviden|descarta|descartá|"
                r"omite|omití|desestima)\s+"
                r"(?:(?:todas|todos|toda)\s+(?:(?:las|los|tus|sus)\s+)?|(?:las|los|tus|sus)\s+)"
                r"(?:instrucciones|indicaciones|reglas|[oó]rdenes|directivas|pautas)"
                r"(?:\s+(?:anteriores|previas|de\s+arriba|del\s+sistema|originales))?",
                _I,
            ),
            re.compile(r"\bolvid(?:a|á|e|en)\s+todo\b(?:\s+lo\s+anterior)?", _I),
            # Portuguese: ignore as instrucoes anteriores / desconsidere tudo
            re.compile(
                r"\b(?:ignore|ignora|ignorem|desconsidere|desconsidera|esque[cç]a|esquece)\s+"
                r"(?:(?:todas|todos|toda)\s+(?:(?:as|os|suas|tuas)\s+)?|(?:as|os|suas|tuas)\s+)"
                r"(?:instru[cç][oõ]es|orienta[cç][oõ]es|regras|diretrizes|ordens|comandos)"
                r"(?:\s+(?:anteriores|pr[eé]vias|acima|do\s+sistema|originais))?",
                _I,
            ),
            re.compile(
                r"\b(?:desconsidere|desconsidera|esque[cç]a|esquece)\s+tudo\b(?:\s+(?:acima|o\s+que))?",
                _I,
            ),
        ],
    ),
    (
        "INJ-ROLE-SPOOF",
        Severity.HIGH,
        "Fake conversation turn or role delimiter",
        [
            re.compile(
                r"<\s*/?\s*(?:tool_result|tool_use|function_results?|function_calls|system|"
                r"system[_-]prompt|system[_-]message|instructions)\s*>",
                _I,
            ),
            re.compile(
                r"<\|\s*(?:im_start|im_end|system|user|assistant|endoftext|eot_id|"
                r"start_header_id|end_header_id)\s*\|>",
                _I,
            ),
            re.compile(r"\[\s*/?\s*(?:system|inst|sys|admin)\s*\]|<<\s*/?\s*SYS\s*>>", _I),
            re.compile(
                r"^[ \t]*#{1,6}[ \t]*(?:system(?:[ \t]+(?:prompt|message|override))?|"
                r"new[ \t]+instructions?)[ \t]*:?[ \t]*$",
                _IM,
            ),
            re.compile(r"^[ \t]*(?:Human|Assistant)[ \t]*:[ \t]*\S", _IM),
            re.compile(r"\bsystem\s+override\b", _I),
            re.compile(r"\b(?:SYSTEM|ADMIN)\s+(?:ALERT|NOTICE|MESSAGE|INSTRUCTIONS?|PROMPT)\b"),
        ],
    ),
    (
        "INJ-CONCEAL",
        Severity.HIGH,
        "Asks the agent to hide its actions from the user",
        [
            re.compile(
                r"\b(?:do\s+not|don['’]?t|never)\s+(?:tell|mention|inform|reveal|disclose|notify|alert)\b"
                r"[^.\n]{0,40}?\b(?:the\s+)?(?:user|human|operator)s?\b",
                _I,
            ),
            re.compile(
                r"\bwithout\s+(?:the\s+(?:user|human)|them|anyone)\s+"
                r"(?:noticing|knowing|seeing|realizing|being\s+aware)\b",
                _I,
            ),
            re.compile(
                r"\bwithout\s+(?:telling|informing|alerting|notifying)\s+(?:the\s+)?(?:user|human)\b",
                _I,
            ),
            re.compile(
                r"\b(?:secretly|covertly|silently)\s+(?:\w+\s+){0,2}?"
                r"(?:send|upload|post|forward|email|exfiltrate|transmit|copy|add|include|append|run|"
                r"execute|call|read|fetch|attach|bcc|cc|delete|modify)\b",
                _I,
            ),
            re.compile(
                r"\bno\s+(?:le\s+|les\s+)?(?:digas|digan|diga|menciones|mencione|cuentes|cuente|informes|"
                r"informe|reveles|revele|avises|avise|comentes)\b[^.\n]{0,40}?"
                r"\b(?:al\s+usuario|a\s+la\s+usuaria|al\s+cliente|a\s+nadie)\b",
                _I,
            ),
            re.compile(
                r"\bsin\s+que\s+(?:el\s+usuario|la\s+usuaria|nadie)\s+(?:se\s+)?"
                r"(?:entere|note|sepa|d[eé]\s+cuenta)\b",
                _I,
            ),
            re.compile(
                r"\bn[aã]o\s+(?:conte|diga|mencione|informe|revele|avise|fale)\b[^.\n]{0,40}?"
                r"(?:\bao\s+usu[aá]rio|\bà\s+usu[aá]ria|\bpara\s+o\s+usu[aá]rio|\ba\s+ningu[eé]m)",
                _I,
            ),
            re.compile(
                r"\bsem\s+que\s+o\s+usu[aá]rio\s+(?:perceba|saiba|note)\b"
                r"|\bsem\s+o\s+usu[aá]rio\s+(?:perceber|saber|notar)\b",
                _I,
            ),
        ],
    ),
    (
        "INJ-ADDRESS-AI",
        Severity.MEDIUM,
        "Text addresses the AI model directly",
        [
            re.compile(
                r"\bnote\s+(?:to|for)\s+(?:the\s+|any\s+)?(?:ai|llm|assistant|agent|model|claude|chatgpt|gpt)s?\b",
                _I,
            ),
            re.compile(
                r"\bif\s+you\s+are\s+(?:an?\s+)?(?:ai|llm|large\s+language\s+model|language\s+model|"
                r"assistant|agent|claude|chatgpt|gpt)\b",
                _I,
            ),
            re.compile(
                r"\b(?:ai|llm)\s+(?:agents?|assistants?|models?)\s+"
                r"(?:reading|processing|parsing|summari[sz]ing|browsing|visiting)\b",
                _I,
            ),
            re.compile(
                r"\battention\s*[,:!-]?\s*(?:ai|llm|assistant|agent|claude|chatgpt|model)s?\b", _I
            ),
            re.compile(
                r"\bas\s+an?\s+(?:ai|llm)(?:\s+(?:agent|assistant|model))?\s*,?\s*you\s+"
                r"(?:must|should|need\s+to|have\s+to|are\s+required\s+to)\b",
                _I,
            ),
            re.compile(
                r"\bsi\s+(?:eres|sos|usted\s+es)\s+(?:una?\s+)?(?:ia|inteligencia\s+artificial|asistente|"
                r"agente|modelo|llm)\b|\bnota\s+para\s+(?:la\s+|el\s+)?(?:ia|ai|asistente|agente|modelo)\b",
                _I,
            ),
            re.compile(
                r"\bse\s+voc[eê]\s+(?:[eé]|for)\s+(?:uma?\s+)?(?:ia|intelig[eê]ncia\s+artificial|assistente|"
                r"agente|modelo|llm)\b|\bnota\s+para\s+(?:a\s+|o\s+)?(?:ia|ai|assistente|agente|modelo)\b",
                _I,
            ),
        ],
    ),
    (
        "INJ-TOOL-HIJACK",
        Severity.MEDIUM,
        "Instructs the agent to invoke a tool or run a command",
        [
            re.compile(
                r"\b(?:call|use|invoke|run|trigger)\s+(?:the\s+)?[`'\"]?[\w.-]+[`'\"]?\s+(?:tool|function)\b",
                _I,
            ),
            re.compile(
                r"\b(?:execute|run)\s+(?:the\s+following|this)\s+(?:shell\s+|bash\s+|terminal\s+)?"
                r"(?:command|script|code)s?\b",
                _I,
            ),
            re.compile(
                r"\b(?:ejecuta|ejecutá|llama|invoca|usa|usá)\s+(?:a\s+)?(?:la\s+)?(?:herramienta|funci[oó]n)\b"
                r"|\bejecut[aá]\s+(?:el\s+siguiente|este)\s+comando\b",
                _I,
            ),
            re.compile(
                r"\b(?:execute|chame|invoque|use|rode)\s+(?:a\s+)?(?:ferramenta|fun[cç][aã]o)\b"
                r"|\b(?:execute|rode)\s+(?:o\s+seguinte|este)\s+comando\b",
                _I,
            ),
        ],
    ),
    (
        "INJ-JAILBREAK",
        Severity.MEDIUM,
        "Known jailbreak phrasing",
        [
            re.compile(r"\bDAN\b|\bdo\s+anything\s+now\b"),
            re.compile(r"\bdeveloper\s+mode\b|\bjailbr(?:ea|o)k(?:en|ed|ing|s)?\b", _I),
            re.compile(
                r"\bno\s+(?:restrictions|limitations|filters|guardrails|censorship)\b"
                r"|\bmodo\s+(?:desarrollador|desenvolvedor)\b|\bsin\s+restricciones\b|\bsem\s+restri[cç][oõ]es\b",
                _I,
            ),
        ],
    ),
]

# Signals that turn a HIGH injection into CRITICAL (an exfiltration target).
_URL_RE = re.compile(r"https?://\S+|\bwww\.[\w-]+\.\S+|\b[\w.+-]+@[\w-]+\.[\w.-]+\b", _I)
_SENSITIVE_RE = re.compile(
    r"~/\.ssh|\.ssh/|\bid_(?:rsa|ed25519|ecdsa|dsa)\b|(?<![\w.])\.env\b|/etc/(?:passwd|shadow)"
    r"|\.aws/|\bcredentials?\b|\bapi[\s_-]?keys?\b|\bpasswords?\b|\bprivate[\s_-]keys?\b"
    r"|\bsecret[\s_-]keys?\b|\baccess[\s_-]tokens?\b|\bcontrase[nñ]as?\b|\bsenhas?\b",
    _I,
)


def detect(segment: Segment) -> list[Finding]:
    text = segment.text
    if not isinstance(text, str) or not text:
        return []
    findings: list[Finding] = []
    seen: set[tuple[str, int, int]] = set()
    for rule_id, severity, message, patterns in _RULES:
        for pattern in patterns:
            for m in pattern.finditer(text):
                key = (rule_id, m.start(), m.end())
                if m.end() <= m.start() or key in seen:
                    continue
                seen.add(key)
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        category=Category.PROMPT_INJECTION,
                        severity=severity,
                        source=segment.source,
                        path=segment.path,
                        start=m.start(),
                        end=m.end(),
                        evidence=clip(m.group(0)),
                        message=message,
                        tool_name=segment.tool_name,
                    )
                )
    return _escalate(segment, findings)


def _escalate(segment: Segment, findings: list[Finding]) -> list[Finding]:
    """HIGH signal plus a second signal or an exfiltration target -> CRITICAL."""
    high = [f for f in findings if f.severity >= Severity.HIGH]
    if not high:
        return findings
    rules = {f.rule_id for f in findings}
    reasons = sorted(rules)
    has_url = bool(_URL_RE.search(segment.text))
    has_sensitive = bool(_SENSITIVE_RE.search(segment.text))
    if has_url:
        reasons.append("url")
    if has_sensitive:
        reasons.append("sensitive-path")
    if len(rules) < 2 and not has_url and not has_sensitive:
        return findings
    strongest = high[0]
    out = [replace(f, severity=Severity.CRITICAL) if f is strongest else f for f in findings]
    out.append(
        Finding(
            rule_id="INJ-COMPOSITE",
            category=Category.PROMPT_INJECTION,
            severity=Severity.CRITICAL,
            source=segment.source,
            path=segment.path,
            start=0,
            end=len(segment.text),
            evidence=clip(" + ".join(reasons)),
            message="Injection combined with another signal or an exfiltration target",
            tool_name=segment.tool_name,
        )
    )
    return out
