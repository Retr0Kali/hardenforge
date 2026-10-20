"""Redaction applied to every prompt before it can leave the machine."""
from __future__ import annotations

import re

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"sk-ant-[A-Za-z0-9_\-]{8,}"), "[REDACTED_KEY]"),
    (re.compile(r"sk-[A-Za-z0-9_\-]{16,}"), "[REDACTED_KEY]"),
    (re.compile(r"AIza[0-9A-Za-z_\-]{20,}"), "[REDACTED_KEY]"),
    (re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=\-]{12,}"), "Bearer [REDACTED]"),
    (re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key)\b(\s*[=:]\s*)\S+"), r"\1\2[REDACTED]"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "[REDACTED_PRIVATE_KEY]"),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"), "[REDACTED_IP]"),
    (re.compile(r"\b[A-Fa-f0-9:]{2,}(?::[A-Fa-f0-9]{0,4}){4,}\b"), "[REDACTED_IPV6]"),
    (re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"), "[REDACTED_EMAIL]"),
    (re.compile(r"/(?:home|Users)/[^/\s]+"), "/home/[USER]"),
    (re.compile(r"(?i)C:\\Users\\[^\\\s]+"), r"C:\\Users\\[USER]"),
]


def redact(text: str, extra_secrets: list[str] | None = None) -> str:
    for s in extra_secrets or []:
        if s:
            text = text.replace(s, "[REDACTED_KEY]")
    for pat, repl in _PATTERNS:
        text = pat.sub(repl, text)
    return text
