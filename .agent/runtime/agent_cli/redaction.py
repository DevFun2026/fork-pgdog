from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
import re


@dataclass(frozen=True)
class RedactionResult:
    text: str
    redaction_count: int


_PRIVATE_BLOCK = re.compile(r"<no-memory>.*?</no-memory>", re.DOTALL | re.IGNORECASE)
_UNCLOSED_PRIVATE = re.compile(r"<no-memory>.*\Z", re.DOTALL | re.IGNORECASE)
_PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?"
    r"-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)
_SECRET_PATTERNS = (
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\b(?:ghp_|github_pat_)[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bAIza[A-Za-z0-9_-]{20,}\b"),
)


def redact(text: str, secrets: Iterable[str] = ()) -> RedactionResult:
    if not isinstance(text, str):
        raise TypeError("text must be a string")

    redacted, count = _PRIVATE_BLOCK.subn("[REDACTED_PRIVATE]", text)
    redacted, additional = _UNCLOSED_PRIVATE.subn("[REDACTED_PRIVATE]", redacted)
    count += additional
    redacted, additional = _PRIVATE_KEY.subn("[REDACTED_SECRET]", redacted)
    count += additional

    for secret in sorted({item for item in secrets if item}, key=len, reverse=True):
        occurrences = redacted.count(secret)
        if occurrences:
            redacted = redacted.replace(secret, "[REDACTED_SECRET]")
            count += occurrences

    for pattern in _SECRET_PATTERNS:
        redacted, additional = pattern.subn("[REDACTED_SECRET]", redacted)
        count += additional

    return RedactionResult(text=redacted, redaction_count=count)
