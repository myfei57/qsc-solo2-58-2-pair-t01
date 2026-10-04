"""Column-name tokenization and keyword matching.

Column names come in many shapes (``user_email``, ``emailAddress``,
``EMAIL1``, ``客户手机号``). Names are normalized into lowercase ASCII tokens
(with camelCase split) plus contiguous CJK phrases, and category keyword
phrases are matched against the normalized text so a phrase only hits on a
real token boundary rather than as an arbitrary substring.
"""

from __future__ import annotations

import re

_ASCII_RUN = re.compile(r"[a-z0-9]+")
_CJK_RUN = re.compile(r"[一-鿿㐀-䶿]+")
_CAMEL_STEP = re.compile(r"[a-z0-9]+|[A-Z]+(?=[A-Z][a-z]|\b)|[A-Z]?[a-z]+|[0-9]+")


def _ascii_tokens(text: str) -> list[str]:
    tokens: list[str] = []
    for chunk in re.split(r"[^A-Za-z0-9]+", text):
        if not chunk:
            continue
        tokens.extend(part.lower() for part in _CAMEL_STEP.findall(chunk) if part)
    return tokens


def normalize(name: str) -> str:
    text = name.strip()
    tokens = _ascii_tokens(text)
    cjk = " ".join(_CJK_RUN.findall(text))
    return " ".join(tokens + ([cjk] if cjk else []))


def name_tokens(name: str) -> list[str]:
    text = name.strip()
    tokens = _ascii_tokens(text)
    tokens.extend(_CJK_RUN.findall(text))
    return tokens


def phrase_tokens(phrase: str) -> list[str]:
    text = phrase.strip().lower()
    if _CJK_RUN.fullmatch(text):
        return [text]
    return _ASCII_RUN.findall(text)


def phrase_hit(normalized: str, phrase: str) -> bool:
    needle = phrase.strip().lower()
    if not needle:
        return False
    if _CJK_RUN.fullmatch(needle):
        # CJK phrases match inside a contiguous CJK run.
        return needle in normalized.replace(" ", "")
    tokens = normalized.split()
    parts = phrase_tokens(needle)
    if not parts:
        return False
    if len(parts) == 1:
        return parts[0] in tokens
    # multi-token phrases must appear as a contiguous token subsequence
    for start in range(0, len(tokens) - len(parts) + 1):
        if tokens[start : start + len(parts)] == parts:
            return True
    return False
