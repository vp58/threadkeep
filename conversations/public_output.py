"""Audience-aware Discord output filtering shared by both orchestrators."""
from __future__ import annotations

import re


MAX_PUBLIC_RESPONSE_CHARS = 100_000
SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"\b(?:mfa\.[A-Za-z0-9_-]{20,}|[A-Za-z0-9_-]{23,28}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{20,})\b"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{16,}=*"),
    re.compile(r"(?i)\b(?:https?|postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s/@:]+:[^\s/@]+@[^\s]+"),
    re.compile(r"(?i)\b(api[_ -]?key|access[_ -]?token|refresh[_ -]?token|token|password|secret|client[_ -]?secret|session|cookie)\s*[:=]\s*[^\s,;]+"),
)
PERSONAL_VALUE_PATTERNS = (
    ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("EMAIL", re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")),
    (
        "PHONE",
        re.compile(
            r"(?<!\d)(?:\+?\d{1,3}[-. (]*)?(?:\d{3}[-. )]*)\d{3}[-. ]*\d{4}(?!\d)"
        ),
    ),
)
PRIVACY_TOPIC_PATTERNS = (
    re.compile(r"(?i)\b(?:customer|patient|employee)\s+(?:email|phone|address|name)\s*[:=]"),
    re.compile(r"(?i)\b(?:medical record|mrn|patient name|diagnosis|prescription)\s*[:=]"),
    re.compile(r"(?i)\b(?:bank account|account number|routing number|iban|tax id|date of birth|dob|home address)\s*[:=]"),
    re.compile(r"(?i)\b(?:confidential|internal only|do not distribute|under nda)\b"),
)
PRIVATE_DETAIL_PATTERNS = (
    re.compile(
        r"(?im)\b(?:customer|patient|employee)\s+"
        r"(?:email|phone|address|name)\s*[:=]\s*[^\n]{1,500}"
    ),
    re.compile(
        r"(?im)\b(?:medical record|mrn|patient name|diagnosis|prescription)"
        r"\s*[:=]\s*[^\n]{1,500}"
    ),
    re.compile(
        r"(?im)\b(?:bank account|account number|routing number|iban|tax id|"
        r"date of birth|dob|home address)\s*[:=]\s*[^\n]{1,500}"
    ),
    re.compile(
        r"(?im)\b(?:confidential|internal only|do not distribute|under nda)\b[^\n]{0,500}"
    ),
)
SENSITIVE_DATA_PATTERNS = tuple(
    pattern for _label, pattern in PERSONAL_VALUE_PATTERNS
) + PRIVACY_TOPIC_PATTERNS


def withheld_notice(agent_name: str) -> str:
    return (
        f"{agent_name} completed the task, but its response was withheld because it "
        "matched the public-channel sensitive-data filter. Ask for a public-safe "
        "summary, or review the result in a private local session."
    )


def redact_credentials(text: str) -> str:
    redacted = text
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub("[REDACTED CREDENTIAL]", redacted)
    return redacted


def _looks_like_payment_card(text: str) -> bool:
    for candidate in re.findall(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)", text):
        digits = re.sub(r"\D", "", candidate)
        if not 13 <= len(digits) <= 19:
            continue
        total = 0
        parity = len(digits) % 2
        for index, char in enumerate(digits):
            value = int(char)
            if index % 2 == parity:
                value *= 2
                if value > 9:
                    value -= 9
            total += value
        if total % 10 == 0:
            return True
    return False


def redact_payment_cards(text: str) -> tuple[str, bool]:
    """Mask Luhn-valid payment-card candidates without dropping the response."""

    found = False

    def replace(match: re.Match[str]) -> str:
        nonlocal found
        candidate = match.group(0)
        if not _looks_like_payment_card(candidate):
            return candidate
        found = True
        return "[REDACTED PAYMENT CARD]"

    return re.sub(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)", replace, text), found


def contains_secret_data(text: str) -> bool:
    """Return whether text contains credentials or a valid payment-card number."""

    return any(pattern.search(text) for pattern in SECRET_PATTERNS) or _looks_like_payment_card(
        text
    )


def contains_sensitive_data(text: str) -> bool:
    """Return whether text matches the bounded public-channel DLP heuristic.

    Callers can use this before a durable write. This remains a pattern-based
    safety net, not a complete secret or personal-data classifier.
    """

    return contains_secret_data(text) or any(
        pattern.search(text) for pattern in SENSITIVE_DATA_PATTERNS
    )


def public_safe_output(
    text: str,
    *,
    agent_name: str = "Disco Party",
    channel_trust: str = "public",
) -> str:
    """Redact for a declared audience while preserving the useful response.

    Credentials and payment-card numbers are masked at every trust level.
    Personal values are additionally masked in the default ``public`` mode.
    ``owner_private`` is only safe when the caller independently proves that the
    parent channel denies @everyone and has exactly the owner and bridge as
    effective readers.
    """

    if channel_trust not in {"public", "owner_private"}:
        raise ValueError("unsupported Discord channel trust level")
    stripped = text.strip() or f"{agent_name} returned an empty response."
    notes: list[str] = []
    redacted = redact_credentials(stripped)
    if redacted != stripped:
        notes.append("credentials")
    redacted, card_found = redact_payment_cards(redacted)
    if card_found:
        notes.append("payment card numbers")
    if channel_trust == "public":
        for label, pattern in PERSONAL_VALUE_PATTERNS:
            redacted, count = pattern.subn(f"[REDACTED {label}]", redacted)
            if count:
                notes.append(f"{label.lower()} values")
        for pattern in PRIVATE_DETAIL_PATTERNS:
            redacted, count = pattern.subn("[REDACTED PRIVATE DETAIL]", redacted)
            if count:
                notes.append("private detail")
        if any(pattern.search(redacted) for pattern in PRIVACY_TOPIC_PATTERNS):
            notes.append("possible private detail; review before sharing")
    # Redact the complete response before applying the Discord size bound. If
    # truncation splits a structured credential such as a PEM block, filtering
    # only the prefix can remove its closing delimiter and defeat the matcher.
    if len(redacted) > MAX_PUBLIC_RESPONSE_CHARS:
        redacted = (
            redacted[:MAX_PUBLIC_RESPONSE_CHARS].rstrip()
            + f"\n\n[Response truncated at {MAX_PUBLIC_RESPONSE_CHARS} characters; "
            "ask for the remainder.]"
        )
    if notes:
        redacted = (
            redacted.rstrip()
            + "\n\n[Bridge filter masked: "
            + "; ".join(dict.fromkeys(notes))
            + f". Channel trust is '{channel_trust}'.]"
        )
    return redacted
