"""Checksum and shape validators used to keep false positives low."""

from __future__ import annotations

import re

_WHITESPACE = re.compile(r"\s+")
_IBAN_SHAPE = re.compile(r"[A-Z]{2}\d{2}[A-Z0-9]+")
_SEPARATORS = re.compile(r"[\s().-]+")


def always_valid(value: str) -> bool:
    """Accept every candidate; used for rules with an unambiguous prefix."""
    return bool(value)


def is_tckn(value: str) -> bool:
    """Validate a Turkish national identity number with its two check digits."""
    if len(value) != 11 or not value.isdigit():
        return False
    digits = [int(char) for char in value]
    if digits[0] == 0:
        return False
    odd = sum(digits[0:9:2])
    even = sum(digits[1:8:2])
    if digits[9] != (odd * 7 - even) % 10:
        return False
    return sum(digits[:10]) % 10 == digits[10]


def is_iban(value: str) -> bool:
    """Validate an IBAN with the ISO 13616 mod-97 check."""
    compact = _WHITESPACE.sub("", value).upper()
    if not 15 <= len(compact) <= 34:
        return False
    if not _IBAN_SHAPE.fullmatch(compact):
        return False
    if compact.startswith("TR") and len(compact) != 26:
        return False
    rearranged = compact[4:] + compact[:4]
    numeric = "".join(str(int(char, 36)) for char in rearranged)
    return int(numeric) % 97 == 1


def is_card(value: str) -> bool:
    """Validate a payment card number with the Luhn algorithm."""
    digits = _WHITESPACE.sub("", value).replace("-", "")
    if not 13 <= len(digits) <= 19 or not digits.isdigit():
        return False
    total = 0
    for index, char in enumerate(reversed(digits)):
        digit = int(char)
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def is_email(value: str) -> bool:
    """Reject malformed local parts and domain labels in a candidate address."""
    local, separator, domain = value.partition("@")
    if not separator or not local or local[0] in ".-" or local[-1] in ".-" or ".." in local:
        return False
    labels = domain.split(".")
    if len(labels) < 2:
        return False
    for label in labels:
        if not label or label.startswith("-") or label.endswith("-") or len(label) > 63:
            return False
    return True


def is_ipv4(value: str) -> bool:
    """Validate an IPv4 address and reject ambiguous leading zeros."""
    parts = value.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit() or len(part) > 3:
            return False
        if len(part) > 1 and part.startswith("0"):
            return False
        if int(part) > 255:
            return False
    return True


def is_tr_mobile(value: str) -> bool:
    """Validate a Turkish mobile number after removing country and trunk codes."""
    digits = _SEPARATORS.sub("", value)
    if digits.startswith("+90"):
        digits = digits[3:]
    elif digits.startswith("0") and len(digits) == 11:
        digits = digits[1:]
    elif digits.startswith("90") and len(digits) == 12:
        digits = digits[2:]
    return len(digits) == 10 and digits.startswith("5") and digits.isdigit()
