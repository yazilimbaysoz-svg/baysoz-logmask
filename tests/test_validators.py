"""Validator unit tests, including negative cases that must stay unmasked."""

import pytest

from baysoz_logmask.validators import (
    always_valid,
    is_card,
    is_email,
    is_iban,
    is_ipv4,
    is_tckn,
    is_tr_mobile,
)


def _build_tckn(first_nine: str) -> str:
    digits = [int(char) for char in first_nine]
    tenth = (sum(digits[0::2]) * 7 - sum(digits[1::2])) % 10
    first_ten = first_nine + str(tenth)
    return first_ten + str(sum(int(char) for char in first_ten) % 10)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("10000000146", True),
        (_build_tckn("123456789"), True),
        ("12345678901", False),
        ("00000000146", False),
        ("1000000014", False),
        ("100000001462", False),
        ("1000000014A", False),
    ],
)
def test_is_tckn(value: str, expected: bool) -> None:
    assert is_tckn(value) is expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("TR330006100519786457841326", True),
        ("TR33 0006 1005 1978 6457 8413 26", True),
        ("TR330006100519786457841327", False),
        ("ZZ330006100519786457841326", False),
        ("TR3300061005197864578413", False),
    ],
)
def test_is_iban(value: str, expected: bool) -> None:
    assert is_iban(value) is expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("4111111111111111", True),
        ("4111 1111 1111 1111", True),
        ("4111-1111-1111-1111", True),
        ("4111111111111112", False),
        ("411111111111", False),
    ],
)
def test_is_card(value: str, expected: bool) -> None:
    assert is_card(value) is expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("aday@example.com", True),
        ("ad.ay+etiket@example.co.uk", True),
        ("a..b@example.com", False),
        ("user@localhost", False),
        ("-bad@example.com", False),
        ("aday@example..com", False),
    ],
)
def test_is_email(value: str, expected: bool) -> None:
    assert is_email(value) is expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("192.168.1.44", True),
        ("8.8.8.8", True),
        ("999.1.1.1", False),
        ("01.2.3.4", False),
        ("1.2.3", False),
        ("1.2.3.4.5", False),
    ],
)
def test_is_ipv4(value: str, expected: bool) -> None:
    assert is_ipv4(value) is expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("0532 123 45 67", True),
        ("+90 532 123 45 67", True),
        ("905321234567", True),
        ("05321234567", True),
        ("0532 123 45", False),
        ("1234567890", False),
    ],
)
def test_is_tr_mobile(value: str, expected: bool) -> None:
    assert is_tr_mobile(value) is expected


def test_always_valid() -> None:
    assert always_valid("herhangi bir metin") is True
