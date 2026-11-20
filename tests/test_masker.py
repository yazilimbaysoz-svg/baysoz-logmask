"""End-to-end masking tests for every rule and for overlap/idempotency behaviour."""

from __future__ import annotations

import io
import secrets

import pytest

from baysoz_logmask.masker import Masker, mask_stream, merge_stats

_PEM = "-----BEGIN RSA PRIVATE KEY-----\nAB\nCD\n-----END RSA PRIVATE KEY-----"
_JWT = "eyJ" + "a" * 8 + "." + "b" * 8 + "." + "c" * 8


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("kimlik=10000000146", "kimlik=[TCKN]"),
        ("iban TR330006100519786457841326", "iban [IBAN]"),
        ("kart 4111 1111 1111 1111", "kart [CARD]"),
        ("posta aday@example.com", "posta [EMAIL]"),
        ("ip 192.168.1.44", "ip [IP]"),
        ("tel 0532 123 45 67", "tel [PHONE]"),
        ("Bearer " + "a" * 24, "[BEARER]"),
        ("Bearer " + _JWT, "[BEARER]"),
        (_JWT, "[JWT]"),
        ("AKIA" + "B" * 16, "[AWS_KEY]"),
        ("ghp_" + "A" * 36, "[GITHUB_TOKEN]"),
        ("api_key=" + "x" * 12, "api_key=[REDACTED:API_KEY]"),
        ('{"token": "' + "q" * 12 + '"}', '{"token": "[REDACTED:TOKEN]"}'),
        ("Authorization: Bearer " + "z" * 20, "Authorization: [BEARER]"),
        ("kimlik=12345678901", "kimlik=12345678901"),
        ("iban TR330006100519786457841327", "iban TR330006100519786457841327"),
        ("kimlik=1234567890", "kimlik=1234567890"),
        ("ip 999.1.1.1", "ip 999.1.1.1"),
    ],
    ids=[
        "tckn",
        "iban",
        "card",
        "email",
        "ipv4",
        "phone",
        "bearer",
        "bearer_jwt",
        "jwt",
        "aws_key",
        "github_token",
        "secret_assignment",
        "json_secret",
        "authorization_bearer",
        "invalid_tckn",
        "invalid_iban",
        "ten_digits",
        "invalid_ip",
    ],
)
def test_rule_masking(raw: str, expected: str) -> None:
    assert Masker().mask(raw) == expected


def test_private_key_block_is_masked_with_line_breaks_preserved() -> None:
    raw = "önce\n" + _PEM + "\nsonra\n"
    masked = Masker().mask(raw)
    assert masked.startswith("önce\n[PRIVATE_KEY]")
    assert masked.endswith("\nsonra\n")
    assert masked.count("\n") == raw.count("\n")


def test_private_key_block_with_crlf() -> None:
    raw = _PEM.replace("\n", "\r\n")
    masked = Masker().mask(raw)
    assert masked.count("\r\n") == raw.count("\r\n")


def test_masking_is_idempotent() -> None:
    masker = Masker()
    raw = "kimlik=10000000146 posta=aday@example.com api_key=" + "x" * 12 + " " + _JWT + "\n" + _PEM
    once = masker.mask(raw)
    assert masker.mask(once) == once


def test_stats_count_each_rule() -> None:
    masked, stats = Masker().mask_with_stats("kimlik=10000000146 posta=aday@example.com")
    assert masked == "kimlik=[TCKN] posta=[EMAIL]"
    assert stats == {"tckn": 1, "email": 1}


def test_merge_stats() -> None:
    target = {"tckn": 1}
    assert merge_stats(target, {"tckn": 2, "email": 1}) == {"tckn": 3, "email": 1}
    assert target == {"tckn": 3, "email": 1}


def test_hash_mode_is_deterministic_and_keyed() -> None:
    first_key = secrets.token_bytes(32)
    second_key = secrets.token_bytes(32)
    first = Masker(mode="hash", key=first_key).mask("kimlik=10000000146")
    second = Masker(mode="hash", key=first_key).mask("kimlik=10000000146")
    other = Masker(mode="hash", key=second_key).mask("kimlik=10000000146")
    assert first == second
    assert first != other
    assert first.startswith("kimlik=[TCKN:")
    assert "10000000146" not in first


def test_invalid_configuration_is_rejected() -> None:
    with pytest.raises(ValueError):
        Masker(mode="bilinmeyen")
    with pytest.raises(ValueError):
        Masker(mode="hash")


def test_mask_stream_buffers_only_private_key_blocks() -> None:
    raw = "kimlik=10000000146\n" + _PEM + "\nip 192.168.1.44\n"
    output = io.StringIO()
    stats = mask_stream(io.StringIO(raw), output, Masker())
    assert "[TCKN]" in output.getvalue()
    assert "[PRIVATE_KEY]" in output.getvalue()
    assert "[IP]" in output.getvalue()
    assert stats == {"tckn": 1, "private_key": 1, "ipv4": 1}


def test_unterminated_private_key_block_is_flushed() -> None:
    raw = "-----BEGIN RSA PRIVATE KEY-----\nAB\n"
    output = io.StringIO()
    mask_stream(io.StringIO(raw), output, Masker())
    assert output.getvalue() == raw
