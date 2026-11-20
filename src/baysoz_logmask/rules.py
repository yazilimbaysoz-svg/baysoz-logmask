"""Ordered detection rules shared by the masking engine and the CLI."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from .validators import (
    always_valid,
    is_card,
    is_email,
    is_iban,
    is_ipv4,
    is_tckn,
    is_tr_mobile,
)

type Label = str | Callable[[re.Match[str]], str]


@dataclass(frozen=True, slots=True)
class Rule:
    """A single detector: a pattern, an optional checksum and a replacement label."""

    name: str
    description: str
    pattern: re.Pattern[str]
    label: Label
    validate: Callable[[str], bool] = always_valid
    priority: int = 100


def _secret_label(match: re.Match[str]) -> str:
    key = re.sub(r"[^A-Z0-9]+", "_", match.group(1).upper()).strip("_")
    prefix_length = match.start(2) - match.start(0)
    return match.group(0)[:prefix_length] + f"[REDACTED:{key}]"


RULES: tuple[Rule, ...] = (
    Rule(
        name="private_key",
        description="PEM özel anahtar blokları",
        pattern=re.compile(
            r"-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----.*?-----END \1-----",
            re.DOTALL,
        ),
        label="[PRIVATE_KEY]",
        priority=0,
    ),
    Rule(
        name="jwt",
        description="JWT belirteçleri",
        pattern=re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"),
        label="[JWT]",
        priority=1,
    ),
    Rule(
        name="bearer",
        description="Bearer yetkilendirme değerleri",
        pattern=re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{12,}", re.IGNORECASE),
        label="[BEARER]",
        priority=2,
    ),
    Rule(
        name="aws_key",
        description="AWS erişim anahtarları",
        pattern=re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        label="[AWS_KEY]",
        priority=3,
    ),
    Rule(
        name="github_token",
        description="GitHub kişisel erişim belirteçleri",
        pattern=re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
        label="[GITHUB_TOKEN]",
        priority=4,
    ),
    Rule(
        name="secret_assignment",
        description="anahtar/değer biçimindeki sır atamaları",
        pattern=re.compile(
            r"\b(api[_-]?key|access[_-]?token|token|secret|password|passwd|authorization)\b"
            r"[\"']?\s*[:=]\s*[\"']?(?!(?:Bearer|Basic)\b)([^\s\"'\[\],;}{]{6,})",
            re.IGNORECASE,
        ),
        label=_secret_label,
        priority=5,
    ),
    Rule(
        name="iban",
        description="IBAN numaraları (mod-97 doğrulamalı)",
        pattern=re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b"),
        label="[IBAN]",
        validate=is_iban,
        priority=10,
    ),
    Rule(
        name="card",
        description="ödeme kartı numaraları (Luhn doğrulamalı)",
        pattern=re.compile(r"\b\d(?:[ -]?\d){12,18}\b"),
        label="[CARD]",
        validate=is_card,
        priority=11,
    ),
    Rule(
        name="tckn",
        description="Türkiye kimlik numaraları (sağlama doğrulamalı)",
        pattern=re.compile(r"\b\d{11}\b"),
        label="[TCKN]",
        validate=is_tckn,
        priority=12,
    ),
    Rule(
        name="email",
        description="e-posta adresleri",
        pattern=re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        label="[EMAIL]",
        validate=is_email,
        priority=13,
    ),
    Rule(
        name="phone_tr",
        description="Türkiye cep telefonu numaraları",
        pattern=re.compile(r"(?<!\w)(?:\+90[\s]?|0)?5\d{2}[\s.\-]?\d{3}[\s.\-]?\d{2}[\s.\-]?\d{2}\b"),
        label="[PHONE]",
        validate=is_tr_mobile,
        priority=14,
    ),
    Rule(
        name="ipv4",
        description="IPv4 adresleri",
        pattern=re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        label="[IP]",
        validate=is_ipv4,
        priority=15,
    ),
)
