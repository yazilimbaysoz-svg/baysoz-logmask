"""Command line interface for baysoz-logmask."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from contextlib import ExitStack

from . import __version__
from .masker import Masker, mask_stream, merge_stats
from .rules import RULES

_DEFAULT_KEY_ENV = "LOGMASK_KEY"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="baysoz-logmask",
        description="Log metnindeki kişisel verileri ve sırları maskele.",
    )
    parser.add_argument("paths", nargs="*", help="girdi dosyaları; verilmezse stdin okunur")
    parser.add_argument(
        "--mode",
        choices=("label", "hash"),
        default="label",
        help="maskeleme biçimi",
    )
    parser.add_argument(
        "--key-env",
        default=_DEFAULT_KEY_ENV,
        help=f"hash modunda anahtarın okunacağı ortam değişkeni (öntanımlı: {_DEFAULT_KEY_ENV})",
    )
    parser.add_argument("--json", action="store_true", help="çıktıyı JSON nesnesi olarak ver")
    parser.add_argument("--stats", action="store_true", help="kural sayımlarını stderr'e yaz")
    parser.add_argument("--list-rules", action="store_true", help="kuralları listele ve çık")
    parser.add_argument("--version", action="version", version=__version__)
    return parser


def _load_key(mode: str, key_env: str) -> bytes | None:
    if mode != "hash":
        return None
    value = os.environ.get(key_env)
    if not value:
        raise ValueError(f"{key_env} ortam değişkeni boş")
    return value.encode("utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.list_rules:
        for rule in RULES:
            print(f"{rule.name:18} {rule.description}")
        return 0

    try:
        masker = Masker(mode=args.mode, key=_load_key(args.mode, args.key_env))
    except ValueError as exc:
        print(f"hata: {exc}", file=sys.stderr)
        return 2

    stats: dict[str, int] = {}
    if args.json:
        report: dict[str, str] = {}
        with ExitStack() as stack:
            sources = [stack.enter_context(open(path, encoding="utf-8")) for path in args.paths]
            if not sources:
                sources = [sys.stdin]
            for path, source in zip(args.paths or ["-"], sources, strict=True):
                masked, counts = masker.mask_with_stats(source.read())
                report[path] = masked
                merge_stats(stats, counts)
        json.dump(report, sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
    else:
        with ExitStack() as stack:
            sources = [stack.enter_context(open(path, encoding="utf-8")) for path in args.paths]
            if not sources:
                sources = [sys.stdin]
            for source in sources:
                merge_stats(stats, mask_stream(source, sys.stdout, masker))

    if args.stats:
        print(json.dumps(stats, ensure_ascii=False, sort_keys=True), file=sys.stderr)
    return 0
