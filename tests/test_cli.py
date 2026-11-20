"""CLI tests covering stdin, files, JSON, hash mode and the module entry point."""

from __future__ import annotations

import io
import json
import os
import secrets
import subprocess
import sys

import pytest

from baysoz_logmask.cli import main


def test_list_rules(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--list-rules"]) == 0
    output = capsys.readouterr().out
    assert "tckn" in output
    assert "private_key" in output


def test_stdin_masking(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO("posta=aday@example.com\n"))
    assert main([]) == 0
    assert capsys.readouterr().out == "posta=[EMAIL]\n"


def test_file_json_and_stats(tmp_path, capsys: pytest.CaptureFixture[str]) -> None:
    source = tmp_path / "girdi.txt"
    source.write_text("kimlik=10000000146\n", encoding="utf-8")
    assert main([str(source), "--json", "--stats"]) == 0
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert report[str(source)] == "kimlik=[TCKN]\n"
    assert json.loads(captured.err) == {"tckn": 1}


def test_hash_mode_without_key_fails(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("LOGMASK_KEY", raising=False)
    assert main(["--mode", "hash"]) == 2
    assert "LOGMASK_KEY" in capsys.readouterr().err


def test_hash_mode_with_key(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO("kimlik=10000000146\n"))
    monkeypatch.setenv("LOGMASK_KEY", secrets.token_hex(32))
    assert main(["--mode", "hash"]) == 0
    output = capsys.readouterr().out
    assert "[TCKN:" in output
    assert "10000000146" not in output


def test_custom_key_env(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO("posta=aday@example.com\n"))
    monkeypatch.setenv("OZEL_ANAHTAR", secrets.token_hex(32))
    assert main(["--mode", "hash", "--key-env", "OZEL_ANAHTAR"]) == 0
    assert "[EMAIL:" in capsys.readouterr().out


def test_missing_file_raises_os_error() -> None:
    with pytest.raises(OSError):
        main(["/var/empty-baysoz-logmask-does-not-exist.txt"])


def test_module_entry_point() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "baysoz_logmask", "--version"],
        capture_output=True,
        check=True,
        text=True,
        env=os.environ.copy(),
    )
    assert result.stdout.strip() == "0.1.0"
