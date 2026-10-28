"""Tests for pagevault._fs.atomic_write."""

import os
import stat

import pytest

from pagevault._fs import atomic_write


def _mode(path):
    return stat.S_IMODE(path.stat().st_mode)


def test_writes_text_and_bytes(tmp_path):
    atomic_write(tmp_path / "a" / "t.html", "héllo")
    atomic_write(tmp_path / "b.bin", b"\x00\xff")

    assert (tmp_path / "a" / "t.html").read_text(encoding="utf-8") == "héllo"
    assert (tmp_path / "b.bin").read_bytes() == b"\x00\xff"


def test_name_at_the_filesystem_limit(tmp_path):
    limit = os.pathconf(tmp_path, "PC_NAME_MAX")
    target = tmp_path / ("a" * (limit - len(".html")) + ".html")

    atomic_write(target, "x")

    assert target.read_text() == "x"


def test_interrupted_write_keeps_old_file_and_no_temp(tmp_path, monkeypatch):
    target = tmp_path / "locked.html"
    target.write_text("old ciphertext")

    def interrupted(*args):
        raise KeyboardInterrupt

    monkeypatch.setattr(os, "replace", interrupted)
    with pytest.raises(KeyboardInterrupt):
        atomic_write(target, "new ciphertext")

    assert target.read_text() == "old ciphertext"
    assert [p.name for p in tmp_path.iterdir()] == ["locked.html"]


def test_new_file_gets_umask_mode_not_tempfile_mode(tmp_path):
    old = os.umask(0o022)
    try:
        atomic_write(tmp_path / "new.html", "x")
    finally:
        os.umask(old)

    assert _mode(tmp_path / "new.html") == 0o644


def test_existing_file_keeps_its_mode(tmp_path):
    target = tmp_path / "keep.html"
    target.write_text("x")
    target.chmod(0o640)

    atomic_write(target, "y")

    assert _mode(target) == 0o640


def test_explicit_mode_overrides_existing(tmp_path):
    target = tmp_path / "secret.yaml"
    target.write_text("old")
    target.chmod(0o644)

    atomic_write(target, "new", mode=0o600)

    assert target.read_text() == "new"
    assert _mode(target) == 0o600


def test_writes_through_a_symlink(tmp_path):
    target = tmp_path / "dotfiles" / "pagevault.yaml"
    target.parent.mkdir()
    target.write_text("old")
    link = tmp_path / ".pagevault.yaml"
    link.symlink_to(target)

    atomic_write(link, "new", mode=0o600)

    assert link.is_symlink()
    assert target.read_text() == "new"
    assert _mode(target) == 0o600
