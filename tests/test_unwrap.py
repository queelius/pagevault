"""Tests for decrypting and re-keying wrapped (file/site) HTML.

Wrapped files use a document-level encoding (``<script id="pv-meta">`` +
``<script id="pv-N">``) that ``unlock_html``/``sync_html_keys`` do not
handle. ``WrapDocument`` is the Python-side counterpart of the browser's
file/site renderer, used by the ``unlock`` and ``sync`` commands.
"""

import io
import json
import os
import zipfile
from pathlib import Path

import pytest
from bs4 import BeautifulSoup
from click.testing import CliRunner

from pagevault.cli import main
from pagevault.crypto import CHUNK_SIZE, PagevaultError, encrypt_v4
from pagevault.parser import lock_html
from pagevault.wrap import (
    WrapDocument,
    WrapKind,
    _generate_wrap_html_v4,
    unwrap_html,
    wrap_file,
    wrap_site,
)

USERS = {"alice": "pw-a", "bob": "pw-b"}


def _envelope(html: str) -> dict:
    soup = BeautifulSoup(html, "html.parser")
    return json.loads(soup.find("script", {"id": "pv-meta"}).string)


def _runtime_scripts(html: str) -> list[str]:
    soup = BeautifulSoup(html, "html.parser")
    return [s.string for s in soup.find_all("script", {"data-pagevault-runtime": True})]


def _wrap_bytes(tmp_path: Path, data: bytes, name: str = "doc.bin", **kw) -> str:
    src = tmp_path / name
    src.write_bytes(data)
    return wrap_file(src, output_path=tmp_path / f"{name}.html", **kw).read_text()


def _crafted_wrap(data: bytes, meta: dict) -> str:
    """A wrap document whose (authenticated) meta the author fully controls."""
    envelope, chunks = encrypt_v4(data, password="pw", meta=meta)
    return _generate_wrap_html_v4(envelope, chunks, title="t")


class TestParse:
    def test_wrap_file_is_recognized(self, tmp_path):
        assert WrapDocument.parse(_wrap_bytes(tmp_path, b"x", password="pw"))

    @pytest.mark.parametrize(
        "html",
        [
            "<html><body><p>plain</p></body></html>",
            "<html><body><pagevault>marked</pagevault></body></html>",
            lock_html("<html><body><pagevault>region</pagevault></body></html>", "pw"),
        ],
        ids=["plain", "marked", "region-locked"],
    )
    def test_other_documents_are_not(self, html):
        assert WrapDocument.parse(html) is None

    @pytest.mark.parametrize(
        ("meta_json", "chunks", "match"),
        [
            ("{not json", "", "pv-meta JSON"),
            ("[1, 2]", "", "JSON object"),
            ('{"chunk_count": -1}', "", "chunk_count"),
            (
                '{"chunk_count": 2}',
                '<script id="pv-0" type="x-pv">AA==</script>',
                "chunk 1",
            ),
        ],
        ids=["bad-json", "not-object", "negative-count", "missing-chunk"],
    )
    def test_malformed_document_raises(self, meta_json, chunks, match):
        html = (
            f'<html><body><script id="pv-meta" type="application/json">{meta_json}'
            f"</script>{chunks}<pagevault data-pv-chunked></pagevault></body></html>"
        )

        with pytest.raises(PagevaultError, match=match):
            WrapDocument.parse(html)

    def test_unwrap_html_rejects_other_documents(self):
        with pytest.raises(PagevaultError, match="Not a pagevault wrapped file"):
            unwrap_html("<html><body><pagevault>x</pagevault></body></html>", "pw")


class TestDecryptFile:
    @pytest.mark.parametrize("pad", [False, True])
    def test_returns_exact_original_bytes(self, tmp_path, pad):
        # Trailing NULs must survive: unpadding is by authenticated size,
        # never by stripping zeros.
        data = b"\x00\x01binary\xff" + b"\x00" * 5
        doc = WrapDocument.parse(_wrap_bytes(tmp_path, data, password="pw", pad=pad))

        payload = doc.decrypt("pw")

        assert payload.kind is WrapKind.FILE
        assert payload.data == data
        assert payload.filename == "doc.bin"
        assert payload.meta["mime"] == "application/octet-stream"

    def test_multi_user(self, tmp_path):
        doc = WrapDocument.parse(_wrap_bytes(tmp_path, b"shared", users=USERS))

        assert doc.decrypt("pw-b", username="bob").data == b"shared"

    def test_wrong_password_raises(self, tmp_path):
        doc = WrapDocument.parse(_wrap_bytes(tmp_path, b"x", password="pw"))

        with pytest.raises(PagevaultError):
            doc.decrypt("nope")

    def test_dropped_chunk_is_detected(self, tmp_path):
        """Rewriting the cleartext chunk_count/total_size can't hide truncation."""
        data = os.urandom(CHUNK_SIZE + 1000)
        html = _wrap_bytes(tmp_path, data, password="pw")
        soup = BeautifulSoup(html, "html.parser")
        meta_el = soup.find("script", {"id": "pv-meta"})
        envelope = json.loads(meta_el.string)
        envelope["chunk_count"] = 1
        envelope["total_size"] = CHUNK_SIZE
        meta_el.string = json.dumps(envelope)
        soup.find("script", {"id": "pv-1"}).decompose()

        with pytest.raises(PagevaultError, match="truncated"):
            WrapDocument.parse(str(soup)).decrypt("pw")

    @pytest.mark.parametrize(
        ("stored", "expected"),
        [
            ("../../.bashrc", ".bashrc"),
            ("/etc/passwd", "passwd"),
            ("a\\b.txt", "b.txt"),
        ],
    )
    def test_filename_is_reduced_to_a_bare_name(self, stored, expected):
        html = _crafted_wrap(b"x", {"type": "file", "filename": stored, "size": 1})

        assert WrapDocument.parse(html).decrypt("pw").filename == expected

    @pytest.mark.parametrize("stored", ["", "..", "."])
    def test_unusable_filename_raises(self, stored):
        html = _crafted_wrap(b"x", {"type": "file", "filename": stored, "size": 1})
        payload = WrapDocument.parse(html).decrypt("pw")

        with pytest.raises(PagevaultError, match="filename"):
            payload.filename

    def test_unknown_payload_type_raises(self):
        html = _crafted_wrap(b"x", {"type": "mystery", "size": 1})

        with pytest.raises(PagevaultError, match="mystery"):
            WrapDocument.parse(html).decrypt("pw")

    def test_hash_mismatch_raises(self):
        html = _crafted_wrap(
            b"x", {"type": "file", "filename": "a", "size": 1, "content_hash": "00"}
        )

        with pytest.raises(PagevaultError, match="hash mismatch"):
            WrapDocument.parse(html).decrypt("pw")

    def test_file_payload_is_not_a_site(self, tmp_path):
        payload = WrapDocument.parse(
            _wrap_bytes(tmp_path, b"x", password="pw")
        ).decrypt("pw")

        with pytest.raises(PagevaultError, match="not a site"):
            payload.extract_site(tmp_path / "out")


class TestDecryptSite:
    def test_extracts_tree(self, tmp_path):
        site = tmp_path / "site"
        (site / "sub").mkdir(parents=True)
        (site / "index.html").write_text("<h1>home</h1>")
        (site / "sub" / "a.css").write_text("p{}")
        doc = WrapDocument.parse(wrap_site(site, password="pw", pad=True).read_text())
        dest = tmp_path / "out"

        payload = doc.decrypt("pw")
        payload.extract_site(dest)

        assert payload.kind is WrapKind.SITE
        assert (dest / "index.html").read_text() == "<h1>home</h1>"
        assert (dest / "sub" / "a.css").read_text() == "p{}"

    @pytest.mark.parametrize(
        "member",
        ["../escape.txt", "/abs.txt", "a/../../b.txt", "a\\..\\..\\b.txt", "C:/x.txt"],
    )
    def test_refuses_members_outside_destination(self, tmp_path, member):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("index.html", "ok")
            zf.writestr(member, "pwned")
        data = buf.getvalue()
        html = _crafted_wrap(
            data, {"type": "site", "entry": "index.html", "size": len(data)}
        )
        dest = tmp_path / "deep" / "out"

        with pytest.raises(PagevaultError, match="outside"):
            WrapDocument.parse(html).decrypt("pw").extract_site(dest)
        assert not list(tmp_path.rglob("*.txt"))

    def test_filename_is_not_defined_for_sites(self, tmp_path):
        site = tmp_path / "site"
        site.mkdir()
        (site / "index.html").write_text("x")
        doc = WrapDocument.parse(wrap_site(site, password="pw").read_text())

        with pytest.raises(PagevaultError):
            doc.decrypt("pw").filename

    def test_corrupt_archive_raises(self, tmp_path):
        html = _crafted_wrap(b"not a zip", {"type": "site", "entry": "index.html"})

        with pytest.raises(PagevaultError, match="not a valid zip"):
            WrapDocument.parse(html).decrypt("pw").extract_site(tmp_path / "out")


class TestRekey:
    def test_revokes_removed_user(self, tmp_path):
        html = _wrap_bytes(tmp_path, b"payroll", users=USERS)

        rekeyed = WrapDocument.parse(html).rekey(
            old_users=USERS, new_users={"alice": "pw-a"}
        )

        doc = WrapDocument.parse(rekeyed)
        assert doc.decrypt("pw-a", username="alice").data == b"payroll"
        with pytest.raises(PagevaultError):
            doc.decrypt("pw-b", username="bob")

    def test_preserves_padding_runtime_and_meta(self, tmp_path):
        html = _wrap_bytes(tmp_path, b"x" * 1000, users=USERS, pad=True)

        rekeyed = WrapDocument.parse(html).rekey(old_users=USERS, new_users=USERS)

        assert _envelope(rekeyed)["total_size"] == _envelope(html)["total_size"] == 1024
        assert _runtime_scripts(rekeyed) == _runtime_scripts(html)
        payload = WrapDocument.parse(rekeyed).decrypt("pw-a", username="alice")
        assert payload.data == b"x" * 1000
        assert payload.filename == "doc.bin"

    def test_no_valid_old_credential_raises(self, tmp_path):
        html = _wrap_bytes(tmp_path, b"x", users=USERS)

        with pytest.raises(PagevaultError, match="credentials"):
            WrapDocument.parse(html).rekey(
                old_users={"mallory": "guess"}, new_users={"mallory": "guess"}
            )


class TestUnlockCli:
    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_unlock_writes_original_file(self, runner, tmp_path):
        data = b"%PDF-1.7\x00\xff"
        locked = tmp_path / "locked"
        locked.mkdir()
        (tmp_path / "report.pdf").write_bytes(data)
        wrap_file(
            tmp_path / "report.pdf",
            password="pw",
            output_path=locked / "report.pdf.html",
        )
        out = tmp_path / "out"

        result = runner.invoke(
            main, ["unlock", str(locked), "-r", "-p", "pw", "-d", str(out)]
        )

        assert result.exit_code == 0, result.output
        assert (out / "report.pdf").read_bytes() == data
        assert not (out / "report.pdf.html").exists()
        assert "1 file(s) unlocked" in result.output

    def test_unlock_dry_run_names_destination_and_writes_nothing(
        self, runner, tmp_path
    ):
        src = tmp_path / "a.txt"
        src.write_text("secret")
        wrap_file(src, password="pw", output_path=tmp_path / "wrapped.html")
        out = tmp_path / "out"

        result = runner.invoke(
            main,
            [
                "unlock",
                str(tmp_path / "wrapped.html"),
                "-p",
                "pw",
                "-d",
                str(out),
                "--dry-run",
            ],
        )

        assert result.exit_code == 0, result.output
        assert "Would unlock:" in result.output
        assert "a.txt" in result.output
        assert not out.exists()

    def test_unlock_stdout_emits_raw_bytes(self, runner, tmp_path):
        data = b"\x89PNG\r\n\x1a\n\x00binary"
        html = tmp_path / "img.png.html"
        html.write_text(
            _crafted_wrap(
                data,
                {
                    "type": "file",
                    "filename": "img.png",
                    "mime": "image/png",
                    "size": len(data),
                },
            )
        )

        result = runner.invoke(main, ["unlock", str(html), "-p", "pw", "--stdout"])

        assert result.exit_code == 0, result.output
        assert result.stdout_bytes == data

    def test_unlock_site_extracts_directory(self, runner, tmp_path):
        site = tmp_path / "site"
        site.mkdir()
        (site / "index.html").write_text("<p>hi</p>")
        wrap_site(site, password="pw", output_path=tmp_path / "site.html")
        out = tmp_path / "out"

        result = runner.invoke(
            main, ["unlock", str(tmp_path / "site.html"), "-p", "pw", "-d", str(out)]
        )

        assert result.exit_code == 0, result.output
        assert (out / "site" / "index.html").read_text() == "<p>hi</p>"

    def test_unlock_wrap_wrong_password_writes_nothing(self, runner, tmp_path):
        src = tmp_path / "a.txt"
        src.write_text("secret")
        wrap_file(src, password="pw", output_path=tmp_path / "a.txt.html")
        out = tmp_path / "out"

        result = runner.invoke(
            main, ["unlock", str(tmp_path / "a.txt.html"), "-p", "bad", "-d", str(out)]
        )

        assert "Error processing" in result.output
        assert "0 file(s) unlocked" in result.output
        assert not out.exists()

    def test_unlock_does_not_claim_success_for_unencrypted_regions(
        self, runner, tmp_path
    ):
        page = tmp_path / "marked.html"
        page.write_text(
            "<html><body><pagevault>not yet locked</pagevault></body></html>"
        )
        out = tmp_path / "out"

        result = runner.invoke(main, ["unlock", str(page), "-p", "pw", "-d", str(out)])

        assert result.exit_code == 0, result.output
        assert "0 file(s) unlocked, 1 skipped" in result.output
        assert not out.exists()

    def test_unlock_stdout_refuses_file_without_encrypted_content(
        self, runner, tmp_path
    ):
        page = tmp_path / "marked.html"
        page.write_text(
            "<html><body><pagevault>not yet locked</pagevault></body></html>"
        )

        result = runner.invoke(main, ["unlock", str(page), "-p", "pw", "--stdout"])

        assert result.exit_code != 0
        assert "not yet locked" not in result.stdout


class TestSyncCli:
    @pytest.fixture
    def runner(self):
        return CliRunner()

    def _config(self, tmp_path: Path, users: dict[str, str]) -> Path:
        cfg = tmp_path / ".pagevault.yaml"
        cfg.write_text("users:\n" + "".join(f"  {u}: {p}\n" for u, p in users.items()))
        return cfg

    def test_sync_revokes_removed_user_from_wrapped_file(self, runner, tmp_path):
        target = tmp_path / "doc.txt.html"
        target.write_text(_wrap_bytes(tmp_path, b"payroll", users=USERS))
        cfg = self._config(tmp_path, {"alice": "pw-a"})

        result = runner.invoke(main, ["sync", str(target), "-c", str(cfg)])

        assert result.exit_code == 0, result.output
        assert "Synced:" in result.output
        doc = WrapDocument.parse(target.read_text())
        assert doc.decrypt("pw-a", username="alice").data == b"payroll"
        with pytest.raises(PagevaultError):
            doc.decrypt("pw-b", username="bob")

    def test_sync_dry_run_lists_wrapped_file(self, runner, tmp_path):
        target = tmp_path / "doc.txt.html"
        original = _wrap_bytes(tmp_path, b"payroll", users=USERS)
        target.write_text(original)
        cfg = self._config(tmp_path, USERS)

        result = runner.invoke(main, ["sync", str(target), "-c", str(cfg), "--dry-run"])

        assert "Would sync:" in result.output
        assert target.read_text() == original
