"""Browser tests for "remember": what it stores, and that it still works.

Remembering must never put a password in browser storage. It keeps the key
the password derives for the page's salt: a non-extractable CryptoKey in
IndexedDB ('local'), or the key bytes in sessionStorage ('session').

Skipped if Playwright is not installed.
"""

import json
import time
from pathlib import Path

import pytest

from pagevault.parser import lock_html

pytest.importorskip("playwright.sync_api")

PASSWORD = "correct horse battery staple"
SALT = bytes(range(16))

_DUMP_STORAGE = """async () => {
  const records = [];
  const dbs = indexedDB.databases ? await indexedDB.databases() : [];
  if (dbs.some(d => d.name === 'pagevault')) {
    const db = await new Promise(r => {
      const q = indexedDB.open('pagevault'); q.onsuccess = () => r(q.result);
    });
    if (db.objectStoreNames.contains('keys')) {
      const all = await new Promise(r => {
        const q = db.transaction('keys').objectStore('keys').getAll();
        q.onsuccess = () => r(q.result);
      });
      for (const e of all) {
        let exported = false;
        try { await crypto.subtle.exportKey('raw', e.key); exported = true; }
        catch (err) {}
        records.push({salt: e.salt, expires: e.expires,
                      isKey: e.key instanceof CryptoKey,
                      extractable: e.key.extractable, exported});
      }
    }
    db.close();
  }
  return {local: JSON.stringify({...localStorage}),
          session: JSON.stringify({...sessionStorage}),
          records};
}"""


@pytest.fixture
def context(browser):
    """One browser profile per test; pages in it share storage."""
    ctx = browser.new_context()
    yield ctx
    ctx.close()


def _locked_page(tmp_path: Path, name: str, attrs: str = "", **kwargs) -> str:
    html = (
        f"<html><body><pagevault {attrs}><p id='secret'>{name}</p>"
        "</pagevault></body></html>"
    )
    path = tmp_path / f"{name}.html"
    if "users" not in kwargs:
        kwargs.setdefault("password", PASSWORD)
    path.write_text(lock_html(html, salt=SALT, **kwargs), encoding="utf-8")
    return f"file://{path}"


def _submit(page, password=PASSWORD, username=None, remember=False):
    page.wait_for_selector("input[type=password]")
    page.evaluate(
        """([password, username, remember]) => {
            const user = document.querySelector('.pagevault-username');
            if (user) user.value = username;
            document.querySelector('input[type=password]').value = password;
            const box = document.querySelector('input[name=remember]');
            if (box) box.checked = remember;
            document.querySelector('button[type=submit]').click();
        }""",
        [password, username, remember],
    )


def _wait_decrypted(page):
    page.wait_for_function("document.querySelector('pagevault')._pvDecrypted === true")


def _storage(page, until=None, timeout=5.0):
    """Dump storage; with ``until``, poll until it holds."""
    deadline = time.monotonic() + timeout
    while True:
        dump = page.evaluate(_DUMP_STORAGE)
        if until is None or until(dump) or time.monotonic() > deadline:
            return dump
        time.sleep(0.05)


def _assert_no_password(dump, password=PASSWORD):
    assert password not in dump["local"]
    assert password not in dump["session"]
    assert password not in json.dumps(dump["records"])


def _stays_locked(page):
    """The prompt is showing and no stored key unlocks the page."""
    page.wait_for_selector("input[type=password]")
    page.wait_for_timeout(500)  # give any auto-unlock time to happen
    return page.evaluate("document.querySelector('pagevault')._pvDecrypted") is False


class TestRememberLocal:
    def test_stores_a_non_extractable_key_not_the_password(self, context, tmp_path):
        page = context.new_page()
        page.goto(_locked_page(tmp_path, "one"))
        _submit(page, remember=True)
        _wait_decrypted(page)

        dump = _storage(page, until=lambda d: d["records"])
        _assert_no_password(dump)
        assert dump["records"] == [
            {
                "salt": SALT.hex(),
                "expires": None,
                "isKey": True,
                "extractable": False,
                "exported": False,
            }
        ]

    def test_reopens_this_and_other_pages_with_the_same_salt(self, context, tmp_path):
        first, second = _locked_page(tmp_path, "one"), _locked_page(tmp_path, "two")
        page = context.new_page()
        page.goto(first)
        _submit(page, remember=True)
        _wait_decrypted(page)
        _storage(page, until=lambda d: d["records"])

        page.reload()
        _wait_decrypted(page)
        other = context.new_page()
        other.goto(second)
        _wait_decrypted(other)
        assert other.locator("#secret").text_content() == "two"

    def test_key_for_a_different_password_leaves_the_page_locked(
        self, context, tmp_path
    ):
        page = context.new_page()
        page.goto(_locked_page(tmp_path, "one"))
        _submit(page, remember=True)
        _wait_decrypted(page)
        _storage(page, until=lambda d: d["records"])

        page.goto(_locked_page(tmp_path, "other", password="a different one"))
        assert _stays_locked(page)

    def test_unchecked_box_remembers_nothing(self, context, tmp_path):
        url = _locked_page(tmp_path, "one")
        page = context.new_page()
        page.goto(url)
        _submit(page, remember=False)
        _wait_decrypted(page)

        assert _storage(page)["records"] == []
        page.reload()
        assert _stays_locked(page)

    def test_multi_user_key_reopens_the_page(self, context, tmp_path):
        url = _locked_page(
            tmp_path, "team", users={"alice": "pw-alice", "bob": "pw-bob"}
        )
        page = context.new_page()
        page.goto(url)
        _submit(page, password="pw-alice", username="alice", remember=True)
        _wait_decrypted(page)
        _assert_no_password(_storage(page, until=lambda d: d["records"]), "pw-alice")

        page.reload()
        _wait_decrypted(page)

    def test_expired_key_is_dropped(self, context, tmp_path):
        url = _locked_page(tmp_path, "one")
        page = context.new_page()
        page.goto(url)
        _submit(page, remember=True)
        _wait_decrypted(page)
        _storage(page, until=lambda d: d["records"])
        page.evaluate(
            """async () => {
                const db = await new Promise(r => {
                  const q = indexedDB.open('pagevault');
                  q.onsuccess = () => r(q.result);
                });
                const store = db.transaction('keys', 'readwrite').objectStore('keys');
                const e = await new Promise(r => {
                  const q = store.get(%r); q.onsuccess = () => r(q.result);
                });
                e.expires = Date.now() - 1000;
                await new Promise(r => { store.put(e).onsuccess = r; });
                db.close();
            }"""
            % SALT.hex()
        )

        page.reload()
        assert _stays_locked(page)
        assert _storage(page, until=lambda d: not d["records"])["records"] == []

    def test_logout_fragment_forgets_keys(self, context, tmp_path):
        url = _locked_page(tmp_path, "one")
        page = context.new_page()
        page.goto(url)
        _submit(page, remember=True)
        _wait_decrypted(page)
        _storage(page, until=lambda d: d["records"])

        # Logout is a link from elsewhere: a load, not a same-page hash change.
        page.goto("about:blank")
        page.goto(url + "#pagevault_logout")
        page.wait_for_url(url)
        assert _stays_locked(page)
        assert _storage(page)["records"] == []


class TestRememberSession:
    def test_session_keeps_key_bytes_not_the_password(self, context, tmp_path):
        url = _locked_page(tmp_path, "one", attrs='remember="session"')
        page = context.new_page()
        page.goto(url)
        _submit(page)
        _wait_decrypted(page)

        dump = _storage(page, until=lambda d: "pagevault_keys" in d["session"])
        _assert_no_password(dump)
        assert dump["records"] == []
        assert SALT.hex() in json.loads(json.loads(dump["session"])["pagevault_keys"])

        page.reload()
        _wait_decrypted(page)
        # sessionStorage is per tab: a new tab must ask again.
        other = context.new_page()
        other.goto(url)
        assert _stays_locked(other)


def test_legacy_plaintext_passwords_are_purged(context, tmp_path):
    url = _locked_page(tmp_path, "one")
    page = context.new_page()
    page.goto(url)
    page.evaluate(
        """(pw) => {
            localStorage.setItem('pagevault_passwords',
              JSON.stringify({[location.origin]: {password: pw, expires: null}}));
            sessionStorage.setItem('pagevault_passwords',
              JSON.stringify({password: pw}));
        }""",
        PASSWORD,
    )

    page.reload()
    assert _stays_locked(page)  # the old entry is not used either
    _assert_no_password(_storage(page))
