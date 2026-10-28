"""Browser tests for wrapped files and sites in real Chromium.

Sites render inside a srcdoc iframe whose pages talk to the wrapper over
postMessage (navigation, and fetch() of bundled files); wrapped files are
decrypted and verified by the file renderer. These behaviors only exist in
a browser, so they are tested here rather than with string checks.

Skipped if Playwright is not installed.
"""

import json
from pathlib import Path

import pytest
from bs4 import BeautifulSoup

from pagevault.crypto import CHUNK_SIZE
from pagevault.wrap import WrapDocument, wrap_file, wrap_site

pytest.importorskip("playwright.sync_api")


@pytest.fixture
def page(browser):
    context = browser.new_context()
    page = context.new_page()
    yield page
    context.close()


def _unlock(page, path: Path, password: str = "pw", username: str | None = None):
    """Open a wrapped file in ``page`` and submit the password prompt."""
    page.goto(f"file://{path}")
    if username is not None:
        page.fill("input[autocomplete=username]", username)
    page.fill("input.pagevault-password", password)
    page.press("input.pagevault-password", "Enter")


def _open_site(page, tmp_path: Path, files: dict[str, str]):
    """Wrap ``files`` as a site, unlock it in ``page``; return the site frame."""
    site = tmp_path / "site"
    for name, text in files.items():
        (site / name).parent.mkdir(parents=True, exist_ok=True)
        (site / name).write_text(text, encoding="utf-8")
    out = wrap_site(site, password="pw", output_path=tmp_path / "site.html")

    _unlock(page, out)
    page.wait_for_selector("iframe.pagevault-site-frame")
    frame = page.frame_locator("iframe.pagevault-site-frame")
    frame.locator("body").wait_for()
    return page.frames[1]


def test_fetch_during_page_load_reaches_bundled_file(page, tmp_path):
    """A page script that fetches at load time must get the bundled file.

    The fetch shim has to be installed before the page's own scripts run.
    """
    frame = _open_site(
        page,
        tmp_path,
        {
            "index.html": (
                "<!DOCTYPE html><html><head><script>"
                "fetch('data/info.json').then(r => r.json())"
                ".then(d => { document.title = 'got:' + d.v; })"
                ".catch(e => { document.title = 'error:' + e; });"
                "</script></head><body>home</body></html>"
            ),
            "data/info.json": '{"v": "bundled"}',
        },
    )

    frame.wait_for_function("document.title.includes(':')")
    assert frame.title() == "got:bundled"


def test_fetch_after_load_reaches_bundled_file(page, tmp_path):
    frame = _open_site(
        page,
        tmp_path,
        {"index.html": "<p>home</p>", "notes.txt": "plain notes"},
    )

    text = frame.evaluate("fetch('notes.txt').then(r => r.text())")
    assert text == "plain notes"


def test_page_content_survives_shim_injection(page, tmp_path):
    """The page is re-serialized around the shim; its own markup must hold.

    Head metadata stays in the head, inline scripts run once, in order, and
    escaped text stays text.
    """
    frame = _open_site(
        page,
        tmp_path,
        {
            "index.html": (
                '<!DOCTYPE html><html lang="en"><head><title>Home</title>'
                '<meta name="k" content="v"><style>p{color:red}</style></head>'
                "<body><p id='t'>a &lt;b&gt; c</p>"
                "<script>window.order = (window.order || '') + '1';</script>"
                "<script>window.order += '2';</script></body></html>"
            )
        },
    )

    assert frame.title() == "Home"
    assert frame.evaluate("document.documentElement.lang") == "en"
    assert frame.evaluate("document.head.querySelector('meta[name=k]').content") == "v"
    assert frame.inner_text("#t") == "a <b> c"
    assert frame.evaluate("window.order") == "12"


def test_link_navigation_between_pages(page, tmp_path):
    frame = _open_site(
        page,
        tmp_path,
        {
            "index.html": '<a id="go" href="about.html">about</a>',
            "about.html": "<h1 id='about'>About page</h1>",
        },
    )

    frame.click("#go")
    page.frame_locator("iframe.pagevault-site-frame").locator("#about").wait_for()
    assert page.frames[1].inner_text("#about") == "About page"


def test_foreign_page_in_site_frame_cannot_read_bundled_files(page, tmp_path):
    """A page the user navigates to inside the site iframe shares its window
    object with the site's pages, but must not be answered by the wrapper."""
    attacker = tmp_path / "attacker.html"
    attacker.write_text(
        "<script>window.got = 'none';"
        "addEventListener('message', e => {"
        "  if (e.data && e.data.type === 'pagevault-fetch-response')"
        "    window.got = e.data.data ? 'LEAKED' : 'answered';"
        "});"
        "parent.postMessage({type: 'pagevault-fetch', path: 'secret.txt', id: 1}, '*');"
        "</script>"
    )
    frame = _open_site(
        page, tmp_path, {"index.html": "<p>home</p>", "secret.txt": "PAYROLL"}
    )

    with page.expect_event("framenavigated"):
        frame.evaluate(f"location.href = {json.dumps(attacker.as_uri())}")
    frame.wait_for_function("window.got !== undefined")
    page.wait_for_timeout(500)  # time for a reply to arrive, if one were sent

    assert frame.url == attacker.as_uri()
    assert frame.evaluate("window.got") == "none"


def _file_text(page) -> str:
    page.wait_for_selector(".pagevault-viewer pre, .pagevault-error")
    return page.inner_text(".pagevault-viewer pre, .pagevault-error")


def test_truncated_wrapped_file_is_refused(page, tmp_path):
    """Dropping trailing chunks (and fixing the cleartext counts) is detected."""
    src = tmp_path / "big.txt"
    src.write_text("x" * (CHUNK_SIZE + 1000))
    out = wrap_file(src, password="pw", output_path=tmp_path / "big.html")
    soup = BeautifulSoup(out.read_text(), "html.parser")
    meta = soup.find("script", id="pv-meta")
    envelope = json.loads(meta.string)
    envelope.update(chunk_count=1, total_size=CHUNK_SIZE)
    meta.string = json.dumps(envelope)
    soup.find("script", id="pv-1").decompose()
    out.write_text(str(soup))

    _unlock(page, out)

    assert "truncated" in _file_text(page)


def test_rekeyed_file_opens_for_remaining_user_only(page, tmp_path):
    users = {"alice": "pw-a", "bob": "pw-b"}
    src = tmp_path / "notes.txt"
    src.write_text("payroll notes")
    out = wrap_file(src, users=users, output_path=tmp_path / "notes.html")
    out.write_text(
        WrapDocument.parse(out.read_text()).rekey(
            old_users=users, new_users={"alice": "pw-a"}
        )
    )

    _unlock(page, out, "pw-a", username="alice")
    assert _file_text(page) == "payroll notes"

    _unlock(page, out, "pw-b", username="bob")
    page.wait_for_selector(".pagevault-error:not(:empty)")
    assert "Wrong password" in page.inner_text(".pagevault-error")
    assert page.query_selector(".pagevault-viewer") is None
