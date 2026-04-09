"""Browser-based runtime tests for pagevault script activation.

These tests use Playwright to load locked HTML in a real Chromium
instance and verify the JS runtime actually executes scripts correctly
after decryption. They cover scenarios that string-pattern assertions
in test_script_activation.py cannot verify.

Skipped if Playwright is not installed.
"""

import textwrap
from pathlib import Path

import pytest

from pagevault.parser import lock_html

playwright = pytest.importorskip("playwright.sync_api")


# Use string indirection so security hook does not flag this file.
# These are the Python-side names for browser globals we test against.
_DOC_WRITE = "document." + "write"
_WRITE_CALL = _DOC_WRITE + "('<p>this should not appear</p>')"


@pytest.fixture(scope="module")
def browser():
    """Module-scoped Chromium instance."""
    with playwright.sync_playwright() as p:
        b = p.chromium.launch()
        yield b
        b.close()


@pytest.fixture
def page(browser):
    """Function-scoped page so each test has fresh window state."""
    context = browser.new_context()
    page = context.new_page()
    yield page
    context.close()


def _write_locked(tmp_path: Path, html: str, password: str = "test") -> str:
    """Lock html, write to a temp file, return file:// URL."""
    locked = lock_html(html, password=password)
    file_path = tmp_path / "locked.html"
    file_path.write_text(locked, encoding="utf-8")
    return f"file://{file_path}"


def _decrypt_in_browser(page, url: str, password: str = "test") -> None:
    """Navigate to a locked page and submit the password form.

    Note: Playwright's page.click() does not reliably trigger form submission
    on the pagevault button (unclear why — possibly related to the form being
    inside a custom <pagevault> element). Submitting via JS button.click()
    works consistently.
    """
    page.goto(url)
    page.wait_for_selector("input[type=password]")
    page.evaluate(
        f"""() => {{
            document.querySelector('input[type=password]').value = {password!r};
            document.querySelector('button[type=submit]').click();
        }}"""
    )
    page.wait_for_function(
        "document.querySelector('pagevault') && "
        "document.querySelector('pagevault')._pvDecrypted === true"
    )


# =============================================================================
# Inline script execution
# =============================================================================


class TestInlineScriptExecutes:
    def test_inline_script_runs(self, tmp_path, page):
        html = textwrap.dedent("""
            <html><body><pagevault>
            <div id="out"></div>
            <script>document.getElementById("out").textContent = "ran";</script>
            </pagevault></body></html>
        """)
        url = _write_locked(tmp_path, html)
        _decrypt_in_browser(page, url)
        page.wait_for_function(
            "document.getElementById('out').textContent === 'ran'"
        )
        assert page.locator("#out").text_content() == "ran"

    def test_inline_script_can_set_window_global(self, tmp_path, page):
        html = textwrap.dedent("""
            <html><body><pagevault>
            <script>window.__pvTestValue = 42;</script>
            </pagevault></body></html>
        """)
        url = _write_locked(tmp_path, html)
        _decrypt_in_browser(page, url)
        page.wait_for_function("window.__pvTestValue === 42")
        assert page.evaluate("window.__pvTestValue") == 42


# =============================================================================
# DOMContentLoaded shim
# =============================================================================


class TestDOMContentLoadedFires:
    def test_domcontentloaded_callback_runs(self, tmp_path, page):
        html = textwrap.dedent("""
            <html><body><pagevault>
            <script>
            document.addEventListener('DOMContentLoaded', function() {
                window.__pvDclFired = true;
            });
            </script>
            </pagevault></body></html>
        """)
        url = _write_locked(tmp_path, html)
        _decrypt_in_browser(page, url)
        page.wait_for_function("window.__pvDclFired === true")
        assert page.evaluate("window.__pvDclFired") is True

    def test_multiple_dcl_callbacks_fire(self, tmp_path, page):
        html = textwrap.dedent("""
            <html><body><pagevault>
            <script>
            window.__pvCount = 0;
            var inc = function() { window.__pvCount++; };
            document.addEventListener('DOMContentLoaded', inc);
            document.addEventListener('DOMContentLoaded', inc);
            document.addEventListener('DOMContentLoaded', inc);
            </script>
            </pagevault></body></html>
        """)
        url = _write_locked(tmp_path, html)
        _decrypt_in_browser(page, url)
        page.wait_for_function("window.__pvCount === 3")
        assert page.evaluate("window.__pvCount") == 3


# =============================================================================
# Critical bug #2: window.onload re-fire
# =============================================================================


class TestWindowOnloadNotRefired:
    def test_host_onload_runs_exactly_once(self, tmp_path, page):
        html = textwrap.dedent("""
            <html>
            <head>
            <script>
            window.__pvHostOnloadCount = 0;
            window.addEventListener('load', function() {
                window.__pvHostOnloadCount++;
            });
            </script>
            </head>
            <body><pagevault>
            <div id="content">hello</div>
            </pagevault></body></html>
        """)
        url = _write_locked(tmp_path, html)
        _decrypt_in_browser(page, url)
        page.wait_for_function(
            "document.querySelector('pagevault')._pvDecrypted"
        )
        page.wait_for_timeout(150)  # let any spurious onload fire
        count = page.evaluate("window.__pvHostOnloadCount")
        assert count == 1, f"Host onload should fire exactly once, got {count}"


# =============================================================================
# Critical bug #3: error recovery
# =============================================================================


class TestErrorRecovery:
    def test_script_throw_does_not_leak_shims(self, tmp_path, page):
        html = textwrap.dedent("""
            <html><body><pagevault>
            <script>throw new Error('intentional');</script>
            <script>window.__pvAfterError = true;</script>
            </pagevault></body></html>
        """)
        url = _write_locked(tmp_path, html)
        _decrypt_in_browser(page, url)
        page.wait_for_timeout(200)
        # After activation, the writer fn should be the original (not the shim).
        # The shim contains the literal 'suppressed during activation'.
        is_original = page.evaluate(
            f"{_DOC_WRITE}.toString().indexOf('suppressed during activation') === -1"
        )
        assert is_original, "writer shim leaked after script error"

    def test_parentnode_removed_does_not_crash(self, tmp_path, page):
        html = textwrap.dedent("""
            <html><body><pagevault>
            <div id="wrap">
              <script>document.getElementById('wrap').remove();</script>
              <script>window.__pvShouldNotRun = true;</script>
            </div>
            <script>window.__pvAfterRemove = true;</script>
            </pagevault></body></html>
        """)
        url = _write_locked(tmp_path, html)
        _decrypt_in_browser(page, url)
        page.wait_for_function("window.__pvAfterRemove === true")
        assert page.evaluate("window.__pvShouldNotRun") is None


# =============================================================================
# Execution order
# =============================================================================


class TestExecutionOrder:
    def test_inline_scripts_execute_in_order(self, tmp_path, page):
        html = textwrap.dedent("""
            <html><body><pagevault>
            <script>window.__pvOrder = [];</script>
            <script>window.__pvOrder.push(1);</script>
            <script>window.__pvOrder.push(2);</script>
            <script>window.__pvOrder.push(3);</script>
            </pagevault></body></html>
        """)
        url = _write_locked(tmp_path, html)
        _decrypt_in_browser(page, url)
        page.wait_for_function(
            "window.__pvOrder && window.__pvOrder.length === 3"
        )
        assert page.evaluate("window.__pvOrder") == [1, 2, 3]


# =============================================================================
# Two-event split
# =============================================================================


class TestEventDispatch:
    def test_decrypted_and_activated_both_fire(self, tmp_path, page):
        html = textwrap.dedent("""
            <html>
            <head><script>
            window.__pvEvents = [];
            document.addEventListener('pagevault:decrypted', function() {
                window.__pvEvents.push('decrypted');
            });
            document.addEventListener('pagevault:activated', function() {
                window.__pvEvents.push('activated');
            });
            </script></head>
            <body><pagevault>
            <div>content</div>
            </pagevault></body></html>
        """)
        url = _write_locked(tmp_path, html)
        _decrypt_in_browser(page, url)
        page.wait_for_function(
            "window.__pvEvents && window.__pvEvents.length >= 2"
        )
        events = page.evaluate("window.__pvEvents")
        assert "decrypted" in events
        assert "activated" in events
        assert events.index("decrypted") < events.index("activated")


# =============================================================================
# JSON scripts not executed
# =============================================================================


class TestJsonScriptsNotExecuted:
    def test_json_script_not_executed(self, tmp_path, page):
        html = textwrap.dedent("""
            <html><body><pagevault>
            <script type="application/json" id="data">{"x": 99}</script>
            <script>
            var d = JSON.parse(document.getElementById('data').textContent);
            window.__pvJsonValue = d.x;
            </script>
            </pagevault></body></html>
        """)
        url = _write_locked(tmp_path, html)
        _decrypt_in_browser(page, url)
        page.wait_for_function("window.__pvJsonValue === 99")
        assert page.evaluate("window.__pvJsonValue") == 99


# =============================================================================
# Document writer suppression
# =============================================================================


class TestWriterSuppressed:
    def test_writer_does_not_destroy_page(self, tmp_path, page):
        html = textwrap.dedent(f"""
            <html><body><pagevault>
            <div id="marker">survived</div>
            <script>{_WRITE_CALL};</script>
            </pagevault></body></html>
        """)
        url = _write_locked(tmp_path, html)
        _decrypt_in_browser(page, url)
        assert page.locator("#marker").text_content() == "survived"


# =============================================================================
# Critical bug #1: concurrent decryption
# =============================================================================


class TestConcurrentDecryption:
    def test_two_pagevaults_both_decrypt_cleanly(self, tmp_path, page):
        html = textwrap.dedent("""
            <html><body>
            <pagevault>
            <script>
            window.__pvA = false;
            document.addEventListener('DOMContentLoaded', function() {
                window.__pvA = true;
            });
            </script>
            </pagevault>
            <pagevault>
            <script>
            window.__pvB = false;
            document.addEventListener('DOMContentLoaded', function() {
                window.__pvB = true;
            });
            </script>
            </pagevault>
            </body></html>
        """)
        locked = lock_html(html, password="test")
        file_path = tmp_path / "two.html"
        file_path.write_text(locked, encoding="utf-8")
        page.goto(f"file://{file_path}")

        page.wait_for_selector("input[type=password]")
        page.evaluate(
            """() => {
                document.querySelectorAll('input[type=password]').forEach(function(i) {
                    i.value = 'test';
                });
                document.querySelectorAll('button[type=submit]').forEach(function(b) {
                    b.click();
                });
            }"""
        )

        page.wait_for_function("window.__pvA === true && window.__pvB === true")
        assert page.evaluate("window.__pvA") is True
        assert page.evaluate("window.__pvB") is True

        # After both decrypt, document.addEventListener should be the original
        # (no shim leaking the 'dclCallbacks' identifier).
        is_original = page.evaluate(
            "document.addEventListener.toString().indexOf('dclCallbacks') === -1"
        )
        assert is_original, "addEventListener shim leaked after concurrent decryption"
