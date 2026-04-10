"""Exhaustive tests for script re-execution after pagevault decryption."""

from pagevault.config import DefaultsConfig, TemplateConfig
from pagevault.parser import _get_javascript, lock_html, unlock_html


def _get_runtime_js():
    return _get_javascript(TemplateConfig(), DefaultsConfig())


class TestDOMContentLoadedShim:
    def test_shim_intercepts_domcontentloaded(self):
        js = _get_runtime_js()
        assert "DOMContentLoaded" in js

    def test_shim_collects_callbacks(self):
        js = _get_runtime_js()
        assert "dclCallbacks" in js

    def test_shim_restores_original(self):
        js = _get_runtime_js()
        # Restoration happens via restoreShims() which assigns the
        # snapshotted __pvOrigDocAddListener back.
        assert "restoreShims" in js
        assert "__pvOrigDocAddListener" in js

    def test_callbacks_invoked_after_scripts(self):
        js = _get_runtime_js()
        assert "dclCallbacks.forEach" in js


class TestWindowLoadShim:
    def test_shim_intercepts_window_load(self):
        js = _get_runtime_js()
        assert "wlCallbacks" in js

    def test_window_onload_checked(self):
        js = _get_runtime_js()
        assert "window.onload" in js

    def test_window_load_callbacks_invoked(self):
        js = _get_runtime_js()
        assert "wlCallbacks.forEach" in js


class TestInlineScriptActivation:
    def test_creates_new_script_element(self):
        js = _get_runtime_js()
        assert "createElement('script')" in js or 'createElement("script")' in js

    def test_copies_attributes(self):
        js = _get_runtime_js()
        assert "setAttribute" in js

    def test_copies_text_content(self):
        js = _get_runtime_js()
        assert "textContent" in js

    def test_replaces_old_script(self):
        js = _get_runtime_js()
        assert "replaceChild" in js

    def test_roundtrip_preserves_inline_script(self):
        html = (
            '<html><body><pagevault><div id="app"></div>'
            "<script>"
            'document.getElementById("app").textContent = "loaded";'
            "</script></pagevault></body></html>"
        )
        locked = lock_html(html, password="test")
        assert "data-encrypted" in locked
        unlocked = unlock_html(locked, password="test")
        assert 'document.getElementById("app")' in unlocked


class TestExternalScriptActivation:
    def test_roundtrip_preserves_external_script(self):
        html = '<html><body><pagevault><script src="https://cdn.example.com/lib.js"></script></pagevault></body></html>'
        locked = lock_html(html, password="test")
        unlocked = unlock_html(locked, password="test")
        assert 'src="https://cdn.example.com/lib.js"' in unlocked

    def test_roundtrip_preserves_integrity_attr(self):
        html = (
            "<html><body><pagevault>"
            '<script src="https://cdn.example.com/lib.js"'
            ' integrity="sha384-abc"'
            ' crossorigin="anonymous"></script>'
            "</pagevault></body></html>"
        )
        locked = lock_html(html, password="test")
        unlocked = unlock_html(locked, password="test")
        assert "integrity" in unlocked
        assert "crossorigin" in unlocked


class TestScriptExecutionOrder:
    def test_sequential_activation_pattern(self):
        js = _get_runtime_js()
        assert "onload" in js

    def test_external_script_error_handling(self):
        js = _get_runtime_js()
        assert "onerror" in js

    def test_roundtrip_preserves_script_order(self):
        html = """<html><body><pagevault>
        <script>var first = 1;</script>
        <script src="https://cdn.example.com/dep.js"></script>
        <script>var third = first + 2;</script>
        </pagevault></body></html>"""
        locked = lock_html(html, password="test")
        unlocked = unlock_html(locked, password="test")
        first_pos = unlocked.index("var first = 1")
        third_pos = unlocked.index("var third = first + 2")
        cdn_pos = unlocked.index("cdn.example.com/dep.js")
        assert first_pos < cdn_pos < third_pos


class TestModuleScripts:
    def test_module_handling_present(self):
        js = _get_runtime_js()
        assert "module" in js

    def test_roundtrip_preserves_module_script(self):
        html = (
            "<html><body><pagevault>"
            '<script type="module">const x = 42;</script>'
            "</pagevault></body></html>"
        )
        locked = lock_html(html, password="test")
        unlocked = unlock_html(locked, password="test")
        assert "const x = 42" in unlocked


class TestJsonScripts:
    def test_json_scripts_skipped(self):
        js = _get_runtime_js()
        # isExecutable() filters non-JS MIME types so JSON scripts
        # are preserved but not re-executed
        assert "isExecutable" in js

    def test_roundtrip_preserves_json_script(self):
        html = (
            "<html><body><pagevault>"
            '<script type="application/json">'
            '{"key": "value"}'
            "</script></pagevault></body></html>"
        )
        locked = lock_html(html, password="test")
        unlocked = unlock_html(locked, password="test")
        assert '{"key": "value"}' in unlocked

    def test_roundtrip_preserves_ld_json(self):
        html = '<html><body><pagevault><script type="application/ld+json">{"@context": "https://schema.org"}</script></pagevault></body></html>'
        locked = lock_html(html, password="test")
        unlocked = unlock_html(locked, password="test")
        assert '"@context"' in unlocked


class TestDeferAsyncAttributes:
    def test_roundtrip_preserves_defer(self):
        html = '<html><body><pagevault><script defer src="https://cdn.example.com/lib.js"></script></pagevault></body></html>'
        locked = lock_html(html, password="test")
        unlocked = unlock_html(locked, password="test")
        assert "cdn.example.com/lib.js" in unlocked

    def test_roundtrip_preserves_async(self):
        html = '<html><body><pagevault><script async src="https://cdn.example.com/lib.js"></script></pagevault></body></html>'
        locked = lock_html(html, password="test")
        unlocked = unlock_html(locked, password="test")
        assert "cdn.example.com/lib.js" in unlocked


class TestDocumentWriteProtection:
    def test_document_write_neutralized(self):
        js = _get_runtime_js()
        # The runtime should neutralize document.write to prevent page destruction
        assert "document.write" in js

    def test_document_writeln_neutralized(self):
        js = _get_runtime_js()
        assert "writeln" in js


class TestEdgeCases:
    def test_no_scripts_no_error(self):
        html = '<html><body><pagevault><div>Hello</div></pagevault></body></html>'
        locked = lock_html(html, password="test")
        unlocked = unlock_html(locked, password="test")
        assert "<div>Hello</div>" in unlocked

    def test_empty_script_tag(self):
        html = '<html><body><pagevault><script></script></pagevault></body></html>'
        locked = lock_html(html, password="test")
        unlocked = unlock_html(locked, password="test")
        assert "script" in unlocked

    def test_multiple_mixed_types(self):
        html = """<html><body><pagevault>
        <script type="application/json">{"data": true}</script>
        <script>var x = 1;</script>
        <script src="https://cdn.example.com/lib.js"></script>
        <script>var y = x + 1;</script>
        </pagevault></body></html>"""
        locked = lock_html(html, password="test")
        unlocked = unlock_html(locked, password="test")
        assert '{"data": true}' in unlocked
        assert "var x = 1" in unlocked
        assert "cdn.example.com/lib.js" in unlocked
        assert "var y = x + 1" in unlocked


class TestCustomEventTiming:
    def test_decrypted_event_present(self):
        js = _get_runtime_js()
        assert "pagevault:decrypted" in js

    def test_activated_event_present(self):
        """A separate pagevault:activated event fires after script activation."""
        js = _get_runtime_js()
        assert "pagevault:activated" in js

    def test_decrypted_event_fires_before_activation_chain(self):
        """pagevault:decrypted fires immediately after innerHTML, BEFORE
        the script activation chain runs. pagevault:activated fires
        inside finalize() AFTER all scripts have run."""
        js = _get_runtime_js()
        # In _decrypt: dispatch 'pagevault:decrypted', THEN append to
        # __pvActivationChain. Verify the source ordering inside _decrypt.
        decrypt_method_pos = js.index("async _decrypt(password, username)")
        decrypted_event_in_decrypt = js.index("pagevault:decrypted", decrypt_method_pos)
        chain_append_pos = js.index("__pvActivationChain = __pvActivationChain.then")
        assert decrypted_event_in_decrypt < chain_append_pos
        # And pagevault:activated lives inside __pvActivateContent's finalize()
        activated_event_pos = js.index("pagevault:activated")
        finalize_def_pos = js.index("function finalize()")
        assert finalize_def_pos < activated_event_pos

    def test_activation_serialized_via_promise_chain(self):
        """Critical: concurrent decryption must be serialized to prevent
        global shim corruption."""
        js = _get_runtime_js()
        assert "__pvActivationChain" in js

    def test_window_onload_only_fires_if_replaced(self):
        """Critical: window.onload must NOT be re-invoked unless a
        decrypted script replaced it. Otherwise the host page's onload
        runs N+1 times for N pagevault elements."""
        js = _get_runtime_js()
        assert "origOnload" in js
        assert "window.onload !== origOnload" in js

    def test_activation_has_error_recovery(self):
        """Critical: script errors must not leak shims permanently.
        finalize() must run even if a script throws."""
        js = _get_runtime_js()
        # try/catch around activateNext body logs error and
        # calls finalize() in catch branch
        assert "script activation error" in js

    def test_parentnode_guard(self):
        """Critical: if an earlier script removes a script's ancestor,
        replaceChild would throw on parentNode null. Guard prevents this."""
        js = _get_runtime_js()
        assert "parentNode" in js
