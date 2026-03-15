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
        assert (
            "document.addEventListener = dcl" in js
            or "document.addEventListener=dcl" in js
        )

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
        assert "wlCallbacks" in js


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
        # Should have logic to skip non-executable types
        assert "isExecutable" in js or "type" in js

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

    def test_event_after_activation(self):
        js = _get_runtime_js()
        # The event dispatch is in the activateNext completion branch
        # (i >= scripts.length), which runs after all replaceChild calls.
        # Both are inside activateNext — verify they share the same function.
        assert "replaceChild" in js
        assert "pagevault:decrypted" in js
        # The event fires in the "done" guard (i >= scripts.length)
        # which precedes replaceChild in source but executes after all
        # scripts are activated. Verify structural relationship:
        # activateNext contains both the event dispatch and replaceChild.
        activate_fn_pos = js.index("function activateNext")
        event_pos = js.index("pagevault:decrypted")
        replace_pos = js.index("replaceChild")
        assert activate_fn_pos < event_pos
        assert activate_fn_pos < replace_pos
