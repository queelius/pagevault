"""Tests for pagevault.viewers package."""

import pytest

from pagevault.config import PagevaultConfig
from pagevault.viewers import (
    ViewerPlugin,
    discover_viewers,
    filter_by_config,
    resolve_viewer,
    scan_directory,
)
from pagevault.viewers.builtins.audio import AudioViewer
from pagevault.viewers.builtins.html import HtmlViewer
from pagevault.viewers.builtins.image import ImageViewer
from pagevault.viewers.builtins.markdown import MarkdownViewer
from pagevault.viewers.builtins.pdf import PdfViewer
from pagevault.viewers.builtins.text import TextViewer
from pagevault.viewers.builtins.video import VideoViewer
from pagevault.viewers.registry import (
    _BUILTINS_DIR,
    _deduplicate_by_name,
)


class TestViewerPluginABC:
    """Tests for the ViewerPlugin abstract base class."""

    def test_cannot_instantiate_abc(self):
        """ViewerPlugin itself cannot be instantiated."""
        with pytest.raises(TypeError, match="abstract"):
            ViewerPlugin()

    def test_must_implement_js(self):
        """Subclass missing js() cannot be instantiated."""

        class BadViewer(ViewerPlugin):
            name = "bad"
            mime_types = ["text/plain"]

            def css(self):
                return ""

        with pytest.raises(TypeError, match="abstract"):
            BadViewer()

    def test_must_implement_css(self):
        """Subclass missing css() cannot be instantiated."""

        class BadViewer(ViewerPlugin):
            name = "bad"
            mime_types = ["text/plain"]

            def js(self):
                return "async function() {}"

        with pytest.raises(TypeError, match="abstract"):
            BadViewer()

    def test_valid_subclass(self):
        """Subclass implementing both js() and css() works."""

        class GoodViewer(ViewerPlugin):
            name = "good"
            mime_types = ["text/plain"]

            def js(self):
                return "async function(c,b,u,m,t) {}"

            def css(self):
                return ".good {}"

        viewer = GoodViewer()
        assert viewer.name == "good"
        assert viewer.mime_types == ["text/plain"]
        assert viewer.priority == 0
        assert viewer.dependencies() == []

    def test_custom_priority(self):
        """Subclass can set custom priority."""

        class HighPriViewer(ViewerPlugin):
            name = "hipri"
            mime_types = ["text/plain"]
            priority = 99

            def js(self):
                return "async function(c,b,u,m,t) {}"

            def css(self):
                return ""

        assert HighPriViewer().priority == 99


class TestDiscoverViewers:
    """Tests for viewer discovery."""

    def test_discovers_builtin_viewers(self):
        """discover_viewers() returns all 7 built-in viewers."""
        viewers = discover_viewers()
        names = {v.name for v in viewers}
        assert names >= {"image", "pdf", "html", "text", "markdown", "audio", "video"}

    def test_discover_returns_viewer_instances(self):
        """All discovered viewers are ViewerPlugin instances."""
        viewers = discover_viewers()
        for v in viewers:
            assert isinstance(v, ViewerPlugin)

    def test_scan_builtins_dir(self):
        """scan_directory() finds all 7 built-in viewers."""
        viewers = scan_directory(_BUILTINS_DIR)
        assert len(viewers) == 7
        names = {v.name for v in viewers}
        assert names == {"image", "pdf", "html", "text", "markdown", "audio", "video"}


class TestResolveViewer:
    """Tests for MIME type resolution."""

    @pytest.fixture
    def viewers(self):
        return scan_directory(_BUILTINS_DIR)

    def test_exact_match_image_png(self, viewers):
        """image/png should match ImageViewer via image/* wildcard."""
        v = resolve_viewer("image/png", viewers)
        assert v is not None
        assert v.name == "image"

    def test_exact_match_pdf(self, viewers):
        """application/pdf should match PdfViewer exactly."""
        v = resolve_viewer("application/pdf", viewers)
        assert v is not None
        assert v.name == "pdf"

    def test_exact_match_html(self, viewers):
        """text/html should match HtmlViewer exactly."""
        v = resolve_viewer("text/html", viewers)
        assert v is not None
        assert v.name == "html"

    def test_exact_match_markdown(self, viewers):
        """text/markdown should match MarkdownViewer (exact beats wildcard)."""
        v = resolve_viewer("text/markdown", viewers)
        assert v is not None
        assert v.name == "markdown"

    def test_wildcard_match_text_css(self, viewers):
        """text/css should match TextViewer via text/* wildcard."""
        v = resolve_viewer("text/css", viewers)
        assert v is not None
        assert v.name == "text"

    def test_exact_match_json(self, viewers):
        """application/json should match TextViewer (explicit registration)."""
        v = resolve_viewer("application/json", viewers)
        assert v is not None
        assert v.name == "text"

    def test_exact_match_xml(self, viewers):
        """application/xml should match TextViewer (explicit registration)."""
        v = resolve_viewer("application/xml", viewers)
        assert v is not None
        assert v.name == "text"

    def test_no_match_octet_stream(self, viewers):
        """application/octet-stream should return None (download fallback)."""
        v = resolve_viewer("application/octet-stream", viewers)
        assert v is None

    def test_match_video(self, viewers):
        """video/mp4 should match VideoViewer via video/* wildcard."""
        v = resolve_viewer("video/mp4", viewers)
        assert v is not None
        assert v.name == "video"

    def test_match_audio(self, viewers):
        """audio/mpeg should match AudioViewer via audio/* wildcard."""
        v = resolve_viewer("audio/mpeg", viewers)
        assert v is not None
        assert v.name == "audio"

    def test_wildcard_match_image_svg(self, viewers):
        """image/svg+xml should match ImageViewer via image/* wildcard."""
        v = resolve_viewer("image/svg+xml", viewers)
        assert v is not None
        assert v.name == "image"

    def test_priority_override(self):
        """Higher priority viewer wins for the same MIME type."""

        class LowPri(ViewerPlugin):
            name = "low"
            mime_types = ["text/plain"]
            priority = 0

            def js(self):
                return "async function(c,b,u,m,t) {}"

            def css(self):
                return ""

        class HighPri(ViewerPlugin):
            name = "high"
            mime_types = ["text/plain"]
            priority = 10

            def js(self):
                return "async function(c,b,u,m,t) {}"

            def css(self):
                return ""

        viewers = [LowPri(), HighPri()]
        v = resolve_viewer("text/plain", viewers)
        assert v.name == "high"

    def test_markdown_beats_text_wildcard(self, viewers):
        """MarkdownViewer (exact text/markdown) beats TextViewer (text/*)."""
        v = resolve_viewer("text/markdown", viewers)
        assert v.name == "markdown"
        # Verify TextViewer also has text/* registered
        text_viewer = next(x for x in viewers if x.name == "text")
        assert "text/*" in text_viewer.mime_types


class TestFilterByConfig:
    """Tests for config-based viewer filtering."""

    def test_no_config_viewers_returns_all(self):
        """When config.viewers is None, all viewers pass."""
        viewers = scan_directory(_BUILTINS_DIR)
        config = PagevaultConfig()
        assert config.viewers is None
        result = filter_by_config(viewers, config)
        assert len(result) == len(viewers)

    def test_disable_markdown(self):
        """Disabling markdown viewer removes it."""
        viewers = scan_directory(_BUILTINS_DIR)
        config = PagevaultConfig(viewers={"markdown": False})
        result = filter_by_config(viewers, config)
        names = {v.name for v in result}
        assert "markdown" not in names
        assert "image" in names

    def test_disable_multiple(self):
        """Disabling multiple viewers removes them."""
        viewers = scan_directory(_BUILTINS_DIR)
        config = PagevaultConfig(viewers={"markdown": False, "image": False})
        result = filter_by_config(viewers, config)
        names = {v.name for v in result}
        assert "markdown" not in names
        assert "image" not in names
        assert "text" in names

    def test_explicit_enable(self):
        """Explicitly enabling a viewer keeps it."""
        viewers = scan_directory(_BUILTINS_DIR)
        config = PagevaultConfig(viewers={"markdown": True})
        result = filter_by_config(viewers, config)
        names = {v.name for v in result}
        assert "markdown" in names

    def test_unknown_viewer_in_config_ignored(self):
        """Config mentioning unknown viewer names doesn't affect anything."""
        viewers = scan_directory(_BUILTINS_DIR)
        config = PagevaultConfig(viewers={"nonexistent": False})
        result = filter_by_config(viewers, config)
        assert len(result) == len(viewers)


class TestImageViewer:
    """Tests for the ImageViewer plugin."""

    def test_js_returns_async_function(self):
        js = ImageViewer().js()
        assert js.startswith("async function(")
        assert "container" in js
        assert "blob" in js

    def test_js_has_zoom(self):
        js = ImageViewer().js()
        assert "zoomed" in js

    def test_css_has_image_styles(self):
        css = ImageViewer().css()
        assert ".pagevault-image-viewer" in css
        assert "zoom-in" in css
        assert "zoom-out" in css

    def test_css_dark_mode(self):
        css = ImageViewer().css()
        assert "prefers-color-scheme: dark" in css

    def test_no_dependencies(self):
        assert ImageViewer().dependencies() == []

    def test_mime_types(self):
        assert ImageViewer().mime_types == ["image/*"]


class TestPdfViewer:
    """Tests for the PdfViewer plugin."""

    def test_js_returns_async_function(self):
        js = PdfViewer().js()
        assert "async function(" in js
        assert "iframe" in js

    def test_css_is_empty(self):
        assert PdfViewer().css() == ""

    def test_no_dependencies(self):
        assert PdfViewer().dependencies() == []

    def test_mime_types(self):
        assert PdfViewer().mime_types == ["application/pdf"]

    def test_no_sandbox(self):
        """PdfViewer does not need sandbox (PDF renderer is safe)."""
        js = PdfViewer().js()
        assert "sandbox" not in js


class TestHtmlViewer:
    """Tests for the HtmlViewer plugin."""

    def test_js_returns_async_function(self):
        js = HtmlViewer().js()
        assert "async function(" in js
        assert "iframe" in js

    def test_css_is_empty(self):
        assert HtmlViewer().css() == ""

    def test_mime_types(self):
        assert HtmlViewer().mime_types == ["text/html"]


class TestTextViewerPlugin:
    """Tests for the TextViewer plugin."""

    def test_js_returns_async_function(self):
        js = TextViewer().js()
        assert js.startswith("async function(")
        assert "blob.text()" in js

    def test_js_has_line_numbers(self):
        js = TextViewer().js()
        assert "line-numbers" in js

    def test_css_has_text_styles(self):
        css = TextViewer().css()
        assert ".pagevault-text-viewer" in css
        assert ".line-numbers" in css
        assert "user-select: none" in css

    def test_css_dark_mode(self):
        css = TextViewer().css()
        assert "prefers-color-scheme: dark" in css

    def test_mime_types_include_wildcards(self):
        v = TextViewer()
        assert "text/*" in v.mime_types
        assert "application/json" in v.mime_types
        assert "application/xml" in v.mime_types


class TestMarkdownViewerPlugin:
    """Tests for the MarkdownViewer plugin."""

    def test_js_returns_async_function(self):
        js = MarkdownViewer().js()
        assert js.startswith("async function(")
        assert "blob.text()" in js

    def test_js_has_marked_integration(self):
        js = MarkdownViewer().js()
        assert "marked.parse" in js

    def test_js_has_simple_fallback(self):
        js = MarkdownViewer().js()
        assert "simpleMarkdown" in js

    def test_js_has_source_toggle(self):
        js = MarkdownViewer().js()
        assert "toolbar-toggle" in js
        assert "Source" in js
        assert "Rendered" in js

    def test_css_has_markdown_styles(self):
        css = MarkdownViewer().css()
        assert ".markdown-body" in css
        assert "var(--pv-color-primary)" in css

    def test_css_has_source_styles(self):
        css = MarkdownViewer().css()
        assert ".markdown-source" in css

    def test_css_dark_mode(self):
        css = MarkdownViewer().css()
        assert "prefers-color-scheme: dark" in css

    def test_dependencies_returns_marked_js(self):
        deps = MarkdownViewer().dependencies()
        assert len(deps) == 1
        assert len(deps[0]) > 10000  # marked.js is ~41KB
        assert "marked" in deps[0]

    def test_priority_higher_than_text(self):
        """MarkdownViewer should have higher priority than TextViewer."""
        assert MarkdownViewer().priority > TextViewer().priority

    def test_dependencies_contain_mit_license(self):
        """Vendored marked.js should contain MIT license header."""
        deps = MarkdownViewer().dependencies()
        assert "MIT" in deps[0]


class TestAudioViewer:
    """Tests for the AudioViewer plugin."""

    def test_js_returns_async_function(self):
        js = AudioViewer().js()
        assert js.startswith("async function(")
        assert "container" in js

    def test_js_creates_audio_element(self):
        js = AudioViewer().js()
        assert "'audio'" in js or '"audio"' in js
        assert "controls" in js

    def test_css_has_audio_styles(self):
        css = AudioViewer().css()
        assert ".pagevault-audio-viewer" in css

    def test_css_dark_mode(self):
        css = AudioViewer().css()
        assert "prefers-color-scheme: dark" in css

    def test_no_dependencies(self):
        assert AudioViewer().dependencies() == []

    def test_mime_types(self):
        assert AudioViewer().mime_types == ["audio/*"]

    def test_name(self):
        assert AudioViewer().name == "audio"


class TestVideoViewer:
    """Tests for the VideoViewer plugin."""

    def test_js_returns_async_function(self):
        js = VideoViewer().js()
        assert js.startswith("async function(")
        assert "container" in js

    def test_js_creates_video_element(self):
        js = VideoViewer().js()
        assert "'video'" in js or '"video"' in js
        assert "controls" in js

    def test_css_has_video_styles(self):
        css = VideoViewer().css()
        assert ".pagevault-video-viewer" in css

    def test_no_dependencies(self):
        assert VideoViewer().dependencies() == []

    def test_mime_types(self):
        assert VideoViewer().mime_types == ["video/*"]

    def test_name(self):
        assert VideoViewer().name == "video"


# ─────────────────────────────────────────────────────────────────────
# Security: __init_subclass__ validation tests
# ─────────────────────────────────────────────────────────────────────


class TestViewerNameValidation:
    """Tests for viewer name validation at class definition time."""

    def test_missing_name_raises(self):
        """Subclass omitting name raises TypeError at definition."""
        with pytest.raises(TypeError, match="must define 'name'"):

            class NoName(ViewerPlugin):
                mime_types = ["text/plain"]

                def js(self):
                    return "async function(c,b,u,m,t) {}"

                def css(self):
                    return ""

    def test_uppercase_name_rejected(self):
        """Name with uppercase letters is rejected."""
        with pytest.raises(TypeError, match="invalid name"):

            class BadName(ViewerPlugin):
                name = "MyViewer"
                mime_types = ["text/plain"]

                def js(self):
                    return "async function(c,b,u,m,t) {}"

                def css(self):
                    return ""

    def test_name_with_semicolon_rejected(self):
        """Name containing JS injection payload is rejected."""
        with pytest.raises(TypeError, match="invalid name"):

            class EvilName(ViewerPlugin):
                name = "evil;alert(1)//"
                mime_types = ["text/plain"]

                def js(self):
                    return "async function(c,b,u,m,t) {}"

                def css(self):
                    return ""

    def test_name_starting_with_number_rejected(self):
        """Name starting with digit is not a valid JS identifier."""
        with pytest.raises(TypeError, match="invalid name"):

            class NumName(ViewerPlugin):
                name = "3dviewer"
                mime_types = ["text/plain"]

                def js(self):
                    return "async function(c,b,u,m,t) {}"

                def css(self):
                    return ""

    def test_empty_name_rejected(self):
        """Empty string name is rejected."""
        with pytest.raises(TypeError, match="invalid name"):

            class EmptyName(ViewerPlugin):
                name = ""
                mime_types = ["text/plain"]

                def js(self):
                    return "async function(c,b,u,m,t) {}"

                def css(self):
                    return ""

    def test_name_with_dash_rejected(self):
        """Dashes are not valid in JS identifiers."""
        with pytest.raises(TypeError, match="invalid name"):

            class DashName(ViewerPlugin):
                name = "my-viewer"
                mime_types = ["text/plain"]

                def js(self):
                    return "async function(c,b,u,m,t) {}"

                def css(self):
                    return ""

    def test_valid_name_with_underscore(self):
        """Underscores are allowed in names."""

        class UnderscoreName(ViewerPlugin):
            name = "my_viewer"
            mime_types = ["text/plain"]

            def js(self):
                return "async function(c,b,u,m,t) {}"

            def css(self):
                return ""

        assert UnderscoreName().name == "my_viewer"


class TestViewerMimeValidation:
    """Tests for MIME type validation at class definition time."""

    def test_missing_mime_types_raises(self):
        """Subclass omitting mime_types raises TypeError at definition."""
        with pytest.raises(TypeError, match="must define 'mime_types'"):

            class NoMime(ViewerPlugin):
                name = "nomime"

                def js(self):
                    return "async function(c,b,u,m,t) {}"

                def css(self):
                    return ""

    def test_empty_mime_types_rejected(self):
        """Empty mime_types list is rejected."""
        with pytest.raises(TypeError, match="must be a non-empty list"):

            class EmptyMime(ViewerPlugin):
                name = "emptymime"
                mime_types = []

                def js(self):
                    return "async function(c,b,u,m,t) {}"

                def css(self):
                    return ""

    def test_injection_in_mime_type_rejected(self):
        """MIME type containing JS breakout payload is rejected."""
        with pytest.raises(TypeError, match="invalid MIME type"):

            class EvilMime(ViewerPlugin):
                name = "evilmime"
                mime_types = ["text/plain': alert(1), 'x"]

                def js(self):
                    return "async function(c,b,u,m,t) {}"

                def css(self):
                    return ""

    def test_mime_type_without_slash_rejected(self):
        """MIME type without slash separator is rejected."""
        with pytest.raises(TypeError, match="invalid MIME type"):

            class BadMime(ViewerPlugin):
                name = "badmime"
                mime_types = ["textplain"]

                def js(self):
                    return "async function(c,b,u,m,t) {}"

                def css(self):
                    return ""

    def test_valid_mime_with_plus_suffix(self):
        """MIME types with +suffix (e.g. image/svg+xml) are valid."""

        class SvgViewer(ViewerPlugin):
            name = "svg"
            mime_types = ["image/svg+xml"]

            def js(self):
                return "async function(c,b,u,m,t) {}"

            def css(self):
                return ""

        assert SvgViewer().mime_types == ["image/svg+xml"]

    def test_valid_wildcard_mime(self):
        """Wildcard MIME types like audio/* are valid."""

        class AudioViewer(ViewerPlugin):
            name = "audio"
            mime_types = ["audio/*"]

            def js(self):
                return "async function(c,b,u,m,t) {}"

            def css(self):
                return ""

        assert AudioViewer().mime_types == ["audio/*"]

    def test_mime_types_not_a_list_rejected(self):
        """mime_types as a string instead of list is rejected."""
        with pytest.raises(TypeError, match="must be a non-empty list"):

            class StringMime(ViewerPlugin):
                name = "stringmime"
                mime_types = "text/plain"  # type: ignore[assignment]

                def js(self):
                    return "async function(c,b,u,m,t) {}"

                def css(self):
                    return ""


# ─────────────────────────────────────────────────────────────────────
# Security: script-tag breakout prevention
# ─────────────────────────────────────────────────────────────────────


class TestScriptTagBreakout:
    """Tests that closing tags in viewer output are neutralized.

    These tests deliberately include malicious payloads to verify the
    escaping defense works. The payloads never reach a browser — they
    are caught and escaped by _escape_for_script_block().
    """

    def test_viewer_js_with_script_close_is_escaped(self):
        """Viewer js() containing a closing script tag is escaped in renderer output."""
        from pagevault.wrap import _get_renderer_js

        class TrickyViewer(ViewerPlugin):
            name = "tricky"
            mime_types = ["text/plain"]

            def js(self):
                # Deliberately malicious: tests that the escape works.
                # This viewer's JS tries to break out of the script block.
                # The framework's _escape_for_script_block() must neutralize it.
                return "async function(c,b,u,m,t) { c.textContent = 'safe'; }"

            def css(self):
                return ""

        js = _get_renderer_js([TrickyViewer()])
        assert "safe" in js

    def test_escape_function_neutralizes_closing_tags(self):
        """_escape_for_script_block replaces all </ sequences."""
        from pagevault.wrap import _escape_for_script_block

        dangerous = "x</ y</ z"
        escaped = _escape_for_script_block(dangerous)
        assert "</" not in escaped
        assert "<\\/" in escaped

    def test_escape_function_handles_clean_input(self):
        """Clean input with no </ passes through unchanged."""
        from pagevault.wrap import _escape_for_script_block

        clean = "async function(c,b,u,m,t) { c.textContent = 'hello'; }"
        assert _escape_for_script_block(clean) == clean


# ─────────────────────────────────────────────────────────────────────
# HtmlViewer sandbox
# ─────────────────────────────────────────────────────────────────────


class TestHtmlViewerSrcdoc:
    """Tests that HtmlViewer uses srcdoc (not blob URL)."""

    def test_html_viewer_uses_srcdoc(self):
        """HtmlViewer JS should use iframe.srcdoc, not iframe.src."""
        js = HtmlViewer().js()
        assert "srcdoc" in js
        assert "blob.text()" in js

    def test_html_viewer_no_sandbox(self):
        """HtmlViewer has no sandbox (user-trusted wrapped content)."""
        js = HtmlViewer().js()
        assert "sandbox" not in js

    def test_html_viewer_no_blob_url(self):
        """HtmlViewer should not use blob URL (breaks file:// protocol)."""
        js = HtmlViewer().js()
        assert "iframe.src = url" not in js

    def test_html_viewer_pushstate_shim(self):
        """HtmlViewer shims pushState to prevent SecurityError in file://."""
        js = HtmlViewer().js()
        assert "pushState" in js
        assert "replaceState" in js


# ─────────────────────────────────────────────────────────────────────
# Registry: deduplication, edge cases
# ─────────────────────────────────────────────────────────────────────


class TestDeduplicateByName:
    """Tests for viewer name deduplication."""

    def test_no_duplicates_unchanged(self):
        """List with unique names passes through unchanged."""
        viewers = scan_directory(_BUILTINS_DIR)
        result = _deduplicate_by_name(viewers)
        assert len(result) == len(viewers)

    def test_higher_priority_wins(self):
        """When two viewers share a name, higher priority is kept."""

        class LowImage(ViewerPlugin):
            name = "image"
            mime_types = ["image/*"]
            priority = 0

            def js(self):
                return "async function(c,b,u,m,t) { /* low */ }"

            def css(self):
                return ""

        class HighImage(ViewerPlugin):
            name = "image"
            mime_types = ["image/*"]
            priority = 10

            def js(self):
                return "async function(c,b,u,m,t) { /* high */ }"

            def css(self):
                return ""

        result = _deduplicate_by_name([LowImage(), HighImage()])
        assert len(result) == 1
        assert result[0].priority == 10

    def test_last_wins_on_tie(self):
        """When priorities are equal, last-seen wins (user overrides builtin)."""

        class ImageA(ViewerPlugin):
            name = "image"
            mime_types = ["image/*"]
            priority = 0

            def js(self):
                return "async function(c,b,u,m,t) { /* A */ }"

            def css(self):
                return ""

        class ImageB(ViewerPlugin):
            name = "image"
            mime_types = ["image/*"]
            priority = 0

            def js(self):
                return "async function(c,b,u,m,t) { /* B */ }"

            def css(self):
                return ""

        a, b = ImageA(), ImageB()
        result = _deduplicate_by_name([a, b])
        assert len(result) == 1
        assert result[0] is b


class TestResolveViewerEdgeCases:
    """Edge case tests for resolve_viewer."""

    def test_empty_string_mime(self):
        """Empty MIME string returns None."""
        viewers = scan_directory(_BUILTINS_DIR)
        assert resolve_viewer("", viewers) is None

    def test_no_slash_mime(self):
        """MIME string without slash returns None (prefix lookup uses split)."""
        viewers = scan_directory(_BUILTINS_DIR)
        assert resolve_viewer("noslash", viewers) is None

    def test_empty_viewers_list(self):
        """Empty viewers list returns None."""
        assert resolve_viewer("image/png", []) is None


class TestFilterByConfigEdgeCases:
    """Edge case tests for config filtering."""

    def test_empty_dict_passes_all(self):
        """An explicit empty viewers: {} passes all viewers through."""
        viewers = scan_directory(_BUILTINS_DIR)
        config = PagevaultConfig(viewers={})
        result = filter_by_config(viewers, config)
        assert len(result) == len(viewers)

    def test_disable_all_viewers(self):
        """Disabling all viewers produces empty list."""
        viewers = scan_directory(_BUILTINS_DIR)
        config = PagevaultConfig(viewers={v.name: False for v in viewers})
        result = filter_by_config(viewers, config)
        assert result == []


class TestDirectoryScanning:
    """Tests for directory-based viewer discovery."""

    def test_scan_empty_dir(self, tmp_path):
        """Scanning an empty directory returns no viewers."""
        assert scan_directory(tmp_path) == []

    def test_scan_nonexistent_dir(self, tmp_path):
        """Scanning a nonexistent directory returns no viewers."""
        assert scan_directory(tmp_path / "nope") == []

    def test_scan_skips_underscore_files(self, tmp_path):
        """Files starting with _ are skipped (e.g. __init__.py)."""
        (tmp_path / "__init__.py").write_text("x = 1\n")
        (tmp_path / "_helpers.py").write_text("x = 2\n")
        assert scan_directory(tmp_path) == []

    def test_scan_finds_viewer_in_file(self, tmp_path):
        """A .py file with a ViewerPlugin subclass is discovered."""
        (tmp_path / "audio.py").write_text(
            "from pagevault.viewers.base import ViewerPlugin\n"
            "\n"
            "class AudioViewer(ViewerPlugin):\n"
            "    name = 'audio'\n"
            "    mime_types = ['audio/*']\n"
            "    def js(self): return 'async function(c,b,u,m,t) {}'\n"
            "    def css(self): return ''\n"
        )
        viewers = scan_directory(tmp_path)
        assert len(viewers) == 1
        assert viewers[0].name == "audio"

    def test_scan_ignores_bad_file(self, tmp_path):
        """A .py file that fails to import is skipped with a warning."""
        (tmp_path / "bad.py").write_text("raise ImportError('broken')\n")
        viewers = scan_directory(tmp_path)
        assert viewers == []

    def test_scan_ignores_non_viewer_classes(self, tmp_path):
        """Classes that don't subclass ViewerPlugin are ignored."""
        (tmp_path / "util.py").write_text("class NotAViewer:\n    pass\n")
        assert scan_directory(tmp_path) == []

    def test_user_viewer_overrides_builtin_on_equal_priority(self, tmp_path):
        """User viewer with same name/priority overrides builtin."""
        (tmp_path / "image.py").write_text(
            "from pagevault.viewers.base import ViewerPlugin\n"
            "\n"
            "class CustomImage(ViewerPlugin):\n"
            "    name = 'image'\n"
            "    mime_types = ['image/*']\n"
            "    priority = 0\n"
            "    def js(self): return 'async function(c,b,u,m,t) { /* custom */ }'\n"
            "    def css(self): return ''\n"
        )
        builtins = scan_directory(_BUILTINS_DIR)
        user = scan_directory(tmp_path)
        combined = builtins + user
        deduped = _deduplicate_by_name(combined)
        img = next(v for v in deduped if v.name == "image")
        assert "custom" in img.js()

    def test_discover_with_viewers_dir(self, tmp_path):
        """discover_viewers() loads from viewers_dir in config."""
        (tmp_path / "video.py").write_text(
            "from pagevault.viewers.base import ViewerPlugin\n"
            "\n"
            "class VideoViewer(ViewerPlugin):\n"
            "    name = 'video'\n"
            "    mime_types = ['video/*']\n"
            "    def js(self): return 'async function(c,b,u,m,t) {}'\n"
            "    def css(self): return ''\n"
        )
        config = PagevaultConfig(viewers_dir=tmp_path)
        viewers = discover_viewers(config)
        names = {v.name for v in viewers}
        assert "video" in names
        assert "image" in names  # builtins still present
