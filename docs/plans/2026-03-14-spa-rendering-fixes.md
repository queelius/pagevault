# SPA Rendering Fixes Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix bugs in pagevault's site/file renderer, remove dead code, and improve SPA compatibility for encrypted HTML sites.

**Architecture:** The site renderer (`wrap.py`) zips a directory, encrypts it, and generates self-contained HTML. After browser decryption, a JS runtime unzips files, rewrites resource URLs to data: URIs via regex, and renders HTML pages in an `srcdoc` iframe with navigation interception via `postMessage`. Bugs in URL rewriting, path resolution, and navigation interception cause complex sites/SPAs to break.

**Tech Stack:** Python (BeautifulSoup, zipfile), inline JavaScript (Web Crypto API, DecompressionStream), pytest

---

## Chunk 1: Dead Code Removal + Bug Fixes

### Task 1: Remove dead v2 wrap functions

The v2 functions `_generate_wrap_html()`, `_get_crypto_js()`, and `_get_renderer_js()` are never called — all code paths use the v3 equivalents. Removing them eliminates ~270 lines of dead code and duplication.

**Important:** Some tests import `_get_renderer_js` to test viewer dispatch table generation. These tests exercise `_build_viewer_dispatch()` which is shared. The tests should be updated to use `_get_renderer_js_v3` instead, since it calls the same `_build_viewer_dispatch()` and produces the same viewer dispatch output.

**Files:**
- Modify: `src/pagevault/wrap.py` (remove lines 283-852: `_generate_wrap_html`, `_get_crypto_js`, `_get_renderer_js`)
- Modify: `tests/test_wrap.py` (update imports and calls from `_get_renderer_js` to `_get_renderer_js_v3`)
- Modify: `tests/test_viewers.py` (update import from `_get_renderer_js` to `_get_renderer_js_v3`)

- [ ] **Step 1: Update test imports**

In `tests/test_wrap.py`, change the import:
```python
# Change this:
from pagevault.wrap import (
    ...
    _get_renderer_js,
    ...
)
# To this:
from pagevault.wrap import (
    ...
    _get_renderer_js_v3,
    ...
)
```

Then find-replace all calls: `_get_renderer_js(` → `_get_renderer_js_v3(` in `tests/test_wrap.py`.

In `tests/test_viewers.py`, change:
```python
from pagevault.wrap import _get_renderer_js
# to:
from pagevault.wrap import _get_renderer_js_v3
```
And update the call at line ~721.

- [ ] **Step 2: Run tests to verify they pass with v3**

Run: `pytest tests/test_wrap.py tests/test_viewers.py -v --timeout=30 2>&1 | tail -20`
Expected: All tests pass (the v3 renderer produces identical viewer dispatch output).

- [ ] **Step 3: Remove dead v2 functions from wrap.py**

Delete from `src/pagevault/wrap.py`:
- `_generate_wrap_html()` (lines 283-376) — entire function
- `_get_crypto_js()` (lines 551-622) — entire function
- `_get_renderer_js()` (lines 674-852) — entire function

Keep the docstring reference to v2 in `_get_crypto_js_v3()` (line 992) since it documents the differences.

- [ ] **Step 4: Run full test suite**

Run: `pytest tests/ -v --timeout=30`
Expected: All 667 tests pass.

- [ ] **Step 5: Run lint**

Run: `ruff check src/pagevault/wrap.py tests/test_wrap.py tests/test_viewers.py`
Expected: Clean (only pre-existing E501 suppressions).

- [ ] **Step 6: Commit**

```bash
git add src/pagevault/wrap.py tests/test_wrap.py tests/test_viewers.py
git commit -m "refactor: remove dead v2 wrap renderer functions (~270 lines)"
```

---

### Task 2: Fix v3 renderer null-byte padding

The v3 renderer returns a raw `Blob` from `decryptV3Chunked` and passes it directly to `renderFile`/`renderSite` without stripping `--pad` null bytes. The v2 renderer strips padding (`result.content.replace(/\0+$/, '')`), but v3 never does. The `meta.size` field contains the original unpadded size and should be used to slice the blob.

**Files:**
- Modify: `src/pagevault/wrap.py` — `_get_renderer_js_v3()`, after successful decryption
- Create test in: `tests/test_wrap.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_wrap.py` in an appropriate test class:

```python
class TestV3PaddingStrip:
    """Tests for v3 renderer stripping null-byte padding."""

    def test_v3_renderer_truncates_blob_to_meta_size(self):
        """v3 renderer JS should truncate blob using meta.size after decryption."""
        from pagevault.wrap import _get_renderer_js_v3
        js = _get_renderer_js_v3([])
        # The renderer should use meta.size to slice the blob
        assert "meta.size" in js
        assert ".slice(" in js or "slice(0" in js

    def test_v3_site_renderer_truncates_blob(self):
        """v3 site renderer path should also truncate blob."""
        from pagevault.wrap import _get_renderer_js_v3
        js = _get_renderer_js_v3([])
        # Both file and site paths should handle size truncation
        assert "blob.slice" in js or "result.blob.slice" in js
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_wrap.py::TestV3PaddingStrip -v`
Expected: FAIL — the current JS doesn't contain `slice` for blob truncation.

- [ ] **Step 3: Implement the fix**

In `src/pagevault/wrap.py`, in `_get_renderer_js_v3()`, after the decryption result check and before the `if (meta.type === 'site'...)` block, add blob truncation:

```javascript
    // Strip null-byte padding (from --pad option during lock)
    if (meta.size && result.blob.size > meta.size) {{
      result.blob = result.blob.slice(0, meta.size, result.blob.type);
    }}
```

This goes right after `var meta = result.meta || {};` (around line 1202).

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_wrap.py::TestV3PaddingStrip -v`
Expected: PASS.

- [ ] **Step 5: Run full suite + lint**

Run: `pytest tests/ -v --timeout=30 && ruff check src/pagevault/wrap.py`

- [ ] **Step 6: Commit**

```bash
git add src/pagevault/wrap.py tests/test_wrap.py
git commit -m "fix: v3 renderer strips null-byte padding using meta.size"
```

---

### Task 3: Fix `resolvePath` for absolute paths

`resolvePath('/images/logo.png')` currently treats the leading `/` as relative (the empty first segment is skipped but the current page's directory is prepended). Sites using root-relative paths (common in static site generators like Hugo, Jekyll) have broken resource references.

**Files:**
- Modify: `src/pagevault/wrap.py` — `_get_site_renderer_js()`, the `resolvePath` function
- Add test in: `tests/test_wrap.py`

- [ ] **Step 1: Write the failing test**

```python
class TestResolvePathAbsolute:
    """Tests for resolvePath handling absolute paths."""

    def test_resolve_path_handles_absolute_path(self):
        """Site renderer resolvePath should strip leading / for absolute paths."""
        from pagevault.wrap import _get_site_renderer_js
        js = _get_site_renderer_js()
        # Should detect and handle absolute paths
        assert "href.startsWith('/')" in js or 'href.charAt(0)' in js

    def test_site_with_absolute_paths_wraps(self, tmp_path):
        """A site using root-relative paths should wrap successfully."""
        site_dir = tmp_path / "site"
        site_dir.mkdir()
        img_dir = site_dir / "images"
        img_dir.mkdir()

        (img_dir / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 20)
        (site_dir / "index.html").write_text(
            '<html><body><img src="/images/logo.png"></body></html>'
        )

        output = wrap_site(site_dir, password="pw")
        content = output.read_text()
        # The site renderer should include absolute path handling
        assert "startsWith('/')" in content
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_wrap.py::TestResolvePathAbsolute -v`
Expected: FAIL.

- [ ] **Step 3: Implement the fix**

In `_get_site_renderer_js()`, at the top of the `resolvePath` function (around line 1580), add:

```javascript
  function resolvePath(fromPage, href) {
    if (!href) return fromPage;
    // Handle absolute paths (strip leading / since zip paths don't have it)
    if (href.startsWith('/')) {
      return href.substring(1);
    }
    href = href.replace(/^\\.\\//g, '');
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_wrap.py::TestResolvePathAbsolute -v`
Expected: PASS.

- [ ] **Step 5: Full suite + lint**

Run: `pytest tests/ -v --timeout=30 && ruff check src/pagevault/wrap.py`

- [ ] **Step 6: Commit**

```bash
git add src/pagevault/wrap.py tests/test_wrap.py
git commit -m "fix: resolvePath handles absolute paths (leading /)"
```

---

### Task 4: Fix `srcset` attribute parsing

The HTML attribute regex captures the entire `srcset` value as one URL, but `srcset` has format `"image1.png 480w, image2.png 1024w"`. Each URL-descriptor pair needs to be resolved separately.

**Files:**
- Modify: `src/pagevault/wrap.py` — `_get_site_renderer_js()`, inside `rewriteUrls()`
- Add test in: `tests/test_wrap.py`

- [ ] **Step 1: Write the failing test**

```python
class TestSrcsetRewriting:
    """Tests for srcset attribute URL rewriting in site renderer."""

    def test_srcset_handling_in_renderer(self):
        """Site renderer should have special srcset handling."""
        from pagevault.wrap import _get_site_renderer_js
        js = _get_site_renderer_js()
        assert "srcset" in js
        # Should split srcset entries on comma and process each URL
        assert "split(',')" in js or "split(', ')" in js
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_wrap.py::TestSrcsetRewriting -v`
Expected: FAIL — current code doesn't split srcset values.

- [ ] **Step 3: Implement the fix**

In `_get_site_renderer_js()`, in the `rewriteUrls` function, modify the attribute replace callback. When `attr.toLowerCase() === 'srcset'`, parse the value specially:

Replace the existing attribute rewrite callback with one that handles srcset:

```javascript
        html = html.replace(attrPattern, function(match, attr, quote, url) {
          if (url.startsWith('http://') || url.startsWith('https://') ||
              url.startsWith('//') || url.startsWith('data:') ||
              url.startsWith('#') || url.startsWith('javascript:') ||
              url.startsWith('mailto:')) {
            return match;
          }
          // Handle srcset: multiple URLs with descriptors
          if (attr.toLowerCase() === 'srcset') {
            var entries = url.split(',');
            var rewritten = entries.map(function(entry) {
              var parts = entry.trim().split(/\\s+/);
              var src = parts[0];
              var descriptor = parts.slice(1).join(' ');
              var clean = src.split('#')[0].split('?')[0];
              var resolved = resolvePath(fromPage, clean);
              var uri = toDataUri(resolved);
              if (uri) return uri + (descriptor ? ' ' + descriptor : '');
              return entry.trim();
            });
            return attr + '=' + quote + rewritten.join(', ') + quote;
          }
          var clean = url.split('#')[0].split('?')[0];
          var resolved = resolvePath(fromPage, clean);
          if (attr.toLowerCase() === 'href' && htmlFiles.has(resolved)) {
            return match;
          }
          var uri = toDataUri(resolved);
          if (uri) return attr + '=' + quote + uri + quote;
          return match;
        });
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_wrap.py::TestSrcsetRewriting -v`
Expected: PASS.

- [ ] **Step 5: Full suite + lint**

Run: `pytest tests/ -v --timeout=30 && ruff check src/pagevault/wrap.py`

- [ ] **Step 6: Commit**

```bash
git add src/pagevault/wrap.py tests/test_wrap.py
git commit -m "fix: parse srcset attribute entries individually in site renderer"
```

---

### Task 5: Fix CSS `@import` bare string rewriting

The URL rewriter handles `url()` references but misses `@import 'style.css'` (bare string syntax without `url()`). This is valid CSS that many codebases use.

**Files:**
- Modify: `src/pagevault/wrap.py` — `_get_site_renderer_js()`, inside `rewriteUrls()`
- Add test in: `tests/test_wrap.py`

- [ ] **Step 1: Write the failing test**

```python
class TestCssImportRewriting:
    """Tests for CSS @import rewriting in site renderer."""

    def test_css_import_bare_string_pattern(self):
        """Site renderer should rewrite @import 'file.css' bare string syntax."""
        from pagevault.wrap import _get_site_renderer_js
        js = _get_site_renderer_js()
        assert "@import" in js
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_wrap.py::TestCssImportRewriting -v`
Expected: FAIL.

- [ ] **Step 3: Implement the fix**

In `_get_site_renderer_js()`, inside `rewriteUrls()`, after the CSS `url()` rewrite block and before the quoted-string rewrite block, add:

```javascript
        // Rewrite CSS @import with bare string syntax
        html = html.replace(/@import\\s+(['"])([^'"]+?)\\1/gi, function(match, quote, url) {
          if (url.startsWith('http://') || url.startsWith('https://') ||
              url.startsWith('data:')) {
            return match;
          }
          var resolved = resolvePath(fromPage, url);
          var uri = toDataUri(resolved);
          if (uri) return '@import ' + quote + uri + quote;
          return match;
        });
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_wrap.py::TestCssImportRewriting -v`
Expected: PASS.

- [ ] **Step 5: Full suite + lint**

Run: `pytest tests/ -v --timeout=30 && ruff check src/pagevault/wrap.py`

- [ ] **Step 6: Commit**

```bash
git add src/pagevault/wrap.py tests/test_wrap.py
git commit -m "fix: rewrite CSS @import bare string syntax in site renderer"
```

---

## Chunk 2: Navigation & Fetch Interception

### Task 6: Fix nav interceptor for `target="_blank"` and `<form>` submissions

The injected nav script only intercepts `<a>` click events. It should also handle `<form>` submissions (with local `action` attributes) and should not override `target="_blank"` link behavior.

**Files:**
- Modify: `src/pagevault/wrap.py` — `_get_site_renderer_js()`, the `injectNavScript()` function
- Add test in: `tests/test_wrap.py`

- [ ] **Step 1: Write the failing test**

```python
class TestNavInterceptor:
    """Tests for site renderer navigation interceptor."""

    def test_form_submit_interceptor_present(self):
        """Nav script should intercept form submissions."""
        from pagevault.wrap import _get_site_renderer_js
        js = _get_site_renderer_js()
        assert "submit" in js
        assert "form" in js.lower() or "closest('form')" in js

    def test_target_blank_not_intercepted(self):
        """Nav script should skip links with target=_blank."""
        from pagevault.wrap import _get_site_renderer_js
        js = _get_site_renderer_js()
        assert "_blank" in js
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_wrap.py::TestNavInterceptor -v`
Expected: FAIL.

- [ ] **Step 3: Implement the fix**

In `_get_site_renderer_js()`, replace the `injectNavScript()` function. The new version should:
1. Skip `<a>` clicks with `target="_blank"`
2. Intercept `<form>` submissions with local `action` attributes

```javascript
  function injectNavScript(html) {
    var tag = '<scr' + 'ipt>' +
      // Intercept link clicks
      'document.addEventListener("click",function(e){' +
      'var a=e.target.closest("a");if(!a)return;' +
      'var h=a.getAttribute("href");' +
      'if(!h||h.startsWith("http://")||h.startsWith("https://")||' +
      'h.startsWith("//")||h.startsWith("#")||h.startsWith("data:")||' +
      'h.startsWith("javascript:")||h.startsWith("mailto:"))return;' +
      'if(a.target==="_blank")return;' +
      'e.preventDefault();' +
      'window.parent.postMessage({type:"pagevault-nav",href:h},"*");' +
      '});' +
      // Intercept form submissions
      'document.addEventListener("submit",function(e){' +
      'var f=e.target;if(!f||f.tagName!=="FORM")return;' +
      'var a=f.getAttribute("action");' +
      'if(!a||a.startsWith("http://")||a.startsWith("https://")||' +
      'a.startsWith("//")||a.startsWith("data:"))return;' +
      'e.preventDefault();' +
      'window.parent.postMessage({type:"pagevault-nav",href:a},"*");' +
      '});' +
      '</scr' + 'ipt>';
    var idx = html.lastIndexOf('</body>');
    if (idx !== -1) return html.slice(0, idx) + tag + html.slice(idx);
    return html + tag;
  }
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_wrap.py::TestNavInterceptor -v`
Expected: PASS.

- [ ] **Step 5: Full suite + lint**

Run: `pytest tests/ -v --timeout=30 && ruff check src/pagevault/wrap.py`

- [ ] **Step 6: Commit**

```bash
git add src/pagevault/wrap.py tests/test_wrap.py
git commit -m "fix: nav interceptor handles form submissions and target=_blank"
```

---

### Task 7: Intercept `fetch()` and `XMLHttpRequest` in site renderer

SPAs commonly use `fetch('./data.json')` to load local resources. In the `srcdoc` iframe, these resolve against `about:srcdoc` and fail. Inject a monkey-patch into the iframe that intercepts fetch/XHR calls for relative URLs and returns matching resources from the in-memory resource map.

The approach: extend `injectNavScript` to also inject fetch/XHR shims that communicate with the parent via `postMessage` to request resource data.

Actually, a simpler approach: since the `rewriteUrls` function already runs on HTML before it's injected into the iframe, we can inject a `<script>` that creates a virtual file system and overrides `fetch` to check it. The parent already has all resources — we just need to pass them into the iframe.

The cleanest approach: inject a script that creates a global `__pvResources` map, then override `fetch()` and `XMLHttpRequest.prototype.open` to check this map first. The resource data for the current page's directory is serialized as a JSON map of path→data-URI.

However, embedding all resources as JSON in every page load would be wasteful. Instead, use `postMessage` for resource requests: the iframe asks the parent for a resource, and the parent responds with the data URI.

**Files:**
- Modify: `src/pagevault/wrap.py` — `_get_site_renderer_js()`, `injectNavScript()`, and the `renderPage()` / `window.addEventListener('message')` handler
- Add test in: `tests/test_wrap.py`

- [ ] **Step 1: Write the failing test**

```python
class TestFetchInterception:
    """Tests for fetch/XHR interception in site renderer."""

    def test_fetch_shim_injected(self):
        """Site renderer should inject a fetch shim into the iframe."""
        from pagevault.wrap import _get_site_renderer_js
        js = _get_site_renderer_js()
        # Should inject a fetch override
        assert "fetch" in js and "pagevault-fetch" in js

    def test_parent_responds_to_fetch_requests(self):
        """Parent should handle pagevault-fetch messages from iframe."""
        from pagevault.wrap import _get_site_renderer_js
        js = _get_site_renderer_js()
        assert "pagevault-fetch" in js
        # Parent should send resource data back
        assert "postMessage" in js
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_wrap.py::TestFetchInterception -v`
Expected: FAIL (current JS doesn't have `pagevault-fetch`).

- [ ] **Step 3: Implement the fix**

This is a two-part change:

**Part A: Parent-side message handler** — In `_get_site_renderer_js()`, extend the `window.addEventListener('message', ...)` handler to also respond to `pagevault-fetch` requests:

```javascript
      window.addEventListener('message', function(e) {
        if (!e.data || !e.data.type) return;
        if (e.data.type === 'pagevault-nav') {
          var href = e.data.href;
          var clean = href.split('#')[0].split('?')[0];
          if (!clean) return;
          var target = resolvePath(currentPage, clean);
          if (htmlFiles.has(target)) {
            renderPage(target);
          }
        } else if (e.data.type === 'pagevault-fetch') {
          var fetchPath = e.data.path;
          var resolved = resolvePath(currentPage, fetchPath);
          var r = resources[resolved];
          if (r) {
            var uri = toDataUri(resolved);
            iframe.contentWindow.postMessage({
              type: 'pagevault-fetch-response',
              id: e.data.id,
              data: uri,
              mime: r.mime
            }, '*');
          } else {
            iframe.contentWindow.postMessage({
              type: 'pagevault-fetch-response',
              id: e.data.id,
              data: null
            }, '*');
          }
        }
      });
```

**Part B: Iframe-side fetch shim** — In `injectNavScript()`, add a fetch override that sends `pagevault-fetch` messages to the parent and waits for responses:

```javascript
      // Fetch shim — intercepts relative URL requests
      'var __pvFetchId=0,__pvFetchWaiters={};' +
      'window.addEventListener("message",function(e){' +
      'if(e.data&&e.data.type==="pagevault-fetch-response"&&__pvFetchWaiters[e.data.id]){' +
      '__pvFetchWaiters[e.data.id](e.data);delete __pvFetchWaiters[e.data.id];}});' +
      'var __pvOrigFetch=window.fetch;' +
      'window.fetch=function(input,init){' +
      'if(typeof input==="string"&&!input.match(/^(https?:|data:|blob:|about:)/)){' +
      'return new Promise(function(resolve){' +
      'var id=++__pvFetchId;' +
      '__pvFetchWaiters[id]=function(resp){' +
      'if(resp.data){' +
      'fetch(resp.data).then(function(r){resolve(r)});' +  // fetch the data URI
      '}else{resolve(__pvOrigFetch.call(window,input,init));}};' +
      'window.parent.postMessage({type:"pagevault-fetch",path:input,id:id},"*");' +
      '});}' +
      'return __pvOrigFetch.call(window,input,init);};' +
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_wrap.py::TestFetchInterception -v`
Expected: PASS.

- [ ] **Step 5: Full suite + lint**

Run: `pytest tests/ -v --timeout=30 && ruff check src/pagevault/wrap.py`

- [ ] **Step 6: Commit**

```bash
git add src/pagevault/wrap.py tests/test_wrap.py
git commit -m "feat: intercept fetch() in site renderer for local resource requests"
```

---

## Chunk 3: Minor Fixes + Documentation

### Task 8: Fix `config set password` security footgun

`config set password <value>` stores plaintext in `.pagevault.yaml` without warning. Add a confirmation prompt and gitignore check.

**Files:**
- Modify: `src/pagevault/cli.py`
- Add test in: `tests/test_cli.py`

- [ ] **Step 1: Write the failing test**

```python
class TestConfigSetPassword:
    """Tests for password security warnings in config set."""

    def test_config_set_password_prompts_confirmation(self, tmp_path, runner):
        """config set password should prompt for confirmation."""
        config_path = tmp_path / ".pagevault.yaml"
        config_path.write_text("password: old\n")
        result = runner.invoke(
            main, ["config", "set", "password", "newsecret", "-c", str(config_path)]
        )
        # Should warn about plaintext storage or prompt
        assert "plaintext" in result.output.lower() or "warning" in result.output.lower()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cli.py::TestConfigSetPassword -v`
Expected: FAIL.

- [ ] **Step 3: Implement the fix**

In `src/pagevault/cli.py`, in the `config_set` command handler, add a warning when the key is `"password"`:

```python
if key == "password":
    click.echo(
        "Warning: This stores the password as plaintext in .pagevault.yaml."
    )
    click.echo("Consider using -p on the command line instead.")
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_cli.py::TestConfigSetPassword -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/pagevault/cli.py tests/test_cli.py
git commit -m "fix: warn when storing plaintext password via config set"
```

---

### Task 9: Fix `config set pad` echo formatting

`config set pad true` echoes `Set 'pad' = 'True'` (Python bool capital T) instead of `true`.

**Files:**
- Modify: `src/pagevault/cli.py`
- Add test in: `tests/test_cli.py`

- [ ] **Step 1: Write the failing test**

```python
def test_config_set_pad_echoes_lowercase(self, tmp_path, runner):
    """config set pad should echo lowercase true/false."""
    config_path = tmp_path / ".pagevault.yaml"
    config_path.write_text("{}\n")
    result = runner.invoke(
        main, ["config", "set", "pad", "true", "-c", str(config_path)]
    )
    assert "True" not in result.output  # Should not have Python True
    assert "true" in result.output.lower()
```

- [ ] **Step 2: Implement the fix**

In `cli.py`, in the `config_set` handler, change the echo for boolean keys:

```python
display_value = str(value).lower() if isinstance(value, bool) else value
click.echo(f"Set '{key}' = '{display_value}'")
```

- [ ] **Step 3: Run tests + commit**

Run: `pytest tests/test_cli.py -v --timeout=30`

```bash
git add src/pagevault/cli.py tests/test_cli.py
git commit -m "fix: config set echoes lowercase for boolean values"
```

---

### Task 10: Final verification and combined commit

- [ ] **Step 1: Run full test suite**

Run: `pytest tests/ -v --timeout=30 --cov=pagevault`
Expected: All tests pass, coverage >= 84%.

- [ ] **Step 2: Run lint**

Run: `ruff check src/ tests/ && ruff format --check src/ tests/`
Expected: Clean.

- [ ] **Step 3: Review the diff**

Run: `git log --oneline HEAD~9..HEAD` to verify all commits are clean and well-described.
