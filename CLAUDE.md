# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Development

```bash
# Setup
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Run all tests
pytest tests/ -v

# Run a single test file or test
pytest tests/test_parser.py -v
pytest tests/test_parser.py::TestLockHtml::test_basic_encryption -v

# Coverage
pytest tests/ -v --cov=pagevault

# Lint
ruff check src/ tests/
ruff format --check src/ tests/
```

## Architecture

**Data flow:** CLI (`cli.py`) loads config (`config.py`), then calls parser (`parser.py`) which orchestrates crypto operations (`crypto.py`) and injects browser runtime via template generation (`template.py`). The `wrap.py` module handles wrapping arbitrary files/sites into encrypted HTML.

```
cli.py  →  config.py (cascade: CLI args > env vars > .pagevault.yaml > defaults)
   ↓
parser.py  →  crypto.py (PBKDF2-SHA256 + AES-256-GCM, WebCrypto-compatible)
   ↓            ↑
template.py    wrap.py  →  crypto.py (file/site → encrypted HTML payloads)
                   ↓
                viewers/  →  ViewerPlugin registry (entry points, MIME dispatch)
```

### Commands

```
pagevault mark <paths> [-r] [-s SELECTOR]... [--hint] [--remember] [--title]
pagevault lock <paths> [-r] [-d DIR] [-p PASSWORD] [-c CONFIG] [--dry-run] [--css] [--pad] [--site] [--entry]
pagevault unlock <paths> [-r] [-d DIR] [-p PASSWORD] [-u USERNAME] [-c CONFIG] [--dry-run] [--stdout]
pagevault sync <paths> [-r] [-c CONFIG] [--dry-run] [--rekey]
pagevault config init|show|where
pagevault info <file>
pagevault check <file> -p PASSWORD [-u USERNAME]
pagevault audit [-c CONFIG]
```

### Modules

- **parser.py** is the core module. It handles HTML manipulation with BeautifulSoup/lxml, marks elements via CSS selectors, locks/unlocks content, and injects the self-contained JS/CSS runtime into output HTML.
  - Key functions: `mark_elements()`, `mark_body()`, `lock_html()`, `unlock_html()`, `process_file()`
  - Backward-compat aliases: `encrypt_html = lock_html`, `decrypt_html = unlock_html`, `wrap_elements_for_encryption = mark_elements`, `wrap_body_for_encryption = mark_body`
- **crypto.py** implements encryption matching the browser Web Crypto API exactly (310,000 PBKDF2 iterations, AES-256-GCM). Output is base64-encoded JSON for browser consumption.
- **wrap.py** handles wrapping arbitrary files and directories into self-contained encrypted HTML payloads. Uses the same v2 crypto format. Key functions: `wrap_file()`, `wrap_site()`.
- **template.py** generates the `<pagevault>` Web Component JS and CSS that gets injected into encrypted HTML files, making them self-contained.
- **config.py** uses dataclasses (`PagevaultConfig`, `DefaultsConfig`, `TemplateConfig`) with directory traversal to find `.pagevault.yaml`.

### Viewer Plugin System

- `viewers/base.py`: `ViewerPlugin` ABC with `js()`, `css()`, `dependencies()`
- `viewers/builtin.py`: 5 built-in viewers (Image, PDF, HTML, Text, Markdown)
- `viewers/registry.py`: `discover_viewers()` (entry points), `resolve_viewer()` (exact > wildcard > download fallback)
- Entry points registered in `pyproject.toml` under `pagevault.viewers` group
- Config `viewers:` section enables/disables viewers; absent = all enabled
- Viewer JS signature: `async function(container, blob, url, meta, toolbar)`

## Key Design Constraints

- **Closure property**: `lock(lock(html)) == lock(html)`. Locking is idempotent: already-encrypted elements are skipped, preserving their ciphertext. To compose encryption layers (nested encryption), explicitly wrap an encrypted element with `mark_elements` first.
- **Attribute preservation**: Original `hint`, `title`, `remember` attributes must survive lock/unlock cycles.
- **Self-contained output**: Locked HTML must include all JS/CSS — no external dependencies at runtime.
- **WebCrypto parity**: Python crypto parameters must exactly match the browser-side JS generated in `parser.py` (`_get_javascript()`) and `wrap.py` (`_get_renderer_js()`). The JS is generated via f-strings — `{{`/`}}` produce `{`/`}` in output.
- **Default output dirs**: `lock` defaults to `_locked/`, `unlock` defaults to `_unlocked/`, both print a warning when using defaults.

## Security Gotchas

- **Each IIFE needs its own `escapeHtml()`** — parser, file renderer, and site renderer are self-contained; helpers can't be shared
- **`_js_string()` must escape `</`** as `<\/` to prevent `</script>` breakout
- **Viewer plugin content uses `_escape_for_script_block()`** — prevents `</script>` and `</style>` breakout in plugin JS/CSS
- **`ViewerPlugin.__init_subclass__`** validates `name` and `mime_types` via regex at class definition time (defense-in-depth)
- **Bare `hint`/`title`/`remember` attrs removed during lock** — only `data-` prefixed versions survive

## Testing Patterns

- CLI tests use Click's `CliRunner` with temp directory fixtures
- Parser/crypto tests use pytest parametrize for edge cases (unicode, empty content, large content, multiple elements)
- Integration tests (`test_integration.py`) verify full lock→unlock roundtrips and multi-password workflows
- Wrap tests (`test_wrap.py`) verify file/site wrapping, MIME detection, encrypted payload integrity, and CLI commands
- Viewer tests (`test_viewers.py`) verify plugin ABC, registry, MIME resolution, priority, config filtering, and XSS hardening
