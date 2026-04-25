# JS Unit Tests

Node-based unit tests for pagevault's browser runtime. No npm dependencies.
Uses `node:test` and `node:vm` (built into Node 20+).

## Run

```bash
node --test "tests/js/**/*.mjs"
```

Or run a specific file:

```bash
node --test tests/js/test_crypto.mjs
```

Requires Node 20+ (for `crypto.subtle` global).

## Scope

**Covered here:** crypto primitives, data transformations, format parsing,
anything testable without a real DOM.

**NOT covered here:** stateful pieces (DOM manipulation, script activation,
lifecycle events). Those are tested via Playwright in
`tests/test_browser_activation.py`. Adding them here would require jsdom
and adds dependency weight for little incremental value.

## Fixtures

`fixtures/generate_v4_fixture.py` regenerates JSON fixtures from Python
when the v4 envelope format changes. Run after any `crypto.py` changes
that affect the envelope schema:

```bash
python tests/js/fixtures/generate_v4_fixture.py
```
