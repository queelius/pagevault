// Node-based tests for the site renderer's postMessage bridge.
//
// The site renderer answers `pagevault-fetch` requests from the site iframe
// with decrypted file contents. The iframe's contentWindow object survives
// navigation, so `e.source === iframe.contentWindow` alone does not prove the
// message came from a pagevault-rendered page: a foreign page the user
// navigated to inside the iframe has the same `source`. These tests drive the
// real nav_injector.js + site_renderer.js against a minimal fake DOM.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import vm from 'node:vm';

const __dirname = dirname(fileURLToPath(import.meta.url));
const runtimeDir = resolve(__dirname, '../../src/pagevault/runtime');
const src = ['wrap/nav_injector.js', 'wrap/site_renderer.js']
  .map((p) => readFileSync(resolve(runtimeDir, p), 'utf-8'))
  .join('\n');

const FILES = {
  'index.html': '<html><body><a href="secret.txt">s</a></body></html>',
  'secret.txt': 'TOP SECRET PAYROLL DATA',
};

// Minimal DOMParser stand-in for injectNavScript. These tests exercise the
// message protocol; where the shim lands in a real document (first in
// <head>, before page scripts) is covered in Chromium by
// tests/test_browser_site.py.
class FakeDOMParser {
  parseFromString(html) {
    const head = {
      nodes: [],
      firstChild: null,
      insertBefore(node) { this.nodes.unshift(node); },
    };
    return {
      head,
      createElement: () => ({ textContent: '' }),
      documentElement: {
        get outerHTML() {
          const scripts = head.nodes.map((n) => `<script>${n.textContent}</script>`);
          return `<html><head>${scripts.join('')}</head><body>${html}</body></html>`;
        },
      },
    };
  }
}

function makeHarness(origin = 'https://owner.example') {
  const listeners = [];
  const posted = [];
  const contentWindow = {
    postMessage: (msg, targetOrigin) => posted.push({ msg, targetOrigin }),
    history: { pushState() {}, replaceState() {} },
  };
  const iframe = {
    contentWindow,
    srcdoc: '',
    className: '',
    addEventListener() {},
  };
  const container = { innerHTML: '', appendChild() {} };
  const enc = new TextEncoder();

  class FakeZipReader {
    getFileNames() { return Object.keys(FILES); }
    async getFile(name) { return enc.encode(FILES[name]); }
  }

  const window = {
    location: { origin, protocol: origin.split(':')[0] + ':' },
    addEventListener: (type, fn) => { if (type === 'message') listeners.push(fn); },
    __pagevault_ZipReader: FakeZipReader,
  };
  const ctx = vm.createContext({
    window,
    location: window.location,
    document: { createElement: () => iframe },
    DOMParser: FakeDOMParser,
    crypto: globalThis.crypto,
    TextDecoder,
    Uint8Array,
    Set,
    String,
    JSON,
    btoa,
    console: { error() {}, warn() {}, log() {} },
  });
  vm.runInContext(src, ctx);

  async function render() {
    await window.__pagevault_renderSite(
      container, new Uint8Array(0), { entry: 'index.html' }
    );
  }
  function send(data, msgOrigin = origin) {
    for (const fn of listeners) fn({ source: contentWindow, origin: msgOrigin, data });
  }
  // The token the renderer embedded into the srcdoc page it rendered.
  function embeddedToken() {
    const m = iframe.srcdoc.match(/__pvTok="([0-9a-f]+)"/);
    return m ? m[1] : null;
  }
  return { render, send, posted, embeddedToken };
}

test('fetch request without the session token gets no response', async () => {
  const h = makeHarness();
  await h.render();
  // A foreign page loaded into the iframe: same `source`, no token.
  h.send({ type: 'pagevault-fetch', path: 'secret.txt', id: 1 });
  assert.equal(h.posted.length, 0);
});

test('fetch request from a foreign origin is rejected even with a token', async () => {
  const h = makeHarness();
  await h.render();
  const token = h.embeddedToken();
  h.send({ type: 'pagevault-fetch', path: 'secret.txt', id: 1, token },
    'https://evil.example');
  assert.equal(h.posted.length, 0);
});

test('fetch request from the rendered page is answered, scoped to our origin', async () => {
  const h = makeHarness();
  await h.render();
  const token = h.embeddedToken();
  assert.ok(token, 'renderer must embed a session token in the srcdoc page');
  h.send({ type: 'pagevault-fetch', path: 'secret.txt', id: 7, token });
  assert.equal(h.posted.length, 1);
  assert.equal(h.posted[0].msg.id, 7);
  assert.match(h.posted[0].msg.data, /^data:text\/plain;base64,/);
  assert.equal(h.posted[0].targetOrigin, 'https://owner.example');
});

test('under file:// (opaque origin) the token alone authorizes', async () => {
  const h = makeHarness('file://');
  await h.render();
  const token = h.embeddedToken();
  h.send({ type: 'pagevault-fetch', path: 'secret.txt', id: 1, token }, 'null');
  assert.equal(h.posted.length, 1);
  h.send({ type: 'pagevault-fetch', path: 'secret.txt', id: 2 }, 'null');
  assert.equal(h.posted.length, 1);
});

test('each render session gets a fresh token', async () => {
  const a = makeHarness();
  const b = makeHarness();
  await a.render();
  await b.render();
  assert.notEqual(a.embeddedToken(), b.embeddedToken());
});
