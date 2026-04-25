// Node-based unit tests for pagevault's browser runtime.
//
// These cover stateless pieces (crypto, parsing) under Node 20+. Stateful
// pieces (DOM, activation, lifecycle) live in tests/test_browser_activation.py
// (Playwright). Run with: node --test tests/js/

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import vm from 'node:vm';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load crypto.js source. Functions are declared at top level, so they
// become properties of the vm context after runInContext.
const cryptoSrc = readFileSync(
  resolve(__dirname, '../../src/pagevault/runtime/core/crypto.js'),
  'utf-8'
);

// Silent console for the runtime — decryption failures intentionally
// log via console.error which Node's test runner treats as suite failure.
const silentConsole = { error: () => {}, warn: () => {}, log: () => {} };

const context = vm.createContext({
  crypto: globalThis.crypto,
  TextEncoder,
  TextDecoder,
  atob,
  btoa,
  Uint8Array,
  ArrayBuffer,
  JSON,
  Array,
  Error,
  console: silentConsole,
  parseInt,
});

vm.runInContext(cryptoSrc, context);


test('_hexToBytes decodes hex to Uint8Array', () => {
  const bytes = context._hexToBytes('48656c6c6f');
  assert.deepEqual(Array.from(bytes), [0x48, 0x65, 0x6c, 0x6c, 0x6f]);
});

test('decryptV4 rejects wrong version', async () => {
  const result = await context.decryptV4({ v: 99 }, [], 'pw', null);
  assert.equal(result, null);
});

test('computeHash returns 32-char hex for text', async () => {
  const hash = await context.computeHash('hello');
  assert.equal(typeof hash, 'string');
  assert.equal(hash.length, 32);
  assert.match(hash, /^[0-9a-f]{32}$/);
});

test('decryptV4 decrypts a Python-generated v4 envelope', async () => {
  const fixtureJson = readFileSync(
    resolve(__dirname, 'fixtures/v4_simple.json'),
    'utf-8'
  );
  const { envelope, chunks, password, expected_text } = JSON.parse(fixtureJson);

  const result = await context.decryptV4(envelope, chunks, password, null);
  assert.notEqual(result, null);
  const decoded = new TextDecoder().decode(result.bytes);
  assert.equal(decoded, expected_text);
  assert.equal(result.meta.kind, 'file');
  assert.equal(result.meta.mime, 'text/plain');
});

test('decryptV4 with wrong password returns null', async () => {
  const fixtureJson = readFileSync(
    resolve(__dirname, 'fixtures/v4_simple.json'),
    'utf-8'
  );
  const { envelope, chunks } = JSON.parse(fixtureJson);

  const result = await context.decryptV4(envelope, chunks, 'wrong-password', null);
  assert.equal(result, null);
});
