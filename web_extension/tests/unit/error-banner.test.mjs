// Unit tests for the pure helpers in src/ui/error-banner.js.
// The DOM-touching functions (showError / clearError / initErrorBanner)
// are exercised by e2e — here we lock the classification heuristic that
// decides whether to surface an RPC failure as an SW-unreachable banner.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const srcPath = resolve(__dirname, '..', '..', 'src', 'ui', 'error-banner.js');

function loadIsConnectivityError() {
  // Strip ESM imports (they reference dom.js which isn't loadable under
  // vm) and pluck just the function we want.
  const src = readFileSync(srcPath, 'utf8')
    .replace(/^import .*$/gm, '')
    .replace(/^export\s+/gm, '');
  const code = `${src}\nglobalThis.isConnectivityError = isConnectivityError;`;
  const ctx = vm.createContext({ String });
  vm.runInContext(code, ctx);
  return ctx.isConnectivityError;
}

const isConnectivityError = loadIsConnectivityError();

test('isConnectivityError: detects SW disconnect errors', () => {
  assert.equal(isConnectivityError(new Error('Could not establish connection. Receiving end does not exist.')), true);
  assert.equal(isConnectivityError(new Error('The message port closed before a response was received.')), true);
  assert.equal(isConnectivityError(new Error('Extension context invalidated.')), true);
});

test('isConnectivityError: ignores ordinary errors', () => {
  assert.equal(isConnectivityError(new Error('VALIDATION: invalid package name')), false);
  assert.equal(isConnectivityError(new Error('CDN fetch base.apk → 404')), false);
  assert.equal(isConnectivityError(new Error('Cancelled')), false);
});

test('isConnectivityError: tolerates non-Error inputs', () => {
  assert.equal(isConnectivityError(null), false);
  assert.equal(isConnectivityError(undefined), false);
  assert.equal(isConnectivityError(''), false);
  assert.equal(isConnectivityError('Could not establish connection'), true);
});
