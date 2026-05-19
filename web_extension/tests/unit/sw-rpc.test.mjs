// Unit tests for src/sw/99-rpc.js — RPC dispatch + error serialization.
// The dispatcher is the gateway between every page-side call and the SW
// handlers; if it routes incorrectly or swallows error fields, every
// downstream UX is wrong.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const swDir = resolve(__dirname, '..', '..', 'src', 'sw');

/**
 * Load 99-rpc.js with a stubbed `chrome.runtime.onMessage.addListener`
 * that captures the registered handler. Each test installs its own RPC
 * function table (overriding the symbols 99-rpc.js references) so we
 * can exercise success + failure + unknown-rpc cleanly.
 */
function loadRpc(handlers) {
  const captured = { listener: null };
  const chromeStub = {
    runtime: {
      onMessage: { addListener: (fn) => { captured.listener = fn; } },
      sendMessage: () => Promise.resolve(),
    },
  };
  const stubs = {};
  // The dispatcher names every handler symbol used in the RPC map.
  for (const name of ['authStatus','authSignIn','authSignOut','setArchRpc','appDetails','appDelivery','appDownload','cancelDownload','showDownload','appPrepareInstall','releaseRules','appSearch']) {
    stubs[name] = handlers[name] || (async () => { throw new Error(name + ' not stubbed'); });
  }
  const code = readFileSync(resolve(swDir, '99-rpc.js'), 'utf8');
  const ctx = vm.createContext({ chrome: chromeStub, Promise, console, ...stubs });
  vm.runInContext(code, ctx);
  return captured.listener;
}

async function rpcCall(listener, msg) {
  return new Promise((resolve) => {
    // The MV3 dispatcher contract: listener returns `true` when it will
    // call sendResponse asynchronously, anything else means "no response
    // coming" (broadcasts, unknown rpc that already invoked sendResponse
    // synchronously, or genuine ignore). Resolve immediately in those
    // cases — otherwise we'd hang forever waiting on a sendResponse
    // call that never comes.
    let settled = false;
    const sendResponse = (r) => { if (!settled) { settled = true; resolve(r); } };
    const ret = listener(msg, {}, sendResponse);
    if (ret !== true && !settled) { settled = true; resolve(undefined); }
  });
}

test('rpc dispatch: routes auth.status to authStatus()', async () => {
  const listener = loadRpc({ authStatus: async () => ({ signedIn: true }) });
  const res = await rpcCall(listener, { type: 'auth.status' });
  assert.equal(res?.result?.signedIn, true);
});

test('rpc dispatch: passes payload through to the handler', async () => {
  let captured;
  const listener = loadRpc({ appDetails: async (p) => { captured = p; return { ok: 1 }; } });
  await rpcCall(listener, { type: 'app.details', payload: { packageName: 'com.x' } });
  assert.equal(captured?.packageName, 'com.x');
});

test('rpc dispatch: serializes error.message into response', async () => {
  const listener = loadRpc({ appDetails: async () => { throw new Error('boom'); } });
  const res = await rpcCall(listener, { type: 'app.details' });
  assert.equal(res.error, 'boom');
});

test('rpc dispatch: preserves err.code and err.status on the response', async () => {
  const listener = loadRpc({
    appDetails: async () => {
      const e = new Error('Unauthorized');
      e.code = 'AUTH';
      e.status = 401;
      throw e;
    },
  });
  const res = await rpcCall(listener, { type: 'app.details' });
  assert.equal(res.error, 'Unauthorized');
  assert.equal(res.code, 'AUTH');
  assert.equal(res.status, 401);
});

test('rpc dispatch: unknown rpc types respond with UNKNOWN_RPC', async () => {
  const listener = loadRpc({});
  const res = await rpcCall(listener, { type: 'app.doesNotExist' });
  assert.match(res.error, /unknown rpc/);
  assert.equal(res.code, 'UNKNOWN_RPC');
});

test('rpc dispatch: ignores broadcast event types (auth.event / download.event)', async () => {
  let called = false;
  const listener = loadRpc({ authStatus: async () => { called = true; return {}; } });
  // Calling auth.event must NOT trigger any handler nor schedule sendResponse.
  await rpcCall(listener, { type: 'auth.event', payload: { phase: 'ok' } });
  await rpcCall(listener, { type: 'download.event', payload: { phase: 'progress' } });
  assert.equal(called, false);
});

test('rpc dispatch: missing payload defaults to {} for the handler', async () => {
  let captured;
  const listener = loadRpc({ appDetails: async (p) => { captured = p; return {}; } });
  await rpcCall(listener, { type: 'app.details' });
  assert.ok(captured && Object.keys(captured).length === 0, 'payload defaults to {}');
});

test('rpc dispatch: handler returning non-promise still resolves', async () => {
  const listener = loadRpc({ authStatus: () => ({ signedIn: false }) }); // sync
  const res = await rpcCall(listener, { type: 'auth.status' });
  assert.equal(res?.result?.signedIn, false);
});

test('rpc dispatch: stringifies non-Error rejections', async () => {
  const listener = loadRpc({ appDetails: async () => { throw 'string-error'; } });
  const res = await rpcCall(listener, { type: 'app.details' });
  assert.equal(res.error, 'string-error');
});
