// Unit tests for src/sw/50-auth.js — authStatus / authSignOut / setArchRpc
// state transitions. authSignIn is covered by the live integration test.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadSw } from '../helpers/sw-load.mjs';

function makeChrome({ auth = null, arch = null } = {}) {
  const local = {};
  if (auth) local['gplaydl.auth'] = auth;
  if (arch) local['gplaydl.arch'] = arch;
  return {
    runtime: { sendMessage: () => Promise.resolve(), getURL: (p) => 'chrome-extension://test/' + p },
    storage: {
      local: {
        get:    async (k) => (k in local ? { [k]: local[k] } : {}),
        set:    async (o) => Object.assign(local, o),
        remove: async (k) => { delete local[k]; },
      },
      session: { get: async () => ({}), set: async () => {} },
    },
  };
}

function loadAuth(chromeStub) {
  return loadSw(
    ['00-config.js', '05-logger.js', '10-utils.js', '15-errors.js', '30-storage.js', '50-auth.js'],
    ['authStatus', 'authSignOut', 'setArchRpc', 'ValidationError'],
    { chrome: chromeStub },
  );
}

test('authStatus: not signed in → { signedIn: false } with default arch', async () => {
  const sw = loadAuth(makeChrome());
  const s = await sw.authStatus();
  assert.equal(s.signedIn, false);
  assert.equal(s.arch, 'arm64-v8a');
});

test('authStatus: signed in returns profile fields + age + stale flag', async () => {
  const fresh = {
    authToken: 'abc', email: 'x@y', gsfId: 'gsf',
    _profileKey: 'pk', _profileLabel: 'Pixel 9a', _profileArch: 'arm64-v8a',
    _obtainedAt: Date.now(),
  };
  const sw = loadAuth(makeChrome({ auth: fresh }));
  const s = await sw.authStatus();
  assert.equal(s.signedIn, true);
  assert.equal(s.profileKey, 'pk');
  assert.equal(s.profileLabel, 'Pixel 9a');
  assert.equal(s.profileArch, 'arm64-v8a');
  assert.equal(s.gsfId, 'gsf');
  assert.equal(s.email, 'x@y');
  assert.ok(s.ageMs >= 0 && s.ageMs < 1000);
  assert.equal(s.stale, false);
});

test('authStatus: marks stale when older than TTL (4 h)', async () => {
  const old = {
    authToken: 'abc',
    _obtainedAt: Date.now() - 5 * 60 * 60 * 1000, // 5 hours ago
  };
  const sw = loadAuth(makeChrome({ auth: old }));
  const s = await sw.authStatus();
  assert.equal(s.stale, true);
});

test('authStatus: defaults profileArch to arm64-v8a when missing', async () => {
  const sw = loadAuth(makeChrome({ auth: { authToken: 't', _obtainedAt: 0 } }));
  const s = await sw.authStatus();
  assert.equal(s.profileArch, 'arm64-v8a');
});

test('authSignOut: clears stored auth and returns { signedIn: false }', async () => {
  const sw = loadAuth(makeChrome({ auth: { authToken: 't', _obtainedAt: 0 } }));
  // Sanity: starts signed in.
  assert.equal((await sw.authStatus()).signedIn, true);
  const s = await sw.authSignOut();
  assert.equal(s.signedIn, false);
  assert.equal((await sw.authStatus()).signedIn, false);
});

test('authSignOut: preserves the arch preference', async () => {
  const sw = loadAuth(makeChrome({
    auth: { authToken: 't', _obtainedAt: 0 },
    arch: 'armeabi-v7a',
  }));
  const s = await sw.authSignOut();
  assert.equal(s.arch, 'armeabi-v7a');
});

test('setArchRpc: persists arch and returns updated status', async () => {
  const sw = loadAuth(makeChrome());
  const s = await sw.setArchRpc({ arch: 'armeabi-v7a' });
  assert.equal(s.arch, 'armeabi-v7a');
});

test('setArchRpc: rejects unknown arch values via storage layer', async () => {
  const sw = loadAuth(makeChrome());
  await assert.rejects(sw.setArchRpc({ arch: 'x86_64' }), /unknown arch/);
});
