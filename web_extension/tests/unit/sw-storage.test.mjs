// Unit tests for src/sw/30-storage.js — chrome.storage wrappers + the
// download↔rule map's hydrate/persist round-trip.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadSw } from '../helpers/sw-load.mjs';

function makeChrome({ local = {}, session = {}, sessionThrows = false } = {}) {
  return {
    runtime: { sendMessage: () => Promise.resolve(), getURL: (p) => 'chrome-extension://test/' + p },
    storage: {
      local: {
        get:    async (k) => (k in local ? { [k]: local[k] } : {}),
        set:    async (o) => Object.assign(local, o),
        remove: async (k) => { delete local[k]; },
      },
      session: {
        get: async (k) => { if (sessionThrows) throw new Error('no session'); return (k in session ? { [k]: session[k] } : {}); },
        set: async (o) => { if (sessionThrows) throw new Error('no session'); Object.assign(session, o); },
      },
    },
  };
}

function loadStorage(chromeStub) {
  return loadSw(
    ['00-config.js', '05-logger.js', '15-errors.js', '30-storage.js'],
    [
      'getAuthStored', 'setAuthStored', 'clearAuthStored',
      'getArchPref', 'setArchPref',
      'hydrateDlMap', 'persistDlMap', 'downloadRuleByDl',
      'ValidationError',
    ],
    { chrome: chromeStub },
  );
}

test('auth: set → get round-trip', async () => {
  const local = {};
  const sw = loadStorage(makeChrome({ local }));
  await sw.setAuthStored({ authToken: 'abc', email: 'x@y' });
  const got = await sw.getAuthStored();
  assert.equal(got.authToken, 'abc');
  assert.equal(got.email, 'x@y');
});

test('auth: clear removes the key', async () => {
  const local = { 'gplaydl.auth': { authToken: 't' } };
  const sw = loadStorage(makeChrome({ local }));
  assert.ok((await sw.getAuthStored())?.authToken);
  await sw.clearAuthStored();
  assert.equal(await sw.getAuthStored(), null);
});

test('auth: getAuthStored returns null on empty', async () => {
  const sw = loadStorage(makeChrome());
  assert.equal(await sw.getAuthStored(), null);
});

test('arch: default to arm64-v8a when nothing stored', async () => {
  const sw = loadStorage(makeChrome());
  assert.equal(await sw.getArchPref(), 'arm64-v8a');
});

test('arch: set arm64-v8a or armeabi-v7a, get back what was set', async () => {
  const sw = loadStorage(makeChrome());
  await sw.setArchPref('armeabi-v7a');
  assert.equal(await sw.getArchPref(), 'armeabi-v7a');
});

test('arch: rejects unknown values with ValidationError', async () => {
  const sw = loadStorage(makeChrome());
  await assert.rejects(sw.setArchPref('x86_64'), /unknown arch/);
  await assert.rejects(sw.setArchPref(''),       /unknown arch/);
  await assert.rejects(sw.setArchPref(null),     /unknown arch/);
});

test('downloadRuleByDl: hydrate from chrome.storage.session', async () => {
  const session = { 'gplaydl.downloadRules': { 42: 100, 43: 101 } };
  const sw = loadStorage(makeChrome({ session }));
  await sw.hydrateDlMap();
  assert.equal(sw.downloadRuleByDl.get(42), 100);
  assert.equal(sw.downloadRuleByDl.get(43), 101);
});

test('downloadRuleByDl: hydrate is idempotent (only loads once)', async () => {
  const session = { 'gplaydl.downloadRules': { 1: 100 } };
  const chromeStub = makeChrome({ session });
  let getCalls = 0;
  const realGet = chromeStub.storage.session.get;
  chromeStub.storage.session.get = async (k) => { getCalls++; return realGet(k); };
  const sw = loadStorage(chromeStub);
  await sw.hydrateDlMap();
  await sw.hydrateDlMap();
  await sw.hydrateDlMap();
  assert.equal(getCalls, 1, 'second+ calls must be no-ops');
});

test('downloadRuleByDl: persist serialises every entry into session', async () => {
  const session = {};
  const sw = loadStorage(makeChrome({ session }));
  sw.downloadRuleByDl.set(7, 100);
  sw.downloadRuleByDl.set(8, 101);
  await sw.persistDlMap();
  const stored = session['gplaydl.downloadRules'];
  assert.equal(stored[7], 100);
  assert.equal(stored[8], 101);
  assert.equal(Object.keys(stored).length, 2);
});

test('downloadRuleByDl: hydrate swallows session-API errors gracefully', async () => {
  const sw = loadStorage(makeChrome({ sessionThrows: true }));
  await assert.doesNotReject(sw.hydrateDlMap());
});
