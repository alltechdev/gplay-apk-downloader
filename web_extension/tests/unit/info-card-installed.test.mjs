// Unit tests for getInstalledVersion in src/ui/info-card.js — parses
// the device's `dumpsys package` output. The function is module-private
// so we pluck it via regex + vm. Critical: a wrong parse mis-tags the
// "(update available)" / "(up to date)" badges.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const srcPath = resolve(__dirname, '..', '..', 'src', 'ui', 'info-card.js');

function loadInstalled({ connected = true, shellOut = '', shellThrows = false } = {}) {
  const src = readFileSync(srcPath, 'utf8');
  const fnMatch = /async function getInstalledVersion\(pkg\) \{[\s\S]*?\n\}/.exec(src);
  if (!fnMatch) throw new Error('cannot find getInstalledVersion');
  const code = `
    const adb = () => ({
      connected: ${connected},
      shell: async () => { ${shellThrows ? 'throw new Error("shell failed");' : `return ${JSON.stringify(shellOut)};`} },
    });
    ${fnMatch[0]}
    globalThis.getInstalledVersion = getInstalledVersion;
  `;
  const ctx = vm.createContext({ Number });
  vm.runInContext(code, ctx);
  return ctx.getInstalledVersion;
}

test('getInstalledVersion: returns null when no ADB device is connected', async () => {
  const fn = loadInstalled({ connected: false });
  assert.equal(await fn('com.example.app'), null);
});

test('getInstalledVersion: extracts versionName + versionCode from dumpsys output', async () => {
  const out = '    versionName=120.0.5\n    versionCode=120005000 targetSdk=34\n';
  const fn = loadInstalled({ shellOut: out });
  const r = await fn('com.example.app');
  assert.equal(r.versionName, '120.0.5');
  assert.equal(r.versionCode, 120005000);
  assert.equal(typeof r.versionCode, 'number');
});

test('getInstalledVersion: handles versionName-only output (no versionCode)', async () => {
  const fn = loadInstalled({ shellOut: '    versionName=1.0.0\n' });
  const r = await fn('com.x');
  assert.equal(r.versionName, '1.0.0');
  assert.equal(r.versionCode, 0);
});

test('getInstalledVersion: handles versionCode-only output (no versionName)', async () => {
  const fn = loadInstalled({ shellOut: '    versionCode=42\n' });
  const r = await fn('com.x');
  assert.equal(r.versionName, '?');
  assert.equal(r.versionCode, 42);
});

test('getInstalledVersion: returns null when neither field is present', async () => {
  const fn = loadInstalled({ shellOut: 'Cannot find package: com.x\n' });
  assert.equal(await fn('com.x'), null);
});

test('getInstalledVersion: returns null on empty shell output', async () => {
  const fn = loadInstalled({ shellOut: '' });
  assert.equal(await fn('com.x'), null);
});

test('getInstalledVersion: swallows shell errors and returns null', async () => {
  const fn = loadInstalled({ shellThrows: true });
  assert.equal(await fn('com.x'), null);
});

test('getInstalledVersion: tolerates multi-line / whitespace-padded dumpsys output', async () => {
  const out = `
    Hidden system packages:
      versionName=18.7.10024
      versionCode=187100245 minSdk=24 targetSdk=34
      apkSigningVersion=2`;
  const fn = loadInstalled({ shellOut: out });
  const r = await fn('org.x');
  assert.equal(r.versionName, '18.7.10024');
  assert.equal(r.versionCode, 187100245);
});

test('getInstalledVersion: only takes the first versionName / versionCode match', async () => {
  // Some packages list multiple versions (current + hidden / staged).
  const out = '    versionName=2.0.0\n    versionCode=200\n    versionName=1.0.0\n';
  const fn = loadInstalled({ shellOut: out });
  const r = await fn('com.x');
  assert.equal(r.versionName, '2.0.0');
});
