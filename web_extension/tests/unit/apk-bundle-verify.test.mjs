// Verify the shipped artifact: source-only tests cannot catch an outdated bundle.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { spawnSync, execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import vm from 'node:vm';
import { webcrypto } from 'node:crypto';
import * as fflate from 'fflate';

test('shipped browser bundle merges with verified alignment and v1/v2/v3 signatures', async (t) => {
  if (spawnSync('apksigner', ['--version'], { stdio: 'ignore' }).status !== 0) return t.skip('apksigner not available');
  let downloaded;
  const context = vm.createContext({ window: {}, crypto: webcrypto, Blob, TextEncoder, TextDecoder, btoa, atob,
    Uint8Array, Uint16Array, Uint32Array, Int32Array, ArrayBuffer, DataView,
    URL: { createObjectURL: (blob) => { downloaded = blob; return 'blob:test'; }, revokeObjectURL: () => {} },
    document: { createElement: () => ({ click() {} }), body: { appendChild() {}, removeChild() {} } },
    setTimeout: () => {},
  });
  vm.runInContext(readFileSync(new URL('../../src/vendor/apk-tools-bundle.js', import.meta.url), 'utf8'), context);
  const base = fflate.zipSync({ 'AndroidManifest.xml': new Uint8Array([3, 0, 8, 0, 8, 0, 0, 0]), 'classes.dex': new Uint8Array(4097), 'lib/arm64-v8a/libtest.so': new Uint8Array(1001) }, { level: 0 });
  const split = fflate.zipSync({ 'assets/test.txt': new TextEncoder().encode('split data') }, { level: 0 });
  await context.window.gplaydlApkTools.mergeAndSign([
    { name: 'base.apk', blob: new Blob([base]) }, { name: 'config.test.apk', blob: new Blob([split]) },
  ], 'signed.apk');
  const bytes = new Uint8Array(await downloaded.arrayBuffer());
  assert.equal(new TextDecoder().decode(fflate.unzipSync(bytes)['assets/test.txt']), 'split data');
  const dir = mkdtempSync(join(tmpdir(), 'gplay-bundle-'));
  try {
    const path = join(dir, 'signed.apk');
    writeFileSync(path, bytes);
    execFileSync('zipalign', ['-c', '-p', '4', path]);
    const output = execFileSync('apksigner', ['verify', '--min-sdk-version', '21', '--verbose', path], { encoding: 'utf8' });
    for (const scheme of ['v1', 'v2', 'v3']) assert.match(output, new RegExp(`Verified using ${scheme} scheme.*true`, 'i'));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
