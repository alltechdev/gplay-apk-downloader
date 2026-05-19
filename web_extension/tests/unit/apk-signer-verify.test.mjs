// End-to-end signing test: build a minimal APK, sign it with our pure-JS
// signApk(), and shell out to the real `apksigner` to verify it. Skipped
// (not failed) when apksigner is not on PATH so CI without Android SDK
// still passes.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import * as fflate from 'fflate';
import { signApk } from '../../src/modules/apk-signer.js';
import { DEBUG_CERT_DER, DEBUG_KEY_PKCS8_DER } from '../../src/modules/debug-cert.js';

function apksignerAvailable() {
  const r = spawnSync('apksigner', ['--version'], { stdio: 'ignore' });
  return r.status === 0;
}

// A minimal AXML stub valid enough for apksigner to read it. Real
// AndroidManifest parsing happens at install time; apksigner verify
// only needs the file present.
function minimalManifestAxml() {
  // Empty resource map + minimum-viable AXML chunk header. apksigner
  // tolerates a manifest it can't decode; what it requires is presence.
  return new Uint8Array([
    0x03, 0x00, 0x08, 0x00, 0x08, 0x00, 0x00, 0x00,
  ]);
}

test('signApk: signed APK passes `apksigner verify` (v1+v2+v3)', async (t) => {
  if (!apksignerAvailable()) {
    t.skip('apksigner not on PATH — skipping end-to-end verify');
    return;
  }

  const apk = fflate.zipSync({
    'AndroidManifest.xml': minimalManifestAxml(),
    'classes.dex':         new Uint8Array(4096),
    'resources.arsc':      new Uint8Array(2048),
  }, { level: 0 });

  const signed = await signApk(apk, DEBUG_KEY_PKCS8_DER, DEBUG_CERT_DER, { v1: true, v2: true, v3: true });

  const dir = mkdtempSync(join(tmpdir(), 'gplaydl-sign-'));
  const apkPath = join(dir, 'signed.apk');
  writeFileSync(apkPath, signed);
  try {
    // --min-sdk-version 21 forces apksigner to check every scheme it
    // can (v1 for API < 24, v2 for API 24+, v3 for API 28+). With higher
    // min-sdk values apksigner skips v1 verification entirely.
    const out = execFileSync('apksigner',
      ['verify', '--min-sdk-version', '21', '--verbose', apkPath],
      { encoding: 'utf8' });
    assert.match(out, /Verified using v1 scheme.*true/i,  'v1 scheme should verify');
    assert.match(out, /Verified using v2 scheme.*true/i,  'v2 scheme should verify');
    assert.match(out, /Verified using v3 scheme.*true/i,  'v3 scheme should verify');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
