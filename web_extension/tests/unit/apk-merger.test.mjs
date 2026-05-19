// Unit tests for src/modules/apk-merger.js
// Confirms entries combine, signatures drop, base wins on conflict.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mergeApks, mergeApksFromBlobs } from '../../src/modules/apk-merger.js';
import * as fflate from 'fflate';

function makeZip(entries) {
  const obj = {};
  for (const [k, v] of Object.entries(entries)) {
    obj[k] = typeof v === 'string' ? new TextEncoder().encode(v) : v;
  }
  return fflate.zipSync(obj, { level: 0 });
}

test('mergeApks: combines entries from base + splits', () => {
  const base = makeZip({
    'AndroidManifest.xml': 'base-manifest',
    'classes.dex': 'base-dex',
  });
  const split1 = makeZip({
    'lib/arm64-v8a/libnative.so': 'arm64-lib',
  });
  const split2 = makeZip({
    'res/values-en/strings.xml': 'english-strings',
  });
  const merged = mergeApks(base, [
    { name: 'config.arm64_v8a', bytes: split1 },
    { name: 'config.en', bytes: split2 },
  ]);
  const entries = fflate.unzipSync(merged);
  assert.ok('AndroidManifest.xml' in entries);
  assert.ok('classes.dex' in entries);
  assert.ok('lib/arm64-v8a/libnative.so' in entries);
  assert.ok('res/values-en/strings.xml' in entries);
});

test('mergeApks: base wins on path conflict', () => {
  const base = makeZip({ 'AndroidManifest.xml': 'base-manifest' });
  const split = makeZip({ 'AndroidManifest.xml': 'split-manifest' });
  const merged = mergeApks(base, [{ name: 'x', bytes: split }]);
  const entries = fflate.unzipSync(merged);
  assert.equal(new TextDecoder().decode(entries['AndroidManifest.xml']), 'base-manifest');
});

test('mergeApksFromBlobs: produces byte-identical output to mergeApks', async () => {
  const base = makeZip({
    'AndroidManifest.xml':        'base-manifest',
    'classes.dex':                'base-dex',
    'META-INF/MANIFEST.MF':       'old-sig',
  });
  const split1 = makeZip({ 'lib/arm64-v8a/libnative.so': 'arm64-lib' });
  const split2 = makeZip({ 'res/values-en/strings.xml': 'english-strings' });

  const fromBytes = mergeApks(base, [
    { name: 'config.arm64_v8a', bytes: split1 },
    { name: 'config.en',        bytes: split2 },
  ]);
  const fromBlobs = await mergeApksFromBlobs(new Blob([base]), [
    { name: 'config.arm64_v8a', blob: new Blob([split1]) },
    { name: 'config.en',        blob: new Blob([split2]) },
  ]);

  // Byte-identical output → identical merge logic, just a different
  // intake path.
  assert.equal(fromBlobs.length, fromBytes.length);
  for (let i = 0; i < fromBytes.length; i++) {
    if (fromBlobs[i] !== fromBytes[i]) {
      assert.fail(`byte ${i} differs: blob=${fromBlobs[i]} bytes=${fromBytes[i]}`);
    }
  }
});

test('mergeApks: strips old signatures', () => {
  const base = makeZip({
    'AndroidManifest.xml': 'x',
    'META-INF/MANIFEST.MF': 'sig1',
    'META-INF/CERT.SF': 'sig2',
    'META-INF/CERT.RSA': 'sig3',
    'META-INF/keep.txt': 'kept',
  });
  const merged = mergeApks(base, []);
  const entries = fflate.unzipSync(merged);
  assert.ok(!('META-INF/MANIFEST.MF' in entries));
  assert.ok(!('META-INF/CERT.SF' in entries));
  assert.ok(!('META-INF/CERT.RSA' in entries));
  assert.ok('META-INF/keep.txt' in entries, 'non-signature META-INF should remain');
});
