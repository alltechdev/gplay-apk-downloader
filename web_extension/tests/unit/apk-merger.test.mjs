// Unit tests for src/modules/apk-merger.js
// Confirms entries combine, signatures drop, base wins on conflict.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mergeApks } from '../../src/modules/apk-merger.js';
import * as fflate from 'fflate';

function makeZip(entries) {
  const obj = {};
  for (const [k, v] of Object.entries(entries)) {
    obj[k] = typeof v === 'string' ? new TextEncoder().encode(v) : v;
  }
  return fflate.zipSync(obj, { level: 0 });
}
const asBlob = (u8) => new Blob([u8]);

test('mergeApks: combines entries from base + splits', async () => {
  const base = makeZip({
    'AndroidManifest.xml': 'base-manifest',
    'classes.dex': 'base-dex',
  });
  const split1 = makeZip({ 'lib/arm64-v8a/libnative.so': 'arm64-lib' });
  const split2 = makeZip({ 'res/values-en/strings.xml': 'english-strings' });
  const merged = await mergeApks(asBlob(base), [
    { name: 'config.arm64_v8a', blob: asBlob(split1) },
    { name: 'config.en',        blob: asBlob(split2) },
  ]);
  const entries = fflate.unzipSync(merged);
  assert.ok('AndroidManifest.xml' in entries);
  assert.ok('classes.dex' in entries);
  assert.ok('lib/arm64-v8a/libnative.so' in entries);
  assert.ok('res/values-en/strings.xml' in entries);
});

test('mergeApks: base wins on path conflict', async () => {
  const base  = makeZip({ 'AndroidManifest.xml': 'base-manifest' });
  const split = makeZip({ 'AndroidManifest.xml': 'split-manifest' });
  const merged = await mergeApks(asBlob(base), [{ name: 'x', blob: asBlob(split) }]);
  const entries = fflate.unzipSync(merged);
  assert.equal(new TextDecoder().decode(entries['AndroidManifest.xml']), 'base-manifest');
});

test('mergeApks: strips old signatures', async () => {
  const base = makeZip({
    'AndroidManifest.xml':    'x',
    'META-INF/MANIFEST.MF':   'sig1',
    'META-INF/CERT.SF':       'sig2',
    'META-INF/CERT.RSA':      'sig3',
    'META-INF/keep.txt':      'kept',
  });
  const merged = await mergeApks(asBlob(base), []);
  const entries = fflate.unzipSync(merged);
  assert.ok(!('META-INF/MANIFEST.MF' in entries));
  assert.ok(!('META-INF/CERT.SF' in entries));
  assert.ok(!('META-INF/CERT.RSA' in entries));
  assert.ok('META-INF/keep.txt' in entries, 'non-signature META-INF should remain');
});
