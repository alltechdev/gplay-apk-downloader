// Unit tests for src/modules/apk-signer.js
// Confirms a synthetic APK (zip) round-trips through signApk and
// produces a structurally valid signing block for every scheme combo.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { signApk } from '../../src/modules/apk-signer.js';
import { DEBUG_CERT_DER, DEBUG_KEY_PKCS8_DER } from '../../src/modules/debug-cert.js';
import * as fflate from 'fflate';

const MAGIC = new TextEncoder().encode('APK Sig Block 42');

function findMagic(buf, magic) {
  outer: for (let i = 0; i + magic.length <= buf.length; i++) {
    for (let j = 0; j < magic.length; j++) if (buf[i + j] !== magic[j]) continue outer;
    return i;
  }
  return -1;
}

function readU32LE(buf, off) {
  return (buf[off]) | (buf[off + 1] << 8) | (buf[off + 2] << 16) | ((buf[off + 3] << 24) >>> 0);
}

function freshApk() {
  return fflate.zipSync({
    'AndroidManifest.xml': new TextEncoder().encode('<?xml?>'),
    'classes.dex':    new Uint8Array(2048),
    'resources.arsc': new Uint8Array(1024),
  }, { level: 0 });
}

test('signApk(v2 only): produces a parseable zip with signing block + magic', async () => {
  const apk = freshApk();
  const signed = await signApk(apk, DEBUG_KEY_PKCS8_DER, DEBUG_CERT_DER, { v1: false, v2: true, v3: false });
  assert.ok(signed.length > apk.length, 'signed output should be larger than input');

  // EOCD must still be parseable.
  const entries = fflate.unzipSync(signed);
  assert.ok('AndroidManifest.xml' in entries);
  assert.ok('classes.dex' in entries);

  // Magic must appear exactly once.
  const magicOff = findMagic(signed, MAGIC);
  assert.notEqual(magicOff, -1, 'APK Sig Block 42 magic not found');

  // The signing block sits before the Central Directory. EOCD's CD offset
  // should point past the signing block.
  let eocdOff = -1;
  for (let i = signed.length - 22; i >= Math.max(0, signed.length - 65557); i--) {
    if (readU32LE(signed, i) === 0x06054b50) { eocdOff = i; break; }
  }
  assert.notEqual(eocdOff, -1, 'EOCD not found in signed output');
  const cdOffset = readU32LE(signed, eocdOff + 16);
  assert.ok(magicOff + MAGIC.length === cdOffset, 'magic should end where the central directory starts');
});

test('signApk(v1 only): produces a JAR-style signed zip with META-INF entries', async () => {
  const apk = freshApk();
  const signed = await signApk(apk, DEBUG_KEY_PKCS8_DER, DEBUG_CERT_DER, { v1: true, v2: false, v3: false });
  const entries = fflate.unzipSync(signed);
  assert.ok('META-INF/MANIFEST.MF' in entries, 'v1 must add MANIFEST.MF');
  assert.ok('META-INF/CERT.SF'     in entries, 'v1 must add CERT.SF');
  assert.ok('META-INF/CERT.RSA'    in entries, 'v1 must add CERT.RSA');
  // No APK Signing Block (that's v2/v3 territory).
  assert.equal(findMagic(signed, MAGIC), -1, 'v1-only output must not include APK Signing Block');
});

test('signApk(v3 only): produces an APK Signing Block but no META-INF signature files', async () => {
  const apk = freshApk();
  const signed = await signApk(apk, DEBUG_KEY_PKCS8_DER, DEBUG_CERT_DER, { v1: false, v2: false, v3: true });
  const entries = fflate.unzipSync(signed);
  assert.ok(!('META-INF/CERT.SF' in entries), 'v3-only output must not include CERT.SF');
  assert.notEqual(findMagic(signed, MAGIC), -1, 'v3-only output must include APK Signing Block magic');
});

test('signApk(v1+v2+v3): output contains both META-INF and APK Signing Block', async () => {
  const apk = freshApk();
  const signed = await signApk(apk, DEBUG_KEY_PKCS8_DER, DEBUG_CERT_DER, { v1: true, v2: true, v3: true });
  const entries = fflate.unzipSync(signed);
  assert.ok('META-INF/MANIFEST.MF' in entries);
  assert.notEqual(findMagic(signed, MAGIC), -1);
});

test('signApk(no schemes): returns the input unchanged', async () => {
  const apk = freshApk();
  const signed = await signApk(apk, DEBUG_KEY_PKCS8_DER, DEBUG_CERT_DER, { v1: false, v2: false, v3: false });
  assert.equal(signed.length, apk.length);
});
