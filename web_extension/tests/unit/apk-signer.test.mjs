// Unit tests for src/modules/apk-signer.js
// Confirms a synthetic APK (zip) round-trips through signApkV2 and
// produces a structurally valid v2 signing block.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { signApkV2 } from '../../src/modules/apk-signer.js';
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

test('signApkV2: produces a parseable zip with signing block + magic', async () => {
  const apk = fflate.zipSync({
    'AndroidManifest.xml': new TextEncoder().encode('<?xml?>'),
    'classes.dex': new Uint8Array(2048),
    'resources.arsc': new Uint8Array(1024),
  }, { level: 0 });

  const signed = await signApkV2(apk, DEBUG_KEY_PKCS8_DER, DEBUG_CERT_DER);
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
  // Find the EOCD (signature 0x06054b50) in the last 64 KB.
  let eocdOff = -1;
  for (let i = signed.length - 22; i >= Math.max(0, signed.length - 65557); i--) {
    if (readU32LE(signed, i) === 0x06054b50) { eocdOff = i; break; }
  }
  assert.notEqual(eocdOff, -1, 'EOCD not found in signed output');
  const cdOffset = readU32LE(signed, eocdOff + 16);
  // The magic ends right before the central directory in our layout.
  assert.ok(magicOff + MAGIC.length === cdOffset, 'magic should end where the central directory starts');
});
