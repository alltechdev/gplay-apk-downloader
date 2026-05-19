// Unit tests for src/modules/pkcs7.js — buildPkcs7 structural verification.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildPkcs7 } from '../../src/modules/pkcs7.js';
import { parseTLV } from '../../src/modules/asn1.js';
import { DEBUG_CERT_DER } from '../../src/modules/debug-cert.js';

const OID_PKCS7_SIGNED_DATA = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];

function hasBytesAt(buf, off, expected) {
  for (let i = 0; i < expected.length; i++) if (buf[off + i] !== expected[i]) return false;
  return true;
}

test('buildPkcs7: returns a DER SEQUENCE', () => {
  const sig = new Uint8Array(256); // pretend RSA-2048 signature
  const out = buildPkcs7(DEBUG_CERT_DER, sig);
  assert.equal(out[0], 0x30, 'top-level must be SEQUENCE');
  const top = parseTLV(out, 0);
  assert.equal(top.totalLen, out.length, 'top SEQUENCE length must cover the whole blob');
});

test('buildPkcs7: ContentInfo contentType is pkcs7-signedData OID', () => {
  const out = buildPkcs7(DEBUG_CERT_DER, new Uint8Array(256));
  const top = parseTLV(out, 0);
  // First inside the top SEQUENCE is the contentType OID.
  assert.ok(hasBytesAt(out, top.valueStart, OID_PKCS7_SIGNED_DATA), 'contentType OID must match pkcs7-signedData');
});

test('buildPkcs7: explicit-tag [0] wraps SignedData', () => {
  const out = buildPkcs7(DEBUG_CERT_DER, new Uint8Array(256));
  const top = parseTLV(out, 0);
  // After contentType OID, we expect [0] EXPLICIT (tag 0xa0).
  const oid = parseTLV(out, top.valueStart);
  assert.equal(out[top.valueStart + oid.totalLen], 0xa0, 'expected [0] EXPLICIT after contentType');
});
