// Unit tests for src/modules/asn1.js — DER builder + minimal Certificate parser.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  derLen, derTLV, derSeq, derSet, derOid, derInteger, derNull, derOctet,
  parseTLV, parseCertIssuerAndSerial, concat,
} from '../../src/modules/asn1.js';
import { DEBUG_CERT_DER } from '../../src/modules/debug-cert.js';

const hex = (u8) => Array.from(u8).map((b) => b.toString(16).padStart(2, '0')).join('');

test('derLen: short form (< 0x80)', () => {
  assert.deepEqual(Array.from(derLen(0)), [0]);
  assert.deepEqual(Array.from(derLen(0x7f)), [0x7f]);
});

test('derLen: long form (>= 0x80)', () => {
  assert.deepEqual(Array.from(derLen(0x80)),   [0x81, 0x80]);
  assert.deepEqual(Array.from(derLen(0x100)),  [0x82, 0x01, 0x00]);
  assert.deepEqual(Array.from(derLen(65535)),  [0x82, 0xff, 0xff]);
});

test('derTLV: wraps tag + length + value', () => {
  const tlv = derTLV(0x04, new Uint8Array([1, 2, 3]));
  assert.deepEqual(Array.from(tlv), [0x04, 0x03, 1, 2, 3]);
});

test('derInteger: positive values', () => {
  assert.deepEqual(Array.from(derInteger(new Uint8Array([0x42]))),         [0x02, 0x01, 0x42]);
  assert.deepEqual(Array.from(derInteger(new Uint8Array([0x01, 0x00]))),   [0x02, 0x02, 0x01, 0x00]);
});

test('derInteger: pads with 0x00 when high bit would make it negative', () => {
  assert.deepEqual(Array.from(derInteger(new Uint8Array([0xff]))),       [0x02, 0x02, 0x00, 0xff]);
  assert.deepEqual(Array.from(derInteger(new Uint8Array([0x80, 0x01]))), [0x02, 0x03, 0x00, 0x80, 0x01]);
});

test('derSeq + derSet + derNull + derOctet', () => {
  assert.equal(hex(derSeq([])), '3000');
  assert.equal(hex(derSet([])), '3100');
  assert.equal(hex(derNull()), '0500');
  assert.equal(hex(derOctet(new Uint8Array([0xaa]))), '0401aa');
});

test('derOid: known OIDs', () => {
  // 1.2.840.113549.1.7.2  →  pkcs7-signedData
  assert.equal(hex(derOid([1, 2, 840, 113549, 1, 7, 2])), '06092a864886f70d010702');
  // 2.16.840.1.101.3.4.2.1  →  sha-256
  assert.equal(hex(derOid([2, 16, 840, 1, 101, 3, 4, 2, 1])), '0609608648016503040201');
});

test('parseTLV: short and long lengths', () => {
  // tag 0x30, len 5
  const a = parseTLV(new Uint8Array([0x30, 0x05, 1, 2, 3, 4, 5]), 0);
  assert.equal(a.tag, 0x30);
  assert.equal(a.headerLen, 2);
  assert.equal(a.valueStart, 2);
  assert.equal(a.valueLen, 5);
  assert.equal(a.totalLen, 7);

  // tag 0x04, len 0x80 (long form: 2 header bytes)
  const data = new Uint8Array(3 + 0x80);
  data[0] = 0x04; data[1] = 0x81; data[2] = 0x80;
  const b = parseTLV(data, 0);
  assert.equal(b.tag, 0x04);
  assert.equal(b.headerLen, 3);
  assert.equal(b.valueStart, 3);
  assert.equal(b.valueLen, 0x80);
});

test('parseCertIssuerAndSerial: extracts a non-empty issuer SEQUENCE and serial INTEGER from the bundled debug cert', () => {
  const { issuer, serial } = parseCertIssuerAndSerial(DEBUG_CERT_DER);
  assert.equal(issuer[0], 0x30, 'issuer should be a SEQUENCE');
  assert.equal(serial[0], 0x02, 'serial should be an INTEGER');
  assert.ok(issuer.length > 2);
  assert.ok(serial.length > 2);
});

test('concat: joins Uint8Arrays end-to-end', () => {
  const out = concat([new Uint8Array([1, 2]), new Uint8Array([3, 4, 5]), new Uint8Array([])]);
  assert.deepEqual(Array.from(out), [1, 2, 3, 4, 5]);
});
