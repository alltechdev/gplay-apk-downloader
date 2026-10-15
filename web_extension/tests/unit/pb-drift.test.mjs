// pb-drift.test.mjs — verifies the SW decoder (sw/20-pb.js, loaded via
// `tests/helpers/pb-sw.mjs`) and the ESM decoder (modules/pb-decode.js)
// produce identical output on a synthetic protobuf message that exercises
// every field type we use against the live Play API.
//
// This catches drift in either decoder implementation. The Play API
// schemas live only in `src/sw/20-pb.js`; this test (and the integration
// test) import them through the helper, so the schema definitions
// themselves are never duplicated.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decode } from '../../src/modules/pb-decode.js';
import { pbDecode, PB_ResponseWrapper } from '../helpers/pb-sw.mjs';

// --- tiny protobuf encoder (test-only) -----------------------------------

function vint(n) {
  const out = [];
  let v = BigInt(n);
  while (v > 0x7fn) { out.push(Number(v & 0x7fn) | 0x80); v >>= 7n; }
  out.push(Number(v));
  return out;
}
// Tag is itself a varint of (field << 3) | wire. Field numbers >= 16
// (where the encoded value exceeds 127) need multi-byte tags.
function tag(fieldNo, wire) { return vint((fieldNo << 3) | wire); }
function str(fieldNo, s) {
  const e = new TextEncoder().encode(s);
  return [...tag(fieldNo, 2), ...vint(e.length), ...e];
}
function int(fieldNo, n) {
  return [...tag(fieldNo, 0), ...vint(n)];
}
function nested(fieldNo, bytes) {
  return [...tag(fieldNo, 2), ...vint(bytes.length), ...bytes];
}

// --- fixture --------------------------------------------------------------

function buildFixture() {
  // HttpCookie x2
  const cookie1 = [...str(1, 'a'), ...str(2, 'cookie-value-1')];
  const cookie2 = [...str(1, 'auth'), ...str(2, 'cookie-value-2')];

  // SplitDeliveryData
  const split = [
    ...str(1, 'config.en'),
    ...int(2, 102400),
    ...str(5, 'https://cdn.example/split.en.apk'),
  ];

  // AndroidAppDeliveryData
  const appDelivery = [
    ...int(1, 19821680),
    ...str(2, 'b2a3c4d5e6f7'),
    ...str(3, 'https://cdn.example/base.apk'),
    ...nested(5, cookie1),
    ...nested(5, cookie2),
    ...nested(15, split),
  ];
  const deliveryResp = [
    ...int(1, 1),
    ...nested(2, appDelivery),
  ];

  // AppDetails
  const appDetails = [
    ...str(1, 'Example Devs'),
    ...int(3, 52791000),
    ...str(4, '5.279.1'),
    ...int(9, 120103189),
    ...str(14, 'com.example.app'),
    ...str(16, '2026-05-19'),
    ...str(25, 'config.arm64_v8a'),
    ...str(25, 'config.en'),
  ];
  const docDetails = [...nested(1, appDetails)];
  const docV2 = [
    ...str(1, 'com.example.app'),
    ...str(5, 'Example App'),
    ...nested(13, docDetails),
  ];
  const detailsResp = [...nested(4, docV2)];

  const payload = [...nested(2, detailsResp), ...nested(21, deliveryResp)];
  const wrapper = nested(1, payload);
  return new Uint8Array(wrapper);
}

// --- the test ------------------------------------------------------------

// Walk an object tree and normalise it into plain in-context objects with
// BigInts converted to strings. `deepStrictEqual` checks prototype
// identity, which differs for objects/arrays coming from a vm context;
// rebuilding them in the current realm makes the comparison meaningful.
function normalize(o) {
  if (o === null || o === undefined) return o;
  if (typeof o === 'bigint') return 'bigint:' + o.toString();
  if (typeof o !== 'object') return o;
  if (o instanceof Uint8Array) return 'bytes:' + Array.from(o).join(',');
  if (Array.isArray(o)) {
    const arr = [];
    for (let i = 0; i < o.length; i++) arr.push(normalize(o[i]));
    return arr;
  }
  const out = {};
  for (const k of Object.keys(o)) out[k] = normalize(o[k]);
  return out;
}

test('pb decoder drift: sw/20-pb.js and modules/pb-decode.js match', () => {
  const fixture = buildFixture();
  const moduleOut = decode(fixture, PB_ResponseWrapper);
  const swOut     = pbDecode(fixture, PB_ResponseWrapper);
  assert.deepEqual(normalize(moduleOut), normalize(swOut), 'sw and modules decoders disagree');

  // Spot-check a few fields.
  assert.equal(moduleOut.payload.detailsResponse.docV2.docid, 'com.example.app');
  assert.equal(moduleOut.payload.detailsResponse.docV2.title, 'Example App');
  assert.equal(moduleOut.payload.detailsResponse.docV2.details.appDetails.versionCode, 52791000);
  assert.equal(moduleOut.payload.deliveryResponse.appDeliveryData.downloadUrl, 'https://cdn.example/base.apk');
  assert.equal(moduleOut.payload.deliveryResponse.appDeliveryData.downloadAuthCookie.length, 2);
  assert.equal(moduleOut.payload.deliveryResponse.appDeliveryData.splitDeliveryData[0].name, 'config.en');
});
