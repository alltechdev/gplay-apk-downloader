// Unit test for the tiny protobuf decoder.
// Hand-encoded payloads round-trip the wire format we care about.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decode, STRING, INT32, INT64, NESTED, BOOL } from '../../src/modules/pb-decode.js';

function tag(fieldNo, wire) {
  return (fieldNo << 3) | wire;
}
function varint(n) {
  const out = [];
  let v = BigInt(n);
  while (v > 0x7fn) {
    out.push(Number(v & 0x7fn) | 0x80);
    v >>= 7n;
  }
  out.push(Number(v));
  return out;
}
function str(fieldNo, s) {
  const enc = new TextEncoder().encode(s);
  return [tag(fieldNo, 2), ...varint(enc.length), ...enc];
}
function vint(fieldNo, n) {
  return [tag(fieldNo, 0), ...varint(n)];
}
function nested(fieldNo, bytes) {
  return [tag(fieldNo, 2), ...varint(bytes.length), ...bytes];
}

test('decode: string + int32 field', () => {
  const buf = new Uint8Array([...str(1, 'hello'), ...vint(2, 42)]);
  const schema = { 1: { name: 'a', type: STRING }, 2: { name: 'b', type: INT32 } };
  assert.deepEqual(decode(buf, schema), { a: 'hello', b: 42 });
});

test('decode: skips unknown fields', () => {
  const buf = new Uint8Array([...str(99, 'ignored'), ...str(1, 'kept')]);
  const schema = { 1: { name: 'a', type: STRING } };
  assert.deepEqual(decode(buf, schema), { a: 'kept' });
});

test('decode: repeated string', () => {
  const buf = new Uint8Array([...str(1, 'a'), ...str(1, 'b'), ...str(1, 'c')]);
  const schema = { 1: { name: 'tags', type: STRING, repeated: true } };
  assert.deepEqual(decode(buf, schema), { tags: ['a', 'b', 'c'] });
});

test('decode: nested message', () => {
  const inner = [...str(1, 'inside'), ...vint(2, 7)];
  const buf = new Uint8Array(nested(3, inner));
  const innerSchema = { 1: { name: 'name', type: STRING }, 2: { name: 'n', type: INT32 } };
  const schema = { 3: { name: 'child', type: NESTED, schema: innerSchema } };
  assert.deepEqual(decode(buf, schema), { child: { name: 'inside', n: 7 } });
});

test('decode: int64 stays BigInt', () => {
  const buf = new Uint8Array(vint(1, '9876543210'));
  const schema = { 1: { name: 'big', type: INT64 } };
  const out = decode(buf, schema);
  assert.equal(typeof out.big, 'bigint');
  assert.equal(out.big, 9876543210n);
});

test('decode: bool', () => {
  const buf = new Uint8Array([...vint(1, 1), ...vint(2, 0)]);
  const schema = { 1: { name: 't', type: BOOL }, 2: { name: 'f', type: BOOL } };
  assert.deepEqual(decode(buf, schema), { t: true, f: false });
});
