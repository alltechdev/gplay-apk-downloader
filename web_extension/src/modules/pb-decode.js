// Minimal protobuf decoder. Handles exactly what the Play API responses use:
//   wire types 0 (varint / int32 / int64 / bool / enum)
//             2 (length-delimited: string / bytes / nested message)
//             1, 5 (skipped as raw bytes)
//
// Usage:
//   const root = decode(bytes, schema);
//   schema = { 1: { name: 'payload', type: NESTED, schema: payloadSchema },
//              5: { name: 'title',   type: STRING, repeated: false }, ... }
//
// Unknown field tags are skipped silently. Repeated fields accumulate into
// arrays. Missing optional fields are simply absent from the result object.

export const VARINT = 'varint';
export const INT32  = 'int32';
export const INT64  = 'int64';
export const BOOL   = 'bool';
export const STRING = 'string';
export const BYTES  = 'bytes';
export const NESTED = 'nested';

function readVarint(buf, pos) {
  let result = 0n, shift = 0n, byte;
  for (;;) {
    if (pos >= buf.length) throw new Error('pb: truncated varint');
    byte = buf[pos++];
    result |= BigInt(byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) break;
    shift += 7n;
    if (shift > 70n) throw new Error('pb: varint too long');
  }
  return [result, pos];
}

function skip(buf, pos, wire) {
  if (wire === 0) return readVarint(buf, pos)[1];
  if (wire === 2) {
    const [len, p] = readVarint(buf, pos);
    return p + Number(len);
  }
  if (wire === 1) return pos + 8;
  if (wire === 5) return pos + 4;
  throw new Error('pb: unknown wire type ' + wire);
}

function utf8Decode(buf, pos, len) {
  return new TextDecoder('utf-8').decode(buf.subarray(pos, pos + len));
}

export function decode(buf, schema) {
  if (!(buf instanceof Uint8Array)) buf = new Uint8Array(buf);
  const out = {};
  let pos = 0;
  while (pos < buf.length) {
    const [tag, p1] = readVarint(buf, pos);
    pos = p1;
    const tagN = Number(tag);
    const fieldNo = tagN >>> 3;
    const wire = tagN & 7;
    const field = schema[fieldNo];
    if (!field) { pos = skip(buf, pos, wire); continue; }
    let value;
    if (field.type === STRING) {
      const [len, p2] = readVarint(buf, pos);
      const L = Number(len);
      value = utf8Decode(buf, p2, L);
      pos = p2 + L;
    } else if (field.type === BYTES) {
      const [len, p2] = readVarint(buf, pos);
      const L = Number(len);
      value = buf.subarray(p2, p2 + L);
      pos = p2 + L;
    } else if (field.type === NESTED) {
      const [len, p2] = readVarint(buf, pos);
      const L = Number(len);
      value = decode(buf.subarray(p2, p2 + L), field.schema);
      pos = p2 + L;
    } else if (field.type === INT32 || field.type === VARINT) {
      const [v, p2] = readVarint(buf, pos);
      // Two's complement for negative int32.
      const n = Number(v & 0xffffffffn);
      value = (n & 0x80000000) ? n - 0x100000000 : n;
      pos = p2;
    } else if (field.type === INT64) {
      const [v, p2] = readVarint(buf, pos);
      value = v; // BigInt — caller can convert if it fits in Number.
      pos = p2;
    } else if (field.type === BOOL) {
      const [v, p2] = readVarint(buf, pos);
      value = v !== 0n;
      pos = p2;
    } else {
      throw new Error('pb: unsupported field type ' + field.type);
    }
    if (field.repeated) {
      (out[field.name] ||= []).push(value);
    } else {
      out[field.name] = value;
    }
  }
  return out;
}
