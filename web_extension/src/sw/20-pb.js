// 20-pb.js — tiny protobuf decoder + Play API message schemas.
//
// Handles wire types 0 (varint), 1 (64-bit), 2 (length-delimited), 5
// (32-bit). Field numbers verified against gpapi's compiled descriptor
// and cross-checked with the Aurora Store proto.

const PB_STRING = 'string';
const PB_INT32  = 'int32';
const PB_INT64  = 'int64';
const PB_BOOL   = 'bool';
const PB_BYTES  = 'bytes';
const PB_NESTED = 'nested';

function pbReadVarint(buf, pos) {
  let result = 0n, shift = 0n, byte;
  for (;;) {
    if (pos >= buf.length) throw new ProtoError('pb: truncated varint');
    byte = buf[pos++];
    result |= BigInt(byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) break;
    shift += 7n;
    if (shift > 70n) throw new ProtoError('pb: varint too long');
  }
  return [result, pos];
}
function pbSkip(buf, pos, wire) {
  if (wire === 0) return pbReadVarint(buf, pos)[1];
  if (wire === 2) { const [len, p] = pbReadVarint(buf, pos); return p + Number(len); }
  if (wire === 1) return pos + 8;
  if (wire === 5) return pos + 4;
  throw new ProtoError('pb: unknown wire type ' + wire);
}
function pbDecode(buf, schema) {
  if (!(buf instanceof Uint8Array)) buf = new Uint8Array(buf);
  const out = {};
  let pos = 0;
  while (pos < buf.length) {
    const [tag, p1] = pbReadVarint(buf, pos);
    pos = p1;
    const fieldNo = Number(tag) >>> 3;
    const wire = Number(tag) & 7;
    const field = schema[fieldNo];
    if (!field) { pos = pbSkip(buf, pos, wire); continue; }
    let value;
    if (field.type === PB_STRING) {
      const [len, p2] = pbReadVarint(buf, pos);
      const L = Number(len);
      value = new TextDecoder('utf-8').decode(buf.subarray(p2, p2 + L));
      pos = p2 + L;
    } else if (field.type === PB_BYTES) {
      const [len, p2] = pbReadVarint(buf, pos);
      const L = Number(len);
      value = buf.subarray(p2, p2 + L);
      pos = p2 + L;
    } else if (field.type === PB_NESTED) {
      const [len, p2] = pbReadVarint(buf, pos);
      const L = Number(len);
      value = pbDecode(buf.subarray(p2, p2 + L), field.schema);
      pos = p2 + L;
    } else if (field.type === PB_INT32) {
      const [v, p2] = pbReadVarint(buf, pos);
      const n = Number(v & 0xffffffffn);
      value = (n & 0x80000000) ? n - 0x100000000 : n;
      pos = p2;
    } else if (field.type === PB_INT64) {
      const [v, p2] = pbReadVarint(buf, pos);
      value = v;
      pos = p2;
    } else if (field.type === PB_BOOL) {
      const [v, p2] = pbReadVarint(buf, pos);
      value = v !== 0n;
      pos = p2;
    } else {
      throw new ProtoError('pb: unsupported type ' + field.type);
    }
    if (field.repeated) (out[field.name] ||= []).push(value);
    else out[field.name] = value;
  }
  return out;
}

const PB_HttpCookie = {
  1: { name: 'name',  type: PB_STRING },
  2: { name: 'value', type: PB_STRING },
};
const PB_SplitDeliveryData = {
  1: { name: 'name',         type: PB_STRING },
  2: { name: 'downloadSize', type: PB_INT64 },
  5: { name: 'downloadUrl',  type: PB_STRING },
};
const PB_AndroidAppDeliveryData = {
  1:  { name: 'downloadSize',         type: PB_INT64 },
  2:  { name: 'sha1',                 type: PB_STRING },
  3:  { name: 'downloadUrl',          type: PB_STRING },
  5:  { name: 'downloadAuthCookie',   type: PB_NESTED, schema: PB_HttpCookie, repeated: true },
  15: { name: 'splitDeliveryData',    type: PB_NESTED, schema: PB_SplitDeliveryData, repeated: true },
};
const PB_DeliveryResponse = {
  1: { name: 'status',          type: PB_INT32 },
  2: { name: 'appDeliveryData', type: PB_NESTED, schema: PB_AndroidAppDeliveryData },
};
const PB_AppDetails = {
  1:  { name: 'developerName',    type: PB_STRING },
  3:  { name: 'versionCode',      type: PB_INT32 },
  4:  { name: 'versionString',    type: PB_STRING },
  9:  { name: 'installationSize', type: PB_INT64 },
  14: { name: 'packageName',      type: PB_STRING },
  16: { name: 'uploadDate',       type: PB_STRING },
  25: { name: 'splitId',          type: PB_STRING, repeated: true },
};
const PB_DocumentDetails = { 1: { name: 'appDetails', type: PB_NESTED, schema: PB_AppDetails } };
const PB_DocV2 = {
  1:  { name: 'docid',   type: PB_STRING },
  5:  { name: 'title',   type: PB_STRING },
  13: { name: 'details', type: PB_NESTED, schema: PB_DocumentDetails },
};
const PB_DetailsResponse = { 4: { name: 'docV2', type: PB_NESTED, schema: PB_DocV2 } };
const PB_Payload = {
  2:  { name: 'detailsResponse',  type: PB_NESTED, schema: PB_DetailsResponse },
  21: { name: 'deliveryResponse', type: PB_NESTED, schema: PB_DeliveryResponse },
};
const PB_ResponseWrapper = { 1: { name: 'payload', type: PB_NESTED, schema: PB_Payload } };
