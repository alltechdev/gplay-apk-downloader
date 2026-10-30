// axml-patcher.js — JS port of legacy axml_patcher.py.
//
// Patches a binary AndroidManifest.xml to add:
//   <meta-data android:name="com.android.dynamic.apk.fused.modules"
//              android:value="<asset_pack_names>"/>
// inside the <application> element. This is the same metadata the Play Core
// AssetPackManager looks for; without it, apps with fused asset packs
// detect missing splits at runtime.
//
// Pure binary manipulation, no deps.

const CHUNK_STRINGPOOL = 0x0001;
const CHUNK_RESOURCEIDS = 0x0180;
const CHUNK_START_ELEMENT = 0x0102;
const CHUNK_END_ELEMENT = 0x0103;
const RES_ANDROID_NAME = 0x01010003;
const RES_ANDROID_VALUE = 0x01010024;
const TYPE_STRING = 0x03;
const FUSED_MODULES_KEY = 'com.android.dynamic.apk.fused.modules';
const AXML_MAGIC = 0x00080003;

function readU16(buf, off) { return buf[off] | (buf[off + 1] << 8); }
function readU32(buf, off) {
  return ((buf[off]) | (buf[off + 1] << 8) | (buf[off + 2] << 16) | (buf[off + 3] << 24)) >>> 0;
}
function writeU16(buf, off, v) { buf[off] = v & 0xff; buf[off + 1] = (v >>> 8) & 0xff; }
function writeU32(buf, off, v) {
  buf[off] = v & 0xff; buf[off + 1] = (v >>> 8) & 0xff;
  buf[off + 2] = (v >>> 16) & 0xff; buf[off + 3] = (v >>> 24) & 0xff;
}

function appendU16(arr, v) { arr.push(v & 0xff, (v >>> 8) & 0xff); }
function appendU32(arr, v) { arr.push(v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff); }
function appendBytes(arr, bytes) { for (const b of bytes) arr.push(b); }

function parseStringPool(data, off) {
  const headerSize = readU16(data, off + 2);
  const chunkSize = readU32(data, off + 4);
  const stringCount = readU32(data, off + 8);
  const styleCount = readU32(data, off + 12);
  const flags = readU32(data, off + 16);
  const stringsStart = readU32(data, off + 20);
  const stylesStart = readU32(data, off + 24);
  const isUtf8 = !!(flags & (1 << 8));
  const offsetsBase = off + headerSize;
  const strOffsets = [];
  for (let i = 0; i < stringCount; i++) strOffsets.push(readU32(data, offsetsBase + i * 4));
  const absStrStart = off + stringsStart;
  const strings = [];
  for (let i = 0; i < stringCount; i++) {
    let pos = absStrStart + strOffsets[i];
    if (isUtf8) {
      // char length (1-2 bytes)
      if (data[pos] & 0x80) pos += 2;
      else pos += 1;
      // byte length
      let byteLen;
      if (data[pos] & 0x80) {
        byteLen = ((data[pos] & 0x7f) << 8) | data[pos + 1];
        pos += 2;
      } else {
        byteLen = data[pos];
        pos += 1;
      }
      strings.push(new TextDecoder('utf-8').decode(data.subarray(pos, pos + byteLen)));
    } else {
      const charLen = readU16(data, pos);
      pos += 2;
      strings.push(new TextDecoder('utf-16le').decode(data.subarray(pos, pos + charLen * 2)));
    }
  }
  return { offset: off, chunkSize, headerSize, stringCount, styleCount, flags, isUtf8, stringsStart, stylesStart, strings };
}

function encodeString(s, isUtf8) {
  const out = [];
  if (isUtf8) {
    const utf8 = new TextEncoder().encode(s);
    const charLen = s.length;
    const byteLen = utf8.length;
    if (charLen >= 0x80) { out.push((charLen >> 8) | 0x80, charLen & 0xff); } else { out.push(charLen); }
    if (byteLen >= 0x80) { out.push((byteLen >> 8) | 0x80, byteLen & 0xff); } else { out.push(byteLen); }
    for (const b of utf8) out.push(b);
    out.push(0);
  } else {
    out.push(s.length & 0xff, (s.length >>> 8) & 0xff);
    for (let i = 0; i < s.length; i++) {
      const c = s.charCodeAt(i);
      out.push(c & 0xff, (c >>> 8) & 0xff);
    }
    out.push(0, 0);
  }
  return out;
}

function buildStringPool(strings, styleCount, flags) {
  const isUtf8 = !!(flags & (1 << 8));
  const headerSize = 0x1C;
  const encoded = strings.map((s) => encodeString(s, isUtf8));
  const offsets = [];
  const stringData = [];
  for (const e of encoded) {
    appendU32(offsets, stringData.length);
    appendBytes(stringData, e);
  }
  const styleOffsets = [];
  const stringsStart = headerSize + offsets.length + styleOffsets.length;
  const chunk = [];
  appendU16(chunk, CHUNK_STRINGPOOL);
  appendU16(chunk, headerSize);
  appendU32(chunk, 0); // size placeholder
  appendU32(chunk, strings.length);
  appendU32(chunk, styleCount);
  appendU32(chunk, flags);
  appendU32(chunk, stringsStart);
  appendU32(chunk, 0); // stylesStart
  appendBytes(chunk, offsets);
  appendBytes(chunk, styleOffsets);
  appendBytes(chunk, stringData);
  while (chunk.length % 4) chunk.push(0);
  // patch size
  writeU32(chunk, 4, chunk.length);
  return chunk;
}

function buildStartElement(nameIdx, androidNsIdx, nameAttrIdx, valueAttrIdx, keyStrIdx, valStrIdx) {
  const attrCount = 2;
  const chunkSize = 36 + attrCount * 20;
  const chunk = [];
  appendU16(chunk, CHUNK_START_ELEMENT);
  appendU16(chunk, 0x10);
  appendU32(chunk, chunkSize);
  appendU32(chunk, 0);          // lineNumber
  appendU32(chunk, 0xffffffff); // comment
  appendU32(chunk, 0xffffffff); // namespace
  appendU32(chunk, nameIdx);
  appendU16(chunk, 0x14);
  appendU16(chunk, 0x14);
  appendU16(chunk, attrCount);
  appendU16(chunk, 0); appendU16(chunk, 0); appendU16(chunk, 0);
  // attr 1
  appendU32(chunk, androidNsIdx);
  appendU32(chunk, nameAttrIdx);
  appendU32(chunk, keyStrIdx);
  appendU16(chunk, 8);
  chunk.push(0);
  chunk.push(TYPE_STRING);
  appendU32(chunk, keyStrIdx);
  // attr 2
  appendU32(chunk, androidNsIdx);
  appendU32(chunk, valueAttrIdx);
  appendU32(chunk, valStrIdx);
  appendU16(chunk, 8);
  chunk.push(0);
  chunk.push(TYPE_STRING);
  appendU32(chunk, valStrIdx);
  return chunk;
}

function buildEndElement(nameIdx) {
  const chunk = [];
  appendU16(chunk, CHUNK_END_ELEMENT);
  appendU16(chunk, 0x10);
  appendU32(chunk, 24);
  appendU32(chunk, 0);
  appendU32(chunk, 0xffffffff);
  appendU32(chunk, 0xffffffff);
  appendU32(chunk, nameIdx);
  return chunk;
}

export function getAssetPackSplitNames(splitNames) {
  return (splitNames || []).filter((n) => n && !n.startsWith('config.'));
}

export function patchManifestFusedModules(manifestData, fusedValue) {
  const data = manifestData instanceof Uint8Array ? manifestData : new Uint8Array(manifestData);
  if (data.length < 8 || readU32(data, 0) !== AXML_MAGIC) return manifestData;

  const sp = parseStringPool(data, 8);
  const { strings } = sp;
  if (strings.includes(FUSED_MODULES_KEY)) return manifestData;

  const androidNsIdx = strings.indexOf('http://schemas.android.com/apk/res/android');
  const metaDataIdx = strings.indexOf('meta-data');
  const applicationIdx = strings.indexOf('application');
  if (androidNsIdx < 0 || metaDataIdx < 0 || applicationIdx < 0) return manifestData;

  const residStart = 8 + sp.chunkSize;
  if (residStart + 8 > data.length || readU16(data, residStart) !== CHUNK_RESOURCEIDS) return manifestData;
  const residHeader = readU16(data, residStart + 2);
  const residChunkSize = readU32(data, residStart + 4);
  const residCount = Math.floor((residChunkSize - residHeader) / 4);
  let nameAttrIdx = -1, valueAttrIdx = -1;
  for (let i = 0; i < residCount; i++) {
    const rid = readU32(data, residStart + residHeader + i * 4);
    if (rid === RES_ANDROID_NAME) nameAttrIdx = i;
    else if (rid === RES_ANDROID_VALUE) valueAttrIdx = i;
  }
  if (nameAttrIdx < 0 || valueAttrIdx < 0) return manifestData;

  const keyStrIdx = strings.length;
  const valStrIdx = strings.length + 1;
  const newStrings = strings.concat([FUSED_MODULES_KEY, fusedValue]);
  const newSp = buildStringPool(newStrings, sp.styleCount, sp.flags);
  const metaStart = buildStartElement(metaDataIdx, androidNsIdx, nameAttrIdx, valueAttrIdx, keyStrIdx, valStrIdx);
  const metaEnd = buildEndElement(metaDataIdx);

  const out = [];
  appendU32(out, AXML_MAGIC);
  appendU32(out, 0); // file size placeholder
  appendBytes(out, newSp);

  let pos = 8 + sp.chunkSize;
  let inserted = false;
  while (pos + 8 <= data.length) {
    const chunkType = readU16(data, pos);
    const chunkSize = readU32(data, pos + 4);
    if (chunkSize < 8 || pos + chunkSize > data.length) break;
    if (!inserted && chunkType === CHUNK_END_ELEMENT) {
      const elNameIdx = readU32(data, pos + 20);
      if (elNameIdx === applicationIdx) {
        appendBytes(out, metaStart);
        appendBytes(out, metaEnd);
        inserted = true;
      }
    }
    for (let i = 0; i < chunkSize; i++) out.push(data[pos + i]);
    pos += chunkSize;
  }

  // patch file size
  writeU32(out, 4, out.length);
  return new Uint8Array(out);
}
