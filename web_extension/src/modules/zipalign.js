// zipalign.js — pure-JS port of Android's `zipalign -p 4`.
//
// Writes a STORE-only ZIP where each uncompressed entry's file data starts
// at an offset that's a multiple of `alignment` (default 4). For native
// shared libraries under `lib/*/*.so`, the alignment is bumped to 4096 to
// match `zipalign -p 4` page-alignment behaviour, so `mmap` can map them
// directly out of the APK on Android.
//
// Padding is placed in the local-file-header's "extra field". When there's
// at least 6 bytes of padding available, a real Android-alignment extra
// (id 0xd935) is emitted so other tooling sees the alignment as intentional;
// otherwise raw zero bytes are used (still valid per the ZIP spec).

const SIG_LFH = 0x04034b50;
const SIG_CD  = 0x02014b50;
const SIG_EOCD = 0x06054b50;
const ALIGN_EXTRA_ID = 0xd935;
const DEFAULT_ALIGN = 4;
const SO_ALIGN = 4096;

function writeU16LE(buf, off, v) {
  buf[off]     = v & 0xff;
  buf[off + 1] = (v >>> 8) & 0xff;
}
function writeU32LE(buf, off, v) {
  buf[off]     = v & 0xff;
  buf[off + 1] = (v >>> 8) & 0xff;
  buf[off + 2] = (v >>> 16) & 0xff;
  buf[off + 3] = (v >>> 24) & 0xff;
}

const CRC32_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    t[i] = c >>> 0;
  }
  return t;
})();
function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC32_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function alignFor(name) {
  if (name.startsWith('lib/') && name.endsWith('.so')) return SO_ALIGN;
  return DEFAULT_ALIGN;
}

// entries: { [path]: Uint8Array }, in iteration order.
// Returns the assembled ZIP as a Uint8Array.
export function writeAlignedZip(entries) {
  const parts = [];           // [LFH+extra+data, ...]
  const cdParts = [];         // [CD entry bytes, ...]
  let offset = 0;

  for (const name of Object.keys(entries)) {
    const data = entries[name];
    const nameBytes = new TextEncoder().encode(name);
    const align = alignFor(name);
    const headerBase = 30 + nameBytes.length;
    const dataOffsetWithoutExtra = offset + headerBase;
    const padLen = (align - (dataOffsetWithoutExtra % align)) % align;

    const extra = new Uint8Array(padLen);
    if (padLen >= 6) {
      writeU16LE(extra, 0, ALIGN_EXTRA_ID);
      writeU16LE(extra, 2, padLen - 4);
      writeU16LE(extra, 4, align);
      // bytes 6..padLen-1 are already zero
    }

    const crc = crc32(data);
    const size = data.length;

    const lfh = new Uint8Array(headerBase + padLen);
    writeU32LE(lfh, 0, SIG_LFH);
    writeU16LE(lfh, 4, 20);          // version needed
    writeU16LE(lfh, 6, 0);           // flags
    writeU16LE(lfh, 8, 0);           // method = store
    writeU16LE(lfh, 10, 0);          // mod time
    writeU16LE(lfh, 12, 0x21);       // mod date (1980-01-01)
    writeU32LE(lfh, 14, crc);
    writeU32LE(lfh, 18, size);       // compressed size = uncompressed (store)
    writeU32LE(lfh, 22, size);
    writeU16LE(lfh, 26, nameBytes.length);
    writeU16LE(lfh, 28, padLen);
    lfh.set(nameBytes, 30);
    lfh.set(extra, 30 + nameBytes.length);

    parts.push(lfh);
    parts.push(data);

    const cd = new Uint8Array(46 + nameBytes.length);
    writeU32LE(cd, 0, SIG_CD);
    writeU16LE(cd, 4, 20);            // version made by (zip 2.0)
    writeU16LE(cd, 6, 20);            // version needed
    writeU16LE(cd, 8, 0);
    writeU16LE(cd, 10, 0);            // method = store
    writeU16LE(cd, 12, 0);
    writeU16LE(cd, 14, 0x21);
    writeU32LE(cd, 16, crc);
    writeU32LE(cd, 20, size);
    writeU32LE(cd, 24, size);
    writeU16LE(cd, 28, nameBytes.length);
    writeU16LE(cd, 30, 0);            // extra len in CD = 0
    writeU16LE(cd, 32, 0);            // comment len = 0
    writeU16LE(cd, 34, 0);            // disk number
    writeU16LE(cd, 36, 0);            // internal attrs
    writeU32LE(cd, 38, 0);            // external attrs
    writeU32LE(cd, 42, offset);       // offset of corresponding LFH
    cd.set(nameBytes, 46);
    cdParts.push(cd);

    offset += lfh.length + data.length;
  }

  const cdStart = offset;
  let cdSize = 0;
  for (const c of cdParts) cdSize += c.length;

  const eocd = new Uint8Array(22);
  writeU32LE(eocd, 0, SIG_EOCD);
  writeU16LE(eocd, 4, 0);
  writeU16LE(eocd, 6, 0);
  writeU16LE(eocd, 8, cdParts.length);
  writeU16LE(eocd, 10, cdParts.length);
  writeU32LE(eocd, 12, cdSize);
  writeU32LE(eocd, 16, cdStart);
  writeU16LE(eocd, 20, 0);

  const total = cdStart + cdSize + 22;
  const out = new Uint8Array(total);
  let p = 0;
  for (const x of parts)   { out.set(x, p); p += x.length; }
  for (const c of cdParts) { out.set(c, p); p += c.length; }
  out.set(eocd, p);
  return out;
}
