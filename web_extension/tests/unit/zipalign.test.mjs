// Unit tests for src/modules/zipalign.js
// Asserts every uncompressed entry's file data starts at a multiple of 4,
// and entries under lib/*/*.so at a multiple of 4096.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fflate from 'fflate';
import { writeAlignedZip } from '../../src/modules/zipalign.js';

function readU16LE(buf, off) { return buf[off] | (buf[off + 1] << 8); }
function readU32LE(buf, off) {
  return ((buf[off]) | (buf[off + 1] << 8) | (buf[off + 2] << 16) | ((buf[off + 3] << 24) >>> 0)) >>> 0;
}

// Walk LFHs and check file-data alignment.
function checkAlignment(zipBytes) {
  let pos = 0;
  const results = [];
  while (pos < zipBytes.length) {
    const sig = readU32LE(zipBytes, pos);
    if (sig !== 0x04034b50) break;
    const compMethod = readU16LE(zipBytes, pos + 8);
    const compressedSize = readU32LE(zipBytes, pos + 18);
    const nameLen = readU16LE(zipBytes, pos + 26);
    const extraLen = readU16LE(zipBytes, pos + 28);
    const name = new TextDecoder().decode(zipBytes.subarray(pos + 30, pos + 30 + nameLen));
    const dataOff = pos + 30 + nameLen + extraLen;
    const expected = name.startsWith('lib/') && name.endsWith('.so') ? 4096 : 4;
    results.push({ name, dataOff, compMethod, expected, aligned: (dataOff % expected) === 0 });
    pos = dataOff + compressedSize;
  }
  return results;
}

test('writeAlignedZip: every entry data-aligned to 4 bytes', () => {
  const entries = {
    'AndroidManifest.xml': new TextEncoder().encode('<?xml?>'),
    'classes.dex': new Uint8Array(513),         // odd size to force misalignment
    'resources.arsc': new Uint8Array(1027),
    'META-INF/CERT.SF': new TextEncoder().encode('sf'),
  };
  const zip = writeAlignedZip(entries);
  for (const r of checkAlignment(zip)) {
    assert.ok(r.aligned, `entry "${r.name}" misaligned: dataOff=${r.dataOff} (mod ${r.expected} = ${r.dataOff % r.expected})`);
  }
});

test('writeAlignedZip: lib/*/*.so aligned to 4096', () => {
  const entries = {
    'AndroidManifest.xml': new Uint8Array(7),
    'lib/arm64-v8a/libnative.so': new Uint8Array(1000),
    'lib/armeabi-v7a/libnative.so': new Uint8Array(1500),
    'classes.dex': new Uint8Array(100),
  };
  const zip = writeAlignedZip(entries);
  const results = checkAlignment(zip);
  const sos = results.filter((r) => r.name.endsWith('.so'));
  assert.equal(sos.length, 2);
  for (const r of sos) {
    assert.equal(r.dataOff % 4096, 0, `${r.name} not 4096-aligned: dataOff=${r.dataOff}`);
  }
});

test('writeAlignedZip: round-trip parses back via fflate', () => {
  const entries = {
    'a.txt': new TextEncoder().encode('hello'),
    'b.bin': new Uint8Array([1, 2, 3, 4, 5]),
    'lib/arm64-v8a/foo.so': new Uint8Array(100),
  };
  const zip = writeAlignedZip(entries);
  const parsed = fflate.unzipSync(zip);
  assert.equal(new TextDecoder().decode(parsed['a.txt']), 'hello');
  assert.deepEqual(Array.from(parsed['b.bin']), [1, 2, 3, 4, 5]);
  assert.equal(parsed['lib/arm64-v8a/foo.so'].length, 100);
});
