// apk-signer.js — APK Signature Scheme v1 (JAR) + v2 + v3, pure JS.
//
// Mirrors the legacy `apksigner` default behaviour (which signs with all
// three by default) using Web Crypto for the actual SHA-256 + RSA work.
//
// References:
//   v1: https://docs.oracle.com/javase/8/docs/technotes/guides/jar/jar.html#Signed_JAR_File
//   v2: https://source.android.com/docs/security/features/apksigning/v2
//   v3: https://source.android.com/docs/security/features/apksigning/v3

import * as fflate from 'fflate';

// =========================================================================
//  Constants
// =========================================================================

const CHUNK_SIZE = 1024 * 1024;
const SIG_ALG_RSA_PKCS1_V1_5_SHA256 = 0x00000103;
const APK_SIG_V2_BLOCK_ID = 0x7109871a;
const APK_SIG_V3_BLOCK_ID = 0xf05368c0;
const MAGIC = new TextEncoder().encode('APK Sig Block 42'); // 16 bytes
const V3_ATTR_ID_MIN_MAX_SDK = 0x559f8b02; // ProofOfRotationStruct min/max SDK attr

// =========================================================================
//  Tiny byte helpers
// =========================================================================

function readU32LE(buf, off) {
  return (buf[off]) | (buf[off + 1] << 8) | (buf[off + 2] << 16) | ((buf[off + 3] << 24) >>> 0);
}
function writeU32LE(buf, off, v) {
  buf[off] = v & 0xff;
  buf[off + 1] = (v >>> 8) & 0xff;
  buf[off + 2] = (v >>> 16) & 0xff;
  buf[off + 3] = (v >>> 24) & 0xff;
}
function writeU64LE(buf, off, v) {
  const lo = Number(BigInt(v) & 0xffffffffn);
  const hi = Number((BigInt(v) >> 32n) & 0xffffffffn);
  writeU32LE(buf, off, lo);
  writeU32LE(buf, off + 4, hi);
}
function concat(parts) {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}
function lp32(bytes) {
  const out = new Uint8Array(4 + bytes.length);
  writeU32LE(out, 0, bytes.length);
  out.set(bytes, 4);
  return out;
}

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

function base64Encode(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

// =========================================================================
//  Minimal ASN.1 DER builder & parser
// =========================================================================

function derLen(n) {
  if (n < 0x80) return Uint8Array.of(n);
  const bytes = [];
  while (n > 0) { bytes.unshift(n & 0xff); n >>>= 8; }
  return Uint8Array.of(0x80 | bytes.length, ...bytes);
}
function derTLV(tag, value) {
  const len = derLen(value.length);
  const out = new Uint8Array(1 + len.length + value.length);
  out[0] = tag;
  out.set(len, 1);
  out.set(value, 1 + len.length);
  return out;
}
function derSeq(parts)  { return derTLV(0x30, concat(parts)); }
function derSet(parts)  { return derTLV(0x31, concat(parts)); }
function derCtxC0(value){ return derTLV(0xa0, value); }
function derOctet(bytes){ return derTLV(0x04, bytes); }
function derNull()      { return derTLV(0x05, new Uint8Array(0)); }
function derOid(parts) {
  // parts: array of integers
  const body = [];
  body.push(parts[0] * 40 + parts[1]);
  for (let i = 2; i < parts.length; i++) {
    const v = parts[i];
    if (v === 0) { body.push(0); continue; }
    const stack = [];
    let x = v;
    while (x > 0) { stack.unshift(x & 0x7f); x >>>= 7; }
    for (let j = 0; j < stack.length - 1; j++) stack[j] |= 0x80;
    for (const b of stack) body.push(b);
  }
  return derTLV(0x06, new Uint8Array(body));
}
function derInteger(bytes) {
  // Pad with 0x00 if high bit set (to keep value positive).
  if (bytes.length > 0 && (bytes[0] & 0x80)) {
    const v = new Uint8Array(bytes.length + 1);
    v.set(bytes, 1);
    return derTLV(0x02, v);
  }
  return derTLV(0x02, bytes);
}

// ASN.1 parser: just enough to navigate a Certificate.
function parseTLV(buf, off) {
  const tag = buf[off];
  let pos = off + 1;
  let len = buf[pos++];
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | buf[pos++];
  }
  return { tag, headerLen: pos - off, valueStart: pos, valueLen: len, totalLen: (pos - off) + len };
}

// Extract issuer Name (raw DER) and serial number (raw DER INTEGER) from a cert.
function parseCertIssuerAndSerial(certDer) {
  // Certificate := SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
  const certSeq = parseTLV(certDer, 0);
  if (certSeq.tag !== 0x30) throw new Error('not a SEQUENCE at cert root');
  const tbsStart = certSeq.valueStart;
  const tbsSeq = parseTLV(certDer, tbsStart);
  if (tbsSeq.tag !== 0x30) throw new Error('not a SEQUENCE at tbsCertificate');
  // Inside tbsCertificate:
  //   [0] version (optional, EXPLICIT), serialNumber, signature, issuer, ...
  let pos = tbsSeq.valueStart;
  const end = tbsSeq.valueStart + tbsSeq.valueLen;
  let first = parseTLV(certDer, pos);
  if (first.tag === 0xa0) {
    // skip [0] version
    pos += first.totalLen;
    first = parseTLV(certDer, pos);
  }
  // serialNumber
  if (first.tag !== 0x02) throw new Error('expected INTEGER serial');
  const serialDer = certDer.subarray(pos, pos + first.totalLen);
  pos += first.totalLen;
  // signature AlgorithmIdentifier (skip)
  const algo = parseTLV(certDer, pos);
  pos += algo.totalLen;
  // issuer
  const issuer = parseTLV(certDer, pos);
  if (issuer.tag !== 0x30) throw new Error('expected SEQUENCE issuer');
  const issuerDer = certDer.subarray(pos, pos + issuer.totalLen);
  if (end < pos + issuer.totalLen) throw new Error('cert too short');
  return { serial: serialDer, issuer: issuerDer };
}

// =========================================================================
//  PKCS#7 SignedData (no signed-attrs flavour) for CERT.RSA
// =========================================================================

const OID_PKCS7_SIGNED_DATA  = [1, 2, 840, 113549, 1, 7, 2];
const OID_PKCS7_DATA         = [1, 2, 840, 113549, 1, 7, 1];
const OID_SHA256             = [2, 16, 840, 1, 101, 3, 4, 2, 1];
const OID_RSA_ENCRYPTION     = [1, 2, 840, 113549, 1, 1, 1];

function algoIdSha256()  { return derSeq([derOid(OID_SHA256), derNull()]); }
function algoIdRsaEnc()  { return derSeq([derOid(OID_RSA_ENCRYPTION), derNull()]); }

function buildPkcs7(certDer, signatureBytes) {
  const { issuer, serial } = parseCertIssuerAndSerial(certDer);

  // SignerInfo
  const signerInfo = derSeq([
    derInteger(Uint8Array.of(1)),     // version
    derSeq([issuer, serial]),         // sid: IssuerAndSerialNumber
    algoIdSha256(),                   // digestAlgorithm
    algoIdRsaEnc(),                   // digestEncryptionAlgorithm (signatureAlgorithm)
    derOctet(signatureBytes),         // encryptedDigest (signature)
  ]);

  const certsField = derTLV(0xa0, certDer); // [0] IMPLICIT certificates

  const signedData = derSeq([
    derInteger(Uint8Array.of(1)),     // version
    derSet([algoIdSha256()]),         // digestAlgorithms
    derSeq([derOid(OID_PKCS7_DATA)]), // encapContentInfo: { contentType=data, content omitted }
    certsField,
    derSet([signerInfo]),
  ]);

  return derSeq([
    derOid(OID_PKCS7_SIGNED_DATA),
    derCtxC0(signedData),
  ]);
}

// =========================================================================
//  v1 (JAR) signing
// =========================================================================

const CRLF = new Uint8Array([0x0d, 0x0a]);
const CRLF_CRLF = new Uint8Array([0x0d, 0x0a, 0x0d, 0x0a]);

function textBytes(s) { return new TextEncoder().encode(s); }

// Wrap a Manifest line to 70-byte width per JAR spec (continuation lines
// start with a single space).
function manifestLine(name, value) {
  const raw = name + ': ' + value;
  // Most digests + names stay under 70; if longer, we wrap.
  const bytes = textBytes(raw);
  if (bytes.length <= 70) return concat([bytes, CRLF]);
  const out = [];
  let first = true;
  for (let i = 0; i < bytes.length; i += 70) {
    const chunk = bytes.subarray(i, Math.min(i + 70, bytes.length));
    if (!first) out.push(Uint8Array.of(0x20)); // single space
    out.push(chunk, CRLF);
    first = false;
  }
  return concat(out);
}

async function v1Sign(zipBytes, pkcs8KeyDer, certDer) {
  // Decode the (post-merge) APK so we can read each entry's bytes.
  const entries = fflate.unzipSync(zipBytes);

  // Compute SHA-256 of every entry except META-INF/* signature files
  // (none should exist post-merge, but stay defensive).
  const names = Object.keys(entries).filter((n) => !/^META-INF\//.test(n) || (!n.endsWith('.SF') && !n.endsWith('.RSA') && !n.endsWith('.DSA') && !n.endsWith('.EC') && n !== 'META-INF/MANIFEST.MF'));
  const digests = {};
  for (const name of names) {
    digests[name] = base64Encode(await sha256(entries[name]));
  }

  // Build MANIFEST.MF
  const manifestParts = [];
  manifestParts.push(manifestLine('Manifest-Version', '1.0'));
  manifestParts.push(manifestLine('Created-By', '1.0 (Android gplaydl)'));
  manifestParts.push(CRLF); // blank line ends main section
  // Per-entry sections
  const perEntryMfSections = {}; // name -> bytes of this section, for CERT.SF digest computation
  for (const name of names) {
    const section = concat([
      manifestLine('Name', name),
      manifestLine('SHA-256-Digest', digests[name]),
      CRLF, // blank line ends section
    ]);
    perEntryMfSections[name] = section;
    manifestParts.push(section);
  }
  const manifestBytes = concat(manifestParts);

  // Build CERT.SF
  const mainSectionEnd = (() => {
    // The main section ends at the first \r\n\r\n.
    for (let i = 0; i + 3 < manifestBytes.length; i++) {
      if (manifestBytes[i] === 0x0d && manifestBytes[i + 1] === 0x0a && manifestBytes[i + 2] === 0x0d && manifestBytes[i + 3] === 0x0a) {
        return i + 4;
      }
    }
    return manifestBytes.length;
  })();
  const mainAttrsDigest = base64Encode(await sha256(manifestBytes.subarray(0, mainSectionEnd)));
  const manifestDigest = base64Encode(await sha256(manifestBytes));

  const sfParts = [];
  sfParts.push(manifestLine('Signature-Version', '1.0'));
  sfParts.push(manifestLine('Created-By', '1.0 (Android gplaydl)'));
  sfParts.push(manifestLine('SHA-256-Digest-Manifest-Main-Attributes', mainAttrsDigest));
  sfParts.push(manifestLine('SHA-256-Digest-Manifest', manifestDigest));
  sfParts.push(manifestLine('X-Android-APK-Signed', '2, 3'));
  sfParts.push(CRLF);
  for (const name of names) {
    const sectionDigest = base64Encode(await sha256(perEntryMfSections[name]));
    sfParts.push(concat([
      manifestLine('Name', name),
      manifestLine('SHA-256-Digest', sectionDigest),
      CRLF,
    ]));
  }
  const sfBytes = concat(sfParts);

  // Sign CERT.SF
  const signingKey = await crypto.subtle.importKey(
    'pkcs8', pkcs8KeyDer, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
  const sigBuf = await crypto.subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, signingKey, sfBytes);
  const sigBytes = new Uint8Array(sigBuf);

  const certRsa = buildPkcs7(certDer, sigBytes);

  // Add the three META-INF files. Insert AT THE TOP (apksigner's order).
  const newEntries = {
    'META-INF/MANIFEST.MF': manifestBytes,
    'META-INF/CERT.SF': sfBytes,
    'META-INF/CERT.RSA': certRsa,
    ...entries,
  };
  return fflate.zipSync(newEntries, { level: 0 });
}

// =========================================================================
//  Common helpers for v2/v3 (chunk-digest, EOCD lookup, signing-block assembly)
// =========================================================================

function findEocd(apk) {
  const sig = 0x06054b50;
  const min = Math.max(0, apk.length - 65557);
  for (let i = apk.length - 22; i >= min; i--) {
    if (readU32LE(apk, i) === sig) return i;
  }
  throw new Error('EOCD not found');
}
function readEocd(apk, eocdOff) {
  return {
    cdSize: readU32LE(apk, eocdOff + 12),
    cdOffset: readU32LE(apk, eocdOff + 16),
    eocdSize: apk.length - eocdOff,
  };
}

async function computeApkDigest(apk, cdOffset, cdSize, patchedEocd) {
  const chunkDigests = [];
  // Section 1: ZIP entries [0, cdOffset)
  // Section 2: Central Directory [cdOffset, cdOffset+cdSize)
  for (const [start, end] of [[0, cdOffset], [cdOffset, cdOffset + cdSize]]) {
    for (let off = start; off < end; off += CHUNK_SIZE) {
      const limit = Math.min(off + CHUNK_SIZE, end);
      const chunkLen = limit - off;
      const buf = new Uint8Array(1 + 4 + chunkLen);
      buf[0] = 0xa5;
      writeU32LE(buf, 1, chunkLen);
      buf.set(apk.subarray(off, limit), 5);
      chunkDigests.push(await sha256(buf));
    }
  }
  // Section 3: EOCD with patched CD offset
  for (let off = 0; off < patchedEocd.length; off += CHUNK_SIZE) {
    const limit = Math.min(off + CHUNK_SIZE, patchedEocd.length);
    const chunkLen = limit - off;
    const buf = new Uint8Array(1 + 4 + chunkLen);
    buf[0] = 0xa5;
    writeU32LE(buf, 1, chunkLen);
    buf.set(patchedEocd.subarray(off, limit), 5);
    chunkDigests.push(await sha256(buf));
  }
  const root = new Uint8Array(1 + 4 + chunkDigests.length * 32);
  root[0] = 0x5a;
  writeU32LE(root, 1, chunkDigests.length);
  let off = 5;
  for (const d of chunkDigests) { root.set(d, off); off += 32; }
  return sha256(root);
}

async function importSigningKey(pkcs8) {
  return crypto.subtle.importKey('pkcs8', pkcs8, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
}
async function extractSpki(pkcs8) {
  const priv = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, true, ['sign']);
  const jwk = await crypto.subtle.exportKey('jwk', priv);
  const pub = await crypto.subtle.importKey('jwk',
    { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: jwk.alg, ext: true, key_ops: ['verify'] },
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, true, ['verify']);
  return new Uint8Array(await crypto.subtle.exportKey('spki', pub));
}

// ----- v2 SignedData / SignerInfo --------------------------------------

function v2DigestsField(d) {
  const inner = new Uint8Array(8 + d.length);
  writeU32LE(inner, 0, SIG_ALG_RSA_PKCS1_V1_5_SHA256);
  writeU32LE(inner, 4, d.length);
  inner.set(d, 8);
  return lp32(inner);
}
function certsField(certDer) { return lp32(lp32(certDer)); }
function emptyAttrs() { return lp32(new Uint8Array(0)); }
function v2SignedData(digestsField, cf, attrs) { return concat([digestsField, cf, attrs]); }
function sigField(sig) {
  const inner = new Uint8Array(8 + sig.length);
  writeU32LE(inner, 0, SIG_ALG_RSA_PKCS1_V1_5_SHA256);
  writeU32LE(inner, 4, sig.length);
  inner.set(sig, 8);
  return lp32(inner);
}
function signer(signedData, signatures, spki) {
  return lp32(concat([lp32(signedData), signatures, lp32(spki)]));
}
function signers(signer) { return lp32(signer); }

// ----- v3 SignerInfo (adds min/max SDK + attributes block) -------------

function v3MinMaxAttrs(minSdk = 28, maxSdk = 0x7fffffff) {
  // attributes: sequence of length-prefixed (id + value)
  const attrValue = new Uint8Array(4); // 4 bytes for ?
  writeU32LE(attrValue, 0, 0);
  // Actually for min/max SDK we use the dedicated bytes-in-attribute form.
  // Spec: id 0x559f8b02, value: (uint32 minSDK | uint32 maxSDK)
  // Wait — the attribute ID schema differs. For v3 SignerInfo we add the
  // proofOfRotation attribute (0x3ba06f8c) and an attributes list. We're
  // not rotating, so attributes can be empty. Min/max SDK live OUTSIDE
  // signedData in the v3 SignerInfo (see spec table). Return empty.
  return emptyAttrs();
}

function v3SignerInfo(digestsField, cf, attrs, sigsField, spki, minSdk, maxSdk) {
  // v3 signed-data is the same as v2's signed-data (digests + certs + attrs).
  const signedData = v2SignedData(digestsField, cf, attrs);
  // v3 signer = lp(signed-data) + minSdk + maxSdk + signatures + lp(spki)
  const inner = new Uint8Array(
    4 + signedData.length + 4 + 4 + sigsField.length + 4 + spki.length,
  );
  let off = 0;
  writeU32LE(inner, off, signedData.length); off += 4;
  inner.set(signedData, off); off += signedData.length;
  writeU32LE(inner, off, minSdk); off += 4;
  writeU32LE(inner, off, maxSdk); off += 4;
  inner.set(sigsField, off); off += sigsField.length;
  writeU32LE(inner, off, spki.length); off += 4;
  inner.set(spki, off);
  return lp32(inner);
}

// ----- Pack signing block from one or more (id, payload) pairs ---------

function packSigningBlock(pairs) {
  // pair: { id: u32, payload: Uint8Array }
  let pairsLen = 0;
  for (const p of pairs) pairsLen += 8 + 4 + p.payload.length;
  const sizeOfBlockField = pairsLen + 8 /* trailing size */ + 16 /* magic */;
  const totalLen = 8 + sizeOfBlockField;
  const out = new Uint8Array(totalLen);
  writeU64LE(out, 0, sizeOfBlockField);
  let off = 8;
  for (const p of pairs) {
    writeU64LE(out, off, 4 + p.payload.length);
    off += 8;
    writeU32LE(out, off, p.id);
    off += 4;
    out.set(p.payload, off);
    off += p.payload.length;
  }
  writeU64LE(out, off, sizeOfBlockField);
  off += 8;
  out.set(MAGIC, off);
  return out;
}

// =========================================================================
//  Top-level signApk()
// =========================================================================

export async function signApk(apk, pkcs8KeyDer, certDer, opts = { v1: true, v2: true, v3: true }) {
  apk = apk instanceof Uint8Array ? apk : new Uint8Array(apk);
  // v1 first: it mutates the ZIP (adds META-INF files).
  if (opts.v1) {
    apk = await v1Sign(apk, pkcs8KeyDer, certDer);
  }
  if (!opts.v2 && !opts.v3) return apk;

  // For v2/v3, compute payloads with placeholder digest+signature first
  // to size the signing block, then re-compute with the real digest.
  const spki = await extractSpki(pkcs8KeyDer);
  const cf = certsField(certDer);

  function buildV2Payload(digestBytes, sigBytes) {
    const df = v2DigestsField(digestBytes);
    const sd = v2SignedData(df, cf, emptyAttrs());
    const sigs = sigField(sigBytes);
    return signers(signer(sd, sigs, spki));
  }
  function buildV3Payload(digestBytes, sigBytes) {
    const df = v2DigestsField(digestBytes);
    const sigs = sigField(sigBytes);
    return signers(v3SignerInfo(df, cf, emptyAttrs(), sigs, spki, 28, 0x7fffffff));
  }

  // Sizing pass.
  const tentativeDigest = new Uint8Array(32);
  const tentativeSig = new Uint8Array(256); // RSA-2048
  const pairs = [];
  if (opts.v2) pairs.push({ id: APK_SIG_V2_BLOCK_ID, payload: buildV2Payload(tentativeDigest, tentativeSig) });
  if (opts.v3) pairs.push({ id: APK_SIG_V3_BLOCK_ID, payload: buildV3Payload(tentativeDigest, tentativeSig) });
  const tentativeBlock = packSigningBlock(pairs);
  const signingBlockSize = tentativeBlock.length;

  // Compute the real digest with the CD-offset patched EOCD.
  const eocdOff = findEocd(apk);
  const { cdSize, cdOffset, eocdSize } = readEocd(apk, eocdOff);
  if (cdOffset + cdSize > eocdOff) throw new Error('malformed APK: CD past EOCD');
  const patchedEocd = new Uint8Array(eocdSize);
  patchedEocd.set(apk.subarray(eocdOff, eocdOff + eocdSize));
  writeU32LE(patchedEocd, 16, cdOffset + signingBlockSize);
  const realDigest = await computeApkDigest(apk, cdOffset, cdSize, patchedEocd);

  // Sign signedData for v2 (same signedData also drives v3 here).
  const signingKey = await importSigningKey(pkcs8KeyDer);
  const signedDataBytes = v2SignedData(v2DigestsField(realDigest), cf, emptyAttrs());
  const sigBuf = await crypto.subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, signingKey, signedDataBytes);
  const realSig = new Uint8Array(sigBuf);
  if (realSig.length !== 256) throw new Error('expected 256-byte RSA-2048 signature, got ' + realSig.length);

  const realPairs = [];
  if (opts.v2) realPairs.push({ id: APK_SIG_V2_BLOCK_ID, payload: buildV2Payload(realDigest, realSig) });
  if (opts.v3) realPairs.push({ id: APK_SIG_V3_BLOCK_ID, payload: buildV3Payload(realDigest, realSig) });
  const realBlock = packSigningBlock(realPairs);
  if (realBlock.length !== signingBlockSize) {
    throw new Error('signing block size mismatch (tentative vs real); padding/alignment bug');
  }

  const finalLen = cdOffset + realBlock.length + cdSize + eocdSize;
  const out = new Uint8Array(finalLen);
  out.set(apk.subarray(0, cdOffset), 0);
  out.set(realBlock, cdOffset);
  out.set(apk.subarray(cdOffset, cdOffset + cdSize), cdOffset + realBlock.length);
  out.set(patchedEocd, cdOffset + realBlock.length + cdSize);
  return out;
}

// Back-compat alias for the older signApkV2 name used in unit tests.
export async function signApkV2(apk, pkcs8KeyDer, certDer) {
  return signApk(apk, pkcs8KeyDer, certDer, { v1: false, v2: true, v3: false });
}
