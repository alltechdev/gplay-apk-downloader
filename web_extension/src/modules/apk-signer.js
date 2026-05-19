// apk-signer.js — APK Signature Scheme v1 (JAR) + v2 + v3, pure JS.
//
// Mirrors the legacy `apksigner` default behaviour using Web Crypto for
// SHA-256 + RSA-2048. ASN.1 helpers live in `./asn1.js`; the PKCS#7
// `CERT.RSA` builder lives in `./pkcs7.js`.
//
// References:
//   v1: https://docs.oracle.com/javase/8/docs/technotes/guides/jar/jar.html#Signed_JAR_File
//   v2: https://source.android.com/docs/security/features/apksigning/v2
//   v3: https://source.android.com/docs/security/features/apksigning/v3

import * as fflate from 'fflate';
import { concat } from './asn1.js';
import { buildPkcs7 } from './pkcs7.js';

// =========================================================================
//  Constants
// =========================================================================

const CHUNK_SIZE = 1024 * 1024;
const SIG_ALG_RSA_PKCS1_V1_5_SHA256 = 0x00000103;
const APK_SIG_V2_BLOCK_ID = 0x7109871a;
const APK_SIG_V3_BLOCK_ID = 0xf05368c0;
const MAGIC = new TextEncoder().encode('APK Sig Block 42'); // 16 bytes
const V3_DEFAULT_MIN_SDK = 28;
const V3_DEFAULT_MAX_SDK = 0x7fffffff;
const RSA_2048_SIG_LEN = 256;

// =========================================================================
//  Byte / crypto helpers
// =========================================================================

const readU32LE = (b, o) => ((b[o]) | (b[o+1] << 8) | (b[o+2] << 16) | ((b[o+3] << 24) >>> 0)) >>> 0;
const writeU32LE = (b, o, v) => { b[o] = v & 0xff; b[o+1] = (v >>> 8) & 0xff; b[o+2] = (v >>> 16) & 0xff; b[o+3] = (v >>> 24) & 0xff; };
const writeU64LE = (b, o, v) => {
  const lo = Number(BigInt(v) & 0xffffffffn);
  const hi = Number((BigInt(v) >> 32n) & 0xffffffffn);
  writeU32LE(b, o, lo);
  writeU32LE(b, o + 4, hi);
};

const sha256 = async (bytes) => new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));

function lp32(bytes) {
  const out = new Uint8Array(4 + bytes.length);
  writeU32LE(out, 0, bytes.length);
  out.set(bytes, 4);
  return out;
}

function base64Encode(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

// =========================================================================
//  v1 (JAR) signing
// =========================================================================

const CRLF = new Uint8Array([0x0d, 0x0a]);
const textBytes = (s) => new TextEncoder().encode(s);

/** Emit one Manifest/SF line, wrapping over 70 bytes per JAR spec. */
function manifestLine(name, value) {
  const raw = name + ': ' + value;
  const bytes = textBytes(raw);
  if (bytes.length <= 70) return concat([bytes, CRLF]);
  const out = [];
  let first = true;
  for (let i = 0; i < bytes.length; i += 70) {
    const chunk = bytes.subarray(i, Math.min(i + 70, bytes.length));
    if (!first) out.push(Uint8Array.of(0x20)); // continuation space
    out.push(chunk, CRLF);
    first = false;
  }
  return concat(out);
}

async function v1Sign(zipBytes, pkcs8KeyDer, certDer) {
  const entries = fflate.unzipSync(zipBytes);
  const names = Object.keys(entries).filter((n) => {
    if (!/^META-INF\//.test(n)) return true;
    return !(n.endsWith('.SF') || n.endsWith('.RSA') || n.endsWith('.DSA') || n.endsWith('.EC') || n === 'META-INF/MANIFEST.MF');
  });

  // Per-entry digests for MANIFEST.MF.
  const entryDigests = {};
  for (const name of names) entryDigests[name] = base64Encode(await sha256(entries[name]));

  // MANIFEST.MF.
  const mfParts = [
    manifestLine('Manifest-Version', '1.0'),
    manifestLine('Created-By', '1.0 (Android gplaydl)'),
    CRLF,
  ];
  const perEntryMfSection = {};
  for (const name of names) {
    const section = concat([
      manifestLine('Name', name),
      manifestLine('SHA-256-Digest', entryDigests[name]),
      CRLF,
    ]);
    perEntryMfSection[name] = section;
    mfParts.push(section);
  }
  const manifestBytes = concat(mfParts);

  // CERT.SF — digests of MANIFEST.MF and per-section.
  const mainSectionEnd = (() => {
    for (let i = 0; i + 3 < manifestBytes.length; i++) {
      if (manifestBytes[i] === 0x0d && manifestBytes[i+1] === 0x0a && manifestBytes[i+2] === 0x0d && manifestBytes[i+3] === 0x0a) return i + 4;
    }
    return manifestBytes.length;
  })();
  const mainAttrsDigest = base64Encode(await sha256(manifestBytes.subarray(0, mainSectionEnd)));
  const manifestDigest  = base64Encode(await sha256(manifestBytes));

  const sfParts = [
    manifestLine('Signature-Version', '1.0'),
    manifestLine('Created-By', '1.0 (Android gplaydl)'),
    manifestLine('SHA-256-Digest-Manifest-Main-Attributes', mainAttrsDigest),
    manifestLine('SHA-256-Digest-Manifest', manifestDigest),
    manifestLine('X-Android-APK-Signed', '2, 3'),
    CRLF,
  ];
  for (const name of names) {
    const sectionDigest = base64Encode(await sha256(perEntryMfSection[name]));
    sfParts.push(concat([
      manifestLine('Name', name),
      manifestLine('SHA-256-Digest', sectionDigest),
      CRLF,
    ]));
  }
  const sfBytes = concat(sfParts);

  // RSA-sign CERT.SF.
  const key = await crypto.subtle.importKey('pkcs8', pkcs8KeyDer, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
  const sig = new Uint8Array(await crypto.subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, key, sfBytes));
  const certRsa = buildPkcs7(certDer, sig);

  // Add the three META-INF files at the top of the new ZIP (apksigner's order).
  return fflate.zipSync({
    'META-INF/MANIFEST.MF': manifestBytes,
    'META-INF/CERT.SF':     sfBytes,
    'META-INF/CERT.RSA':    certRsa,
    ...entries,
  }, { level: 0 });
}

// =========================================================================
//  v2/v3 — APK Signing Block
// =========================================================================

function findEocd(apk) {
  const sig = 0x06054b50;
  const min = Math.max(0, apk.length - 65557);
  for (let i = apk.length - 22; i >= min; i--) {
    if (readU32LE(apk, i) === sig) return i;
  }
  throw new Error('EOCD not found');
}
const readEocd = (apk, eocdOff) => ({
  cdSize:  readU32LE(apk, eocdOff + 12),
  cdOffset: readU32LE(apk, eocdOff + 16),
  eocdSize: apk.length - eocdOff,
});

/** Compute the v2/v3 chunked digest over (ZIP entries, Central Directory, EOCD). */
async function computeApkDigest(apk, cdOffset, cdSize, patchedEocd) {
  const chunkDigests = [];
  const hashRange = async (src, start, end) => {
    for (let off = start; off < end; off += CHUNK_SIZE) {
      const limit = Math.min(off + CHUNK_SIZE, end);
      const chunkLen = limit - off;
      const buf = new Uint8Array(1 + 4 + chunkLen);
      buf[0] = 0xa5;
      writeU32LE(buf, 1, chunkLen);
      buf.set(src.subarray(off, limit), 5);
      chunkDigests.push(await sha256(buf));
    }
  };
  await hashRange(apk, 0,        cdOffset);
  await hashRange(apk, cdOffset, cdOffset + cdSize);
  await hashRange(patchedEocd, 0, patchedEocd.length);

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

/** Derive the SubjectPublicKeyInfo (DER) from a PKCS#8 RSA private key. */
async function extractSpki(pkcs8) {
  const priv = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, true, ['sign']);
  const jwk = await crypto.subtle.exportKey('jwk', priv);
  const pub = await crypto.subtle.importKey('jwk',
    { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: jwk.alg, ext: true, key_ops: ['verify'] },
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, true, ['verify']);
  return new Uint8Array(await crypto.subtle.exportKey('spki', pub));
}

// Layout helpers — every container is length-prefixed (u32 LE).
const digestsField = (d) => {
  const inner = new Uint8Array(8 + d.length);
  writeU32LE(inner, 0, SIG_ALG_RSA_PKCS1_V1_5_SHA256);
  writeU32LE(inner, 4, d.length);
  inner.set(d, 8);
  return lp32(inner);
};
const certsField = (certDer) => lp32(lp32(certDer));
const emptyAttrs = ()         => lp32(new Uint8Array(0));
const signedData = (df, cf, attrs) => concat([df, cf, attrs]);
const sigField   = (sig) => {
  const inner = new Uint8Array(8 + sig.length);
  writeU32LE(inner, 0, SIG_ALG_RSA_PKCS1_V1_5_SHA256);
  writeU32LE(inner, 4, sig.length);
  inner.set(sig, 8);
  return lp32(inner);
};
const signer     = (sd, sigs, spki) => lp32(concat([lp32(sd), sigs, lp32(spki)]));
const signers    = (s) => lp32(s);

/** v3 SignerInfo wraps signedData plus min/max SDK + sigs + pubkey. */
function v3SignerBlock(df, cf, attrs, sigs, spki, minSdk = V3_DEFAULT_MIN_SDK, maxSdk = V3_DEFAULT_MAX_SDK) {
  const sd = signedData(df, cf, attrs);
  const inner = new Uint8Array(4 + sd.length + 4 + 4 + sigs.length + 4 + spki.length);
  let off = 0;
  writeU32LE(inner, off, sd.length); off += 4;
  inner.set(sd, off);                 off += sd.length;
  writeU32LE(inner, off, minSdk);     off += 4;
  writeU32LE(inner, off, maxSdk);     off += 4;
  inner.set(sigs, off);               off += sigs.length;
  writeU32LE(inner, off, spki.length); off += 4;
  inner.set(spki, off);
  return lp32(inner);
}

/** Pack a list of (id, payload) pairs into an APK Signing Block. */
function packSigningBlock(pairs) {
  let pairsLen = 0;
  for (const p of pairs) pairsLen += 8 + 4 + p.payload.length;
  const sizeOfBlockField = pairsLen + 8 /* trailing size */ + 16 /* magic */;
  const totalLen = 8 + sizeOfBlockField;
  const out = new Uint8Array(totalLen);
  writeU64LE(out, 0, sizeOfBlockField);
  let off = 8;
  for (const p of pairs) {
    writeU64LE(out, off, 4 + p.payload.length); off += 8;
    writeU32LE(out, off, p.id);                  off += 4;
    out.set(p.payload, off);                     off += p.payload.length;
  }
  writeU64LE(out, off, sizeOfBlockField); off += 8;
  out.set(MAGIC, off);
  return out;
}

// =========================================================================
//  Public API
// =========================================================================

/**
 * Sign an APK with any combination of v1 (JAR), v2, and v3 schemes.
 *
 * @param {Uint8Array} apk          The (already-merged) APK bytes.
 * @param {Uint8Array} pkcs8KeyDer  RSA-2048 private key in PKCS#8 DER.
 * @param {Uint8Array} certDer      Self-signed X.509 cert in DER.
 * @param {{v1?: boolean, v2?: boolean, v3?: boolean}} [opts]
 *        Which schemes to apply. Defaults to all three (apksigner default).
 * @returns {Promise<Uint8Array>}   Signed APK bytes.
 */
export async function signApk(apk, pkcs8KeyDer, certDer, opts = { v1: true, v2: true, v3: true }) {
  apk = apk instanceof Uint8Array ? apk : new Uint8Array(apk);
  if (opts.v1) apk = await v1Sign(apk, pkcs8KeyDer, certDer);
  if (!opts.v2 && !opts.v3) return apk;

  const spki = await extractSpki(pkcs8KeyDer);
  const cf   = certsField(certDer);

  const buildV2 = (digest, sig) => signers(signer(signedData(digestsField(digest), cf, emptyAttrs()), sigField(sig), spki));
  const buildV3 = (digest, sig) => signers(v3SignerBlock(digestsField(digest), cf, emptyAttrs(), sigField(sig), spki));

  // Sizing pass — SHA-256 digest is always 32 bytes, RSA-2048 sig is 256.
  const sizePairs = [];
  if (opts.v2) sizePairs.push({ id: APK_SIG_V2_BLOCK_ID, payload: buildV2(new Uint8Array(32), new Uint8Array(RSA_2048_SIG_LEN)) });
  if (opts.v3) sizePairs.push({ id: APK_SIG_V3_BLOCK_ID, payload: buildV3(new Uint8Array(32), new Uint8Array(RSA_2048_SIG_LEN)) });
  const signingBlockSize = packSigningBlock(sizePairs).length;

  // Patch EOCD so the central-directory offset reflects the future block.
  const eocdOff = findEocd(apk);
  const { cdSize, cdOffset, eocdSize } = readEocd(apk, eocdOff);
  if (cdOffset + cdSize > eocdOff) throw new Error('malformed APK: CD past EOCD');
  const patchedEocd = new Uint8Array(eocdSize);
  patchedEocd.set(apk.subarray(eocdOff, eocdOff + eocdSize));
  writeU32LE(patchedEocd, 16, cdOffset + signingBlockSize);

  const realDigest = await computeApkDigest(apk, cdOffset, cdSize, patchedEocd);
  const key        = await importSigningKey(pkcs8KeyDer);
  const sdBytes    = signedData(digestsField(realDigest), cf, emptyAttrs());
  const realSig    = new Uint8Array(await crypto.subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, key, sdBytes));
  if (realSig.length !== RSA_2048_SIG_LEN) throw new Error('expected ' + RSA_2048_SIG_LEN + '-byte signature, got ' + realSig.length);

  const realPairs = [];
  if (opts.v2) realPairs.push({ id: APK_SIG_V2_BLOCK_ID, payload: buildV2(realDigest, realSig) });
  if (opts.v3) realPairs.push({ id: APK_SIG_V3_BLOCK_ID, payload: buildV3(realDigest, realSig) });
  const realBlock = packSigningBlock(realPairs);
  if (realBlock.length !== signingBlockSize) throw new Error('signing block size drift between sizing pass and real pass');

  const out = new Uint8Array(cdOffset + realBlock.length + cdSize + eocdSize);
  out.set(apk.subarray(0, cdOffset), 0);
  out.set(realBlock, cdOffset);
  out.set(apk.subarray(cdOffset, cdOffset + cdSize), cdOffset + realBlock.length);
  out.set(patchedEocd, cdOffset + realBlock.length + cdSize);
  return out;
}

/** Back-compat helper used by older unit tests. */
export async function signApkV2(apk, pkcs8KeyDer, certDer) {
  return signApk(apk, pkcs8KeyDer, certDer, { v1: false, v2: true, v3: false });
}
