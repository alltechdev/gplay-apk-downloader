// apk-signer-v2v3.js — APK Signature Scheme v2 + v3 (APK Signing Block).
//
// References:
//   v2: https://source.android.com/docs/security/features/apksigning/v2
//   v3: https://source.android.com/docs/security/features/apksigning/v3

import { concat } from './asn1.js';
import {
  CHUNK_SIZE, SIG_ALG_RSA_PKCS1_V1_5_SHA256, MAGIC,
  V3_DEFAULT_MIN_SDK, V3_DEFAULT_MAX_SDK,
  readU32LE, writeU32LE, writeU64LE, sha256, lp32,
} from './apk-signer-utils.js';

// =========================================================================
//  EOCD / digest
// =========================================================================

export function findEocd(apk) {
  const sig = 0x06054b50;
  const min = Math.max(0, apk.length - 65557);
  for (let i = apk.length - 22; i >= min; i--) {
    if (readU32LE(apk, i) === sig) return i;
  }
  throw new Error('EOCD not found');
}
export const readEocd = (apk, eocdOff) => ({
  cdSize:  readU32LE(apk, eocdOff + 12),
  cdOffset: readU32LE(apk, eocdOff + 16),
  eocdSize: apk.length - eocdOff,
});

/** Compute the v2/v3 chunked digest over (ZIP entries, Central Directory, EOCD). */
export async function computeApkDigest(apk, cdOffset, cdSize, patchedEocd) {
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

// =========================================================================
//  Layout helpers — every container is length-prefixed (u32 LE).
// =========================================================================

export const digestsField = (d) => {
  const inner = new Uint8Array(8 + d.length);
  writeU32LE(inner, 0, SIG_ALG_RSA_PKCS1_V1_5_SHA256);
  writeU32LE(inner, 4, d.length);
  inner.set(d, 8);
  return lp32(inner);
};
export const certsField  = (certDer) => lp32(lp32(certDer));
export const emptyAttrs  = ()        => lp32(new Uint8Array(0));
// `df` from digestsField() is a single length-prefixed (algo, digest)
// record; the v2/v3 spec wraps it once more as a length-prefixed
// *sequence* of records, same shape as `certsField` and the sigs field.

/** v2 signed-data layout: digests-seq || certs-seq || attrs-seq. */
export const signedData  = (df, cf, attrs) => concat([lp32(df), cf, attrs]);

/**
 * v3 signed-data layout: digests-seq || certs-seq || minSdk(u32) || maxSdk(u32) || attrs-seq.
 * The min/max SDK values inside signed-data MUST match the values in the
 * outer SignerInfo or apksigner reports "minSdkVersion mismatch".
 */
export function v3SignedData(df, cf, attrs, minSdk, maxSdk) {
  const sdk = new Uint8Array(8);
  writeU32LE(sdk, 0, minSdk);
  writeU32LE(sdk, 4, maxSdk);
  return concat([lp32(df), cf, sdk, attrs]);
}
export const sigField    = (sig) => {
  const inner = new Uint8Array(8 + sig.length);
  writeU32LE(inner, 0, SIG_ALG_RSA_PKCS1_V1_5_SHA256);
  writeU32LE(inner, 4, sig.length);
  inner.set(sig, 8);
  return lp32(inner);
};
// `sigs` here is a single length-prefixed signature record; per the v2/v3
// spec the `signatures` field is itself a length-prefixed *sequence* of
// records, so we wrap it once more with lp32.
export const signer  = (sd, sigs, spki) => lp32(concat([lp32(sd), lp32(sigs), lp32(spki)]));
export const signers = (s) => lp32(s);

/**
 * v3 SignerInfo wraps signedData plus min/max SDK + sigs + pubkey.
 * `sd` is the already-built v3 signed-data (caller built it with v3SignedData()).
 */
export function v3SignerBlock(sd, sigs, spki, minSdk = V3_DEFAULT_MIN_SDK, maxSdk = V3_DEFAULT_MAX_SDK) {
  // sigs gets an additional lp32 wrap (signatures sequence), same as v2.
  const sigsSeq = lp32(sigs);
  const inner = new Uint8Array(4 + sd.length + 4 + 4 + sigsSeq.length + 4 + spki.length);
  let off = 0;
  writeU32LE(inner, off, sd.length); off += 4;
  inner.set(sd, off);                 off += sd.length;
  writeU32LE(inner, off, minSdk);     off += 4;
  writeU32LE(inner, off, maxSdk);     off += 4;
  inner.set(sigsSeq, off);            off += sigsSeq.length;
  writeU32LE(inner, off, spki.length); off += 4;
  inner.set(spki, off);
  return lp32(inner);
}

/** Pack a list of (id, payload) pairs into an APK Signing Block. */
export function packSigningBlock(pairs) {
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
