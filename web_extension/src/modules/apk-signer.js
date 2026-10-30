// apk-signer.js — top-level orchestrator for APK Signature Scheme v1+v2+v3.
//
// Helpers live in:
//   ./apk-signer-utils.js  — byte/crypto helpers + constants
//   ./apk-signer-v1.js     — JAR-style META-INF signing
//   ./apk-signer-v2v3.js   — APK Signing Block (v2 + v3)
//   ./asn1.js              — DER builder + cert parser
//   ./pkcs7.js             — CERT.RSA builder

import {
  APK_SIG_V2_BLOCK_ID, APK_SIG_V3_BLOCK_ID, RSA_2048_SIG_LEN,
  V3_DEFAULT_MIN_SDK, V3_DEFAULT_MAX_SDK,
  writeU32LE, importSigningKey, extractSpki,
} from './apk-signer-utils.js';
import { v1Sign } from './apk-signer-v1.js';
import {
  findEocd, readEocd, computeApkDigest,
  digestsField, certsField, emptyAttrs, signedData, v3SignedData,
  sigField, signer, signers, v3SignerBlock, packSigningBlock,
} from './apk-signer-v2v3.js';

async function rsaSign(key, bytes) {
  return new Uint8Array(await crypto.subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, key, bytes));
}

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
  if (opts.v1) {
    const alsoSchemes = [opts.v2 && 2, opts.v3 && 3].filter(Boolean);
    apk = await v1Sign(apk, pkcs8KeyDer, certDer, alsoSchemes);
  }
  if (!opts.v2 && !opts.v3) return apk;

  const spki = await extractSpki(pkcs8KeyDer);
  const cf   = certsField(certDer);

  // v2: signed-data = digests || certs || attrs
  // v3: signed-data = digests || certs || minSdk || maxSdk || attrs (must
  //     mirror the outer SignerInfo's min/max SDK).
  const v2Sd = (digest) => signedData(digestsField(digest), cf, emptyAttrs());
  const v3Sd = (digest) => v3SignedData(digestsField(digest), cf, emptyAttrs(), V3_DEFAULT_MIN_SDK, V3_DEFAULT_MAX_SDK);

  const buildV2 = (digest, sig) => signers(signer(v2Sd(digest), sigField(sig), spki));
  const buildV3 = (digest, sig) => signers(v3SignerBlock(v3Sd(digest), sigField(sig), spki));

  // Sizing pass — SHA-256 digest is always 32 bytes, RSA-2048 sig is 256.
  const sizePairs = [];
  if (opts.v2) sizePairs.push({ id: APK_SIG_V2_BLOCK_ID, payload: buildV2(new Uint8Array(32), new Uint8Array(RSA_2048_SIG_LEN)) });
  if (opts.v3) sizePairs.push({ id: APK_SIG_V3_BLOCK_ID, payload: buildV3(new Uint8Array(32), new Uint8Array(RSA_2048_SIG_LEN)) });
  const signingBlockSize = packSigningBlock(sizePairs).length;

  // Two EOCDs:
  //   digestEocd: used when computing the v2/v3 chunked digest. Per spec,
  //               its CD-offset must point at the APK Signing Block (= the
  //               original on-disk CD offset before the block is inserted).
  //   onDiskEocd: written to the final APK. Its CD-offset must point at
  //               the NEW central-directory location, after the block.
  const eocdOff = findEocd(apk);
  const { cdSize, cdOffset, eocdSize } = readEocd(apk, eocdOff);
  if (cdOffset + cdSize > eocdOff) throw new Error('malformed APK: CD past EOCD');
  const digestEocd  = apk.subarray(eocdOff, eocdOff + eocdSize);
  const onDiskEocd  = new Uint8Array(digestEocd);
  writeU32LE(onDiskEocd, 16, cdOffset + signingBlockSize);

  const realDigest = await computeApkDigest(apk, cdOffset, cdSize, digestEocd);
  const key        = await importSigningKey(pkcs8KeyDer);

  const v2Sig = opts.v2 ? await rsaSign(key, v2Sd(realDigest)) : null;
  const v3Sig = opts.v3 ? await rsaSign(key, v3Sd(realDigest)) : null;
  for (const s of [v2Sig, v3Sig]) {
    if (s && s.length !== RSA_2048_SIG_LEN) throw new Error('expected ' + RSA_2048_SIG_LEN + '-byte signature, got ' + s.length);
  }

  const realPairs = [];
  if (opts.v2) realPairs.push({ id: APK_SIG_V2_BLOCK_ID, payload: buildV2(realDigest, v2Sig) });
  if (opts.v3) realPairs.push({ id: APK_SIG_V3_BLOCK_ID, payload: buildV3(realDigest, v3Sig) });
  const realBlock = packSigningBlock(realPairs);
  if (realBlock.length !== signingBlockSize) throw new Error('signing block size drift between sizing pass and real pass');

  const out = new Uint8Array(cdOffset + realBlock.length + cdSize + eocdSize);
  out.set(apk.subarray(0, cdOffset), 0);
  out.set(realBlock, cdOffset);
  out.set(apk.subarray(cdOffset, cdOffset + cdSize), cdOffset + realBlock.length);
  out.set(onDiskEocd, cdOffset + realBlock.length + cdSize);
  return out;
}

