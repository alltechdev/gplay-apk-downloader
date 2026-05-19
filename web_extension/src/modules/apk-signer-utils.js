// apk-signer-utils.js — byte/crypto helpers shared by v1 + v2 + v3 signing.

export const CHUNK_SIZE                  = 1024 * 1024;
export const SIG_ALG_RSA_PKCS1_V1_5_SHA256 = 0x00000103;
export const APK_SIG_V2_BLOCK_ID         = 0x7109871a;
export const APK_SIG_V3_BLOCK_ID         = 0xf05368c0;
export const MAGIC                       = new TextEncoder().encode('APK Sig Block 42'); // 16 bytes
export const V3_DEFAULT_MIN_SDK          = 28;
export const V3_DEFAULT_MAX_SDK          = 0x7fffffff;
export const RSA_2048_SIG_LEN            = 256;

export const readU32LE  = (b, o) => ((b[o]) | (b[o+1] << 8) | (b[o+2] << 16) | ((b[o+3] << 24) >>> 0)) >>> 0;
export const writeU32LE = (b, o, v) => { b[o] = v & 0xff; b[o+1] = (v >>> 8) & 0xff; b[o+2] = (v >>> 16) & 0xff; b[o+3] = (v >>> 24) & 0xff; };
export const writeU64LE = (b, o, v) => {
  const lo = Number(BigInt(v) & 0xffffffffn);
  const hi = Number((BigInt(v) >> 32n) & 0xffffffffn);
  writeU32LE(b, o, lo);
  writeU32LE(b, o + 4, hi);
};

export const sha256 = async (bytes) => new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));

/** Prepend a 4-byte little-endian length to `bytes`. */
export function lp32(bytes) {
  const out = new Uint8Array(4 + bytes.length);
  writeU32LE(out, 0, bytes.length);
  out.set(bytes, 4);
  return out;
}

export function base64Encode(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

export async function importSigningKey(pkcs8) {
  return crypto.subtle.importKey('pkcs8', pkcs8, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
}

/** Derive the SubjectPublicKeyInfo (DER) from a PKCS#8 RSA private key. */
export async function extractSpki(pkcs8) {
  const priv = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, true, ['sign']);
  const jwk = await crypto.subtle.exportKey('jwk', priv);
  const pub = await crypto.subtle.importKey('jwk',
    { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: jwk.alg, ext: true, key_ops: ['verify'] },
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, true, ['verify']);
  return new Uint8Array(await crypto.subtle.exportKey('spki', pub));
}
