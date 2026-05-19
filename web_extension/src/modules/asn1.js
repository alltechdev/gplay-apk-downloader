// asn1.js — small ASN.1 DER builder + minimal parser.
// Used by apk-signer.js and pkcs7.js to construct CERT.RSA payloads and
// to extract the issuer + serial from an X.509 cert.

/** Encode a DER length prefix. */
export function derLen(n) {
  if (n < 0x80) return Uint8Array.of(n);
  const bytes = [];
  while (n > 0) { bytes.unshift(n & 0xff); n >>>= 8; }
  return Uint8Array.of(0x80 | bytes.length, ...bytes);
}

/** Concatenate Uint8Array parts. */
export function concat(parts) {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

/** Build a TLV with the given tag and value bytes. */
export function derTLV(tag, value) {
  const len = derLen(value.length);
  const out = new Uint8Array(1 + len.length + value.length);
  out[0] = tag;
  out.set(len, 1);
  out.set(value, 1 + len.length);
  return out;
}

export const derSeq    = (parts) => derTLV(0x30, concat(parts));
export const derSet    = (parts) => derTLV(0x31, concat(parts));
export const derCtxC0  = (value) => derTLV(0xa0, value); // [0] EXPLICIT
export const derOctet  = (bytes) => derTLV(0x04, bytes);
export const derNull   = ()      => derTLV(0x05, new Uint8Array(0));

/** Encode an OID like [1, 2, 840, 113549, 1, 7, 2]. */
export function derOid(parts) {
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

/** INTEGER. Pads with a leading 0 if the top bit is set (to keep it positive). */
export function derInteger(bytes) {
  if (bytes.length > 0 && (bytes[0] & 0x80)) {
    const v = new Uint8Array(bytes.length + 1);
    v.set(bytes, 1);
    return derTLV(0x02, v);
  }
  return derTLV(0x02, bytes);
}

// --- Minimal parser: just enough to navigate a Certificate -----------------

/** Parse a single TLV at `off`. Returns header + value layout info. */
export function parseTLV(buf, off) {
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

/**
 * Extract `issuer` (raw DER Name SEQUENCE) and `serial` (raw DER INTEGER)
 * from an X.509 certificate DER blob. Used as `IssuerAndSerialNumber` in
 * the PKCS#7 SignerInfo we build for CERT.RSA.
 */
export function parseCertIssuerAndSerial(certDer) {
  const cert = parseTLV(certDer, 0);
  if (cert.tag !== 0x30) throw new Error('not a SEQUENCE at cert root');
  const tbs = parseTLV(certDer, cert.valueStart);
  if (tbs.tag !== 0x30) throw new Error('not a SEQUENCE at tbsCertificate');

  let pos = tbs.valueStart;
  let first = parseTLV(certDer, pos);
  if (first.tag === 0xa0) {        // skip [0] version
    pos += first.totalLen;
    first = parseTLV(certDer, pos);
  }
  if (first.tag !== 0x02) throw new Error('expected INTEGER serial');
  const serial = certDer.subarray(pos, pos + first.totalLen);
  pos += first.totalLen;

  const algo = parseTLV(certDer, pos);  // signature AlgorithmIdentifier
  pos += algo.totalLen;

  const issuer = parseTLV(certDer, pos);
  if (issuer.tag !== 0x30) throw new Error('expected SEQUENCE issuer');
  return { serial, issuer: certDer.subarray(pos, pos + issuer.totalLen) };
}
