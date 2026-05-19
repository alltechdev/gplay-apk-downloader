// apk-signer-v1.js — APK Signature Scheme v1 (JAR-style META-INF files).
//
// Reference: https://docs.oracle.com/javase/8/docs/technotes/guides/jar/jar.html#Signed_JAR_File

import * as fflate from 'fflate';
import { concat } from './asn1.js';
import { buildPkcs7 } from './pkcs7.js';
import { sha256, base64Encode } from './apk-signer-utils.js';

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

/**
 * Produce a v1-signed APK by inserting MANIFEST.MF + CERT.SF + CERT.RSA.
 *
 * `alsoSchemes` lists which other APK Signature Schemes will be applied
 * after v1 (e.g. `[2, 3]`). It controls the `X-Android-APK-Signed` header
 * in CERT.SF — declaring schemes that aren't actually present makes
 * apksigner report "Signature stripped?".
 */
export async function v1Sign(zipBytes, pkcs8KeyDer, certDer, alsoSchemes = [2, 3]) {
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
  ];
  if (alsoSchemes.length) {
    sfParts.push(manifestLine('X-Android-APK-Signed', alsoSchemes.join(', ')));
  }
  sfParts.push(CRLF);
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
