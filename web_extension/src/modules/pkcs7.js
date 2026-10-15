// pkcs7.js — minimal PKCS#7 SignedData builder for CERT.RSA in JAR signing.
//
// Builds a detached, no-signed-attrs SignedData containing:
//   - our certificate
//   - one SignerInfo with SHA-256 digest algorithm
//   - the RSA signature of the CERT.SF bytes
//
// CERT.RSA bytes are the DER encoding of:
//   ContentInfo SignedData { … signers[].encryptedDigest = sig(CERT.SF) }

import {
  derSeq, derSet, derCtxC0, derOctet, derNull, derOid, derInteger,
  parseCertIssuerAndSerial,
} from './asn1.js';

const OID_PKCS7_SIGNED_DATA = [1, 2, 840, 113549, 1, 7, 2];
const OID_PKCS7_DATA        = [1, 2, 840, 113549, 1, 7, 1];
const OID_SHA256            = [2, 16, 840, 1, 101, 3, 4, 2, 1];
const OID_RSA_ENCRYPTION    = [1, 2, 840, 113549, 1, 1, 1];

const algoIdSha256 = () => derSeq([derOid(OID_SHA256),         derNull()]);
const algoIdRsaEnc = () => derSeq([derOid(OID_RSA_ENCRYPTION), derNull()]);

/**
 * Build the CERT.RSA bytes for a JAR-style v1 signature.
 *
 * @param {Uint8Array} certDer        Our X.509 cert as DER.
 * @param {Uint8Array} signatureBytes RSA-SHA256 signature over CERT.SF.
 * @returns {Uint8Array}              The full DER-encoded PKCS#7 ContentInfo.
 */
export function buildPkcs7(certDer, signatureBytes) {
  const { issuer, serial } = parseCertIssuerAndSerial(certDer);

  const signerInfo = derSeq([
    derInteger(Uint8Array.of(1)),     // version
    derSeq([issuer, serial]),         // sid: IssuerAndSerialNumber
    algoIdSha256(),                   // digestAlgorithm
    algoIdRsaEnc(),                   // digestEncryptionAlgorithm
    derOctet(signatureBytes),         // encryptedDigest (the signature)
  ]);

  const certsField = derCtxC0(certDer); // [0] IMPLICIT certificates

  const signedData = derSeq([
    derInteger(Uint8Array.of(1)),     // version
    derSet([algoIdSha256()]),         // digestAlgorithms
    derSeq([derOid(OID_PKCS7_DATA)]), // encapContentInfo: contentType=data, content omitted
    certsField,
    derSet([signerInfo]),
  ]);

  return derSeq([
    derOid(OID_PKCS7_SIGNED_DATA),
    derCtxC0(signedData),
  ]);
}
