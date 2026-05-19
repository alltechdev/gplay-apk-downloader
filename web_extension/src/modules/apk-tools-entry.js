// Source for src/vendor/apk-tools-bundle.js (esbuild output).
// Exposes pure-browser APK helpers on window.gplaydlApkTools:
//
//   await window.gplaydlApkTools.bundleZip(files, archiveName)
//     files: [{ name: string, blob: Blob }]
//     archiveName: string (.zip filename without dir)
//     → triggers a download of the assembled zip via <a download>.
//
//   await window.gplaydlApkTools.mergeAndSign(files, outputName)
//     Combines base + splits into a single APK and signs it with a
//     debug RSA-2048 keypair bundled in `debug-cert.js`. Triggers a
//     download. Streams blobs through `mergeApksFromBlobs` so peak
//     memory tracks "merged APK + signed APK" instead of "every split
//     + merged + signed".

import * as fflate from 'fflate';
import { DEBUG_CERT_DER, DEBUG_KEY_PKCS8_DER } from './debug-cert.js';
import { mergeApks } from './apk-merger.js';
import { signApk } from './apk-signer.js';

function downloadBlob(blob, name) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 30_000);
}

async function bundleZip(files, archiveName) {
  // Load one entry at a time so we don't hold every split's bytes at once.
  const entries = {};
  for (const f of files) {
    entries[f.name] = new Uint8Array(await f.blob.arrayBuffer());
  }
  const zipBytes = fflate.zipSync(entries, { level: 0 }); // store-only — APKs are already compressed
  const blob = new Blob([zipBytes], { type: 'application/zip' });
  downloadBlob(blob, archiveName);
  return { bytes: zipBytes.byteLength };
}

async function mergeAndSign(files, outputName) {
  // files: [{ name: 'base.apk' | 'config.X.apk', blob: Blob }]
  const baseFile = files.find((f) => /^base\.apk$/i.test(f.name)) || files[0];
  const splitFiles = files.filter((f) => f !== baseFile);

  let merged = await mergeApks(baseFile.blob, splitFiles);

  // Match legacy `apksigner sign` defaults: v1 + v2 + v3 all enabled.
  const signed = await signApk(merged, DEBUG_KEY_PKCS8_DER, DEBUG_CERT_DER, { v1: true, v2: true, v3: true });
  merged = null; // free the intermediate before we wrap+download.

  const blob = new Blob([signed], { type: 'application/vnd.android.package-archive' });
  downloadBlob(blob, outputName);
  return { bytes: signed.byteLength };
}

window.gplaydlApkTools = { bundleZip, mergeAndSign };
