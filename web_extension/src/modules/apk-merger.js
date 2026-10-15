// apk-merger.js — pure-JS merge of base + splits into a single APK.
//
// Strategy:
//   1. Parse each APK as a ZIP (fflate.unzipSync).
//   2. Strip every old signature (META-INF/MANIFEST.MF, META-INF/*.SF, META-INF/*.RSA, META-INF/*.EC).
//   3. Combine entries: base wins on path conflicts.
//   4. If splits include asset packs (anything not config.*), patch
//      AndroidManifest.xml to add the `com.android.dynamic.apk.fused.modules`
//      meta-data, matching legacy axml_patcher.py.
//   5. Re-emit as a new ZIP (fflate.zipSync, store-only).

import * as fflate from 'fflate';
import { patchManifestFusedModules, getAssetPackSplitNames } from './axml-patcher.js';
import { writeAlignedZip } from './zipalign.js';

function isOldSignature(path) {
  if (!path.startsWith('META-INF/')) return false;
  const rest = path.slice(9);
  if (rest === 'MANIFEST.MF') return true;
  if (/\.SF$/i.test(rest)) return true;
  if (/\.RSA$/i.test(rest)) return true;
  if (/\.DSA$/i.test(rest)) return true;
  if (/\.EC$/i.test(rest)) return true;
  return false;
}

function copyEntriesInto(out, entries) {
  for (const [path, data] of Object.entries(entries)) {
    if (isOldSignature(path)) continue;
    if (path in out) continue; // base wins
    out[path] = data;
  }
}

function patchFusedModulesIfNeeded(out, splitNames) {
  const assetPacks = getAssetPackSplitNames(splitNames);
  if (assetPacks.length > 0 && out['AndroidManifest.xml']) {
    const patched = patchManifestFusedModules(out['AndroidManifest.xml'], assetPacks.join(','));
    if (patched !== out['AndroidManifest.xml']) {
      out['AndroidManifest.xml'] = patched;
    }
  }
}

/**
 * Streaming merge: loads one Blob at a time and lets the previous
 * Uint8Array go GC-eligible before the next allocation. The merged
 * entries dict still holds every path's data, but we never have N+1
 * raw split buffers in flight at once.
 *
 * @param {Blob} baseBlob
 * @param {Array<{ name: string, blob: Blob }>} splitFiles
 * @returns {Promise<Uint8Array>}
 */
export async function mergeApks(baseBlob, splitFiles) {
  const out = {};

  {
    const baseBytes = new Uint8Array(await baseBlob.arrayBuffer());
    const baseEntries = fflate.unzipSync(baseBytes);
    for (const [path, data] of Object.entries(baseEntries)) {
      if (isOldSignature(path)) continue;
      out[path] = data;
    }
    // baseBytes + baseEntries dict now have no live refs.
  }

  for (const split of splitFiles) {
    const bytes = new Uint8Array(await split.blob.arrayBuffer());
    copyEntriesInto(out, fflate.unzipSync(bytes));
    // bytes drops out of scope before the next iteration allocates.
  }

  patchFusedModulesIfNeeded(out, splitFiles.map((s) => s.name));
  return writeAlignedZip(out);
}
