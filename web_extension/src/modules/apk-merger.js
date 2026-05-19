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

export function mergeApks(baseBytes, splits) {
  const out = {};
  const baseEntries = fflate.unzipSync(baseBytes);
  for (const [path, data] of Object.entries(baseEntries)) {
    if (isOldSignature(path)) continue;
    out[path] = data;
  }
  for (const split of splits) {
    const entries = fflate.unzipSync(split.bytes);
    for (const [path, data] of Object.entries(entries)) {
      if (isOldSignature(path)) continue;
      if (path in out) continue; // base wins
      out[path] = data;
    }
  }

  // If there are asset-pack splits, add the fused-modules meta-data so
  // Play Core's AssetPackManager treats them as fused-into-base.
  const splitNames = splits.map((s) => s.name);
  const assetPacks = getAssetPackSplitNames(splitNames);
  if (assetPacks.length > 0 && out['AndroidManifest.xml']) {
    const fusedValue = assetPacks.join(',');
    const patched = patchManifestFusedModules(out['AndroidManifest.xml'], fusedValue);
    if (patched !== out['AndroidManifest.xml']) {
      out['AndroidManifest.xml'] = patched;
    }
  }

  // Use the aligned writer (zipalign-equivalent) so the merged APK is
  // 4-byte aligned and lib/*/*.so is 4096-byte page-aligned, matching
  // what legacy `zipalign -p 4` produces.
  return writeAlignedZip(out);
}
