// download-handler.js — fetch splits from CDN and save them as a single file.
//
// "Merge splits" checkbox drives output format:
//   checked   → merged + zipaligned + v1+v2+v3-signed single APK
//   unchecked → one ZIP containing the original splits

import { $, fmtSize } from './dom.js';
import { rpc } from './rpc.js';
import { apkTools } from './runtime.js';
import {
  log, setLogActive, ensureLogOpen,
  shouldEmitProgress, updateProgressEntry, removeProgressEntry, logWithAction,
} from './log.js';
import { getDetailsCached, showMsg } from './info-card.js';
import { pMapLimit } from './p-map-limit.js';

const fileById = new Map();
const sizeById = new Map();

/** Concurrency: legacy uses `download_splits_parallel(splits, max_workers=4)`. */
const FETCH_CONCURRENCY = 4;

async function fetchOne(f) {
  log('Fetching ' + f.name + ' (' + fmtSize(f.size) + ') from CDN…', 'dl');
  const res = await fetch(f.url);
  if (!res.ok) throw new Error('CDN fetch ' + f.name + ' → ' + res.status);
  const blob = await res.blob();
  log('  Fetched ' + f.name + ' (' + fmtSize(blob.size) + ')', 'ok');
  return { name: f.name, blob, size: blob.size };
}

/** Fetch every split listed in `app.prepareInstall` straight from the CDN. */
export async function fetchSplits(pkg, details) {
  const prep = await rpc('app.prepareInstall', { packageName: pkg, versionCode: details.versionCode });
  try {
    return await pMapLimit(prep.files, FETCH_CONCURRENCY, fetchOne);
  } finally {
    rpc('app.releaseRules', { ruleIds: prep.ruleIds }).catch(() => {});
  }
}

/** Save splits as either a merged-signed APK ('merge') or a single ZIP ('zip'). */
export async function downloadAsSingleFile(pkg, details, format) {
  const tools = apkTools();
  log('Preparing ' + (format === 'zip' ? 'zip bundle' : 'merged signed APK') + '…', 'dl');
  const apks = await fetchSplits(pkg, details);
  const baseName = pkg + '-' + details.versionCode;
  if (format === 'zip') {
    const r = await tools.bundleZip(apks, baseName + '.zip');
    log('ZIP ready (' + fmtSize(r.bytes) + ') — downloading ' + baseName + '.zip', 'ok');
  } else {
    log('Merging and signing… this can take a few seconds', 'dl');
    const r = await tools.mergeAndSign(apks, baseName + '.apk');
    log('Merged APK ready (' + fmtSize(r.bytes) + ') — downloading ' + baseName + '.apk', 'ok');
  }
}

/**
 * Fetch and produce a single-file download for the given package.
 * Used by the Direct Download button and the bulk Restore flow.
 *
 * @param {string} pkg - Play Store package name.
 * @param {string} [format] - 'merge' | 'zip'; falls back to the checkbox state.
 */
export async function downloadPackage(pkg, format = null) {
  const d = await getDetailsCached(pkg);
  log('Download: ' + d.title + ' v' + d.versionString + ' (vc=' + d.versionCode + ')', 'info');
  const fmt = format || ($('#merge-apks').checked ? 'merge' : 'zip');
  await downloadAsSingleFile(pkg, d, fmt);
}

async function doDownload() {
  const pkg = $('#pkg-input').value.trim();
  if (!pkg) { showMsg('enter a package name first', 'err'); return; }
  ensureLogOpen();
  setLogActive(true);
  try { await downloadPackage(pkg); }
  catch (err) { log('Download failed: ' + err.message, 'err'); }
  finally { setLogActive(false); }
}

/** Chrome `downloads` SW events forwarded via runtime.onMessage. */
function onDownloadEvent(p) {
  if (p.phase === 'purchase')        log('Purchasing ' + p.packageName + ' v' + p.versionCode, 'info');
  else if (p.phase === 'delivery')   log('Resolving delivery for ' + p.packageName, 'info');
  else if (p.phase === 'start')      {
    fileById.set(p.id || '', p.file);
    sizeById.set(p.id || '', p.size || 0);
    log('Starting download: ' + p.file + (p.size ? ' (' + fmtSize(p.size) + ')' : ''), 'dl');
  }
  else if (p.phase === 'queued')     { fileById.set(p.id, p.file); log('Queued #' + p.id + ': ' + p.file, 'dl'); }
  else if (p.phase === 'progress') {
    if (!shouldEmitProgress(p.id)) return;
    const file = fileById.get(p.id) || ('#' + p.id);
    const total = sizeById.get(p.id) || 0;
    const pct = total ? Math.round(100 * p.bytes / total) : null;
    const txt = 'Progress ' + file + ': ' + fmtSize(p.bytes) + (pct != null ? ' (' + pct + '%)' : '');
    updateProgressEntry(p.id, txt, () => rpc('app.cancelDownload', { id: p.id }).catch((e) => log('Cancel failed: ' + e.message, 'err')));
  }
  else if (p.phase === 'complete')   {
    removeProgressEntry(p.id);
    fileById.delete(p.id); sizeById.delete(p.id);
    logWithAction('Download #' + p.id + ' complete' + (p.bytes ? ' (' + fmtSize(p.bytes) + ')' : ''), 'ok', 'show',
      () => rpc('app.showDownload', { id: p.id }).catch((e) => log('show failed: ' + e.message, 'err')));
  }
  else if (p.phase === 'interrupted'){
    removeProgressEntry(p.id);
    fileById.delete(p.id); sizeById.delete(p.id);
    log('Download #' + p.id + ' interrupted', 'err');
  }
}

export function initDownloadHandler() {
  $('#download-btn').addEventListener('click', doDownload);
  chrome.runtime.onMessage.addListener((msg) => { if (msg?.type === 'download.event') onDownloadEvent(msg.payload || {}); });
}
