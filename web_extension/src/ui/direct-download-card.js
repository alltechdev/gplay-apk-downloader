// direct-download-card.js — Info / Download / Install-to-Device.
//
// "Merge splits" checkbox drives output format:
//   checked   → merged + zipaligned + v1+v2+v3-signed single APK
//   unchecked → one ZIP containing the original splits
// "Install to Device" button (visible only when an ADB device is connected)
// fetches blobs directly from the CDN and pushes them via
// `pm install-create/write/commit` — no disk roundtrip.

import { $, esc, fmtSize } from './dom.js';
import { rpc } from './rpc.js';
import {
  log, setLogActive, ensureLogOpen,
  shouldEmitProgress, updateProgressEntry, removeProgressEntry, logWithAction,
} from './log.js';
import { getAdbInfo } from './adb-card.js';

let currentDetails = null;
const fileById = new Map();
const sizeById = new Map();

function showMsg(html, cls = 'info') {
  $('#info-result').innerHTML = '<div class="msg ' + cls + '">' + html + '</div>';
}

async function getInstalledVersion(pkg) {
  if (!window.gplaydlAdb?.connected) return null;
  try {
    const out = await window.gplaydlAdb.shell("dumpsys package " + pkg + " | grep -E 'versionName|versionCode' | head -2");
    const vn = out.match(/versionName=([^\s]+)/)?.[1];
    const vc = out.match(/versionCode=([0-9]+)/)?.[1];
    if (!vn && !vc) return null;
    return { versionName: vn || '?', versionCode: vc ? Number(vc) : 0 };
  } catch { return null; }
}

async function doInfo() {
  const pkg = $('#pkg-input').value.trim();
  if (!pkg) { showMsg('enter a package name first', 'err'); return; }
  showMsg('<span class="spinner"></span>looking up ' + esc(pkg) + '…');
  log('Info: ' + pkg, 'info');
  try {
    const [d, installed] = await Promise.all([
      rpc('app.details', { packageName: pkg }),
      getInstalledVersion(pkg),
    ]);
    currentDetails = d;
    let body =
      '<strong>' + esc(d.title) + '</strong>' +
      '<br>' + esc(d.packageName) +
      '<br>Play: v' + esc(d.versionString) + ' (vc=' + d.versionCode + ')' +
      '<br>' + esc(d.developerName) +
      '<br>size: ' + fmtSize(d.installationSize) +
      (d.splitId?.length ? '<br>splits: ' + d.splitId.map(esc).join(', ') : '<br>splits: (none)');
    if (installed) {
      const tag = d.versionCode > installed.versionCode
        ? ' <span style="color:var(--accent);font-weight:600">(update available)</span>'
        : d.versionCode === installed.versionCode
          ? ' <span style="color:var(--success)">(up to date)</span>'
          : ' <span style="color:#fbbf24">(device has newer)</span>';
      body += '<br>Device: v' + esc(installed.versionName) + ' (vc=' + installed.versionCode + ')' + tag;
    }
    showMsg(body, 'ok');
    log('Info ok: ' + d.title + ' v' + d.versionString + (installed ? ' · device has v' + installed.versionName : ''), 'ok');
  } catch (err) {
    currentDetails = null;
    showMsg(esc(err.message), 'err');
    log('Info failed: ' + err.message, 'err');
  }
}

async function fetchSplits(pkg, details) {
  const prep = await rpc('app.prepareInstall', { packageName: pkg, versionCode: details.versionCode });
  const apks = [];
  try {
    for (const f of prep.files) {
      log('Fetching ' + f.name + ' (' + fmtSize(f.size) + ') from CDN…', 'dl');
      const res = await fetch(f.url);
      if (!res.ok) throw new Error('CDN fetch ' + f.name + ' → ' + res.status);
      const blob = await res.blob();
      apks.push({ name: f.name, blob, size: blob.size });
      log('  Fetched ' + f.name + ' (' + fmtSize(blob.size) + ')', 'ok');
    }
    return apks;
  } finally {
    rpc('app.releaseRules', { ruleIds: prep.ruleIds }).catch(() => {});
  }
}

async function downloadAsSingleFile(pkg, details, format) {
  if (!window.gplaydlApkTools) throw new Error('apk-tools bundle not loaded');
  log('Preparing ' + (format === 'zip' ? 'zip bundle' : 'merged signed APK') + '…', 'dl');
  const apks = await fetchSplits(pkg, details);
  const baseName = pkg + '-' + details.versionCode;
  if (format === 'zip') {
    const r = await window.gplaydlApkTools.bundleZip(apks, baseName + '.zip');
    log('ZIP ready (' + fmtSize(r.bytes) + ') — downloading ' + baseName + '.zip', 'ok');
  } else {
    log('Merging and signing… this can take a few seconds', 'dl');
    const r = await window.gplaydlApkTools.mergeAndSign(apks, baseName + '.apk');
    log('Merged APK ready (' + fmtSize(r.bytes) + ') — downloading ' + baseName + '.apk', 'ok');
  }
}

async function installToDevice(pkg, details) {
  log('Preparing install for ' + pkg + ' (ADB device connected)', 'dl');
  const apks = await fetchSplits(pkg, details);
  log('Installing on device via ADB…', 'dl');
  await window.gplaydlAdb.installSplit(apks, (phase, msg) => log('ADB ' + phase + ': ' + msg, 'dl'));
  log('Install complete: ' + details.title + ' v' + details.versionString, 'ok');
}

export async function downloadPackage(pkg, format = null) {
  const d = currentDetails && currentDetails.packageName === pkg
    ? currentDetails
    : await rpc('app.details', { packageName: pkg });
  currentDetails = d;
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

async function doInstall() {
  const pkg = $('#pkg-input').value.trim();
  if (!pkg) { showMsg('enter a package name first', 'err'); return; }
  if (!window.gplaydlAdb?.connected) { log('Connect a device first', 'warn'); return; }
  ensureLogOpen();
  setLogActive(true);
  try {
    const d = currentDetails && currentDetails.packageName === pkg
      ? currentDetails
      : await rpc('app.details', { packageName: pkg });
    currentDetails = d;
    log('Install: ' + d.title + ' v' + d.versionString + ' (vc=' + d.versionCode + ')', 'info');
    await installToDevice(pkg, d);
  } catch (err) {
    log('Install failed: ' + err.message, 'err');
  } finally { setLogActive(false); }
}

// Listen to SW download.event broadcasts (chrome.downloads progress, queueing,
// completion — only fires when the legacy app.download splits path is used).
function onDownloadEvent(p) {
  if (p.phase === 'purchase')        log('Purchasing ' + p.packageName + ' v' + p.versionCode, 'info');
  else if (p.phase === 'delivery')   log('Resolving delivery for ' + p.packageName, 'info');
  else if (p.phase === 'start')      { fileById.set(p.id || '', p.file); sizeById.set(p.id || '', p.size || 0); log('Starting download: ' + p.file + (p.size ? ' (' + fmtSize(p.size) + ')' : ''), 'dl'); }
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

function updateInstallBtnVisibility() {
  const btn = $('#install-btn');
  if (btn) btn.style.display = window.gplaydlAdb?.connected ? '' : 'none';
}

export function initDirectDownloadCard() {
  $('#info-btn').addEventListener('click', doInfo);
  $('#download-btn').addEventListener('click', doDownload);
  $('#install-btn').addEventListener('click', doInstall);
  $('#pkg-input').addEventListener('keypress', (e) => { if (e.key === 'Enter') doInfo(); });
  chrome.runtime.onMessage.addListener((msg) => { if (msg?.type === 'download.event') onDownloadEvent(msg.payload || {}); });
  document.addEventListener('adb-status', updateInstallBtnVisibility);
  updateInstallBtnVisibility();
}
