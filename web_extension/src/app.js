// app.js — UI controller for the extension page.

const $ = (s) => document.querySelector(s);
const LOG_ICONS = { info: '\u2022', ok: '\u2713', err: '\u2717', warn: '\u25B3', dl: '\u2193' };
let logCount = 0;

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function logWithAction(msg, type, actionLabel, onClick) {
  const scroll = $('#log-scroll');
  const empty = $('#log-empty');
  if (empty) empty.remove();
  const entry = document.createElement('div');
  entry.className = 'log-entry';
  const now = new Date();
  const time = now.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
  entry.innerHTML =
    '<span class="log-time">' + time + '</span>' +
    '<span class="log-icon ' + type + '">' + (LOG_ICONS[type] || LOG_ICONS.info) + '</span>' +
    '<span class="log-msg">' + esc(msg) + ' <a href="#" class="log-action" style="color:var(--accent);margin-left:6px">' + esc(actionLabel) + '</a></span>';
  entry.querySelector('.log-action').addEventListener('click', (e) => { e.preventDefault(); onClick(); });
  scroll.appendChild(entry);
  scroll.scrollTop = scroll.scrollHeight;
  logCount++;
  const badge = $('#log-badge');
  badge.textContent = logCount;
  badge.classList.remove('empty');
}

function log(msg, type = 'info') {
  const scroll = $('#log-scroll');
  const empty = $('#log-empty');
  if (empty) empty.remove();
  const entry = document.createElement('div');
  entry.className = 'log-entry';
  const now = new Date();
  const time = now.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
  entry.innerHTML =
    '<span class="log-time">' + time + '</span>' +
    '<span class="log-icon ' + type + '">' + (LOG_ICONS[type] || LOG_ICONS.info) + '</span>' +
    '<span class="log-msg">' + esc(msg) + '</span>';
  scroll.appendChild(entry);
  scroll.scrollTop = scroll.scrollHeight;
  logCount++;
  const badge = $('#log-badge');
  badge.textContent = logCount;
  badge.classList.remove('empty');
}

function clearLog() {
  $('#log-scroll').innerHTML = '<div class="log-empty" id="log-empty">No activity yet</div>';
  logCount = 0;
  const badge = $('#log-badge');
  badge.textContent = '0';
  badge.classList.add('empty');
}
function setLogActive(active) { $('#log-dot').style.display = active ? 'block' : 'none'; }
function toggleLog() { $('#log-panel').classList.toggle('open'); }
function showMsg(targetSel, html, cls = 'info') {
  $(targetSel).innerHTML = '<div class="msg ' + cls + '">' + html + '</div>';
}

async function rpc(type, payload = {}) {
  const res = await chrome.runtime.sendMessage({ type, payload });
  if (res?.error) throw new Error(res.error);
  return res?.result;
}

function setAuthCard(status) {
  const statusEl = $('#auth-status');
  const signInBtn = $('#auth-signin-btn');
  const signOutBtn = $('#auth-signout-btn');
  $('#arch-select').value = status.arch || 'arm64-v8a';
  if (status.signedIn) {
    const stale = status.stale ? ' (stale, will refresh on next call)' : '';
    // Legacy does not surface the dispenser-account email; we don't either.
    statusEl.innerHTML =
      '<div class="adb-dot"></div>' +
      '<div class="adb-device-name">Authenticated' +
      '<small>' + esc(status.profileLabel || status.profileKey || '') +
      ' · ' + esc(status.profileArch || '') + stale + '</small></div>';
    signInBtn.style.display = 'none';
    signOutBtn.style.display = '';
  } else {
    statusEl.textContent = 'Not signed in. Click "Sign in" for an anonymous AuroraOSS token.';
    signInBtn.style.display = '';
    signOutBtn.style.display = 'none';
  }
}

async function refreshAuth() {
  try { setAuthCard(await rpc('auth.status')); }
  catch (err) { log('auth status failed: ' + err.message, 'err'); }
}

function fmtSize(n) {
  if (!n) return '?';
  const units = ['B', 'KB', 'MB', 'GB'];
  let v = Number(n), i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return v.toFixed(v >= 100 ? 0 : v >= 10 ? 1 : 2) + ' ' + units[i];
}

let currentDetails = null;
const activeFileById = {};
const activeSizeById = {};
const progressLastUpdateAt = {};
const progressEntryById = {};

function updateProgressEntry(id, text) {
  let el = progressEntryById[id];
  if (!el) {
    const scroll = $('#log-scroll');
    const empty = $('#log-empty');
    if (empty) empty.remove();
    el = document.createElement('div');
    el.className = 'log-entry';
    el.dataset.progressId = String(id);
    scroll.appendChild(el);
    scroll.scrollTop = scroll.scrollHeight;
    progressEntryById[id] = el;
  }
  const now = new Date();
  const time = now.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
  el.innerHTML =
    '<span class="log-time">' + time + '</span>' +
    '<span class="log-icon dl">' + LOG_ICONS.dl + '</span>' +
    '<span class="log-msg">' + esc(text) + ' <a href="#" class="log-cancel" data-id="' + id + '" style="color:var(--error);margin-left:6px">cancel</a></span>';
  el.querySelector('.log-cancel')?.addEventListener('click', async (ev) => {
    ev.preventDefault();
    try { await rpc('app.cancelDownload', { id }); log('Cancelled #' + id, 'warn'); }
    catch (err) { log('Cancel #' + id + ' failed: ' + err.message, 'err'); }
  });
}

function removeProgressEntry(id) {
  const el = progressEntryById[id];
  if (el) { el.remove(); delete progressEntryById[id]; delete progressLastUpdateAt[id]; }
}

async function getInstalledVersion(pkg) {
  if (!window.gplaydlAdb?.connected) return null;
  try {
    const out = await window.gplaydlAdb.shell('dumpsys package ' + pkg + " | grep -E 'versionName|versionCode' | head -2");
    const verName = out.match(/versionName=([^\s]+)/)?.[1];
    const verCode = out.match(/versionCode=([0-9]+)/)?.[1];
    if (!verName && !verCode) return null;
    return { versionName: verName || '?', versionCode: verCode ? Number(verCode) : 0 };
  } catch { return null; }
}

async function doInfo() {
  const pkg = $('#pkg-input').value.trim();
  if (!pkg) { showMsg('#info-result', 'enter a package name first', 'err'); return; }
  showMsg('#info-result', '<span class="spinner"></span>looking up ' + esc(pkg) + '…', 'info');
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
      const newer = d.versionCode > installed.versionCode;
      const tag = newer ? ' <span style="color:var(--accent);font-weight:600">(update available)</span>' :
                    d.versionCode === installed.versionCode ? ' <span style="color:var(--success)">(up to date)</span>' :
                    ' <span style="color:#fbbf24">(device has newer)</span>';
      body += '<br>Device: v' + esc(installed.versionName) + ' (vc=' + installed.versionCode + ')' + tag;
    }
    showMsg('#info-result', body, 'ok');
    log('Info ok: ' + d.title + ' v' + d.versionString + (installed ? ' · device has v' + installed.versionName : ''), 'ok');
  } catch (err) {
    currentDetails = null;
    showMsg('#info-result', esc(err.message), 'err');
    log('Info failed: ' + err.message, 'err');
  }
}

async function doDownload() {
  const pkg = $('#pkg-input').value.trim();
  if (!pkg) { showMsg('#info-result', 'enter a package name first', 'err'); return; }
  if (!$('#log-panel').classList.contains('open')) toggleLog();
  log('Download: looking up ' + pkg, 'info');
  setLogActive(true);
  try {
    const d = currentDetails && currentDetails.packageName === pkg
      ? currentDetails
      : await rpc('app.details', { packageName: pkg });
    currentDetails = d;
    log('Download: ' + d.title + ' v' + d.versionString + ' (vc=' + d.versionCode + ')', 'info');
    const merge = $('#merge-apks').checked;
    if (merge) {
      await downloadAsSingleFile(pkg, d, 'merge');
    } else {
      const res = await rpc('app.download', { packageName: pkg, versionCode: d.versionCode });
      log('Queued ' + res.files.length + ' file(s) under ' + res.dirPrefix, 'dl');
    }
  } catch (err) {
    log('Download failed: ' + err.message, 'err');
  } finally {
    setLogActive(false);
  }
}

async function doInstall() {
  const pkg = $('#pkg-input').value.trim();
  if (!pkg) { showMsg('#info-result', 'enter a package name first', 'err'); return; }
  if (!window.gplaydlAdb?.connected) { log('Connect a device first', 'warn'); return; }
  if (!$('#log-panel').classList.contains('open')) toggleLog();
  log('Install: looking up ' + pkg, 'info');
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
  } finally {
    setLogActive(false);
  }
}

function updateInstallBtnVisibility() {
  const btn = $('#install-btn');
  if (!btn) return;
  btn.style.display = window.gplaydlAdb?.connected ? '' : 'none';
}

async function downloadAsSingleFile(pkg, details, format) {
  if (!window.gplaydlApkTools) throw new Error('apk-tools bundle not loaded');
  log('Preparing ' + (format === 'zip' ? 'zip bundle' : 'merged signed APK') + '…', 'dl');
  const prep = await rpc('app.prepareInstall', { packageName: pkg, versionCode: details.versionCode });
  try {
    const files = [];
    for (const f of prep.files) {
      log('Fetching ' + f.name + ' (' + fmtSize(f.size) + ')…', 'dl');
      const res = await fetch(f.url);
      if (!res.ok) throw new Error('CDN fetch ' + f.name + ' → ' + res.status);
      const blob = await res.blob();
      files.push({ name: f.name, blob });
    }
    const baseName = pkg + '-' + details.versionCode;
    if (format === 'zip') {
      const r = await window.gplaydlApkTools.bundleZip(files, baseName + '.zip');
      log('ZIP ready (' + fmtSize(r.bytes) + ') — downloading ' + baseName + '.zip', 'ok');
    } else {
      log('Merging and signing… this can take a few seconds', 'dl');
      const r = await window.gplaydlApkTools.mergeAndSign(files, baseName + '.apk');
      log('Merged APK ready (' + fmtSize(r.bytes) + ') — downloading ' + baseName + '.apk', 'ok');
    }
  } finally {
    await rpc('app.releaseRules', { ruleIds: prep.ruleIds }).catch(() => {});
  }
}

async function installToDevice(pkg, details) {
  log('Preparing install for ' + pkg + ' (ADB device connected)', 'dl');
  const prep = await rpc('app.prepareInstall', { packageName: pkg, versionCode: details.versionCode });
  try {
    const apks = [];
    for (const f of prep.files) {
      log('Fetching ' + f.name + ' (' + fmtSize(f.size) + ') from CDN…', 'dl');
      const res = await fetch(f.url);
      if (!res.ok) throw new Error('CDN fetch ' + f.name + ' → ' + res.status);
      const blob = await res.blob();
      apks.push({ name: f.name, blob, size: blob.size });
      log('  Fetched ' + f.name + ' (' + fmtSize(blob.size) + ')', 'ok');
    }
    log('Installing on device via ADB…', 'dl');
    await window.gplaydlAdb.installSplit(apks, (phase, msg) => log('ADB ' + phase + ': ' + msg, 'dl'));
    log('Install complete: ' + details.title + ' v' + details.versionString, 'ok');
  } finally {
    await rpc('app.releaseRules', { ruleIds: prep.ruleIds }).catch((e) => log('rule cleanup failed: ' + e.message, 'warn'));
  }
}

// =========================================================================
//  Backup import + bulk download
// =========================================================================

async function onBackupImport(e) {
  const file = e.target.files?.[0];
  if (!file) return;
  e.target.value = '';
  const resultEl = $('#backup-result');
  try {
    const data = JSON.parse(await file.text());
    if (!Array.isArray(data.packages)) throw new Error('expected "packages": [ … ]');
    const available = data.packages.filter((r) => r.available !== false);
    if (available.length === 0) throw new Error('no packages marked "available"');
    const total = data.packages.length;

    let html = '<div class="backup-summary">' + available.length + ' available · ' + (total - available.length) + ' marked unavailable';
    if (data.device) html += ' · from ' + esc(data.device);
    if (data.date) html += ' · ' + new Date(data.date).toLocaleDateString();
    html += ' · <a href="#" id="backup-all" style="color:var(--accent)">Select all</a> / <a href="#" id="backup-none" style="color:var(--accent)">None</a>';
    html += '</div>';
    html += '<div class="backup-list">';
    for (const r of data.packages) {
      const av = r.available !== false;
      html += '<div class="backup-item">' +
        '<input type="checkbox" class="backup-check" data-pkg="' + esc(r.package) + '"' + (av ? ' checked' : ' disabled') + '>' +
        '<span class="pkg-name">' + (r.title ? esc(r.title) + ' <span style="opacity:.5">(' + esc(r.package) + ')</span>' : esc(r.package)) + '</span>' +
        '<span class="pkg-status ' + (av ? 'available' : 'unavailable') + '">' + (av ? 'available' : 'unavailable') + '</span>' +
        '</div>';
    }
    html += '</div>';
    html += '<div class="backup-actions">' +
      '<button class="btn-primary" id="backup-restore-btn">' +
      '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>' +
      'Download all selected' +
      '</button></div>';
    resultEl.innerHTML = html;
    $('#backup-restore-btn').addEventListener('click', doRestore);
    $('#backup-all').addEventListener('click', (ev) => {
      ev.preventDefault();
      document.querySelectorAll('.backup-check:not(:disabled)').forEach((c) => { c.checked = true; });
    });
    $('#backup-none').addEventListener('click', (ev) => {
      ev.preventDefault();
      document.querySelectorAll('.backup-check').forEach((c) => { c.checked = false; });
    });
    log('Imported list with ' + total + ' packages (' + available.length + ' marked available)', 'ok');
  } catch (err) {
    resultEl.innerHTML = '<div class="msg err">' + esc('Invalid backup file: ' + err.message) + '</div>';
    log('Import failed: ' + err.message, 'err');
  }
}

async function doRestore() {
  const selected = Array.from(document.querySelectorAll('.backup-check:checked')).map((c) => c.dataset.pkg);
  if (selected.length === 0) { log('No packages selected', 'warn'); return; }
  const btn = $('#backup-restore-btn');
  const parent = btn?.parentNode;
  if (btn) btn.disabled = true;
  const cancelBtn = document.createElement('button');
  cancelBtn.className = 'btn-ghost';
  cancelBtn.id = 'backup-cancel-btn';
  cancelBtn.textContent = 'Cancel';
  cancelBtn.addEventListener('click', async () => {
    cancelBtn.disabled = true;
    try { await rpc('app.abortBulk'); log('Cancel requested — stopping after current app', 'warn'); }
    catch (err) { log('Cancel failed: ' + err.message, 'err'); }
  });
  if (parent) parent.appendChild(cancelBtn);
  setLogActive(true);
  if (!$('#log-panel').classList.contains('open')) toggleLog();
  log('Downloading ' + selected.length + ' app(s) sequentially…', 'dl');
  try {
    const res = await rpc('app.downloadList', { packages: selected });
    const ok = res.results.filter((r) => r.ok).length;
    const failed = res.results.length - ok;
    const label = res.aborted ? 'Bulk download aborted' : 'Bulk download done';
    log(label + ': ' + ok + ' ok, ' + failed + ' failed' + (res.aborted ? ' (cancelled)' : ''), failed || res.aborted ? 'warn' : 'ok');
  } catch (err) {
    log('Bulk download failed: ' + err.message, 'err');
  } finally {
    setLogActive(false);
    if (btn) btn.disabled = false;
    cancelBtn.remove();
  }
}

// =========================================================================
//  Broadcasts from the SW
// =========================================================================

chrome.runtime.onMessage.addListener((msg) => {
  if (msg?.type === 'auth.event') {
    const p = msg.payload || {};
    if (p.phase === 'start') { log('Sign-in started (arch=' + p.arch + ')', 'info'); setLogActive(true); }
    else if (p.phase === 'try') log('Trying profile ' + p.key + ' (' + p.label + ', ' + p.arch + ')', 'info');
    else if (p.phase === 'reject') log('Dispenser rejected ' + p.key + ' (HTTP ' + p.status + ')', 'warn');
    else if (p.phase === 'error') log('Network error on ' + p.key + ': ' + p.error, 'err');
    else if (p.phase === 'ok') log('Got token from ' + p.key, 'ok');
    else if (p.phase === 'done') { log('Sign-in complete (' + p.profileKey + ')', 'ok'); setLogActive(false); refreshAuth(); }
    else if (p.phase === 'fail') { log('Sign-in failed — all profiles rejected', 'err'); setLogActive(false); }
  } else if (msg?.type === 'download.event') {
    const p = msg.payload || {};
    if (p.phase === 'purchase') log('Purchasing ' + p.packageName + ' v' + p.versionCode, 'info');
    else if (p.phase === 'delivery') log('Resolving delivery for ' + p.packageName, 'info');
    else if (p.phase === 'start') {
      activeFileById[p.id || ''] = p.file; // best-effort; updated by queued
      activeSizeById[p.id || ''] = p.size || 0;
      log('Starting download: ' + p.file + (p.size ? ' (' + fmtSize(p.size) + ')' : ''), 'dl');
    }
    else if (p.phase === 'queued') {
      activeFileById[p.id] = p.file;
      log('Queued #' + p.id + ': ' + p.file, 'dl');
    }
    else if (p.phase === 'progress') {
      const file = activeFileById[p.id] || ('#' + p.id);
      const total = activeSizeById[p.id] || 0;
      const pct = total ? Math.round(100 * p.bytes / total) : null;
      const txt = 'Progress ' + file + ': ' + fmtSize(p.bytes) + (pct != null ? ' (' + pct + '%)' : '');
      const now = Date.now();
      const last = progressLastUpdateAt[p.id] || 0;
      if (now - last < 750 && pct !== 100) return; // throttle to ~1.3 Hz
      progressLastUpdateAt[p.id] = now;
      updateProgressEntry(p.id, txt);
    }
    else if (p.phase === 'complete') {
      removeProgressEntry(p.id);
      delete activeFileById[p.id];
      delete activeSizeById[p.id];
      const file = activeFileById[p.id]; // already deleted above; safe
      logWithAction(
        'Download #' + p.id + ' complete' + (p.bytes ? ' (' + fmtSize(p.bytes) + ')' : ''),
        'ok',
        'show',
        async () => { try { await rpc('app.showDownload', { id: p.id }); } catch (err) { log('show failed: ' + err.message, 'err'); } },
      );
    }
    else if (p.phase === 'interrupted') {
      removeProgressEntry(p.id);
      delete activeFileById[p.id];
      delete activeSizeById[p.id];
      log('Download #' + p.id + ' interrupted', 'err');
    }
    else if (p.phase === 'list.aborted') log('Bulk aborted: ' + p.completed + ' done, ' + p.remaining + ' skipped', 'warn');
    else if (p.phase === 'list.start') log('[' + p.index + '/' + p.total + '] ' + p.packageName, 'info');
    else if (p.phase === 'list.itemDone') log('[done] ' + p.packageName + ' — ' + p.files + ' file(s) queued', 'ok');
    else if (p.phase === 'list.itemFail') log('[fail] ' + p.packageName + ': ' + p.error, 'err');
    else if (p.phase === 'list.done') log('Bulk list complete', 'ok');
  }
});

// =========================================================================
//  Boot
// =========================================================================

// =========================================================================
//  ADB (WebUSB) via window.gplaydlAdb (bundled in src/vendor/adb-bundle.js)
// =========================================================================

let adbInfo = null;

function setAdbCard(state, info) {
  const card = $('#adb-card');
  const statusEl = $('#adb-status');
  const backupBtn = $('#backup-btn');
  card.classList.toggle('connected', state === 'connected');
  if (state === 'unsupported') {
    statusEl.innerHTML = '<span class="adb-unsupported">WebUSB requires Chrome or Edge (and a secure context)</span>';
    updateInstallBtnVisibility();
    return;
  }
  if (state === 'connected') {
    statusEl.innerHTML =
      '<div class="adb-dot"></div>' +
      '<div class="adb-device-name">' + esc(info.model || 'device') +
      '<small>Android ' + esc(info.android || '?') +
      (info.serial ? ' · ' + esc(info.serial) : '') + '</small></div>' +
      '<button class="btn-ghost" id="adb-disconnect-btn">Disconnect</button>';
    $('#adb-disconnect-btn').addEventListener('click', adbDoDisconnect);
    if (backupBtn) backupBtn.disabled = false;
  } else {
    statusEl.innerHTML =
      '<button class="btn-secondary" id="adb-connect-btn">' +
      '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M7 2v4M17 2v4M2 12h4M18 12h4M4.93 4.93l2.83 2.83M16.24 4.93l-2.83 2.83M12 8v4M12 16v.01"/><circle cx="12" cy="12" r="6"/></svg>' +
      'Connect Device' +
      '</button>';
    $('#adb-connect-btn').addEventListener('click', adbDoConnect);
    if (backupBtn) backupBtn.disabled = true;
  }
  updateInstallBtnVisibility();
}

async function adbDoConnect() {
  if (!window.gplaydlAdb) { log('ADB bundle not loaded', 'err'); return; }
  log('Connecting to device — tap "Allow" if your device prompts', 'info');
  try {
    const info = await window.gplaydlAdb.connect();
    adbInfo = info;
    setAdbCard('connected', info);
    log('ADB connected: ' + info.model + ' (Android ' + info.android + ')', 'ok');
  } catch (err) {
    log('ADB connect failed: ' + err.message, 'err');
    setAdbCard('disconnected');
  }
}

async function adbDoDisconnect() {
  try { await window.gplaydlAdb.disconnect(); }
  catch (err) { log('ADB disconnect error: ' + err.message, 'warn'); }
  adbInfo = null;
  setAdbCard('disconnected');
  log('ADB disconnected', 'info');
}

async function backupAppList() {
  if (!window.gplaydlAdb?.connected) { log('Connect a device first', 'warn'); return; }
  const btn = $('#backup-btn');
  btn.disabled = true;
  const resultEl = $('#backup-result');
  resultEl.innerHTML = '<div class="msg info"><span class="spinner"></span>Reading installed packages from device…</div>';
  setLogActive(true);
  try {
    const packages = await window.gplaydlAdb.listUserPackages();
    log('Found ' + packages.length + ' user-installed packages on device', 'ok');
    const data = {
      device: adbInfo?.model || 'unknown',
      android: adbInfo?.android || '',
      date: new Date().toISOString(),
      packages: packages.map((p) => ({ package: p, available: true })),
    };
    const filename = 'app-backup-' + new Date().toISOString().slice(0, 10) + '.json';
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    URL.revokeObjectURL(url);
    log('Backup exported as ' + filename, 'ok');
    resultEl.innerHTML = '<div class="msg ok">Saved ' + packages.length + ' packages to <code>' + esc(filename) + '</code>. Import it later to re-download.</div>';
  } catch (err) {
    log('Backup failed: ' + err.message, 'err');
    resultEl.innerHTML = '<div class="msg err">' + esc(err.message) + '</div>';
  } finally {
    btn.disabled = false;
    setLogActive(false);
  }
}

document.addEventListener('DOMContentLoaded', async () => {
  $('#log-header').addEventListener('click', toggleLog);
  $('#log-clear-btn').addEventListener('click', (e) => { e.stopPropagation(); clearLog(); });

  // Initialise ADB card based on WebUSB availability.
  if (!window.gplaydlAdb) {
    setAdbCard('unsupported');
  } else if (!window.gplaydlAdb.supported) {
    setAdbCard('unsupported');
  } else {
    setAdbCard('disconnected');
  }
  $('#backup-btn').addEventListener('click', backupAppList);

  $('#arch-select').addEventListener('change', async (e) => {
    const arch = e.target.value;
    try {
      const status = await rpc('arch.set', { arch });
      log('Architecture set to ' + arch, 'info');
      // Legacy parity: auth picks a profile per arch at request time. If we
      // already have a token for a different arch, rotate now so subsequent
      // downloads use the matching profile.
      if (status.signedIn && status.profileArch && status.profileArch !== arch) {
        log('Profile arch (' + status.profileArch + ') differs — re-authenticating', 'info');
        setAuthCard(await rpc('auth.signIn', { arch }));
      }
    } catch (err) {
      log('arch.set failed: ' + err.message, 'err');
    }
  });

  $('#auth-signin-btn').addEventListener('click', async () => {
    $('#auth-signin-btn').disabled = true;
    try {
      setAuthCard(await rpc('auth.signIn', { arch: $('#arch-select').value }));
    } catch (err) {
      log('Sign-in failed: ' + err.message, 'err');
      setLogActive(false);
    } finally {
      $('#auth-signin-btn').disabled = false;
    }
  });
  $('#auth-signout-btn').addEventListener('click', async () => {
    try { setAuthCard(await rpc('auth.signOut')); log('Signed out', 'info'); }
    catch (err) { log('Sign-out failed: ' + err.message, 'err'); }
  });
  $('#info-btn').addEventListener('click', doInfo);
  $('#download-btn').addEventListener('click', doDownload);
  $('#install-btn').addEventListener('click', doInstall);
  $('#pkg-input').addEventListener('keypress', (e) => { if (e.key === 'Enter') doInfo(); });
  $('#backup-import').addEventListener('change', onBackupImport);

  await refreshAuth();
  $('#pkg-input').focus();
  // GitHub stars badge (legacy parity, footer)
  fetch('https://api.github.com/repos/alltechdev/gplay-apk-downloader')
    .then((r) => r.json())
    .then((d) => {
      if (d?.stargazers_count != null) {
        $('#gh-stars-count').textContent = d.stargazers_count.toLocaleString();
        $('#gh-stars').style.display = 'inline-flex';
      }
    })
    .catch(() => {});
  log('Extension page loaded', 'ok');
});
