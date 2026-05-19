// backup-card.js — Backup app list from ADB + Import JSON + sequential restore.

import { $, esc } from './dom.js';
import { rpc } from './rpc.js';
import { log, setLogActive, ensureLogOpen } from './log.js';
import { downloadPackage } from './direct-download-card.js';
import { getAdbInfo } from './adb-card.js';

let bulkAborted = false;

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
    const info = getAdbInfo();
    const data = {
      device: info?.model || 'unknown',
      android: info?.android || '',
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
    html += ' · <a href="#" id="backup-all" style="color:var(--accent)">Select all</a> / <a href="#" id="backup-none" style="color:var(--accent)">None</a></div>';
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
  bulkAborted = false;
  const cancelBtn = document.createElement('button');
  cancelBtn.className = 'btn-ghost';
  cancelBtn.id = 'backup-cancel-btn';
  cancelBtn.textContent = 'Cancel';
  cancelBtn.addEventListener('click', () => {
    cancelBtn.disabled = true;
    bulkAborted = true;
    log('Cancel requested — stopping after current app', 'warn');
  });
  if (parent) parent.appendChild(cancelBtn);
  setLogActive(true);
  ensureLogOpen();
  log('Downloading ' + selected.length + ' app(s) sequentially…', 'dl');
  let ok = 0, failed = 0;
  try {
    for (let i = 0; i < selected.length; i++) {
      if (bulkAborted) { log('Bulk aborted after ' + i + ' of ' + selected.length, 'warn'); break; }
      const pkg = selected[i];
      log('[' + (i + 1) + '/' + selected.length + '] ' + pkg, 'info');
      try { await downloadPackage(pkg); ok++; }
      catch (err) { failed++; log('[fail] ' + pkg + ': ' + err.message, 'err'); }
    }
    const label = bulkAborted ? 'Bulk download aborted' : 'Bulk download done';
    log(label + ': ' + ok + ' ok, ' + failed + ' failed', failed || bulkAborted ? 'warn' : 'ok');
  } finally {
    setLogActive(false);
    if (btn) btn.disabled = false;
    cancelBtn.remove();
  }
}

function onAdbStatus(e) {
  const btn = $('#backup-btn');
  if (!btn) return;
  if (e.detail?.connected) { btn.disabled = false; btn.style.display = ''; }
  else { btn.disabled = true; btn.style.display = 'none'; }
}

export function initBackupCard() {
  $('#backup-btn').addEventListener('click', backupAppList);
  $('#backup-import').addEventListener('change', onBackupImport);
  document.addEventListener('adb-status', onAdbStatus);
}
