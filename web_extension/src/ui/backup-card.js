// backup-card.js — Backup app list from ADB + Import JSON + sequential restore.

import { $, h, replace } from './dom.js';
import { icoDownload } from './icons.js';
import { rpc } from './rpc.js';
import { log, setLogActive, ensureLogOpen } from './log.js';
import { downloadPackage } from './direct-download-card.js';
import { getAdbInfo } from './adb-card.js';

let bulkAborted = false;

function msgNode(text, cls) { return h('div', { class: 'msg ' + cls }, text); }

async function backupAppList() {
  if (!window.gplaydlAdb?.connected) { log('Connect a device first', 'warn'); return; }
  const btn = $('#backup-btn');
  btn.disabled = true;
  const resultEl = $('#backup-result');
  replace(resultEl,
    h('div', { class: 'msg info' }, h('span', { class: 'spinner' }), 'Reading installed packages from device…'),
  );
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
    replace(resultEl,
      h('div', { class: 'msg ok' },
        'Saved ' + packages.length + ' packages to ', h('code', null, filename),
        '. Import it later to re-download.',
      ),
    );
  } catch (err) {
    log('Backup failed: ' + err.message, 'err');
    replace(resultEl, msgNode(err.message, 'err'));
  } finally {
    btn.disabled = false;
    setLogActive(false);
  }
}

function renderImported(resultEl, data, available, total) {
  const summary = h('div', { class: 'backup-summary' });
  summary.append(available.length + ' available · ' + (total - available.length) + ' marked unavailable');
  if (data.device) summary.append(' · from ' + data.device);
  if (data.date)   summary.append(' · ' + new Date(data.date).toLocaleDateString());
  summary.append(' · ');
  const allLink = h('a', { href: '#', style: 'color:var(--accent)' }, 'Select all');
  const noneLink = h('a', { href: '#', style: 'color:var(--accent)' }, 'None');
  allLink.addEventListener('click', (ev) => { ev.preventDefault(); document.querySelectorAll('.backup-check:not(:disabled)').forEach((c) => { c.checked = true; }); });
  noneLink.addEventListener('click', (ev) => { ev.preventDefault(); document.querySelectorAll('.backup-check').forEach((c) => { c.checked = false; }); });
  summary.append(allLink, ' / ', noneLink);

  const list = h('div', { class: 'backup-list' });
  for (const r of data.packages) {
    const av = r.available !== false;
    const pkgLabel = r.title
      ? [r.title, ' ', h('span', { style: 'opacity:.5' }, '(' + r.package + ')')]
      : [r.package];
    list.append(
      h('div', { class: 'backup-item' },
        h('input', av
          ? { type: 'checkbox', class: 'backup-check', 'data-pkg': r.package, checked: 'checked' }
          : { type: 'checkbox', class: 'backup-check', 'data-pkg': r.package, disabled: 'disabled' }
        ),
        h('span', { class: 'pkg-name' }, pkgLabel),
        h('span', { class: 'pkg-status ' + (av ? 'available' : 'unavailable') }, av ? 'available' : 'unavailable'),
      ),
    );
  }

  const restoreBtn = h('button', { class: 'btn-primary', id: 'backup-restore-btn', onClick: doRestore },
    icoDownload(), 'Download all selected',
  );
  const actions = h('div', { class: 'backup-actions' }, restoreBtn);

  replace(resultEl, summary, list, actions);
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
    renderImported(resultEl, data, available, data.packages.length);
    log('Imported list with ' + data.packages.length + ' packages (' + available.length + ' marked available)', 'ok');
  } catch (err) {
    replace(resultEl, msgNode('Invalid backup file: ' + err.message, 'err'));
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
  const cancelBtn = h('button', { class: 'btn-ghost', id: 'backup-cancel-btn',
    onClick: () => { cancelBtn.disabled = true; bulkAborted = true; log('Cancel requested — stopping after current app', 'warn'); },
  }, 'Cancel');
  if (parent) parent.appendChild(cancelBtn);

  setLogActive(true);
  ensureLogOpen();
  const format = $('#merge-apks').checked ? 'merge' : 'zip';
  log('Downloading ' + selected.length + ' app(s) sequentially…', 'dl');
  let ok = 0, failed = 0;
  try {
    for (let i = 0; i < selected.length; i++) {
      if (bulkAborted) { log('Bulk aborted after ' + i + ' of ' + selected.length, 'warn'); break; }
      const pkg = selected[i];
      log('[' + (i + 1) + '/' + selected.length + '] ' + pkg, 'info');
      try { await downloadPackage(pkg, format); ok++; }
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
  else                     { btn.disabled = true;  btn.style.display = 'none'; }
}

export function initBackupCard() {
  $('#backup-btn').addEventListener('click', backupAppList);
  $('#backup-import').addEventListener('change', onBackupImport);
  document.addEventListener('adb-status', onAdbStatus);
}
