// info-card.js — Info lookup + render + #info-result message helper.
//
// Owns the `currentDetails` cache: once `Info` (or `triggerDownloadFor`)
// has fetched details for a package, Download/Install on the same pkg
// can skip the round-trip via `getDetailsCached(pkg)`.

import { $, h, replace, fmtSize } from './dom.js';
import { rpc } from './rpc.js';
import { adb } from './runtime.js';
import { log } from './log.js';

let currentDetails = null;

/** Replace the #info-result block with a message node. */
export function showMsg(content, cls = 'info') {
  const box = h('div', { class: 'msg ' + cls });
  if (content instanceof Node) box.append(content);
  else if (Array.isArray(content)) for (const c of content) box.append(c);
  else box.append(String(content));
  replace($('#info-result'), box);
}

/** Look up the currently installed version on the connected ADB device, if any. */
async function getInstalledVersion(pkg) {
  const a = adb();
  if (!a?.connected) return null;
  try {
    const out = await a.shell("dumpsys package " + pkg + " | grep -E 'versionName|versionCode' | head -2");
    const vn = out.match(/versionName=([^\s]+)/)?.[1];
    const vc = out.match(/versionCode=([0-9]+)/)?.[1];
    if (!vn && !vc) return null;
    return { versionName: vn || '?', versionCode: vc ? Number(vc) : 0 };
  } catch { return null; }
}

const ARCH_LABEL = { 'arm64-v8a': 'ARM64 (modern)', 'armeabi-v7a': 'ARMv7 (legacy)' };

/** Render splits like legacy: `name (size)` plus `[asset pack]` for non-config splits. */
function describeSplits(splits) {
  return splits.map((s) => {
    const name = typeof s === 'string' ? s : s.name;
    const size = typeof s === 'string' ? null : s.size;
    let label = name + (size ? ' (' + fmtSize(size) + ')' : '');
    if (!name.startsWith('config.')) label += ' [asset pack]';
    return label;
  });
}

function infoBody(d, installed, arch) {
  const splits = (d.splitId || []).map((name) => ({ name, size: 0 }));
  const obbSplits = splits.filter((s) => !s.name.startsWith('config.'));
  const obbLabel  = obbSplits.length
    ? ' \u00b7 includes ' + obbSplits.map((s) => s.name).join(', ')
    : '';
  const archLabel = ARCH_LABEL[arch] || arch || '';

  // Legacy line: <title>\n v<ver> · <arch> · <size> · includes <obb>
  const rows = [
    h('strong', null, d.title),
    h('br'),
    'v' + d.versionString
      + (archLabel ? ' \u00b7 ' + archLabel : '')
      + ' \u00b7 ' + fmtSize(d.installationSize)
      + obbLabel,
  ];

  if (splits.length) {
    const totalFiles = 1 + splits.length;
    const splitNames = describeSplits(splits).join(', ');
    rows.push(
      h('br'),
      h('span', { style: 'font-family:var(--font-mono);font-size:11px;opacity:0.7' },
        totalFiles + ' files: ' + splitNames),
    );
  }

  if (installed) {
    const tag = d.versionCode > installed.versionCode
      ? h('span', { style: 'color:var(--accent);font-weight:600' }, ' (update available)')
      : d.versionCode === installed.versionCode
        ? h('span', { style: 'color:var(--success)' }, ' (up to date)')
        : h('span', { style: 'color:#fbbf24' }, ' (device has newer)');
    rows.push(h('br'), 'Device: v' + installed.versionName, tag);
  }
  return rows;
}

/** Fetch details + installed version, cache details, render to #info-result. */
export async function fetchAndShowInfo(pkg) {
  const [d, installed] = await Promise.all([
    rpc('app.details', { packageName: pkg }),
    getInstalledVersion(pkg),
  ]);
  currentDetails = d;
  const arch = $('#arch-select')?.value;
  showMsg(infoBody(d, installed, arch), 'ok');
  return { details: d, installed };
}

/** Return cached details if they match `pkg`, else fetch fresh. */
export async function getDetailsCached(pkg) {
  if (currentDetails && currentDetails.packageName === pkg) return currentDetails;
  const d = await rpc('app.details', { packageName: pkg });
  currentDetails = d;
  return d;
}

export function clearDetailsCache() { currentDetails = null; }

async function doInfo() {
  const pkg = $('#pkg-input').value.trim();
  if (!pkg) { showMsg('enter a package name first', 'err'); return; }
  showMsg([h('span', { class: 'spinner' }), 'looking up ' + pkg + '…']);
  log('Info: ' + pkg, 'info');
  try {
    const { details, installed } = await fetchAndShowInfo(pkg);
    log('Info ok: ' + details.title + ' v' + details.versionString + (installed ? ' · device has v' + installed.versionName : ''), 'ok');
  } catch (err) {
    clearDetailsCache();
    showMsg(err.message, 'err');
    log('Info failed: ' + err.message, 'err');
  }
}

export function initInfoCard() {
  $('#info-btn').addEventListener('click', doInfo);
  $('#pkg-input').addEventListener('keypress', (e) => { if (e.key === 'Enter') doInfo(); });
}
