// install-handler.js — push splits to a connected ADB device via
// `pm install-create/write/commit`. No disk roundtrip; blobs go from
// the CDN straight to the device.

import { $ } from './dom.js';
import { adb, adbConnected } from './runtime.js';
import { log, setLogActive, ensureLogOpen } from './log.js';
import { getDetailsCached, showMsg } from './info-card.js';
import { fetchSplits } from './download-handler.js';

/** Stream `apks` to the device with logging callbacks. */
export async function installToDevice(pkg, details) {
  log('Preparing install for ' + pkg + ' (ADB device connected)', 'dl');
  const apks = await fetchSplits(pkg, details);
  log('Installing on device via ADB…', 'dl');
  await adb().installSplit(apks, (phase, msg) => log('ADB ' + phase + ': ' + msg, 'dl'));
  log('Install complete: ' + details.title + ' v' + details.versionString, 'ok');
}

async function doInstall() {
  const pkg = $('#pkg-input').value.trim();
  if (!pkg) { showMsg('enter a package name first', 'err'); return; }
  if (!adbConnected()) { log('Connect a device first', 'warn'); return; }
  ensureLogOpen();
  setLogActive(true);
  try {
    const d = await getDetailsCached(pkg);
    log('Install: ' + d.title + ' v' + d.versionString + ' (vc=' + d.versionCode + ')', 'info');
    await installToDevice(pkg, d);
  } catch (err) {
    log('Install failed: ' + err.message, 'err');
  } finally { setLogActive(false); }
}

function updateInstallBtnVisibility() {
  const btn = $('#install-btn');
  if (btn) btn.style.display = adbConnected() ? '' : 'none';
}

export function initInstallHandler() {
  $('#install-btn').addEventListener('click', doInstall);
  document.addEventListener('adb-status', updateInstallBtnVisibility);
  updateInstallBtnVisibility();
}
