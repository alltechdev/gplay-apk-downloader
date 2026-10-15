// direct-download-card.js — wires together the three sub-modules that
// share the Direct Download card UI (info-card / download-handler /
// install-handler). Also owns `triggerDownloadFor`: the cross-card entry
// point used by the Search card.

import { $, h } from './dom.js';
import { adbConnected } from './runtime.js';
import { log, setLogActive, ensureLogOpen } from './log.js';
import { initInfoCard, fetchAndShowInfo, clearDetailsCache, showMsg } from './info-card.js';
import { initDownloadHandler, downloadAsSingleFile, downloadPackage } from './download-handler.js';
import { initInstallHandler, installToDevice } from './install-handler.js';

export { downloadPackage };

/**
 * External-trigger entry point (e.g. clicking Download on a search result).
 * Mirrors what the user sees from typing a package name + clicking the
 * Direct Download button:
 *   1. Fill #pkg-input.
 *   2. Open the Activity Log.
 *   3. Render the Info block in #info-result.
 *   4. Install to device (if ADB connected) or save the single file.
 *
 * @param {string} pkg
 */
export async function triggerDownloadFor(pkg) {
  $('#pkg-input').value = pkg;
  ensureLogOpen();
  setLogActive(true);
  showMsg([h('span', { class: 'spinner' }), 'looking up ' + pkg + '…']);
  try {
    const { details, installed } = await fetchAndShowInfo(pkg);
    log('Info ok: ' + details.title + ' v' + details.versionString + (installed ? ' · device has v' + installed.versionName : ''), 'ok');
    if (adbConnected()) {
      log('ADB device connected — installing to device', 'info');
      await installToDevice(pkg, details);
    } else {
      const fmt = $('#merge-apks').checked ? 'merge' : 'zip';
      await downloadAsSingleFile(pkg, details, fmt);
    }
  } catch (err) {
    clearDetailsCache();
    showMsg(err.message, 'err');
    log('Download failed: ' + err.message, 'err');
  } finally {
    setLogActive(false);
  }
}

export function initDirectDownloadCard() {
  initInfoCard();
  initDownloadHandler();
  initInstallHandler();
}
