// adb-card.js — "Install to Device" card.
//
// All WebUSB work lives in window.gplaydlAdb (loaded from
// vendor/adb-bundle.js). This module is just the UI wrapper plus a
// `adb-status` custom event dispatched on the document so other cards
// can react (Backup enables its Backup-App-List button, Direct Download
// shows the Install-to-Device button).

import { $, esc } from './dom.js';
import { log } from './log.js';

let info = null;

function emitStatus(connected) {
  document.dispatchEvent(new CustomEvent('adb-status', { detail: { connected, info } }));
}

function setCard(state, deviceInfo) {
  const card = $('#adb-card');
  const statusEl = $('#adb-status');
  card.classList.toggle('connected', state === 'connected');
  if (state === 'unsupported') {
    statusEl.innerHTML = '<span class="adb-unsupported">WebUSB requires Chrome or Edge (and a secure context)</span>';
    emitStatus(false);
    return;
  }
  if (state === 'connected') {
    statusEl.innerHTML =
      '<div class="adb-dot"></div>' +
      '<div class="adb-device-name">' + esc(deviceInfo.model || 'device') +
      '<small>Android ' + esc(deviceInfo.android || '?') +
      (deviceInfo.serial ? ' · ' + esc(deviceInfo.serial) : '') + '</small></div>' +
      '<button class="btn-ghost" id="adb-disconnect-btn">Disconnect</button>';
    $('#adb-disconnect-btn').addEventListener('click', doDisconnect);
    emitStatus(true);
    return;
  }
  statusEl.innerHTML =
    '<button class="btn-secondary" id="adb-connect-btn">' +
    '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M7 2v4M17 2v4M2 12h4M18 12h4M4.93 4.93l2.83 2.83M16.24 4.93l-2.83 2.83M12 8v4M12 16v.01"/><circle cx="12" cy="12" r="6"/></svg>' +
    'Connect Device' +
    '</button>';
  $('#adb-connect-btn').addEventListener('click', doConnect);
  emitStatus(false);
}

async function doConnect() {
  if (!window.gplaydlAdb) { log('ADB bundle not loaded', 'err'); return; }
  log('Connecting to device — tap "Allow" if your device prompts', 'info');
  try {
    info = await window.gplaydlAdb.connect();
    setCard('connected', info);
    log('ADB connected: ' + info.model + ' (Android ' + info.android + ')', 'ok');
  } catch (err) {
    log('ADB connect failed: ' + err.message, 'err');
    setCard('disconnected');
  }
}

async function doDisconnect() {
  try { await window.gplaydlAdb.disconnect(); }
  catch (err) { log('ADB disconnect error: ' + err.message, 'warn'); }
  info = null;
  setCard('disconnected');
  log('ADB disconnected', 'info');
}

export function getAdbInfo() { return info; }

export function initAdbCard() {
  if (!window.gplaydlAdb || !window.gplaydlAdb.supported) setCard('unsupported');
  else setCard('disconnected');
}
