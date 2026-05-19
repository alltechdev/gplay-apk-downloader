// adb-card.js — "Install to Device" card.
//
// All WebUSB work lives behind `ui/runtime.js#adb()` (loaded from
// vendor/adb-bundle.js). This module is just the UI wrapper plus a
// `adb-status` custom event dispatched on the document so other cards
// can react (Backup enables its Backup-App-List button, Direct Download
// shows the Install-to-Device button).

import { $, h, replace } from './dom.js';
import { icoConnect } from './icons.js';
import { log } from './log.js';
import { adb, adbSupported } from './runtime.js';

let info = null;

function emitStatus(connected) {
  document.dispatchEvent(new CustomEvent('adb-status', { detail: { connected, info } }));
}

function setCard(state, deviceInfo) {
  const card = $('#adb-card');
  const statusEl = $('#adb-status');
  card.classList.toggle('connected', state === 'connected');

  if (state === 'unsupported') {
    replace(statusEl, h('span', { class: 'adb-unsupported' }, 'WebUSB requires Chrome or Edge (and a secure context)'));
    emitStatus(false);
    return;
  }

  if (state === 'connected') {
    const small = h('small', null,
      'Android ' + (deviceInfo.android || '?') + (deviceInfo.serial ? ' · ' + deviceInfo.serial : ''),
    );
    replace(statusEl,
      h('div', { class: 'adb-dot' }),
      h('div', { class: 'adb-device-name' }, deviceInfo.model || 'device', small),
      h('button', { class: 'btn-ghost', onClick: doDisconnect }, 'Disconnect'),
    );
    emitStatus(true);
    return;
  }

  replace(statusEl,
    h('button', { class: 'btn-secondary', onClick: doConnect }, icoConnect(), 'Connect Device'),
  );
  emitStatus(false);
}

async function doConnect() {
  const a = adb();
  if (!a) { log('ADB bundle not loaded', 'err'); return; }
  log('Connecting to device — tap "Allow" if your device prompts', 'info');
  try {
    info = await a.connect();
    setCard('connected', info);
    log('ADB connected: ' + info.model + ' (Android ' + info.android + ')', 'ok');
  } catch (err) {
    log('ADB connect failed: ' + err.message, 'err');
    setCard('disconnected');
  }
}

async function doDisconnect() {
  try { await adb()?.disconnect(); }
  catch (err) { log('ADB disconnect error: ' + err.message, 'warn'); }
  info = null;
  setCard('disconnected');
  log('ADB disconnected', 'info');
}

export function getAdbInfo() { return info; }

export function initAdbCard() {
  if (!adbSupported()) setCard('unsupported');
  else setCard('disconnected');
}
