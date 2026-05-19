// log.js — Activity Log panel: append entries, in-place progress, clear.
//
// Other modules use `log(msg, type)` and `logWithAction(msg, type, label, fn)`.
// In-flight progress for a chrome.downloads id uses
// `updateProgressEntry(id, text)` and `removeProgressEntry(id)` so the
// same row is mutated rather than the log spammed.

import { $, h, replace } from './dom.js';

const ICONS = { info: '\u2022', ok: '\u2713', err: '\u2717', warn: '\u25B3', dl: '\u2193' };
let count = 0;
const progressEl = new Map();
const progressLastAt = new Map();

function ensureLogReady() {
  const empty = $('#log-empty');
  if (empty) empty.remove();
}

function entryNode(type, msg, action) {
  const now = new Date();
  const time = now.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const icon = ICONS[type] || ICONS.info;
  const children = [
    h('span', { class: 'log-time' }, time),
    h('span', { class: 'log-icon ' + type }, icon),
  ];
  const msgSpan = h('span', { class: 'log-msg' }, msg);
  if (action) {
    msgSpan.append(' ');
    msgSpan.append(h('a', {
      href: '#',
      class: action.cancel ? 'log-cancel' : 'log-action',
      style: 'color:var(--' + (action.cancel ? 'error' : 'accent') + ');margin-left:6px',
      onclick: (e) => { e.preventDefault(); action.fn(); },
    }, action.label));
  }
  children.push(msgSpan);
  return h('div', { class: 'log-entry' }, children);
}

function bumpBadge() {
  count++;
  const badge = $('#log-badge');
  badge.textContent = String(count);
  badge.classList.remove('empty');
}

/** Append a log entry. */
export function log(msg, type = 'info') {
  ensureLogReady();
  const scroll = $('#log-scroll');
  scroll.append(entryNode(type, msg));
  scroll.scrollTop = scroll.scrollHeight;
  bumpBadge();
}

/** Append a log entry with a clickable action link. */
export function logWithAction(msg, type, actionLabel, onAction) {
  ensureLogReady();
  const scroll = $('#log-scroll');
  scroll.append(entryNode(type, msg, { label: actionLabel, fn: onAction }));
  scroll.scrollTop = scroll.scrollHeight;
  bumpBadge();
}

export function clearLog() {
  replace($('#log-scroll'), h('div', { class: 'log-empty', id: 'log-empty' }, 'No activity yet'));
  count = 0;
  const badge = $('#log-badge');
  badge.textContent = '0';
  badge.classList.add('empty');
}

export function toggleLog()      { $('#log-panel').classList.toggle('open'); }
export function ensureLogOpen()  { if (!$('#log-panel').classList.contains('open')) toggleLog(); }
export function setLogActive(active) { $('#log-dot').style.display = active ? 'block' : 'none'; }

// Per-download in-place progress.
const PROGRESS_THROTTLE_MS = 750;
export function shouldEmitProgress(id) {
  const now = Date.now();
  const last = progressLastAt.get(id) || 0;
  if (now - last < PROGRESS_THROTTLE_MS) return false;
  progressLastAt.set(id, now);
  return true;
}

export function updateProgressEntry(id, text, onCancel) {
  ensureLogReady();
  let el = progressEl.get(id);
  if (!el) {
    el = h('div', { class: 'log-entry' });
    el.dataset.progressId = String(id);
    $('#log-scroll').append(el);
    progressEl.set(id, el);
    $('#log-scroll').scrollTop = $('#log-scroll').scrollHeight;
  }
  const node = entryNode('dl', text, onCancel ? { label: 'cancel', cancel: true, fn: onCancel } : null);
  replace(el, ...node.childNodes);
}

export function removeProgressEntry(id) {
  const el = progressEl.get(id);
  if (el) { el.remove(); progressEl.delete(id); progressLastAt.delete(id); }
}

export function initLog() {
  $('#log-header').addEventListener('click', toggleLog);
  $('#log-clear-btn').addEventListener('click', (e) => { e.stopPropagation(); clearLog(); });
}
