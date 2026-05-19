// log.js — Activity Log panel: append entries, in-place progress, clear.
//
// Other modules use `log(msg, type)` and `logWithAction(msg, type, label, fn)`.
// In-flight progress for a chrome.downloads id uses
// `updateProgressEntry(id, text)` and `removeProgressEntry(id)` so the
// same row is mutated rather than the log spammed.

import { $, esc } from './dom.js';

const ICONS = { info: '\u2022', ok: '\u2713', err: '\u2717', warn: '\u25B3', dl: '\u2193' };
let count = 0;
const progressEl = new Map();
const progressLastAt = new Map();

function ensureLogReady() {
  const empty = $('#log-empty');
  if (empty) empty.remove();
}

function makeEntry(type, msg, actionLabel, onAction) {
  const entry = document.createElement('div');
  entry.className = 'log-entry';
  const now = new Date();
  const time = now.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const icon = ICONS[type] || ICONS.info;
  let html =
    '<span class="log-time">' + time + '</span>' +
    '<span class="log-icon ' + type + '">' + icon + '</span>' +
    '<span class="log-msg">' + esc(msg);
  if (actionLabel) html += ' <a href="#" class="log-action" style="color:var(--accent);margin-left:6px">' + esc(actionLabel) + '</a>';
  html += '</span>';
  entry.innerHTML = html;
  if (actionLabel && onAction) {
    entry.querySelector('.log-action').addEventListener('click', (e) => { e.preventDefault(); onAction(); });
  }
  return entry;
}

function bumpBadge() {
  count++;
  const badge = $('#log-badge');
  badge.textContent = String(count);
  badge.classList.remove('empty');
}

export function log(msg, type = 'info') {
  ensureLogReady();
  const scroll = $('#log-scroll');
  scroll.appendChild(makeEntry(type, msg));
  scroll.scrollTop = scroll.scrollHeight;
  bumpBadge();
}

export function logWithAction(msg, type, actionLabel, onAction) {
  ensureLogReady();
  const scroll = $('#log-scroll');
  scroll.appendChild(makeEntry(type, msg, actionLabel, onAction));
  scroll.scrollTop = scroll.scrollHeight;
  bumpBadge();
}

export function clearLog() {
  $('#log-scroll').innerHTML = '<div class="log-empty" id="log-empty">No activity yet</div>';
  count = 0;
  const badge = $('#log-badge');
  badge.textContent = '0';
  badge.classList.add('empty');
}

export function toggleLog() {
  $('#log-panel').classList.toggle('open');
}

export function ensureLogOpen() {
  if (!$('#log-panel').classList.contains('open')) toggleLog();
}

export function setLogActive(active) {
  $('#log-dot').style.display = active ? 'block' : 'none';
}

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
    el = document.createElement('div');
    el.className = 'log-entry';
    el.dataset.progressId = String(id);
    $('#log-scroll').appendChild(el);
    progressEl.set(id, el);
    $('#log-scroll').scrollTop = $('#log-scroll').scrollHeight;
  }
  const now = new Date();
  const time = now.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
  el.innerHTML =
    '<span class="log-time">' + time + '</span>' +
    '<span class="log-icon dl">' + ICONS.dl + '</span>' +
    '<span class="log-msg">' + esc(text) +
    (onCancel ? ' <a href="#" class="log-cancel" style="color:var(--error);margin-left:6px">cancel</a>' : '') +
    '</span>';
  if (onCancel) el.querySelector('.log-cancel')?.addEventListener('click', (e) => { e.preventDefault(); onCancel(); });
}
export function removeProgressEntry(id) {
  const el = progressEl.get(id);
  if (el) { el.remove(); progressEl.delete(id); progressLastAt.delete(id); }
}

// Wire up the log header + clear button on import.
export function initLog() {
  $('#log-header').addEventListener('click', toggleLog);
  $('#log-clear-btn').addEventListener('click', (e) => { e.stopPropagation(); clearLog(); });
}
