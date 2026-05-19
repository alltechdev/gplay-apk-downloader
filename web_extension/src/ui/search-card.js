// search-card.js — Play Store search via SW HTML scrape.
// Clicking a result fills the pkg input and kicks off doDownload.

import { $, esc } from './dom.js';
import { rpc } from './rpc.js';
import { log } from './log.js';
import { downloadPackage } from './direct-download-card.js';

async function doSearch() {
  const q = $('#search-q').value.trim();
  if (!q) return;
  const el = $('#search-results');
  el.innerHTML = '<div class="loading"><span class="spinner"></span>Searching…</div>';
  log('Searching for "' + q + '"…', 'info');
  try {
    const d = await rpc('app.search', { query: q });
    if (!d?.results?.length) {
      el.innerHTML = '<div class="msg info">No results found</div>';
      log('No results for "' + q + '"', 'warn');
      return;
    }
    log('Found ' + d.results.length + ' results for "' + q + '"', 'ok');
    el.innerHTML = d.results.map((a) =>
      '<div class="app-item">' +
      (a.icon ? '<img class="app-icon" src="' + esc(a.icon) + '" alt="" loading="lazy">' : '') +
      '<div class="app-info"><h3>' + esc(a.title || a.package) + '</h3>' +
      '<div class="pkg">' + esc(a.package) + '</div></div>' +
      '<div class="app-actions"><button class="btn-primary" data-pkg="' + esc(a.package) + '">Download</button></div>' +
      '</div>'
    ).join('');
    el.querySelectorAll('button[data-pkg]').forEach((b) => {
      b.addEventListener('click', async () => {
        $('#pkg-input').value = b.dataset.pkg;
        try { await downloadPackage(b.dataset.pkg); }
        catch (err) { log('Download failed: ' + err.message, 'err'); }
      });
    });
  } catch (err) {
    el.innerHTML = '<div class="msg err">' + esc(err.message) + '</div>';
    log('Search failed: ' + err.message, 'err');
  }
}

export function initSearchCard() {
  $('#search-btn').addEventListener('click', doSearch);
  $('#search-q').addEventListener('keypress', (e) => { if (e.key === 'Enter') doSearch(); });
}
