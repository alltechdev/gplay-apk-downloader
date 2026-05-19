// search-card.js — Play Store search via SW HTML scrape.
// Clicking a result fills the pkg input and kicks off downloadPackage.

import { $, h, replace } from './dom.js';
import { rpc } from './rpc.js';
import { log } from './log.js';
import { downloadPackage } from './direct-download-card.js';

function resultRow(app, onClick) {
  const children = [];
  if (app.icon) children.push(h('img', { class: 'app-icon', src: app.icon, alt: '', loading: 'lazy' }));
  children.push(
    h('div', { class: 'app-info' },
      h('h3', null, app.title || app.package),
      h('div', { class: 'pkg' }, app.package),
    ),
    h('div', { class: 'app-actions' },
      h('button', { class: 'btn-primary', onClick }, 'Download'),
    ),
  );
  return h('div', { class: 'app-item' }, children);
}

async function doSearch() {
  const q = $('#search-q').value.trim();
  if (!q) return;
  const el = $('#search-results');
  replace(el,
    h('div', { class: 'loading' },
      h('span', { class: 'spinner' }), 'Searching…'
    ),
  );
  log('Searching for "' + q + '"…', 'info');
  try {
    const d = await rpc('app.search', { query: q });
    if (!d?.results?.length) {
      replace(el, h('div', { class: 'msg info' }, 'No results found'));
      log('No results for "' + q + '"', 'warn');
      return;
    }
    log('Found ' + d.results.length + ' results for "' + q + '"', 'ok');
    replace(el, d.results.map((a) =>
      resultRow(a, async () => {
        $('#pkg-input').value = a.package;
        try { await downloadPackage(a.package); }
        catch (err) { log('Download failed: ' + err.message, 'err'); }
      })
    ));
  } catch (err) {
    replace(el, h('div', { class: 'msg err' }, err.message));
    log('Search failed: ' + err.message, 'err');
  }
}

export function initSearchCard() {
  $('#search-btn').addEventListener('click', doSearch);
  $('#search-q').addEventListener('keypress', (e) => { if (e.key === 'Enter') doSearch(); });
}
