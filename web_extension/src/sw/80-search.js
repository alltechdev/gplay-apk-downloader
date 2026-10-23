// 80-search.js — Play Store HTML search scrape.
//
// Mirrors legacy server.py:/api/search. Three extraction strategies in
// priority order: featured app, related apps, JSON-embedded packages.

const _decodeHtml = (s) => s.replace(/&amp;/g, '&').replace(/&#39;/g, "'").replace(/&quot;/g, '"');
const _upgradeIcon = (url) => url.replace(/=s\d+/, '=s128').replace(/=w\d+/, '=s128');

/**
 * Search the Play Store by HTML scrape. Returns up to 5 results.
 * @param {{query:string}} args
 * @returns {Promise<{results:{package:string,title:string,icon:string}[]}>}
 */
async function appSearch({ query }) {
  if (typeof query !== 'string' || !query.trim()) throw new ValidationError('query required');
  if (query.length > 200) throw new ValidationError('query too long');
  const url = SEARCH_URL + '?q=' + encodeURIComponent(query) + '&c=apps&hl=en&gl=us';
  const res = await fetch(url, { credentials: 'omit', referrer: 'https://play.google.com/' });
  if (!res.ok) throw new NetworkError('Play search HTTP ' + res.status, res.status);
  if (res.url.includes('accounts.google.com')) throw new PlayApiError('Play Store redirected to sign-in — try a different query');
  const html = await res.text();
  const results = [];
  const seen = new Set();

  // Method 1a: featured (vWM94c)
  const featured = html.match(
    /href="\/store\/apps\/details\?id=([^"&]+)"[^>]*>[\s\S]*?<img[^>]*src="(https:\/\/play-lh\.googleusercontent\.com\/[^"]+)"[^>]*>[\s\S]*?<div class="vWM94c">([^<]+)<\/div>/,
  );
  if (featured) {
    const [, pkg, icon, title] = featured;
    if (!seen.has(pkg)) {
      seen.add(pkg);
      results.push({ package: pkg, title: _decodeHtml(title), icon: _upgradeIcon(icon) });
    }
  }

  // Method 1b: related apps (Epkrse)
  const relRe = /href="\/store\/apps\/details\?id=([^"&]+)"[^>]*>[\s\S]*?<img[^>]*src="(https:\/\/play-lh\.googleusercontent\.com\/[^"=]+=[sw]\d+[^"]*)"[^>]*>[\s\S]*?class="Epkrse\s*">([^<]+)<\/div>/g;
  let m;
  while ((m = relRe.exec(html)) !== null && results.length < 5) {
    const [, pkg, icon, title] = m;
    if (seen.has(pkg)) continue;
    seen.add(pkg);
    results.push({ package: pkg, title: _decodeHtml(title), icon: _upgradeIcon(icon) });
  }

  // Method 2: JSON-embedded packages.
  if (results.length < 3) {
    const pkgRe = /\[\["(com\.[a-zA-Z0-9_.]+)",7\],\[null,2/g;
    let pm;
    while ((pm = pkgRe.exec(html)) !== null && results.length < 5) {
      const pkg = pm[1];
      if (seen.has(pkg)) continue;
      const titleRe = new RegExp(
        '\\[\\["' + pkg.replace(/[.]/g, '\\.') + '",7\\][\\s\\S]*?\\],"([^"]+)",\\["[0-9.]+",\\s*[0-9.]+',
      );
      const iconRe = new RegExp(
        '\\[\\["' + pkg.replace(/[.]/g, '\\.') + '",7\\],\\[null,2,(?:null|\\[[0-9]+,[0-9]+\\]),\\[null,null,"(https://play-lh\\.googleusercontent\\.com/[^"]+)"\\]',
      );
      const titleM = html.match(titleRe);
      const iconM = html.match(iconRe);
      seen.add(pkg);
      results.push({
        package: pkg,
        title: titleM ? titleM[1].replace(/\\u0026/g, '&').replace(/\\u0027/g, "'") : pkg,
        icon: iconM ? _upgradeIcon(iconM[1]) : '',
      });
    }
  }
  return { results };
}
