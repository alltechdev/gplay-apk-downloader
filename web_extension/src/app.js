// app.js — page entry. Each UI card has its own module; this file
// just wires them up after DOMContentLoaded.

import { $ } from './ui/dom.js';
import { initLog, log } from './ui/log.js';
import { initAuthCard } from './ui/auth-card.js';
import { initAdbCard } from './ui/adb-card.js';
import { initDirectDownloadCard } from './ui/direct-download-card.js';
import { initSearchCard } from './ui/search-card.js';
import { initBackupCard } from './ui/backup-card.js';
import { trackPageview } from './ui/analytics.js';

document.addEventListener('DOMContentLoaded', () => {
  initLog();
  initAdbCard();              // dispatches `adb-status` events that other cards listen for
  initAuthCard();
  initDirectDownloadCard();   // listens for `adb-status` to show the Install button
  initSearchCard();
  initBackupCard();           // listens for `adb-status` to enable Backup App List

  $('#pkg-input').focus();

  // GitHub stars badge (legacy parity).
  fetch('https://api.github.com/repos/alltechdev/gplay-apk-downloader')
    .then((r) => r.json())
    .then((d) => {
      if (d?.stargazers_count != null) {
        $('#gh-stars-count').textContent = d.stargazers_count.toLocaleString();
        $('#gh-stars').style.display = 'inline-flex';
      }
    })
    .catch(() => {});

  log('Extension page loaded', 'ok');

  // Umami pageview — tagged hostname:'extension' to differentiate from website traffic.
  trackPageview();
});
