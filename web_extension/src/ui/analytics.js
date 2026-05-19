// Umami analytics — extension-side beacon.
//
// MV3 forbids loading remote scripts, so we can't use the standard
// <script src="…/script.js"> embed. Instead we POST directly to the
// Umami collector at /api/send.
//
// The extension has its own dedicated Umami website entry (separate
// website-id from the apkdl.dietdroid.com site), so extension traffic
// shows up under its own row in the Umami dashboard rather than mixed
// into the website's stats.
//
// To remove analytics entirely, delete the `trackPageview()` call in
// `src/app.js` (and optionally this file).

const UMAMI_HOST       = 'https://stats.dietdroid.com';
const UMAMI_WEBSITE_ID = '9875f721-0411-4cbd-9702-87e6bb8be189';
const EXT_HOSTNAME     = 'extension.gplaydl';
const EXT_URL_BASE     = 'https://extension.gplaydl';

function payload(path, extra = {}) {
  return {
    website:  UMAMI_WEBSITE_ID,
    hostname: EXT_HOSTNAME,
    language: navigator.language || 'en',
    screen:   `${screen.width}x${screen.height}`,
    title:    document.title || 'GPlay APK Downloader',
    url:      EXT_URL_BASE + (path || '/'),
    referrer: '',
    ...extra,
  };
}

async function send(payloadFields) {
  try {
    await fetch(`${UMAMI_HOST}/api/send`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 'event', payload: payloadFields }),
      keepalive: true,
    });
  } catch {
    // Analytics must never break the page.
  }
}

/** Single anonymous pageview ping fired on page load. */
export function trackPageview() {
  return send(payload('/'));
}

/** Fire a named custom event (e.g. trackEvent('download', { pkg })). */
export function trackEvent(name, data) {
  return send(payload('/event', { name, ...(data ? { data } : {}) }));
}
