// Umami analytics — extension-side beacon.
//
// MV3 forbids loading remote scripts, so we can't use the standard
// <script src="…/script.js"> embed. Instead we POST directly to the
// Umami collector at /api/send. Every event is tagged with
// `hostname: 'extension'` so it shows up segmented from the
// apkdl.dietdroid.com website traffic in the Umami dashboard.
//
// Same Umami instance and website-id as the legacy site (so both
// surfaces feed the same project), but filterable by hostname.
//
// Opt-out: set `analytics-opt-out` to true in chrome.storage.local
// (toggled by the checkbox in the Auth card).

const UMAMI_HOST       = 'https://stats.dietdroid.com';
const UMAMI_WEBSITE_ID = '12d179c4-3415-494c-995b-19d1eca1cc2a';
const EXT_HOSTNAME     = 'extension';
const OPT_OUT_KEY      = 'analytics-opt-out';

async function isOptedOut() {
  try {
    if (typeof chrome === 'undefined' || !chrome.storage?.local) return false;
    const r = await chrome.storage.local.get(OPT_OUT_KEY);
    return !!r[OPT_OUT_KEY];
  } catch { return false; }
}

export async function getOptOut() { return isOptedOut(); }

export async function setOptOut(value) {
  try {
    await chrome.storage.local.set({ [OPT_OUT_KEY]: !!value });
  } catch { /* storage failure shouldn't break the UI */ }
}

function payload(extra = {}) {
  return {
    website:  UMAMI_WEBSITE_ID,
    hostname: EXT_HOSTNAME,
    language: navigator.language || 'en',
    screen:   `${screen.width}x${screen.height}`,
    title:    document.title || 'GPlay APK Downloader',
    url:      '/',
    referrer: '',
    ...extra,
  };
}

async function send(type, extra) {
  if (await isOptedOut()) return;
  try {
    await fetch(`${UMAMI_HOST}/api/send`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type, payload: payload(extra) }),
      keepalive: true,
    });
  } catch {
    // Analytics must never break the page.
  }
}

export function trackPageview() {
  return send('event', {});
}

export function trackEvent(name, data) {
  return send('event', { name, ...(data ? { data } : {}) });
}
