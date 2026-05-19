# Architecture

Concrete map of the extension's moving parts. Keep this current as code lands.

```
┌──────────────────────────────┐   chrome.runtime.sendMessage   ┌─────────────────────────┐
│  Extension page (index.html) │ ──────────────────────────────▶│  Service Worker         │
│  app.js                      │ ◀── broadcasts: auth.event,    │  background.js          │
│                              │      download.event             │  (single file by design)│
└──────────────────────────────┘                                 └─────────────┬───────────┘
                                                                                │
                                                                                │ fetch() with
                                                                                │ Authorization +
                                                                                │ X-DFE-*
                                                                                ▼
                                              ┌─────────────────────────────────────────────────┐
                                              │  declarativeNetRequest dynamic rules            │
                                              │  - dispenser (id 1): set Aurora UA, strip Origin │
                                              │  - /fdfe/*  (id 2): set Play UA, strip Origin    │
                                              │  - cookies  (id 100+): set Cookie per-URL        │
                                              └────────────┬────────────────────────────────────┘
                                                           │
                                                           ▼
                                              ┌─────────────────────────────────────────────────┐
                                              │  Network:                                       │
                                              │   auroraoss.com/api/auth        (sign-in)        │
                                              │   android.clients.google.com/fdfe (details,     │
                                              │     purchase, delivery — protobuf)               │
                                              │   <Google APK CDN>              (binary APK)     │
                                              └─────────────────────────────────────────────────┘
```

## Why single-file service worker

Early testing with `"type": "module"` in `background` plus relative `import`s left the SW unregistered in Chrome 144 (no `service_worker` target appeared, page got no responses). Single-file with no module mechanics has been reliable across every e2e run since. Source code is grouped into clearly labelled sections.

The same code's pure-logic parts are also published as ES modules in `src/modules/` for unit tests in Node (`tests/unit/`). When the two diverge, the SW is the source of truth and the modules get re-synced.

## Why a tab page, not a popup

The legacy site's visual style (cards, log panel, dark theme) doesn't compress into 360×600. Click the toolbar icon → `chrome.action.onClicked` → open `index.html` in a new tab (reuse if already open).

## How forbidden headers get set

`fetch()` from extension code can't set `User-Agent`, `Origin`, or `Cookie` — they're in the browser's forbidden-header list. We use `declarativeNetRequest` `modifyHeaders` actions to set them at the network layer, narrowly scoped by `urlFilter`:

| Rule id | URL filter                              | Purpose |
|---------|-----------------------------------------|---------|
| 1       | `||auroraoss.com/api/auth`              | Set Aurora UA, strip Origin (or Cloudflare 403s). |
| 2       | `||android.clients.google.com/fdfe`     | Set per-profile Android-Finsky UA, strip Origin. UA updates after each sign-in to match the profile. |
| 100+    | exact download URL                      | Attach `Cookie: name=value; …` from `downloadAuthCookie[]` returned by `/delivery`. Each in-flight download gets its own id. |

Rules are dynamic (`chrome.declarativeNetRequest.updateDynamicRules`) and re-installed on `onInstalled`, `onStartup`, and SW boot.

## Protobuf handling

No `protobufjs` dependency. A ~70-line hand-rolled decoder in `src/modules/pb-decode.js` (also inlined into the SW) handles wire types 0, 2, 1, 5. Field-number schemas for `ResponseWrapper`, `Payload`, `DetailsResponse`, `DocV2`, `AppDetails`, `DeliveryResponse`, `AndroidAppDeliveryData`, `SplitDeliveryData`, `HttpCookie` are hand-written from the `gpapi` Python descriptor (cross-checked against Aurora Store's proto). Unknown fields are skipped.

## RPC contract

```
auth.status   → { signedIn, profileKey, profileLabel, gsfId, email, ageMs, stale }
auth.signIn   → same as auth.status; broadcasts auth.event { phase: 'try'|'reject'|'ok'|'done'|'fail' }
auth.signOut  → { signedIn: false }
app.details   { packageName }                  → { title, versionCode, versionString, installationSize, … }
app.delivery  { packageName, versionCode }     → { downloadUrl, sha1, cookies[], splits[] }
app.download  { packageName, versionCode }     → { dirPrefix, files: [{ id, file }] }
                                                  broadcasts download.event { phase, file, url, size, id }
```

## Storage

`chrome.storage.local`:
- `gplaydl.auth` — the full auth response from AuroraOSS (authToken, gsfId, dfeCookie, deviceInfoProvider, plus internal `_profileKey`, `_profileLabel`, `_obtainedAt`).

That's it. No tokens in localStorage, no IndexedDB. `chrome.storage.local` is sandboxed per extension and not accessible to web pages.

## Security posture

- **Permissions requested**: `storage` (for the auth token), `downloads` (for the APK save), `declarativeNetRequest` + `declarativeNetRequestWithHostAccess` (for header injection on host-permission URLs only).
- **Host permissions** are narrow: AuroraOSS dispenser, Play API endpoints, Google Fonts. Nothing else.
- **No `tabs`/`scripting`/`activeTab`** permissions — we don't read or inject into other pages.
- **No `eval`**, no `unsafe-eval` in CSP. `unsafe-inline` is allowed for **style only**, not script.
- **Package-name validation**: every `app.*` RPC validates the package name against `/^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$/` before it's sent anywhere.
- **DNR rules** are narrowly scoped by `urlFilter`. We never rewrite headers globally.
- **Auth token never leaves the extension**: only sent to AuroraOSS (mint) and Google (consume).
