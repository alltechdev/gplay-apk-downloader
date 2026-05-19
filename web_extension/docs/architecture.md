# Architecture

How the moving parts fit together. Pair with `docs/source-layout.md` for the file map.

```
┌──────────────────────────────────────┐
│ Extension page (index.html)          │
│  ┌──────────────────────────────┐    │   chrome.runtime.sendMessage
│  │ ui/auth-card        ui/log   │    │ ─────────────────────────────▶ ┌──────────────────────────┐
│  │ ui/adb-card         ui/dom   │    │                                │  Service Worker          │
│  │ ui/direct-download  ui/rpc   │    │ ◀── broadcasts:                │  background.js (21 LOC)  │
│  │ ui/search           …         │    │     auth.event,                │  importScripts:          │
│  │ ui/backup                     │   │     download.event              │   sw/00-config           │
│  └──────────────────────────────┘    │                                │   sw/10-utils            │
│  app.js (34-line ES-module entry)   │                                 │   sw/20-pb               │
│                                      │                                │   sw/30-storage          │
│  vendor/adb-bundle.js               │                                 │   sw/40-dnr              │
│   → window.gplaydlAdb (WebUSB ADB)  │                                 │   sw/50-auth             │
│  vendor/apk-tools-bundle.js         │                                 │   sw/60-play-api         │
│   → window.gplaydlApkTools (merge,  │                                 │   sw/70-downloads        │
│     sign, zipalign, zip bundle)     │                                 │   sw/80-search           │
└──────────────────────────────────────┘                                │   sw/90-action           │
                                                                        │   sw/99-rpc              │
                                                                        └──────────────┬───────────┘
                                                                                       │
                                                                                       │ fetch() with
                                                                                       │ Authorization +
                                                                                       │ X-DFE-*
                                                                                       ▼
                                                                ┌─────────────────────────────────────────────────┐
                                                                │  declarativeNetRequest dynamic rules            │
                                                                │  - dispenser (id 1): set Aurora UA, strip Origin │
                                                                │  - /fdfe/*  (id 2): set Play UA, strip Origin    │
                                                                │  - CDN      (id 3): strip Origin on *.gvt1.com   │
                                                                │  - cookies  (id 100+): set Cookie per-URL        │
                                                                └────────────┬────────────────────────────────────┘
                                                                             │
                                                                             ▼
                                                                ┌─────────────────────────────────────────────────┐
                                                                │  Network:                                       │
                                                                │   auroraoss.com/api/auth        (sign-in)        │
                                                                │   android.clients.google.com/fdfe (details,     │
                                                                │     purchase, delivery — protobuf)               │
                                                                │   play.google.com/store/search  (HTML scrape)    │
                                                                │   <Google APK CDN>              (binary APK)     │
                                                                └─────────────────────────────────────────────────┘
```

## Source layout

**Service worker** is split into eleven `sw/NN-*.js` files loaded in numeric order via `importScripts`. The numeric prefix encodes the dependency order — config first, dispatcher last. Each file declares its functions at top level and they're visible to every later file via the SW's shared global scope. No `import`/`export`; this avoids Chrome 144's flakiness with MV3 module service workers.

| File | Responsibility |
|------|----------------|
| `sw/00-config.js`  | Constants: URLs, storage keys, DNR rule IDs, hardcoded DFE headers, TTLs. |
| `sw/10-utils.js`   | `broadcast`, `validatePackageName`, `sanitizeFilenameSegment`, `loadProfilesJson`. |
| `sw/20-pb.js`      | `pbDecode` (wire types 0/1/2/5) + Play API message schemas (`PB_ResponseWrapper`, `PB_AppDetails`, …). |
| `sw/30-storage.js` | `chrome.storage` wrappers, arch preference, download↔rule map persisted in `chrome.storage.session`. |
| `sw/40-dnr.js`     | Static DNR rules (dispenser / fdfe / CDN) + per-download cookie rule allocator. |
| `sw/50-auth.js`    | AuroraOSS sign-in (iterates priority profiles by arch), sign-out, status, arch.set. |
| `sw/60-play-api.js`| `fdfeGet` / `fdfePost` with 401 auto-retry; `appDetails`, `appPurchase`, `appDelivery`. |
| `sw/70-downloads.js`| `chrome.downloads.onChanged` lifecycle; `queueDownloadFile`, `cancelDownload`, `showDownload`, `appDownload`, `appPrepareInstall`, `releaseRules`. |
| `sw/80-search.js`  | `appSearch` — HTML scrape of `play.google.com/store/search`, three extraction strategies. |
| `sw/90-action.js`  | Toolbar `chrome.action.onClicked` → open `index.html`; `installCoreDnrRules` on `onInstalled` / `onStartup` / boot. |
| `sw/99-rpc.js`     | The RPC table; routes message types to SW handlers. |

**Extension page** is one HTML file plus eight ES-module `ui/*.js` files. `app.js` is a 34-line entry that imports each card's `init*()` function. Cross-card communication happens via a single `adb-status` `CustomEvent` (no import cycles).

| File | Responsibility |
|------|----------------|
| `ui/dom.js`                | `$`, `$$`, `esc`, `fmtSize`. |
| `ui/rpc.js`                | `rpc(type, payload)` — normalises SW response into a Promise. |
| `ui/log.js`                | Activity Log: append, in-place progress, clear, toggle, "show in folder" action, per-download cancel link. |
| `ui/auth-card.js`          | Auth status display + sign-in/out + arch dropdown (auto re-auth on change). |
| `ui/adb-card.js`           | WebUSB connect/disconnect; dispatches `adb-status` on document. |
| `ui/direct-download-card.js`| Info / Download / Install-to-Device. Exports `downloadPackage(pkg)` used by search + backup. |
| `ui/search-card.js`        | Renders search results; clicking Download fills `#pkg-input` and calls `downloadPackage`. |
| `ui/backup-card.js`        | Backup App List (ADB) + Import List + sequential restore with cancel. |

## How forbidden headers get set

`fetch()` from extension code can't set `User-Agent`, `Origin`, or `Cookie` (they're on the browser's forbidden-header list). We rewrite them at the network layer via `declarativeNetRequest` `modifyHeaders` actions, narrowly scoped:

| Rule id | URL filter                              | Purpose |
|---------|-----------------------------------------|---------|
| 1       | `||auroraoss.com/api/auth`              | Aurora UA + strip Origin (Cloudflare rejects without). |
| 2       | `||android.clients.google.com/fdfe`     | Per-profile Android-Finsky UA + strip Origin. UA refreshed after each sign-in. |
| 3       | `gvt1.com` / `googleusercontent.com` / `play.googleapis.com` | Strip Origin on CDN redirects. |
| 100+    | exact download URL                      | Inject `Cookie: name=value; …` from `downloadAuthCookie[]`. Reused across SW restarts via `chrome.storage.session`. |

## RPC contract

```
auth.status   → { signedIn, arch, profileKey, profileLabel, profileArch, gsfId, email, ageMs, stale }
auth.signIn   { arch? } → same as auth.status; broadcasts auth.event { phase, … }
auth.signOut  → { signedIn: false, arch }
arch.set      { arch }   → auth.status
app.details   { packageName } → { title, versionCode, versionString, installationSize, splitId[], … }
app.delivery  { packageName, versionCode } → { downloadUrl, sha1, cookies[], splits[] }
app.download  { packageName, versionCode } → { dirPrefix, files: [{ id, file, ruleId }] }
app.prepareInstall { packageName, versionCode } → { files[], ruleIds[] }    // page-side fetch (zip/merge/ADB)
app.releaseRules   { ruleIds }       → { released }                          // clean up after page fetch
app.cancelDownload { id }            → { ok }
app.showDownload   { id }            → { ok }
app.search    { query }              → { results: [{ package, title, icon }] }
```

Broadcast event names (SW → all open pages):
- `auth.event { phase: 'start'|'try'|'reject'|'ok'|'done'|'fail'|'error'|'refresh', … }`
- `download.event { phase: 'purchase'|'delivery'|'start'|'queued'|'progress'|'complete'|'interrupted', … }`

## Bundles and the merge / sign pipeline

```
splits download (Play CDN) ─▶ Page Blob[] ─▶ apk-merger.js:
                                                strip META-INF/*
                                                base wins on path conflict
                                                axml-patcher.js: patch AndroidManifest.xml
                                                  add com.android.dynamic.apk.fused.modules
                                                zipalign.js: emit aligned ZIP (4-byte default,
                                                  4096-byte for lib/*/*.so)
                                              ▶ apk-signer.js:
                                                v1 (JAR): MANIFEST.MF + CERT.SF + CERT.RSA (PKCS#7)
                                                v2 (APK Signing Scheme v2): id 0x7109871a block
                                                v3 (id 0xf05368c0 block, with min/max SDK)
                                              ▶ Blob ▶ <a download>
```

All four pieces are pure JS, no external CLI. The protobuf decoder, AXML patcher, and zipalign are unit-tested; the AXML patcher is cross-validated against the legacy Python source for byte-identical output.

## Storage

`chrome.storage.local`:
- `gplaydl.auth` — full auth response from AuroraOSS plus internal `_profileKey`, `_profileLabel`, `_profileArch`, `_obtainedAt`.
- `gplaydl.arch` — current arch preference (`arm64-v8a` or `armeabi-v7a`).

`chrome.storage.session`:
- `gplaydl.downloadRules` — map from `chrome.downloads.id` → DNR rule id so SW restarts mid-download don't orphan rules.

No `localStorage`, no `IndexedDB`. Both stores are sandboxed per extension and never reach the network.

## Security posture

- **Permissions requested**: `storage` (auth + arch + dl→rule map), `downloads` (chrome.downloads.{download, cancel, show}), `declarativeNetRequest` + `declarativeNetRequestWithHostAccess` (per-URL header rewriting on host-permission targets only).
- **Host permissions** are narrow and explicit (`auroraoss.com/api/auth`, `android.clients.google.com`, `play.googleapis.com`, `play.google.com`, `*.gvt1.com`, `*.googleusercontent.com`, `fonts.{googleapis,gstatic}.com`, `api.github.com`).
- **No `tabs`/`scripting`/`activeTab`**, no content scripts, no telemetry.
- **No `eval`**, no `unsafe-eval`. `unsafe-inline` is allowed for **style only**, not script.
- **Package-name validation** at every `app.*` RPC entry point.
- **DNR rules** are narrowly scoped by `urlFilter` / `requestDomains`. No global header rewriting.
- **Auth token never leaves the extension**: only sent to AuroraOSS (mint) and Google (consume).
