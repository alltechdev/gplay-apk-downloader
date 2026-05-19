# web_extension — Browser-side port of gplay-apk-downloader

A Chromium / Firefox Manifest V3 extension that replaces the Flask server in the parent repo with a **fully client-side flow**: anonymous AuroraOSS sign-in, Play API details/purchase/delivery over a hand-rolled protobuf decoder, APKs streamed directly from Google Play's CDN to the user's disk or to a connected Android device, optional merge + sign of split APKs locally.

**No APK bytes ever transit a server.** The extension is a tool author, not a service operator.

## Install (development)

```bash
cd web_extension
bash scripts/install.sh         # creates .venv, npm install, sanity-launches chromium
```

Then load `web_extension/src/` as an unpacked extension at `chrome://extensions` (Developer mode on), or drag-drop the packaged zip from `dist/`.

## Try it without loading the extension

```bash
npm run serve                   # http://localhost:8765/index.html — visual preview, chrome.* APIs unavailable
npm run dev                     # launches system chromium with the extension loaded (headed if $DISPLAY)
```

## Package for release

```bash
npm run build                   # builds the WebUSB ADB + APK-tools bundles, then web-ext pack into dist/
```

A GitHub Actions workflow at `.github/workflows/build-extension.yml` runs the lint + unit suite and uploads the packaged zip + the unpacked source tree as artifacts on every push to `feat/web-extension` / `main` (and on PRs touching `web_extension/`).

## What it does

| Card | Feature |
|------|---------|
| Authentication | Anonymous AuroraOSS dispenser sign-in. Iterates priority device profiles by architecture. Auto-rotates to a matching profile when the arch selector changes. Auto-retries on Play 401. Surfaces only "Authenticated" + profile name + arch — no dispenser-account email. |
| Install to Device | WebUSB ADB connection (`@yume-chan/adb`). Shows model + Android version + serial when connected. |
| Direct Download | Type a package name → Info shows title/version/size/splits/installed-version-on-device (when ADB is connected). **Merge splits** checkbox (default ON, legacy-parity): merged + zipaligned + v1/v2/v3-signed single APK; unchecked: separate APK files. **Install to Device** button (when ADB connected): fetches blobs directly from Play CDN and `pm install-create` / `install-write` / `install-commit` to the device. |
| Activity Log | Every step is logged with a clickable per-download cancel link and a "show in folder" action on completed entries. |
| Backup & Restore | Pull installed user-package list from the connected device (`pm list packages -3`) → export as JSON. Import a JSON list and sequentially re-download with a Cancel button + Select all/None links. |

## Legacy parity matrix

| Feature | Legacy server | This extension |
|---------|---------------|----------------|
| AuroraOSS anonymous auth | server-side `cloudscraper` POST | client-side `fetch` + `declarativeNetRequest` to set Aurora UA |
| Play API protobuf (details/purchase/delivery) | gpapi (Python) | hand-rolled `pb-decode.js` + schema |
| Architecture selector | `arch=` query param | `arch.set` RPC; auto re-auth on change |
| Merge splits + sign | `APKEditor.jar` + `apksigner` | `fflate` merge + zipalign + v1 (JAR) + v2 + v3 signing |
| `axml_patcher.py` fused-modules meta-data | yes | **byte-identical port** (unit-tested against the Python source) |
| `zipalign -p 4` (4-byte entries, 4096-byte page-align for `lib/*.so`) | yes | yes (`zipalign.js`) |
| Backup app list via ADB | server-side `adb` binary | WebUSB ADB |
| Install via ADB | server-side `adb install-multiple` | WebUSB ADB `pm install-create/write/commit` |
| GitHub stars badge in footer | yes | yes |
| `--version` CLI arg | yes (CLI only; **not in legacy web UI**) | not in extension web UI either |
| Search / App Catalog | yes | **omitted by policy** (no catalog, no descriptions, no images) |
| Stats counter | yes (`/api/stats`) | omitted (no server) |
| Server-side download SSE | yes | `chrome.downloads.onChanged` broadcasts |
| Classic OBB (`additionalFile[]`) | not handled | not handled (parity) |

## Test pipeline

```bash
npm run lint                    # web-ext lint on manifest
npm test                        # node:test unit tests (protobuf decoder, merge, zipalign, AXML patcher cross-validated against Python, v2 signer)
npm run test:net                # integration against live AuroraOSS + Play API
npm run test:e2e                # puppeteer + system chromium, real downloads from real Google
npm run test:all                # lint + unit + net + e2e
```

Every release-blocking claim is backed by a test, and every visual claim is backed by a screenshot in `docs/test-runs/`.

## Layout

Every source file is single-responsibility and under ~200 LOC.

```
web_extension/
  src/                          loaded as the unpacked extension
    manifest.json
    index.html                  the tab page (matches legacy site visual style verbatim)
    style.css                   verbatim from public/style.css
    icons/                      16 / 32 / 48 / 128 PNG
    profiles.json               14 priority device profiles, generated from legacy CLI's .properties

    background.js               21-line `importScripts(...)` entry
    sw/                         service-worker modules (loaded in numeric order)
      00-config.js              constants (URLs, IDs, TTLs, hardcoded DFE headers)
      10-utils.js               broadcast, validatePackageName, sanitizeFilenameSegment, loadProfilesJson
      20-pb.js                  protobuf decoder + Play API message schemas
      30-storage.js             chrome.storage wrappers + download↔rule map persistence
      40-dnr.js                 declarativeNetRequest dynamic rules (UA / Origin / Cookie injection)
      50-auth.js                AuroraOSS sign-in / sign-out / status + arch selection
      60-play-api.js            /fdfe/details, /fdfe/purchase, /fdfe/delivery (with 401 auto-retry)
      70-downloads.js           chrome.downloads + per-download cookie rule lifecycle + prepareInstall
      80-search.js              Play Store HTML scrape
      90-action.js              toolbar click handler + DNR install hooks
      99-rpc.js                 RPC dispatcher

    app.js                      34-line ES-module entry; imports each ui/ card and calls init…()
    ui/                         page-side modules (ES modules)
      dom.js                    $, $$, esc, fmtSize
      rpc.js                    page → SW request helper
      log.js                    Activity Log with in-place progress entries
      auth-card.js              authentication card + arch dropdown
      adb-card.js               WebUSB ADB connect/disconnect; dispatches `adb-status` events
      direct-download-card.js   Info / Download / Install-to-Device + exported downloadPackage()
      search-card.js            Play Store search rendering
      backup-card.js            backup app-list + import JSON + sequential restore

    modules/                    ESM source consumed by unit tests AND bundled by esbuild
      pb-decode.js              same wire format as sw/20-pb.js; ESM version for unit tests
      apk-merger.js             merge base + splits with axml patching + zipalign
      apk-signer.js             v1 (JAR) + v2 + v3 APK signing in pure JS (Web Crypto)
      axml-patcher.js           binary AndroidManifest.xml patcher; byte-identical to legacy Python
      zipalign.js               zipalign -p 4 in JS (4-byte default, 4096-byte page-align for lib/*/*.so)
      debug-cert.js             auto-generated RSA-2048 cert/key for merged-APK signing
      adb-entry.js              entry: wraps @yume-chan/adb for the page
      apk-tools-entry.js        entry: bundles fflate + merger + signer + zipalign

    vendor/                     committed esbuild output, loaded by index.html
      adb-bundle.js             ~65 KB
      apk-tools-bundle.js       ~33 KB

  docs/                         living documentation (port-spec, architecture, play-api, testing, ADRs, test-runs, changelog)
  scripts/                      install.sh, serve.mjs, dev.mjs, lint.mjs
  tests/
    unit/                       node --test (pb-decode, merger, signer, axml-patcher, zipalign)
    integration/                node --test, real network (AuroraOSS + Play API)
    e2e/                        puppeteer-core + system chromium (smoke + page-loads + auth + info-and-download + backup-restore)
    fixtures/, logs/, parity/   transient + future
  screenshots/                  history of e2e screenshots (committed)
  package.json
  .venv/                        Python venv (gitignored)
  node_modules/                 (gitignored)

.github/workflows/build-extension.yml  CI: lint + unit + build; uploads zip + unpacked artifacts on push to main / feat/web-extension and on PRs touching web_extension/
```

## Permissions requested

| Permission | Why |
|------------|-----|
| `storage`  | auth token + arch preference (`chrome.storage.local`); per-download → DNR-rule id map (`chrome.storage.session`) |
| `downloads`| `chrome.downloads.download` for split files; `chrome.downloads.show` for the in-log "show in folder" action |
| `declarativeNetRequest` + `declarativeNetRequestWithHostAccess` | rewrite forbidden headers (User-Agent / Origin / Sec-Fetch-*) and inject the per-download `Cookie` from the delivery response |
| `host_permissions` | `auroraoss.com`, `android.clients.google.com`, `play.googleapis.com`, `*.gvt1.com`, `*.googleusercontent.com`, `fonts.googleapis.com`, `fonts.gstatic.com`, `api.github.com` |

No `tabs` / `scripting` / `activeTab`. No content scripts. No telemetry.
