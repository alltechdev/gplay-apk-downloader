# web_extension — Browser-side port of gplay-apk-downloader

A Chromium / Firefox Manifest V3 extension that downloads APKs (base + splits) directly from Google Play to the user's disk or to a connected Android device, with **no server in the loop**. The legacy Flask service still exists in the parent repo; this directory replaces it.

## Why an extension

- The server stops being a DMCA distributor when it never holds APK bytes. The extension makes the user's browser the only thing that ever touches Play CDN output.
- The user's own anonymous AuroraOSS auth token + their own bandwidth + their own disk.
- The extension is a tool author, not a service operator. Closer to the legal posture of youtube-dl than of any APK-hosting site.

## Install (development)

```bash
cd web_extension
bash scripts/install.sh      # creates .venv, npm install, sanity-launches chromium
```

Then load `web_extension/src/` as an unpacked extension at `chrome://extensions` (Developer mode on).

## Try it without loading the extension

```bash
npm run serve                # http://localhost:8765/index.html — visual preview, chrome.* APIs unavailable
npm run dev                  # launches system chromium with the extension loaded (headed if $DISPLAY)
```

## Package for release

```bash
npm run build                # builds the WebUSB ADB bundle, then web-ext pack into dist/
```

## What it does

| Card | Feature |
|------|---------|
| Authentication | Anonymous AuroraOSS dispenser sign-in; iterates priority device profiles; arch selector (ARM64 / ARMv7); auto-retry on Play 401. |
| Install to Device | WebUSB ADB connection (`@yume-chan/adb`). When connected, the Download button installs to the device instead of saving to disk — no disk roundtrip. |
| Direct Download | Type a package name → look up details → download base + splits to `gplaydl/<pkg>-<vc>/` with `chrome.downloads`. Per-URL `Cookie` injection via `declarativeNetRequest`. Per-file cancel + show-in-folder. |
| Activity Log | Every step is logged. In-flight downloads update in place. |
| Backup & Restore | Pull installed-package list from the connected device; export/import as JSON; bulk re-download with sequential cancel. |

## Test pipeline

```bash
npm run lint                 # web-ext lint on manifest
npm test                     # node:test unit tests
npm run test:net             # integration against live AuroraOSS + Play API
npm run test:e2e             # puppeteer + system chromium, real downloads from real Google
npm run test:all             # lint + unit + net + e2e
```

Every release-blocking claim is backed by a test, and every visual claim is backed by a screenshot in `docs/test-runs/`.

## What's intentionally not here

- **No APK catalog.** No `/apps` page, no search box, no descriptions, no icons. The user types a package name they already know. Reduces DMCA surface to zero on the project side.
- **No blacklist.** The extension runs on the user's own machine; the user is responsible for what they download.
- **No telemetry, no stats counter, no external requests** beyond AuroraOSS, Google Play, Google Fonts.

## What's not yet implemented

- **Merge splits + re-sign** into a single APK. Legacy uses `APKEditor.jar` + `apksigner` server-side. A pure-browser implementation needs a WASM build of the APK tooling — significant work.
- **Live e2e test of ADB install.** The bundle loads and exposes `window.gplaydlAdb`; connecting and installing has been exercised manually but not automated (no real USB device on the test host).

## Layout

```
web_extension/
  src/                          loaded as the unpacked extension
    manifest.json
    background.js               single-file MV3 service worker (auth, Play API, downloads, DNR)
    index.html                  the tab page (matches legacy site visual style)
    app.js                      page controller
    style.css                   verbatim from public/style.css
    icons/                      16/32/48/128 PNG
    profiles.json               14 priority device profiles, generated from legacy CLI's .properties files
    vendor/adb-bundle.js        esbuild output of @yume-chan/adb (~65 KB)
    modules/                    ESM versions of pb-decode, profile.js, auth.js, adb-entry.js for unit tests
  docs/                         living documentation (port-spec, architecture, play-api, testing, changelog, ADRs, test-runs)
  scripts/                      install.sh, serve.mjs, dev.mjs
  tests/
    unit/                       node --test
    integration/                node --test, real network
    e2e/                        puppeteer-core + system chromium
    fixtures/, logs/, parity/   transient + future
  screenshots/                  history of e2e screenshots (committed)
  package.json
  .venv/                        Python venv (gitignored)
  node_modules/                 (gitignored)
```
