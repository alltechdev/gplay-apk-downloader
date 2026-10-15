# Dev server / local preview

Two ways to look at the extension while working on it:

## `npm run serve` — visual preview over HTTP

```bash
cd web_extension
npm run serve              # default port 8765
PORT=9000 npm run serve    # custom port
```

Serves the files in `src/` over plain HTTP. Open `http://localhost:8765/index.html` in any browser to see the dark theme, fonts, and layout.

**Limit:** the page is loaded as a normal web page, not as an extension. `chrome.runtime`, `chrome.tabs`, `chrome.action`, etc. are `undefined`. Anything that calls `chrome.*` will throw. The current page only uses `chrome.*` inside the service worker, so the rendered look-and-feel is accurate, but click handlers that route through the service worker won't work.

Use this when iterating on CSS / HTML.

## `npm run dev` — real extension in a real browser

```bash
cd web_extension
npm run dev                       # opens a dedicated test browser
HEADLESS=1 npm run dev            # same persistent profile, without a window
npm run logs                      # latest redacted diagnostic entries
npm run test:live -- --smoke      # no account needed
npm run test:live -- --package com.kiloo.subwaysurf
```

The browser loads `src/` and retains its separate profile in `.local/chrome-profile`.
Set `CHROMIUM_BIN` to override the detected Chrome/Chromium executable. Close the
browser before starting another instance. Sign-in in this profile is separate
from your normal browser and persists across restarts.

Automation connects over a random loopback-only debugging port recorded in
`.local/browser.json`. Activity Log entries, console errors, service-worker errors,
HTTP failures and Chrome network/CORS reasons are saved in `.local/extension.jsonl`.
Capture excludes request bodies, headers and storage; emails, credentials and
HTTP URL paths/query strings are redacted. The entire `.local/` directory is
ignored by Git; it contains private browser state and downloaded APKs.

The smoke check verifies logging, DNR rules and the shipped merge/sign bundle,
then verifies actual browser-downloaded APK signatures and alignment with
`apksigner` and `zipalign` (required on PATH). The live check additionally exercises search, details, purchase,
delivery, complete CDN downloads, ZIP packaging and merged APK signatures.
It reports blocked account-dependent checks if this profile is not signed in.
Reports and downloads are saved under `.local/runs/`. USB hardware installation
requires a connected device and browser permission and is reported separately.

`npm run test:all` runs lint, unit, integration and isolated Chromium scenarios.
Deterministic browser fault tests cover network failures, 403/429/503 responses,
short bodies, recovery, concurrent cleanup and simulated ADB installation.
These tests do not establish that a live Google Play download or hardware install works.

## Which one for what

| Goal | Command |
|------|---------|
| Tweak CSS / layout | `npm run serve` |
| Verify popup → service worker RPC actually works | `npm run dev` |
| Confirm a network request reaches Google with the right headers | `npm run dev` |
| Take screenshots that prove a UI state | already automated by `npm run test:e2e` — but `npm run dev` lets you do it interactively |

## On Termux specifically

- `npm run serve` works out of the box, no display needed.
- `npm run dev` headed needs a display. Easiest: install **Termux:X11** from F-Droid, then:
  ```bash
  export DISPLAY=:0
  npm run dev
  ```
- `npm run dev` headless supports local automation without a display.

`npm run test:cdn` uses local HTTP/HTTPS servers and the actual extension host permissions and cookie rules. It verifies authenticated CDN reads without CORS response headers, 231 MB + 32 MB parallel downloads, interrupted-body recovery and rule cleanup. Requires OpenSSL. Test-only TLS and hostname overrides apply only to its isolated browser.
