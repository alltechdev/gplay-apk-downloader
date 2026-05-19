# Testing Pipeline

> **Principle:** no claim is treated as a fact until it has passed the realistic test stage for that claim. This file documents what "realistic" means for each layer of the extension.

## Environment (verified 2026-05-19)

What's available on the dev host (Termux on Android, aarch64), confirmed by `scripts/install.sh`:

| Tool | Version | Status |
|------|---------|--------|
| node | v24.14.1 | installed |
| npm  | 11.12.1 | installed |
| python3 | 3.12.12 | installed |
| chromium-browser | 144.0.7559.109 | installed (`/data/data/com.termux/files/usr/bin/chromium-browser`) |
| chromedriver | 144.0.7559.109 | installed |
| puppeteer-core | 23.x | installed via npm |
| web-ext | 8.x | installed via npm |
| protobufjs | 7.x | installed via npm |

Real-browser E2E is **local** on this host. There is no manual gate.

## The five-stage pipeline

### Stage 1 — Manifest lint (static)
- Command: `npm run lint`
- Tool: `web-ext lint` against `web_extension/src/`.
- Catches: MV3 schema errors, deprecated APIs, missing permissions.
- Requires: `src/manifest.json` to exist (scaffold task #2).

### Stage 2 — Unit tests (Node)
- Command: `npm test`
- Tool: `node --test 'tests/unit/**/*.test.mjs'`.
- Scope: pure logic — protobuf encoding/decoding, blacklist matching, profile selection, URL/header construction.
- Stub strategy: browser globals (`chrome.*`, `fetch`) stubbed per test; pure modules need no stubs.

### Stage 3 — Integration against real Google endpoints (Node)
- Command: `npm run test:net`
- Tool: `node --test 'tests/integration/**/*.test.mjs'` with real `fetch` to AuroraOSS + `android.clients.google.com/fdfe/*`.
- Confirms request shape and response parsing against live endpoints.
- Limit: Node `fetch` doesn't enforce CORS; browser-specific failures cannot be caught here — those land in Stage 5.

### Stage 4 — Parity vs. legacy CLI (opt-in)
- Command: `npm run test:parity`
- Tool: drives the legacy Python CLI (in a separate `.venv-legacy`) against a known package, then runs the JS port on the same package, then diffs.
- Required when: any byte that goes into a downloaded APK could change.

### Stage 5 — Real-browser E2E (local, automated)
- Command: `npm run test:e2e`
- Tool: `puppeteer-core` driving system chromium with the unpacked extension loaded from `src/`.
- Scope: CORS, cookies, downloads API, popup rendering, declarativeNetRequest rules.
- Output: `tests/logs/e2e-<timestamp>/` with `result.json`, console logs, network HAR, screenshots.
- Required: every release tag, every "X works in the extension" claim that depends on browser behavior.

### Combined
- `npm run test:all` = lint + unit + net + e2e (parity opt-in).

## Pipeline status — first end-to-end run (2026-05-19)

| Stage | Result |
|-------|--------|
| 1 lint | skipped — no manifest yet (depends on task #2) |
| 2 unit | ✔ 1/1 placeholder pass |
| 3 net  | ✔ 1/1 placeholder pass |
| 4 parity | ✔ stub returns 0 (legacy not yet wired) |
| 5 e2e  | ✔ puppeteer-core launched Chrome 144.0.7559.109, rendered about:blank |

Log: `tests/logs/install-20260519T140113Z.log`, `tests/logs/e2e-2026-05-19T14-06-39-854Z/`.

## What this pipeline still does not verify

Each item below requires a written stage-4 or stage-5 test before being claimed:

- That Chrome's CORS allows our `X-DFE-*` preflight from an MV3 extension with `host_permissions: ["https://android.clients.google.com/*"]`.
- That `declarativeNetRequest` injects the download `Cookie` header on the APK CDN request.
- That `chrome.downloads.download` handles multi-hundred-MB blob URLs without OOM.
- That the popup renders at the default 360×600.

All of the above are tracked as test-pending items in `docs/test-runs/`.
