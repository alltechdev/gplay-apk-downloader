# Source layout

Companion to `architecture.md`. Every source file is single-responsibility and < 200 LOC.

## Service worker — `src/background.js` + `src/sw/`

`background.js` is a 21-line entry that does nothing but `importScripts(...)`:

```js
importScripts(
  'sw/00-config.js',
  'sw/10-utils.js',
  'sw/20-pb.js',
  'sw/30-storage.js',
  'sw/40-dnr.js',
  'sw/50-auth.js',
  'sw/60-play-api.js',
  'sw/70-downloads.js',
  'sw/80-search.js',
  'sw/90-action.js',
  'sw/99-rpc.js',
);
```

The numeric prefix is the dependency order — config first, dispatcher last. Each file declares its functions/constants at top level; they're shared across files via the SW's global scope (the `importScripts` model). No `import`/`export`, which sidesteps Chrome 144's flakiness with MV3 module service workers.

| File                | What it owns                                                                                                |
|---------------------|-------------------------------------------------------------------------------------------------------------|
| `sw/00-config.js`   | URLs (dispenser, Play, search), storage keys, DNR rule IDs, TTL constants, hardcoded `X-DFE-*` headers.     |
| `sw/10-utils.js`    | `broadcast`, `validatePackageName`, `sanitizeFilenameSegment`, `loadProfilesJson`.                           |
| `sw/20-pb.js`       | Minimal protobuf decoder + Play API schemas (`PB_ResponseWrapper`, `PB_AppDetails`, `PB_AndroidAppDeliveryData`, …). |
| `sw/30-storage.js`  | `chrome.storage` wrappers (`getAuthStored`/`setAuthStored`/…) + the download↔rule map persisted in `chrome.storage.session`. |
| `sw/40-dnr.js`      | Three static dynamic rules + the per-download cookie-rule allocator/free-er.                                |
| `sw/50-auth.js`     | `authSignIn` (iterates priority profiles by arch), `authStatus`, `authSignOut`, `setArchRpc`.               |
| `sw/60-play-api.js` | `fdfeRequest` (auto-retry on 401), `appDetails`, `appPurchase`, `appDelivery`.                              |
| `sw/70-downloads.js`| `chrome.downloads.onChanged` listener; `queueDownloadFile`, `cancelDownload`, `showDownload`, `appDownload`, `appPrepareInstall`, `releaseRules`. |
| `sw/80-search.js`   | `appSearch` — HTML scrape of `play.google.com/store/search`, three extraction strategies (featured / related / JSON). |
| `sw/90-action.js`   | Toolbar click → open `index.html`; `installCoreDnrRules` on `onInstalled` / `onStartup` / SW boot.          |
| `sw/99-rpc.js`      | The RPC table; routes message types to SW handlers. Ignores broadcast events (`auth.event`, `download.event`). |

## Page — `src/app.js` + `src/ui/`

`app.js` is a 34-line ES-module entry:

```js
import { initLog }                from './ui/log.js';
import { initAuthCard }           from './ui/auth-card.js';
import { initAdbCard }            from './ui/adb-card.js';
import { initDirectDownloadCard } from './ui/direct-download-card.js';
import { initSearchCard }         from './ui/search-card.js';
import { initBackupCard }         from './ui/backup-card.js';

document.addEventListener('DOMContentLoaded', () => {
  initLog();
  initAdbCard();              // dispatches `adb-status` events
  initAuthCard();
  initDirectDownloadCard();   // listens for `adb-status` (shows Install-to-Device)
  initSearchCard();
  initBackupCard();           // listens for `adb-status` (enables Backup App List)
  …
});
```

Cross-card communication is one `adb-status` `CustomEvent` on the document — no import cycles. Anything else that needs to share between cards is exported by name (e.g., `direct-download-card.js` exports `downloadPackage` for `search-card.js` and `backup-card.js` to call).

| File                            | What it owns                                                          |
|---------------------------------|-----------------------------------------------------------------------|
| `ui/dom.js`                     | `$`, `$$`, `esc`, `fmtSize`.                                          |
| `ui/rpc.js`                     | `rpc(type, payload)` — Promise that resolves with `result` or rejects. |
| `ui/log.js`                     | Activity Log: append, in-place progress, clear, toggle, action links. |
| `ui/auth-card.js`               | Auth status display + sign-in / sign-out + arch dropdown.             |
| `ui/adb-card.js`                | WebUSB ADB UI; emits `adb-status` events.                             |
| `ui/direct-download-card.js`    | Info / Download / Install-to-Device. Exports `downloadPackage(pkg)`.  |
| `ui/search-card.js`             | Renders search results; click → calls `downloadPackage`.              |
| `ui/backup-card.js`             | Backup App List + Import + sequential restore (with Cancel).         |

## Modules + vendor bundles — `src/modules/` + `src/vendor/`

`modules/` is the ESM source consumed by **both** the unit-test runner and esbuild:

| File                       | Used by                                                                        |
|----------------------------|--------------------------------------------------------------------------------|
| `modules/pb-decode.js`     | Unit + integration tests. (The SW has a copy at `sw/20-pb.js`.)                |
| `modules/apk-merger.js`    | Bundled into `vendor/apk-tools-bundle.js`; unit-tested.                        |
| `modules/apk-signer.js`    | Bundled; unit-tested.                                                          |
| `modules/axml-patcher.js`  | Bundled; unit-tested with byte-identical parity against legacy Python source.  |
| `modules/zipalign.js`      | Bundled; unit-tested.                                                          |
| `modules/debug-cert.js`    | Bundled. Auto-generated RSA-2048 cert + key embedded as JS constants.          |
| `modules/adb-entry.js`     | esbuild entry → `vendor/adb-bundle.js`.                                        |
| `modules/apk-tools-entry.js`| esbuild entry → `vendor/apk-tools-bundle.js`.                                  |

`vendor/` holds the committed esbuild output:

| File                          | Size    | Exposed as              |
|-------------------------------|---------|-------------------------|
| `vendor/adb-bundle.js`        | ~65 KB  | `window.gplaydlAdb`     |
| `vendor/apk-tools-bundle.js`  | ~33 KB  | `window.gplaydlApkTools`|

## Tests — `tests/`

| Dir                | Runner           | What                                                              |
|--------------------|------------------|-------------------------------------------------------------------|
| `tests/unit/`      | `node --test`    | pb-decode, apk-merger, apk-signer, axml-patcher (Python parity), zipalign. |
| `tests/integration/`| `node --test`   | live AuroraOSS dispenser, live Play API details + delivery.       |
| `tests/e2e/`       | `puppeteer-core` | system chromium + the unpacked extension. 4 scenarios + smoke.    |
| `tests/parity/`    | bash             | placeholder for future legacy CLI byte-diff runs.                 |
| `tests/fixtures/`  | —                | gitignored binary fixtures.                                       |
| `tests/logs/`      | —                | per-run logs, gitignored.                                         |

See `testing.md` for the pipeline + how each stage runs locally and in CI.
