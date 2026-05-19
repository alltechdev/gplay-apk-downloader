# Test run — 2026-05-19 — Visual style port

Confirms the legacy site's dark theme, JetBrains Mono headings, blue accent, and card styling are rendered identically when the extension page is loaded from `chrome-extension://<id>/index.html`.

## Stages

| Stage | Result |
|-------|--------|
| 1 lint | exit 0 (notices only — Firefox-future stuff) |
| 2 unit | ✔ 1/1 |
| 3 net  | ✔ 1/1 placeholder |
| 5 e2e  | ✔ 2/2 (`smoke.page`, `scenarios/01-page-loads.mjs`) |

## Visual style assertions (proven by `01-page-loads.mjs`)

- `<header h1>` reads exactly "GPlay APK Downloader".
- Footer exists.
- Activity Log panel exists and logs the page-load event (`#log-badge` = "1").
- No `#search-q`, no `#download-btn`, no `#adb-connect-btn` — every UI element with no working backend is **absent** (no-stubs policy).
- Google Fonts CSS loads via the relaxed CSP (`style-src` + `font-src` allowlists `fonts.googleapis.com` / `fonts.gstatic.com`).

## Screenshots
- `2026-05-19-style-port-collapsed.png`
- `2026-05-19-style-port-full.png`
- `2026-05-19-style-port-log-open.png`
