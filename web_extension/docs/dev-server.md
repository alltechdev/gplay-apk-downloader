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
npm run dev                          # headed if $DISPLAY is set, else headless with CDP
HEADLESS=1 npm run dev               # force headless + CDP
DEBUG_PORT=9333 npm run dev          # custom CDP port (default 9222)
```

Launches system Chromium with the extension loaded unpacked from `src/`. Uses a fresh temp profile each time so nothing pollutes your real browser data.

- **With a display** (X server, Termux:X11, VNC, real desktop): a Chromium window opens. Click the toolbar icon to open the extension page.
- **Without a display**: runs headless with `--remote-debugging-port=9222`. From any other machine on your network you can:
  - Open `http://<termux-ip>:9222` in a desktop Chrome to inspect.
  - Use `chrome://inspect` → "Configure" → add `<termux-ip>:9222` to attach DevTools.

Use this when you need real `chrome.*` behaviour (CORS, downloads, declarativeNetRequest, service worker).

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
- `npm run dev` headless works anywhere — useful for poking the extension via DevTools from your laptop on the same Wi-Fi.
