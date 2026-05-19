# web_extension/tests

This is the canonical test pipeline. Everything that proves the extension works lives here.

## Layout

```
tests/
  unit/         node --test, pure-logic JS modules
  integration/  node --test, real network to AuroraOSS + Play API
  parity/       bash + python: drive the legacy CLI in venv, compare bytes/protobuf
  e2e/          puppeteer-core driving system chromium with the unpacked extension
  fixtures/     captured protobuf payloads, golden outputs (binary, gitignored)
  logs/         test run logs + screenshots (gitignored)
```

## Pipeline order (no skipping)

| Stage | Command | What it proves | Required for |
|-------|---------|----------------|--------------|
| 1 | `npm run lint` | manifest is valid MV3 | every commit |
| 2 | `npm test` | pure modules behave (no browser, no network) | every commit |
| 3 | `npm run test:net` | request shapes accepted by real Google endpoints | any auth/API change |
| 4 | `npm run test:parity` | byte-equivalent to legacy Python CLI for same package | any download change |
| 5 | `npm run test:e2e` | extension actually works inside real Chromium | release tag, before "X works" claim |

`npm run test:all` runs 1, 2, 3, 5 in sequence (parity is opt-in because it actually downloads APKs).

## Logs

Every E2E run writes to `logs/e2e-<timestamp>/`:
- `console.log` — Chrome devtools console output
- `network.har` — full network capture
- `screenshot-*.png` — at each test step
- `result.json` — pass/fail breakdown

Logs are gitignored. To preserve a run for posterity, copy it into `docs/test-runs/`.

## Rule: tests prove claims

If a doc says "we authenticate with AuroraOSS", there is a test in `tests/integration/auth.test.mjs` that proves it. If a doc says "the popup opens", there is a screenshot in `docs/test-runs/`. No exceptions.
