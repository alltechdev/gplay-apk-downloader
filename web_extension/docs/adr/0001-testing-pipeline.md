# ADR-0001 — Testing pipeline

**Date:** 2026-05-19
**Status:** Accepted

## Context

The extension's whole legal premise is that the server never touches APK bytes. That only holds if the client actually does what we claim. Untested claims about CORS, cookies, downloads, and rendering are the failure modes that would silently route us back to a server-mediated architecture.

The dev host is Termux on aarch64 Android. We initially assumed real-browser testing required a desktop machine, but the system already has:
- `chromium-browser` 144 (works headless)
- `chromedriver` 144
- `puppeteer-core` installable via npm with `executablePath` pointing at the system binary

That means stage 5 (real Chrome E2E) is local and automated — not a manual gate.

## Decision

Five-stage pipeline, all stages runnable on the dev host:

1. `web-ext lint` — manifest static check
2. `node --test` over `tests/unit/` — pure-logic unit tests
3. `node --test` over `tests/integration/` — live network against AuroraOSS + Google
4. `tests/parity/run.sh` — diff JS output against legacy Python CLI (opt-in)
5. `puppeteer-core` over `src/` loaded as unpacked extension — real Chrome E2E

Rules:
- A claim in `docs/` that depends on browser behaviour requires a stage-5 test artifact under `docs/test-runs/`.
- A claim about wire compatibility requires a stage-3 (or stage-4) test.
- Untested claims are marked `[UNVERIFIED]`.
- Tests live at `web_extension/tests/`, never elsewhere.

## Alternatives considered

- **Manual stage-5 only.** Rejected because the user explicitly forbade shortcuts and because the env supports automation.
- **Bundle puppeteer's own Chromium.** Rejected because puppeteer doesn't ship aarch64-Android Chromium; the system binary works fine.
- **Vitest / Jest.** Rejected because Node 24's built-in `node:test` is sufficient for our needs and has zero install cost.
- **Selenium + chromedriver.** Kept as a backup option; puppeteer-core is more ergonomic for extension testing.

## Consequences

- Stage 5 is now the default gate, not a manual ritual. Slower CI but stronger guarantees.
- Logs under `tests/logs/` can balloon — they're gitignored; significant runs are promoted to `docs/test-runs/` by hand.
- Two Python venvs: `.venv` for our own tests, `.venv-legacy` (created by `tests/parity/setup.sh`) for running the old CLI as an oracle. This avoids the `protobuf<4` constraint of the parent project.
