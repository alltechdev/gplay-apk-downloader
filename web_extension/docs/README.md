# web_extension/docs

Living documentation for the browser-extension port. **Everything is documented here**, including:

- The porting spec (`port-spec.md`)
- Architecture decisions (`adr/`)
- Testing approach (`testing.md`)
- A running log of changes (`changelog.md`)
- Subsystem deep-dives as we build them (auth, play-api, downloads, ui)

## Ground rules

1. **No claim is a fact until tested.** Anything not verified by a real run is marked `[UNVERIFIED]`.
2. **Tests before assertions.** When we say "X works," there is a test artifact (script, log, screenshot) checked in or referenced.
3. **Decisions are recorded.** Every non-trivial design choice gets an ADR in `adr/`.
4. **No silent rewrites.** When we change a documented behavior, the doc changes in the same commit.

## Index

- `port-spec.md` — what we're porting and how.
- `architecture.md` — current concrete architecture (SW, page, DNR rules, RPC contract).
- `play-api.md` — endpoints, headers, protobuf schemas, gotchas.
- `testing.md` — the realistic 5-stage test pipeline.
- `dev-server.md` — local preview (`npm run serve`) + real-extension launch (`npm run dev`).
- `adr/0001-testing-pipeline.md` — decision record for the test pipeline.
- `changelog.md` — running log of changes (append-only).
- `test-runs/` — promoted evidence (screenshots + result.json) for milestone test runs.
