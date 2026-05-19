# web_extension/screenshots

Canonical home for every screenshot the test pipeline produces.

## Layout

```
screenshots/
  latest/                       overwritten on every e2e run; one-glance current state
    smoke-popup.png
    rpc-ping-1-empty.png
    rpc-ping-2-filled.png
    rpc-ping-3-response.png
    result.json
  2026-05-19T14-15-00-000Z/     timestamped, append-only history of all runs
    smoke-popup.png
    ...
```

- `latest/` always reflects the most recent `npm run test:e2e` run.
- Timestamped dirs are kept indefinitely so we can compare visual regressions over time.
- Both are tracked in git so reviewers can see the UI without running the suite.

`tests/logs/e2e-*/` still receives a per-run copy for forensics (gitignored, larger).
