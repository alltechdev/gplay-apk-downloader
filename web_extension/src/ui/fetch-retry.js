// fetch-retry.js — wraps fetch() with exponential backoff for transient
// failures. Mirrors the legacy server's `get_backoff_delay(attempt,
// base=1.0, max_delay=30.0)` pattern.
//
// Retry policy:
//   - Network errors (TypeError from fetch): retry
//   - 5xx status / 429: retry
//   - 4xx other: do NOT retry (no point — the URL is wrong or unauthorised)
//   - Caller-controlled max attempts; default 3 (= 2 retries)
//
// Pure function — `sleep` is injectable so tests don't actually wait.

/** Compute the delay before attempt #n (0-indexed, n>=1). */
export function backoffMs(attempt, { base = 1000, max = 30_000, jitter = 0.25 } = {}) {
  const expo = base * Math.pow(2, attempt - 1);
  const capped = Math.min(expo, max);
  const j = capped * jitter * (Math.random() * 2 - 1); // ±jitter
  return Math.max(0, Math.round(capped + j));
}

const DEFAULT_SLEEP = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * @param {() => Promise<Response>} doFetch  Closure that performs one fetch.
 * @param {object} opts
 * @param {number} [opts.attempts]  Total attempts including the first. Default 3.
 * @param {(attempt: number, err: Error|null, status: number|null) => void} [opts.onRetry]
 * @param {(ms: number) => Promise<void>} [opts.sleep]  Injected for tests.
 * @returns {Promise<Response>}
 */
export async function fetchWithRetry(doFetch, opts = {}) {
  const attempts = opts.attempts ?? 3;
  const sleep    = opts.sleep    ?? DEFAULT_SLEEP;
  let lastErr = null;
  for (let i = 1; i <= attempts; i++) {
    try {
      const res = await doFetch();
      if (res.ok) return res;
      // Retry on 5xx and 429; everything else is a hard fail.
      if (res.status >= 500 || res.status === 429) {
        lastErr = new Error('HTTP ' + res.status);
        lastErr.status = res.status;
      } else {
        const e = new Error('HTTP ' + res.status);
        e.status = res.status;
        throw e;
      }
    } catch (err) {
      // Network errors (no status) are retryable; rethrows from above carry .status.
      if (err?.status && err.status < 500 && err.status !== 429) throw err;
      lastErr = err;
    }
    if (i < attempts) {
      const ms = backoffMs(i);
      if (opts.onRetry) opts.onRetry(i, lastErr, lastErr?.status ?? null);
      await sleep(ms);
    }
  }
  throw lastErr || new Error('fetch failed');
}
