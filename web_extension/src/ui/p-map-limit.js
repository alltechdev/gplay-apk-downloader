// Run `worker(item, idx)` over `items` with at most `limit` invocations
// in flight at any time. The returned array preserves the order of
// `items` regardless of completion order. Stops scheduling on the first error, waits for active workers, then rejects.

export async function pMapLimit(items, limit, worker) {
  const out = new Array(items.length);
  let next = 0;
  let failed = false;
  let firstError;
  const runners = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (!failed) {
      const i = next++;
      if (i >= items.length) return;
      try { out[i] = await worker(items[i], i); }
      catch (err) {
        if (!failed) { failed = true; firstError = err; }
      }
    }
  });
  await Promise.all(runners);
  if (failed) throw firstError;
  return out;
}
