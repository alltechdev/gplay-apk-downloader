// Run `worker(item, idx)` over `items` with at most `limit` invocations
// in flight at any time. The returned array preserves the order of
// `items` regardless of completion order. Rejects on the first error.

export async function pMapLimit(items, limit, worker) {
  const out = new Array(items.length);
  let next = 0;
  const runners = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (true) {
      const i = next++;
      if (i >= items.length) return;
      out[i] = await worker(items[i], i);
    }
  });
  await Promise.all(runners);
  return out;
}
