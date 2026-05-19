// Static check: every exported symbol in `src/ui/` and `src/modules/`
// must be imported somewhere in `src/` or `tests/`. Catches the case
// where the only caller of an API was deleted but the export stuck
// around — a quiet way for dead code to accumulate.
//
// Service-worker files in `src/sw/` use `importScripts` (not ESM), so
// their function declarations are not `export`-ed and are out of scope
// for this test.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { resolve, dirname, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '..', '..');

/** Files that are entry-points (loaded by <script>, importScripts, or
 *  bundled directly), and therefore aren't expected to be imported. */
const ENTRY_FILES = new Set([
  'src/app.js',
  'src/background.js',
  'src/modules/adb-entry.js',
  'src/modules/apk-tools-entry.js',
]);

function walk(dir, acc = []) {
  for (const ent of readdirSync(dir, { withFileTypes: true })) {
    if (['node_modules', 'vendor', '.venv', 'screenshots', 'logs', 'fixtures'].includes(ent.name)) continue;
    const full = resolve(dir, ent.name);
    if (ent.isDirectory()) walk(full, acc);
    else if (/\.m?js$/.test(ent.name)) acc.push(full);
  }
  return acc;
}

/** Extract every name introduced by an `export` in `src`. */
function exportNames(src) {
  const out = new Set();
  // `export function NAME`, `export async function NAME`, `export const NAME`, `export let NAME`, `export class NAME`
  for (const m of src.matchAll(/^export\s+(?:async\s+)?(?:function|const|let|class)\s+([A-Za-z0-9_$]+)/gm)) {
    out.add(m[1]);
  }
  // `export { a, b as c, d }` (with or without `from ...`)
  for (const m of src.matchAll(/^export\s*\{([^}]+)\}/gm)) {
    for (const tok of m[1].split(',')) {
      const t = tok.trim();
      if (!t) continue;
      // `x as y` → exported name is `y`; `x` alone → `x`.
      const parts = t.split(/\s+as\s+/);
      out.add((parts[1] || parts[0]).trim());
    }
  }
  return out;
}

/** Extract every name pulled in by an `import { … }` statement in `src`. */
function importNames(src) {
  const out = new Set();
  // `import { a, b as c, d } from '...'`
  for (const m of src.matchAll(/import\s+\{([^}]+)\}\s+from/gm)) {
    for (const tok of m[1].split(',')) {
      const t = tok.trim();
      if (!t) continue;
      // For `x as y` the consumer reads `y`, but the source-side name is `x`.
      // Our exports record source-side names, so we collect `x`.
      out.add(t.split(/\s+as\s+/)[0].trim());
    }
  }
  return out;
}

const allFiles    = walk(resolve(ROOT, 'src')).concat(walk(resolve(ROOT, 'tests')));
const allImports  = new Set();
for (const f of allFiles) for (const n of importNames(readFileSync(f, 'utf8'))) allImports.add(n);

function rel(f) { return f.slice(ROOT.length + 1).split(sep).join('/'); }

test('dead-code: every src/ui export is imported by someone', () => {
  const orphans = [];
  for (const f of allFiles) {
    const r = rel(f);
    if (!r.startsWith('src/ui/')) continue;
    if (ENTRY_FILES.has(r)) continue;
    for (const sym of exportNames(readFileSync(f, 'utf8'))) {
      if (!allImports.has(sym)) orphans.push(`${r}:${sym}`);
    }
  }
  if (orphans.length) assert.fail('Unused exports:\n  ' + orphans.join('\n  '));
});

test('dead-code: every src/modules export is imported by someone', () => {
  const orphans = [];
  for (const f of allFiles) {
    const r = rel(f);
    if (!r.startsWith('src/modules/')) continue;
    if (ENTRY_FILES.has(r)) continue;
    for (const sym of exportNames(readFileSync(f, 'utf8'))) {
      if (!allImports.has(sym)) orphans.push(`${r}:${sym}`);
    }
  }
  if (orphans.length) assert.fail('Unused exports:\n  ' + orphans.join('\n  '));
});

test('dead-code: every src/ui and src/modules file is referenced by an import', () => {
  // Collect every "from '<path>'" target across the repo. Then assert each
  // non-entry file in src/ui or src/modules is referenced by basename.
  const refTargets = new Set();
  for (const f of allFiles) {
    const src = readFileSync(f, 'utf8');
    for (const m of src.matchAll(/from\s+['"]([^'"]+)['"]/g)) {
      const target = m[1];
      // Drop directory components and the .js extension to get a basename.
      const base = target.split('/').pop().replace(/\.m?js$/, '');
      refTargets.add(base);
    }
  }
  const orphans = [];
  for (const f of allFiles) {
    const r = rel(f);
    if (!/^src\/(ui|modules)\//.test(r)) continue;
    if (ENTRY_FILES.has(r)) continue;
    const base = r.split('/').pop().replace(/\.m?js$/, '');
    if (!refTargets.has(base)) orphans.push(r);
  }
  if (orphans.length) assert.fail('Files not imported by anyone:\n  ' + orphans.join('\n  '));
});
