// Wrapper around `web-ext lint` that ignores the addons-linter false
// positive about MV3 `background.service_worker`. Chrome MV3 *requires*
// that field; addons-linter (which targets Firefox) flags it as
// unsupported. We treat that single error code/message as a notice and
// fail the script only on real errors.

import { spawn } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '..');

function run(cmd, args, opts) {
  return new Promise((resolveOk, rejectErr) => {
    const p = spawn(cmd, args, { cwd: ROOT, ...opts });
    const chunks = [];
    p.stdout.on('data', (c) => chunks.push(c));
    p.stderr.on('data', (c) => process.stderr.write(c));
    p.on('error', rejectErr);
    p.on('close', (code) => resolveOk({ code, stdout: Buffer.concat(chunks).toString('utf8') }));
  });
}

const { code, stdout } = await run(
  'npx',
  ['--no-install', 'web-ext', 'lint', '--source-dir=src', '--self-hosted', '--output=json'],
  {},
);

let data;
try { data = JSON.parse(stdout); } catch (err) {
  console.error('lint: failed to parse web-ext JSON output');
  console.error(stdout);
  process.exit(code || 1);
}

function isServiceWorkerFalsePositive(e) {
  return e.code === 'MANIFEST_FIELD_UNSUPPORTED'
      && /service_worker/.test(String(e.message || ''));
}

const realErrors = (data.errors || []).filter((e) => !isServiceWorkerFalsePositive(e));
const ignored = (data.errors || []).filter(isServiceWorkerFalsePositive);
const warnings = data.warnings || [];
const notices = data.notices || [];

console.log(`web-ext lint: errors=${realErrors.length}  warnings=${warnings.length}  notices=${notices.length}  ignored=${ignored.length}`);
if (ignored.length) {
  console.log('  ignored (addons-linter MV3 false-positive on service_worker):');
  for (const e of ignored) console.log('    -', e.code, '·', (e.message || '').slice(0, 100));
}
for (const e of realErrors) {
  console.error('ERROR', e.file ? `${e.file}:${e.line || 0}` : '', e.code, '·', e.message);
}
for (const w of warnings.slice(0, 5)) {
  console.warn('warn ', w.file ? `${w.file}:${w.line || 0}` : '', w.code, '·', (w.message || '').slice(0, 100));
}
if (warnings.length > 5) console.warn(`  … ${warnings.length - 5} more warnings (run \`npx web-ext lint --source-dir=src --self-hosted\` to see all)`);

if (realErrors.length > 0) process.exit(1);
