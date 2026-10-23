// Opt-in live tests use an explicitly supplied personal account, never a dispenser.
import { readFileSync } from 'node:fs';
import { loadSw } from './sw-load.mjs';
export const accountTestSkip = process.env.NO_NETWORK === '1' || !process.env.GPLAY_ACCOUNT_EMAIL || !process.env.GPLAY_AAS_TOKEN;
export async function personalAccountSession() {
  const local = {}, session = {}, rules = [];
  const storage = (data) => ({ get: async (k) => ({ [k]: data[k] }), set: async (o) => Object.assign(data, o), remove: async (k) => { delete data[k]; } });
  const chrome = {
    runtime: { getURL: (p) => `chrome-extension://test/${p}`, sendMessage: async () => {} },
    storage: { local: storage(local), session: storage(session) },
    declarativeNetRequest: { getDynamicRules: async () => rules, updateDynamicRules: async ({ addRules }) => { rules.splice(0, rules.length, ...addRules); } },
  };
  const sw = loadSw(['00-config.js', '05-logger.js', '10-utils.js', '15-errors.js', '20-pb.js', '30-storage.js', '40-dnr.js',
    '45-account-proto.js', '46-account-session.js', '50-auth.js', '60-play-api.js'], ['authSignIn', 'getAuthStored'], {
    chrome, console, URLSearchParams, AbortSignal,
    fetch: async (url, opts = {}) => {
      if (url.endsWith('profiles.json')) return { ok: true, json: async () => JSON.parse(readFileSync(new URL('../../src/profiles.json', import.meta.url))) };
      // Node has no DNR: apply the same UA that the extension's rules provide.
      const ruleId = url.endsWith('/auth') ? 1 : url.endsWith('/checkin') ? 5 : 2;
      const ua = rules.find((r) => r.id === ruleId)?.action.requestHeaders.find((h) => h.header === 'User-Agent')?.value || '';
      return fetch(url, { ...opts, headers: { ...opts.headers, 'User-Agent': ua } });
    },
  });
  await sw.authSignIn({ email: process.env.GPLAY_ACCOUNT_EMAIL, token: process.env.GPLAY_AAS_TOKEN });
  return sw.getAuthStored();
}
