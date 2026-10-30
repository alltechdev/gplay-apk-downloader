// 05-logger.js — tiny tagged logger for the service worker.
//
// `swLog.debug/info/warn/error(...args)` prefixes everything with
// `[gplaydl]` and respects a runtime level filter so debug noise can be
// silenced without touching every call site.

const SW_LOG_LEVEL = 'info';                  // 'debug' | 'info' | 'warn' | 'error'
const SW_LOG_RANK  = { debug: 0, info: 1, warn: 2, error: 3 };
const SW_LOG_MIN   = SW_LOG_RANK[SW_LOG_LEVEL] ?? 1;
const SW_LOG_TAG   = '[gplaydl]';

const swLog = {
  debug: (...a) => { if (SW_LOG_RANK.debug >= SW_LOG_MIN) console.debug(SW_LOG_TAG, ...a); },
  info:  (...a) => { if (SW_LOG_RANK.info  >= SW_LOG_MIN) console.info (SW_LOG_TAG, ...a); },
  warn:  (...a) => { if (SW_LOG_RANK.warn  >= SW_LOG_MIN) console.warn (SW_LOG_TAG, ...a); },
  error: (...a) => { if (SW_LOG_RANK.error >= SW_LOG_MIN) console.error(SW_LOG_TAG, ...a); },
};
