// dom.js — tiny DOM helpers shared by every UI module.

export const $  = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

/** HTML-entity escape; for cases where a raw text string sneaks into markup. */
export function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

/**
 * `h('div', { class: 'foo', onClick: fn }, child1, [child2, ...], 'text')`
 *  → a real DOM Element with the given attributes and children.
 *
 * - String children become text nodes (auto-escaped by the DOM).
 * - Node children are appended as-is.
 * - Nested arrays are flattened.
 * - `null` / `undefined` / `false` children are skipped.
 * - `on…` attribute names register event listeners.
 * - `class` attribute uses `className` for chained class lists.
 */
export function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v == null || v === false) continue;
      if (k === 'class')          el.className = v;
      else if (k === 'style')     el.setAttribute('style', v);
      else if (k.startsWith('on') && typeof v === 'function') {
        el.addEventListener(k.slice(2).toLowerCase(), v);
      }
      else el.setAttribute(k, v);
    }
  }
  appendAll(el, children);
  return el;
}

function appendAll(parent, children) {
  for (const c of children) {
    if (c == null || c === false) continue;
    if (Array.isArray(c))       appendAll(parent, c);
    else if (c instanceof Node) parent.append(c);
    else                        parent.append(document.createTextNode(String(c)));
  }
}

/**
 * Replace an element's children with the given list (handles single Node,
 * arrays, or mixed strings/Nodes). Equivalent to clearing innerHTML and
 * appending, but without using innerHTML.
 */
export function replace(el, ...children) {
  el.replaceChildren();
  appendAll(el, children);
}

/** Format bytes as a human-readable size: 1.5 MB, 824 KB, etc. */
export function fmtSize(n) {
  if (!n) return '?';
  const units = ['B', 'KB', 'MB', 'GB'];
  let v = Number(n), i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return v.toFixed(v >= 100 ? 0 : v >= 10 ? 1 : 2) + ' ' + units[i];
}
