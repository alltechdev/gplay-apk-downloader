// Unit tests for h() and replace() in src/ui/dom.js. They are the DOM
// builder used by every card; subtle mishandling of attribute names,
// child flattening, or event-listener registration causes silent UI
// breakage that is awful to debug. Linkedom gives us a real DOM under
// Node so we can assert against actual elements.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseHTML } from 'linkedom';

const __dirname = dirname(fileURLToPath(import.meta.url));
const srcPath = resolve(__dirname, '..', '..', 'src', 'ui', 'dom.js');

function loadDom() {
  const { document, Node } = parseHTML('<!doctype html><html><body></body></html>');
  const code = readFileSync(srcPath, 'utf8')
    .replace(/^export\s+(?:async\s+)?function\s+/gm, 'function ')
    .replace(/^export\s+const\s+/gm, 'const ')
    + `\nObject.assign(globalThis, { h, replace, esc, fmtSize, $: $ });`;
  const ctx = vm.createContext({ document, Node, Object, Array, String });
  vm.runInContext(code, ctx);
  return ctx;
}

test('h: returns an Element of the given tag', () => {
  const { h } = loadDom();
  const el = h('div');
  assert.equal(el.tagName.toLowerCase(), 'div');
});

test('h: sets the class via className (so chained classes work)', () => {
  const { h } = loadDom();
  const el = h('div', { class: 'btn primary' });
  assert.equal(el.className, 'btn primary');
});

test('h: sets style via setAttribute', () => {
  const { h } = loadDom();
  const el = h('div', { style: 'color: red; font-weight: 700' });
  assert.match(el.getAttribute('style'), /color:\s*red/);
});

test('h: skips attributes whose value is null / undefined / false', () => {
  const { h } = loadDom();
  const el = h('input', { type: 'text', disabled: false, placeholder: null, id: undefined });
  assert.equal(el.getAttribute('type'), 'text');
  assert.equal(el.hasAttribute('disabled'), false);
  assert.equal(el.hasAttribute('placeholder'), false);
  assert.equal(el.hasAttribute('id'), false);
});

test('h: registers on<Event> handlers via addEventListener', () => {
  const { h, document } = loadDom();
  let fired = 0;
  const btn = h('button', { onClick: () => { fired++; } }, 'go');
  document.body.append(btn);
  btn.dispatchEvent(new btn.ownerDocument.defaultView.Event('click'));
  assert.equal(fired, 1, 'click handler should be wired via addEventListener');
});

test('h: lowercases the event name after stripping the `on` prefix', () => {
  const { h } = loadDom();
  let fired = 0;
  const el = h('div', { onMouseEnter: () => { fired++; } });
  el.dispatchEvent(new el.ownerDocument.defaultView.Event('mouseenter'));
  assert.equal(fired, 1);
});

test('h: appends string children as text nodes (auto-escaping HTML)', () => {
  const { h } = loadDom();
  const el = h('div', null, 'plain', '<script>');
  assert.equal(el.childNodes.length, 2);
  assert.equal(el.childNodes[0].nodeType, 3); // TEXT_NODE
  assert.equal(el.textContent, 'plain<script>');
});

test('h: appends Node children as-is', () => {
  const { h } = loadDom();
  const child = h('span', null, 'inner');
  const parent = h('div', null, child);
  assert.equal(parent.firstChild, child);
});

test('h: flattens nested arrays of children', () => {
  const { h } = loadDom();
  const el = h('ul', null, [h('li', null, 'a'), [h('li', null, 'b'), h('li', null, 'c')]]);
  assert.equal(el.children.length, 3);
});

test('h: skips null / undefined / false children', () => {
  const { h } = loadDom();
  const el = h('div', null, 'a', null, undefined, false, 'b');
  assert.equal(el.childNodes.length, 2);
  assert.equal(el.textContent, 'ab');
});

test('h: coerces numeric children to strings', () => {
  const { h } = loadDom();
  const el = h('span', null, 42);
  assert.equal(el.textContent, '42');
});

test('replace: clears existing children before appending new ones', () => {
  const { h, replace } = loadDom();
  const el = h('div', null, h('p', null, 'old1'), h('p', null, 'old2'));
  assert.equal(el.children.length, 2);
  replace(el, h('span', null, 'new'));
  assert.equal(el.children.length, 1);
  assert.equal(el.firstChild.textContent, 'new');
});

test('replace: empty arg list leaves the element with no children', () => {
  const { h, replace } = loadDom();
  const el = h('div', null, 'old');
  replace(el);
  assert.equal(el.childNodes.length, 0);
});

test('replace: accepts the same mixed child types as h()', () => {
  const { h, replace } = loadDom();
  const el = h('div', null, 'x');
  replace(el, 'a', [h('span', null, 'b'), 'c'], null);
  assert.equal(el.textContent, 'abc');
});
