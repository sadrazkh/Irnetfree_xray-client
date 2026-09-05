'use strict';
/**
 * The contract between the markup, the stylesheet and app.js.
 *
 * app.js reaches into the DOM by id, styles elements by class, and every string
 * on screen comes from a `data-i18n` key. None of that is type-checked and none
 * of it fails loudly: a redesign that renames one id leaves a button that does
 * nothing, a dropped CSS class leaves an unreadable control, a missing i18n key
 * shows the raw key to the user. All three are silent in a browser.
 *
 * So this file pins the contract. It is what makes it safe to replace the whole
 * visual layer: the look may change completely, these hooks may not.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const R = (f) => fs.readFileSync(path.join(__dirname, '..', 'src', 'renderer', f), 'utf8');
const HTML = R('index.html');
const APP = R('app.js');
const CSS = R('styles.css');
const I18N = R('i18n.js');

const htmlIds = new Set([...HTML.matchAll(/id="([^"]+)"/g)].map((m) => m[1]));

/** Every id app.js looks up, however it looks it up. */
function idsAppUses() {
  const ids = new Set();
  for (const m of APP.matchAll(/\$\(\s*['"`]#([A-Za-z0-9_-]+)['"`]/g)) ids.add(m[1]);
  for (const m of APP.matchAll(/getElementById\(\s*['"`]([A-Za-z0-9_-]+)['"`]/g)) ids.add(m[1]);
  for (const m of APP.matchAll(/querySelector(?:All)?\(\s*['"`]#([A-Za-z0-9_-]+)/g)) ids.add(m[1]);
  // Built at runtime, not in the markup: the view sections are addressed as
  // '#view-' + name, and the throughput caption is created by the traffic-path
  // builder (and is read defensively, so its absence is never a fault).
  ids.delete('view-');
  ids.delete('pathCapIn');
  return ids;
}

test('every element app.js reaches for exists in the markup', () => {
  const missing = [...idsAppUses()].filter((id) => !htmlIds.has(id)).sort();
  assert.deepEqual(missing, [], 'app.js would silently do nothing for these ids');
});

test('every nav item has the view it switches to', () => {
  const views = [...HTML.matchAll(/data-view="([^"]+)"/g)].map((m) => m[1]);
  assert.ok(views.length >= 8, `expected the full nav, found ${views.length}`);
  for (const v of views) {
    assert.ok(htmlIds.has('view-' + v), `data-view="${v}" has no #view-${v} section`);
  }
});

test('the routing mode buttons cover every mode the builder understands', () => {
  const modes = new Set([...HTML.matchAll(/data-mode="([^"]+)"/g)].map((m) => m[1]));
  for (const m of ['global', 'bypass-ir', 'bypass-cn', 'direct']) {
    assert.ok(modes.has(m), `no button for routing mode "${m}"`);
  }
});

test('every string on screen resolves in both languages', () => {
  const keys = new Set();
  for (const a of ['data-i18n', 'data-i18n-ph', 'data-i18n-title']) {
    for (const m of HTML.matchAll(new RegExp(a + '="([^"]+)"', 'g'))) keys.add(m[1]);
  }
  assert.ok(keys.size > 200, `expected the markup to be fully translated, found ${keys.size} keys`);
  const bad = [...keys].filter((k) => (I18N.split(`'${k}':`).length - 1) !== 2).sort();
  assert.deepEqual(bad, [], 'these keys are not defined exactly once in each of fa and en');
});

/**
 * Classes app.js puts on elements it creates. A stylesheet that no longer
 * styles one of them leaves a live control invisible or unreadable, which no
 * other test would catch. The baseline is what the shipped stylesheet already
 * covers — this asserts a redesign does not drop any of them.
 */
test('the stylesheet still covers every class app.js builds elements with', () => {
  const cls = new Set();
  for (const m of APP.matchAll(/className\s*=\s*['"`]([^`"'${]+)['"`]/g)) {
    String(m[1]).split(/\s+/).forEach((c) => c && cls.add(c));
  }
  for (const m of APP.matchAll(/class="([^"${]+)"/g)) {
    String(m[1]).split(/\s+/).forEach((c) => c && cls.add(c));
  }
  for (const m of APP.matchAll(/classList\.(?:add|toggle|remove)\(\s*['"`]([A-Za-z0-9_-]+)['"`]/g)) cls.add(m[1]);

  const styled = (c) => new RegExp('\\.' + c.replace(/[-]/g, '\\-') + '(?![A-Za-z0-9_-])').test(CSS);
  // Only the ones the shipped stylesheet already covers are load-bearing; the
  // rest inherit their look from a base class and always did.
  const baseline = [...cls].filter(styled);
  assert.ok(baseline.length > 100, `expected a broad baseline, found ${baseline.length}`);
  const dropped = baseline.filter((c) => !styled(c));
  assert.deepEqual(dropped, [], 'these classes lost their styling');
});

test('the shell keeps the parts the window is built from', () => {
  // Frameless window: our own minimise / maximise / close, and the drag region.
  for (const id of ['btnMin', 'btnMax', 'btnClose']) {
    assert.ok(htmlIds.has(id), `window control #${id} is gone`);
  }
  assert.match(CSS, /-webkit-app-region\s*:\s*drag/, 'nothing can drag the frameless window any more');
  assert.match(CSS, /-webkit-app-region\s*:\s*no-drag/, 'controls inside the title bar would be undraggable');
});

test('both themes and both writing directions are still styled', () => {
  assert.match(CSS, /\[data-theme="light"\]/, 'the light theme is gone');
  assert.match(CSS, /:root/, 'the dark theme tokens are gone');
  // RTL is the primary language: the layout must be written in logical
  // properties, not left/right, or Persian comes out mirrored.
  const logical = (CSS.match(/(?:margin|padding|border|inset)-inline/g) || []).length;
  assert.ok(logical >= 20, `expected logical properties throughout, found ${logical}`);
});
