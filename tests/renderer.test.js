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
// The diagnostics dialog is built entirely in JS, so none of its strings and
// none of its classes reach index.html — it has to be read on its own.
const DIAG = R('diagnostics.js');
// the stylesheet is split by surface (styles/home/lists/routing/settings/skins);
// the contract is against all of it, so read them as one
const CSS_FILES = ['styles.css', 'home.css', 'lists.css', 'routing.css', 'settings.css', 'skins.css', 'diagnostics.css'];
const CSS = CSS_FILES.map(R).join(String.fromCharCode(10));
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
  // The diagnostics dialog has no markup to scan: every one of its strings is a
  // 'diag.…' key handed to t(), tel() or say(), so the keys ARE the contract.
  const diag = new Set([...DIAG.matchAll(/'(diag\.[A-Za-z0-9.]+)'/g)].map((m) => m[1]));
  assert.ok(diag.size >= 30, `expected the whole dialog to be translated, found ${diag.size} keys`);
  for (const k of diag) keys.add(k);
  const bad = [...keys].filter((k) => (I18N.split(`'${k}':`).length - 1) !== 2).sort();
  assert.deepEqual(bad, [], 'these keys are not defined exactly once in each of fa and en');
});

/**
 * The OpenWrt gateway (v1.13.0): the device list under LAN sharing and the
 * inspector's gateway row. Hidden until the service reports flavor=openwrt —
 * on the desktop these must never show — and every string of theirs is a key
 * in both languages, including the ones only t() ever sees.
 */
test('the OpenWrt device list and gateway row exist, hidden by default, and are fully translated', () => {
  for (const id of ['gwRow', 'gwList', 'btnGwRefresh', 'insGatewayRow', 'insGateway']) {
    assert.ok(htmlIds.has(id), `#${id} is missing`);
  }
  const between = HTML.slice(HTML.indexOf('id="lanInfo"'), HTML.indexOf('id="optKillSwitch"'));
  assert.ok(between.includes('id="gwRow"'), 'the device list sits under LAN sharing, before the kill switch');
  assert.match(HTML, /id="gwRow" hidden/, 'hidden until flavor=openwrt');
  assert.match(HTML, /id="insGatewayRow" hidden/, 'hidden until flavor=openwrt');
  assert.match(APP, /state\.flavor = data\.flavor \|\| null/);

  const keys = new Set();
  for (const m of HTML.matchAll(/data-i18n(?:-ph|-title)?="(gw\.[^"]+|ins\.gateway)"/g)) keys.add(m[1]);
  for (const m of APP.matchAll(/\bt\(\s*'(gw\.[^']+)'/g)) keys.add(m[1]);
  assert.ok(keys.size >= 10, `expected the whole card to be translated, found ${keys.size} keys`);
  const bad = [...keys].filter((k) => (I18N.split(`'${k}':`).length - 1) !== 2).sort();
  assert.deepEqual(bad, [], 'these keys are not defined exactly once in each of fa and en');

  // the classes the list is built from exist in the stylesheet
  for (const cls of ['gw-list', 'gw-item', 'gw-dot', 'gw-name', 'gw-meta', 'gw-direct', 'gw-check']) {
    assert.ok(CSS.includes('.' + cls), `.${cls} has no style`);
  }
});

/**
 * The dialog's own controls. styles.css resets `button { background:none;
 * border:0 }` and gives inputs `color: inherit`, so a class-less <button> in
 * there rendered as bare padded text and its <input>s as near-white text on the
 * UA's white box. They have to opt into the shared classes like every other
 * control, and nothing may write a visible string past t().
 */
test('the diagnostics dialog uses the shared controls and no hard-coded strings', () => {
  const buttons = [...DIAG.matchAll(/tel\('button', '[^']+', '([^']+)'\)/g)].map((m) => m[1]);
  assert.equal(buttons.length, 6, 'the dialog has six buttons');
  assert.equal(buttons.filter((c) => c === 'btn primary').length, 1, 'only Test is the primary action');
  for (const cls of buttons) assert.match(cls, /^btn( |$)/, `a class-less button renders as bare text: "${cls}"`);
  assert.equal([...DIAG.matchAll(/el\('input', null, '([^']+)'\)/g)].map((m) => m[1]).length, 2);
  assert.doesNotMatch(DIAG, /el\('input', null, '(?!input')/, 'an unstyled input is white on white');

  // el() writes its second argument verbatim; tel() sends it through t(). A
  // quoted word there is therefore untranslated English on screen. The \b is
  // load-bearing: without it the pattern matches the "el(" inside "tel(".
  assert.doesNotMatch(DIAG, /\bel\('(?:p|h3|li|span|h2|button)', '[A-Za-z]/,
    'a visible string written straight into el() never reaches t()');

  // Neither the direction nor the language is the dialog's to decide: it is a
  // panel of the page, and the page is RTL in Persian.
  assert.doesNotMatch(DIAG, /\.dir\s*=|\.lang\s*=/, 'the dialog must follow the page direction');

  // One idempotent teardown, run by the button AND the event — the `close`
  // event alone did not arrive in every Chromium, and the panel could then
  // never be reopened.
  assert.match(DIAG, /close\.onclick = \(\) => teardown\(\)/);
  assert.match(DIAG, /addEventListener\('close', \(\) => teardown\(\)\)/);
  assert.match(DIAG, /function teardown\(\) \{\s*if \(!panel\) return;/);
});

/**
 * Per-app routing under the sing-box TUN (D10) — the row in the TUN card.
 *
 * Three things can go wrong silently here and nowhere else catches them: an id
 * app.js drives that the markup never grew, a mode the config builder does not
 * understand (the tunnel would then be built from a value nothing routes on),
 * and `tunapp.pickNone` — the one string of this row that never reaches the
 * markup, because it only ever appears in a toast, so the whole-markup i18n
 * test above cannot see it.
 */
test('the TUN card carries the per-app routing controls, in both languages', () => {
  for (const id of ['tunAppRow', 'optTunAppMode', 'tunAppModeCards', 'tunAppsBlock',
    'optTunApps', 'tunAppsPick', 'btnTunAppsPick', 'tunAppStrictNote', 'tunAppNeedsSingbox']) {
    assert.ok(htmlIds.has(id), `#${id} is missing from the TUN card`);
  }

  // it belongs to the tunnel's own card, between the backend and the guard
  const between = HTML.slice(HTML.indexOf('id="tunBackendRow"'), HTML.indexOf('id="leakGuardRow"'));
  assert.ok(between.includes('id="tunAppRow"'),
    'the per-app row is not in the TUN card, after the backend row');

  // exactly the modes the sing-box config builder understands
  const from = HTML.slice(HTML.indexOf('id="optTunAppMode"'));
  const select = from.slice(0, from.indexOf('</select>'));
  const modes = [...select.matchAll(/<option value="([^"]*)"/g)].map((m) => m[1]);
  assert.deepEqual(modes, ['off', 'exclude', 'only']);

  const keys = new Set();
  for (const m of HTML.matchAll(/data-i18n(?:-ph|-title)?="(tunapp\.[^"]+)"/g)) keys.add(m[1]);
  for (const m of APP.matchAll(/\bt\(\s*'(tunapp\.[^']+)'/g)) keys.add(m[1]);
  assert.ok(keys.size >= 10, `expected the whole row to be translated, found ${keys.size} keys`);
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

test('the markup carries no inline style attributes', () => {
  // An inline style bypasses the tokens, the three skins and the RTL logical
  // properties, and nothing else in this file can see it.
  const inline = [...HTML.matchAll(/ style="([^"]*)"/g)].map((m) => m[1]);
  assert.deepEqual(inline, []);
});

/**
 * The traffic path has to survive a narrow window. The owner's report was a
 * throughput caption printed on top of the "This device" node: the caption was
 * absolutely positioned and centred on a link that flexbox had shrunk to 56px,
 * while the caption itself needed 115px, so it escaped onto its neighbour — and
 * the panel scrolled sideways instead of reflowing, hiding the rest.
 *
 * Measured in the browser at 900px (the window's own minimum) across all three
 * skins and all three path shapes after the fix: no overlap, no overflow, no
 * scrollbar, nothing truncated. These assertions pin the properties that make
 * that true, because none of them can be checked without a layout engine.
 */
test('the traffic path reflows instead of scrolling, and its caption cannot escape its link', () => {
  const rule = (selector) => {
    const i = CSS.indexOf(selector + ' {');
    assert.ok(i !== -1, `no rule for ${selector}`);
    return CSS.slice(i, CSS.indexOf('}', i));
  };

  const panel = rule('.path-panel');
  assert.match(panel, /flex-wrap:\s*wrap/, 'the panel must wrap; a single row clips at 900px');
  assert.doesNotMatch(panel, /overflow-x:\s*auto/, 'wrapping replaces the sideways scrollbar');

  const link = rule('.path-link');
  assert.match(link, /flex-direction:\s*column/, 'the caption sits above the line, in flow');
  assert.match(link, /min-width:\s*auto/,
    'a numeric min-width lets flexbox shrink the link under its own caption — the original bug');

  // The caption must take part in layout: positioned out of flow, its width
  // says nothing about the link's, and it lands on whatever is next to it.
  const cap = rule('.path-cap');
  assert.doesNotMatch(cap, /position:\s*absolute/);
});
