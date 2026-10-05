'use strict';
/**
 * 📶 and ⚡ on every server group's head, and "⚡ Fastest — <subscription>" rows
 * in the home picker (v1.18.0 final, task B). The renderer is the desktop
 * window's AND the router's web UI, so these cover both.
 *
 *   📶  tests every config of one group (TCP, then real delay — what "Ping all"
 *       does, for that group only);
 *   ⚡  connects to that group's fastest: it tests the group again unless all of
 *       it was tested in the last three minutes, then connects to the best —
 *       real delay first, the TCP handshake as the fallback (Auto's ranking);
 *   the picker's "⚡ Fastest — <name>" row is that same ⚡, one per subscription,
 *       under the global Auto row, which is unchanged.
 *
 * app.js reaches into the DOM at load, so — like desktopUx.test.js — its own
 * functions are compiled in a vm over fakes, and its wiring is read as text.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

// CRLF on a Windows checkout (core.autocrlf): the patterns below are written with \n.
const R = (...p) => fs.readFileSync(path.join(__dirname, '..', ...p), 'utf8').replace(/\r\n/g, '\n');
const APP = R('src', 'renderer', 'app.js');
const I18N = R('src', 'renderer', 'i18n.js');
const CSS = ['styles.css', 'home.css', 'lists.css', 'routing.css', 'settings.css', 'skins.css'].map((f) => R('src', 'renderer', f)).join('\n');

/** A top-level (async) function of app.js, as source. */
function fnSource(name) {
  let start = APP.indexOf(`\nfunction ${name}(`);
  if (start === -1) start = APP.indexOf(`\nasync function ${name}(`);
  assert.ok(start > -1, `app.js has no function ${name}`);
  let depth = 0, j = APP.indexOf('{', APP.indexOf(')', start));
  for (; j < APP.length; j++) {
    if (APP[j] === '{') depth++;
    else if (APP[j] === '}' && --depth === 0) break;
  }
  return APP.slice(start, j + 1);
}
/** A top-level one-line `const NAME = …;` of app.js, as source. */
function constSource(name) {
  const m = APP.match(new RegExp(`\\nconst ${name} = [^\\n]*;\\n`));
  assert.ok(m, `app.js has no const ${name}`);
  return m[0];
}
/** Compile these app.js functions in a context of fakes; returns the context. */
function compile(names, globals, prelude = '') {
  const ctx = vm.createContext(globals);
  vm.runInContext(prelude + '\n' + names.map(fnSource).join('\n'), ctx);
  return ctx;
}
/** One language's value of a key, from i18n.js (fa is the first table, en the second). */
function str(lang, key) {
  const enAt = I18N.indexOf('\n  en: {');
  assert.ok(enAt > 0, 'i18n.js has no en table');
  const part = lang === 'fa' ? I18N.slice(0, enAt) : I18N.slice(enAt);
  const m = part.match(new RegExp(`'${key.replace(/\./g, '\\.')}': '((?:[^'\\\\]|\\\\.)*)'`));
  assert.ok(m, `${lang} has no '${key}'`);
  return m[1].replace(/\\'/g, "'");
}
/** Out of the vm's realm, so deepEqual compares values and not prototypes. */
const plain = (x) => JSON.parse(JSON.stringify(x));

/** Just enough of an element for serverGroup() and renderPicker(): children, attributes, classes, a click. */
function fakeEl(tag) {
  const el = {
    tagName: tag.toUpperCase(), children: [], attrs: {}, dataset: {}, hidden: false, disabled: false,
    textContent: '', title: '', className: '', type: '', id: '', dir: '', onclick: null, html: '',
    classList: {
      toggle(c, on) {
        const set = new Set(el.className.split(/\s+/).filter(Boolean));
        if (on === undefined ? !set.has(c) : on) set.add(c); else set.delete(c);
        el.className = [...set].join(' ');
      },
      contains: (c) => el.className.split(/\s+/).includes(c)
    },
    appendChild(c) { el.children.push(c); return c; },
    get firstChild() { return el.children[0] || null; },
    setAttribute(k, v) { el.attrs[k] = String(v); },
    getAttribute(k) { return k in el.attrs ? el.attrs[k] : null; },
    // innerHTML is only ever a template here; the parts it names are looked up by class
    parts: {},
    querySelector(sel) { return el.parts[sel] || (el.parts[sel] = fakeEl('span')); },
    set innerHTML(v) { el.html = v; },
    get innerHTML() { return el.html; }
  };
  return el;
}
const hasClass = (el, cls) => el.className.split(/\s+/).includes(cls);
const byClass = (el, cls) => (hasClass(el, cls) ? [el] : []).concat(...el.children.map((c) => byClass(c, cls)));
const tick = () => new Promise((r) => setImmediate(r));

/* ------------------------------------ strings ------------------------------------ */

test('the four strings exist once in fa and once in en, and the picker’s label takes the subscription’s name', () => {
  const want = {
    'srv.groupPing': ['پینگ همهٔ کانفیگ‌های این گروه', 'Test every config in this group'],
    'srv.groupFastest': ['وصل به سریع‌ترینِ این گروه', 'Connect to the fastest in this group'],
    'picker.autoSub': ['سریع‌ترین — {name}', 'Fastest — {name}'],
    't.autoGroupNone': ['هیچ کانفیگی در این گروه جواب نداد', 'Nothing in this group answered']
  };
  for (const [key, [fa, en]] of Object.entries(want)) {
    assert.equal(I18N.split(`'${key}':`).length - 1, 2, `'${key}' is not defined exactly once in each of fa and en`);
    assert.equal(str('fa', key), fa, `fa ${key}`);
    assert.equal(str('en', key), en, `en ${key}`);
  }
  // the global Auto's own strings are what they were
  assert.equal(str('en', 'picker.auto'), 'Auto (fastest)');
  assert.equal(str('en', 't.autoNone'), 'No server answered');
});

/* ------------------------------- the group's head ------------------------------- */

const HOUR = 3600;
const SUB = { id: 'sub1', name: 'Sub one', lastUpdated: 1, usage: { upload: 0, download: 40 * 2 ** 30, total: 50 * 2 ** 30, expire: Date.now() / 1000 + 12.5 * 24 * HOUR } };

function headHarness() {
  const calls = [];
  const gate = { release: null };
  const ctx = compile(['serverGroup', 'groupKey', 'setGroupFolded', 'loadFoldedGroups', 'subUsageBrief', 'fmtBytes', 'fmtDuration'], {
    localStorage: { getItem: () => null, setItem: () => {} },
    document: { createElement: fakeEl },
    t: (k) => k,
    timeAgo: () => '5 min',
    refreshSub: async () => {},
    serverCard: () => fakeEl('div'),
    pingMany: (ids) => { calls.push(['pingMany', [...ids]]); return new Promise((resolve) => { gate.release = resolve; }); },
    connectAuto: (scope) => { calls.push(['connectAuto', plain(scope)]); },
    Date, Math, JSON, Set, Array, String, Infinity
  }, "const FOLDED_KEY = 'irnetfree.foldedGroups';\nconst foldedGroups = loadFoldedGroups();");
  return { ctx, calls, gate };
}
/** The head's children, each named by its srv-group-* class, in document order. */
const headKinds = (wrap) => wrap.children[0].children.map((c) => c.className.split(/\s+/).find((x) => /^srv-group-/.test(x)));
const items = (...ids) => ids.map((id) => ({ id }));

test('a group with two or more configs gets 📶 and ⚡ — a subscription’s between its quota and its refresh, the hand-added pile’s after its name', () => {
  const h = headHarness();
  const sub = h.ctx.serverGroup({ id: 'sub1', name: 'Sub one', sub: SUB, items: items('a', 'b') }, 0);
  assert.deepEqual(headKinds(sub), ['srv-group-toggle', 'srv-group-meta', 'srv-group-ping', 'srv-group-fastest', 'srv-group-refresh'],
    'the tools read in the order the page does: quota, then test, connect, refresh');
  const [ping] = byClass(sub, 'srv-group-ping');
  const [fast] = byClass(sub, 'srv-group-fastest');
  for (const [btn, glyph, key] of [[ping, '📶', 'srv.groupPing'], [fast, '⚡', 'srv.groupFastest']]) {
    assert.equal(btn.tagName, 'BUTTON');
    assert.equal(btn.type, 'button', 'never a submit');
    assert.equal(btn.textContent, glyph);
    assert.equal(btn.title, key);
    assert.equal(btn.getAttribute('aria-label'), key, 'an emoji alone is no accessible name');
    assert.equal(hasClass(btn, 'icon-btn'), true, 'the refresh’s own base class: same size, hover and focus ring');
  }

  const manual = h.ctx.serverGroup({ id: '', name: 'srv.manual', sub: null, items: items('m1', 'm2', 'm3') }, 1);
  assert.deepEqual(headKinds(manual), ['srv-group-toggle', 'srv-group-ping', 'srv-group-fastest'],
    'what was added by hand has the two, and no subscription to refresh');

  const gone = h.ctx.serverGroup({ id: 'old', name: 'srv.subGone', sub: null, items: items('g1', 'g2') }, 2);
  assert.deepEqual(headKinds(gone), ['srv-group-toggle', 'srv-group-ping', 'srv-group-fastest'],
    'a deleted subscription’s servers are still a group worth testing');
});

test('a group of one config gets neither: there is nothing to rank or to choose between', () => {
  const h = headHarness();
  const one = h.ctx.serverGroup({ id: 'sub1', name: 'Sub one', sub: SUB, items: items('a') }, 0);
  assert.deepEqual(headKinds(one), ['srv-group-toggle', 'srv-group-meta', 'srv-group-refresh'], 'the refresh and the quota are as they were');
  assert.deepEqual(byClass(one, 'srv-group-ping'), []);
  assert.deepEqual(byClass(one, 'srv-group-fastest'), []);
  const manual = h.ctx.serverGroup({ id: '', name: 'srv.manual', sub: null, items: items('m1') }, 1);
  assert.deepEqual(headKinds(manual), ['srv-group-toggle']);
});

test('📶 tests this group’s configs, one test at a time; ⚡ connects to its fastest, naming the group', async () => {
  const h = headHarness();
  const wrap = h.ctx.serverGroup({ id: 'sub1', name: 'Sub one', sub: SUB, items: items('a', 'b', 'c') }, 0);
  const [ping] = byClass(wrap, 'srv-group-ping');
  const [fast] = byClass(wrap, 'srv-group-fastest');

  ping.onclick();
  assert.equal(ping.disabled, true, 'a second tap while it runs would start a second test');
  assert.deepEqual(h.calls, [['pingMany', ['a', 'b', 'c']]], 'this group’s ids and nobody else’s');
  h.gate.release();
  await tick();
  assert.equal(ping.disabled, false, 'free again when the test is over');

  fast.onclick();
  assert.deepEqual(h.calls.slice(1), [['connectAuto', { ids: ['a', 'b', 'c'], name: 'Sub one' }]]);
});

/* ----------------------------- the picker's rows ----------------------------- */

const PICKER_TEXT = {
  'picker.auto': 'Auto', 'picker.autoSub': 'Fastest — {name}', 'power.cancelHint': 'Cancel connecting',
  'srv.manual': 'Added by hand', 'srv.subGone': 'Deleted subscription', 'picker.listLabel': 'Servers'
};
const srv = (id, subId) => Object.assign({ id, name: id.toUpperCase(), protocol: 'vless', address: '192.0.2.1', port: 443 }, subId ? { subId } : {});
const SUBS = [{ id: 'sa', name: 'Sub A' }, { id: 'sb', name: 'Sub B' }, { id: 'sc', name: 'Sub C' }];

function pickerHarness({ servers, subscriptions = SUBS, connecting = false }) {
  const calls = [];
  const els = new Map();
  const $ = (sel) => { if (!els.has(sel)) els.set(sel, fakeEl('div')); return els.get(sel); };
  const menu = $('#pickerMenu');
  // `menu.innerHTML = ''` clears the menu, as it does in a browser
  Object.defineProperty(menu, 'innerHTML', { configurable: true, get: () => menu.html, set: (v) => { menu.html = v; menu.children.length = 0; } });
  const ctx = compile(['renderPicker', 'serverGroups'], {
    state: { servers, subscriptions, chains: [], pool: [], settings: {}, pings: {}, selectedServerId: servers[0] && servers[0].id, connecting },
    $,
    document: { createElement: fakeEl },
    t: (k) => PICKER_TEXT[k] || k,
    escapeHtml: (s) => String(s),
    keepSelectionValid: () => {},
    chainById: () => undefined, anyChainReady: () => false, advancedReady: () => false, poolReady: () => false, poolEnabledValid: () => [],
    pingLabel: () => ({ txt: '—', cls: '' }), pingResultLabel: () => ({ txt: '—', cls: '' }),
    closePicker: () => calls.push(['closePicker']),
    connectAuto: (scope) => calls.push(['connectAuto', scope === undefined ? undefined : plain(scope)]),
    selectServer: () => {}, pingServer: () => {}, pingAllVisible: () => {}
  }, "const ADV_ID = '__advanced__';\nconst POOL_ID = '__pool__';");
  return { ctx, menu, calls };
}
const subRows = (menu) => menu.children.filter((c) => hasClass(c, 'picker-auto-sub'));
const subRowName = (row) => row.querySelector('.pi-name').textContent;

const MIXED = [srv('m1'), srv('m2'), srv('a1', 'sa'), srv('a2', 'sa'), srv('b1', 'sb'), srv('b2', 'sb'), srv('b3', 'sb'), srv('c1', 'sc')];

test('the picker adds one “Fastest — <subscription>” row per subscription with two or more servers, under the Auto row, when there are two or more groups', () => {
  const h = pickerHarness({ servers: MIXED });
  h.ctx.renderPicker();
  const rows = subRows(h.menu);
  assert.deepEqual(rows.map(subRowName), ['Fastest — Sub A', 'Fastest — Sub B'],
    'Sub C has one server and the hand-added pile has the Servers page: neither gets a row');
  for (const row of rows) {
    assert.equal(hasClass(row, 'picker-item') && hasClass(row, 'picker-special') && hasClass(row, 'picker-auto'), true, 'looks like the Auto row it sits under');
    assert.match(row.html, /<span class="proto-badge proto-auto">⚡<\/span>/);
  }
  // the Auto row first, the Fastest rows right after it, then the servers
  const order = h.menu.children.map((c) => (hasClass(c, 'picker-head') ? 'head' : hasClass(c, 'picker-auto-sub') ? 'sub' : hasClass(c, 'picker-auto') ? 'auto' : 'server'));
  assert.deepEqual(order, ['head', 'auto', 'sub', 'sub', 'server', 'server', 'server', 'server', 'server', 'server', 'server', 'server']);
});

test('the rows appear only when there is something to tell apart, and never for the hand-added pile or a single config', () => {
  // one subscription and nothing else: one group
  const one = pickerHarness({ servers: [srv('a1', 'sa'), srv('a2', 'sa'), srv('a3', 'sa')] });
  one.ctx.renderPicker();
  assert.deepEqual(subRows(one.menu), [], 'one group: the Auto row already is its fastest');
  assert.equal(one.menu.children.filter((c) => hasClass(c, 'picker-auto') && !hasClass(c, 'picker-auto-sub')).length, 1, 'and the Auto row is there');

  // hand-added and one subscription: two groups, but only the subscription is offered
  const two = pickerHarness({ servers: [srv('m1'), srv('m2'), srv('m3'), srv('a1', 'sa'), srv('a2', 'sa')] });
  two.ctx.renderPicker();
  assert.deepEqual(subRows(two.menu).map(subRowName), ['Fastest — Sub A']);

  // two groups of one: nothing to rank inside either
  const singles = pickerHarness({ servers: [srv('a1', 'sa'), srv('b1', 'sb')] });
  singles.ctx.renderPicker();
  assert.deepEqual(subRows(singles.menu), []);

  // a subscription that was deleted while its servers stayed is still named, and still a group
  const orphan = pickerHarness({ servers: [srv('a1', 'sa'), srv('a2', 'sa'), srv('x1', 'gone'), srv('x2', 'gone')] });
  orphan.ctx.renderPicker();
  assert.deepEqual(subRows(orphan.menu).map(subRowName), ['Fastest — Sub A', 'Fastest — Deleted subscription']);
});

test('a row takes the name as text — a name with markup or a replacement pattern comes out as typed', () => {
  const name = 'Fast $& <i>x</i> $\'';
  const h = pickerHarness({ servers: [srv('a1', 'sa'), srv('a2', 'sa'), srv('b1', 'sb'), srv('b2', 'sb')], subscriptions: [{ id: 'sa', name }, { id: 'sb', name: 'Sub B' }] });
  h.ctx.renderPicker();
  assert.equal(subRowName(subRows(h.menu)[0]), 'Fastest — ' + name);
  assert.doesNotMatch(subRows(h.menu)[0].html, /Fast/, 'the name never goes through innerHTML');
});

test('a row closes the picker and runs ⚡ on its group; the global Auto row is as it was, and still the first picker-auto in the menu', () => {
  const h = pickerHarness({ servers: MIXED });
  h.ctx.renderPicker();
  const [a, b] = subRows(h.menu);
  b.onclick();
  a.onclick();
  assert.deepEqual(h.calls, [
    ['closePicker'], ['connectAuto', { ids: ['b1', 'b2', 'b3'], name: 'Sub B' }],
    ['closePicker'], ['connectAuto', { ids: ['a1', 'a2'], name: 'Sub A' }]
  ]);

  h.calls.length = 0;
  const autoRows = h.menu.children.filter((c) => hasClass(c, 'picker-auto'));
  const global = autoRows[0];
  assert.equal(hasClass(global, 'picker-auto-sub'), false,
    'refreshConnectControls rewrites the first ".picker-auto .pi-name" while a connect is in flight — that has to stay the global row');
  assert.match(global.html, /<span class="pi-name">Auto<\/span>/);
  global.onclick();
  assert.deepEqual(h.calls, [['closePicker'], ['connectAuto', undefined]], 'no scope: every server, as before');

  // while connecting the global row says so in its own markup, as before
  const busy = pickerHarness({ servers: MIXED, connecting: true });
  busy.ctx.renderPicker();
  assert.match(busy.menu.children.find((c) => hasClass(c, 'picker-auto')).html, /<span class="pi-name">Cancel connecting<\/span>/);
});

test('refreshConnectControls still rewrites the global Auto row, by the selector it always used', () => {
  assert.match(fnSource('refreshConnectControls'),
    /const auto = \$\('#pickerMenu \.picker-auto \.pi-name'\);\n\s*if \(auto\) auto\.textContent = t\(busy \? 'power\.cancelHint' : 'picker\.auto'\);/);
});

/* ------------------------------ ⚡: the ranking and the test ------------------------------ */

// Two groups. b1 is the fastest of all; a2 is the fastest of group A.
const PINGS = () => ({
  a1: { tcp: { ok: true, ms: 40 }, real: { ok: true, ms: 300 } },
  a2: { tcp: { ok: true, ms: 50 }, real: { ok: true, ms: 120 } },
  b1: { tcp: { ok: true, ms: 5 }, real: { ok: true, ms: 20 } },
  b2: { tcp: { ok: true, ms: 60 }, real: { ok: true, ms: 400 } }
});
const SCOPE_A = () => ({ ids: ['a1', 'a2'], name: 'Sub A' });

function autoHarness({ state: over = {}, onPing = () => {} } = {}) {
  const clock = { t: 10_000_000 };
  const calls = [];
  const state = Object.assign({
    servers: [{ id: 'a1', name: 'A one' }, { id: 'a2', name: 'A two' }, { id: 'b1', name: 'B one' }, { id: 'b2', name: 'B two' }],
    pings: PINGS(), connecting: false, connected: false, activeServerId: null
  }, over);
  const ctx = compile(['bestServerId', 'connectAuto', 'srvById'], {
    state,
    Date: { now: () => clock.t },
    t: (k) => ({ 'picker.autoSub': 'Fastest — {name}', 'picker.auto': 'Auto' }[k] || k),
    toast: (msg, kind) => calls.push(['toast', msg, kind || '']),
    cancelConnect: () => { calls.push(['cancel']); },
    connect: async (id) => { calls.push(['connect', id]); },
    // like the real one: tests, stores what it found, and stamps when it finished
    pingMany: async (ids) => {
      calls.push(['pingMany', [...ids]]);
      onPing(ids, state);
      for (const id of ids) pingAt[id] = clock.t;
    }
  }, constSource('pingAt') + constSource('GROUP_FRESH_MS'));
  const pingAt = vm.runInContext('pingAt', ctx);
  const fresh = vm.runInContext('GROUP_FRESH_MS', ctx);
  return { ctx, state, calls, clock, pingAt, FRESH: fresh, tested: () => calls.filter((c) => c[0] === 'pingMany') };
}

test('the three-minute window is three minutes', () => {
  assert.equal(autoHarness().FRESH, 3 * 60 * 1000);
});

test('⚡ on a group ranks only that group — a faster config outside it never wins — and trusts a test younger than three minutes', async () => {
  const h = autoHarness();
  h.pingAt.a1 = h.clock.t - 10_000;
  h.pingAt.a2 = h.clock.t - (h.FRESH - 1);          // just inside the window
  await h.ctx.connectAuto(SCOPE_A());
  assert.deepEqual(h.calls, [['toast', 'Fastest — Sub A → A two', 'ok'], ['connect', 'a2']],
    'b1 (20 ms) is faster than a2 (120 ms) and is not in the group; no test, the group was tested a moment ago');
});

test('⚡ on a group tests it again — that group only — when any config of it has no test younger than three minutes', async () => {
  // one of the group never tested
  let h = autoHarness();
  h.pingAt.a1 = h.clock.t - 1_000;
  await h.ctx.connectAuto(SCOPE_A());
  assert.deepEqual(h.tested(), [['pingMany', ['a1', 'a2']]], 'a2 has no result of its own, so the whole group is tested — and not b1, b2');

  // a test of exactly three minutes ago is no longer young
  h = autoHarness();
  h.pingAt.a1 = h.clock.t - 1_000;
  h.pingAt.a2 = h.clock.t - h.FRESH;
  await h.ctx.connectAuto(SCOPE_A());
  assert.equal(h.tested().length, 1);

  // an old result is not trusted, and the new ones decide: a1 got faster
  h = autoHarness({ onPing: (ids, state) => { state.pings.a1 = { tcp: { ok: true, ms: 9 }, real: { ok: true, ms: 15 } }; } });
  h.pingAt.a1 = h.clock.t - 10 * 60 * 1000;
  h.pingAt.a2 = h.clock.t - 10 * 60 * 1000;
  await h.ctx.connectAuto(SCOPE_A());
  assert.deepEqual(h.calls.map((c) => c[0] === 'pingMany' ? 'pingMany' : c.slice(0, 2).join(' ')), ['pingMany', 'toast Fastest — Sub A → A one', 'connect a1']);

  // and what that test stamped keeps the next ⚡ from testing again
  await h.ctx.connectAuto(SCOPE_A());
  assert.equal(h.tested().length, 1, 'tested once; the second ⚡ goes straight to the connect');
});

test('the TCP handshake is the fallback inside a group, and real delay still beats it', async () => {
  const h = autoHarness({ state: { pings: {
    a1: { tcp: { ok: true, ms: 30 }, real: { ok: false } },       // answers, but carries nothing
    a2: { tcp: { ok: true, ms: 500 }, real: { ok: true, ms: 900 } },
    b1: { tcp: { ok: true, ms: 5 }, real: { ok: true, ms: 20 } }
  } } });
  h.pingAt.a1 = h.pingAt.a2 = h.clock.t;
  assert.equal(h.ctx.bestServerId(['a1']), 'a1', 'TCP only: still ranked');
  assert.equal(h.ctx.bestServerId(['a1', 'a2']), 'a2', 'a real delay of 900 ms still beats a TCP handshake of 30 ms');
  assert.equal(h.ctx.bestServerId(['b2']), null, 'never tested: no answer rather than a guess');
  assert.equal(h.ctx.bestServerId(['gone', 'b1']), 'b1', 'an id that is no server any more is skipped');
  assert.equal(h.ctx.bestServerId(), 'b1', 'no ids: every server, as the global Auto ranks');
  await h.ctx.connectAuto(SCOPE_A());
  assert.deepEqual(h.calls.at(-1), ['connect', 'a2']);
});

test('⚡ on a group where nothing answers says so, in the group’s own words, and connects to nothing', async () => {
  const dead = (ids, state) => { for (const id of ids) state.pings[id] = { tcp: { ok: false, error: 'timeout' }, real: { ok: false, error: 'timeout' } }; };
  const h = autoHarness({ state: { pings: {} }, onPing: dead });
  await h.ctx.connectAuto(SCOPE_A());
  assert.deepEqual(h.calls, [['pingMany', ['a1', 'a2']], ['toast', 't.autoGroupNone', 'err']]);

  // the global Auto keeps its own message
  const g = autoHarness({ state: { pings: {} }, onPing: dead });
  await g.ctx.connectAuto();
  assert.deepEqual(g.calls, [['pingMany', ['a1', 'a2', 'b1', 'b2']], ['toast', 't.autoNone', 'err']]);
});

test('the global Auto is untouched: it tests only when nothing was ever tested, and ranks every server', async () => {
  const h = autoHarness();                      // everything has a result; nothing was stamped
  await h.ctx.connectAuto();
  assert.deepEqual(h.calls, [['toast', 'Auto → B one', 'ok'], ['connect', 'b1']], 'no re-test, however old its results: that is Auto’s way');

  const empty = autoHarness({ state: { pings: {} }, onPing: (ids, state) => Object.assign(state.pings, PINGS()) });
  await empty.ctx.connectAuto();
  assert.deepEqual(empty.calls, [['pingMany', ['a1', 'a2', 'b1', 'b2']], ['toast', 'Auto → B one', 'ok'], ['connect', 'b1']]);
});

test('while a connect is in flight, ⚡ — a group’s or the global — is its Cancel and tests nothing', async () => {
  for (const scope of [SCOPE_A(), undefined]) {
    const h = autoHarness({ state: { connecting: true } });
    await h.ctx.connectAuto(scope);
    assert.deepEqual(h.calls, [['cancel']]);
  }
});

test('a group’s ⚡ never turns into a disconnect, and never cancels a connect somebody else started meanwhile', async () => {
  // already on the group's fastest: connect() would be its toggle
  let h = autoHarness({ state: { connected: true, activeServerId: 'a2' } });
  h.pingAt.a1 = h.pingAt.a2 = h.clock.t;
  await h.ctx.connectAuto(SCOPE_A());
  assert.deepEqual(h.calls, [['toast', 'Fastest — Sub A → A two', 'ok']], 'it says which one it is, and leaves the connection alone');

  // connected elsewhere: the switch is the point
  h = autoHarness({ state: { connected: true, activeServerId: 'b1' } });
  h.pingAt.a1 = h.pingAt.a2 = h.clock.t;
  await h.ctx.connectAuto(SCOPE_A());
  assert.deepEqual(h.calls.at(-1), ['connect', 'a2']);

  // the test takes a while; the user starts another connect (or taps another ⚡) before it ends — connect() would cancel that one
  h = autoHarness({ onPing: (ids, state) => { state.connecting = true; } });
  await h.ctx.connectAuto(SCOPE_A());
  assert.deepEqual(h.calls, [['pingMany', ['a1', 'a2']]], 'the connect that began meanwhile stands');
});

/* ------------------------------ when a test finished ------------------------------ */

function pingHarness({ withMany = true } = {}) {
  const clock = { t: 5_000 };
  const api = {
    pingTcp: async () => ({ ok: true, ms: 10 }),
    pingReal: async () => ({ ok: true, ms: 100 }),
    pingUpload: async () => ({ ok: true, ms: 50 })
  };
  if (withMany) api.pingRealMany = async (ids) => Object.fromEntries(ids.filter((id) => id !== 'silent').map((id) => [id, { ok: true, ms: 80 }]));
  const cells = {};
  const ctx = compile(['pingServer', 'pingTcpOnly', 'pingRealOnly', 'pingMany', 'quickPing'], {
    state: { pings: {}, selectedServerId: null },
    window: { api },
    Date: { now: () => clock.t },
    $: (sel) => cells[sel] || (cells[sel] = { textContent: '' }),
    t: (k) => k,
    toast: () => {},
    setPingPending: () => {}, setPhasePending: () => {}, applyPingDisplays: () => {}, renderPicker: () => {},
    Set, Array, Object
  }, constSource('pingAt') + "\nconst ADV_ID = '__advanced__';\nconst POOL_ID = '__pool__';");
  return { ctx, clock, api, pingAt: vm.runInContext('pingAt', ctx) };
}

test('every way a config’s real delay is stored also records when the test finished', async () => {
  // pingMany: one throwaway core for all of them
  let h = pingHarness();
  await h.ctx.pingMany(['a', 'b', 'silent']);
  assert.deepEqual(plain(h.pingAt), { a: 5000, b: 5000, silent: 5000 }, 'a test that came back with nothing is still a test that finished');

  // pingMany against a backend without the batch call: one at a time
  h = pingHarness({ withMany: false });
  await h.ctx.pingMany(['a', 'b']);
  assert.deepEqual(plain(h.pingAt), { a: 5000, b: 5000 });

  // a single config: the card's ⚡ (TCP, download, upload), the TCP-then-real of "quick ping", and the real-only one
  h = pingHarness();
  h.clock.t = 7000;
  await h.ctx.pingServer('s1');
  assert.equal(h.pingAt.s1, 7000);
  h.clock.t = 8000;
  await h.ctx.quickPing('s2');
  assert.equal(h.pingAt.s2, 8000);
  h.clock.t = 9000;
  await h.ctx.pingRealOnly('s3');
  assert.equal(h.pingAt.s3, 9000);

  // a pseudo target is no test
  await h.ctx.quickPing('__pool__');
  assert.equal('__pool__' in h.pingAt, false);

  // a TCP-only result is not a finished test: the group's ⚡ wants the real delay too
  const tcp = pingHarness();
  await tcp.ctx.pingTcpOnly('t1');
  assert.equal('t1' in tcp.pingAt, false);
});

test('pingServer stamps as soon as the real delay is in — the upload test after it is not what ⚡ ranks by', async () => {
  const h = pingHarness();
  let release;
  h.api.pingUpload = () => new Promise((r) => { release = () => r({ ok: true, ms: 1 }); });
  const running = h.ctx.pingServer('s1');
  for (let i = 0; i < 20 && !release; i++) await tick();
  assert.equal(h.pingAt.s1, 5000, 'stamped while the upload test is still running');
  release();
  await running;
});

/* ------------------------------------- styling ------------------------------------- */

/** The rule blocks of the stylesheet whose selector list names exactly `selector`. */
function rulesFor(selector) {
  const flat = CSS.replace(/\/\*[\s\S]*?\*\//g, '');
  const out = [];
  for (const m of flat.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
    const list = m[1].split(',').map((s) => s.trim());
    if (list.includes(selector)) out.push({ selectors: list, body: m[2] });
  }
  return out;
}

test('the three head buttons are one rule — 📶 and ⚡ look exactly like the refresh — and no skin has its own say about them', () => {
  const [rule] = rulesFor('.srv-group-refresh');
  assert.ok(rule, 'no rule for .srv-group-refresh');
  assert.deepEqual(rule.selectors.filter((s) => /^\.srv-group-(ping|fastest|refresh)$/.test(s)).sort(), ['.srv-group-fastest', '.srv-group-ping', '.srv-group-refresh']);
  assert.match(rule.body, /order:\s*1;/, 'past the rule, at the end of the row');
  assert.match(rule.body, /font-size:\s*13px;/);
  assert.equal(rulesFor('.srv-group-ping').length, 1, 'one rule, not a copy of it that can drift');
  assert.equal(rulesFor('.srv-group-fastest').length, 1);
  assert.doesNotMatch(R('src', 'renderer', 'skins.css'), /srv-group-(ping|fastest|refresh)/);
  assert.doesNotMatch(rule.body, /(?:margin|padding)-(?:left|right)|\b(?:left|right):/, 'logical properties only: the row runs both ways');
});

test('the head neither wraps nor overflows with all three buttons: the quota folds with an ellipsis, the name already did', () => {
  const [head] = rulesFor('.srv-group-head');
  assert.doesNotMatch(head.body, /flex-wrap/, 'one line');
  const [meta] = rulesFor('.srv-group-meta');
  assert.match(meta.body, /min-width:\s*0;/, 'a flex item does not shrink below its content without it');
  assert.match(meta.body, /flex:\s*0 1 auto;/, 'it gives way; the buttons beside it do not');
  assert.match(meta.body, /white-space:\s*nowrap;/);
  const [part] = rulesFor('.srv-group-meta > span');
  assert.ok(part, 'each part (the figures, the time left) folds on its own');
  assert.match(part.body, /min-width:\s*0;/);
  assert.match(part.body, /overflow:\s*hidden;/);
  assert.match(part.body, /text-overflow:\s*ellipsis;/);
  const [name] = rulesFor('.srv-group-name');
  assert.match(name.body, /text-overflow:\s*ellipsis;/);
});
