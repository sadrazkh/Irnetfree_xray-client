'use strict';
/**
 * The renderer half of the v1.15 desktop round — the same renderer the
 * router's web UI serves:
 *
 *   D1  every connect control is the connect's Cancel while one is in flight;
 *   D2  the Servers page's groups fold, remember it, and carry their
 *       subscription's own refresh and quota;
 *   D3  the selected config survives a restart (main keeps it; the renderer
 *       resolves it against what can still be selected);
 *   D4  the app's version, small, under the logo.
 *
 * app.js reaches into the DOM at load, so — like renderer.test.js — its pure
 * pieces are compiled on their own in a vm, and its wiring is read as text.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

// CRLF on a Windows checkout (core.autocrlf): the patterns below are written with \n.
const R = (...p) => fs.readFileSync(path.join(__dirname, '..', ...p), 'utf8').replace(/\r\n/g, '\n');
const APP = R('src', 'renderer', 'app.js');
const HTML = R('src', 'renderer', 'index.html');
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
/** Compile these app.js functions in a context of fakes; returns the context. */
function compile(names, globals, prelude = '') {
  const ctx = vm.createContext(globals);
  vm.runInContext(prelude + '\n' + names.map(fnSource).join('\n'), ctx);
  return ctx;
}
/** Each key defined exactly once in fa and once in en (that the file parses is syntax.test.js's). */
function assertTranslated(keys) {
  const bad = keys.filter((k) => (I18N.split(`'${k}':`).length - 1) !== 2);
  assert.deepEqual(bad, [], 'these keys are not defined exactly once in each of fa and en');
}

/* ------------------------------ D1: Cancel while connecting ------------------------------ */

function connectHarness() {
  const calls = [];
  const pending = [];
  const connState = { textContent: '' };
  const ctx = compile(['connect', 'disconnect', 'cancelConnect'], {
    state: { connecting: false, connected: false, activeServerId: null, settings: {}, assets: {}, platform: 'linux' },
    window: {
      api: {
        connect: (id) => new Promise((resolve, reject) => { calls.push('api.connect:' + id); pending.push({ resolve, reject }); }),
        disconnect: async () => { calls.push('api.disconnect'); }
      }
    },
    $: (sel) => (sel === '#connState' ? connState : { textContent: '' }),
    t: (k) => k,
    toast: (msg, kind) => calls.push('toast:' + (kind || '')),
    setConnUI: (s) => calls.push('ui:' + s),
    selectServer: () => {},
    promptRelaunchAdmin: async () => false,
    openFilesModal: () => {},
    assetsOk: true
  }, 'let connectSeq = 0;\nlet cancelledSeq = 0;');
  return { ctx, calls, pending, connState };
}

test('D1: while a connect is in flight, a connect control cancels it instead of doing nothing', async () => {
  const h = connectHarness();
  const first = h.ctx.connect('srv-a');
  assert.equal(h.ctx.state.connecting, true);
  assert.deepEqual(h.calls, ['ui:connecting', 'api.connect:srv-a']);
  // the same ▶, another server's ▶, the power button, the picker's Auto row: all the Cancel
  await h.ctx.connect('srv-b');
  assert.deepEqual(h.calls.slice(2), ['api.disconnect'], 'a disconnect, and no second connect');
  assert.equal(h.connState.textContent, 'state.cancelling', 'says so before the disconnect answers');
  // the connect in flight then fails because of the cancel: nothing to show
  h.pending[0].reject(new Error('xray exited on startup'));
  await first;
  assert.equal(h.calls.some((c) => c === 'ui:error' || c === 'toast:err'), false, 'no error painted over the Cancel');
  // a later connect that fails on its own is still an error
  h.ctx.state.connecting = false;             // the 'disconnected' status came in
  const later = h.ctx.connect('srv-a');
  h.pending[1].reject(new Error('Config error: bad'));
  await later;
  assert.deepEqual(h.calls.slice(-2), ['ui:error', 'toast:err']);
});

test('D1: the power button, the pool’s button and the picker’s Auto row are the Cancel too', () => {
  const power = APP.slice(APP.indexOf("$('#powerBtn').onclick = () => {"));
  assert.match(power, /^\$\('#powerBtn'\)\.onclick = \(\) => \{\n\s*if \(state\.connecting\) return cancelConnect\(\);\n\s*if \(state\.connected\) return disconnect\(\);/);
  const pool = APP.slice(APP.indexOf("$('#btnPoolConnect').onclick = () => {"));
  assert.match(pool, /^\$\('#btnPoolConnect'\)\.onclick = \(\) => \{\n\s*if \(state\.connecting\) return cancelConnect\(\);/);
  assert.match(fnSource('connectAuto'), /^\nasync function connectAuto\(\) \{\n\s*if \(state\.connecting\) return cancelConnect\(\);/);
  assert.match(fnSource('connect'), /^\nasync function connect\(id\) \{\n(?:\s*\/\/[^\n]*\n)*\s*if \(state\.connecting\) return cancelConnect\(\);/);
  // every ▶ is drawn by connectGlyph, and every state change redraws them
  assert.match(APP, /connectGlyph\(card\.querySelector\('\.connect-srv'\)\)\.onclick = /);
  assert.match(APP, /connectGlyph\(card\.querySelector\('\.ch-connect'\)\)\.onclick = /);
  assert.match(fnSource('setConnUI'), /refreshConnectControls\(\);\n\}$/);
});

test('D1: the controls say Cancel while connecting — the power button’s word, tooltip and accessible name, every ▶', () => {
  const els = new Map();
  const el = (id) => {
    if (!els.has(id)) els.set(id, { id, title: '', textContent: '', attrs: {}, setAttribute(k, v) { this.attrs[k] = v; } });
    return els.get(id);
  };
  const plays = [el('play1'), el('play2')];
  const ctx = compile(['refreshConnectControls', 'connectGlyph'], {
    state: { connecting: true, connected: false },
    t: (k) => k,
    $: (sel) => (sel === '#powerBtn' ? el('power') : sel === '#btnPoolConnect' ? el('pool') : sel === '#pickerMenu .picker-auto .pi-name' ? el('auto') : null),
    $$: (sel) => (sel === '.connect-srv, .ch-connect' ? plays : [])
  });
  ctx.refreshConnectControls();
  assert.equal(el('power').title, 'power.cancelHint');
  assert.equal(el('power').attrs['aria-label'], 'power.cancelHint');
  assert.deepEqual(plays.map((b) => [b.textContent, b.title]), [['■', 'power.cancel'], ['■', 'power.cancel']]);
  assert.equal(el('pool').textContent, 'power.cancel');
  assert.equal(el('auto').textContent, 'power.cancelHint');
  ctx.state.connecting = false;
  ctx.state.connected = true;
  ctx.refreshConnectControls();
  assert.equal(el('power').title, 'power.disconnect');
  assert.deepEqual(plays.map((b) => b.textContent), ['▶', '▶']);
  assert.equal(el('pool').textContent, 'pool.connect');
  assert.equal(el('auto').textContent, 'picker.auto');
  ctx.state.connected = false;
  ctx.refreshConnectControls();
  assert.equal(el('power').attrs['aria-label'], 'power.connect');

  // the visible word lives in the button and shows only while connecting
  const btn = HTML.slice(HTML.indexOf('id="powerBtn"'), HTML.indexOf('</button>', HTML.indexOf('id="powerBtn"')));
  assert.match(btn, /<span class="power-cancel" data-i18n="power\.cancel">لغو<\/span>/);
  assert.match(CSS, /\.power-cancel \{\n\s*display: none;/);
  assert.match(CSS, /\.power-btn\.connecting \.power-cancel \{ display: block; \}/);
  assertTranslated(['power.connect', 'power.disconnect', 'power.cancel', 'power.cancelHint', 'state.cancelling']);
});

/* --------------------------- D3: the selection survives a restart --------------------------- */

test('D3: the stored selection wins while it can still be connected; then the live one, the last one, the first server', () => {
  const { resolveSelection } = compile(['resolveSelection'], {});
  const servers = [{ id: 's1' }, { id: 's2' }, { id: 's3' }];
  const valid = (id) => ['s1', 's2', 's3', 'chain-ok', '__pool__'].includes(id);
  assert.equal(resolveSelection(['s3', null, 's2'], valid, servers), 's3', 'the choice itself — not the first server');
  assert.equal(resolveSelection(['gone', null, 's2'], valid, servers), 's2', 'deleted or dropped by a refresh: the last connection made');
  assert.equal(resolveSelection(['gone', null, 'also-gone'], valid, servers), 's1', 'then the first server');
  assert.equal(resolveSelection(['chain-ok'], valid, servers), 'chain-ok', 'a chain, advanced routing, the pool are selections too');
  assert.equal(resolveSelection(['chain-broken', '__pool__'], valid, servers), '__pool__');
  assert.equal(resolveSelection([null, undefined, ''], valid, []), null, 'nothing to select');
});

test('D3: whatever can be selected decides — a chain that lost a hop, advanced routing or the pool emptied fall back', () => {
  const ctx = compile(['selectable', 'chainById', 'isChainId', 'chainMembers', 'chainReady', 'srvById', 'poolTargetValid', 'poolEnabledValid', 'poolReady', 'advancedReady'], {
    state: {
      servers: [{ id: 's1' }, { id: 's2' }],
      chains: [{ id: 'c-ok', members: ['s1', 's2'] }, { id: 'c-short', members: ['s1', 'gone'] }],
      pool: [],
      settings: {}
    }
  }, "const ADV_ID = '__advanced__';\nconst POOL_ID = '__pool__';");
  assert.equal(ctx.selectable('s2'), true);
  assert.equal(ctx.selectable('gone'), false);
  assert.equal(ctx.selectable('c-ok'), true);
  assert.equal(ctx.selectable('c-short'), false, 'a chain with one hop left is no chain');
  assert.equal(ctx.selectable('__advanced__'), false);
  assert.equal(ctx.selectable('__pool__'), false);
  ctx.state.settings = { advancedRouting: true, routeRules: [{ type: 'domain', value: 'x', target: 's1' }] };
  ctx.state.pool = [{ id: 'p', enabled: true, socksPort: 60001, target: 's1' }];
  assert.equal(ctx.selectable('__advanced__'), true);
  assert.equal(ctx.selectable('__pool__'), true);
});

test('D3: a selection that is gone falls back when the picker is drawn, and main hears of a choice only when it moved', () => {
  const stored = [];
  const ctx = compile(['keepSelectionValid', 'resolveSelection'], {
    state: { servers: [{ id: 's1' }, { id: 's2' }], selectedServerId: 's2', savedSelection: 's2', activeServerId: null, lastServerId: 's1' },
    selectable: (id) => ['s1', 's2'].includes(id),
    refreshSelection: () => stored.push('refresh'),
    window: { api: { setSelection: async (id) => { stored.push(id); return id; } } }
  });
  ctx.keepSelectionValid();
  assert.deepEqual(stored, [], 'nothing moved, nothing written');
  ctx.state.servers = [{ id: 's1' }];                 // s2 deleted, or dropped by a subscription refresh
  ctx.selectable = (id) => id === 's1';
  ctx.keepSelectionValid();
  assert.equal(ctx.state.selectedServerId, 's1');
  assert.deepEqual(stored, ['refresh', 's1'], 'the cards follow, and main keeps the new choice');
  ctx.keepSelectionValid();
  assert.deepEqual(stored, ['refresh', 's1'], 'once');

  // at launch: the stored choice, the live connection, the last one made — resolved after the chains and the pool are in
  const init = fnSource('init');
  assert.match(init, /state\.savedSelection = data\.selectedServerId \|\| null;\n\s*state\.selectedServerId = resolveSelection\(\[data\.selectedServerId, data\.activeServerId, data\.lastServerId\], selectable, state\.servers\);/);
  assert.ok(init.indexOf('resolveSelection(') > init.indexOf('state.pool = '), 'the chains, the pool and the settings decide what is selectable');
  assert.doesNotMatch(init, /state\.selectedServerId = data\.activeServerId \|\|/, 'the v1.14 line that lost the choice at every restart');
  assert.match(fnSource('renderPicker'), /\n\s*keepSelectionValid\(\);\n/);
  assert.match(fnSource('deleteServer'), /if \(state\.selectedServerId === id\) state\.selectedServerId = null;/);
});

/* --------------------------- D2: the Servers page's groups fold --------------------------- */

/** Just enough of an element for serverGroup(): children, attributes, classes, a click. */
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
const byClass = (el, cls) => (el.className.split(/\s+/).includes(cls) ? [el] : []).concat(...el.children.map((c) => byClass(c, cls)));

function groupHarness(stored) {
  const storage = new Map(stored === undefined ? [] : [['irnetfree.foldedGroups', stored]]);
  const built = [];
  const refreshed = [];
  const ctx = compile(['serverGroup', 'groupKey', 'setGroupFolded', 'loadFoldedGroups', 'subUsageBrief', 'fmtBytes', 'fmtDuration'], {
    localStorage: { getItem: (k) => (storage.has(k) ? storage.get(k) : null), setItem: (k, v) => storage.set(k, String(v)) },
    document: { createElement: fakeEl },
    t: (k) => k,
    timeAgo: () => '5 min',
    refreshSub: async (id) => { refreshed.push(id); },
    serverCard: (s) => { built.push(s.id); const c = fakeEl('div'); c.className = 'server-card'; return c; },
    Date, Math, JSON, Set, Array, String, Infinity
  }, "const FOLDED_KEY = 'irnetfree.foldedGroups';\nconst foldedGroups = loadFoldedGroups();");
  return { ctx, storage, built, refreshed };
}
const HOUR = 3600;
const SUB = { id: 'sub1', name: 'Sub one', lastUpdated: 1, usage: { upload: 0, download: 40 * 2 ** 30, total: 50 * 2 ** 30, expire: Date.now() / 1000 + 12.5 * 24 * HOUR } };

test('D2: a group’s head is a button that folds it — aria-expanded, the count in it, remembered, cards built only when open', async () => {
  const h = groupHarness();
  const g = { id: 'sub1', name: 'Sub one', sub: SUB, items: [{ id: 'a' }, { id: 'b' }] };
  const wrap = h.ctx.serverGroup(g, 3);
  const [toggle] = byClass(wrap, 'srv-group-toggle');
  const [body] = byClass(wrap, 'srv-group-body');
  assert.equal(toggle.tagName, 'BUTTON');
  assert.equal(toggle.getAttribute('aria-expanded'), 'true', 'open unless folded by hand');
  assert.equal(toggle.getAttribute('aria-controls'), body.id);
  assert.equal(body.id, 'srvGroup3');
  assert.equal(toggle.querySelector('.srv-group-count').textContent, '2', 'the count is part of the head, so it shows folded too');
  assert.equal(toggle.querySelector('.srv-group-name').textContent, 'Sub one');
  assert.equal(wrap.dataset.group, 'sub:sub1');
  assert.deepEqual(h.built, ['a', 'b']);

  toggle.onclick();                                    // fold
  assert.equal(toggle.getAttribute('aria-expanded'), 'false');
  assert.equal(body.hidden, true);
  assert.equal(wrap.classList.contains('folded'), true);
  assert.deepEqual(JSON.parse(h.storage.get('irnetfree.foldedGroups')), ['sub:sub1'], 'remembered across restarts');
  toggle.onclick();                                    // and open again
  assert.equal(toggle.getAttribute('aria-expanded'), 'true');
  assert.equal(body.hidden, false);
  assert.deepEqual(h.built, ['a', 'b'], 'the cards it had are kept, not built twice');
  assert.deepEqual(JSON.parse(h.storage.get('irnetfree.foldedGroups')), []);
});

test('D2: a group folded last time opens folded and builds no card until it is opened', () => {
  const h = groupHarness(JSON.stringify(['manual']));
  const manual = h.ctx.serverGroup({ id: '', name: 'srv.manual', sub: null, items: [{ id: 'm1' }, { id: 'm2' }, { id: 'm3' }] }, 0);
  const [toggle] = byClass(manual, 'srv-group-toggle');
  const [body] = byClass(manual, 'srv-group-body');
  assert.equal(manual.dataset.group, 'manual');
  assert.equal(toggle.getAttribute('aria-expanded'), 'false');
  assert.equal(body.hidden, true);
  assert.deepEqual(h.built, [], 'a folded 300-server subscription costs one row');
  assert.deepEqual(byClass(manual, 'srv-group-refresh'), [], 'the hand-added pile has no subscription to refresh');
  toggle.onclick();
  assert.deepEqual(h.built, ['m1', 'm2', 'm3']);
  // storage that is not ours, or not there at all, only costs remembering
  assert.equal(groupHarness('{not json').ctx.loadFoldedGroups().size, 0);
  assert.equal(groupHarness(JSON.stringify({ a: 1 })).ctx.loadFoldedGroups().size, 0);
  assert.deepEqual([...groupHarness(JSON.stringify(['sub:x', 7, null])).ctx.loadFoldedGroups()], ['sub:x']);
});

test('D2: a subscription’s head carries its own refresh, and its quota and time left in its bars’ colours', async () => {
  const h = groupHarness();
  const wrap = h.ctx.serverGroup({ id: 'sub1', name: 'Sub one', sub: SUB, items: [{ id: 'a' }] }, 0);
  const [refresh] = byClass(wrap, 'srv-group-refresh');
  assert.equal(refresh.tagName, 'BUTTON');
  assert.equal(refresh.getAttribute('aria-label'), 'srv.subRefresh');
  refresh.onclick();
  assert.equal(refresh.disabled, true, 'one refresh at a time');
  await new Promise((r) => setImmediate(r));
  assert.deepEqual(h.refreshed, ['sub1']);
  assert.equal(refresh.disabled, false);
  const [meta] = byClass(wrap, 'srv-group-meta');
  assert.equal(meta.className, 'srv-group-meta mid', '80% of the quota used');
  assert.deepEqual(meta.children.map((c) => [c.textContent, c.dir]), [['40.0 GB / 50.0 GB', 'ltr'], ['12 sub.days sub.left', '']]);
  assert.equal(meta.title, 'sub.lastUpdate: 5 min');

  const brief = (usage) => ({ ...h.ctx.subUsageBrief({ usage }) });   // out of the vm's realm, for deepEqual
  const now = Date.now() / 1000;
  assert.deepEqual(brief(undefined), { data: '', time: '', level: '' }, 'a subscription that reports nothing shows nothing');
  assert.equal(brief({ upload: 95, download: 0, total: 100 }).level, 'bad');
  assert.equal(brief({ upload: 10, download: 0, total: 100 }).level, '');
  assert.equal(brief({ total: 0, expire: now + 2 * 24 * HOUR }).level, 'bad', 'two days left');
  assert.equal(brief({ total: 0, expire: now + 5 * 24 * HOUR }).level, 'mid');
  assert.deepEqual(brief({ total: 0, expire: now - 10 }), { data: '', time: 'sub.expired', level: 'bad' });
  assert.equal(brief({ upload: 2048, download: 0 }).data, '2.0 KB · sub.unlimited');
});

test('D2: the list is flat when there is nothing to tell apart, a folded group says it holds the selection, and it is styled both ways', () => {
  const render = fnSource('renderServers');
  assert.match(render, /if \(!labelled\) \{\n\s*for \(const g of groups\) for \(const s of g\.items\) list\.appendChild\(serverCard\(s\)\);\n\s*return;/);
  assert.match(render, /groups\.forEach\(\(g, n\) => list\.appendChild\(serverGroup\(g, n\)\)\);\n\s*refreshSelection\(\);/);
  assert.match(fnSource('refreshSelection'), /g\.classList\.toggle\('has-sel', g\.dataset\.group === selGroup\)/);
  assert.match(fnSource('serverGroups'), /sub: sub \|\| null/);
  assert.match(CSS, /\.srv-group\.folded \.srv-group-chev \{ transform: rotate\(-90deg\); \}/);
  assert.match(CSS, /\[dir="rtl"\] \.srv-group\.folded \.srv-group-chev \{ transform: rotate\(90deg\); \}/, 'folded, it points along a Persian line too');
  assert.match(CSS, /\.srv-group-body \{ display: flex; flex-direction: column; gap: 10px; \}/);
  assert.match(CSS, /\.srv-group\.folded\.has-sel \.srv-group-count \{/);
  // the Subscriptions page keeps adding and editing: nothing of it moved
  for (const id of ['btnSubAddOpen', 'btnSubAdd', 'subList', 'btnRefreshAll']) assert.match(HTML, new RegExp(`id="${id}"`));
  assertTranslated(['srv.groupToggle', 'srv.subRefresh']);
});
