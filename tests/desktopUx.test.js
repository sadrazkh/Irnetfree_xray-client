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
