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
