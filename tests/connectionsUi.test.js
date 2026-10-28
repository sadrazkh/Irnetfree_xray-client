'use strict';
/**
 * The Logs page's Connections tab (src/renderer/connections.js). Like
 * tests/lanUsersUi.test.js the file runs in a vm over a DOM of plain objects
 * (innerHTML throws), with the REAL i18n.js beside it, so every string is
 * checked in Persian and in English; window.api is a fake conns:get /
 * conns:close whose answers are connectionsWatch.js's shape, and the page's
 * timer is the test's — a read happens when the test says so.
 *
 * Drawn: the apps folded to their heads (the program's name left to right,
 * how many, rates, bytes), a connection's row once unfolded (where to, TCP /
 * UDP, from which device, bytes, age, the way it took and the rule, the close
 * button), the filter, why there is nothing to show, the rows holding still
 * while the pointer is on the list, a close; the polling only while on screen
 * and connected. Then the markup, app.js's wiring and the styles.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const R = (...p) => fs.readFileSync(path.join(__dirname, '..', ...p), 'utf8').replace(/\r\n/g, '\n');
const PAGE = R('src', 'renderer', 'connections.js');
const I18N = R('src', 'renderer', 'i18n.js');
const clone = (v) => JSON.parse(JSON.stringify(v));

/* ------------------------------ a DOM of plain objects ------------------------------ */

class FakeText {
  constructor(data) { this.nodeType = 3; this.data = String(data); this.parentNode = null; }
  get textContent() { return this.data; }
}
class FakeEl {
  constructor(doc, tag) {
    Object.assign(this, { ownerDocument: doc, nodeType: 1, tagName: String(tag).toUpperCase(), childNodes: [], parentNode: null,
      attributes: {}, listeners: {}, hidden: false, disabled: false, dataset: {}, style: {}, value: '', checked: false, type: '', id: '', title: '', placeholder: '' });
    const cls = this._cls = new Set();
    this.classList = {
      add: (...c) => c.forEach((x) => cls.add(x)),
      remove: (...c) => c.forEach((x) => cls.delete(x)),
      toggle: (c, on) => { const v = on === undefined ? !cls.has(c) : !!on; if (v) cls.add(c); else cls.delete(c); return v; },
      contains: (c) => cls.has(c)
    };
  }
  get className() { return [...this._cls].join(' '); }
  set className(v) { this._cls.clear(); String(v).split(/\s+/).filter(Boolean).forEach((c) => this._cls.add(c)); }
  get children() { return this.childNodes.filter((n) => n.nodeType === 1); }
  appendChild(n) { if (n.parentNode) n.parentNode.removeChild(n); this.childNodes.push(n); n.parentNode = this; this.ownerDocument.moves++; return n; }
  insertBefore(n, ref) {
    if (!ref) return this.appendChild(n);
    if (n.parentNode) n.parentNode.removeChild(n);
    this.childNodes.splice(this.childNodes.indexOf(ref), 0, n);
    n.parentNode = this;
    this.ownerDocument.moves++;
    return n;
  }
  append(...nodes) { for (const n of nodes) this.appendChild(typeof n === 'string' ? new FakeText(n) : n); }
  removeChild(n) { const i = this.childNodes.indexOf(n); if (i > -1) this.childNodes.splice(i, 1); n.parentNode = null; return n; }
  replaceChildren(...nodes) { for (const c of this.childNodes) c.parentNode = null; this.childNodes = []; this.append(...nodes); }
  get textContent() { return this.childNodes.map((c) => c.textContent).join(''); }
  set textContent(v) { for (const c of this.childNodes) c.parentNode = null; this.childNodes = []; if (v != null && v !== '') this.childNodes.push(Object.assign(new FakeText(v), { parentNode: this })); }
  get innerHTML() { throw new Error('innerHTML read'); }
  set innerHTML(v) { throw new Error(`innerHTML: ${JSON.stringify(String(v).slice(0, 60))} went into the DOM as HTML`); }
  setAttribute(k, v) { this.attributes[k] = String(v); }
  getAttribute(k) { return Object.prototype.hasOwnProperty.call(this.attributes, k) ? this.attributes[k] : null; }
  removeAttribute(k) { delete this.attributes[k]; }
  addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); }
  dispatch(type, extra) { const ev = Object.assign({ type, target: this, preventDefault() {} }, extra); for (const fn of [...(this.listeners[type] || [])]) fn(ev); }
  click() { if (!this.disabled) this.dispatch('click'); }
  contains(n) { for (let x = n; x; x = x.parentNode) if (x === this) return true; return false; }
  hiddenUp() { for (let n = this; n && n.nodeType === 1; n = n.parentNode) if (n.hidden) return true; return false; }
  all(pred, out = []) { for (const c of this.childNodes) if (c.nodeType === 1) { if (pred(c)) out.push(c); c.all(pred, out); } return out; }
  byClass(c) { return this.all((n) => n.classList.contains(c)); }
  one(c) { const r = this.byClass(c); assert.equal(r.length, 1, `.${c}: ${r.length} found`); return r[0]; }
  byKey(k) { const r = this.all((n) => n.dataset.cn === k); assert.equal(r.length, 1, `[data-cn=${k}]: ${r.length} found`); return r[0]; }
}
function fakeDocument() {
  const doc = { moves: 0 };
  doc.createElement = (tag) => new FakeEl(doc, tag);
  doc.documentElement = new FakeEl(doc, 'html');
  doc.documentElement.lang = 'fa';
  doc.body = new FakeEl(doc, 'body');
  doc.documentElement.appendChild(doc.body);
  doc.querySelectorAll = () => [];   // i18n.applyI18n: no data-i18n nodes here
  doc.querySelector = () => null;
  return doc;
}

/* ------------------------------ what conns:get answers ------------------------------ */

const c = (id, o = {}) => Object.assign({
  id, dest: 'www.google.com:443', ip: '142.250.74.110', network: 'tcp', source: '172.19.0.1',
  upload: 2048, download: 3 * 1024 * 1024, up: 0, down: 0, start: 0, age: 65000, outbound: 'socks-out', chain: ['socks-out'], rule: 'final'
}, o);
function payload(over = {}) {
  return Object.assign({
    available: true, at: 1000, processes: true,
    apps: [
      { app: 'Telegram.exe', paths: ['C:\\Users\\sadra\\AppData\\Roaming\\Telegram Desktop\\Telegram.exe'], count: 1, more: 0, upload: 5 * 1024 * 1024, download: 9 * 1024 * 1024, up: 1024, down: 20480,
        connections: [c('t1', { dest: 'web.telegram.org:443', ip: '149.154.167.99', upload: 5 * 1024 * 1024, download: 9 * 1024 * 1024, up: 1024, down: 20480, age: 3725000 })] },
      { app: 'chrome.exe', paths: ['C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'], count: 2, more: 0, upload: 3072, download: 3 * 1024 * 1024 + 512, up: 0, down: 0,
        connections: [
          c('c2', { dest: '[2001:db8::5]:8443', ip: '2001:db8::5', network: 'udp', upload: 1024, download: 512, age: 4000, outbound: 'direct', chain: ['direct'], rule: 'process_name=[chrome.exe] => route(direct)' }),
          c('c1')
        ] },
      { app: '', paths: [], count: 1, more: 0, upload: 60, download: 120, up: 0, down: 0,
        connections: [c('u1', { dest: '8.8.8.8:53', ip: '8.8.8.8', network: 'udp', source: '192.168.137.45', upload: 60, download: 120, age: 1000, outbound: 'lu-tp-1', chain: ['lu-tp-1'], rule: 'rule_set=[lu-tp-1] => route(lu-tp-1)' })] }
    ],
    totals: { count: 4, upload: 5 * 1024 * 1024 + 3132, download: 12 * 1024 * 1024 + 632, up: 1024, down: 20480 }
  }, over);
}

const flush = () => new Promise((r) => setImmediate(r));

function harness({ lang = 'fa', connected = true, visible = true, router = false, data = null, api = {} } = {}) {
  const document = fakeDocument();
  const store = { data: clone(data || payload()), closeOk: true };
  const calls = [];
  const toasts = [];
  const state = { connected, visible, router };
  const timers = [];
  const window = {
    api: Object.assign({
      connsGet: async () => { calls.push(['get']); return clone(store.data); },
      connsClose: async (id) => { calls.push(['close', id]); return store.closeOk ? { ok: true } : { ok: false, error: 'HTTP 500' }; }
    }, api)
  };
  const fakeSetTimeout = (fn, ms) => { const h = { fn, ms, done: false }; timers.push(h); return h; };
  const fakeClearTimeout = (h) => { if (h) h.done = true; };
  const ctx = vm.createContext({ window, document, console, setTimeout: fakeSetTimeout, clearTimeout: fakeClearTimeout });
  vm.runInContext(I18N, ctx, { filename: 'i18n.js' });
  vm.runInContext(PAGE, ctx, { filename: 'connections.js' });
  window.i18n.applyI18n(lang);
  const host = document.createElement('div');
  host.id = 'connsPage';
  document.body.appendChild(host);
  const hooks = {
    connected: () => state.connected,
    visible: () => state.visible,
    router: () => state.router,
    toast: (msg, kind) => toasts.push([msg, kind || ''])
  };
  const page = window.connsPage;
  const mounted = page.mount(host, hooks);
  const t = (k) => window.i18n.t(k);
  /** The pending timer fires (the page's next read), if there is one. */
  async function tick() {
    const h = timers.filter((x) => !x.done).at(-1);
    if (!h) return false;
    h.done = true;
    await h.fn();
    await flush();
    return true;
  }
  const pending = () => timers.filter((x) => !x.done);
  async function open() { await page.open(); await flush(); }
  const app = (name) => host.all((n) => n.classList.contains('cn-app') && n.dataset.app === name)[0];
  const conn = (id) => host.all((n) => n.classList.contains('cn-conn') && n.dataset.id === id)[0];
  const list = () => host.one('cn-list');
  return { window, document, host, page, mounted, store, calls, toasts, state, timers, pending, tick, open, t, app, conn, list };
}

/* ------------------------------ drawing ------------------------------ */

test('in Persian, connected over sing-box\'s TUN: the apps folded, the busiest first, each named left to right with its count, rates and bytes', async () => {
  const h = harness();
  assert.equal(h.mounted, true);
  assert.equal(h.calls.length, 0, 'mounted: nothing asked until the tab opens');
  const reading = h.page.open();
  assert.equal(h.host.one('cn-status').textContent, h.t('cn.loading'), 'drawn while the first read is on its way');
  await reading;
  await flush();
  const { host, t } = h;
  assert.deepEqual(h.calls, [['get']]);
  assert.equal(host.one('cn-status').hidden, true, 'nothing to say');
  assert.equal(host.one('cn-sum').textContent, '4 اتصال');
  assert.equal(host.one('cn-sum-rate').textContent, '↓ 20.0 KB/s  ↑ 1.0 KB/s');
  assert.equal(host.one('cn-sum-rate').getAttribute('dir'), 'ltr');
  const apps = host.byClass('cn-app');
  assert.deepEqual(apps.map((a) => a.dataset.app), ['Telegram.exe', 'chrome.exe', '']);
  const tg = h.app('Telegram.exe');
  assert.equal(tg.one('cn-name').textContent, 'Telegram.exe');
  assert.equal(tg.one('cn-name').getAttribute('dir'), 'ltr', 'a program\'s name left to right in a Persian line');
  assert.equal(tg.one('cn-count').textContent, '1 اتصال');
  assert.equal(tg.one('cn-rate').textContent, '↓ 20.0 KB/s  ↑ 1.0 KB/s');
  assert.equal(tg.one('cn-bytes').textContent, '↓ 9.0 MB  ↑ 5.0 MB');
  assert.equal(tg.one('cn-head').title, 'C:\\Users\\sadra\\AppData\\Roaming\\Telegram Desktop\\Telegram.exe', 'its full path in the tooltip');
  assert.equal(tg.one('cn-head').getAttribute('aria-expanded'), 'false');
  assert.equal(tg.one('cn-caret').textContent, '◂', 'folded, pointing the way a Persian line reads');
  assert.equal(h.app('chrome.exe').one('cn-rate').hidden, true, 'nothing moving: no rate line');
  const unknown = h.app('');
  assert.equal(unknown.one('cn-name').textContent, 'برنامهٔ نامعلوم');
  assert.equal(unknown.one('cn-name').getAttribute('dir'), null, 'Persian words, not a file name');
  assert.equal(host.byClass('cn-conn').length, 0, 'folded: no connection rows at all');
  assert.equal(host.byKey('filter').placeholder, t('cn.filter'));
  assert.equal(host.byKey('expand').textContent, 'باز کردن همه');
});

test('an app unfolded: a row per connection — where to (left to right), TCP / UDP, its bytes and age, the way it took with the rule, the close button; a device on the hotspot named', async () => {
  const h = harness();
  await h.open();
  h.app('chrome.exe').one('cn-head').click();
  const chrome = h.app('chrome.exe');
  assert.equal(chrome.one('cn-head').getAttribute('aria-expanded'), 'true');
  assert.equal(chrome.one('cn-caret').textContent, '▾');
  assert.deepEqual(chrome.byClass('cn-conn').map((r) => r.dataset.id), ['c2', 'c1'], 'in the order the watch sent (newest first)');
  const c1 = h.conn('c1');
  assert.equal(c1.one('cn-dest').textContent, 'www.google.com:443');
  assert.equal(c1.one('cn-dest').getAttribute('dir'), 'ltr');
  assert.equal(c1.one('cn-dest').title, 'www.google.com:443 · 142.250.74.110', 'the address behind the name');
  assert.equal(c1.one('cn-net').textContent, 'TCP');
  assert.equal(c1.one('cn-bytes').textContent, '↓ 3.0 MB  ↑ 2.0 KB');
  assert.equal(c1.one('cn-age').textContent, '1 دقیقه');
  assert.equal(c1.one('cn-out').textContent, 'تونل');
  assert.equal(c1.one('cn-out').className, 'cn-out cn-out-tunnel');
  assert.equal(c1.one('cn-out').title, 'قاعدهٔ پیش‌فرضِ تونل');
  assert.equal(c1.one('cn-from').hidden, true, 'this PC: no "from"');
  const x = h.host.byKey('x:c1');
  assert.equal(x.getAttribute('aria-label'), 'بستن این اتصال');
  assert.equal(x.title, 'بستن این اتصال');
  const c2 = h.conn('c2');
  assert.equal(c2.one('cn-dest').textContent, '[2001:db8::5]:8443');
  assert.equal(c2.one('cn-dest').title, '[2001:db8::5]:8443', 'the address is the destination: said once');
  assert.equal(c2.one('cn-net').textContent, 'UDP');
  assert.equal(c2.one('cn-age').textContent, '4 ثانیه');
  assert.equal(c2.one('cn-out').textContent, 'مستقیم');
  assert.equal(c2.one('cn-out').title, 'process_name=[chrome.exe] => route(direct)', 'the rule that sent it there');
  // expand all: the unnamed one too — a phone on the hotspot, an outbound of its own shown by its tag
  h.host.byKey('expand').click();
  const u1 = h.conn('u1');
  assert.equal(u1.one('cn-from').hidden, false);
  assert.equal(u1.one('cn-from').textContent, 'از 192.168.137.45');
  assert.equal(u1.one('cn-out').textContent, 'lu-tp-1');
  assert.equal(u1.one('cn-out').className, 'cn-out');
  assert.equal(h.conn('t1').one('cn-age').textContent, '1 ساعت و 2 دقیقه');
  h.host.byKey('collapse').click();
  assert.equal(h.host.byClass('cn-conn').length, 0, 'collapse all');
});

test('in English: the same rows in English words', async () => {
  const h = harness({ lang: 'en' });
  await h.open();
  h.host.byKey('expand').click();
  assert.equal(h.host.one('cn-sum').textContent, '4 connections');
  assert.equal(h.app('').one('cn-name').textContent, 'Unknown app');
  assert.equal(h.app('chrome.exe').one('cn-caret').textContent, '▾');
  assert.equal(h.conn('c1').one('cn-age').textContent, '1 min');
  assert.equal(h.conn('c2').one('cn-age').textContent, '4s');
  assert.equal(h.conn('t1').one('cn-age').textContent, '1 h 2 min');
  assert.equal(h.conn('c1').one('cn-out').textContent, 'Tunnel');
  assert.equal(h.conn('c2').one('cn-out').textContent, 'Direct');
  assert.equal(h.conn('u1').one('cn-from').textContent, 'from 192.168.137.45');
  assert.equal(h.host.byKey('x:c1').getAttribute('aria-label'), 'Close this connection');
  h.host.byKey('collapse').click();
  assert.equal(h.app('Telegram.exe').one('cn-caret').textContent, '▸');
  // a language switch redraws in place
  h.window.i18n.applyI18n('fa');
  h.page.render();
  assert.equal(h.host.one('cn-sum').textContent, '4 اتصال');
  assert.equal(h.app('').one('cn-name').textContent, 'برنامهٔ نامعلوم');
});

test('the filter: by an app\'s name — all its connections; by a destination — only the ones that match, unfolded; nothing — said', async () => {
  const h = harness();
  await h.open();
  const f = h.host.byKey('filter');
  f.value = 'TELEGRAM';
  f.dispatch('input');
  assert.deepEqual(h.host.byClass('cn-app').map((a) => a.dataset.app), ['Telegram.exe'], 'case does not matter');
  assert.equal(h.host.byClass('cn-conn').length, 0, 'still folded: the name matched, not a connection');
  f.value = 'Google\\Chrome';
  f.dispatch('input');
  assert.deepEqual(h.host.byClass('cn-app').map((a) => a.dataset.app), ['chrome.exe'], 'by the program\'s path too');
  assert.equal(h.host.byClass('cn-conn').length, 0);
  f.value = 'www.google';
  f.dispatch('input');
  assert.deepEqual(h.host.byClass('cn-app').map((a) => a.dataset.app), ['chrome.exe']);
  assert.deepEqual(h.host.byClass('cn-conn').map((r) => r.dataset.id), ['c1'], 'only the match, opened for it');
  f.value = 'مستقیم';
  f.dispatch('input');
  assert.deepEqual(h.host.byClass('cn-conn').map((r) => r.dataset.id), ['c2'], 'by the way it took, in the words on screen');
  f.value = '192.168.137';
  f.dispatch('input');
  assert.deepEqual(h.host.byClass('cn-conn').map((r) => r.dataset.id), ['u1'], 'by the device it came from');
  f.value = 'nothing-like-this';
  f.dispatch('input');
  assert.equal(h.host.byClass('cn-app').length, 0);
  assert.equal(h.host.one('cn-status').textContent, h.t('cn.noMatch'));
  assert.equal(h.host.one('cn-status').hidden, false);
  f.value = '';
  f.dispatch('input');
  assert.equal(h.host.byClass('cn-app').length, 3);
  assert.equal(h.host.byClass('cn-conn').length, 0, 'back to folded');
});

/* ------------------------------ why nothing is shown ------------------------------ */

test('why nothing is shown: not connected (nothing asked), no TUN, tun2socks, the native macOS service, an API silent — and only the last one is asked again', async () => {
  const off = harness({ connected: false });
  await off.open();
  assert.deepEqual(off.calls, [], 'not connected: nothing asked');
  assert.equal(off.host.one('cn-status').textContent, off.t('cn.why.off'));
  assert.equal(off.host.one('cn-bar').hidden, true);
  assert.equal(off.pending().length, 0);
  for (const [answer, key] of [
    [{ available: false, reason: 'noTun' }, 'cn.why.noTun'],
    [{ available: false, reason: 'backend', backend: 'tun2socks' }, 'cn.why.tun2socks'],
    [{ available: false, reason: 'backend', backend: 'native-macos' }, 'cn.why.native'],
    [{ available: false, reason: 'backend', backend: 'something' }, 'cn.why.backend']
  ]) {
    const h = harness({ data: answer });
    await h.open();
    assert.equal(h.host.one('cn-status').textContent, h.t(key), key);
    assert.equal(h.pending().length, 0, `${key}: no next read — only a new connection can change it`);
    assert.equal(h.host.one('cn-list').hidden, true);
  }
  const err = harness({ data: { available: false, reason: 'error', error: 'HTTP 401' } });
  await err.open();
  assert.equal(err.host.one('cn-status').textContent, 'فهرستِ اتصال‌های تونل جواب نداد: HTTP 401');
  assert.ok(err.host.one('cn-status').classList.contains('cn-warn'));
  assert.equal(err.pending().length, 1, 'an API that did not answer is asked again');
  const thrown = harness({ api: { connsGet: async () => { throw new Error('unknown channel: conns:get'); } } });
  await thrown.open();
  assert.match(thrown.host.one('cn-status').textContent, /unknown channel: conns:get/);
  const garbage = harness({ api: { connsGet: async () => 'nope' } });
  await garbage.open();
  assert.match(garbage.host.one('cn-status').textContent, /no answer/);
});

test('an empty tunnel, and a sing-box that named no program: each said', async () => {
  const none = harness({ data: payload({ apps: [], totals: { count: 0, upload: 0, download: 0, up: 0, down: 0 } }) });
  await none.open();
  assert.equal(none.host.one('cn-status').textContent, none.t('cn.none'));
  assert.equal(none.host.byKey('expand').hidden, true);
  const unnamed = harness({ data: payload({ processes: false, apps: [payload().apps[2]] }) });
  await unnamed.open();
  assert.equal(unnamed.host.one('cn-status').textContent, unnamed.t('cn.noProcess'));
  assert.equal(unnamed.host.byClass('cn-app').length, 1);
});

test('mount: not on a back end without conns:get, not on the router — the caller hides the tab', () => {
  assert.equal(harness({ api: { connsGet: undefined } }).mounted, false);
  const r = harness({ router: true });
  assert.equal(r.mounted, false);
  assert.equal(r.host.hidden, true);
});

/* ------------------------------ reading ------------------------------ */

test('the polling: a read every 1.5 s while on screen and connected; none once the tab is left; a disconnect forgets everything, a connect while on screen reads at once', async () => {
  const h = harness();
  await h.open();
  assert.equal(h.pending().length, 1);
  assert.equal(h.pending()[0].ms, 1500);
  assert.equal(h.page.polling(), true);
  await h.tick();
  assert.deepEqual(h.calls, [['get'], ['get']]);
  // the tab left: the timer fires once more, asks nothing, and stops
  h.state.visible = false;
  await h.tick();
  assert.equal(h.calls.length, 2, 'off screen: nothing asked');
  assert.equal(h.pending().length, 0);
  assert.equal(h.page.polling(), false);
  // back on screen
  h.state.visible = true;
  await h.open();
  assert.equal(h.calls.length, 3);
  // disconnected: the timer goes, the rows go, the status says why
  h.state.connected = false;
  h.page.connection(false);
  assert.equal(h.pending().length, 0);
  assert.equal(h.host.byClass('cn-app').length, 0);
  assert.equal(h.host.one('cn-status').textContent, h.t('cn.why.off'));
  // connected again while on screen: read at once
  h.state.connected = true;
  h.page.connection(true);
  await flush();
  assert.equal(h.calls.length, 4);
  assert.equal(h.host.byClass('cn-app').length, 3);
  // …and while off screen: nothing until the tab opens
  h.state.visible = false;
  h.page.connection(false);
  h.page.connection(true);
  await flush();
  assert.equal(h.calls.length, 4);
});

test('a read that lands after a disconnect is dropped', async () => {
  let release;
  const h = harness({ api: { connsGet: () => new Promise((r) => { release = r; }) } });
  const p = h.page.open();
  h.state.connected = false;
  h.page.connection(false);
  release(payload());
  await p;
  await flush();
  assert.equal(h.host.byClass('cn-app').length, 0);
  assert.equal(h.pending().length, 0);
});

/* ------------------------------ holding still, closing ------------------------------ */

test('while the pointer is on the list no row comes, goes or moves — one that ended is dimmed; when it leaves, the list catches up', async () => {
  const h = harness();
  await h.open();
  h.host.byKey('expand').click();
  const before = h.document.moves;
  h.list().dispatch('pointerenter');
  // the next read: chrome's c1 ended, a new connection and a new app arrived, and the order changed
  const next = payload();
  next.apps[1].connections = [c('c3', { dest: 'mail.google.com:443' }), next.apps[1].connections[0]];
  next.apps.unshift({ app: 'Code.exe', paths: [], count: 1, more: 0, upload: 99 * 1024 * 1024, download: 99 * 1024 * 1024, up: 0, down: 0, connections: [c('v1')] });
  next.apps[1].upload = 1;   // Telegram is no longer the busiest — but it stays where it is for now
  h.store.data = next;
  await h.tick();
  assert.equal(h.document.moves, before, 'not one node added, moved or removed');
  assert.deepEqual(h.host.byClass('cn-app').map((a) => a.dataset.app), ['Telegram.exe', 'chrome.exe', '']);
  assert.equal(h.conn('c3'), undefined, 'the new connection waits');
  assert.ok(h.conn('c1').classList.contains('cn-gone'), 'the ended one dimmed in place');
  assert.equal(h.host.byKey('x:c1').disabled, true);
  assert.equal(h.conn('c2').classList.contains('cn-gone'), false);
  // the words still change
  assert.equal(h.host.one('cn-sum').textContent, '4 اتصال');
  h.list().dispatch('pointerleave');
  assert.deepEqual(h.host.byClass('cn-app').map((a) => a.dataset.app), ['Code.exe', 'Telegram.exe', 'chrome.exe', '']);
  assert.deepEqual(h.app('chrome.exe').byClass('cn-conn').map((r) => r.dataset.id), ['c3', 'c2']);
  assert.equal(h.conn('c1'), undefined);
  assert.equal(h.app('Code.exe').byClass('cn-conn').length, 0, 'a new app comes folded');
});

test('focus in the list holds it still too (a keyboard user on a close button)', async () => {
  const h = harness();
  await h.open();
  h.host.byKey('expand').click();
  h.list().dispatch('focusin');
  const next = payload();
  next.apps[1].connections = [next.apps[1].connections[0]];
  h.store.data = next;
  await h.tick();
  assert.ok(h.conn('c1').classList.contains('cn-gone'));
  h.list().dispatch('focusout', { relatedTarget: h.host.byKey('x:c2') });
  assert.ok(h.conn('c1'), 'the focus moved inside the list: still holding');
  h.list().dispatch('focusout', { relatedTarget: null });
  assert.equal(h.conn('c1'), undefined);
});

test('close: the ✕ asks conns:close with the id; the row dims while the pointer is there and goes when it leaves; a refusal is said and the button comes back', async () => {
  const h = harness();
  await h.open();
  h.app('chrome.exe').one('cn-head').click();
  h.list().dispatch('pointerenter');
  h.host.byKey('x:c1').click();
  await flush();
  assert.deepEqual(h.calls.at(-1), ['close', 'c1']);
  assert.ok(h.conn('c1').classList.contains('cn-gone'));
  assert.equal(h.host.byKey('x:c1').disabled, true);
  // the next read still lists it (sing-box takes a moment): still dimmed, not back
  await h.tick();
  assert.ok(h.conn('c1').classList.contains('cn-gone'));
  h.list().dispatch('pointerleave');
  assert.equal(h.conn('c1'), undefined, 'gone once the pointer leaves');
  // the read after: the tunnel listing it again would not bring it back before it is gone from the list
  await h.tick();
  assert.equal(h.conn('c1'), undefined);
  // a refusal
  h.store.closeOk = false;
  h.host.byKey('x:c2').click();
  await flush();
  assert.deepEqual(h.toasts.at(-1), ['اتصال بسته نشد: HTTP 500', 'err']);
  assert.equal(h.host.byKey('x:c2').disabled, false);
  assert.equal(h.conn('c2').classList.contains('cn-gone'), false);
});

/* ------------------------------ markup, wiring, styles ------------------------------ */

test('the markup: two tabs in the Logs page\'s head, the log and the connections as their panels, the script before app.js', () => {
  const html = R('src', 'renderer', 'index.html');
  const view = html.slice(html.indexOf('<section class="view" id="view-logs">'), html.indexOf('</section>', html.indexOf('id="view-logs"')));
  assert.match(view, /<div class="seg logs-tabs" role="tablist" id="logsTabs">/);
  assert.match(view, /<button class="seg-btn active" type="button" role="tab" id="logsTabLog" aria-selected="true" aria-controls="logBox" data-i18n="logs\.tabLog">/);
  assert.match(view, /<button class="seg-btn" type="button" role="tab" id="logsTabConns" aria-selected="false" aria-controls="connsPage" data-i18n="logs\.tabConns">/);
  assert.match(view, /<pre class="logbox" id="logBox" role="tabpanel" aria-labelledby="logsTabLog"><\/pre>/);
  assert.match(view, /<div class="conns" id="connsPage" role="tabpanel" aria-labelledby="logsTabConns" hidden><\/div>/);
  assert.match(html, /<button class="nav-item pro-only" data-view="logs"/, 'pro-only, as the log');
  const scripts = [...html.matchAll(/<script src="([^"]+)"><\/script>/g)].map((m) => m[1]);
  assert.ok(scripts.indexOf('i18n.js') < scripts.indexOf('connections.js') && scripts.indexOf('connections.js') < scripts.indexOf('app.js'), scripts.join(', '));
});

test('app.js: mounts the tab after the Users page, switches the tabs, opens it with the view, hands it each connection change and the language', () => {
  const app = R('src', 'renderer', 'app.js');
  assert.match(app, /mountLanUsers\(\);\n {2}mountConns\(\);/);
  assert.match(app, /let logsTabNow = 'log';[^\n]*\nfunction showView\(view\) \{/, 'declared before anything can show a view');
  assert.match(app, /if \(view === 'logs' && logsTabNow === 'conns' && window\.connsPage\) window\.connsPage\.open\(\);/);
  assert.match(app, /if \(window\.connsPage\) window\.connsPage\.connection\(live\);/);
  assert.match(app, /if \(window\.connsPage\) window\.connsPage\.render\(\);/);
  const fn = app.slice(app.indexOf('function logsTab(name)'), app.indexOf('/** The Users page'));
  assert.match(fn, /\$\('#btnClearLogs'\)\.hidden = conns;/, 'the Clear button is the log\'s');
  assert.match(fn, /\$\('#logBox'\)\.hidden = conns;\n\s*\$\('#connsPage'\)\.hidden = !conns;/);
  assert.match(fn, /if \(conns && \$\('#view-logs'\)\.classList\.contains\('active'\)\) window\.connsPage\.open\(\);/);
  assert.match(fn, /visible: \(\) => logsTabNow === 'conns' && \$\('#view-logs'\)\.classList\.contains\('active'\),/);
  assert.match(fn, /router: \(\) => state\.flavor === 'openwrt',/);
  assert.match(fn, /\$\('#logsTabs'\)\.hidden = !on;/, 'no tab bar where the tab cannot be');
});

test('every class the tab draws has a style; no literal colours, logical properties only; a phone puts the figures under the destination', () => {
  const css = R('src', 'renderer', 'settings.css');
  const cls = new Set();
  for (const m of PAGE.matchAll(/mk\('[a-z]+', '([^']+)'/g)) m[1].split(/\s+/).forEach((x) => cls.add(x));
  for (const m of PAGE.matchAll(/button\('([^']+)'/g)) m[1].split(/\s+/).forEach((x) => cls.add(x));
  for (const x of ['cn-gone', 'cn-warn', 'cn-out-tunnel', 'cn-out-direct']) cls.add(x);
  const own = [...cls].filter((x) => x.startsWith('cn-'));
  assert.ok(own.length >= 20, `found ${own.length}`);
  for (const x of own) assert.match(css, new RegExp('\\.' + x + '(?![\\w-])'), `.${x} has no style`);
  const block = css.slice(css.indexOf('the tunnel\'s live connections (connections.js)'), css.indexOf('Choices with consequences, as cards'));
  assert.ok(block.length > 2000);
  assert.doesNotMatch(block, /#[0-9a-f]{3,8}\b(?![\w-])|rgba?\(/i, 'no literal colours: the skins pick them');
  assert.doesNotMatch(block, /(?:margin|padding|border)-(?:left|right)|text-align:\s*(?:left|right)|\b(?:left|right):/, 'logical properties only: the app runs RTL');
  assert.match(block, /\.logs-tabs\[hidden\], #btnClearLogs\[hidden\], \.logbox\[hidden\], \.conns\[hidden\], \.conns \[hidden\] \{ display: none; \}/, 'a display rule never beats `hidden`');
  assert.match(block, /height: calc\(100vh - var\(--tbh\) - 120px\);/, 'the log box\'s own height');
  assert.match(block, /@media \(max-width: 560px\) \{[\s\S]*\.cn-fill \{ flex-basis: 100%; height: 0; \}[\s\S]*\.cn-dest \{ order: -3; max-width: calc\(100% - 44px\); \}\n\s*\.cn-x \{ order: -2; margin-inline-start: auto; \}\n\s*\.cn-conn \.cn-fill \{ order: -1; \}/);
  assert.match(block, /\.cn-fill \{ flex: 1 1 0; min-width: 0; \}/, 'the name and the destination keep to the row\'s start');
});

test('every string the tab uses is in Persian and in English', () => {
  const ctx = vm.createContext({ window: {}, document: fakeDocument(), console });
  vm.runInContext(I18N, ctx);
  const keys = new Set([...PAGE.matchAll(/t\('((?:cn|logs)\.[\w.]+)'\)/g)].map((m) => m[1]));
  for (const k of ['cn.why.tun2socks', 'cn.why.native', 'cn.why.backend', 'cn.out.tunnel', 'cn.out.direct', 'logs.tabLog', 'logs.tabConns']) keys.add(k);
  assert.ok(keys.size >= 25, `found ${keys.size}`);
  for (const lang of ['fa', 'en']) {
    ctx.window.i18n.applyI18n(lang);
    for (const k of keys) assert.notEqual(ctx.window.i18n.t(k), k, `${lang}: ${k}`);
  }
});
