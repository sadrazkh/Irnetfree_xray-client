'use strict';
/**
 * The Users page (src/renderer/lanUsers.js) — the same renderer in the window
 * and on the router's page. Like tests/multiWanUi.test.js the file runs in a vm
 * over a DOM of plain objects (innerHTML throws), with the REAL i18n.js beside
 * it, so every string is checked in Persian and in English; window.api is a fake
 * service that keeps a store and answers the whole lanusers:get payload after
 * every write, as the contract's channels do.
 *
 * Drawn: the settings card (proxy accounts, ports, the address to give people
 * left to right, the Windows hotspot note; on the router the transparent mode),
 * a box per user (state, password hidden / shown / copied / renewed, the config
 * picker by subscription, the cap with its usage bar and period end, the expiry
 * in the Persian calendar, the device limit on the router, the switch), the
 * add / edit dialog with the username and password rules, delete after asking,
 * and the router's devices (online first, IP and MAC left to right, user, block,
 * usage, live rates while connected).
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { webcrypto } = require('node:crypto');

const R = (...p) => fs.readFileSync(path.join(__dirname, '..', ...p), 'utf8').replace(/\r\n/g, '\n');
const PAGE = R('src', 'renderer', 'lanUsers.js');
const I18N = R('src', 'renderer', 'i18n.js');
const GIB = 1024 ** 3;
const DAY = 86400000;
const clone = (v) => JSON.parse(JSON.stringify(v));

/* ------------------------------ a DOM of plain objects ------------------------------ */

class FakeText {
  constructor(data) { this.nodeType = 3; this.data = String(data); this.parentNode = null; }
  get textContent() { return this.data; }
}
class FakeEl {
  constructor(doc, tag) {
    Object.assign(this, { ownerDocument: doc, nodeType: 1, tagName: String(tag).toUpperCase(), childNodes: [], parentNode: null,
      attributes: {}, listeners: {}, hidden: false, disabled: false, dataset: {}, style: {}, value: '', checked: false, type: '', id: '', title: '' });
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
  appendChild(n) { if (n.parentNode) n.parentNode.removeChild(n); this.childNodes.push(n); n.parentNode = this; return n; }
  append(...nodes) { for (const n of nodes) this.appendChild(typeof n === 'string' ? new FakeText(n) : n); }
  removeChild(n) { const i = this.childNodes.indexOf(n); if (i > -1) this.childNodes.splice(i, 1); n.parentNode = null; return n; }
  replaceChildren(...nodes) { for (const c of this.childNodes) c.parentNode = null; this.childNodes = []; this.append(...nodes); }
  get textContent() { return this.childNodes.map((c) => c.textContent).join(''); }
  set textContent(v) { for (const c of this.childNodes) c.parentNode = null; this.childNodes = []; if (v != null && v !== '') this.appendChild(new FakeText(v)); }
  get innerHTML() { throw new Error('innerHTML read'); }
  set innerHTML(v) { throw new Error(`innerHTML: ${JSON.stringify(String(v).slice(0, 60))} went into the DOM as HTML`); }
  setAttribute(k, v) { this.attributes[k] = String(v); }
  getAttribute(k) { return Object.prototype.hasOwnProperty.call(this.attributes, k) ? this.attributes[k] : null; }
  hasAttribute(k) { return Object.prototype.hasOwnProperty.call(this.attributes, k); }
  removeAttribute(k) { delete this.attributes[k]; }
  addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); }
  dispatch(type, extra) { const ev = Object.assign({ type, target: this, preventDefault() {} }, extra); for (const fn of [...(this.listeners[type] || [])]) fn(ev); }
  click() { if (!this.disabled) this.dispatch('click'); }
  focus() { this.ownerDocument.activeElement = this; }
  contains(n) { for (let x = n; x; x = x.parentNode) if (x === this) return true; return false; }
  hiddenUp() { for (let n = this; n && n.nodeType === 1; n = n.parentNode) if (n.hidden) return true; return false; }
  all(pred, out = []) { for (const c of this.childNodes) if (c.nodeType === 1) { if (pred(c)) out.push(c); c.all(pred, out); } return out; }
  byClass(c) { return this.all((n) => n.classList.contains(c)); }
  one(c) { const r = this.byClass(c); assert.equal(r.length, 1, `.${c}: ${r.length} found`); return r[0]; }
  byKey(k) { const r = this.all((n) => n.dataset.lu === k); assert.equal(r.length, 1, `[data-lu=${k}]: ${r.length} found`); return r[0]; }
  hasKey(k) { return this.all((n) => n.dataset.lu === k).length > 0; }
}
function fakeDocument() {
  const doc = { activeElement: null };
  doc.createElement = (tag) => new FakeEl(doc, tag);
  doc.documentElement = new FakeEl(doc, 'html');
  doc.documentElement.lang = 'fa';
  doc.documentElement.dir = 'rtl';
  doc.body = new FakeEl(doc, 'body');
  doc.documentElement.appendChild(doc.body);
  doc.activeElement = doc.body;
  doc.querySelectorAll = () => [];   // i18n.applyI18n: no data-i18n nodes here
  doc.querySelector = (sel) => (sel === '.nav-item[data-view="users"]' ? doc.navItem : null);
  doc.navItem = new FakeEl(doc, 'button');
  return doc;
}

/* ------------------------------ the service the page talks to ------------------------------ */

const TARGETS = [
  { value: 'srv-m', label: 'My VPS', pile: { key: 'manual', name: 'دستی', ico: '✎' } },
  { value: 'srv-1', label: 'DE-1', pile: { key: 'sub:s1', name: 'Tes sub', ico: '🔗' } },
  { value: 'srv-2', label: 'NL-2', pile: { key: 'sub:s1', name: 'Tes sub', ico: '🔗' } },
  { value: 'chain:c1', label: '⛓ Home chain', pile: { key: 'chains', name: 'Chains', ico: '⛓' } }
];
const MONTH_END = new Date(2026, 10, 1).getTime();
const DAY_END = new Date(2026, 9, 27).getTime();

/** A lanusers:get payload: four users (active / near its daily cap / expired / off and at its cap) on a Windows PC. */
function payload(over = {}) {
  const now = Date.now();
  return Object.assign({
    config: { proxy: { enabled: true, port: 30820, httpPort: 30821 }, transparent: { enabled: false, unassigned: 'login', sessionHours: 24, portalPort: 30822 } },
    users: [
      { id: 'usr-a1', username: 'sara', password: 'pa55-Sara', name: 'سارا', target: 'srv-1', quotaGb: 20, quotaPeriod: 'month', expiresAt: 0, maxDevices: 2, enabled: true },
      { id: 'usr-b2', username: 'reza', password: 'reza1234', name: 'Reza', target: '', quotaGb: 2, quotaPeriod: 'day', expiresAt: now + 30 * DAY, maxDevices: 0, enabled: true },
      { id: 'usr-c3', username: 'guest', password: 'guest', name: '', target: 'block', quotaGb: 0, quotaPeriod: 'none', expiresAt: now - DAY, maxDevices: 0, enabled: true },
      { id: 'usr-d4', username: 'kid', password: 'kid-pass', name: 'Kid', target: 'srv-gone', quotaGb: 5, quotaPeriod: 'month', expiresAt: 0, maxDevices: 0, enabled: false }
    ],
    devices: [],
    usage: {
      'usr-a1': { bytes: 6.5 * GIB, period: '2026-10', until: MONTH_END, quotaBytes: 20 * GIB, over: false },
      'usr-b2': { bytes: 1.8 * GIB, period: '2026-10-26', until: DAY_END, quotaBytes: 2 * GIB, over: false },
      'usr-c3': { bytes: 300 * 1024 * 1024, period: '2026-10', until: MONTH_END, quotaBytes: 0, over: false },
      'usr-d4': { bytes: 5 * GIB, period: '2026-10', until: MONTH_END, quotaBytes: 5 * GIB, over: true }
    },
    live: {},
    online: {},
    platform: 'win32',
    lanAddresses: ['192.168.1.20', 'fd00::20']
  }, over);
}
/** The router: transparent mode on, three devices (two online, one stored and blocked). */
function routerPayload(over = {}) {
  return payload(Object.assign({
    platform: 'openwrt',
    lanAddresses: ['192.168.1.1'],
    config: { proxy: { enabled: false, port: 30820, httpPort: 30821 }, transparent: { enabled: true, unassigned: 'login', sessionHours: 24, portalPort: 30822 } },
    devices: [
      { mac: 'aa:bb:cc:00:00:01', name: 'Sara phone', userId: 'usr-a1', blocked: false },
      { mac: 'aa:bb:cc:00:00:02', name: '', userId: '', blocked: true }
    ],
    online: {
      'aa:bb:cc:00:00:01': { ip: '192.168.1.101', hostname: 'Galaxy-S23', userId: 'usr-a1', up: 20480, down: 1572864 },
      'AA:BB:CC:00:00:03': { ip: '192.168.1.150', hostname: 'DESKTOP-7Q', userId: '' }
    },
    deviceUsage: { 'aa:bb:cc:00:00:01': 700 * 1024 * 1024 },
    live: { 'usr-a1': { up: 20480, down: 1572864 } }
  }, over));
}

const flush = () => new Promise((r) => setImmediate(r));

function harness({ lang = 'fa', platform = 'win32', router = false, connected = false, data = null, api = {}, confirm = true, visible = true, picker = null, qrcode = null } = {}) {
  const document = fakeDocument();
  const store = { data: clone(data || (router ? routerPayload() : payload())) };
  const calls = [];
  const toasts = [];
  const copies = [];
  const asked = [];
  const applied = [];
  const state = { connected, confirm, visible };
  const answer = () => clone(store.data);
  const window = {
    crypto: webcrypto,
    api: Object.assign({
      lanUsersGet: async () => { calls.push(['get']); return answer(); },
      lanUsersConfig: async (partial) => {
        calls.push(['config', clone(partial)]);
        const c = store.data.config;
        for (const k of Object.keys(partial)) c[k] = Object.assign({}, c[k], partial[k]);
        return Object.assign(answer(), { pendingReconnect: ['lanUsers'] });
      },
      lanUsersUser: async ({ op, user }) => {
        calls.push(['user', op, clone(user)]);
        const d = store.data;
        if (op === 'add') d.users.push(Object.assign({ id: 'usr-new' + d.users.length }, user));
        if (op === 'update') d.users = d.users.map((u) => (u.id === user.id ? Object.assign({}, user) : u));
        if (op === 'delete') d.users = d.users.filter((u) => u.id !== user.id);
        return answer();
      },
      lanUsersDevice: async (arg) => {
        calls.push(['device', clone(arg)]);
        const d = store.data;
        const dev = d.devices.find((x) => x.mac === arg.mac);
        const patch = Object.assign({}, arg);
        delete patch.mac;
        if (dev) Object.assign(dev, patch); else d.devices.push(Object.assign({ mac: arg.mac, name: '', userId: '', blocked: false }, patch));
        return answer();
      }
    }, api)
  };
  const ctx = vm.createContext(Object.assign({ window, document, console, setTimeout, clearTimeout, Uint32Array, btoa }, qrcode ? { qrcode } : {}));
  vm.runInContext(I18N, ctx, { filename: 'i18n.js' });
  vm.runInContext(PAGE, ctx, { filename: 'lanUsers.js' });
  window.i18n.applyI18n(lang);
  const host = document.createElement('div');
  host.id = 'lanUsersPage';
  document.body.appendChild(host);
  const hooks = {
    applied: (res) => { applied.push(res && res.pendingReconnect); },
    connected: () => state.connected,
    targets: () => TARGETS,
    platform: () => platform,
    router: () => router,
    visible: () => state.visible,
    copy: async (text) => { copies.push(text); },
    confirm: (msg) => { asked.push(msg); return state.confirm; },
    toast: (msg, kind) => toasts.push([msg, kind || ''])
  };
  if (picker) hooks.picker = picker;
  const page = window.lanUsersPage;
  page.mount(host, hooks);
  const t = (k) => window.i18n.t(k);
  async function load() { await page.refresh(); await flush(); }
  const user = (id) => host.all((n) => n.classList.contains('lu-user') && n.dataset.user === id)[0];
  const device = (mac) => host.all((n) => n.classList.contains('lu-dev') && n.dataset.mac === mac)[0];
  const dialog = () => document.body.children.find((c) => c.id === 'luModal') || null;
  return { window, document, ctx, host, page, hooks, store, calls, toasts, copies, asked, applied, state, t, load, user, device, dialog };
}

/** What the page writes for a date, the same Intl call: the Persian calendar in fa, Latin digits. */
const persian = (ms, opts) => new Intl.DateTimeFormat('fa-IR-u-nu-latn', opts).format(new Date(ms));
const english = (ms, opts) => new Intl.DateTimeFormat('en', opts).format(new Date(ms));
const FULL = { year: 'numeric', month: 'long', day: 'numeric' };
const SHORT = { month: 'long', day: 'numeric' };

/* ------------------------------ drawing ------------------------------ */

test('empty, in Persian on a Windows PC: proxy accounts off, no users yet, the hotspot note, no devices block', async () => {
  const h = harness({ data: payload({ users: [], usage: {}, config: { proxy: { enabled: false, port: 30820, httpPort: 30821 } } }) });
  assert.ok(h.host.textContent.includes(h.t('lu.loading')), 'drawn before the users are read');
  assert.equal(h.host.byKey('add').disabled, true, 'nothing to add to before the read');
  await h.load();
  const { host, t } = h;
  assert.equal(host.one('lu-intro').textContent, t('lu.intro'));
  const settings = host.one('lu-settings');
  assert.equal(settings.byClass('switch-title')[0].textContent, 'حساب‌های پروکسی');
  assert.equal(host.byKey('proxy').checked, false);
  assert.equal(settings.byClass('lu-body')[0].hidden, true, 'off: only the switch');
  const note = host.one('lu-hotspot');
  assert.equal(note.textContent, t('lu.hotspot'));
  assert.match(note.textContent, /Mobile Hotspot/);
  assert.match(note.textContent, /حالت شفاف\) مخصوصِ روتر است/, 'the transparent mode is the router’s — said');
  assert.equal(host.byClass('lu-devices').length, 0, 'no devices on a PC');
  assert.equal(host.one('lu-users').one('empty').textContent, t('lu.none'));
  assert.equal(host.one('lu-users').one('lu-title').textContent, 'فهرست کاربران');
  assert.equal(host.one('lu-users').one('lu-meta').textContent, '0 کاربر');
  assert.equal(host.byKey('add').textContent, '+ کاربر');
  assert.equal(host.byKey('add').disabled, false);
  assert.equal(host.byClass('lu-user').length, 0);
});

test('with users, in Persian: the address to give people left to right with copy, each user’s box as drawn', async () => {
  const h = harness();
  await h.load();
  const { host, t } = h;
  assert.equal(host.byKey('proxy').checked, true);
  assert.equal(host.byKey('port').value, '30820');
  assert.equal(host.byKey('port').getAttribute('dir'), 'ltr');
  assert.equal(host.byKey('httpPort').value, '30821');
  const addrs = host.one('lu-addr').byClass('lu-mono');
  assert.deepEqual(addrs.map((a) => [a.dataset.addr, a.textContent, a.getAttribute('dir')]), [
    ['SOCKS5', '192.168.1.20:30820', 'ltr'], ['HTTP', '192.168.1.20:30821', 'ltr'],
    ['SOCKS5', '[fd00::20]:30820', 'ltr'], ['HTTP', '[fd00::20]:30821', 'ltr']
  ], 'every address runs left to right in a Persian page; an IPv6 one in brackets');
  assert.ok(host.byClass('lu-proto').every((p) => ['SOCKS5', 'HTTP'].includes(p.textContent)));
  host.byKey('copy:SOCKS5:192.168.1.20').click();
  await flush();
  assert.deepEqual(h.copies, ['192.168.1.20:30820']);
  assert.deepEqual(h.toasts.at(-1), ['کپی شد', 'ok']);
  assert.deepEqual(host.byClass('lu-hint').map((n) => n.textContent), [t('lu.whileConnected'), t('lu.hotspotOff')],
    'disconnected: the accounts need the connection; no 192.168.137.1 among the addresses: the hotspot is off');
  assert.equal(host.byClass('lu-hs').length, 0, 'no address marked as the hotspot’s');
  assert.equal(host.byClass('lu-alert').length, 0, 'proxy accounts on: nothing to warn about');

  assert.equal(host.byClass('lu-user').length, 4);
  assert.equal(host.one('lu-users').one('lu-meta').textContent, '4 کاربر');
  const sara = h.user('usr-a1');
  assert.equal(sara.one('lu-av').textContent, 'س');
  assert.equal(sara.one('lu-name').textContent, 'سارا');
  assert.equal(sara.one('lu-uname').textContent, 'sara');
  assert.equal(sara.one('lu-uname').getAttribute('dir'), 'ltr');
  assert.equal(sara.one('lu-state').textContent, 'فعال');
  assert.ok(sara.one('lu-state').classList.contains('lu-s-on'));
  assert.equal(sara.classList.contains('lu-dim'), false);
  assert.deepEqual(['usr-b2', 'usr-c3', 'usr-d4'].map((id) => h.user(id).one('lu-state').textContent), ['فعال', 'منقضی', 'خاموش']);
  assert.ok(h.user('usr-c3').classList.contains('lu-dim'));
  assert.equal(h.user('usr-c3').one('lu-name').textContent, 'guest', 'no name: the username');
  assert.equal(host.byKey('enabled:usr-d4').checked, false);
  assert.equal(host.byKey('enabled:usr-a1').checked, true);
  assert.equal(sara.byClass('lu-rate')[0].hidden, true, 'no live rate while disconnected');
  assert.equal(host.hasKey('max:usr-a1'), false, 'the device limit is the router’s sign-in page’s: not on a PC');

  // the password: hidden
  const secret = sara.one('lu-secret');
  assert.equal(secret.textContent, '••••••••');
  assert.equal(secret.getAttribute('dir'), 'ltr');
  assert.deepEqual(sara.byClass('field-label').map((l) => l.textContent), ['رمز', 'کانفیگ', 'سقف حجم', 'انقضا']);

  // the cap: 6.5 of 20 GB this month, until the month's end
  const bar = sara.one('lu-bar');
  assert.equal(bar.hidden, false);
  assert.equal(bar.getAttribute('role'), 'progressbar');
  assert.equal(bar.children[0].style.width, '32.5%');
  assert.equal(bar.children[0].className, '');
  assert.deepEqual(sara.one('lu-quota').children.map((c) => c.textContent), ['6.5 GB از 20.0 GB', 'تا ' + persian(MONTH_END, SHORT)]);
  assert.equal(host.byKey('quota:usr-a1').value, '20');
  assert.equal(host.byKey('quota:usr-a1').getAttribute('dir'), 'ltr');
  assert.equal(host.byKey('period:usr-a1').value, 'month', 'a user saved before the calendar choice: the Gregorian month');
  assert.deepEqual(host.byKey('period:usr-a1').children.map((o) => o.textContent), ['GB در ماه شمسی', 'GB در ماه میلادی', 'GB در روز', 'بدون سقف'], 'the Persian month first in Persian');
  assert.equal(host.byKey('renew:usr-a1').value, '1', 'renewing on the 1st');
  assert.equal(host.byKey('renew:usr-a1').parentNode.hidden, false, 'a month: its renew day shown');
  assert.equal(host.byKey('renew:usr-b2').parentNode.hidden, true, 'a day: no renew day');
  // near its daily cap: amber, and what happens at it
  const reza = h.user('usr-b2');
  assert.equal(reza.one('lu-bar').children[0].className, 'warn');
  assert.deepEqual(reza.one('lu-quota').children.map((c) => c.textContent), ['1.8 GB از 2.0 GB — نزدیک سقف', 'رسید → قطع می‌شود']);
  // no cap: no bar, the bytes and nothing to type
  const guest = h.user('usr-c3');
  assert.equal(guest.one('lu-bar').hidden, true);
  assert.deepEqual(guest.one('lu-quota').children.map((c) => c.textContent), ['300.0 MB مصرف شده', 'این ماه']);
  assert.equal(host.byKey('quota:usr-c3').disabled, true);
  // at its cap: red, and when it comes back
  const kid = h.user('usr-d4');
  assert.equal(kid.one('lu-bar').children[0].className, 'over');
  assert.deepEqual(kid.one('lu-quota').children.map((c) => c.textContent), ['5.0 GB از 5.0 GB — به سقف رسید، قطع شد', 'برمی‌گردد ' + persian(MONTH_END, SHORT)]);

  // the expiry: a date box, and its day in the Persian calendar
  assert.equal(host.byKey('expires:usr-a1').value, '');
  assert.equal(host.byKey('expires:usr-a1').type, 'date');
  assert.equal(sara.byClass('lu-sub').at(-1).textContent, 'بدون انقضا');
  assert.equal(host.hasKey('noexpiry:usr-a1'), false);
  const rezaEnd = h.store.data.users[1].expiresAt;
  const d = new Date(rezaEnd);
  assert.equal(host.byKey('expires:usr-b2').value, `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`);
  assert.equal(reza.byClass('lu-sub').at(-1).textContent, 'تا پایانِ ' + persian(rezaEnd, FULL));
  assert.match(persian(rezaEnd, FULL), /^\d{1,2} \S+ 14\d\d$/, 'the Solar Hijri year, Latin digits');
  assert.ok(host.hasKey('noexpiry:usr-b2'));
  const gone = guest.byClass('lu-sub').at(-1);
  assert.equal(gone.textContent, 'منقضی شد — ' + persian(h.store.data.users[2].expiresAt, FULL));
  assert.ok(gone.classList.contains('lu-bad'));
});

test('users there and no way in: said above everything, with the button that turns the proxy on — and gone once it is', async () => {
  const off = { proxy: { enabled: false, port: 30820, httpPort: 30821 }, transparent: { enabled: false, unassigned: 'login', sessionHours: 24, portalPort: 30822 } };
  const h = harness({ data: payload({ config: clone(off) }) });
  await h.load();
  const alert = h.host.one('lu-alert');
  assert.equal(alert.getAttribute('role'), 'status');
  assert.equal(alert.one('lu-alert-text').textContent, 'هنوز کسی نمی‌تواند وصل شود: حساب‌های پروکسی خاموش است.');
  assert.equal(h.host.children[1], alert, 'right under the intro, above the settings');
  h.host.byKey('turnon').click();
  await flush();
  assert.deepEqual(h.calls.find((c) => c[0] === 'config'), ['config', { proxy: { enabled: true } }]);
  assert.equal(h.host.byClass('lu-alert').length, 0);
  assert.equal(h.host.byKey('proxy').checked, true);

  const none = harness({ data: payload({ users: [], usage: {}, config: clone(off) }) });
  await none.load();
  assert.equal(none.host.byClass('lu-alert').length, 0, 'no users: nobody to warn for');

  const router = harness({ router: true, lang: 'en', data: routerPayload() });
  await router.load();
  assert.equal(router.host.byClass('lu-alert').length, 0, 'the router with its transparent mode on: a way in');
  const both = harness({ router: true, lang: 'en', data: routerPayload({ config: clone(off) }) });
  await both.load();
  assert.equal(both.host.one('lu-alert-text').textContent, 'Nobody can connect yet: proxy accounts and transparent mode are both off.');
});

test('the Windows hotspot’s address: first, marked as the hotspot’s; a Mac gets no mark', async () => {
  const h = harness({ data: payload({ lanAddresses: ['192.168.137.1', '192.168.1.20'] }) });
  await h.load();
  const rows = h.host.one('lu-addr').byClass('lu-addr-row');
  assert.deepEqual(rows.map((r) => [r.one('lu-mono').textContent, r.byClass('lu-hs').map((x) => x.textContent).join('')]), [
    ['192.168.137.1:30820', 'هات‌اسپات'], ['192.168.137.1:30821', 'هات‌اسپات'], ['192.168.1.20:30820', ''], ['192.168.1.20:30821', '']
  ]);
  assert.deepEqual(h.host.byClass('lu-hint').map((n) => n.textContent), [h.t('lu.whileConnected')], 'the hotspot is on: nothing said about it');
  const mac = harness({ platform: 'darwin', data: payload({ platform: 'darwin', lanAddresses: ['192.168.137.1'] }) });
  await mac.load();
  assert.equal(mac.host.byClass('lu-hs').length, 0);
  assert.equal(mac.host.byClass('lu-hotspot').length, 0);
});

test('a user’s link for a phone: socks:// with the account, its QR, the address picked, copied — and read back by the app’s own parser', async () => {
  const made = [];
  const qrcode = (type, level) => {
    const q = { data: '', addData(s) { q.data = s; }, make() {}, createDataURL(cell, margin) { made.push([q.data, type, level, cell, margin]); return 'data:image/gif;base64,R0lGOD'; } };
    return q;
  };
  const h = harness({ lang: 'en', qrcode, data: payload({ lanAddresses: ['192.168.137.1', '192.168.1.20', 'fd00::20'] }) });
  await h.load();
  h.user('usr-a1').byKey('share:usr-a1').click();
  const box = h.document.body.children.find((c) => c.id === 'luShare');
  assert.ok(box, 'the link dialog is open');
  assert.equal(box.one('modal-title').textContent, 'Connect “سارا”');
  const link = box.byKey('s:link').textContent;
  assert.equal(box.byKey('s:link').getAttribute('dir'), 'ltr');
  assert.match(link, /^socks:\/\/[A-Za-z0-9_-]+@192\.168\.137\.1:30820#/, 'the hotspot’s address first; the SOCKS port; base64url, no padding');
  assert.equal(Buffer.from(link.slice(8, link.indexOf('@')), 'base64url').toString(), 'sara:pa55-Sara');
  const { parseLink } = require('../src/main/parser');
  const s = parseLink(link);
  assert.equal(s.name, 'سارا');
  assert.deepEqual(s.outbound.settings.servers, [{ address: '192.168.137.1', port: 30820, users: [{ user: 'sara', pass: 'pa55-Sara' }] }]);
  assert.deepEqual(made.at(-1), [link, 0, 'M', 6, 16], 'the QR is of the link itself');
  assert.equal(box.one('lu-qrimg').src, 'data:image/gif;base64,R0lGOD');
  assert.deepEqual(box.byClass('lu-ips')[0].children.map((b) => [b.textContent, b.getAttribute('aria-pressed')]),
    [['192.168.137.1 · Hotspot', 'true'], ['192.168.1.20', 'false']], 'IPv4 only: a phone types and scans those');
  box.byKey('s:ip:192.168.1.20').click();
  assert.match(box.byKey('s:link').textContent, /@192\.168\.1\.20:30820#/);
  box.byKey('s:copy').click();
  await flush();
  assert.equal(h.copies.at(-1), box.byKey('s:link').textContent);
  assert.equal(box.byClass('warn').length, 1, 'only the password warning');
  box.dispatch('keydown', { key: 'Escape' });
  assert.equal(h.document.body.children.some((c) => c.id === 'luShare'), false, 'Escape closes it');

  // a password with characters a URL holds apart: still read back as typed
  const odd = harness({ lang: 'en', data: payload({ users: [{ id: 'usr-x', username: 'ali', password: 'a@b:c/d%e f', name: '', target: '', quotaGb: 0, quotaPeriod: 'none', expiresAt: 0, maxDevices: 0, enabled: true }], usage: {}, config: { proxy: { enabled: false, port: 30820, httpPort: 30821 } } }) });
  await odd.load();
  odd.page.share('usr-x');
  const ob = odd.document.body.children.find((c) => c.id === 'luShare');
  assert.equal(parseLink(ob.byKey('s:link').textContent).outbound.settings.servers[0].users[0].pass, 'a@b:c/d%e f');
  assert.equal(ob.byClass('lu-qrimg').length, 0, 'no qrcode.js: the link alone');
  assert.ok(ob.textContent.includes(odd.t('qr.tooBig')));
  assert.ok(ob.textContent.includes(odd.t('lu.shareOff')), 'proxy accounts off: said in the dialog');
});

test('the hotspot check (Windows): each device on the hotspot, whether the tunnel saw it, and what the test means; nothing on the router or without the payload\'s hotspot', async () => {
  const hotspot = { on: true, tun: true, error: '', devices: [
    { ip: '192.168.137.45', mac: 'a2:4b:11:0c:9e:07', seen: true, lastSeen: 1, open: 3, bytes: 5 * 1024 * 1024 },
    { ip: '192.168.137.88', mac: '3c:22:fb:9a:10:7e', seen: false, lastSeen: 0, open: 0, bytes: 0 }
  ] };
  const h = harness({ data: payload({ hotspot }) });
  await h.load();
  const card = h.host.one('lu-hscard');
  assert.equal(card.one('lu-title').textContent, 'دستگاه‌های هات‌اسپات');
  const rows = card.byClass('lu-hsrow');
  assert.deepEqual(rows.map((r) => [r.dataset.ip, r.one('lu-ip').textContent, r.one('lu-ip').getAttribute('dir'), r.one('lu-mac').textContent]), [
    ['192.168.137.45', '192.168.137.45', 'ltr', 'a2:4b:11:0c:9e:07'], ['192.168.137.88', '192.168.137.88', 'ltr', '3c:22:fb:9a:10:7e']
  ]);
  assert.equal(rows[0].one('lu-hs-yes').textContent, 'از VPN می‌رود ✓');
  assert.match(rows[0].one('lu-hsuse').textContent, /^3 اتصالِ باز · 5(\.0)? MB$/);
  assert.equal(rows[1].one('lu-hs-no').textContent, 'هنوز از VPN دیده نشده');
  assert.equal(rows[1].byClass('lu-hsuse').length, 0);
  assert.equal(card.one('lu-hotspot').textContent, h.t('lu.hs.how'));
  assert.equal(card.byClass('warn').length, 0);
  h.host.byKey('hsrefresh').click();
  await flush();
  assert.equal(h.calls.filter((c) => c[0] === 'get').length, 2, 'refresh reads again');

  // TUN off: said, and the devices are "unknown"
  const off = harness({ lang: 'en', data: payload({ hotspot: Object.assign({}, hotspot, { tun: false, devices: [Object.assign({}, hotspot.devices[1])] }) }) });
  await off.load();
  assert.equal(off.host.one('lu-hscard').one('warn').textContent, 'For this test, TUN mode must be on and the app connected.');
  assert.equal(off.host.one('lu-hs-no').textContent, 'Unknown (TUN off)');
  // the hotspot off; the API refused
  const down = harness({ lang: 'en', data: payload({ hotspot: { on: false, tun: true, error: '', devices: [] } }) });
  await down.load();
  assert.equal(down.host.one('lu-hscard').one('warn').textContent, 'The Windows hotspot is off — turn it on and connect a phone to it.');
  assert.equal(down.host.one('lu-hscard').byClass('empty').length, 0);
  const err = harness({ lang: 'en', data: payload({ hotspot: { on: true, tun: true, error: 'HTTP 401', devices: [] } }) });
  await err.load();
  assert.equal(err.host.one('lu-hscard').one('warn').textContent, 'The tunnel did not answer: HTTP 401');
  assert.equal(err.host.one('lu-hscard').one('empty').textContent, 'No device is on the hotspot yet.');
  // no hotspot in the payload (a Mac, Linux, an older service): no card; the router: its devices, not this
  const none = harness({ data: payload() });
  await none.load();
  assert.equal(none.host.byClass('lu-hscard').length, 0);
  const router = harness({ router: true, data: routerPayload({ hotspot }) });
  await router.load();
  assert.equal(router.host.byClass('lu-hscard').length, 0);
});

test('the config picker: the app’s configs by subscription, after the current connection, direct and blocked; a gone one said as gone', async () => {
  const h = harness();
  await h.load();
  const sel = h.host.byKey('target:usr-a1:select');
  assert.equal(sel.tagName, 'SELECT');
  assert.equal(sel.value, 'srv-1');
  const top = sel.children.filter((c) => c.tagName === 'OPTION').map((o) => [o.value, o.textContent]);
  assert.deepEqual(top, [['', 'همان اتصالِ فعلی'], ['direct', 'مستقیم (بدون VPN)'], ['block', 'مسدود']]);
  const groups = sel.children.filter((c) => c.tagName === 'OPTGROUP');
  assert.deepEqual(groups.map((g) => [g.label, g.children.map((o) => o.value)]), [
    ['✎ دستی', ['srv-m']], ['🔗 Tes sub', ['srv-1', 'srv-2']], ['⛓ Chains', ['chain:c1']]
  ], 'one group per pile, as every config picker lists them');
  assert.equal(h.host.byKey('target:usr-b2:select').value, '', 'the current connection');
  const kid = h.host.byKey('target:usr-d4:select');
  assert.equal(kid.value, 'srv-gone');
  assert.deepEqual(kid.children.at(-1).textContent, '⚠ دیگر وجود ندارد', 'the saved choice stays, said as gone');
  // a pick saves the whole user with that one change
  sel.value = 'chain:c1';
  sel.dispatch('change');
  await flush();
  const [kind, op, user] = h.calls.at(-1);
  assert.deepEqual([kind, op, user.id, user.target, user.username, user.password], ['user', 'update', 'usr-a1', 'chain:c1', 'sara', 'pa55-Sara']);
  assert.equal(h.host.byKey('target:usr-a1:select').value, 'chain:c1');
});

test('with app.js’s own picker (makeSearchSelect) the page hands it the same options and takes its pick', async () => {
  const seen = [];
  let pick = null;
  const picker = (o) => {
    seen.push(o);
    const box = { nodeType: 1, tagName: 'DIV', childNodes: [], parentNode: null, dataset: {}, hidden: false, children: [], classList: { contains: () => false }, all: () => [], textContent: '' };
    if (o.value === '') pick = o.onChange;
    return box;
  };
  const h = harness({ picker });
  await h.load();
  const reza = seen.find((o) => o.value === '');
  assert.ok(reza, 'the current connection is a choice');
  assert.deepEqual([...reza.options].slice(0, 3).map((o) => o.value), ['', 'direct', 'block']);
  assert.deepEqual([...reza.options].slice(3).map((o) => o.value), TARGETS.map((x) => x.value));
  assert.equal(reza.options[4].pile.name, 'Tes sub', 'the piles go along: the picker heads them');
  assert.equal(h.host.byClass('lu-target').length, 4);
  pick('srv-2');
  await flush();
  assert.equal(h.calls.at(-1)[2].target, 'srv-2');
});

test('the same page in English, and a language switch redraws it', async () => {
  const h = harness({ lang: 'en' });
  await h.load();
  const { host } = h;
  assert.equal(host.one('lu-settings').byClass('switch-title')[0].textContent, 'Proxy accounts');
  assert.match(host.one('lu-hotspot').textContent, /^Windows Mobile Hotspot: .*\(transparent mode\) is the router’s\.$/);
  assert.equal(host.one('lu-users').one('lu-title').textContent, 'User list');
  assert.deepEqual(['usr-a1', 'usr-b2', 'usr-c3', 'usr-d4'].map((id) => h.user(id).one('lu-state').textContent), ['Active', 'Active', 'Expired', 'Off']);
  assert.deepEqual(h.user('usr-a1').one('lu-quota').children.map((c) => c.textContent), ['6.5 GB of 20.0 GB', 'until ' + english(MONTH_END, SHORT)]);
  assert.equal(h.user('usr-b2').byClass('lu-sub').at(-1).textContent, 'through ' + english(h.store.data.users[1].expiresAt, FULL));
  assert.equal(host.byKey('add').textContent, '+ User');
  h.window.i18n.applyI18n('fa');
  h.page.render();
  assert.equal(host.one('lu-users').one('lu-title').textContent, 'فهرست کاربران');
});

test('the note under the settings: the hotspot on Windows only; a Mac or Linux PC gets the plain one', async () => {
  const mac = harness({ platform: 'darwin', data: payload({ platform: 'darwin' }) });
  await mac.load();
  assert.equal(mac.host.byClass('lu-hotspot').length, 0);
  assert.equal(mac.host.one('lu-note').textContent, mac.t('lu.desktopNote'));
  const win = harness({ platform: 'win32' });
  await win.load();
  assert.equal(win.host.one('lu-note').classList.contains('lu-hotspot'), true);
});

/* ------------------------------ the password ------------------------------ */

test('password: show and hide in place, copy, and a new one after asking — shown, saved, ten characters', async () => {
  const h = harness();
  await h.load();
  const sara = h.user('usr-a1');
  const eye = h.host.byKey('show:usr-a1');
  assert.equal(eye.getAttribute('aria-pressed'), 'false');
  assert.equal(eye.getAttribute('aria-label'), 'نمایش رمز — سارا');
  eye.click();
  assert.equal(sara.one('lu-secret').textContent, 'pa55-Sara');
  assert.equal(eye.getAttribute('aria-pressed'), 'true');
  assert.equal(eye.getAttribute('aria-label'), 'پنهان کردن رمز — سارا');
  assert.equal(h.calls.filter((c) => c[0] !== 'get').length, 0, 'showing saves nothing');
  eye.click();
  assert.equal(sara.one('lu-secret').textContent, '••••••••');

  h.host.byKey('copypass:usr-a1').click();
  await flush();
  assert.deepEqual(h.copies, ['pa55-Sara'], 'copied while hidden too');

  h.state.confirm = false;
  h.host.byKey('gen:usr-a1').click();
  await flush();
  assert.deepEqual(h.asked, [h.t('lu.confirmGenerate').replace('{name}', 'سارا')]);
  assert.equal(h.calls.filter((c) => c[0] === 'user').length, 0, 'not without a yes');
  h.state.confirm = true;
  h.host.byKey('gen:usr-a1').click();
  await flush();
  const [, op, user] = h.calls.at(-1);
  assert.equal(op, 'update');
  assert.match(user.password, /^[abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789]{10}$/, 'no 0/O, 1/l/I');
  assert.notEqual(user.password, 'pa55-Sara');
  assert.equal(h.user('usr-a1').one('lu-secret').textContent, user.password, 'a new password is shown: it has to be read out');
  const many = new Set(Array.from({ length: 50 }, () => h.page.genPassword()));
  assert.equal(many.size, 50);
});

/* ------------------------------ saving from the boxes ------------------------------ */

test('the switch, a cap, its period, an expiry and its removal each save the whole user with that change', async () => {
  const h = harness();
  await h.load();
  const sw = h.host.byKey('enabled:usr-d4');
  sw.checked = true;
  sw.dispatch('change');
  await flush();
  assert.deepEqual(h.calls.at(-1).slice(0, 2), ['user', 'update']);
  assert.equal(h.calls.at(-1)[2].enabled, true);
  assert.equal(h.user('usr-d4').one('lu-state').textContent, 'به سقف رسیده', 'the answer is drawn: on again, and still at its cap this month');

  const q = h.host.byKey('quota:usr-a1');
  q.value = '50';
  q.dispatch('change');
  await flush();
  assert.equal(h.calls.at(-1)[2].quotaGb, 50);
  const bad = h.host.byKey('quota:usr-a1');
  bad.value = '-3';
  bad.dispatch('change');
  await flush();
  assert.equal(h.calls.at(-1)[2].quotaGb, 0, 'no negative cap');
  const per = h.host.byKey('period:usr-a1');
  per.value = 'day';
  per.dispatch('change');
  await flush();
  assert.equal(h.calls.at(-1)[2].quotaPeriod, 'day');

  const date = h.host.byKey('expires:usr-a1');
  date.value = '2026-12-31';
  date.dispatch('change');
  await flush();
  const exp = h.calls.at(-1)[2].expiresAt;
  assert.equal(exp, new Date(2026, 11, 31, 23, 59, 59, 999).getTime(), 'the end of the day picked: the user has all of it');
  assert.equal(h.host.byKey('expires:usr-a1').value, '2026-12-31');
  h.host.byKey('noexpiry:usr-a1').click();
  await flush();
  assert.equal(h.calls.at(-1)[2].expiresAt, 0);
  assert.ok(h.applied.length >= 5, 'every answer goes to app.js (the reconnect question)');
});

test('a month of the admin’s choosing: the Persian or the Gregorian month, its renew day under it, saved as the two fields', async () => {
  const data = payload();
  data.users[0] = Object.assign({}, data.users[0], { quotaCalendar: 'jalali', quotaResetDay: 30 });
  data.usage['usr-a1'] = Object.assign({}, data.usage['usr-a1'], { period: 'j1405-07@30', until: new Date(2026, 10, 20).getTime() });
  data.usage['usr-c3'] = Object.assign({}, data.usage['usr-c3'], { period: '2026-10@15' });
  const h = harness({ data });
  await h.load();
  const note = (id) => h.user(id).all((n) => n.classList.contains('lu-sub') && n.textContent === h.t('lu.renewLast'))[0];
  assert.equal(h.host.byKey('period:usr-a1').value, 'jmonth');
  assert.equal(h.host.byKey('renew:usr-a1').value, '30');
  assert.deepEqual(h.host.byKey('renew:usr-a1').children.map((o) => o.textContent), Array.from({ length: 31 }, (_, i) => String(i + 1)));
  assert.equal(h.user('usr-a1').one('lu-renew').textContent.startsWith('روز تمدید'), true);
  assert.equal(note('usr-a1').hidden, false, 'the 30th: Esfand of a common year has 29 — said');
  assert.deepEqual(h.user('usr-a1').one('lu-quota').children.map((c) => c.textContent), ['6.5 GB از 20.0 GB', 'تا ' + persian(new Date(2026, 10, 20).getTime(), SHORT)], 'when it renews: 30 Aban');
  assert.equal(h.user('usr-c3').one('lu-quota').children[1].textContent, 'این ماه', 'a month renewing on the 15th is a month, not today');
  assert.equal(note('usr-d4').hidden, true, 'the 1st: nothing to say');

  const renew = h.host.byKey('renew:usr-a1');
  renew.value = '15';
  renew.dispatch('change');
  await flush();
  assert.deepEqual(['quotaPeriod', 'quotaCalendar', 'quotaResetDay'].map((k) => h.calls.at(-1)[2][k]), ['month', 'jalali', 15]);
  const per = h.host.byKey('period:usr-a1');
  per.value = 'month';
  per.dispatch('change');
  await flush();
  assert.deepEqual(['quotaPeriod', 'quotaCalendar', 'quotaResetDay'].map((k) => h.calls.at(-1)[2][k]), ['month', 'gregorian', 15], 'the Gregorian month, the same day');
  assert.equal(h.host.byKey('period:usr-a1').value, 'month');
  const per2 = h.host.byKey('period:usr-a1');
  per2.value = 'day';
  per2.dispatch('change');
  await flush();
  assert.equal(h.calls.at(-1)[2].quotaPeriod, 'day');
  assert.equal(h.host.byKey('renew:usr-a1').parentNode.hidden, true, 'a day has no renew day');
  // the Gregorian 29th: February has 28 — said; the Persian 29th is in every month — not
  const per3 = h.host.byKey('period:usr-a1');
  per3.value = 'month';
  per3.dispatch('change');
  await flush();
  const r29 = h.host.byKey('renew:usr-a1');
  r29.value = '29';
  r29.dispatch('change');
  await flush();
  assert.equal(note('usr-a1').hidden, false);
  const per4 = h.host.byKey('period:usr-a1');
  per4.value = 'jmonth';
  per4.dispatch('change');
  await flush();
  assert.equal(note('usr-a1').hidden, true);
});

test('the dialog: a month and its renew day — the line comes and goes with the period; an existing Persian-month user opens as one; English lists the Gregorian month first', async () => {
  const data = payload();
  data.users[1] = Object.assign({}, data.users[1], { quotaPeriod: 'month', quotaCalendar: 'jalali', quotaResetDay: 12 });
  const h = harness({ data });
  await h.load();
  h.host.byKey('edit:usr-b2').click();
  let dlg = h.dialog();
  assert.equal(dlg.byKey('f:period').value, 'jmonth');
  assert.equal(dlg.byKey('f:renew').value, '12');
  assert.equal(dlg.byKey('f:renew').parentNode.hidden, false);
  const per = dlg.byKey('f:period');
  per.value = 'none';
  per.dispatch('change');
  assert.equal(dlg.byKey('f:renew').parentNode.hidden, true, 'no cap: no renew day');
  assert.equal(dlg.byKey('f:quotaGb').disabled, true);
  per.value = 'month';
  per.dispatch('change');
  assert.equal(dlg.byKey('f:renew').parentNode.hidden, false);
  const r = dlg.byKey('f:renew');
  r.value = '31';
  r.dispatch('change');
  assert.equal(dlg.all((n) => n.classList.contains('lu-sub') && n.textContent === h.t('lu.renewLast'))[0].hidden, false);
  dlg.byKey('f:save').click();
  await flush();
  const saved = h.calls.at(-1)[2];
  assert.deepEqual([saved.quotaPeriod, saved.quotaCalendar, saved.quotaResetDay], ['month', 'gregorian', 31]);

  const en = harness({ lang: 'en' });
  await en.load();
  assert.deepEqual(en.host.byKey('period:usr-a1').children.map((o) => o.textContent), ['GB a month', 'GB a Jalali month', 'GB a day', 'No cap']);
  en.host.byKey('add').click();
  dlg = en.dialog();
  assert.equal(dlg.byKey('f:period').value, 'month', 'in English a new user’s month is the Gregorian one');
  assert.equal(dlg.byKey('f:renew').value, '1');
  assert.equal(en.user('usr-a1').one('lu-renew').textContent.startsWith('Renews on day'), true);
});

test('a save that fails says so and the page goes back to what was saved', async () => {
  const h = harness({ api: { lanUsersUser: async () => { throw new Error('disk full'); } } });
  await h.load();
  const sw = h.host.byKey('enabled:usr-a1');
  sw.checked = false;
  sw.dispatch('change');
  await flush();
  assert.deepEqual(h.toasts.at(-1), ['ذخیره نشد: disk full', 'err']);
  assert.equal(h.host.byKey('enabled:usr-a1').checked, true);
  assert.equal(h.user('usr-a1').one('lu-state').textContent, 'فعال');
});

test('the settings: proxy on and off, ports checked before they go, the redraw keeps the focus', async () => {
  const h = harness({ data: payload({ config: { proxy: { enabled: false, port: 30820, httpPort: 30821 } } }) });
  await h.load();
  const sw = h.host.byKey('proxy');
  sw.checked = true;
  sw.dispatch('change');
  await flush();
  assert.deepEqual(h.calls.at(-1), ['config', { proxy: { enabled: true } }]);
  assert.equal(h.host.one('lu-settings').byClass('lu-body')[0].hidden, false);
  assert.deepEqual(h.applied.at(-1), ['lanUsers'], 'the answer’s pendingReconnect goes to app.js');
  const port = h.host.byKey('port');
  port.focus();
  port.value = '30821';
  port.dispatch('change');
  await flush();
  assert.deepEqual(h.toasts.at(-1), [h.t('lu.err.port'), 'err'], 'the same port twice: refused here');
  assert.equal(port.value, '30820');
  port.value = '40000';
  port.dispatch('change');
  await flush();
  assert.deepEqual(h.calls.at(-1), ['config', { proxy: { port: 40000 } }]);
  const now = h.host.byKey('port');
  assert.notEqual(now, port, 'redrawn');
  assert.equal(h.document.activeElement, now, 'the focus stays on the port');
  assert.equal(h.host.one('lu-addr').byClass('lu-mono')[0].textContent, '192.168.1.20:40000');
});

/* ------------------------------ the dialog ------------------------------ */

test('add: the dialog says each broken rule under its field — username, taken (case aside), password — then adds', async () => {
  const h = harness();
  await h.load();
  h.host.byKey('add').click();
  const dlg = h.dialog();
  assert.ok(dlg, 'the dialog is on the page');
  const modal = dlg.one('lu-modal');
  assert.equal(modal.getAttribute('role'), 'dialog');
  assert.equal(modal.getAttribute('aria-modal'), 'true');
  assert.equal(dlg.one('modal-title').textContent, 'کاربرِ تازه');
  assert.equal(h.document.activeElement, dlg.byKey('f:username'), 'the username first');
  const pass = dlg.byKey('f:password');
  assert.match(pass.value, /^[A-Za-z2-9]{10}$/, 'a password ready');
  assert.equal(pass.type, 'text', 'shown: the admin reads it out');
  assert.equal(pass.getAttribute('dir'), 'ltr');
  assert.equal(dlg.byKey('f:username').getAttribute('dir'), 'ltr');
  assert.equal(dlg.byKey('f:username').getAttribute('autocapitalize'), 'none');
  assert.equal(dlg.byKey('f:period').value, 'jmonth', 'in Persian a new user’s cap follows the Persian month…');
  assert.equal(dlg.byKey('f:renew').value, '1', '…from its 1st');
  assert.equal(dlg.byKey('f:enabled').checked, true);
  assert.equal(dlg.hasKey('f:maxDevices'), false, 'not on a PC');
  assert.equal(dlg.hasKey('f:delete'), false, 'nothing to delete yet');
  const err = (k) => dlg.all((n) => n.dataset.err === k)[0].textContent;

  const save = () => { h.dialog().byKey('f:save').click(); return flush(); };
  await save();
  assert.equal(err('username'), h.t('lu.err.username'), 'empty');
  assert.equal(h.dialog().byKey('f:username').getAttribute('aria-invalid'), 'true');
  assert.equal(h.document.activeElement, h.dialog().byKey('f:username'));
  assert.equal(h.calls.filter((c) => c[0] === 'user').length, 0);

  const type = (key, v) => { const n = h.dialog().byKey(key); n.value = v; n.dispatch('input'); };
  type('f:username', 'bad name!');
  assert.equal(h.dialog().all((n) => n.dataset.err === 'username')[0].textContent, '', 'typing clears it');
  await save();
  assert.equal(h.dialog().all((n) => n.dataset.err === 'username')[0].textContent, 'نام کاربری فقط حروف انگلیسی، عدد، نقطه، خط تیره و زیرخط است، از 1 تا 32 نویسه');
  type('f:username', 'x'.repeat(33));
  await save();
  assert.equal(h.dialog().all((n) => n.dataset.err === 'username')[0].textContent, h.t('lu.err.username'), '33 is one too many');
  type('f:username', 'SARA');
  await save();
  assert.equal(h.dialog().all((n) => n.dataset.err === 'username')[0].textContent, 'این نام کاربری مالِ کاربرِ دیگری است');
  type('f:username', 'mina.k_2-x');
  type('f:password', '123');
  await save();
  assert.equal(h.dialog().all((n) => n.dataset.err === 'username')[0].textContent, '');
  assert.equal(h.dialog().all((n) => n.dataset.err === 'password')[0].textContent, 'رمز دست‌کم 4 نویسه می‌خواهد');
  assert.equal(h.document.activeElement, h.dialog().byKey('f:password'));
  type('f:password', ' 1234 ');
  type('f:name', '  مینا ');
  type('f:quotaGb', '15');
  type('f:expires', '2027-03-20');
  const target = h.dialog().byKey('f:target:select');
  target.value = 'srv-2';
  target.dispatch('change');
  await save();
  const [kind, op, user] = h.calls.at(-1);
  assert.deepEqual([kind, op], ['user', 'add']);
  assert.deepEqual(user, {
    username: 'mina.k_2-x', password: ' 1234 ', name: 'مینا', target: 'srv-2', quotaGb: 15, quotaPeriod: 'month', quotaCalendar: 'jalali', quotaResetDay: 1,
    expiresAt: new Date(2027, 2, 20, 23, 59, 59, 999).getTime(), maxDevices: 0, enabled: true
  }, 'the password as typed; no id — the service gives one');
  assert.equal(h.dialog(), null, 'closed');
  assert.equal(h.host.byClass('lu-user').length, 5, 'the answer is drawn');
  assert.deepEqual(h.toasts.at(-1), ['کاربرِ «مینا» اضافه شد', 'ok']);
});

test('edit: the dialog holds the user; the service’s own refusal goes under the username, any other in the dialog', async () => {
  let refuse = 'usernameTaken';
  const h = harness({ router: true, api: { lanUsersUser: async () => { throw new Error(refuse); } } });
  await h.load();
  h.host.byKey('edit:usr-a1').focus();
  h.host.byKey('edit:usr-a1').click();
  const dlg = h.dialog();
  assert.equal(dlg.one('modal-title').textContent, 'ویرایشِ کاربر');
  assert.equal(dlg.byKey('f:name').value, 'سارا');
  assert.equal(dlg.byKey('f:username').value, 'sara');
  assert.equal(dlg.byKey('f:password').value, 'pa55-Sara');
  assert.equal(dlg.byKey('f:password').type, 'password', 'an existing password: hidden until asked');
  dlg.byKey('f:show').click();
  assert.equal(dlg.byKey('f:password').type, 'text');
  assert.equal(dlg.byKey('f:target:select').value, 'srv-1');
  assert.equal(dlg.byKey('f:quotaGb').value, '20');
  assert.equal(dlg.byKey('f:maxDevices').value, '2', 'the router: how many devices');
  assert.ok(dlg.hasKey('f:delete'));
  dlg.byKey('f:gen').click();
  assert.match(h.dialog().byKey('f:password').value, /^[A-Za-z2-9]{10}$/);
  h.dialog().byKey('f:save').click();
  await flush();
  assert.equal(h.dialog().all((n) => n.dataset.err === 'username')[0].textContent, h.t('lu.err.usernameTaken'));
  refuse = 'the store is read-only';
  h.dialog().byKey('f:save').click();
  await flush();
  assert.equal(h.dialog().one('lu-formerr').textContent, 'ذخیره نشد: the store is read-only');
  assert.equal(h.dialog().one('lu-formerr').getAttribute('role'), 'alert');
  // Esc closes it, and the focus goes back to the button that opened it
  h.dialog().dispatch('keydown', { key: 'Escape' });
  assert.equal(h.dialog(), null);
  assert.equal(h.document.activeElement, h.host.byKey('edit:usr-a1'));
});

test('delete asks first, then sends the id; from the dialog too', async () => {
  const h = harness();
  await h.load();
  h.state.confirm = false;
  h.host.byKey('delete:usr-b2').click();
  await flush();
  assert.deepEqual(h.asked, ['کاربرِ «Reza» حذف شود؟ دستگاه‌هایش دیگر وصل نمی‌شوند.']);
  assert.equal(h.calls.filter((c) => c[0] === 'user').length, 0);
  h.state.confirm = true;
  h.host.byKey('delete:usr-b2').click();
  await flush();
  assert.deepEqual(h.calls.at(-1), ['user', 'delete', { id: 'usr-b2' }]);
  assert.equal(h.user('usr-b2'), undefined);
  h.host.byKey('edit:usr-c3').click();
  h.dialog().byKey('f:delete').click();
  await flush();
  assert.deepEqual(h.calls.at(-1), ['user', 'delete', { id: 'usr-c3' }]);
  assert.equal(h.dialog(), null, 'the dialog of a deleted user closes');
  assert.equal(h.host.byClass('lu-user').length, 2);
});

test('validate(): the contract’s rules', () => {
  const h = harness();
  // the answer is the vm's object: compared as plain data
  const page = { validate: (f, others) => clone(h.page.validate(f, others)) };
  const ok = { username: 'a', password: 'abcd', quotaGb: '', maxDevices: '' };
  assert.deepEqual(page.validate(ok, []), {});
  assert.deepEqual(page.validate(Object.assign({}, ok, { username: 'A.b_c-9'.padEnd(32, 'z') }), []), {});
  assert.equal(page.validate(Object.assign({}, ok, { username: 'a'.repeat(33) }), []).username, 'lu.err.username');
  for (const bad of ['', 'ali reza', 'علی', 'a:b', 'a@b', 'a/b']) assert.equal(page.validate(Object.assign({}, ok, { username: bad }), []).username, 'lu.err.username', bad);
  assert.equal(page.validate(ok, [{ username: 'A' }]).username, 'lu.err.usernameTaken');
  assert.equal(page.validate(Object.assign({}, ok, { password: 'abc' }), []).password, 'lu.err.password');
  assert.deepEqual(page.validate(Object.assign({}, ok, { password: '    ' }), []), {}, 'kept as given: four spaces are four characters');
  assert.equal(page.validate(Object.assign({}, ok, { quotaGb: '-1' }), []).quotaGb, 'lu.err.quota');
  assert.equal(page.validate(Object.assign({}, ok, { quotaGb: 'x' }), []).quotaGb, 'lu.err.quota');
  assert.deepEqual(page.validate(Object.assign({}, ok, { quotaGb: '0.5' }), []), {});
  assert.equal(page.validate(Object.assign({}, ok, { maxDevices: '1.5' }), []).maxDevices, 'lu.err.maxDevices');
});

/* ------------------------------ the router ------------------------------ */

test('the router, in English: transparent mode, what an unassigned device gets, the devices online first with IP and MAC left to right', async () => {
  const h = harness({ lang: 'en', router: true, platform: 'linux', connected: true });
  await h.load();
  const { host, t } = h;
  assert.equal(host.byClass('lu-hotspot').length, 0, 'no Windows note on the router');
  const titles = host.one('lu-settings').byClass('switch-title').map((n) => n.textContent);
  assert.deepEqual(titles, ['Proxy accounts', 'Transparent mode']);
  assert.equal(host.byKey('transparent').checked, true);
  const un = host.byKey('unassigned');
  assert.equal(un.value, 'login');
  assert.deepEqual(un.children.map((o) => [o.value, o.textContent]), [['login', 'Sign-in page'], ['allow', 'Allowed (the current connection)'], ['block', 'Blocked']]);
  assert.equal(host.byKey('sessionHours').value, '24');
  assert.ok(host.one('lu-settings').textContent.includes(t('lu.unassignedHint.login')));

  // the users: the device limit, the online count, the live rate
  assert.equal(host.byKey('max:usr-a1').value, '2');
  const sara = h.user('usr-a1');
  assert.equal(sara.one('lu-tag').textContent, '1 online');
  const rate = sara.one('lu-rate');
  assert.equal(rate.hidden, false);
  assert.equal(rate.textContent, '↓ 1.5 MB/s  ↑ 20.0 KB/s');
  assert.equal(rate.getAttribute('dir'), 'ltr');

  const card = host.one('lu-devices');
  assert.equal(card.one('lu-title').textContent, 'Devices');
  assert.equal(card.one('lu-meta').textContent, '2 online of 3');
  const rows = card.byClass('lu-dev');
  assert.deepEqual(rows.map((r) => r.dataset.mac), ['aa:bb:cc:00:00:03', 'aa:bb:cc:00:00:01', 'aa:bb:cc:00:00:02'], 'online first (by name), MACs lowercase');
  const [desk, phone, off] = rows;
  assert.equal(desk.one('lu-dot').classList.contains('on'), true);
  assert.equal(off.one('lu-dot').classList.contains('on'), false);
  assert.ok(off.classList.contains('lu-gone'));
  assert.equal(phone.byClass('lu-devname')[0].value, 'Sara phone');
  assert.equal(desk.byClass('lu-devname')[0].value, '');
  assert.equal(desk.byClass('lu-devname')[0].placeholder, 'DESKTOP-7Q', 'its hostname until it is named');
  for (const [row, ip, mac] of [[desk, '192.168.1.150', 'aa:bb:cc:00:00:03'], [phone, '192.168.1.101', 'aa:bb:cc:00:00:01']]) {
    assert.equal(row.one('lu-ip').textContent, ip);
    assert.equal(row.one('lu-ip').getAttribute('dir'), 'ltr');
    assert.equal(row.one('lu-mac').textContent, mac);
    assert.equal(row.one('lu-mac').getAttribute('dir'), 'ltr');
  }
  assert.equal(off.byClass('lu-ip').length, 0, 'offline: no IP');
  const users = host.byKey('devuser:aa:bb:cc:00:00:01');
  assert.equal(users.value, 'usr-a1');
  assert.deepEqual(users.children.map((o) => o.textContent), ['— nobody —', 'سارا · sara', 'Reza · reza', 'guest', 'Kid · kid']);
  assert.equal(host.byKey('devuser:aa:bb:cc:00:00:03').value, '');
  assert.ok(desk.textContent.includes('Sign-in page'), 'nobody’s device: what it gets, said on its row');
  assert.equal(host.byKey('devblock:aa:bb:cc:00:00:02').checked, true);
  assert.ok(off.textContent.includes('blocked'));
  const use = phone.one('lu-use').children;
  assert.deepEqual(use.map((s) => [s.className, s.textContent, s.getAttribute('dir'), s.hidden]), [
    ['lu-mono lu-bytes', '700.0 MB', 'ltr', false], ['lu-mono lu-devrate', '↓ 1.5 MB/s  ↑ 20.0 KB/s', 'ltr', false]
  ], 'its usage, and its live rate under it');
  assert.deepEqual(desk.one('lu-use').children.map((s) => s.hidden), [true, true], 'nothing counted, nothing moving: nothing said');

  // assign, block, name
  const pickUser = host.byKey('devuser:aa:bb:cc:00:00:03');
  pickUser.value = 'usr-b2';
  pickUser.dispatch('change');
  await flush();
  assert.deepEqual(h.calls.at(-1), ['device', { mac: 'aa:bb:cc:00:00:03', userId: 'usr-b2' }]);
  const blk = host.byKey('devblock:aa:bb:cc:00:00:01');
  blk.checked = true;
  blk.dispatch('change');
  await flush();
  assert.deepEqual(h.calls.at(-1), ['device', { mac: 'aa:bb:cc:00:00:01', blocked: true }]);
  const name = host.byKey('devname:aa:bb:cc:00:00:03');
  name.value = '  Office PC ';
  name.dispatch('change');
  await flush();
  assert.deepEqual(h.calls.at(-1), ['device', { mac: 'aa:bb:cc:00:00:03', name: 'Office PC' }]);
  assert.equal(host.byKey('devname:aa:bb:cc:00:00:03').value, 'Office PC');

  // a policy without a sign-in has no sign-in hours
  const policy = host.byKey('unassigned');
  policy.value = 'block';
  policy.dispatch('change');
  await flush();
  assert.deepEqual(h.calls.at(-1), ['config', { transparent: { unassigned: 'block' } }]);
  assert.equal(host.hasKey('sessionHours'), false);
  assert.ok(host.one('lu-settings').textContent.includes(t('lu.unassignedHint.block')));
});

test('the router\'s sign-in page under login mode: its short name and address copied, its QR, a wall sheet printed in both languages and gone after; down, it says so; another policy, no box', async () => {
  const made = [];
  const qrcode = () => { const q = { data: '', addData(s) { q.data = s; }, make() {}, createDataURL() { made.push(q.data); return 'data:image/gif;base64,R0lGOD'; } }; return q; };
  const portal = { url: 'http://192.168.2.1:30822/', name: 'login.lan', nameUrl: 'http://login.lan:30822/' };
  const h = harness({ lang: 'en', router: true, platform: 'linux', qrcode, data: routerPayload({ portal }) });
  await h.load();
  const box = h.host.one('lu-portal');
  assert.equal(box.byClass('field-label')[0].textContent, 'The sign-in page');
  const values = box.byClass('lu-mono');
  assert.deepEqual(values.map((v) => [v.dataset.portal, v.textContent, v.getAttribute('dir')]), [['name', 'http://login.lan:30822/', 'ltr'], ['address', 'http://192.168.2.1:30822/', 'ltr']]);
  box.byKey('copy:portal:name').click();
  box.byKey('copy:portal:address').click();
  await flush();
  assert.deepEqual(h.copies, ['http://login.lan:30822/', 'http://192.168.2.1:30822/']);
  assert.ok(box.textContent.includes(h.t('lu.portalNameHint')));
  assert.equal(box.one('lu-portal-qr').byClass('lu-qrimg')[0].alt, 'QR code of the sign-in page');
  assert.equal(made[0], 'http://login.lan:30822/', 'the QR is of the short name');

  // the wall sheet: in the page while it prints, Persian and English whatever the window's language, then gone
  const html = h.document.documentElement;
  const on = {};
  let during = null;
  h.window.addEventListener = (type, fn) => { on[type] = fn; };
  h.window.removeEventListener = (type) => { delete on[type]; };
  h.window.print = () => {
    const sheet = h.document.body.children.find((c) => c.classList.contains('lu-printsheet'));
    during = { printing: html.classList.contains('lu-printing'), text: sheet ? sheet.textContent : null, urls: sheet ? sheet.byClass('lu-ps-url').map((u) => u.textContent) : [], qr: sheet ? sheet.byClass('lu-ps-qr').length : 0 };
  };
  box.byKey('portalPrint').click();
  assert.equal(during.printing, true);
  assert.ok(during.text.includes('ورود به اینترنت') && during.text.includes('Sign in to use the internet'), during.text);
  assert.ok(during.text.includes('Join the Wi-Fi') && during.text.includes('به وای‌فای وصل شوید'));
  assert.deepEqual(during.urls, ['http://login.lan:30822/', 'http://192.168.2.1:30822/']);
  assert.equal(during.qr, 1);
  on.afterprint();
  assert.equal(html.classList.contains('lu-printing'), false);
  assert.ok(!h.document.body.children.some((c) => c.classList.contains('lu-printsheet')), 'the sheet is gone after the print');

  // the page is down (not connected): said, no address to hand out
  const down = harness({ lang: 'en', router: true, platform: 'linux', data: routerPayload({ portal: null }) });
  await down.load();
  const dbox = down.host.one('lu-portal');
  assert.equal(dbox.byClass('lu-mono').length, 0);
  assert.ok(dbox.textContent.includes(down.t('lu.portalDown')));
  // only an http address is drawn
  const odd = harness({ lang: 'en', router: true, platform: 'linux', data: routerPayload({ portal: { url: 'javascript:alert(1)' } }) });
  await odd.load();
  assert.ok(odd.host.one('lu-portal').textContent.includes(odd.t('lu.portalDown')));
  // no sign-in page in another policy, and none on a desktop
  const blocked = harness({ lang: 'en', router: true, platform: 'linux', data: routerPayload({ portal, config: { proxy: { enabled: false, port: 30820, httpPort: 30821 }, transparent: { enabled: true, unassigned: 'block', sessionHours: 24, portalPort: 30822 } } }) });
  await blocked.load();
  assert.equal(blocked.host.byClass('lu-portal').length, 0);
  const desk = harness({ lang: 'en', data: payload({ portal }) });
  await desk.load();
  assert.equal(desk.host.byClass('lu-portal').length, 0);
});

test('the router in Persian, transparent mode off: the devices say their settings wait for it', async () => {
  const data = routerPayload();
  data.config.transparent.enabled = false;
  const h = harness({ router: true, data });
  await h.load();
  assert.equal(h.host.one('lu-settings').byClass('lu-body')[1].hidden, true);
  assert.equal(h.host.one('lu-devices').byClass('lu-hint')[0].textContent, h.t('lu.devTransparentOff'));
  assert.equal(h.host.one('lu-devices').one('lu-meta').textContent, '2 آنلاین از 3');
  assert.ok(!h.device('aa:bb:cc:00:00:03').textContent.includes('صفحهٔ ورود'), 'no policy said while it decides nothing');
  assert.equal(h.user('usr-a1').one('lu-rate').hidden, true, 'disconnected: no live rate');
});

/* ------------------------------ live ------------------------------ */

test('a stats tick repaints the usage and the rates in place; while the page is open it reads again every few seconds, quietly', async () => {
  const h = harness({ connected: true });
  await h.load();
  const reads = () => h.calls.filter((c) => c[0] === 'get').length;
  const box = h.user('usr-a1');
  const q = h.host.byKey('quota:usr-a1');
  h.page.tick({ live: { 'usr-a1': { up: 1024, down: 2097152 } }, usage: { 'usr-a1': Object.assign({}, h.store.data.usage['usr-a1'], { bytes: 19 * GIB }) } });
  assert.equal(h.user('usr-a1'), box, 'in place, not redrawn');
  assert.equal(h.host.byKey('quota:usr-a1'), q);
  assert.equal(box.one('lu-bar').children[0].style.width, '95.0%');
  assert.equal(box.one('lu-bar').children[0].className, 'warn');
  assert.equal(box.one('lu-rate').textContent, '↓ 2.0 MB/s  ↑ 1.0 KB/s');
  assert.equal(reads(), 1, 'read just now: not again yet');
  // five seconds on, the same layout: the numbers only
  vm.runInContext('Date.now = ((n) => () => n)(Date.now() + 6000)', h.ctx);
  h.store.data.usage['usr-a1'].bytes = 10 * GIB;
  h.page.tick(null);
  await flush();
  assert.equal(reads(), 2);
  assert.equal(h.user('usr-a1'), box, 'nothing but numbers changed: the same box');
  assert.equal(box.one('lu-bar').children[0].style.width, '50.0%');
  // a new user on the next read: drawn
  vm.runInContext('Date.now = ((n) => () => n)(Date.now() + 6000)', h.ctx);
  h.store.data.users.push({ id: 'usr-e5', username: 'new', password: 'abcd', name: '', target: '', quotaGb: 0, quotaPeriod: 'none', expiresAt: 0, maxDevices: 0, enabled: true });
  h.page.tick(null);
  await flush();
  assert.equal(h.host.byClass('lu-user').length, 5);
  // closed: no reading
  h.state.visible = false;
  vm.runInContext('Date.now = ((n) => () => n)(Date.now() + 6000)', h.ctx);
  h.page.tick(null);
  await flush();
  assert.equal(reads(), 3);
  // disconnected: the rates go and the "while connected" line comes
  h.state.connected = false;
  h.page.connection(false);
  assert.equal(h.user('usr-a1').one('lu-rate').hidden, true);
  assert.equal(h.host.byClass('lu-hint')[0].textContent, h.t('lu.whileConnected'));
});

test('a read that fails says so; a back end without the channels hides the page and its nav item', async () => {
  const h = harness({ api: { lanUsersGet: async () => { throw new Error('No handler registered for lanusers:get'); } } });
  await h.load();
  assert.ok(h.host.textContent.includes('کاربران خوانده نشدند: No handler registered for lanusers:get'));
  const old = harness({ api: { lanUsersGet: undefined } });
  assert.equal(old.host.hidden, true);
  assert.equal(old.document.navItem.hidden, true);
});

/* ------------------------------ strings, classes, markup, wiring ------------------------------ */

test('every string the page can show is defined once in Persian and once in English, right after mi.note', () => {
  const keys = new Set([...PAGE.matchAll(/t\('((?:lu|nav|set)\.[A-Za-z0-9.]+)'\)/g)].map((m) => m[1]));
  for (const s of ['on', 'off', 'expired', 'over']) keys.add('lu.state.' + s);
  for (const p of ['month', 'jmonth', 'day', 'none']) keys.add('lu.period.' + p);
  for (const p of ['login', 'allow', 'block']) { keys.add('lu.unassigned.' + p); keys.add('lu.unassignedHint.' + p); }
  for (const k of ['username', 'usernameTaken', 'password', 'quota', 'maxDevices']) keys.add('lu.err.' + k);
  for (const k of ['nav.users', 'set.lanUsers', 'lu.title']) keys.add(k);
  assert.ok(keys.size > 80, `expected the whole page, found ${keys.size} keys`);
  const bad = [...keys].filter((k) => (I18N.split(`'${k}':`).length - 1) !== 2).sort();
  assert.deepEqual(bad, [], 'not defined exactly once in each of fa and en');
  for (const anchor of I18N.split('\n').map((l, i) => [l, i]).filter(([l]) => l.includes("'mi.note':"))) {
    const next = I18N.split('\n').slice(anchor[1] + 1, anchor[1] + 4).join('\n');
    assert.match(next, /users on this network \(lanUsers\.js\)[\s\S]*'nav\.users':/, 'the block sits right after mi.note');
  }
  assert.doesNotMatch(I18N.slice(I18N.indexOf("'nav.users'"), I18N.indexOf("'lu.dev.blocked'")), /'[^'\n]*[a-z]'[a-z][^'\n]*'/i, 'no ASCII apostrophe inside a string');
});

test('every class the page builds is styled in settings.css — tokens only, logical properties only', () => {
  const css = R('src', 'renderer', 'settings.css');
  const cls = new Set();
  for (const m of PAGE.matchAll(/(?:el|button)\('[a-z]+', '([^']+)'/g)) m[1].split(/\s+/).forEach((c) => cls.add(c));
  for (const c of ['lu-s-on', 'lu-s-off', 'lu-s-expired', 'lu-s-over', 'lu-dim', 'lu-gone', 'lu-bad', 'lu-hotspot', 'lu-date', 'lu-dcell', 'lu-block', 'lu-use']) cls.add(c);
  // the three blocks' own names are hooks (their look is .lu-card's)
  const own = [...cls].filter((c) => c.startsWith('lu-') && c !== 'lu-s-' && !['lu-settings', 'lu-users', 'lu-devices'].includes(c));
  assert.ok(own.length >= 40, `found ${own.length}`);
  for (const c of own) assert.match(css, new RegExp('\\.' + c + '(?![\\w-])'), `.${c} has no style`);
  const block = css.slice(css.indexOf('users on this network (lanUsers.js)'));
  assert.ok(block.length > 2000);
  assert.doesNotMatch(block, /#[0-9a-f]{3,8}\b(?![\w-])|rgba?\(/i, 'no literal colours: the skins pick them');
  assert.doesNotMatch(block, /(?:margin|padding|border)-(?:left|right)|text-align:\s*(?:left|right)|\b(?:left|right):/, 'logical properties only: the app runs RTL');
  assert.match(block, /@media \(max-width: 680px\) \{\s*\.lu-grid, \.lu-ctl \{ grid-template-columns: 1fr; \}/, 'one column on a phone');
});

test('the markup: a nav item and a view for module lanUsers, the page box, the script before app.js', () => {
  const html = R('src', 'renderer', 'index.html');
  assert.match(html, /<button class="nav-item" data-view="users" data-module="lanUsers" data-i18n-title="nav\.users">/);
  assert.match(html, /<section class="view" id="view-users" data-module="lanUsers">/);
  const view = html.slice(html.indexOf('id="view-users"'), html.indexOf('</section>', html.indexOf('id="view-users"')));
  assert.ok(view.includes('<h2 data-i18n="lu.title">'));
  assert.ok(view.includes('<div id="lanUsersPage"></div>'));
  const scripts = [...html.matchAll(/<script src="([^"]+)"><\/script>/g)].map((m) => m[1]);
  assert.ok(scripts.indexOf('i18n.js') < scripts.indexOf('lanUsers.js') && scripts.indexOf('lanUsers.js') < scripts.indexOf('app.js'), scripts.join(', '));
});

test('the wiring: the four calls in the preload and the router’s bridge; app.js mounts, reads on open, redraws, ticks', () => {
  const preload = R('src', 'preload', 'preload.js');
  const web = R('src', 'server', 'web-api.js');
  for (const [name, channel, arg] of [['lanUsersGet', 'lanusers:get', ''], ['lanUsersConfig', 'lanusers:config', 'partial'], ['lanUsersUser', 'lanusers:user', 'change'], ['lanUsersDevice', 'lanusers:device', 'change']]) {
    const call = arg ? `\\('${channel}', ${arg}\\)` : `\\('${channel}'\\)`;
    assert.match(preload, new RegExp(`${name}: \\(${arg}\\) => ipcRenderer\\.invoke${call},`), name);
    assert.match(web, new RegExp(`${name}: \\(${arg}\\) => invoke${call},`), name);
  }
  const app = R('src', 'renderer', 'app.js');
  assert.match(app, /window\.lanUsersPage\.mount\(\$\('#lanUsersPage'\), \{/);
  assert.match(app, /targets: \(\) => configOptions\(\),/, 'the app’s own config list');
  assert.match(app, /picker: \(o\) => makeSearchSelect\(o\),/, 'and its own picker');
  assert.match(app, /router: \(\) => state\.flavor === 'openwrt',/);
  assert.match(app, /if \(view === 'users' && window\.lanUsersPage\) window\.lanUsersPage\.refresh\(\);/);
  assert.match(app, /if \(window\.lanUsersPage\) window\.lanUsersPage\.render\(\);/);
  assert.match(app, /window\.lanUsersPage\.tick\(state\.connected \? s\.lanUsers : null\);/);
  assert.match(app, /window\.lanUsersPage\.connection\(live\);/);
  // the Extensions page mounts between the two (modules.js / extensions.js)
  assert.match(app, /mountMultiWan\(\);\r?\n(?: {2}mountExtensions\(\);\r?\n)? {2}mountLanUsers\(\);/);
  const fn = app.slice(app.indexOf('async function lanUsersApplied'), app.indexOf('function mountLanUsers'));
  assert.match(fn, /if \(state\.connected && \(state\.pendingReconnect \|\| \[\]\)\.some\(k => !before\.includes\(k\)\)\) await promptApplySettings\(\);/);
});
