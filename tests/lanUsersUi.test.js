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
  // `class` is the class list, as in a browser (an SVG element's only way to set one)
  setAttribute(k, v) { if (k === 'class') this.className = String(v); else this.attributes[k] = String(v); }
  getAttribute(k) { if (k === 'class') return this._cls.size ? this.className : null; return Object.prototype.hasOwnProperty.call(this.attributes, k) ? this.attributes[k] : null; }
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
  // an SVG node keeps its tag's case, as a browser's does ('rect', 'title')
  doc.createElementNS = (ns, tag) => Object.assign(new FakeEl(doc, tag), { namespaceURI: ns, tagName: String(tag) });
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

/** A local day 'YYYY-MM-DD', `ago` days before today (by the calendar: a clock change moves nothing). */
function dayKey(ago = 0) {
  const n = new Date();
  const d = new Date(n.getFullYear(), n.getMonth(), n.getDate() - ago);
  return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
}
const TODAY_18 = (() => { const n = new Date(); return new Date(n.getFullYear(), n.getMonth(), n.getDate(), 18, 0).getTime(); })();
const MB = 1024 * 1024;

/** usage().meters as meter.js answers them: every kind by the day and the month, `rows` over them ('vpn:day': {…}), a 'none' row where given. */
function meters(rows = {}) {
  const out = [];
  for (const kind of ['total', 'vpn', 'direct']) {
    for (const period of ['day', 'month']) out.push({ kind, period, bytes: 0, capBytes: 0, extraBytes: 0, since: 0, until: period === 'day' ? DAY_END : MONTH_END, over: false, pct: 0 });
  }
  for (const [k, v] of Object.entries(rows)) {
    const [kind, period] = k.split(':');
    let m = out.find((x) => x.kind === kind && x.period === period);
    if (!m) out.push(m = { kind, period, bytes: 0, capBytes: 0, extraBytes: 0, since: 0, until: 0, over: false, pct: 0 });
    Object.assign(m, v);
  }
  return out;
}

/**
 * A v1.39 payload (contract §1/§2/§6): limits by kind and period, routing,
 * allowed hours; the meters, the hold and when it lifts. Sara: a monthly
 * Total near its cap and a daily VPN limit over it (topped up), so the VPN
 * alone is held — direct only; Reza: a profile, two limits, outside his
 * hours; the guest: no limit, Fridays only, today's and this month's totals.
 */
function payload139(over = {}) {
  return payload(Object.assign({
    users: [
      { id: 'usr-a1', username: 'sara', password: 'pa55-Sara', name: 'سارا', target: 'srv-1', routing: 'bypass-ir', schedule: null,
        limits: [{ kind: 'total', period: 'month', gb: 20 }, { kind: 'vpn', period: 'day', gb: 1 }], quotaGb: 20, quotaPeriod: 'month', expiresAt: 0, maxDevices: 0, enabled: true },
      { id: 'usr-b2', username: 'reza', password: 'reza1234', name: 'Reza', target: '', routing: 'profile:rp-work', schedule: { days: [6, 0, 1, 2, 3], from: '08:00', to: '22:00' },
        limits: [{ kind: 'vpn', period: 'month', gb: 10 }, { kind: 'direct', period: 'none', gb: 50 }], quotaGb: 0, quotaPeriod: 'month', expiresAt: 0, maxDevices: 0, enabled: true },
      { id: 'usr-c3', username: 'guest', password: 'guest', name: '', target: 'block', routing: '', schedule: { days: [5], from: '10:00', to: '10:00' },
        limits: [], quotaGb: 0, quotaPeriod: 'month', expiresAt: 0, maxDevices: 0, enabled: true }
    ],
    usage: {
      'usr-a1': { bytes: 17 * GIB, period: '2026-10', until: MONTH_END, quotaBytes: 20 * GIB, over: false, hold: 'vpn', why: 'vpn', holdUntil: DAY_END, history: [], speed: null,
        meters: meters({ 'total:month': { bytes: 17 * GIB, capBytes: 20 * GIB, pct: 85 }, 'vpn:day': { bytes: 1.6 * GIB, capBytes: GIB, extraBytes: 0.5 * GIB, over: true, pct: 100 } }) },
      'usr-b2': { bytes: 0, period: '2026-10', until: MONTH_END, quotaBytes: 0, over: true, hold: 'all', why: 'schedule', holdUntil: TODAY_18, history: [], speed: null,
        meters: meters({ 'vpn:month': { bytes: 4 * GIB, capBytes: 10 * GIB, pct: 40 }, 'direct:none': { bytes: 5 * GIB, capBytes: 50 * GIB, pct: 10 } }) },
      'usr-c3': { bytes: 0, period: '2026-10', until: MONTH_END, quotaBytes: 0, over: false, hold: null, why: null, holdUntil: 0, history: [], speed: null,
        meters: meters({ 'vpn:day': { bytes: 120 * MB }, 'direct:day': { bytes: 40 * MB }, 'vpn:month': { bytes: 2.1 * GIB }, 'direct:month': { bytes: 300 * MB },
          'total:day': { bytes: 160 * MB }, 'total:month': { bytes: 2.1 * GIB + 300 * MB } }) }
    }
  }, over));
}

const flush = () => new Promise((r) => setImmediate(r));

function harness({ lang = 'fa', platform = 'win32', router = false, connected = false, data = null, api = {}, confirm = true, visible = true, picker = null, qrcode = null, profiles = null, globals = {}, extras = {} } = {}) {
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
      lanUsersUser: async (arg) => {
        const { op, user = {} } = arg;
        // what the op carries beside the user (topUp: kind, period, gb) — a fourth entry when there is any
        const more = Object.assign({}, arg);
        delete more.op;
        delete more.user;
        calls.push(['user', op, clone(user)].concat(Object.keys(more).length ? [clone(more)] : []));
        const d = store.data;
        if (op === 'add') d.users.push(Object.assign({ id: 'usr-new' + d.users.length }, user));
        if (op === 'update') d.users = d.users.map((u) => (u.id === user.id ? Object.assign({}, user) : u));
        if (op === 'delete') d.users = d.users.filter((u) => u.id !== user.id);
        const meters = (d.usage[user.id] && d.usage[user.id].meters) || [];
        if (op === 'topUp') for (const m of meters) if (m.kind === arg.kind && m.period === arg.period) m.extraBytes = (m.extraBytes || 0) + arg.gb * GIB;
        if (op === 'resetUsage') for (const m of meters) Object.assign(m, { bytes: 0, extraBytes: 0, over: false, pct: 0 });
        // v1.40: a top-up or a reset answers the user's request too; a dismiss lets it go
        if (['topUp', 'resetUsage', 'dismissRequest'].includes(op) && d.usage[user.id]) d.usage[user.id].request = null;
        return answer();
      },
      // v1.40: the module's own backup (the store record and the meter's state) and its restore
      lanUsersBackup: async () => {
        calls.push(['backup']);
        const d = store.data;
        return { ok: true, bundle: { kind: 'irnetfree-lanusers', version: 1, at: new Date(2026, 9, 28, 14, 5).getTime(), app: '1.40.0', platform: d.platform,
          lanUsers: { config: clone(d.config), users: clone(d.users), devices: clone(d.devices) }, meter: { usage2: {}, history: {}, months: {}, requests: {} } } };
      },
      lanUsersRestore: async (arg) => {
        calls.push(['restore', clone(arg)]);
        const lu = arg.bundle.lanUsers;
        const have = new Set(store.data.users.map((u) => u.id));
        const fresh = lu.users.filter((u) => !have.has(u.id));
        if (arg.mode === 'replace') { store.data.users = clone(lu.users); store.data.devices = clone(lu.devices || []); } else store.data.users.push(...clone(fresh));
        return { ok: true, added: { users: fresh.filter((u) => !u.voucher).length, devices: (lu.devices || []).length, vouchers: fresh.filter((u) => u.voucher).length },
          updated: { users: lu.users.length - fresh.length, devices: 0 }, skipped: { users: 0 } };
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
  Object.assign(window, extras);   // v1.40: luVouchers.js / luReports.js stubs (window.LuVouchers, window.LuReports)
  const ctx = vm.createContext(Object.assign({ window, document, console, setTimeout, clearTimeout, Uint32Array, btoa }, qrcode ? { qrcode } : {}, globals));
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
  if (profiles) hooks.routingProfiles = () => profiles;
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
/** The days of the calendar from today to ms's day (the box's "N days left"). */
const daysTo = (ms) => { const a = new Date(); const b = new Date(ms); return Math.round((Date.UTC(b.getFullYear(), b.getMonth(), b.getDate()) - Date.UTC(a.getFullYear(), a.getMonth(), a.getDate())) / DAY); };
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
  assert.deepEqual(sara.byClass('field-label').map((l) => l.textContent), ['رمز', 'کانفیگ', 'مصرف', 'انقضا']);

  // an older service's single cap is one Total limit: 6.5 of 20 GB this month, what is left until the month's end
  // (v1.39: the limits are edited in the dialog's grid — the box shows them)
  const meter = sara.one('lu-meter');
  assert.equal(meter.dataset.meter, 'total:month');
  const bar = meter.one('lu-bar');
  assert.equal(bar.getAttribute('role'), 'progressbar');
  assert.equal(bar.getAttribute('aria-label'), 'کل · این ماه');
  assert.equal(bar.children[0].style.width, '32.5%');
  assert.equal(bar.children[0].className, '');
  assert.equal(meter.one('lu-mlabel').textContent, 'کل · این ماه');
  assert.equal(meter.one('lu-mnum').textContent, '6.5 GB / 20.0 GB');
  assert.equal(meter.one('lu-mnum').getAttribute('dir'), 'ltr');
  assert.equal(meter.one('lu-mfoot').textContent, '13.5 GB مانده، تا ' + persian(MONTH_END, SHORT));
  assert.equal(host.hasKey('quota:usr-a1'), false, 'no cap box in the user’s box any more');
  assert.ok(host.hasKey('topup:usr-a1') && host.hasKey('reset:usr-a1'));
  // near its daily cap: amber, and what is left
  const reza = h.user('usr-b2');
  assert.equal(reza.one('lu-bar').children[0].className, 'warn');
  assert.ok(reza.one('lu-meter').classList.contains('lu-m-near'));
  assert.equal(reza.one('lu-mlabel').textContent, 'کل · امروز');
  assert.equal(reza.one('lu-mfoot').textContent, '204.8 MB مانده');
  // no cap: no bar, the bytes and nothing to top up
  const guest = h.user('usr-c3');
  assert.equal(guest.byClass('lu-bar').length, 0);
  assert.deepEqual(guest.one('lu-quota').children.map((c) => c.textContent), ['300.0 MB مصرف شده', 'این ماه']);
  assert.equal(host.hasKey('topup:usr-c3'), false);
  assert.ok(host.hasKey('reset:usr-c3'));
  // at its cap: red, and when it comes back
  const kid = h.user('usr-d4');
  assert.equal(kid.one('lu-bar').children[0].className, 'over');
  assert.equal(kid.one('lu-mfoot').textContent, 'برمی‌گردد ' + persian(MONTH_END, SHORT));
  assert.ok(host.byClass('lu-hist').every((c) => c.hidden), 'no history in an older payload: no chart');
  assert.equal(host.byClass('lu-speed').every((c) => c.hidden), true, 'no speed limit');

  // the expiry: a date box, and its day in the Persian calendar
  assert.equal(host.byKey('expires:usr-a1').value, '');
  assert.equal(host.byKey('expires:usr-a1').type, 'date');
  assert.equal(sara.byClass('lu-sub').at(-1).textContent, 'بدون انقضا');
  assert.equal(host.hasKey('noexpiry:usr-a1'), false);
  const rezaEnd = h.store.data.users[1].expiresAt;
  const d = new Date(rezaEnd);
  assert.equal(host.byKey('expires:usr-b2').value, `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`);
  // v1.40: how many days that is, beside it
  assert.equal(reza.byClass('lu-sub').at(-1).textContent, 'تا پایانِ ' + persian(rezaEnd, FULL) + ' · ' + daysTo(rezaEnd) + ' روز مانده');
  assert.equal(reza.one('lu-left').classList.contains('lu-soon'), false, 'a month away: not in the warning ink');
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
  const meter = h.user('usr-a1').one('lu-meter');
  assert.deepEqual(['lu-mlabel', 'lu-mnum', 'lu-mfoot'].map((c) => meter.one(c).textContent), ['Total · this month', '6.5 GB / 20.0 GB', '13.5 GB left, until ' + english(MONTH_END, SHORT)]);
  assert.equal(host.byKey('topup:usr-a1').textContent, '+ Top up');
  assert.equal(host.byKey('reset:usr-a1').textContent, 'Reset usage');
  assert.equal(h.user('usr-b2').byClass('lu-sub').at(-1).textContent, 'through ' + english(h.store.data.users[1].expiresAt, FULL) + ' · ' + daysTo(h.store.data.users[1].expiresAt) + ' days left');
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

test('the switch, an expiry and its removal each save the whole user with that change (the limits are the dialog’s)', async () => {
  const h = harness();
  await h.load();
  const sw = h.host.byKey('enabled:usr-d4');
  sw.checked = true;
  sw.dispatch('change');
  await flush();
  assert.deepEqual(h.calls.at(-1).slice(0, 2), ['user', 'update']);
  assert.equal(h.calls.at(-1)[2].enabled, true);
  assert.equal(h.user('usr-d4').one('lu-state').textContent, 'به سقف رسیده', 'the answer is drawn: on again, and still at its cap this month');
  assert.equal(h.calls.at(-1)[2].quotaGb, 5, 'a change elsewhere leaves the cap as it was');

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
  assert.ok(h.applied.length >= 3, 'every answer goes to app.js (the reconnect question)');
});

test('a month of the admin’s choosing, in the dialog: the Persian or the Gregorian month and its renew day under the limits, saved as the two fields; the box says when it renews', async () => {
  const data = payload();
  data.users[0] = Object.assign({}, data.users[0], { quotaCalendar: 'jalali', quotaResetDay: 30 });
  data.usage['usr-a1'] = Object.assign({}, data.usage['usr-a1'], { period: 'j1405-07@30', until: new Date(2026, 10, 20).getTime() });
  data.usage['usr-c3'] = Object.assign({}, data.usage['usr-c3'], { period: '2026-10@15' });
  const h = harness({ data });
  await h.load();
  assert.equal(h.user('usr-a1').one('lu-mfoot').textContent, '13.5 GB مانده، تا ' + persian(new Date(2026, 10, 20).getTime(), SHORT), 'when it renews: 30 Aban');
  assert.equal(h.user('usr-c3').one('lu-quota').children[1].textContent, 'این ماه', 'a month renewing on the 15th is a month, not today');

  h.host.byKey('edit:usr-a1').click();
  const dlg = () => h.dialog();
  const note = () => dlg().all((n) => n.classList.contains('lu-sub') && n.textContent === h.t('lu.renewLast'))[0];
  const pick = (key, v) => { const n = dlg().byKey(key); n.value = v; n.dispatch('change'); };
  assert.equal(dlg().byKey('f:calendar').value, 'jalali');
  assert.deepEqual(dlg().byKey('f:calendar').children.map((o) => o.textContent), ['ماه شمسی', 'ماه میلادی'], 'the Persian month first in Persian');
  assert.equal(dlg().byKey('f:renew').value, '30');
  assert.deepEqual(dlg().byKey('f:renew').children.map((o) => o.textContent), Array.from({ length: 31 }, (_, i) => String(i + 1)));
  assert.equal(dlg().byKey('f:renew').parentNode.hidden, false, 'a monthly limit: its month shown');
  assert.equal(note().hidden, false, 'the 30th: Esfand of a common year has 29 — said');
  pick('f:renew', '15');
  assert.equal(note().hidden, true);
  // the Gregorian 29th: February has 28 — said; the Persian 29th is in every month — not
  pick('f:calendar', 'gregorian');
  pick('f:renew', '29');
  assert.equal(note().hidden, false);
  pick('f:calendar', 'jalali');
  assert.equal(note().hidden, true);
  pick('f:renew', '15');
  dlg().byKey('f:save').click();
  await flush();
  assert.deepEqual(['quotaPeriod', 'quotaCalendar', 'quotaResetDay'].map((k) => h.calls.at(-1)[2][k]), ['month', 'jalali', 15]);
  h.host.byKey('edit:usr-a1').click();
  pick('f:calendar', 'gregorian');
  dlg().byKey('f:save').click();
  await flush();
  assert.deepEqual(['quotaPeriod', 'quotaCalendar', 'quotaResetDay'].map((k) => h.calls.at(-1)[2][k]), ['month', 'gregorian', 15], 'the Gregorian month, the same day');
});

test('the dialog: the month line comes and goes with the monthly limits; an existing Persian-month cap opens as a monthly Total; English lists the Gregorian month first', async () => {
  const data = payload();
  data.users[1] = Object.assign({}, data.users[1], { quotaPeriod: 'month', quotaCalendar: 'jalali', quotaResetDay: 12 });
  const h = harness({ data });
  await h.load();
  h.host.byKey('edit:usr-b2').click();
  let dlg = h.dialog();
  assert.equal(dlg.byKey('f:limit:total:month').value, '2', 'its one cap: a monthly Total limit');
  assert.equal(dlg.byKey('f:calendar').value, 'jalali');
  assert.equal(dlg.byKey('f:renew').value, '12');
  assert.equal(dlg.byKey('f:renew').parentNode.hidden, false);
  const type = (key, v) => { const n = h.dialog().byKey(key); n.value = v; n.dispatch('input'); };
  type('f:limit:total:month', '');
  assert.equal(dlg.byKey('f:renew').parentNode.hidden, true, 'no monthly limit: no month to set');
  type('f:limit:vpn:day', '1');
  assert.equal(dlg.byKey('f:renew').parentNode.hidden, true, 'a daily one has no month');
  type('f:limit:direct:month', '30');
  assert.equal(dlg.byKey('f:renew').parentNode.hidden, false, 'any monthly limit: its month');
  const r = dlg.byKey('f:renew');
  r.value = '31';
  r.dispatch('change');
  const c = dlg.byKey('f:calendar');
  c.value = 'gregorian';
  c.dispatch('change');
  assert.equal(dlg.all((n) => n.classList.contains('lu-sub') && n.textContent === h.t('lu.renewLast'))[0].hidden, false);
  dlg.byKey('f:save').click();
  await flush();
  const saved = h.calls.at(-1)[2];
  assert.deepEqual(saved.limits, [{ kind: 'vpn', period: 'day', gb: 1 }, { kind: 'direct', period: 'month', gb: 30 }]);
  assert.deepEqual([saved.quotaGb, saved.quotaPeriod, saved.quotaCalendar, saved.quotaResetDay], [0, 'month', 'gregorian', 31], 'no Total limit: the old single cap says none');

  const en = harness({ lang: 'en' });
  await en.load();
  en.host.byKey('add').click();
  dlg = en.dialog();
  assert.deepEqual(dlg.byKey('f:calendar').children.map((o) => o.textContent), ['Gregorian month', 'Jalali month']);
  assert.equal(dlg.byKey('f:calendar').value, 'gregorian', 'in English a new user’s month is the Gregorian one');
  assert.equal(dlg.byKey('f:renew').value, '1');
  assert.equal(dlg.byKey('f:renew').parentNode.hidden, true, 'a new user: no limit yet, no month line');
  assert.deepEqual(dlg.one('lu-limits').byClass('lu-lhead').map((n) => n.textContent), ['', 'Daily', 'Monthly', 'One-off']);
  assert.deepEqual(dlg.one('lu-limits').byClass('lu-lkind').map((n) => n.textContent), ['Total', 'VPN', 'Direct']);
  assert.equal(dlg.one('lu-renew').textContent.includes('Renews on day'), true);
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
  assert.equal(dlg.byKey('f:calendar').value, 'jalali', 'in Persian a new user’s monthly limits follow the Persian month…');
  assert.equal(dlg.byKey('f:renew').value, '1', '…from its 1st');
  assert.equal(dlg.byKey('f:enabled').checked, true);
  assert.equal(dlg.byKey('f:anytime').checked, true, 'any time');
  assert.equal(dlg.byKey('f:routing').value, '');
  assert.equal(dlg.hasKey('f:maxDevices'), false, 'not on a PC');
  assert.equal(dlg.hasKey('f:delete'), false, 'nothing to delete yet');
  // no speed on a PC: one line where it would be, no cut / slow on the limits
  assert.equal(dlg.one('lu-speednote').textContent, h.t('lu.speedRouter'));
  assert.equal(dlg.hasKey('f:speedDown') || dlg.hasKey('f:act:total:day'), false);
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
  type('f:limit:total:month', '15');
  type('f:expires', '2027-03-20');
  const target = h.dialog().byKey('f:target:select');
  target.value = 'srv-2';
  target.dispatch('change');
  await save();
  const [kind, op, user] = h.calls.at(-1);
  assert.deepEqual([kind, op], ['user', 'add']);
  assert.deepEqual(user, {
    username: 'mina.k_2-x', password: ' 1234 ', name: 'مینا', target: 'srv-2', routing: '',
    limits: [{ kind: 'total', period: 'month', gb: 15 }], quotaGb: 15, quotaPeriod: 'month', quotaCalendar: 'jalali', quotaResetDay: 1,
    schedule: null, expiresAt: new Date(2027, 2, 20, 23, 59, 59, 999).getTime(), maxDevices: 0, enabled: true, filter: null
  }, 'the password as typed; no id — the service gives one; the one Total limit mirrored as the single cap; no speed on a PC');
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
  assert.equal(dlg.byKey('f:limit:total:month').value, '20', 'its single cap: a monthly Total limit');
  assert.equal(dlg.byKey('f:act:total:month').value, 'cut', 'the router: cut when used up, unless said otherwise');
  assert.equal(dlg.byKey('f:act:total:month').hidden, false);
  assert.equal(dlg.byKey('f:act:vpn:day').hidden, true, 'no limit there: nothing to act on');
  assert.equal(dlg.byKey('f:routing').children[0].textContent, 'طبقِ مسیریابیِ روتر', 'the router: the plain routing is its own');
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

/* ------------------------------ v1.39: limits by kind, routing, hours, speed, top-up, the 30 days ------------------------------ */

test('the limits’ grid: a cell per kind and period, round-tripped to `limits` in the grid’s order, the first Total mirrored as the single cap; a broken one said under the grid', async () => {
  const h = harness({ data: payload139() });
  await h.load();
  const cells = () => Object.fromEntries(['total', 'vpn', 'direct'].flatMap((k) => ['day', 'month', 'none'].map((p) => [k + ':' + p, h.dialog().byKey('f:limit:' + k + ':' + p).value])));
  const type = (cell, v) => { const n = h.dialog().byKey('f:limit:' + cell); n.value = v; n.dispatch('input'); };
  h.host.byKey('edit:usr-b2').click();
  assert.deepEqual(cells(), { 'total:day': '', 'total:month': '', 'total:none': '', 'vpn:day': '', 'vpn:month': '10', 'vpn:none': '', 'direct:day': '', 'direct:month': '', 'direct:none': '50' });
  const box = h.dialog().byKey('f:limit:vpn:month');
  assert.deepEqual([box.type, box.getAttribute('dir'), box.getAttribute('aria-label')], ['number', 'ltr', 'VPN — ماهانه (GB)']);
  const grid = h.dialog().one('lu-limits');
  assert.equal(grid.getAttribute('role'), 'group');
  assert.deepEqual(grid.byClass('lu-lhead').map((n) => n.textContent), ['', 'روزانه', 'ماهانه', 'یک‌باره']);
  assert.deepEqual(grid.byClass('lu-lkind').map((n) => n.textContent), ['کل', 'VPN', 'مستقیم']);
  assert.equal(h.dialog().byClass('lu-sect')[0].one('lu-sect-title').textContent, 'سقف‌های حجم');
  h.dialog().byKey('f:save').click();
  await flush();
  let saved = h.calls.at(-1)[2];
  assert.deepEqual(saved.limits, [{ kind: 'vpn', period: 'month', gb: 10 }, { kind: 'direct', period: 'none', gb: 50 }], 'saved untouched: the same limits');
  assert.deepEqual([saved.quotaGb, saved.quotaPeriod], [0, 'month'], 'no Total limit: the mirror says none');

  h.host.byKey('edit:usr-b2').click();
  type('direct:none', '');
  type('direct:day', '2');
  type('total:none', '100');
  type('total:day', '0.5');
  type('vpn:month', '12.25');
  type('vpn:day', '0');
  h.dialog().byKey('f:save').click();
  await flush();
  saved = h.calls.at(-1)[2];
  assert.deepEqual(saved.limits, [{ kind: 'total', period: 'day', gb: 0.5 }, { kind: 'total', period: 'none', gb: 100 }, { kind: 'vpn', period: 'month', gb: 12.25 }, { kind: 'direct', period: 'day', gb: 2 }],
    'typed in any order: stored in the grid’s; 0 is none, as an empty box');
  assert.deepEqual([saved.quotaGb, saved.quotaPeriod], [0.5, 'day'], 'the first Total limit, mirrored for an older reader of the same store');

  // a broken cell: said under the grid, the grid's first box focused, nothing sent
  h.host.byKey('edit:usr-b2').click();
  const sent = h.calls.length;
  const err = () => h.dialog().all((n) => n.dataset.err === 'limits')[0].textContent;
  type('vpn:day', '-1');
  h.dialog().byKey('f:save').click();
  await flush();
  assert.equal(h.calls.length, sent);
  assert.equal(err(), 'هر سقف عددی از 0 تا 1000000 گیگابایت است');
  assert.equal(h.document.activeElement, h.dialog().byKey('f:limit:total:day'));
  type('vpn:day', '1');
  assert.equal(err(), '', 'typing clears it');
  type('direct:month', '2000000');
  h.dialog().byKey('f:save').click();
  await flush();
  assert.equal(err(), h.t('lu.err.limits'), 'more than a million GB: refused too');
  assert.equal(h.calls.length, sent);

  // an older user's single cap opens as its Total limit, whatever its period
  const old = harness({ data: payload() });
  await old.load();
  old.host.byKey('edit:usr-b2').click();
  assert.equal(old.dialog().byKey('f:limit:total:day').value, '2');
  old.dialog().byKey('f:close').click();
  old.host.byKey('edit:usr-c3').click();
  assert.ok(['total', 'vpn', 'direct'].every((k) => ['day', 'month', 'none'].every((p) => old.dialog().byKey('f:limit:' + k + ':' + p).value === '')), 'no cap: an empty grid');

  // the service's own refusal of the limits goes under the grid, not as a line of its own
  const refused = harness({ data: payload139(), api: { lanUsersUser: async () => ({ ok: false, error: 'limits', detail: 'gb' }) } });
  await refused.load();
  refused.host.byKey('edit:usr-a1').click();
  refused.dialog().byKey('f:save').click();
  await flush();
  assert.equal(refused.dialog().all((n) => n.dataset.err === 'limits')[0].textContent, refused.t('lu.err.limits'));
  assert.equal(refused.dialog().byClass('lu-formerr').length, 0);
});

test('routing: as the config, Iranian sites direct, or one of the app’s routing profiles from the hook; a gone one said as gone; said in the box; nothing to route for direct or blocked', async () => {
  const profiles = [{ id: 'rp-work', name: 'Work' }, { id: 'rp-kids', name: 'بچه‌ها' }];
  const h = harness({ data: payload139(), profiles });
  await h.load();
  assert.equal(h.user('usr-a1').one('lu-route').textContent, 'مسیریابی: سایت‌های ایرانی مستقیم');
  assert.equal(h.user('usr-b2').one('lu-route').textContent, 'مسیریابی: Work');
  assert.equal(h.user('usr-c3').byClass('lu-route').length, 0, 'the plain one: nothing said');
  h.host.byKey('edit:usr-b2').click();
  const sel = h.dialog().byKey('f:routing');
  assert.equal(sel.tagName, 'SELECT');
  assert.equal(sel.value, 'profile:rp-work');
  assert.equal(sel.disabled, false);
  assert.deepEqual(sel.children.filter((c) => c.tagName === 'OPTION').map((o) => [o.value, o.textContent]), [['', 'همه از کانفیگِ کاربر'], ['bypass-ir', 'سایت‌های ایرانی مستقیم']]);
  const group = sel.children.find((c) => c.tagName === 'OPTGROUP');
  assert.equal(group.label, 'پروفایل‌های مسیریابی');
  assert.deepEqual(group.children.map((o) => [o.value, o.textContent]), [['profile:rp-work', 'Work'], ['profile:rp-kids', 'بچه‌ها']]);
  sel.value = 'profile:rp-kids';
  sel.dispatch('change');
  h.dialog().byKey('f:save').click();
  await flush();
  assert.equal(h.calls.at(-1)[2].routing, 'profile:rp-kids');
  assert.equal(h.user('usr-b2').one('lu-route').textContent, 'مسیریابی: بچه‌ها');

  // blocked or direct: nothing to route — until the config is a config again
  h.host.byKey('edit:usr-c3').click();
  assert.equal(h.dialog().byKey('f:routing').disabled, true, 'blocked');
  const target = h.dialog().byKey('f:target:select');
  target.value = 'srv-2';
  target.dispatch('change');
  assert.equal(h.dialog().byKey('f:routing').disabled, false);
  target.value = 'direct';
  target.dispatch('change');
  assert.equal(h.dialog().byKey('f:routing').disabled, true, 'direct');
  h.dialog().byKey('f:close').click();

  // 'global' is the plain one by another name: shown as it, kept as it
  h.store.data.users[0].routing = 'global';
  await h.load();
  assert.equal(h.user('usr-a1').byClass('lu-route').length, 0);
  h.host.byKey('edit:usr-a1').click();
  assert.equal(h.dialog().byKey('f:routing').value, '');
  h.dialog().byKey('f:save').click();
  await flush();
  assert.equal(h.calls.at(-1)[2].routing, 'global');

  // a profile that is gone (none from the hook): kept, said as gone
  const gone = harness({ data: payload139() });
  await gone.load();
  assert.equal(gone.user('usr-b2').one('lu-route').textContent, 'مسیریابی: ⚠ دیگر وجود ندارد');
  gone.host.byKey('edit:usr-b2').click();
  const gsel = gone.dialog().byKey('f:routing');
  assert.equal(gsel.value, 'profile:rp-work');
  assert.deepEqual(gsel.children.find((c) => c.tagName === 'OPTGROUP').children.map((o) => [o.value, o.textContent]), [['profile:rp-work', '⚠ دیگر وجود ندارد']]);
  gone.dialog().byKey('f:close').click();
  gone.host.byKey('edit:usr-a1').click();
  assert.equal(gone.dialog().byKey('f:routing').children.some((c) => c.tagName === 'OPTGROUP'), false, 'no profiles, none chosen: no group');

  // the router, in English: the plain routing is the router's own
  const r = harness({ lang: 'en', router: true, data: routerPayload({ users: payload139().users, usage: payload139().usage }), profiles });
  await r.load();
  assert.equal(r.user('usr-a1').one('lu-route').textContent, 'Routing: Iranian sites direct');
  r.host.byKey('edit:usr-a1').click();
  assert.deepEqual(r.dialog().byKey('f:routing').children.filter((c) => c.tagName === 'OPTION').map((o) => o.textContent), ['As the router routes', 'Iranian sites direct']);
});

test('allowed hours: any time, or days in the page’s week order (Saturday first in Persian, Monday in English) and a from–to; saved as the model’s schedule; said in the box', async () => {
  const h = harness({ data: payload139() });
  await h.load();
  const line = h.user('usr-b2').one('lu-hours');
  assert.equal(line.textContent, 'ساعتِ مجاز: شنبه تا چهارشنبه 08:00–22:00');
  assert.equal(line.children[0].getAttribute('dir'), 'ltr', 'the hours left to right');
  assert.equal(h.user('usr-c3').one('lu-hours').textContent, 'ساعتِ مجاز: جمعه تمامِ روز', 'the same from and to: the whole day');
  assert.equal(h.user('usr-a1').byClass('lu-hours').length, 0, 'any time: nothing said');

  h.host.byKey('edit:usr-a1').click();
  assert.equal(h.dialog().byKey('f:anytime').checked, true);
  assert.equal(h.dialog().hasKey('f:day:6'), false, 'any time: no days to pick');
  const any = h.dialog().byKey('f:anytime');
  any.checked = false;
  any.dispatch('change');
  assert.equal(h.document.activeElement, h.dialog().byKey('f:anytime'), 'drawn again, the focus where it was');
  const chips = h.dialog().one('lu-days').children;
  assert.deepEqual(chips.map((c) => c.textContent), ['شنبه', 'یکشنبه', 'دوشنبه', 'سه‌شنبه', 'چهارشنبه', 'پنجشنبه', 'جمعه']);
  assert.deepEqual(chips.map((c) => c.dataset.lu), ['f:day:6', 'f:day:0', 'f:day:1', 'f:day:2', 'f:day:3', 'f:day:4', 'f:day:5']);
  assert.ok(chips.every((c) => c.getAttribute('aria-pressed') === 'true'), 'every day to begin with');
  h.dialog().byKey('f:day:4').click();
  h.dialog().byKey('f:day:5').click();
  assert.equal(h.dialog().byKey('f:day:5').getAttribute('aria-pressed'), 'false');
  const from = h.dialog().byKey('f:sched:from');
  assert.deepEqual([from.type, from.getAttribute('dir'), from.value], ['time', 'ltr', '08:00']);
  from.value = '22:30';
  from.dispatch('input');
  const to = h.dialog().byKey('f:sched:to');
  to.value = '06:00';
  to.dispatch('change');
  assert.ok(h.dialog().textContent.includes(h.t('lu.hoursHint')));
  h.dialog().byKey('f:save').click();
  await flush();
  assert.deepEqual(h.calls.at(-1)[2].schedule, { days: [0, 1, 2, 3, 6], from: '22:30', to: '06:00' }, 'overnight; the days by number, 0 = Sunday');

  // no day: said, not sent; back to any time: none
  h.host.byKey('edit:usr-c3').click();
  h.dialog().byKey('f:day:5').click();
  const sent = h.calls.length;
  h.dialog().byKey('f:save').click();
  await flush();
  assert.equal(h.calls.length, sent);
  assert.equal(h.dialog().all((n) => n.dataset.err === 'schedule')[0].textContent, 'دست‌کم یک روز و دو ساعتِ درست انتخاب کنید');
  assert.equal(h.document.activeElement, h.dialog().byKey('f:anytime'));
  const sw = h.dialog().byKey('f:anytime');
  sw.checked = true;
  sw.dispatch('change');
  h.dialog().byKey('f:save').click();
  await flush();
  assert.equal(h.calls.at(-1)[2].schedule, null);

  // in English the week starts on Monday
  const en = harness({ lang: 'en', data: payload139() });
  await en.load();
  assert.equal(en.user('usr-b2').one('lu-hours').textContent, 'Allowed: Mon–Wed, Sat, Sun 08:00–22:00');
  assert.equal(en.user('usr-c3').one('lu-hours').textContent, 'Allowed: Fri all day');
  en.host.byKey('edit:usr-b2').click();
  assert.deepEqual(en.dialog().one('lu-days').children.map((c) => [c.textContent, c.getAttribute('aria-pressed')]),
    [['Mon', 'true'], ['Tue', 'true'], ['Wed', 'true'], ['Thu', 'false'], ['Fri', 'false'], ['Sat', 'true'], ['Sun', 'true']]);
  en.dialog().byKey('f:save').click();
  await flush();
  assert.deepEqual(en.calls.at(-1)[2].schedule, { days: [0, 1, 2, 3, 6], from: '08:00', to: '22:00' }, 'untouched: as it was');
});

test('the box from a v1.39 payload: a bar per limit (amber from 80 %, red over, a top-up counted in its cap), the hold’s pill and when it lifts, the totals with no limit; a hold a tick brings redraws the pill', async () => {
  const h = harness({ data: payload139() });
  await h.load();
  const sara = h.user('usr-a1');
  const rows = sara.byClass('lu-meter');
  assert.deepEqual(rows.map((r) => r.dataset.meter), ['total:month', 'vpn:day'], 'the meters with a limit only, in the grid’s order');
  const [total, vpn] = rows;
  assert.deepEqual(['lu-mlabel', 'lu-mnum', 'lu-mfoot'].map((c) => total.one(c).textContent), ['کل · این ماه', '17.0 GB / 20.0 GB', '3.0 GB مانده، تا ' + persian(MONTH_END, SHORT)]);
  assert.equal(total.one('lu-bar').children[0].className, 'warn');
  assert.equal(total.one('lu-bar').children[0].style.width, '85.0%');
  assert.equal(total.one('lu-bar').getAttribute('aria-valuenow'), '85');
  assert.ok(total.classList.contains('lu-m-near'));
  assert.deepEqual(['lu-mlabel', 'lu-mnum'].map((c) => vpn.one(c).textContent), ['VPN · امروز', '1.6 GB / 1.5 GB'], 'its cap and its top-up');
  assert.equal(vpn.one('lu-bar').children[0].className, 'over');
  assert.equal(vpn.one('lu-bar').children[0].style.width, '100.0%');
  assert.ok(vpn.classList.contains('lu-m-over'));
  assert.equal(vpn.one('lu-mfoot').textContent, 'برمی‌گردد ' + persian(DAY_END, SHORT) + ' · افزوده +512.0 MB');
  assert.equal(vpn.one('lu-extra').getAttribute('dir'), 'ltr');
  // the VPN alone held: «direct only» — the box not dimmed, when it lifts in the pill, what it means as its tooltip
  const pill = sara.one('lu-state');
  assert.ok(pill.classList.contains('lu-s-novpn'));
  assert.equal(pill.textContent, 'فقط مستقیم · برمی‌گردد ' + persian(DAY_END, SHORT));
  assert.equal(pill.title, h.t('lu.stateHint.novpn'));
  assert.equal(sara.classList.contains('lu-dim'), false);
  // outside the hours: all held until the window opens — today, so its time
  const reza = h.user('usr-b2');
  assert.equal(reza.one('lu-state').textContent, 'خارج از ساعت · برمی‌گردد 18:00');
  assert.ok(reza.one('lu-state').classList.contains('lu-s-schedule'));
  assert.ok(reza.classList.contains('lu-dim'));
  assert.deepEqual(reza.byClass('lu-meter').map((r) => r.dataset.meter), ['vpn:month', 'direct:none']);
  assert.deepEqual(['lu-mlabel', 'lu-mfoot'].map((c) => reza.byClass('lu-meter')[1].one(c).textContent), ['مستقیم · یک‌باره', '45.0 GB مانده'], 'a one-off limit: no period to wait for');
  // no limit: today's and this month's VPN and direct
  const guest = h.user('usr-c3');
  assert.equal(guest.byClass('lu-bar').length, 0);
  assert.deepEqual(guest.byClass('lu-tot').map((l) => [l.dataset.period, l.one('lu-totp').textContent, ...l.byClass('lu-totk').map((k) => k.textContent)]), [
    ['day', 'امروز', 'VPN 120.0 MB', 'مستقیم 40.0 MB'], ['month', 'این ماه', 'VPN 2.1 GB', 'مستقیم 300.0 MB']]);
  assert.ok(guest.byClass('lu-totk').every((k) => k.children[0].getAttribute('dir') === 'ltr'));
  assert.equal(guest.one('lu-state').textContent, 'فعال');
  // a tick that brings a hold: the pill drawn again — the direct routes alone held: «VPN only»
  h.page.tick({ usage: { 'usr-c3': Object.assign({}, h.store.data.usage['usr-c3'], { hold: 'direct', why: 'direct', holdUntil: MONTH_END }) } });
  assert.equal(h.user('usr-c3').one('lu-state').textContent, 'فقط VPN · برمی‌گردد ' + persian(MONTH_END, SHORT));
  assert.equal(h.user('usr-c3').classList.contains('lu-dim'), false);
  h.page.tick({ usage: { 'usr-c3': Object.assign({}, h.store.data.usage['usr-c3'], { hold: 'all', why: 'total', holdUntil: 0 }) } });
  assert.equal(h.user('usr-c3').one('lu-state').textContent, 'به سقف رسیده', 'a Total that never renews: no until');

  const en = harness({ lang: 'en', data: payload139() });
  await en.load();
  assert.equal(en.user('usr-a1').one('lu-state').textContent, 'Direct only · back ' + english(DAY_END, SHORT));
  assert.equal(en.user('usr-b2').one('lu-state').textContent, 'Outside hours · back 18:00');
  assert.equal(en.user('usr-a1').byClass('lu-mfoot')[0].textContent, '3.0 GB left, until ' + english(MONTH_END, SHORT));
  assert.deepEqual(en.user('usr-c3').byClass('lu-tot').map((l) => l.textContent), ['TodayVPN 120.0 MBDirect 40.0 MB', 'This monthVPN 2.1 GBDirect 300.0 MB']);
});

test('top up: a small dialog of the user’s limits (the one over first) and GB → lanusers:user topUp; reset usage after asking → resetUsage; each answer drawn', async () => {
  const h = harness({ data: payload139() });
  await h.load();
  const box = () => h.document.body.children.find((c) => c.id === 'luTopUp') || null;
  const btn = h.host.byKey('topup:usr-a1');
  assert.equal(btn.textContent, '+ حجم');
  assert.equal(btn.getAttribute('aria-label'), '+ حجم — سارا');
  btn.focus();
  btn.click();
  assert.ok(box());
  assert.equal(box().one('lu-modal').getAttribute('role'), 'dialog');
  assert.equal(box().one('modal-title').textContent, 'افزودنِ حجم برای «سارا»');
  const which = box().byKey('t:limit');
  assert.deepEqual(which.children.map((o) => [o.value, o.textContent]), [['total:month', 'کل · ماهانه — 20 GB'], ['vpn:day', 'VPN · روزانه — 1 GB']]);
  assert.equal(which.value, 'vpn:day', 'the one over its cap first');
  assert.equal(h.document.activeElement, box().byKey('t:gb'));
  assert.ok(box().textContent.includes(h.t('lu.topUpHint')));
  // nothing typed: said, not sent
  box().byKey('t:save').click();
  await flush();
  assert.equal(h.calls.filter((c) => c[1] === 'topUp').length, 0);
  assert.equal(box().one('lu-err').textContent, 'مقداری بیشتر از 0 بنویسید (GB)');
  const gb = box().byKey('t:gb');
  gb.value = '0.5';
  gb.dispatch('input');
  assert.equal(box().one('lu-err').textContent, '');
  box().byKey('t:save').click();
  await flush();
  assert.deepEqual(h.calls.at(-1), ['user', 'topUp', { id: 'usr-a1' }, { kind: 'vpn', period: 'day', gb: 0.5 }]);
  assert.equal(box(), null, 'closed');
  assert.deepEqual(h.toasts.at(-1), ['0.5 GB برای «سارا» اضافه شد', 'ok']);
  const vpnRow = () => h.user('usr-a1').all((n) => n.dataset.meter === 'vpn:day')[0];
  assert.equal(vpnRow().one('lu-mnum').textContent, '1.6 GB / 2.0 GB', 'the answer drawn: the top-up in its cap');
  assert.equal(h.document.activeElement, h.host.byKey('topup:usr-a1'), 'the focus back on the button');
  // another limit, picked, Enter adds; Escape closes
  h.page.topUp('usr-a1');
  const pick = box().byKey('t:limit');
  pick.value = 'total:month';
  pick.dispatch('change');
  box().byKey('t:gb').value = '2';
  box().byKey('t:gb').dispatch('keydown', { key: 'Enter' });
  await flush();
  assert.deepEqual(h.calls.at(-1), ['user', 'topUp', { id: 'usr-a1' }, { kind: 'total', period: 'month', gb: 2 }]);
  h.page.topUp('usr-a1');
  box().dispatch('keydown', { key: 'Escape' });
  assert.equal(box(), null);
  assert.equal(h.page.topUp('usr-c3'), false, 'no limit: nothing to top up');

  // reset: asks first; no — nothing sent
  h.state.confirm = false;
  h.host.byKey('reset:usr-a1').click();
  await flush();
  assert.equal(h.asked.at(-1), 'مصرفِ این دورهٔ «سارا» صفر شود؟ حجم‌های افزوده هم پاک می‌شوند؛ نمودارِ 30 روزه می‌ماند.');
  assert.equal(h.calls.filter((c) => c[1] === 'resetUsage').length, 0);
  h.state.confirm = true;
  h.host.byKey('reset:usr-a1').click();
  await flush();
  assert.deepEqual(h.calls.at(-1), ['user', 'resetUsage', { id: 'usr-a1' }]);
  assert.equal(h.user('usr-a1').all((n) => n.dataset.meter === 'total:month')[0].one('lu-mnum').textContent, '0 B / 20.0 GB');
  assert.deepEqual(h.toasts.at(-1), ['مصرفِ «سارا» صفر شد', 'ok']);
  // a refused top-up: said, and the dialog stays for another try
  const no = harness({ data: payload139(), api: { lanUsersUser: async () => ({ ok: false, error: 'notFound' }) } });
  await no.load();
  no.page.topUp('usr-a1');
  const nb = no.document.body.children.find((c) => c.id === 'luTopUp');
  nb.byKey('t:gb').value = '1';
  nb.byKey('t:save').click();
  await flush();
  assert.equal(no.toasts.at(-1)[1], 'err');
  assert.ok(no.document.body.children.some((c) => c.id === 'luTopUp'));
});

test('the 30-day chart: an SVG drawn node by node — a bar a day, VPN under direct, each with its numbers in its title; time left to right up to today; hidden with nothing to show', async () => {
  const midnight = (ago) => { const n = new Date(); return new Date(n.getFullYear(), n.getMonth(), n.getDate() - ago).getTime(); };
  const data = payload139();
  data.usage['usr-a1'].history = [
    { day: dayKey(40), vpn: GIB, direct: 0 },
    { day: dayKey(29), vpn: 2 * GIB, direct: GIB },
    { day: dayKey(3), vpn: 0, direct: 0 },
    { day: dayKey(1), vpn: 0.5 * GIB, direct: 0.5 * GIB },
    { day: dayKey(0), vpn: 3 * GIB, direct: 0 }
  ];
  data.usage['usr-b2'].history = [{ day: dayKey(0), vpn: 0, direct: 0 }];
  const h = harness({ data });
  await h.load();
  const hist = h.user('usr-a1').one('lu-hist');
  assert.equal(hist.hidden, false);
  assert.equal(hist.parentNode, h.user('usr-a1'), 'under the box’s controls, its whole width');
  assert.equal(hist.one('lu-ctitle').textContent, '30 روزِ گذشته');
  assert.deepEqual(hist.byClass('lu-ckey').map((k) => k.textContent), ['VPN 5.5 GB', 'مستقیم 1.5 GB'], 'the 30 days’ sums by the swatches');
  const svg = hist.children.find((c) => c.tagName === 'svg');
  assert.equal(svg.namespaceURI, 'http://www.w3.org/2000/svg');
  assert.deepEqual(['class', 'viewBox', 'preserveAspectRatio', 'role'].map((a) => svg.getAttribute(a)), ['lu-chart', '0 0 300 40', 'none', 'img']);
  assert.equal(svg.getAttribute('aria-label'), 'مصرفِ 30 روزِ گذشته: VPN 5.5 GB، مستقیم 1.5 GB');
  assert.equal(svg.children[0].tagName, 'line');
  assert.equal(svg.children[0].getAttribute('class'), 'lu-cbase');
  const bars = svg.children.filter((c) => c.tagName === 'g');
  assert.deepEqual(bars.map((g) => g.getAttribute('data-day')), [dayKey(29), dayKey(1), dayKey(0)], 'older than 30 days, or nothing that day: no bar');
  const rects = (g) => g.children.filter((c) => c.tagName === 'rect').map((r) => [r.getAttribute('class'), r.getAttribute('x'), r.getAttribute('y'), r.getAttribute('height')]);
  assert.deepEqual(rects(bars[0]), [['lu-chit', '0', '0', '40'], ['lu-cvpn', '1.5', '13.67', '25.33'], ['lu-cdirect', '1.5', '1', '12.67']], '29 days ago: the first slot, VPN under direct');
  assert.deepEqual(rects(bars[1]), [['lu-chit', '280', '0', '40'], ['lu-cvpn', '281.5', '32.67', '6.33'], ['lu-cdirect', '281.5', '26.33', '6.33']]);
  assert.deepEqual(rects(bars[2]), [['lu-chit', '290', '0', '40'], ['lu-cvpn', '291.5', '1', '38']], 'today: the last slot');
  assert.ok(bars.every((g) => g.getAttribute('class') === 'lu-cbar'));
  const title = bars[2].children[0];
  assert.equal(title.tagName, 'title');
  assert.equal(title.textContent, persian(midnight(0), SHORT) + ' — VPN 3.0 GB · مستقیم 0 B');
  assert.equal(bars[0].children[0].textContent, persian(midnight(29), SHORT) + ' — VPN 2.0 GB · مستقیم 1.0 GB');
  // nothing in it, or no history at all: no chart
  assert.equal(h.user('usr-b2').one('lu-hist').hidden, true);
  assert.equal(h.user('usr-c3').one('lu-hist').hidden, true);
  assert.equal(h.user('usr-c3').one('lu-hist').children.length, 0);
  // a tick brings today's bytes: drawn in place
  const c3 = h.user('usr-c3');
  h.page.tick({ usage: { 'usr-c3': Object.assign({}, h.store.data.usage['usr-c3'], { history: [{ day: dayKey(0), vpn: GIB, direct: GIB }] }) } });
  assert.equal(h.user('usr-c3'), c3, 'in place');
  assert.equal(c3.one('lu-hist').hidden, false);
  assert.equal(c3.one('lu-hist').children.find((c) => c.tagName === 'svg').children.filter((c) => c.tagName === 'g').length, 1);
  // the service's clock a day ahead of this browser's: its last day is the last slot
  const ahead = payload139();
  ahead.usage['usr-a1'].history = [{ day: dayKey(0), vpn: GIB, direct: 0 }, { day: dayKey(-1), vpn: GIB, direct: 0 }];
  const a = harness({ lang: 'en', data: ahead });
  await a.load();
  const asvg = a.user('usr-a1').one('lu-hist').children.find((c) => c.tagName === 'svg');
  assert.deepEqual(asvg.children.filter((c) => c.tagName === 'g').map((g) => g.children[1].getAttribute('x')), ['280', '290']);
  assert.equal(a.user('usr-a1').one('lu-ctitle').textContent, 'Last 30 days');
  assert.equal(asvg.getAttribute('aria-label'), 'Usage over the last 30 days: VPN 2.0 GB, direct 0 B');
});

test('speed, on the router: a base download and upload in Mbps stored as kbps, up to four peak-hour windows, and per limit cut or slow to a speed; the speed now in the box; on a PC one line that it is the router’s', async () => {
  const data = routerPayload({ users: clone(payload139().users), usage: clone(payload139().usage) });
  Object.assign(data.users[0], {
    speed: { down: 2000, up: 1000 },
    speedHours: [{ days: [4, 5], from: '18:00', to: '23:00', down: 1500 }],
    limits: [{ kind: 'total', period: 'month', gb: 20 }, { kind: 'vpn', period: 'day', gb: 1, action: 'slow', down: 512, up: 256 }]
  });
  data.usage['usr-a1'].speed = { down: 512, up: 256, why: ['after:vpn:day'] };
  data.usage['usr-b2'].speed = { down: 1500, why: ['base', 'hours'] };
  const h = harness({ router: true, platform: 'linux', data });
  await h.load();
  // the box: the speed they get now, and why; a 'slow' limit over its cap is slowed, not cut
  const sp = h.user('usr-a1').one('lu-speed');
  assert.equal(sp.hidden, false);
  assert.equal(sp.one('lu-speed-k').textContent, 'سرعت');
  assert.equal(sp.one('lu-speed-rate').textContent, '↓ 512 kbps ↑ 256 kbps');
  assert.equal(sp.one('lu-speed-rate').getAttribute('dir'), 'ltr');
  assert.ok(sp.textContent.endsWith(' · بعد از 1 GB VPN امروز'), sp.textContent);
  assert.equal(h.user('usr-a1').all((n) => n.dataset.meter === 'vpn:day')[0].one('lu-mfoot').textContent, 'سرعتِ کم تا ' + persian(DAY_END, SHORT) + ' · افزوده +512.0 MB');
  assert.equal(h.user('usr-b2').one('lu-speed').textContent, 'سرعت↓ 1.5 Mbps · همیشه · ساعتِ اوج');
  assert.equal(h.user('usr-c3').one('lu-speed').hidden, true, 'no limit on it: nothing said');

  // the dialog's speed: the base in Mbps, the windows, the limits' actions
  h.host.byKey('edit:usr-a1').click();
  const d = () => h.dialog();
  const type = (key, v) => { const n = d().byKey(key); n.value = v; n.dispatch('input'); };
  const choose = (key, v) => { const n = d().byKey(key); n.value = v; n.dispatch('change'); };
  const err = (k) => d().all((n) => n.dataset.err === k)[0].textContent;
  assert.deepEqual([d().byKey('f:speedDown').value, d().byKey('f:speedUp').value, d().byKey('f:speedDown').placeholder], ['2', '1', 'بدون محدودیت']);
  assert.equal(d().byKey('f:speedDown').getAttribute('aria-label'), 'دانلود (Mbps)');
  assert.equal(d().byClass('lu-win').length, 1);
  assert.deepEqual([d().byKey('f:win:0:down').value, d().byKey('f:win:0:up').value, d().byKey('f:win:0:from').value, d().byKey('f:win:0:to').value], ['1.5', '', '18:00', '23:00']);
  assert.deepEqual(d().one('lu-win').one('lu-days').children.filter((c) => c.getAttribute('aria-pressed') === 'true').map((c) => c.dataset.lu), ['f:win:0:day:4', 'f:win:0:day:5']);
  assert.equal(d().byKey('f:act:vpn:day').value, 'slow');
  assert.deepEqual(d().byKey('f:act:vpn:day').children.map((o) => [o.value, o.textContent]), [['cut', 'قطع'], ['slow', 'کندتر']]);
  assert.deepEqual([d().byKey('f:slow:down:vpn:day').value, d().byKey('f:slow:up:vpn:day').value], ['0.512', '0.256']);
  assert.equal(d().byKey('f:slow:down:vpn:day').parentNode.parentNode.hidden, false, 'its two speeds, each with its arrow');
  assert.equal(d().byKey('f:act:total:month').value, 'cut');
  assert.equal(d().byKey('f:slow:down:total:month').parentNode.parentNode.hidden, true, 'cut: no speed to type');
  assert.equal(d().byKey('f:act:direct:day').hidden, true, 'no limit there: nothing to act on');
  assert.ok(d().textContent.includes(h.t('lu.limitsHintRouter')));

  // a limit typed: its action shows; slowed to 1 Mbps down
  type('f:limit:direct:day', '3');
  assert.equal(d().byKey('f:act:direct:day').hidden, false);
  choose('f:act:direct:day', 'slow');
  assert.equal(d().byKey('f:slow:down:direct:day').parentNode.parentNode.hidden, false);
  type('f:slow:down:direct:day', '1');
  // slow with no speed: said under the grid
  type('f:limit:total:none', '5');
  choose('f:act:total:none', 'slow');
  d().byKey('f:save').click();
  await flush();
  assert.equal(err('limits'), 'برای «کندتر» دست‌کم سرعتِ دانلود یا آپلود را بنویسید (Mbps)');
  choose('f:act:total:none', 'cut');
  // the base: 10 Mbps down, the upload unlimited; windows up to four
  type('f:speedDown', '10');
  type('f:speedUp', '');
  d().byKey('f:winAdd').click();
  assert.equal(h.document.activeElement, d().byKey('f:win:1:down'), 'a new window: its download first');
  type('f:win:1:down', '0.5');
  type('f:win:1:up', '0.25');
  d().byKey('f:winAdd').click();
  d().byKey('f:winAdd').click();
  assert.equal(d().byClass('lu-win').length, 4);
  assert.equal(d().byKey('f:winAdd').disabled, true, 'four at most');
  d().byKey('f:save').click();
  await flush();
  assert.equal(err('speed'), h.t('lu.err.speed'), 'a window with no speed');
  assert.equal(h.document.activeElement, d().byKey('f:speedDown'));
  d().byKey('f:win:3:remove').click();
  d().byKey('f:win:2:remove').click();
  assert.equal(d().byClass('lu-win').length, 2);
  assert.equal(d().byKey('f:winAdd').disabled, false);
  d().byKey('f:save').click();
  await flush();
  const saved = h.calls.at(-1)[2];
  assert.deepEqual(saved.speed, { down: 10000 }, 'kbps; the unlimited direction left out');
  assert.deepEqual(saved.speedHours, [{ days: [4, 5], from: '18:00', to: '23:00', down: 1500 }, { days: [0, 1, 2, 3, 4, 5, 6], from: '18:00', to: '23:00', down: 500, up: 250 }]);
  assert.deepEqual(saved.limits, [{ kind: 'total', period: 'month', gb: 20 }, { kind: 'total', period: 'none', gb: 5 },
    { kind: 'vpn', period: 'day', gb: 1, action: 'slow', down: 512, up: 256 }, { kind: 'direct', period: 'day', gb: 3, action: 'slow', down: 1000 }]);
  // no speed at all: null, no windows
  h.host.byKey('edit:usr-a1').click();
  type('f:speedDown', '');
  d().byKey('f:win:1:remove').click();
  d().byKey('f:win:0:remove').click();
  assert.equal(h.document.activeElement, d().byKey('f:winAdd'));
  d().byKey('f:save').click();
  await flush();
  assert.deepEqual([h.calls.at(-1)[2].speed, h.calls.at(-1)[2].speedHours], [null, []]);

  // English: the contract's own line
  const enData = clone(data);
  enData.users[0].limits = [{ kind: 'total', period: 'day', gb: 2, action: 'slow', down: 2000, up: 1000 }];
  enData.usage['usr-a1'].speed = { down: 2000, up: 1000, why: ['after:total:day'] };
  const en = harness({ lang: 'en', router: true, platform: 'linux', data: enData });
  await en.load();
  assert.equal(en.user('usr-a1').one('lu-speed').textContent, 'Speed↓ 2 Mbps ↑ 1 Mbps · after 2 GB today');

  // a PC: the one line, and a speed the record has (imported) left as it is
  const pc = clone(payload139());
  pc.users[0].speed = { down: 2000 };
  const desk = harness({ data: pc });
  await desk.load();
  desk.host.byKey('edit:usr-a1').click();
  assert.equal(desk.dialog().one('lu-speednote').textContent, 'محدودیتِ سرعت فقط روی روتر است — هستهٔ Xray سرعتِ هر کاربر را جدا محدود نمی‌کند.');
  assert.equal(desk.dialog().hasKey('f:speedDown') || desk.dialog().hasKey('f:winAdd') || desk.dialog().hasKey('f:act:total:month'), false);
  desk.dialog().byKey('f:save').click();
  await flush();
  assert.deepEqual(desk.calls.at(-1)[2].speed, { down: 2000 });
  assert.equal('speedHours' in desk.calls.at(-1)[2], false);
});

/* ------------------------------ the router ------------------------------ */

test('the router, in English: transparent mode, what an unassigned device gets, the devices online first with IP and MAC left to right', async () => {
  const h = harness({ lang: 'en', router: true, platform: 'linux', connected: true });
  await h.load();
  const { host, t } = h;
  assert.equal(host.byClass('lu-hotspot').length, 0, 'no Windows note on the router');
  const titles = host.one('lu-settings').byClass('switch-title').map((n) => n.textContent);
  assert.deepEqual(titles, ['Proxy accounts', 'Transparent mode', 'Top-up requests from the status page', 'Smooth limits'], 'v1.40: the status page’s requests and the shaping, under the transparent mode');
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
  const q = h.host.byKey('reset:usr-a1');
  h.page.tick({ live: { 'usr-a1': { up: 1024, down: 2097152 } }, usage: { 'usr-a1': Object.assign({}, h.store.data.usage['usr-a1'], { bytes: 19 * GIB }) } });
  assert.equal(h.user('usr-a1'), box, 'in place, not redrawn');
  assert.equal(h.host.byKey('reset:usr-a1'), q, 'its buttons too');
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
  for (const s of ['on', 'off', 'expired', 'over', 'novpn', 'nodirect', 'schedule']) keys.add('lu.state.' + s);
  for (const s of ['novpn', 'nodirect', 'schedule']) keys.add('lu.stateHint.' + s);
  for (const p of ['login', 'allow', 'block']) { keys.add('lu.unassigned.' + p); keys.add('lu.unassignedHint.' + p); }
  for (const k of ['username', 'usernameTaken', 'password', 'quota', 'maxDevices', 'limits', 'slow', 'schedule', 'speed', 'routing', 'topUp']) keys.add('lu.err.' + k);
  // the names the page puts together: a limit's kind and period, the month's calendar, a weekday, an action, a routing
  for (const k of ['total', 'vpn', 'direct']) keys.add('lu.kind.' + k);
  for (const p of ['day', 'month', 'none']) keys.add('lu.col.' + p);
  for (const p of ['day', 'month']) keys.add('lu.tot.' + p);
  for (const c of ['jalali', 'gregorian']) keys.add('lu.cal.' + c);
  for (let d = 0; d < 7; d++) keys.add('lu.wd.' + d);
  for (const a of ['cut', 'slow']) keys.add('lu.act.' + a);
  for (const r of ['all', 'router']) keys.add('lu.route.' + r);
  for (const k of ['lu.oneOff', 'lu.today', 'lu.thisMonth', 'lu.limitsHint', 'lu.limitsHintRouter']) keys.add(k);
  for (const k of ['nav.users', 'set.lanUsers', 'lu.title']) keys.add(k);
  // v1.40: the tabs, the filter's categories, the priorities, the shaper's modes, the refusals' details
  for (const k of ['users', 'vouchers']) keys.add('lu.tab.' + k);
  for (const c of ['adult', 'social', 'games', 'ads']) keys.add('lu.flt.' + c);
  for (const k of ['lu.flt.noGeo', 'lu.flt.safeGroup', 'lu.flt.ex.domain', 'lu.flt.ex.full', 'lu.flt.ex.keyword']) keys.add(k);
  for (const w of ['down', 'up', 'both']) keys.add('lu.shp.which.' + w);
  for (const p of ['high', 'normal', 'low']) keys.add('lu.prio.' + p);
  for (const m of ['tc', 'police', 'off']) keys.add('lu.shp.mode.' + m);
  for (const k of ['lu.prioHint', 'lu.prioNoLine', 'lu.shp.unknown', 'lu.shp.down', 'lu.shp.up', 'lu.err.backup', 'lu.err.filter', 'lu.err.priority', 'lu.err.portal', 'lu.err.shaping']) keys.add(k);
  for (const d of ['kind', 'version', 'shape']) keys.add('lu.err.backup.' + d);
  for (const d of ['category', 'domain', 'domains']) keys.add('lu.err.filter.' + d);
  assert.ok(keys.size > 80, `expected the whole page, found ${keys.size} keys`);
  const bad = [...keys].filter((k) => (I18N.split(`'${k}':`).length - 1) !== 2).sort();
  assert.deepEqual(bad, [], 'not defined exactly once in each of fa and en');
  for (const anchor of I18N.split('\n').map((l, i) => [l, i]).filter(([l]) => l.includes("'mi.note':"))) {
    const next = I18N.split('\n').slice(anchor[1] + 1, anchor[1] + 4).join('\n');
    assert.match(next, /users on this network \(lanUsers\.js\)[\s\S]*'nav\.users':/, 'the block sits right after mi.note');
  }
  assert.doesNotMatch(I18N.slice(I18N.indexOf("'nav.users'"), I18N.indexOf("'lu.dev.blocked'")), /'[^'\n]*[a-z]'[a-z][^'\n]*'/i, 'no ASCII apostrophe inside a string');
  // v1.40's block, right after lu.dev.blocked in both languages
  for (const at of [I18N.indexOf("'lu.dev.blocked'"), I18N.lastIndexOf("'lu.dev.blocked'")]) {
    const block = I18N.slice(at, I18N.indexOf("'lu.dev.rememberedHint'", at));
    assert.match(block, /^'lu\.dev\.blocked': '[^'\n]*',\n\s*\/\* v1\.40: /, 'right after lu.dev.blocked');
    assert.doesNotMatch(block, /'[^'\n]*[a-z]'[a-z][^'\n]*'/i, 'no ASCII apostrophe inside a string');
  }
});

test('every class the page builds is styled in settings.css — tokens only, logical properties only', () => {
  const css = R('src', 'renderer', 'settings.css');
  const cls = new Set();
  for (const m of PAGE.matchAll(/(?:el|button)\('[a-z]+', '([^']+)'/g)) m[1].split(/\s+/).forEach((c) => cls.add(c));
  for (const c of ['lu-s-on', 'lu-s-off', 'lu-s-expired', 'lu-s-over', 'lu-dim', 'lu-gone', 'lu-bad', 'lu-hotspot', 'lu-date', 'lu-dcell', 'lu-block', 'lu-use']) cls.add(c);
  // v1.39: the new states, a meter near or over, the chart's swatches and its SVG nodes (set by setAttribute), the month's calendar
  for (const c of ['lu-s-novpn', 'lu-s-nodirect', 'lu-s-schedule', 'lu-m-near', 'lu-m-over', 'lu-csw-vpn', 'lu-csw-direct',
    'lu-chart', 'lu-cbase', 'lu-cbar', 'lu-chit', 'lu-cvpn', 'lu-cdirect', 'lu-cal']) cls.add(c);
  // v1.40: the classes set beside a base one (the shaper's dot, the days left, the tags, the card's sheet, a tab, a category)
  for (const c of ['lu-dot-warn', 'lu-soon', 'lu-chip-filter', 'lu-chip-prio', 'lu-prio-high', 'lu-prio-low', 'lu-chip-rem', 'lu-pcard', 'lu-pc-qr',
    'lu-pc-small', 'lu-tab', 'lu-cat', 'lu-remrow', 'lu-cardm', 'lu-restore']) cls.add(c);
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
  assert.match(app, /routingProfiles: \(\) => \(Array\.isArray\(state\.profiles\) \? state\.profiles : \[\]\)\.map\(p => \(\{ id: p\.id, name: p\.name \}\)\),/, 'and its routing profiles');
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

/* ------------------------------ v1.40: tabs, kit, requests, filter, priority, remember, card, shaping, backup ------------------------------ */

const TODAY_10 = (() => { const n = new Date(); return new Date(n.getFullYear(), n.getMonth(), n.getDate(), 10, 0).getTime(); })();
const REMEMBERED_AT = new Date(2026, 9, 20, 9, 30).getTime();

/**
 * A v1.40 router payload (contract §1–§3): Sara with a content filter, a high
 * priority, "remember devices" and one device a sign-in gave her; Reza low,
 * with a top-up request; two vouchers (one with a device of its own); the
 * status page's note and contact, the line's speed, the shaper policing for
 * want of tc (its packages missing); Sara's 12 months.
 */
function payload140(over = {}) {
  const base = routerPayload({ users: clone(payload139().users), usage: clone(payload139().usage) });
  Object.assign(base.users[0], { filter: { block: ['adult', 'social'], safeSearch: true, domains: ['example.com', 'keyword:casino'] }, priority: 'high', remember: true });
  Object.assign(base.users[1], { priority: 'low' });
  base.users.push(
    { id: 'usr-v1', username: 'ABCD-EFGH', password: 'ABCD-EFGH', name: 'Cafe #1', target: '', routing: '', schedule: null, limits: [{ kind: 'total', period: 'none', gb: 1, action: 'cut' }],
      quotaGb: 1, quotaPeriod: 'none', expiresAt: 0, maxDevices: 1, enabled: true, voucher: { batch: 'vb-1', hours: 2, activatedAt: 0 } },
    { id: 'usr-v2', username: 'JKMN-PQRS', password: 'JKMN-PQRS', name: 'Cafe #2', target: '', routing: '', schedule: null, limits: [],
      quotaGb: 0, quotaPeriod: 'month', expiresAt: Date.now() + 3600000, maxDevices: 1, enabled: true, voucher: { batch: 'vb-1', hours: 2, activatedAt: Date.now() - 3600000 } });
  base.usage['usr-b2'].request = { at: TODAY_10 };
  base.usage['usr-a1'].months = [
    { key: '2026-09', from: new Date(2026, 8, 1).getTime(), to: new Date(2026, 9, 1).getTime(), vpn: 9 * GIB, direct: GIB },
    { key: '2026-10', from: new Date(2026, 9, 1).getTime(), to: new Date(2026, 10, 1).getTime(), vpn: 12 * GIB, direct: 2 * GIB }
  ];
  base.devices.push({ mac: 'aa:bb:cc:00:00:04', name: '', userId: 'usr-a1', blocked: false, remembered: true, at: REMEMBERED_AT },
    { mac: 'aa:bb:cc:00:00:05', name: 'Cafe phone', userId: 'usr-v2', blocked: false });
  base.config.portal = { note: 'Top-ups on Fridays', contact: '0912 000 0000', requests: true };
  base.config.shaping = { down: 50000, up: 10000, smooth: true };
  base.shaper = { mode: 'police', missing: ['tc-tiny', 'kmod-sched-core', 'kmod-ifb'], line: { down: 50000, up: 10000 } };
  base.portal = { url: 'http://192.168.1.1:30822/', name: 'login.lan', nameUrl: 'http://login.lan:30822/' };
  return Object.assign(base, over);
}
/** The same people on a Windows PC: no router, no shaper, no sign-in page. */
const desktop140 = (over = {}) => payload140(Object.assign({ platform: 'win32', shaper: undefined, portal: null }, over));
const quiet = { console: { error() {}, log() {}, warn() {} } };

test('v1.40 tabs: Users | Vouchers — the Users tab lists no voucher, the Vouchers tab mounts luVouchers.js’s panel on the kit; arrows move between them', async () => {
  const seen = [];
  const LuVouchers = { panel: (kit) => { seen.push(kit); return kit.el('div', 'vx-panel', 'vouchers: ' + kit.vouchers().length); } };
  const h = harness({ lang: 'en', router: true, platform: 'linux', data: payload140(), extras: { LuVouchers } });
  await h.load();
  const tabs = h.host.one('lu-tabs');
  assert.equal(tabs.getAttribute('role'), 'tablist');
  assert.equal(tabs.getAttribute('aria-label'), 'Users page sections');
  assert.deepEqual(tabs.children.map((b) => [b.dataset.lu, b.getAttribute('role'), b.getAttribute('aria-selected'), b.tabIndex, b.textContent]), [
    ['tab:users', 'tab', 'true', 0, 'Users 3 🔔 1'], ['tab:vouchers', 'tab', 'false', -1, 'Vouchers 2']], 'how many each, and the requests waiting');
  assert.equal(h.host.one('lu-tabreq').title, 'top-up requests: 1');
  const pane = h.host.one('lu-pane');
  assert.deepEqual([pane.id, pane.getAttribute('role'), pane.getAttribute('aria-labelledby')], ['luPane', 'tabpanel', 'luTab-users']);
  assert.deepEqual(h.host.byClass('lu-user').map((b) => b.dataset.user), ['usr-a1', 'usr-b2', 'usr-c3'], 'no voucher among the users');
  assert.equal(h.host.one('lu-users').one('lu-meta').textContent, '3 users · top-up requests: 1');
  assert.equal(seen.length, 0, 'the panel is built on its own tab alone');

  h.host.byKey('tab:vouchers').click();
  assert.equal(seen.length, 1);
  assert.deepEqual(['lu-users', 'lu-settings', 'lu-devices'].map((c) => h.host.byClass(c).length), [0, 0, 0], 'the Vouchers tab: its panel alone');
  assert.equal(h.host.one('lu-vpane').one('vx-panel').textContent, 'vouchers: 2');
  assert.equal(h.host.byKey('tab:vouchers').getAttribute('aria-selected'), 'true');
  assert.equal(h.host.one('lu-pane').getAttribute('aria-labelledby'), 'luTab-vouchers');
  assert.equal(h.document.activeElement, h.host.byKey('tab:vouchers'), 'the focus on the tab');
  assert.ok(h.host.hasKey('backup') && h.host.hasKey('restore'), 'the module’s files on both tabs');
  h.host.byKey('tab:vouchers').dispatch('keydown', { key: 'ArrowLeft' });
  assert.equal(h.host.byClass('lu-users').length, 1, 'an arrow: the other tab');
  assert.equal(h.document.activeElement, h.host.byKey('tab:users'));

  // without luVouchers.js: no tab bar, the page as it was (still without the vouchers)
  const plain = harness({ lang: 'en', router: true, platform: 'linux', data: payload140() });
  await plain.load();
  assert.equal(plain.host.byClass('lu-tabs').length, 0);
  assert.equal(plain.host.byClass('lu-pane').length, 0);
  assert.equal(plain.host.byClass('lu-user').length, 3);
  assert.ok(plain.host.hasKey('backup') && plain.host.hasKey('restore'));
  assert.equal(plain.host.children[1].classList.contains('lu-toolbar'), true, 'the bar right under the intro');
});

test('v1.40 the kit (window.LanUsersKit): the contract’s pieces, the users split in two, invoke draws an answer and hands a refusal back as it came', async () => {
  const h = harness({ lang: 'en', router: true, platform: 'linux', data: payload140() });
  await h.load();
  const kit = h.window.LanUsersKit;
  for (const k of ['t', 'el', 'button', 'select', 'field', 'ltr', 'fmtBytes', 'invoke', 'refresh', 'data', 'users', 'vouchers', 'portal', 'switchEl']) assert.equal(typeof kit[k], 'function', k);
  for (const k of ['printSheet', 'qrImage', 'copy', 'toast', 'confirm', 'targetPicker', 'routingPicker', 'withUser', 'errText', 'isVoucher']) assert.equal(typeof kit[k], 'function', k);
  assert.deepEqual(kit.users().map((u) => u.id), ['usr-a1', 'usr-b2', 'usr-c3']);
  assert.deepEqual(kit.vouchers().map((u) => u.id), ['usr-v1', 'usr-v2']);
  assert.deepEqual(clone(kit.portal()), { url: 'http://192.168.1.1:30822/', nameUrl: 'http://login.lan:30822/' });
  assert.equal(kit.fmtBytes(1536), '1.5 KB');
  assert.equal(kit.t('lu.tab.vouchers'), 'Vouchers');
  assert.equal(kit.data().config.portal.contact, '0912 000 0000');
  assert.equal(kit.withUser('http://x:1/', 'sara'), 'http://x:1/?u=sara');
  assert.equal(kit.isRouter(), true);
  // confirm: a promise of the app's answer; the config list and the routing profiles as the dialog has them
  // confirm: the app's answer as it comes — a boolean from window.confirm (luVouchers.js reads it at once), awaitable all the same
  assert.equal(kit.confirm('Delete the batch?'), true);
  assert.equal(h.asked.at(-1), 'Delete the batch?');
  h.state.confirm = false;
  assert.equal(await kit.confirm('again?'), false);
  h.state.confirm = true;
  h.hooks.confirm = async () => true;
  assert.equal(await kit.confirm('async?'), true, 'an asynchronous hook: a promise of its yes');
  h.hooks.confirm = (msg) => { h.asked.push(msg); return h.state.confirm; };
  assert.deepEqual(clone(kit.targets()).slice(0, 4).map((o) => [o.value, o.label]), [['', 'The current connection'], ['direct', 'Direct (no VPN)'], ['block', 'Blocked'], ['srv-m', 'My VPS']]);
  assert.equal(kit.targets()[4].pile.name, 'Tes sub', 'as the picker lists them, the piles too');
  assert.deepEqual(clone(kit.routingProfiles()), []);
  const tp = kit.targetPicker('srv-2', 'Config', 'vx:target', () => {});
  assert.equal(tp.dataset.lu, 'vx:target');
  assert.equal(kit.routingPicker('bypass-ir', 'vx:routing', () => {}).value, 'bypass-ir');
  const b = kit.button('btn small', 'Go');
  assert.deepEqual([b.tagName, b.type, b.textContent], ['BUTTON', 'button', 'Go']);
  assert.equal(kit.ltr(kit.el('span', null, 'x')).getAttribute('dir'), 'ltr');

  // a change through the kit: sent as given, its answer drawn (a new voucher batch, as luVouchers.js makes one)
  h.store.data.users.push({ id: 'usr-v3', username: 'TUVW-XYZ2', password: 'TUVW-XYZ2', name: 'Cafe #3', target: '', limits: [], enabled: true, voucher: { batch: 'vb-2', hours: 0, activatedAt: 0 } });
  const res = await kit.invoke('lanusers:user', { op: 'vouchers', batch: { count: 1, hours: 0, gb: 0, name: 'Cafe' } });
  assert.deepEqual(h.calls.at(-1), ['user', 'vouchers', {}, { batch: { count: 1, hours: 0, gb: 0, name: 'Cafe' } }]);
  assert.ok(Array.isArray(res.users), 'the answer as it came');
  assert.equal(kit.vouchers().length, 3, 'the answer is the page’s new truth');
  assert.equal(h.host.byClass('lu-user').length, 3, 'a voucher never shows among the users');
  assert.ok(h.applied.length >= 1, 'the reconnect question goes to app.js');
  const got = await kit.invoke('lanusers:get');
  assert.ok(Array.isArray(got.users));
  assert.deepEqual(clone(await kit.invoke('lanusers:nothing')), { ok: false, error: 'unavailable' });

  // a refusal: as it came, nothing said — the caller says it where it belongs (luVouchers.js: its form, a toast); said here when asked
  const no = harness({ lang: 'en', router: true, platform: 'linux', data: payload140(), api: { lanUsersUser: async () => ({ ok: false, error: 'priority' }) } });
  await no.load();
  const r = await no.window.LanUsersKit.invoke('lanusers:user', { op: 'deleteBatch', batch: { id: 'vb-1' }, unused: true });
  assert.deepEqual([r.ok, r.error], [false, 'priority']);
  assert.equal(no.toasts.length, 0, 'one toast, the caller’s');
  await no.window.LanUsersKit.invoke('lanusers:user', { op: 'deleteBatch', batch: { id: 'vb-1' } }, { toast: true });
  assert.deepEqual(no.toasts.at(-1), ['Not saved: Priority is high, normal or low', 'err']);
  assert.equal(no.window.LanUsersKit.errText(r), 'Priority is high, normal or low', 'its words, for the caller');
  // a thrown one reads as a refusal
  const err = harness({ lang: 'en', data: desktop140(), api: { lanUsersUser: async () => { throw new Error('disk full'); } } });
  await err.load();
  assert.deepEqual(clone(await err.window.LanUsersKit.invoke('lanusers:user', { op: 'x' })), { ok: false, error: 'disk full' });
});

test('v1.40 a top-up request: its line on the box (when), Top up opens the dialog, Dismiss → dismissRequest and the line goes at once; a tick brings one', async () => {
  const h = harness({ router: true, platform: 'linux', data: payload140() });
  await h.load();
  const line = h.user('usr-b2').one('lu-req');
  assert.equal(line.getAttribute('role'), 'status');
  assert.equal(line.one('lu-req-text').textContent, 'درخواستِ حجم کرده — 10:00');
  assert.equal(h.user('usr-a1').byClass('lu-req').length, 0);
  assert.equal(h.host.one('lu-users').one('lu-meta').textContent, '3 کاربر · 1 درخواستِ حجم');
  h.host.byKey('reqtopup:usr-b2').click();
  assert.ok(h.document.body.children.some((c) => c.id === 'luTopUp'), 'Top up: the top-up dialog');
  h.page.closeTopUp();
  h.host.byKey('dismiss:usr-b2').click();
  assert.equal(h.user('usr-b2').byClass('lu-req').length, 0, 'gone at once');
  await flush();
  assert.deepEqual(h.calls.at(-1), ['user', 'dismissRequest', { id: 'usr-b2' }]);
  assert.equal(h.host.one('lu-users').one('lu-meta').textContent, '3 کاربر');
  // a tick that brings a request: drawn — no limit to top up, Dismiss alone
  h.page.tick({ usage: { 'usr-c3': Object.assign({}, h.store.data.usage['usr-c3'], { request: { at: TODAY_10 } }) } });
  const c3 = h.user('usr-c3').one('lu-req');
  assert.deepEqual(c3.byClass('btn').map((b) => b.dataset.lu), ['dismiss:usr-c3']);
  // a top-up answers it: the service clears it, the page draws that
  h.store.data.usage['usr-b2'].request = { at: TODAY_10 };
  await h.load();
  h.page.topUp('usr-b2');
  const box = h.document.body.children.find((c) => c.id === 'luTopUp');
  box.byKey('t:gb').value = '2';
  box.byKey('t:save').click();
  await flush();
  assert.equal(h.user('usr-b2').byClass('lu-req').length, 0);
});

test('v1.40 the box’s tags (filter, priority, remembered devices) and the days left before an expiry — amber when close', async () => {
  const data = payload140();
  const endOf = (days) => { const n = new Date(); return new Date(n.getFullYear(), n.getMonth(), n.getDate() + days, 23, 59, 59, 999).getTime(); };
  data.users[1].expiresAt = endOf(1);
  data.users[2].expiresAt = endOf(0);
  const h = harness({ lang: 'en', router: true, platform: 'linux', data });
  await h.load();
  assert.deepEqual(h.user('usr-a1').one('lu-tags').children.map((c) => [c.className, c.textContent]), [
    ['lu-chip lu-chip-filter', '🛡 Filter: Adult, Social media · safe search · domains: 2'],
    ['lu-chip lu-chip-prio lu-prio-high', '▲ High priority'],
    ['lu-chip lu-chip-rem', '🔑 Remembers devices · 1']]);
  assert.deepEqual(h.user('usr-b2').one('lu-tags').children.map((c) => c.textContent), ['▼ Low priority']);
  assert.equal(h.user('usr-c3').byClass('lu-tags').length, 0, 'nothing to say: no line');
  const left = (id) => h.user(id).one('lu-left');
  assert.deepEqual([left('usr-b2').textContent, left('usr-b2').classList.contains('lu-soon')], ['1 day left', true]);
  assert.deepEqual([left('usr-c3').textContent, left('usr-c3').classList.contains('lu-soon')], ['ends today', true]);
  assert.equal(h.user('usr-a1').byClass('lu-left').length, 0, 'no expiry: nothing left to count');
  // in Persian
  const fa = harness({ router: true, platform: 'linux', data });
  await fa.load();
  assert.deepEqual(fa.user('usr-a1').one('lu-tags').children.map((c) => c.textContent), ['🛡 فیلتر: بزرگسالان، شبکه‌های اجتماعی · جستجوی امن · 2 دامنه', '▲ اولویتِ بالا', '🔑 دستگاه‌ها را به خاطر می‌سپارد · 1']);
  assert.equal(fa.user('usr-b2').one('lu-left').textContent, '1 روز مانده');
  // a PC: the filter alone — the priority and the remembered devices are the router's
  const pc = harness({ lang: 'en', data: desktop140() });
  await pc.load();
  assert.deepEqual(pc.user('usr-a1').one('lu-tags').children.map((c) => c.textContent), ['🛡 Filter: Adult, Social media · safe search · domains: 2']);
  assert.equal(pc.user('usr-b2').byClass('lu-tags').length, 0);
});

test('v1.40 the dialog on the router: the content filter (categories, safe search, domains — pasted lists and addresses read), the priority and remember devices, saved as the model’s', async () => {
  const h = harness({ lang: 'en', router: true, platform: 'linux', data: payload140() });
  await h.load();
  h.host.byKey('edit:usr-a1').click();
  const d = () => h.dialog();
  const sect = d().all((n) => n.classList.contains('lu-sect') && n.dataset.field === 'filter')[0];
  assert.equal(sect.one('lu-sect-title').textContent, 'Content filter');
  assert.deepEqual(d().one('lu-cats').children.map((b) => [b.dataset.lu, b.textContent, b.getAttribute('aria-pressed')]), [
    ['f:cat:adult', 'Adult', 'true'], ['f:cat:social', 'Social media', 'true'], ['f:cat:games', 'Games', 'false'], ['f:cat:ads', 'Ads', 'false']], 'no gambling: geosite has no list for it');
  assert.equal(d().one('lu-cats').getAttribute('role'), 'group');
  assert.equal(d().byKey('f:safe').checked, true);
  const area = d().byKey('f:domains');
  assert.deepEqual([area.tagName, area.value, area.getAttribute('dir'), area.getAttribute('spellcheck')], ['TEXTAREA', 'example.com\nkeyword:casino', 'ltr', 'false']);
  assert.ok(sect.textContent.includes(h.t('lu.flt.hint')));
  assert.deepEqual(sect.byClass('lu-fltex-c').map((c) => [c.textContent, c.getAttribute('dir')]), [['example.com', 'ltr'], ['full:www.example.com', 'ltr'], ['keyword:casino', 'ltr']], 'the three forms of a line, each beside its words');
  assert.deepEqual(sect.byClass('lu-fltex-w').map((c) => c.textContent), ['it and all its subdomains', 'that one name only', 'any name with the word in it']);
  assert.equal(d().byKey('f:priority').value, 'high');
  assert.deepEqual(d().byKey('f:priority').children.map((o) => [o.value, o.textContent]), [['high', 'High'], ['normal', 'Normal'], ['low', 'Low']]);
  assert.ok(d().textContent.includes(h.t('lu.prioHint')), 'the line speed is set: what a priority does');
  assert.equal(d().byKey('f:remember').checked, true);
  assert.ok(d().textContent.includes(h.t('lu.remSub')));

  d().byKey('f:cat:social').click();
  d().byKey('f:cat:ads').click();
  assert.equal(d().byKey('f:cat:social').getAttribute('aria-pressed'), 'false');
  const sw = d().byKey('f:safe');
  sw.checked = false;
  sw.dispatch('change');
  const box = d().byKey('f:domains');
  box.value = 'Example.com\nhttps://www.Bet365.com/en/?x=1\n  FULL:www.x.org  \nexample.com, domain:y.net\n\n';
  box.dispatch('input');
  const prio = d().byKey('f:priority');
  prio.value = 'low';
  prio.dispatch('change');
  const rem = d().byKey('f:remember');
  rem.checked = false;
  rem.dispatch('change');
  d().byKey('f:save').click();
  await flush();
  const saved = h.calls.at(-1)[2];
  assert.deepEqual(saved.filter, { block: ['adult', 'ads'], safeSearch: false, domains: ['example.com', 'www.bet365.com', 'full:www.x.org', 'y.net'] },
    'the categories in the model’s order; the domains lowercased, once each, an address read as its host');
  assert.deepEqual([saved.priority, saved.remember], ['low', false]);

  // a line that is not a domain: said under the filter, its box focused, nothing sent
  h.host.byKey('edit:usr-a1').click();
  const sent = h.calls.length;
  const type = (v) => { const n = d().byKey('f:domains'); n.value = v; n.dispatch('input'); };
  const err = () => d().all((n) => n.dataset.err === 'filter')[0].textContent;
  type('ok.com\nex@mple.com');
  d().byKey('f:save').click();
  await flush();
  assert.equal(h.calls.length, sent);
  assert.equal(err(), h.t('lu.err.filter.domain'));
  assert.equal(h.document.activeElement, d().byKey('f:domains'));
  assert.equal(d().byKey('f:domains').getAttribute('aria-invalid'), 'true');
  type('ok.com');
  assert.equal(err(), '', 'typing clears it');
  type(Array.from({ length: 201 }, (_, i) => 'd' + i + '.com').join('\n'));
  d().byKey('f:save').click();
  await flush();
  assert.equal(err(), h.t('lu.err.filter.domains'), '200 at most');
  // nothing filtered: null
  type('');
  for (const c of ['adult', 'ads']) d().byKey('f:cat:' + c).click();
  d().byKey('f:save').click();
  await flush();
  assert.equal(h.calls.at(-1)[2].filter, null);

  // the service's own refusal: under the filter in its detail's words; a priority's under the speed
  for (const [answer, field, words] of [[{ error: 'filter', detail: 'category' }, 'filter', 'lu.err.filter.category'], [{ error: 'priority' }, 'speed', 'lu.err.priority']]) {
    const no = harness({ lang: 'en', router: true, platform: 'linux', data: payload140(), api: { lanUsersUser: async () => Object.assign({ ok: false }, answer) } });
    await no.load();
    no.host.byKey('edit:usr-a1').click();
    no.dialog().byKey('f:save').click();
    await flush();
    assert.equal(no.dialog().all((n) => n.dataset.err === field)[0].textContent, no.t(words), JSON.stringify(answer));
    assert.equal(no.dialog().byClass('lu-formerr').length, 0);
  }

  // a voucher: never remembers; no line speed: the priority says it cannot apply
  const v = harness({ lang: 'en', router: true, platform: 'linux', data: payload140({ config: Object.assign(clone(payload140().config), { shaping: { down: 0, up: 0, smooth: true } }) }) });
  await v.load();
  v.page.open('usr-v1');
  assert.equal(v.dialog().hasKey('f:remember'), false);
  assert.equal(v.dialog().hasKey('f:priority'), true);
  const hint = v.dialog().all((n) => n.textContent === v.t('lu.prioNoLine'))[0];
  assert.ok(hint && hint.classList.contains('lu-bad'));
  v.dialog().byKey('f:save').click();
  await flush();
  assert.deepEqual(clone(v.calls.at(-1)[2].voucher), { batch: 'vb-1', hours: 2, activatedAt: 0 }, 'a voucher stays one');
  assert.equal('remember' in v.calls.at(-1)[2], false);
  // a new user on the router: normal, not remembering, nothing filtered
  v.host.byKey('add').click();
  assert.deepEqual([v.dialog().byKey('f:priority').value, v.dialog().byKey('f:remember').checked, v.dialog().byKey('f:domains').value], ['normal', false, '']);
});

test('v1.40 the dialog on a PC: the content filter, no priority or remember (the record’s kept); validate() and domainLines() as the model', async () => {
  const h = harness({ lang: 'en', data: desktop140() });
  await h.load();
  h.host.byKey('edit:usr-a1').click();
  assert.equal(h.dialog().hasKey('f:priority') || h.dialog().hasKey('f:remember'), false);
  assert.equal(h.dialog().byKey('f:domains').value, 'example.com\nkeyword:casino');
  h.dialog().byKey('f:cat:games').click();
  h.dialog().byKey('f:save').click();
  await flush();
  const saved = h.calls.at(-1)[2];
  assert.deepEqual(saved.filter, { block: ['adult', 'social', 'games'], safeSearch: true, domains: ['example.com', 'keyword:casino'] });
  assert.deepEqual([saved.priority, saved.remember], ['high', true], 'the router’s fields as the record has them');

  const v = (f) => clone(h.page.validate(Object.assign({ username: 'a', password: 'abcd' }, f), []));
  assert.deepEqual(v({ filter: { block: ['adult'], safeSearch: false, domains: 'a.com\nfull:b.a.com\nkeyword:x_y-z' } }), {});
  assert.deepEqual(v({ filter: { block: ['news'], domains: '' } }), { filter: 'lu.err.filter.category' });
  assert.deepEqual(v({ filter: { block: ['gambling'], domains: '' } }), { filter: 'lu.err.filter.category' }, 'no list for it: not a category');
  assert.deepEqual(v({ filter: { block: [], domains: 'a b.com' } }), {}, 'a space splits two');
  assert.deepEqual(v({ filter: { block: [], domains: 'keyword:' } }), { filter: 'lu.err.filter.domain' });
  assert.deepEqual(v({ filter: { block: [], domains: 'x'.repeat(254) } }), { filter: 'lu.err.filter.domain' });
  assert.deepEqual(v({ priority: 'urgent' }), { speed: 'lu.err.priority' });
  assert.deepEqual(clone(h.page.domainLines('A.com\r\nA.COM, b.com;full:C.com  http://d.com:8080/x  domain:e.com')), ['a.com', 'b.com', 'full:c.com', 'd.com', 'e.com']);
});

test('v1.40 the filter’s two hints: safe search does not apply through a group (said while the config is one), and the categories need the geo files (when the page knows they are missing)', async () => {
  const h = harness({ lang: 'en', data: desktop140() });
  await h.load();
  h.hooks.targets = () => TARGETS.concat([{ value: 'grp-1', label: '⧉ Fast pair', pile: { key: 'groups', name: 'Groups', ico: '⧉' } }]);
  h.host.byKey('edit:usr-a1').click();
  const hint = () => h.dialog().one('lu-safegroup');
  assert.equal(hint().hidden, true, 'a plain config: nothing said');
  assert.equal(hint().textContent, h.t('lu.flt.safeGroup'));
  const pick = h.dialog().byKey('f:target:select');
  pick.value = 'grp-1';
  pick.dispatch('change');
  assert.equal(hint().hidden, false, 'a group: said at once');
  pick.value = 'srv-2';
  pick.dispatch('change');
  assert.equal(hint().hidden, true);
  h.store.data.users[0].target = 'grp-1';
  h.dialog().byKey('f:close').click();
  await h.load();
  h.host.byKey('edit:usr-a1').click();
  assert.equal(hint().hidden, false, 'opened on a group: said');
  assert.equal(h.dialog().byClass('lu-nogeo').length, 0, 'the geo files not known missing: nothing said');
  h.dialog().byKey('f:close').click();
  // the geo files missing: from the payload, or app.js's hook
  for (const [data, hookGeo] of [[desktop140({ geo: false }), undefined], [desktop140(), false]]) {
    const g = harness({ lang: 'en', data });
    if (hookGeo !== undefined) g.hooks.geo = () => hookGeo;
    await g.load();
    g.host.byKey('edit:usr-a1').click();
    assert.equal(g.dialog().one('lu-nogeo').textContent, g.t('lu.flt.noGeo'));
  }
  const ok = harness({ lang: 'en', data: desktop140({ geo: true }) });
  await ok.load();
  ok.host.byKey('edit:usr-a1').click();
  assert.equal(ok.dialog().byClass('lu-nogeo').length, 0);
});

test('v1.40 the router’s settings: the status page’s note, contact and requests; the line speed and smooth limits; what the shaper does and the packages to install', async () => {
  const h = harness({ lang: 'en', router: true, platform: 'linux', data: payload140() });
  await h.load();
  const set = h.host.one('lu-settings');
  const pt = set.one('lu-ptset');
  assert.equal(pt.parentNode, set.one('lu-portal'), 'with the sign-in page’s addresses');
  assert.equal(pt.one('lu-boxtitle').textContent, 'The user’s status page');
  const note = h.host.byKey('ptNote');
  assert.deepEqual([note.value, note.maxLength, note.getAttribute('dir'), note.placeholder], ['Top-ups on Fridays', 300, 'auto', h.t('lu.pt.notePh')]);
  assert.deepEqual([h.host.byKey('ptContact').value, h.host.byKey('ptContact').maxLength], ['0912 000 0000', 64]);
  assert.equal(h.host.byKey('ptRequests').checked, true);
  const change = (key, v) => { const n = h.host.byKey(key); n.value = v; n.dispatch('change'); return flush(); };
  await change('ptNote', '  Pay by\nthe 5th\t ');
  assert.deepEqual(h.calls.at(-1), ['config', { portal: { note: 'Pay by the 5th' } }], 'one line, trimmed');
  await change('ptContact', '@admin');
  assert.deepEqual(h.calls.at(-1), ['config', { portal: { contact: '@admin' } }]);
  const sent = h.calls.length;
  await change('ptContact', 'x'.repeat(65));
  assert.equal(h.calls.length, sent, 'too long: not sent');
  assert.deepEqual(h.toasts.at(-1), [h.t('lu.err.portal'), 'err']);
  const req = h.host.byKey('ptRequests');
  req.checked = false;
  req.dispatch('change');
  await flush();
  assert.deepEqual(h.calls.at(-1), ['config', { portal: { requests: false } }]);

  // the shaping
  const shp = () => h.host.one('lu-shaping');
  assert.deepEqual(shp().byClass('field-label').map((n) => n.textContent), ['Speed shaping', 'Line download (Mbps)', 'Line upload (Mbps)']);
  assert.deepEqual([h.host.byKey('shp:down').value, h.host.byKey('shp:up').value], ['50', '10'], 'Mbps');
  assert.equal(h.host.byKey('shp:down').parentNode.one('lu-arrow').textContent, '↓');
  assert.equal(shp().one('lu-shpnow').textContent, h.t('lu.shp.mode.police'));
  assert.equal(shp().one('lu-shpnow').dataset.mode, 'police');
  assert.ok(shp().one('lu-dot').classList.contains('lu-dot-warn'));
  const cmd = shp().one('lu-cmdline');
  assert.deepEqual([cmd.tagName, cmd.textContent, cmd.getAttribute('dir')], ['CODE', 'opkg update && opkg install tc-tiny kmod-sched-core kmod-ifb', 'ltr']);
  h.host.byKey('copy:opkg').click();
  await flush();
  assert.equal(h.copies.at(-1), 'opkg update && opkg install tc-tiny kmod-sched-core kmod-ifb');
  await change('shp:down', '100');
  assert.deepEqual(h.calls.at(-1), ['config', { shaping: { down: 100000 } }]);
  await change('shp:up', '0.5');
  assert.deepEqual(h.calls.at(-1), ['config', { shaping: { up: 500 } }]);
  const before = h.calls.length;
  await change('shp:down', '-3');
  assert.equal(h.calls.length, before);
  assert.deepEqual(h.toasts.at(-1), [h.t('lu.err.shaping'), 'err']);
  assert.equal(h.host.byKey('shp:down').value, '100', 'put back');
  await change('shp:down', '');
  assert.deepEqual(h.calls.at(-1), ['config', { shaping: { down: 0 } }], 'empty: not set');
  const smooth = h.host.byKey('shpSmooth');
  smooth.checked = false;
  smooth.dispatch('change');
  await flush();
  assert.deepEqual(h.calls.at(-1), ['config', { shaping: { smooth: false } }]);
  assert.equal(h.host.byClass('lu-cmdline').length, 0, 'smooth limits off: nothing to install');

  // tc: smooth, nothing missing; no shaper in the payload yet: said
  const tc = harness({ lang: 'en', router: true, platform: 'linux', data: payload140({ shaper: { mode: 'tc', missing: [], line: { down: 50000, up: 10000 } } }) });
  await tc.load();
  assert.equal(tc.host.one('lu-shpnow').textContent, tc.t('lu.shp.mode.tc'));
  assert.ok(tc.host.one('lu-shpnow').one('lu-dot').classList.contains('on'));
  assert.equal(tc.host.byClass('lu-cmdline').length, 0);
  assert.equal(tc.host.byClass('lu-shpbusy').length + tc.host.byClass('lu-shpprio').length + tc.host.byClass('lu-shpwhy').length, 0, 'nothing more to say');
  // the shaper's whole info (router/shaper.js): a direction without the line's speed, its reason; another shaper on the interface
  const half = harness({ lang: 'en', router: true, platform: 'linux', data: payload140({ shaper: { mode: 'tc', missing: [], line: { down: 50000, up: 0 }, prio: { down: true, up: false }, busy: null, why: 'shaping 2 devices on br-lan', lanIf: 'br-lan', ifb: 'ifb-lu' } }) });
  await half.load();
  assert.equal(half.host.one('lu-shpprio').textContent, 'Priority does not apply to uploads: set the line speed above.');
  assert.equal(half.host.one('lu-shpwhy').textContent, 'shaping 2 devices on br-lan');
  assert.equal(half.host.one('lu-shpnow').title, 'shaping 2 devices on br-lan');
  const sqm = harness({ router: true, platform: 'linux', data: payload140({ shaper: { mode: 'police', missing: [], line: { down: 50000, up: 10000 }, prio: { down: false, up: false }, busy: 'root', why: 'br-lan has a root qdisc of its own (cake)' } }) });
  await sqm.load();
  assert.equal(sqm.host.one('lu-shpbusy').textContent, sqm.t('lu.shp.busy'));
  assert.match(sqm.t('lu.shp.busy'), /SQM/);
  assert.equal(sqm.host.byClass('lu-shpprio').length, 0, 'policing: the status line says it already');
  const none = harness({ lang: 'en', router: true, platform: 'linux', data: payload140({ shaper: undefined }) });
  await none.load();
  assert.equal(none.host.one('lu-shpnow').textContent, none.t('lu.shp.unknown'));
  // a package name that is not one is never put in the command
  const odd = harness({ lang: 'en', router: true, platform: 'linux', data: payload140({ shaper: { mode: 'police', missing: ['tc-full', 'x; rm -rf /'], line: {} } }) });
  await odd.load();
  assert.equal(odd.host.one('lu-cmdline').textContent, 'opkg update && opkg install tc-full');
  // another policy: no sign-in page, the shaping still; a PC: neither
  const blk = clone(payload140());
  blk.config.transparent.unassigned = 'block';
  const b = harness({ lang: 'en', router: true, platform: 'linux', data: blk });
  await b.load();
  assert.equal(b.host.byClass('lu-ptset').length, 0);
  assert.equal(b.host.byClass('lu-shaping').length, 1);
  const pc = harness({ lang: 'en', data: desktop140() });
  await pc.load();
  assert.equal(pc.host.byClass('lu-shaping').length + pc.host.byClass('lu-ptset').length, 0);
  // the sign-in page down: its words stay editable
  const down = harness({ lang: 'en', router: true, platform: 'linux', data: payload140({ portal: null }) });
  await down.load();
  assert.ok(down.host.one('lu-portal').textContent.includes(down.t('lu.portalDown')));
  assert.equal(down.host.byKey('ptNote').value, 'Top-ups on Fridays');
});

test('v1.40 a sign-in card (router, login mode): the sign-in page with ?u=, its QR, printed in both languages — the password only when ticked', async () => {
  const made = [];
  const qrcode = () => { const q = { data: '', addData(s) { q.data = s; }, make() {}, createDataURL() { made.push(q.data); return 'data:image/gif;base64,R0lGOD'; } }; return q; };
  const h = harness({ lang: 'en', router: true, platform: 'linux', qrcode, data: payload140() });
  await h.load();
  const btn = h.host.byKey('card:usr-a1');
  assert.equal(btn.getAttribute('aria-label'), 'Sign-in card — سارا');
  btn.focus();
  btn.click();
  const box = () => h.document.body.children.find((c) => c.id === 'luCard') || null;
  assert.equal(box().one('lu-modal').getAttribute('role'), 'dialog');
  assert.equal(box().one('modal-title').textContent, 'Sign-in card of “سارا”');
  assert.equal(box().byKey('c:link').textContent, 'http://192.168.1.1:30822/?u=sara');
  assert.equal(box().byKey('c:link').getAttribute('dir'), 'ltr');
  assert.equal(made.at(-1), 'http://192.168.1.1:30822/?u=sara', 'the QR is of the address — no DNS of the router’s needed');
  assert.equal(box().byKey('c:pass').checked, false, 'the password off unless ticked');
  assert.equal(h.document.activeElement, box().byKey('c:print'));

  const html = h.document.documentElement;
  const on = {};
  let during = null;
  h.window.addEventListener = (type, fn) => { on[type] = fn; };
  h.window.removeEventListener = (type) => { delete on[type]; };
  h.window.print = () => {
    const sheet = h.document.body.children.find((c) => c.classList.contains('lu-printsheet'));
    during = { printing: html.classList.contains('lu-printing'), card: sheet.classList.contains('lu-pcard'), dir: sheet.getAttribute('dir'), text: sheet.textContent,
      values: sheet.byClass('lu-pc-v').map((v) => v.textContent), urls: sheet.byClass('lu-pc-url').map((u) => u.textContent), qr: sheet.byClass('lu-pc-qr').length };
  };
  box().byKey('c:print').click();
  assert.deepEqual([during.printing, during.card, during.dir, during.qr], [true, true, 'rtl', 1]);
  assert.deepEqual(during.values, ['sara', '0912 000 0000'], 'the username and the admin’s contact');
  assert.ok(!during.text.includes('pa55-Sara'), 'no password');
  assert.ok(during.text.includes('رمز را از مدیرِ شبکه بگیرید.') && during.text.includes('Get the password from the network’s admin.'));
  assert.ok(during.text.includes('ورود به اینترنت') && during.text.includes('سارا'));
  assert.deepEqual(during.urls, ['http://login.lan:30822/', 'http://192.168.1.1:30822/?u=sara']);
  on.afterprint();
  assert.equal(html.classList.contains('lu-printing'), false);
  assert.ok(!h.document.body.children.some((c) => c.classList.contains('lu-printsheet')), 'gone after the print');
  // ticked: the password too, and the warning said
  const sw = box().byKey('c:pass');
  sw.checked = true;
  sw.dispatch('change');
  assert.equal(box().all((n) => n.textContent === h.t('lu.cardPassWarn'))[0].hidden, false);
  box().byKey('c:print').click();
  assert.deepEqual(during.values, ['sara', 'pa55-Sara', '0912 000 0000']);
  on.afterprint();
  box().dispatch('keydown', { key: 'Escape' });
  assert.equal(box(), null);
  assert.equal(h.document.activeElement, h.host.byKey('card:usr-a1'), 'the focus back');

  // the sign-in page down: said, nothing to print
  const down = harness({ lang: 'en', router: true, platform: 'linux', data: payload140({ portal: null }) });
  await down.load();
  down.page.card('usr-a1');
  const db = down.document.body.children.find((c) => c.id === 'luCard');
  assert.ok(db.textContent.includes(down.t('lu.portalDown')));
  assert.equal(db.hasKey('c:print'), false);
  // no card where there is no sign-in page: another policy, the transparent mode off, a PC
  const blk = clone(payload140());
  blk.config.transparent.unassigned = 'allow';
  const off = clone(payload140());
  off.config.transparent.enabled = false;
  for (const [data, router] of [[blk, true], [off, true], [desktop140(), false]]) {
    const x = harness({ lang: 'en', router, platform: router ? 'linux' : 'win32', data });
    await x.load();
    assert.equal(x.host.hasKey('card:usr-a1'), false);
  }
});

test('v1.40 the devices: one a sign-in gave its user says so and when; no voucher to hand a device to, but a voucher’s own device shows its code', async () => {
  const h = harness({ lang: 'en', router: true, platform: 'linux', data: payload140() });
  await h.load();
  const rem = h.device('aa:bb:cc:00:00:04').one('lu-remembered');
  assert.equal(rem.textContent, '🔑 by sign-in, ' + english(REMEMBERED_AT, SHORT));
  assert.equal(rem.title, h.t('lu.dev.rememberedHint'));
  assert.equal(h.device('aa:bb:cc:00:00:01').byClass('lu-remembered').length, 0, 'the admin’s own pick: nothing said');
  assert.deepEqual(h.host.byKey('devuser:aa:bb:cc:00:00:01').children.map((o) => o.value), ['', 'usr-a1', 'usr-b2', 'usr-c3'], 'the people alone');
  const cafe = h.host.byKey('devuser:aa:bb:cc:00:00:05');
  assert.equal(cafe.value, 'usr-v2');
  assert.deepEqual(cafe.children.map((o) => [o.value, o.textContent]).at(-1), ['usr-v2', '🎫 JKMN-PQRS']);
  // remembered without a time (an older record): by sign-in alone
  const data = payload140();
  data.devices.find((x) => x.mac === 'aa:bb:cc:00:00:04').at = 0;
  const fa = harness({ router: true, platform: 'linux', data });
  await fa.load();
  assert.equal(fa.device('aa:bb:cc:00:00:04').one('lu-remembered').textContent, '🔑 با ورود');
});

test('v1.40 backup: asked first (it holds passwords), then lanusers:backup’s bundle saved as a JSON file through a Blob and a link', async () => {
  const blobs = [];
  class FakeBlob { constructor(parts, opts) { this.parts = parts; this.type = opts && opts.type; } }
  const URLs = { createObjectURL: (b) => { blobs.push(b); return 'blob:lu/' + blobs.length; }, revokeObjectURL: () => {} };
  const h = harness({ lang: 'en', router: true, platform: 'linux', data: payload140(), globals: { Blob: FakeBlob, URL: URLs } });
  await h.load();
  let clicked = null;
  const make = h.document.createElement;
  h.document.createElement = (tag) => {
    const n = make(tag);
    if (tag === 'a') n.click = () => { clicked = { href: n.href, download: n.download, inPage: h.document.body.contains(n) }; };
    return n;
  };
  assert.equal(h.host.byKey('backup').title, h.t('lu.bk.tip'));
  h.state.confirm = false;
  h.host.byKey('backup').click();
  await flush();
  assert.equal(h.asked.at(-1), h.t('lu.bk.confirm'));
  assert.match(h.asked.at(-1), /password/);
  assert.equal(h.calls.filter((c) => c[0] === 'backup').length, 0, 'not without a yes');
  h.state.confirm = true;
  h.host.byKey('backup').click();
  await flush();
  await flush();
  assert.deepEqual(clicked, { href: 'blob:lu/1', download: 'irnetfree-users-2026-10-28.json', inPage: true }, 'named for the day it was made');
  assert.equal(blobs[0].type, 'application/json');
  const bundle = JSON.parse(blobs[0].parts[0]);
  assert.deepEqual([bundle.kind, bundle.version, bundle.lanUsers.users.length], ['irnetfree-lanusers', 1, 5]);
  assert.ok(!h.document.body.children.some((c) => c.tagName === 'A'), 'the link gone after');
  assert.deepEqual(h.toasts.at(-1), ['Users backup saved', 'ok']);
  // refused or failed: said
  const no = harness({ lang: 'en', data: desktop140(), api: { lanUsersBackup: async () => ({ ok: false, error: 'disk full' }) }, globals: { Blob: FakeBlob, URL: URLs } });
  await no.load();
  no.host.byKey('backup').click();
  await flush();
  assert.deepEqual(no.toasts.at(-1), ['The backup could not be made: disk full', 'err']);
  // an older service without the channel: the buttons there, disabled
  const old = harness({ lang: 'en', data: desktop140(), api: { lanUsersBackup: undefined, lanUsersRestore: undefined } });
  await old.load();
  assert.deepEqual([old.host.byKey('backup').disabled, old.host.byKey('restore').disabled], [true, true]);
});

test('v1.40 restore: a file picked and read here — what it holds and when, the passwords’ warning — then Merge, or Replace after asking; a file that is not one said', async () => {
  const at = new Date(2026, 9, 28, 14, 5).getTime();
  const bundle = { kind: 'irnetfree-lanusers', version: 1, at, app: '1.40.0', platform: 'openwrt', meter: {},
    lanUsers: { config: {}, devices: [{ mac: 'aa:bb:cc:00:00:09', name: '', userId: 'usr-n1', blocked: false }], users: [
      Object.assign(clone(payload139().users[0])),
      { id: 'usr-n1', username: 'nima', password: 'nima1234', name: 'Nima', target: '', routing: '', schedule: null, limits: [], quotaGb: 0, quotaPeriod: 'month', expiresAt: 0, maxDevices: 0, enabled: true },
      { id: 'usr-v9', username: 'WXYZ-2345', password: 'WXYZ-2345', name: 'Gift', target: '', limits: [], enabled: true, voucher: { batch: 'vb-9', hours: 0, activatedAt: 0 } }] } };
  const h = harness({ lang: 'en', router: true, platform: 'linux', data: payload140() });
  await h.load();
  const box = () => h.document.body.children.find((c) => c.id === 'luRestore') || null;
  h.host.byKey('restore').focus();
  h.host.byKey('restore').click();
  const input = h.document.body.children.find((c) => c.dataset.lu === 'restoreFile');
  assert.deepEqual([input.tagName, input.type, input.accept, input.hidden], ['INPUT', 'file', '.json,application/json', true]);
  input.files = [{ text: async () => JSON.stringify(bundle) }];
  input.dispatch('change');
  await flush();
  await flush();
  assert.ok(box(), 'read: the dialog');
  assert.equal(input.parentNode, null, 'the file box gone');
  assert.equal(box().one('modal-title').textContent, 'Restore users');
  assert.equal(box().byKey('r:summary').textContent, 'In this file — users: 2, devices: 1, vouchers: 1');
  assert.ok(box().textContent.includes('Made ' + english(at, FULL) + ' 14:05 by IRNetFree 1.40.0'));
  assert.ok(box().textContent.includes(h.t('lu.bk.warn')));
  assert.ok(box().textContent.includes(h.t('lu.bk.mergeSub')) && box().textContent.includes(h.t('lu.bk.replaceSub')));
  assert.equal(h.document.activeElement, box().byKey('r:merge'));
  box().byKey('r:merge').click();
  await flush();
  await flush();
  assert.deepEqual(h.calls.find((c) => c[0] === 'restore'), ['restore', { bundle, mode: 'merge' }]);
  assert.equal(box(), null, 'done: closed');
  assert.deepEqual(h.toasts.at(-1), ['Restored — added users: 1, devices: 1, vouchers: 1; updated: 1', 'ok']);
  assert.ok(h.user('usr-n1'), 'read again: the new user drawn');
  assert.equal(h.user('usr-v9'), undefined, 'a voucher: not among the users');

  // Replace asks first
  h.page.restore(JSON.stringify(bundle));
  h.state.confirm = false;
  box().byKey('r:replace').click();
  await flush();
  assert.equal(h.asked.at(-1), h.t('lu.bk.confirmReplace'));
  assert.equal(h.calls.filter((c) => c[0] === 'restore').length, 1, 'not without a yes');
  assert.ok(box(), 'still open');
  h.state.confirm = true;
  box().byKey('r:replace').click();
  await flush();
  await flush();
  assert.deepEqual(h.calls.filter((c) => c[0] === 'restore').at(-1)[1].mode, 'replace');

  // not a Users backup: said, nothing to press but Close
  for (const [text, why] of [[JSON.stringify({ kind: 'irnetfree-backup', version: 1, servers: [] }), 'kind'], [JSON.stringify(Object.assign({}, bundle, { version: 2 })), 'version'],
    ['{"kind": "irnetfree-lanusers"', 'shape'], [JSON.stringify({ kind: 'irnetfree-lanusers', version: 1 }), 'shape']]) {
    assert.equal(h.page.restore(text), false, why);
    assert.equal(box().one('lu-formerr').textContent, h.t('lu.err.backup.' + why), why);
    assert.equal(box().hasKey('r:merge') || box().hasKey('r:replace'), false);
    assert.equal(h.document.activeElement, box().byKey('r:cancel'));
    box().byKey('r:cancel').click();
  }
  // the service refuses: said in the dialog, which stays
  const no = harness({ lang: 'en', data: desktop140(), api: { lanUsersRestore: async () => ({ ok: false, error: 'backup', detail: 'shape' }) } });
  await no.load();
  no.page.restore(JSON.stringify(bundle));
  const nb = () => no.document.body.children.find((c) => c.id === 'luRestore');
  nb().byKey('r:merge').click();
  await flush();
  assert.equal(nb().one('lu-formerr').textContent, 'Not saved: ' + no.t('lu.err.backup.shape'));
  assert.equal(nb().byKey('r:merge').disabled, false, 'free for another try');
});

test('v1.40 luReports.js on a box: the 12 months behind a toggle (drawn from the user’s usage, again on a tick, open across a redraw), CSV, a month’s statement; the All-users CSV on the bar; a fault of its own breaks nothing', async () => {
  const got = [];
  let h = null;
  const LuReports = {
    monthsChart: (user, usage) => { got.push(['chart', user.id, usage && usage.months ? usage.months.length : -1]); return h.document.createElement('div'); },
    csv: (user) => { got.push(['csv', user.id]); },
    printBill: (user, key) => { got.push(['bill', user.id, key]); },
    csvAll: () => { got.push(['csvAll']); }
  };
  h = harness({ lang: 'en', data: desktop140(), extras: { LuReports } });
  await h.load();
  h.host.byKey('csvAll').click();
  assert.deepEqual(got.at(-1), ['csvAll']);
  const sara = h.user('usr-a1');
  const tog = h.host.byKey('months:usr-a1');
  assert.equal(tog.getAttribute('aria-expanded'), 'false');
  assert.equal(sara.one('lu-months').hidden, true);
  assert.equal(got.filter((g) => g[0] === 'chart').length, 0, 'closed: not drawn');
  tog.click();
  assert.equal(tog.getAttribute('aria-expanded'), 'true');
  assert.equal(sara.one('lu-months').hidden, false);
  assert.deepEqual(got.at(-1), ['chart', 'usr-a1', 2], 'the user and their usage (usage()[id], its months)');
  assert.equal(sara.one('lu-months').children.length, 1);
  h.page.tick({ usage: { 'usr-a1': Object.assign({}, h.store.data.usage['usr-a1']) } });
  assert.equal(got.filter((g) => g[0] === 'chart').length, 2, 'a tick draws it again while open');
  h.host.byKey('csv:usr-a1').click();
  assert.deepEqual(got.at(-1), ['csv', 'usr-a1']);
  const sel = h.host.byKey('billmonth:usr-a1');
  assert.deepEqual(sel.children.map((o) => o.value), ['2026-10', '2026-09'], 'the newest first');
  assert.equal(sel.children[1].textContent, english(new Date(2026, 8, 1).getTime(), { month: 'short', day: 'numeric' }) + ' – ' + english(new Date(2026, 8, 30).getTime(), { year: 'numeric', month: 'short', day: 'numeric' }));
  h.host.byKey('bill:usr-a1').click();
  assert.deepEqual(got.at(-1), ['bill', 'usr-a1', '2026-10']);
  sel.value = '2026-09';
  sel.dispatch('change');
  h.host.byKey('bill:usr-a1').click();
  assert.deepEqual(got.at(-1), ['bill', 'usr-a1', '2026-09']);
  // no months known: no month to pick, the statement of the newest (printBill with no key)
  assert.equal(h.host.hasKey('billmonth:usr-c3'), false);
  h.host.byKey('bill:usr-c3').click();
  assert.deepEqual(got.at(-1), ['bill', 'usr-c3', undefined]);
  // luReports.js's own month list (its names in the user's calendar): the picker's
  LuReports.monthList = (user) => (user.id === 'usr-c3' ? [{ key: 'j1405-08', label: 'آبان 1405' }, { key: 'j1405-07', label: 'مهر 1405' }] : []);
  h.page.render();
  assert.deepEqual(h.host.byKey('billmonth:usr-c3').children.map((o) => [o.value, o.textContent]), [['j1405-08', 'آبان 1405'], ['j1405-07', 'مهر 1405']]);
  h.host.byKey('bill:usr-c3').click();
  assert.deepEqual(got.at(-1), ['bill', 'usr-c3', 'j1405-08']);
  assert.deepEqual(h.host.byKey('billmonth:usr-a1').children.map((o) => o.value), ['2026-10', '2026-09'], 'an empty list: the usage’s months');
  assert.ok(h.host.hasKey('csv:usr-c3'));
  h.page.render();
  assert.equal(h.user('usr-a1').one('lu-months').hidden, false, 'open across a redraw');
  // none: nothing of it
  const plain = harness({ lang: 'en', data: desktop140() });
  await plain.load();
  assert.equal(plain.host.byClass('lu-reps').length + (plain.host.hasKey('csvAll') ? 1 : 0), 0);
  // one that throws: the page stands
  const boom = () => { throw new Error('boom'); };
  const bad = harness({ lang: 'en', data: desktop140(), extras: { LuReports: { monthsChart: boom, csv: boom } }, globals: quiet });
  await bad.load();
  bad.host.byKey('months:usr-a1').click();
  bad.host.byKey('csv:usr-a1').click();
  assert.equal(bad.user('usr-a1').one('lu-months').children.length, 0);
  assert.equal(bad.host.byClass('lu-user').length, 3);
  const badV = harness({ lang: 'en', data: desktop140(), extras: { LuVouchers: { panel: boom } }, globals: quiet });
  await badV.load();
  badV.host.byKey('tab:vouchers').click();
  assert.ok(badV.host.one('lu-vpane').textContent.includes('boom'));
  badV.host.byKey('tab:users').click();
  assert.equal(badV.host.byClass('lu-user').length, 3);
});
