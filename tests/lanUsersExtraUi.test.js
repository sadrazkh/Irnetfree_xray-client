'use strict';
/**
 * The Users page's second round (v1.40): the Vouchers tab (src/renderer/
 * luVouchers.js) and the reports (src/renderer/luReports.js) — built on
 * window.LanUsersKit, which lanUsers.js exposes. Like tests/lanUsersUi.test.js
 * the files run in a vm over a DOM of plain objects (innerHTML throws), with
 * the REAL i18n.js beside them, so every string is checked in Persian and in
 * English; the kit is a stub here that keeps a store and answers as the
 * contract's `lanusers:user` ops do (op 'vouchers', op 'deleteBatch').
 *
 * Drawn: the new batch form (its rules said before the core is asked, the
 * time chips, the speed on the router), the batches newest first with each
 * state's count, the codes with their state and what is left, delete after
 * asking, the printed cards (eight to a page, the QR of the sign-in page with
 * ?code=), the 12-month chart in the user's calendar (Persian months for a
 * jalali one, checked against src/main/jalali.js), the CSV (BOM, header in the
 * page's language, a row per month and per day, formulas defused) and the
 * printed statement; the stylesheet (tokens and logical properties only) and
 * the markup (the scripts before app.js).
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const R = (...p) => fs.readFileSync(path.join(__dirname, '..', ...p), 'utf8').replace(/\r\n/g, '\n');
const VOUCHERS = R('src', 'renderer', 'luVouchers.js');
const REPORTS = R('src', 'renderer', 'luReports.js');
const I18N = R('src', 'renderer', 'i18n.js');
const CSS = R('src', 'renderer', 'lanUsersExtra.css');
const J = require('../src/main/jalali');
const { periodRange } = require('../src/main/capPeriods');
const GIB = 1024 ** 3;
const MB = 1024 * 1024;
const MIN = 60000;
const DAY = 86400000;
const clone = (v) => JSON.parse(JSON.stringify(v));
const flush = () => new Promise((r) => setImmediate(r));

/* ------------------------------ a DOM of plain objects (as tests/lanUsersUi.test.js) ------------------------------ */

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
  setAttribute(k, v) { if (k === 'class') this.className = String(v); else this.attributes[k] = String(v); }
  getAttribute(k) { if (k === 'class') return this._cls.size ? this.className : null; return Object.prototype.hasOwnProperty.call(this.attributes, k) ? this.attributes[k] : null; }
  hasAttribute(k) { return Object.prototype.hasOwnProperty.call(this.attributes, k); }
  removeAttribute(k) { delete this.attributes[k]; }
  addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); }
  dispatch(type, extra) { const ev = Object.assign({ type, target: this, preventDefault() {} }, extra); for (const fn of [...(this.listeners[type] || [])]) fn(ev); }
  click() { if (!this.disabled) this.dispatch('click'); }
  focus() { this.ownerDocument.activeElement = this; }
  contains(n) { for (let x = n; x; x = x.parentNode) if (x === this) return true; return false; }
  all(pred, out = []) { for (const c of this.childNodes) if (c.nodeType === 1) { if (pred(c)) out.push(c); c.all(pred, out); } return out; }
  byClass(c) { return this.all((n) => n.classList.contains(c)); }
  one(c) { const r = this.byClass(c); assert.equal(r.length, 1, `.${c}: ${r.length} found`); return r[0]; }
  byKey(k) { const r = this.all((n) => n.dataset.lu === k); assert.equal(r.length, 1, `[data-lu=${k}]: ${r.length} found`); return r[0]; }
  hasKey(k) { return this.all((n) => n.dataset.lu === k).length > 0; }
}
function fakeDocument() {
  const doc = { activeElement: null };
  doc.createElement = (tag) => new FakeEl(doc, tag);
  doc.createElementNS = (ns, tag) => Object.assign(new FakeEl(doc, tag), { namespaceURI: ns, tagName: String(tag) });
  doc.documentElement = new FakeEl(doc, 'html');
  doc.documentElement.lang = 'fa';
  doc.body = new FakeEl(doc, 'body');
  doc.documentElement.appendChild(doc.body);
  doc.activeElement = doc.body;
  doc.querySelectorAll = () => [];
  doc.querySelector = () => null;
  return doc;
}
/** Type into a box as a person does: its value, then its input event. */
function type(n, v) { n.value = String(v); n.dispatch('input'); }

/* ------------------------------ the data ------------------------------ */

const NOW = Date.now();
const day = (ago) => { const n = new Date(NOW); const d = new Date(n.getFullYear(), n.getMonth(), n.getDate() - ago); return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0'); };
/** A month entry as meter.js keeps one: its span from capPeriods.js, as the meter computes it. */
const month = (key, vpn, direct) => { const r = periodRange(key); return { key, from: r.start, to: r.end, vpn, direct }; };
/** The running Persian month's key, and `n` months before it. */
const jNow = (() => { const d = new Date(NOW); return J.toJalali(d.getFullYear(), d.getMonth() + 1, d.getDate()); })();
const jKey = (back) => { const i = jNow.jy * 12 + (jNow.jm - 1) - back; return 'j' + Math.floor(i / 12) + '-' + String(i % 12 + 1).padStart(2, '0'); };
const noneMeter = (bytes, capGb, extra = 0, over = false) => ({ kind: 'total', period: 'none', bytes, capBytes: capGb * GIB, extraBytes: extra, since: 0, until: 0, over, pct: 0, action: 'cut' });
const voucher = (id, code, name, batch, hours, gb, activatedAt, expiresAt, extra = {}) => Object.assign({
  id, username: code, password: code, name, target: 'srv-1', routing: '', limits: gb ? [{ kind: 'total', period: 'none', gb, action: 'cut' }] : [],
  quotaGb: 0, quotaPeriod: 'none', expiresAt, maxDevices: 1, enabled: true, voucher: { batch, hours, activatedAt } }, extra);

/**
 * The router: Sara (a jalali month, eight months of use with gaps, today's
 * meters with a top-up), and two batches — "Guests" (2 h, 1 GB: unused,
 * active, used up, expired) and "Week" made after it (7 days, no data: two
 * unused).
 */
function payload(over = {}) {
  return Object.assign({
    platform: 'openwrt',
    config: { proxy: { enabled: false, port: 30820, httpPort: 30821 }, transparent: { enabled: true, unassigned: 'login', sessionHours: 24, portalPort: 30822 },
      portal: { note: 'Pay at the desk', contact: '0912 000 0000', requests: true } },
    portal: { url: 'http://192.168.1.1:30822/', nameUrl: 'http://login.lan:30822/' },
    lanAddresses: ['192.168.1.1'],
    users: [
      { id: 'usr-a1', username: 'sara', password: 'pa55-Sara', name: 'سارا', target: 'srv-1', routing: '', quotaCalendar: 'jalali',
        limits: [{ kind: 'total', period: 'month', gb: 20, action: 'cut' }], expiresAt: 0, maxDevices: 0, enabled: true },
      voucher('usr-v1', 'ABCD-EF23', 'Guests #1', 'vb-1', 2, 1, 0, 0),
      voucher('usr-v2', 'GHJK-MN45', 'Guests #2', 'vb-1', 2, 1, NOW - 40 * MIN, NOW + 80 * MIN),
      voucher('usr-v3', 'PQRS-TU67', 'Guests #3', 'vb-1', 2, 1, NOW - 60 * MIN, NOW + 60 * MIN),
      voucher('usr-v4', 'VWXY-Z289', 'Guests #4', 'vb-1', 2, 1, NOW - 3 * DAY, NOW - 3 * DAY + 2 * 3600000),
      voucher('usr-v5', 'BCDE-FG34', 'Week #2', 'vb-2', 168, 0, 0, 0),
      voucher('usr-v6', 'CDEF-GH56', 'Week #1', 'vb-2', 168, 0, 0, 0)
    ],
    devices: [],
    usage: {
      'usr-a1': {
        months: [month(jKey(11), 2 * GIB, GIB), month(jKey(9), 5 * GIB, 0), month(jKey(6), 1.5 * GIB, 300 * MB), month(jKey(5), 0, 0),
          month(jKey(3), 7 * GIB, 2 * GIB), month(jKey(2), 4 * GIB, GIB), month(jKey(1), 9 * GIB, 3 * GIB), month(jKey(0), 3 * GIB, 500 * MB)],
        history: [{ day: day(40), vpn: GIB, direct: 0 }, { day: day(1), vpn: 2 * GIB, direct: 100 * MB }, { day: day(0), vpn: 500 * MB, direct: 20 * MB }],
        meters: [{ kind: 'total', period: 'month', bytes: 3.5 * GIB, capBytes: 20 * GIB, extraBytes: 5 * GIB, since: periodRange(jKey(0)).start, until: periodRange(jKey(0)).end, over: false, pct: 14, action: 'cut' },
          { kind: 'vpn', period: 'month', bytes: 3 * GIB, capBytes: 0, extraBytes: 0, since: periodRange(jKey(0)).start, until: periodRange(jKey(0)).end, over: false, pct: 0, action: null },
          { kind: 'direct', period: 'month', bytes: 500 * MB, capBytes: 0, extraBytes: 0, since: periodRange(jKey(0)).start, until: periodRange(jKey(0)).end, over: false, pct: 0, action: null }]
      },
      'usr-v1': { meters: [noneMeter(0, 1)], history: [] },
      'usr-v2': { meters: [noneMeter(300 * MB, 1)], history: [{ day: day(0), vpn: 300 * MB, direct: 0 }] },
      'usr-v3': { meters: [noneMeter(GIB, 1, 0, true)], history: [{ day: day(0), vpn: GIB, direct: 0 }], months: [month(jKey(0), GIB, 0)] },
      'usr-v4': { meters: [noneMeter(200 * MB, 1)], history: [] },
      'usr-v5': { meters: [], history: [] },
      'usr-v6': { meters: [], history: [] }
    }
  }, over);
}

/**
 * The two files in a vm with the real i18n.js, a stub kit over a store, and
 * the window's print, Blob and URL recorded. `answer` replaces the store's
 * answer to an op (a refusal).
 */
function harness({ lang = 'fa', router = true, data = null, confirm = true, qr = true, answer = null, kit: more = {} } = {}) {
  const document = fakeDocument();
  const store = { data: clone(data || payload()) };
  const calls = [];
  const toasts = [];
  const asked = [];
  const copies = [];
  const printed = [];
  const blobs = [];
  const qrs = [];
  const listeners = {};
  let made = 0;
  const window = {
    print() { printed.push(document.body.children.filter((c) => c.classList.contains('lu-printsheet'))); },
    addEventListener(type, fn) { (listeners[type] = listeners[type] || []).push(fn); },
    removeEventListener(type, fn) { listeners[type] = (listeners[type] || []).filter((f) => f !== fn); },
    setTimeout() { return 0; },
    Blob: class { constructor(parts, opts) { this.parts = parts; this.type = opts && opts.type; } },
    URL: { createObjectURL: (b) => { blobs.push(b); return 'blob:x/' + blobs.length; }, revokeObjectURL() {} }
  };
  const qrcode = (n, level) => {
    const q = { data: '', level };
    return { addData: (s) => { q.data = s; }, make: () => qrs.push(q), createDataURL: () => 'data:image/gif;base64,R0lGOD' + qrs.length };
  };
  const ctx = vm.createContext(Object.assign({ window, document, console, URL, setTimeout, clearTimeout }, qr ? { qrcode } : {}));
  vm.runInContext(I18N, ctx, { filename: 'i18n.js' });
  window.i18n.applyI18n(lang);
  const bytes = (n) => { let v = Number(n) || 0; const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0; while (v >= 1024 && i < 4) { v /= 1024; i++; } return (i === 0 ? Math.round(v) : v.toFixed(1)) + ' ' + u[i]; };
  const kit = Object.assign({
    t: (k) => window.i18n.t(k),
    fmtBytes: bytes,
    data: () => store.data,
    users: () => store.data.users.filter((u) => !u.voucher),
    vouchers: () => store.data.users.filter((u) => u.voucher),
    portal: () => store.data.portal,
    isRouter: () => router,
    targets: () => [{ value: 'srv-1', label: 'DE-1' }, { value: 'srv-2', label: 'NL-2' }],
    routingProfiles: () => [{ id: 'rp-work', name: 'Work' }],
    confirm: (msg) => { asked.push(msg); return confirm; },
    toast: (msg, kind) => toasts.push([msg, kind || '']),
    copy: async (text) => { copies.push(text); },
    refresh: async () => { calls.push(['refresh']); },
    async invoke(channel, p) {
      calls.push([channel, clone(p)]);
      if (answer) return clone(answer);
      const d = store.data;
      if (p.op === 'vouchers') {
        const id = 'vb-new' + (++made);
        const codes = [];
        for (let i = 1; i <= p.batch.count; i++) {
          const code = 'N' + String(made) + 'AA-' + String(1000 + i).slice(1);
          codes.push(code);
          d.users.push(voucher('usr-n' + made + '-' + i, code, p.batch.name + ' #' + i, id, p.batch.hours, p.batch.gb, 0, 0));
        }
        return Object.assign(clone(d), { ok: true, batch: { id, codes } });
      }
      if (p.op === 'deleteBatch') {
        d.users = d.users.filter((u) => !(u.voucher && u.voucher.batch === p.batch.id && (!p.unused || !(u.voucher.activatedAt > 0))));
        return Object.assign(clone(d), { ok: true });
      }
      return { ok: false, error: 'op' };
    }
  }, more);
  window.LanUsersKit = kit;
  vm.runInContext(REPORTS, ctx, { filename: 'luReports.js' });
  vm.runInContext(VOUCHERS, ctx, { filename: 'luVouchers.js' });
  const host = document.createElement('div');
  document.body.appendChild(host);
  const t = (k) => window.i18n.t(k);
  const V = window.LuVouchers;
  const Rp = window.LuReports;
  function mount() { const p = V.panel(kit); host.replaceChildren(p); return p; }
  const batch = (id) => host.all((n) => n.classList.contains('lu-vbatch') && n.dataset.batch === id)[0];
  const sheets = () => document.body.children.filter((c) => c.classList.contains('lu-printsheet'));
  const afterprint = () => { for (const fn of [...(listeners.afterprint || [])]) fn(); };
  return { window, document, ctx, host, store, calls, toasts, asked, copies, printed, blobs, qrs, kit, t, V, Rp, mount, batch, sheets, afterprint };
}
/** A Blob's text, as the stub kept its parts. */
const blobText = (b) => b.parts.join('');

/* ------------------------------ the Vouchers tab ------------------------------ */

test('the tab in Persian on the router: the form’s defaults, the batches newest first, each state counted', () => {
  const h = harness();
  const p = h.mount();
  const { t } = h;
  assert.equal(p.one('lu-vch-intro').textContent, t('lu.vch.intro'));
  assert.equal(p.byKey('vch:count').value, '10');
  assert.equal(p.byKey('vch:hours').value, '2');
  assert.equal(p.byKey('vch:hours').getAttribute('dir'), 'ltr');
  assert.equal(p.byKey('vch:devices').value, '1');
  assert.equal(p.byKey('vch:preset:2').getAttribute('aria-pressed'), 'true', 'the time typed is its chip');
  assert.equal(p.byKey('vch:preset:24').getAttribute('aria-pressed'), 'false');
  assert.deepEqual(['vch:preset:1', 'vch:preset:2', 'vch:preset:24', 'vch:preset:168', 'vch:preset:720'].map((k) => p.byKey(k).textContent),
    ['1 ساعت', '2 ساعت', '1 روز', '7 روز', '30 روز'], 'whole days said as days');
  assert.equal(p.byKey('vch:make').textContent, 'ساختِ 10 کارت');
  assert.ok(p.hasKey('vch:down') && p.hasKey('vch:up'), 'a speed on the router');
  // the config and routing every card rides: the kit's configs, the profiles
  assert.deepEqual(p.byKey('vch:target').children.map((o) => o.value), ['', 'direct', 'block', 'srv-1', 'srv-2']);
  assert.deepEqual(p.byKey('vch:routing').children.map((o) => o.value), ['', 'bypass-ir', 'profile:rp-work']);
  assert.equal(p.byKey('vch:routing').children[0].textContent, t('lu.route.router'));

  const list = p.one('lu-vch-list');
  assert.equal(list.one('lu-meta').textContent, '2 دسته · 6 کارت');
  assert.deepEqual(list.byClass('lu-vbatch').map((b) => b.dataset.batch), ['vb-2', 'vb-1'], 'the batch made last on top');
  const g = h.batch('vb-1');
  assert.equal(g.one('lu-vb-name').textContent, 'Guests', 'the label without the card’s number');
  assert.equal(g.one('lu-vb-meta').textContent, '2 ساعت از اولین ورود · 1 GB · دستگاه: 1');
  assert.deepEqual(g.one('lu-vb-counts').children.map((c) => [c.dataset.count, c.textContent]),
    [['unused', '1 استفاده‌نشده'], ['active', '1 فعال'], ['used', '1 تمام‌شده'], ['expired', '1 منقضی']]);
  assert.equal(h.batch('vb-2').one('lu-vb-meta').textContent, '7 روز از اولین ورود · بدون سقفِ حجم · دستگاه: 1');
  assert.deepEqual(h.batch('vb-2').one('lu-vb-counts').children.map((c) => c.dataset.count), ['unused']);
  assert.equal(g.byKey('vch:print:vb-1').textContent, 'چاپِ 1 کارتِ استفاده‌نشده');
  assert.equal(g.byKey('vch:print:vb-1').disabled, false);
  assert.ok(g.hasKey('vch:delUnused:vb-1'), 'some used, some not: delete the unused ones');
  assert.equal(h.batch('vb-2').hasKey('vch:delUnused:vb-2'), false, 'all unused: one delete says it');
  assert.equal(g.byClass('lu-vcodes').length, 0, 'the codes folded');
  assert.equal(p.byClass('lu-vch-note').length, 0, 'the sign-in page is up: nothing to warn of');
});

test('a batch’s codes: each with its state and what it gives, has left, or when it ended; copy', async () => {
  const h = harness();
  h.mount();
  h.host.byKey('vch:codes:vb-1').click();
  const g = h.batch('vb-1');
  assert.equal(h.host.byKey('vch:codes:vb-1').getAttribute('aria-expanded'), 'true');
  const rows = g.one('lu-vcodes').byClass('lu-vcode');
  assert.deepEqual(rows.map((r) => r.dataset.code), ['ABCD-EF23', 'GHJK-MN45', 'PQRS-TU67', 'VWXY-Z289'], 'in their numbers’ order');
  assert.equal(rows[0].one('lu-vc-mono').getAttribute('dir'), 'ltr');
  assert.deepEqual(rows.map((r) => r.one('lu-state').className.split(' ').find((c) => c.startsWith('lu-vs-'))),
    ['lu-vs-unused', 'lu-vs-active', 'lu-vs-used', 'lu-vs-expired']);
  const left = (r) => r.one('lu-vc-left').textContent;
  assert.equal(left(rows[0]), '2 ساعت · 1 GB');
  assert.match(left(rows[1]), /^1 ساعت و 20 دقیقه مانده · 724\.0 MB از 1\.0 GB مانده$/);
  assert.equal(left(rows[2]), 'حجم تمام شد (1.0 GB)', 'spent beats its time still running');
  assert.match(left(rows[3]), /^تمام شد: /);
  h.host.byKey('vch:copy:GHJK-MN45').click();
  await flush();
  assert.deepEqual(h.copies, ['GHJK-MN45']);
  // in English
  const e = harness({ lang: 'en' });
  e.mount();
  e.host.byKey('vch:codes:vb-1').click();
  const er = e.batch('vb-1').byClass('lu-vcode');
  assert.match(er[1].one('lu-vc-left').textContent, /^1 h 20 min left · 724\.0 MB of 1\.0 GB left$/);
  assert.equal(e.batch('vb-1').one('lu-vb-meta').textContent, '2 h from the first sign-in · 1 GB · devices: 1');
  assert.equal(e.host.byKey('vch:make').textContent, 'Make 10 vouchers');
});

test('the new batch: the core’s rules said first, nothing asked until they hold; then op vouchers, opened and marked', async () => {
  const h = harness();
  const p = h.mount();
  const errOf = (k) => h.host.all((n) => n.dataset.err === k)[0].textContent;
  type(p.byKey('vch:count'), '0');
  type(h.host.byKey('vch:hours'), '');
  h.host.byKey('vch:make').click();
  await flush();
  assert.equal(h.calls.length, 0, 'not asked');
  assert.equal(errOf('count'), h.t('lu.vch.err.count'));
  assert.equal(h.host.byKey('vch:count').getAttribute('aria-invalid'), 'true');
  type(h.host.byKey('vch:count'), '201');
  h.host.byKey('vch:make').click();
  await flush();
  assert.equal(errOf('count'), h.t('lu.vch.err.count'), '200 at most');
  type(h.host.byKey('vch:count'), '3');
  assert.equal(errOf('count'), '', 'typing clears it');
  h.host.byKey('vch:make').click();
  await flush();
  assert.equal(h.host.one('lu-vch-ferr').textContent, h.t('lu.vch.err.empty'), 'neither time nor data: not a voucher');
  type(h.host.byKey('vch:hours'), '8761');
  h.host.byKey('vch:make').click();
  await flush();
  assert.equal(errOf('hours'), h.t('lu.vch.err.hours'));
  h.host.byKey('vch:preset:24').click();
  assert.equal(h.host.byKey('vch:hours').value, '24', 'a chip sets the time');
  type(h.host.byKey('vch:gb'), '1.5');
  type(h.host.byKey('vch:devices'), '2');
  type(h.host.byKey('vch:name'), '  Guests, Aban  ');
  h.host.byKey('vch:target').value = 'srv-2';
  h.host.byKey('vch:target').dispatch('change');
  h.host.byKey('vch:routing').value = 'bypass-ir';
  h.host.byKey('vch:routing').dispatch('change');
  type(h.host.byKey('vch:down'), '2');
  assert.equal(h.host.byKey('vch:make').textContent, 'ساختِ 3 کارت');
  h.host.byKey('vch:make').click();
  await flush();
  await flush();
  assert.deepEqual(h.calls, [['lanusers:user', { op: 'vouchers', batch: { count: 3, hours: 24, gb: 1.5, target: 'srv-2', routing: 'bypass-ir', maxDevices: 2, name: 'Guests, Aban', speed: { down: 2000, up: 0 } } }]]);
  const fresh = h.batch('vb-new1');
  assert.ok(fresh.classList.contains('lu-vb-fresh'), 'the batch just made is marked');
  assert.equal(fresh.byClass('lu-vcode').length, 3, 'and open');
  assert.equal(h.host.one('lu-vch-notice').textContent, '3 کارت ساخته شد: «Guests, Aban»');
  assert.deepEqual(h.toasts.at(-1), ['3 کارت ساخته شد: «Guests, Aban»', 'ok']);
  assert.equal(h.host.byKey('vch:name').value, '', 'the label goes; the rest stays for the next batch');
  assert.equal(h.host.byKey('vch:hours').value, '24');
  assert.match(fresh.one('lu-vb-meta').textContent, /^ساخته‌شده /, 'made in this window: its date');
  // a bad speed; the label left empty is "Cards of <today>"; no speed off the router
  type(h.host.byKey('vch:down'), 'fast');
  h.host.byKey('vch:make').click();
  await flush();
  assert.equal(errOf('speed'), h.t('lu.vch.err.speed'));
  const at = new Date(2026, 9, 29).getTime();
  const v = h.V.validateBatch({ count: '5', hours: '2', gb: '', devices: '', name: '', target: '', routing: '' }, false, at);
  assert.deepEqual(Object.keys(v.errors), []);
  assert.equal(v.batch.maxDevices, 1, 'one device per card when empty');
  assert.equal(v.batch.name, 'کارت‌های ' + new Intl.DateTimeFormat('fa-IR-u-nu-latn', { month: 'long', day: 'numeric' }).format(new Date(at)));
  assert.equal('speed' in v.batch, false);
  assert.equal(h.V.validateBatch({ count: '1', hours: '0', gb: '0.5', name: 'x'.repeat(65) }, false).errors.name, 'lu.vch.err.name');
});

test('a refusal is said in the form, in the page’s language; an answer without the payload is read again', async () => {
  const h = harness({ answer: { ok: false, error: 'lu.err.voucher' } });
  h.mount().byKey('vch:make').click();
  await flush();
  await flush();
  assert.equal(h.host.one('lu-vch-ferr').textContent, h.t('lu.saveFailed') + ': ' + h.t('lu.vch.err.voucher'));
  assert.equal(h.toasts.at(-1)[1], 'err');
  const r = harness({ answer: { ok: true, batch: { id: 'vb-x', codes: ['AAAA-BBBB'] } } });
  r.mount().byKey('vch:make').click();
  await flush();
  await flush();
  assert.deepEqual(r.calls.map((c) => c[0]), ['lanusers:user', 'refresh']);
});

test('delete after asking: the unused ones of a batch, or the whole batch; a no asks nothing of the core', async () => {
  const h = harness({ confirm: false });
  h.mount();
  h.host.byKey('vch:delUnused:vb-1').click();
  await flush();
  assert.deepEqual(h.asked, ['1 کارتِ استفاده‌نشدهٔ «Guests» حذف شود؟']);
  assert.equal(h.calls.length, 0);
  const y = harness();
  y.mount();
  y.host.byKey('vch:delUnused:vb-1').click();
  await flush();
  await flush();
  assert.deepEqual(y.calls, [['lanusers:user', { op: 'deleteBatch', batch: { id: 'vb-1' }, unused: true }]]);
  assert.equal(y.batch('vb-1').one('lu-vb-counts').children.some((c) => c.dataset.count === 'unused'), false);
  assert.equal(y.toasts.at(-1)[0], '1 کارت حذف شد');
  y.host.byKey('vch:delBatch:vb-2').click();
  await flush();
  await flush();
  assert.match(y.asked.at(-1), /^همهٔ 2 کارتِ «Week» حذف شود؟/);
  assert.deepEqual(y.calls.at(-1), ['lanusers:user', { op: 'deleteBatch', batch: { id: 'vb-2' }, unused: false }]);
  assert.equal(y.batch('vb-2'), undefined);
});

/* ------------------------------ the printed cards ------------------------------ */

test('print: the unused cards, eight to an A4 page, each the code, its time and data, the address and a QR with ?code=', async () => {
  const h = harness();
  const p = h.mount();
  type(p.byKey('vch:count'), '10');
  type(h.host.byKey('vch:gb'), '2');
  h.host.byKey('vch:make').click();
  await flush();
  await flush();
  h.host.byKey('vch:print:vb-new1').click();
  assert.equal(h.printed.length, 1, 'printed once');
  const [sheet] = h.printed[0];
  assert.ok(sheet.classList.contains('lu-vcards') && sheet.getAttribute('dir') === 'rtl');
  assert.ok(h.document.documentElement.classList.contains('lu-printing'), 'the rest of the page hidden while it prints');
  const pages = sheet.byClass('lu-vc-page');
  assert.deepEqual(pages.map((pg) => pg.byClass('lu-vc-card').length), [8, 2]);
  const cards = sheet.byClass('lu-vc-card');
  const c1 = cards[0];
  assert.equal(c1.one('lu-vc-code').textContent, 'N1AA-001');
  assert.equal(c1.one('lu-vc-code').getAttribute('dir'), 'ltr');
  assert.equal(c1.one('lu-vc-title').textContent, 'کارت اینترنتInternet card', 'Persian, English beneath');
  assert.equal(c1.one('lu-vc-spec').textContent, '2 ساعت از اولین ورود · 2 GB2 hours from the first sign-in · 2 GB');
  assert.deepEqual(c1.byClass('lu-vc-url').map((u) => u.textContent), ['http://login.lan:30822/', 'http://192.168.1.1:30822/']);
  assert.match(c1.one('lu-vc-label').textContent, / · #1$/);
  assert.equal(h.qrs.length, 10);
  assert.equal(h.qrs[0].data, 'http://192.168.1.1:30822/?code=N1AA-001', 'the numeric address: no DNS needed');
  assert.ok(c1.one('lu-vc-qr').src.startsWith('data:image/gif'));
  h.afterprint();
  assert.equal(h.sheets().length, 0, 'gone after');
  assert.equal(h.document.documentElement.classList.contains('lu-printing'), false);
  // the Guests batch: only its one unused card
  h.host.byKey('vch:print:vb-1').click();
  assert.deepEqual(h.printed[1][0].byClass('lu-vc-card').map((c) => c.dataset.code), ['ABCD-EF23']);
  assert.equal(h.V.codeUrl('http://login.lan:30822/', 'AB CD'), 'http://login.lan:30822/?code=AB+CD');
});

test('print without the sign-in page: no QR, the card says how; on a PC the card is a proxy account', () => {
  const h = harness({ data: payload({ portal: null }) });
  h.mount();
  assert.equal(h.host.one('lu-vch-note').textContent, h.t('lu.vch.noPortal'));
  h.host.byKey('vch:print:vb-2').click();
  const card = h.printed[0][0].byClass('lu-vc-card')[0];
  assert.equal(card.byClass('lu-vc-qr').length, 0);
  assert.equal(card.one('lu-vc-how').textContent, 'این کد را در صفحهٔ ورود بزنید.Enter this code on the sign-in page.');
  assert.equal(card.one('lu-vc-spec').textContent, '7 روز از اولین ورود · بدون سقفِ حجم7 days from the first sign-in · no data cap');
  const pc = harness({ router: false, data: payload({ portal: null, platform: 'win32', lanAddresses: ['192.168.1.20', 'fd00::20'],
    config: { proxy: { enabled: true, port: 30820, httpPort: 30821 }, transparent: { enabled: false } } }) });
  pc.mount();
  assert.equal(pc.host.one('lu-vch-note').textContent, pc.t('lu.vch.desktopNote'));
  assert.equal(pc.host.hasKey('vch:down'), false, 'the speed is the router’s');
  assert.equal(pc.host.byKey('vch:routing').children[0].textContent, pc.t('lu.route.all'));
  pc.host.byKey('vch:print:vb-2').click();
  const pcCard = pc.printed[0][0].byClass('lu-vc-card')[0];
  assert.equal(pcCard.one('lu-vc-how').textContent, 'نام کاربری و رمز: همین کدUsername and password: this code');
  assert.deepEqual(pcCard.byClass('lu-vc-url').map((u) => u.textContent), ['SOCKS5 192.168.1.20:30820']);
});

/* ------------------------------ the 12 months ------------------------------ */

test('the 12-month chart: the user’s Persian months, gaps as empty slots, a bar a month with its numbers', () => {
  const h = harness();
  const sara = h.store.data.users[0];
  const box = h.Rp.monthsChart(sara, h.store.data.usage);
  assert.equal(box.dataset.months, 'usr-a1');
  const labels = box.one('lu-mc-labels');
  assert.equal(labels.getAttribute('dir'), 'ltr', 'time runs left to right, as on the 30-day chart');
  const cells = labels.byClass('lu-mc-label');
  assert.equal(cells.length, 12);
  const keys = Array.from({ length: 12 }, (_, i) => jKey(11 - i));
  assert.deepEqual(cells.map((c) => c.dataset.key), keys, 'twelve months up to the running one, none missing');
  // each name is the Persian calendar's own, as the window's Intl says it for a day of that month
  const faName = (key) => new Intl.DateTimeFormat('fa-IR-u-nu-latn', { month: 'long' }).format(new Date(periodRange(key).start + 12 * 3600000));
  assert.deepEqual(cells.map((c) => c.one('lu-mc-m').textContent), keys.map(faName));
  assert.ok(cells[11].classList.contains('lu-mc-now'), 'the running month marked');
  assert.equal(cells[0].one('lu-mc-y').textContent, keys[0].slice(1, 5), 'the first month carries its year');
  const bars = box.byClass('lu-cbar');
  assert.equal(bars.length, 12);
  assert.equal(box.byClass('lu-cvpn').length, 7, 'a VPN bar for each month that had VPN');
  assert.equal(box.byClass('lu-cdirect').length, 6);
  const last = bars[11].all((n) => n.tagName === 'title')[0].textContent;
  assert.match(last, new RegExp('^' + faName(jKey(0)) + ' ' + keys[11].slice(1, 5) + ' — VPN 3\\.0 GB · مستقیم 500\\.0 MB \\('));
  assert.equal(bars[1].all((n) => n.tagName === 'rect').length, 1, 'a month nothing was used in: its slot alone');
  assert.match(box.one('lu-mc-svg').getAttribute('aria-label'), /^مصرفِ 12 ماهِ گذشته: VPN 31\.5 GB، مستقیم 7\.8 GB$/);
  // in English: the Persian months by their names
  const e = harness({ lang: 'en' });
  const enCells = e.Rp.monthsChart(sara, e.store.data.usage).byClass('lu-mc-label');
  assert.deepEqual(enCells.map((c) => c.one('lu-mc-m').textContent),
    keys.map((k) => new Intl.DateTimeFormat('en-u-ca-persian', { month: 'long' }).format(new Date(periodRange(k).start + 12 * 3600000))));
  // nothing yet: the line that says so
  const empty = h.Rp.monthsChart({ id: 'usr-v1' }, h.store.data.usage);
  assert.equal(empty.one('lu-mc-empty').textContent, h.t('lu.rep.noMonths'));
  // the user's usage alone works too, and the kit's when none is handed in
  assert.equal(h.Rp.monthsChart(sara, h.store.data.usage['usr-a1']).byClass('lu-cbar').length, 12);
  assert.equal(h.Rp.monthsChart(sara).byClass('lu-cbar').length, 12);
});

test('a Gregorian user renewing on the 15th: Gregorian names; mixed calendars are shown as they are', () => {
  const h = harness({ lang: 'en' });
  const months = [month('2026-08@15', GIB, 0), month('2026-10@15', 2 * GIB, GIB)];
  const box = h.Rp.monthsChart({ id: 'x' }, { months });
  const cells = box.byClass('lu-mc-label');
  assert.equal(cells.length, 12);
  assert.deepEqual(cells.slice(-3).map((c) => [c.dataset.key, c.one('lu-mc-m').textContent]), [['2026-08@15', 'Aug'], ['2026-09@15', 'Sep'], ['2026-10@15', 'Oct']]);
  assert.equal(cells.find((c) => c.dataset.key === '2026-01@15').one('lu-mc-y').textContent, '2026', 'January opens a year');
  const mixed = h.Rp.monthSlots([month('2026-09', 1, 0), month('j1405-08', 2, 0)]);
  assert.deepEqual(mixed.map((s) => s.key), ['2026-09', 'j1405-08']);
  assert.equal(h.Rp.stepKey('j1405-01@31', -1), 'j1404-12@31');
  assert.equal(h.Rp.stepKey('2026-12', 1), '2027-01');
  assert.equal(h.Rp.parseKey('2026-13'), null);
});

test('a month’s name: the middle of every Persian month of 1380–1450 is that month (src/main/jalali.js)', () => {
  const Rn = require('../src/renderer/luReports.js');
  for (let y = 1380; y <= 1450; y++) {
    for (let m = 1; m <= 12; m++) {
      const d = Rn.midJalali(y, m);
      assert.deepEqual(J.toJalali(d.getFullYear(), d.getMonth() + 1, d.getDate()).jm, m, `${y}/${m}`);
    }
  }
});

/* ------------------------------ CSV ------------------------------ */

test('csv(user): UTF-8 with a BOM, the header in the page’s language, a row per month then per day, bytes and GB', () => {
  const h = harness();
  const sara = h.store.data.users[0];
  assert.equal(h.Rp.csv(sara), true);
  assert.equal(h.blobs.length, 1);
  const b = h.blobs[0];
  assert.equal(b.type, 'text/csv;charset=utf-8');
  const text = blobText(b);
  assert.ok(text.startsWith('﻿'), 'a BOM: Excel reads Persian with one');
  const lines = text.slice(1).split('\r\n');
  assert.equal(lines.at(-1), '', 'CRLF lines, the last one ended');
  assert.equal(lines[0], 'نام کاربری,نام,نوع,دوره,عنوان,از,تا,VPN (بایت),مستقیم (بایت),کل (بایت),VPN (GB),مستقیم (GB),کل (GB)');
  const rows = lines.slice(1, -1).map((l) => l.split(','));
  assert.equal(rows.length, 8 + 3, 'eight months and three days');
  const first = rows[0];
  const r0 = periodRange(jKey(11));
  const iso = (ms) => { const d = new Date(ms); return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0'); };
  assert.deepEqual(first, ['sara', 'سارا', 'ماه', jKey(11), first[4], iso(r0.start), iso(r0.end - 1), String(2 * GIB), String(GIB), String(3 * GIB), '2.000', '1.000', '3.000']);
  assert.match(first[4], new RegExp(' ' + jKey(11).slice(1, 5) + '$'), 'the month’s name and year');
  const lastDay = rows.at(-1);
  assert.deepEqual(lastDay.slice(0, 4), ['sara', 'سارا', 'روز', day(0)]);
  assert.deepEqual(lastDay.slice(5), [day(0), day(0), String(500 * MB), String(20 * MB), String(520 * MB), '0.488', '0.020', '0.508']);
  // the file's name; the link was in the page for its click alone
  const a = [];
  const e = harness({ lang: 'en' });
  const orig = e.document.createElement;
  e.document.createElement = (tag) => { const n = orig(tag); if (tag === 'a') { a.push(n); n.click = () => a.push(['clicked', n.download, !!n.parentNode]); } return n; };
  e.Rp.csv(e.store.data.users[0]);
  assert.deepEqual(a[1], ['clicked', 'irnetfree-usage-sara-' + day(0) + '.csv', true]);
  assert.equal(a[0].parentNode, null, 'taken out after');
  assert.match(blobText(e.blobs[0]).split('\r\n')[0], /^﻿Username,Name,Kind,Period,Label,From,To,VPN \(bytes\)/);
});

test('a CSV field: quoted with a comma or a quote, and a name that starts like a formula defused', () => {
  const h = harness();
  const text = h.Rp.csvText(h.Rp.rowsOf({ id: 'q', username: 'u1', name: '=HYPERLINK("x"), "y"' }, { history: [{ day: day(0), vpn: 1, direct: 0 }] }));
  const row = text.split('\r\n')[1];
  assert.ok(row.startsWith('u1,"\'=HYPERLINK(""x""), ""y""",روز,'), row);
});

test('csvAll: every user, then the vouchers that were used — one file', () => {
  const h = harness({ lang: 'en' });
  assert.equal(h.Rp.csvAll(), true);
  const lines = blobText(h.blobs[0]).split('\r\n').slice(1, -1);
  const who = [...new Set(lines.map((l) => l.split(',')[0]))];
  assert.deepEqual(who, ['sara', 'GHJK-MN45', 'PQRS-TU67'], 'an unused voucher has no rows');
  assert.equal(lines.filter((l) => l.startsWith('PQRS-TU67,')).length, 2, 'its month and its day');
});

/* ------------------------------ the statement ------------------------------ */

test('printBill: the running month — who, its dates, VPN / direct / total, its limits and top-ups, its days, the admin’s contact', () => {
  const h = harness();
  const sara = h.store.data.users[0];
  assert.equal(h.Rp.printBill(sara), true);
  const [sheet] = h.printed[0];
  assert.ok(sheet.classList.contains('lu-bill'));
  assert.equal(sheet.getAttribute('dir'), 'rtl');
  assert.equal(sheet.dataset.key, jKey(0), 'no key: the newest month');
  assert.equal(sheet.one('lu-bill-title').textContent, h.t('lu.rep.billTitle'));
  const kv = sheet.one('lu-bill-kv').byClass('lu-bill-num').map((n) => n.textContent);
  assert.equal(kv[0], 'سارا');
  assert.equal(kv[1], 'sara');
  assert.match(kv[2], / تا /, 'the period with its first and last day');
  const use = sheet.one('lu-bill-use').byClass('lu-bill-num').map((n) => n.textContent);
  assert.deepEqual(use, ['3.0 GB', '3.000 GB', '500.0 MB', '0.488 GB', '3.5 GB', '3.488 GB']);
  assert.ok(sheet.textContent.includes(h.t('lu.rep.running')), 'a month not over says so');
  const caps = sheet.one('lu-bill-caps').byClass('lu-bill-num').map((n) => n.textContent);
  assert.deepEqual(caps, ['3.5 GB از 25.0 GB', 'شارژِ اضافه +5.0 GB'], 'the cap with its top-up');
  const days = sheet.one('lu-bill-days');
  assert.ok(days.byClass('lu-bill-num').length >= 3, 'the month’s days from the 30-day history');
  assert.equal(days.textContent.includes(new Intl.DateTimeFormat('fa-IR-u-nu-latn', { year: 'numeric', month: 'long', day: 'numeric' }).format(new Date(NOW))), true);
  const foot = sheet.one('lu-bill-foot');
  assert.ok(foot.textContent.includes('Pay at the desk'));
  assert.equal(foot.one('lu-bill-contact').textContent, '0912 000 0000');
  h.afterprint();
  assert.equal(h.sheets().length, 0);
});

test('printBill: a past month has no limits (none are kept), a month nothing was used in says so', () => {
  const h = harness({ lang: 'en' });
  const sara = h.store.data.users[0];
  h.Rp.printBill(sara, jKey(3));
  const [sheet] = h.printed[0];
  assert.equal(sheet.getAttribute('dir'), 'ltr');
  assert.equal(sheet.byClass('lu-bill-caps').length, 0);
  assert.equal(sheet.textContent.includes(h.t('lu.rep.running')), false);
  assert.deepEqual(sheet.one('lu-bill-use').byClass('lu-bill-num').map((n) => n.textContent).slice(0, 2), ['7.0 GB', '7.000 GB']);
  h.Rp.printBill(sara, jKey(5));
  assert.ok(h.printed[1][0].textContent.includes(h.t('lu.rep.noUse')));
  assert.equal(h.sheets().length, 1, 'one sheet at a time');
  assert.deepEqual(h.Rp.monthList(sara).map((m) => m.key).slice(0, 2), [jKey(0), jKey(1)], 'a picker’s months, newest first');
});

/* ------------------------------ the stylesheet, the words, the markup ------------------------------ */

test('every class the two files build is styled — tokens only, logical properties only, the paper’s own ink', () => {
  const settings = R('src', 'renderer', 'settings.css');
  const cls = new Set();
  for (const src of [VOUCHERS, REPORTS]) {
    for (const m of src.matchAll(/(?:el|button)\('[a-z0-9]+', '([^']+)'/g)) m[1].split(/\s+/).forEach((c) => cls.add(c));
    for (const m of src.matchAll(/class: '([^']+)'/g)) m[1].split(/\s+/).forEach((c) => cls.add(c));
  }
  for (const c of ['lu-vs-unused', 'lu-vs-active', 'lu-vs-used', 'lu-vs-expired', 'lu-vb-fresh', 'lu-mc-now', 'lu-csw-vpn', 'lu-csw-direct', 'lu-dim']) cls.add(c);
  // the two cards' own names are hooks (their look is .lu-card's), as the Users page's blocks are
  const own = [...cls].filter((c) => c.startsWith('lu-') && c !== 'lu-vs-' && !['lu-vch-new', 'lu-vch-list'].includes(c));
  assert.ok(own.length >= 45, `found ${own.length}`);
  for (const c of own) assert.match(CSS + settings, new RegExp('\\.' + c + '(?![\\w-])'), `.${c} has no style`);
  assert.doesNotMatch(CSS, /#[0-9a-f]{3,8}\b(?![\w-])|rgba?\(|hsla?\(/i, 'no literal colours: the skins pick them');
  assert.doesNotMatch(CSS, /(?:margin|padding|border)-(?:left|right)|text-align:\s*(?:left|right)|\b(?:left|right):/, 'logical properties only: the app runs RTL');
  const paper = CSS.slice(CSS.indexOf('@media print'));
  assert.doesNotMatch(paper, /var\(--/, 'on paper: currentColor, never a skin’s token (a dark skin’s ink is light)');
  assert.match(CSS, /@page luvc \{ size: A4 portrait;/);
  assert.match(CSS, /\.lu-vc-page \{ display: grid; grid-template-columns: repeat\(2, minmax\(0, 1fr\)\); grid-auto-rows: 70mm;/, 'eight to a page: 2 × 4');
});

test('the words: every key in both languages exactly once, right after lu.sessionHours, no ASCII apostrophe', () => {
  const keys = new Set();
  for (const src of [VOUCHERS, REPORTS]) for (const m of src.matchAll(/'(lu\.(?:vch|rep)\.[A-Za-z0-9.]*[A-Za-z0-9])'/g)) keys.add(m[1]);
  for (const c of ['username', 'name', 'kind', 'period', 'label', 'from', 'to', 'vpn', 'direct', 'total', 'vpnGb', 'directGb', 'totalGb']) keys.add('lu.rep.col.' + c);
  for (const s of ['unused', 'active', 'used', 'expired']) keys.add('lu.vch.st.' + s);
  for (const k of ['month', 'day']) keys.add('lu.rep.kind.' + k);
  for (const k of ['batch', 'voucher']) keys.add('lu.vch.err.' + k);
  // the page's (lanUsers.js) keys these files use
  for (const k of ['lu.copy', 'lu.copied', 'lu.copyFailed', 'lu.saveFailed', 'lu.loading', 'lu.target', 'lu.routing', 'lu.usage', 'lu.limits', 'lu.name', 'lu.username',
    'lu.thisMonth', 'lu.oneOff', 'lu.speedDown', 'lu.speedUp', 'lu.unlimited', 'lu.state.off', 'lu.kind.vpn', 'lu.kind.direct', 'lu.kind.total']) keys.add(k);
  assert.ok(keys.size > 90, `found ${keys.size}`);
  const bad = [...keys].filter((k) => (I18N.split(`'${k}':`).length - 1) !== 2).sort();
  assert.deepEqual(bad, [], 'not defined exactly once in each of fa and en');
  const lines = I18N.split('\n');
  for (const at of lines.map((l, i) => [l, i]).filter(([l]) => l.includes("'lu.sessionHours':")).map(([, i]) => i)) {
    assert.match(lines[at + 1], /luVouchers\.js/, 'the block right after lu.sessionHours');
    const block = lines.slice(at + 1, lines.findIndex((l, i) => i > at && l.includes("'lu.list':"))).join('\n');
    assert.ok(block.includes("'lu.vch.intro':") && block.includes("'lu.rep.contact':"));
    assert.doesNotMatch(block, /'[^'\n]*[a-z]'[a-z][^'\n]*'/i, 'no ASCII apostrophe inside a string');
  }
});

test('the markup: the stylesheet after settings.css, the two scripts after lanUsers.js and before app.js', () => {
  const html = R('src', 'renderer', 'index.html');
  const links = [...html.matchAll(/<link rel="stylesheet" href="([^"]+)"/g)].map((m) => m[1]);
  assert.equal(links.indexOf('lanUsersExtra.css'), links.indexOf('settings.css') + 1);
  const scripts = [...html.matchAll(/<script src="([^"]+)"><\/script>/g)].map((m) => m[1]);
  const at = (s) => scripts.indexOf(s);
  assert.ok(at('i18n.js') < at('lanUsers.js') && at('lanUsers.js') < at('luReports.js') && at('luReports.js') < at('luVouchers.js') && at('luVouchers.js') < at('app.js'), scripts.join(', '));
  assert.ok(at('vendor/qrcode.js') < at('luVouchers.js'), 'the QR maker first');
});
