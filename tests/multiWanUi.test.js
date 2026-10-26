'use strict';
/**
 * The multi-internet Settings card (src/renderer/multiWan.js) — the same
 * renderer on the desktop and on the router's page. The file runs in a vm over
 * a DOM of plain objects, with the REAL i18n.js beside it, so every string on
 * the card is checked in Persian and in English; window.api is a fake whose
 * answers the test holds. Drawn as the approved mockup: the switch, the three
 * mode cards, a row per internet (icon, name, address left to right, state,
 * last test, role / share / cap and the usage bar), the split pickers only in
 * split mode, the live share bars only while connected, "test each internet"
 * with its progress per internet, "find again" with its spinner, the note.
 * Every change is saved at once through app.js's hook.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { normalizeMultiWan } = require('../src/main/multiWan');

const R = (...p) => fs.readFileSync(path.join(__dirname, '..', ...p), 'utf8').replace(/\r\n/g, '\n');
const CARD = R('src', 'renderer', 'multiWan.js');
const I18N = R('src', 'renderer', 'i18n.js');
const GIB = 1024 ** 3;

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
  prepend(...nodes) { const old = this.childNodes; this.childNodes = []; this.append(...nodes); for (const o of old) this.childNodes.push(o); }
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
  dispatch(type) { const ev = { type, target: this, preventDefault() {} }; for (const fn of [...(this.listeners[type] || [])]) fn(ev); }
  click() { if (!this.disabled) this.dispatch('click'); }
  focus() { this.ownerDocument.activeElement = this; }
  contains(n) { for (let x = n; x; x = x.parentNode) if (x === this) return true; return false; }
  hiddenUp() { for (let n = this; n && n.nodeType === 1; n = n.parentNode) if (n.hidden) return true; return false; }
  all(pred, out = []) { for (const c of this.childNodes) if (c.nodeType === 1) { if (pred(c)) out.push(c); c.all(pred, out); } return out; }
  byClass(c) { return this.all((n) => n.classList.contains(c)); }
  one(c) { const r = this.byClass(c); assert.equal(r.length, 1, `.${c}: ${r.length} found`); return r[0]; }
  byKey(k) { const r = this.all((n) => n.dataset.mi === k); assert.equal(r.length, 1, `[data-mi=${k}]: ${r.length} found`); return r[0]; }
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
  return doc;
}

/* ------------------------------ the card in a vm ------------------------------ */

const until = (ms) => new Date(ms).getTime();
/** What multiwan:get answers — the mockup's two internets, and a configured one not connected now. */
function answer(over = {}) {
  const settings = normalizeMultiWan(Object.assign({
    enabled: true, mode: 'balance',
    links: [
      { id: 'Wi-Fi', iface: 'Wi-Fi', name: 'Wi-Fi — Home', role: 'use', weight: 3, quotaGb: 100, quotaPeriod: 'month' },
      { id: 'usb', iface: 'Ethernet 3', name: 'Phone (USB)', role: 'use', weight: 2, quotaGb: 3, quotaPeriod: 'day' },
      { id: 'eth0', iface: 'eth0', name: 'Office cable', role: 'off', weight: 2, quotaGb: 0, quotaPeriod: 'none' }
    ]
  }, over.settings || {}));
  return {
    settings,
    links: over.links || [
      { id: 'Wi-Fi', iface: 'Wi-Fi', name: 'Wi-Fi — Home', kind: 'wifi', address: '192.168.1.34', gateway: '192.168.1.1', present: true, configured: true, test: { id: 'Wi-Fi', ok: true, downMbps: 48.2, upMbps: 3.1 } },
      { id: 'usb', iface: 'Ethernet 3', name: 'Phone (USB)', kind: 'usb', address: '192.168.42.129', gateway: '192.168.42.1', present: true, configured: true, test: { id: 'usb', ok: true, downMbps: 14.6, upMbps: 21.4 } },
      { id: 'eth0', iface: 'eth0', name: 'Office cable', kind: 'ethernet', address: '', gateway: '', present: false, configured: true, test: null }
    ],
    usage: over.usage || {
      'Wi-Fi': { bytes: 34.2 * GIB, period: '2026-10', since: until(new Date(2026, 9, 1)), until: until(new Date(2026, 10, 1)), quotaBytes: 100 * GIB, over: false },
      usb: { bytes: 2.6 * GIB, period: '2026-10-25', since: until(new Date(2026, 9, 25)), until: until(new Date(2026, 9, 26)), quotaBytes: 3 * GIB, over: false },
      eth0: { bytes: 0, period: '2026-10', since: 0, until: until(new Date(2026, 10, 1)), quotaBytes: 0, over: false }
    },
    live: over.live || {}
  };
}

function deferred() { let resolve, reject; const p = new Promise((a, b) => { resolve = a; reject = b; }); return { p, resolve, reject }; }
const flush = () => new Promise((r) => setImmediate(r));

function harness({ connected = false, lang = 'fa', api = {}, saveFails = false } = {}) {
  const document = fakeDocument();
  const calls = [];
  const pending = { get: [], test: [] };
  const saves = [];
  const toasts = [];
  const state = { connected, stored: answer().settings };
  const window = {
    api: Object.assign({
      multiWanGet: () => { calls.push(['get']); const d = deferred(); pending.get.push(d); return d.p; },
      multiWanTest: (ids) => { calls.push(['test', JSON.parse(JSON.stringify(ids))]); const d = deferred(); pending.test.push(d); return d.p; }
    }, api)
  };
  const ctx = vm.createContext({ window, document, console, setTimeout, clearTimeout });
  vm.runInContext(I18N, ctx, { filename: 'i18n.js' });
  vm.runInContext(CARD, ctx, { filename: 'multiWan.js' });
  window.i18n.applyI18n(lang);
  const host = document.createElement('div');
  host.id = 'multiWanCard';
  document.body.appendChild(host);
  const hooks = {
    // what app.js's saveMultiWan answers: the service's normalized multiWan
    save: async (partial) => {
      saves.push(JSON.parse(JSON.stringify(partial)));
      if (saveFails) throw new Error('disk full');
      const cur = state.stored;
      state.stored = normalizeMultiWan(Object.assign({}, cur, partial, { split: Object.assign({}, cur.split, partial.split || {}) }));
      return { multiWan: state.stored, pendingReconnect: [] };
    },
    connected: () => state.connected,
    settings: () => state.stored,
    toast: (msg, kind) => toasts.push([msg, kind || ''])
  };
  const card = window.multiWanCard;
  card.mount(host, hooks);
  const t = (k) => window.i18n.t(k);
  /** refresh() answered with `res`. */
  async function load(res = answer()) {
    const p = card.refresh();
    pending.get.at(-1).resolve(res);
    await p;
  }
  const row = (id) => host.all((n) => n.classList.contains('mi-net') && n.dataset.link === id)[0];
  return { window, document, host, card, hooks, calls, pending, saves, toasts, state, t, load, row };
}

const fa = (k) => { const h = harness(); return h.t(k); };

/* ------------------------------ drawing ------------------------------ */

test('the card as the mockup draws it, in Persian: the switch, three mode cards, a row per internet, the note', async () => {
  const h = harness();
  assert.equal(h.host.one('switch-title').textContent, 'ترکیب اینترنت‌ها', 'drawn before the internets are read');
  assert.ok(h.host.textContent.includes(h.t('mi.loading')));
  await h.load();
  const { host, t } = h;
  assert.equal(host.byKey('enabled').checked, true);
  assert.equal(host.one('mi-body').hidden, false);
  assert.equal(host.one('switch-sub').textContent, t('mi.sub'));

  const modes = host.byClass('mi-mode');
  assert.deepEqual(modes.map((m) => m.dataset.mode), ['balance', 'failover', 'split']);
  assert.deepEqual(modes.map((m) => m.children[0].textContent), ['ترکیب', 'پشتیبان', 'آپلود و دانلود جدا']);
  assert.deepEqual(modes.map((m) => m.children[1].textContent), [t('mi.mode.balanceSub'), t('mi.mode.failoverSub'), t('mi.mode.splitSub')]);
  assert.deepEqual(modes.map((m) => [m.classList.contains('on'), m.getAttribute('aria-pressed')]), [[true, 'true'], [false, 'false'], [false, 'false']]);

  assert.equal(host.byClass('mi-net').length, 3);
  const wifi = h.row('Wi-Fi');
  assert.equal(wifi.one('mi-ic').textContent, '📶');
  assert.equal(wifi.one('mi-name').textContent, 'Wi-Fi — Home');
  assert.equal(wifi.one('mi-meta').textContent, '192.168.1.34 · gw 192.168.1.1');
  assert.equal(wifi.one('mi-meta').getAttribute('dir'), 'ltr', 'addresses run left to right in Persian too');
  assert.equal(wifi.one('mi-ok').textContent, '● اینترنت دارد');
  const spd = wifi.one('mi-spd');
  assert.equal(spd.getAttribute('dir'), 'ltr');
  assert.deepEqual(spd.children.map((c) => c.textContent), ['↓ 48.2', '↑ 3.1', 'Mbps']);
  assert.equal(h.row('usb').one('mi-ic').textContent, '📱');

  // its role, share and cap, as configured
  assert.equal(host.byKey('role:Wi-Fi').value, 'use');
  assert.deepEqual(host.byKey('role:Wi-Fi').children.map((o) => o.textContent), ['در ترکیب', 'فقط پشتیبان', 'استفاده نشود']);
  assert.equal(host.byKey('weight:Wi-Fi').value, '3');
  assert.deepEqual(host.byKey('weight:Wi-Fi').children.map((o) => o.textContent), ['زیاد (3×)', 'عادی', 'کم']);
  assert.equal(host.byKey('quota:Wi-Fi').value, '100');
  assert.equal(host.byKey('quota:Wi-Fi').getAttribute('dir'), 'ltr');
  assert.equal(host.byKey('period:Wi-Fi').value, 'month');
  assert.deepEqual(host.byKey('period:Wi-Fi').children.map((o) => o.textContent), ['GB در ماه شمسی', 'GB در ماه میلادی', 'GB در روز', 'بدون سقف'], 'the Persian month first in Persian');
  assert.equal(host.byKey('renew:Wi-Fi').value, '1', 'a link saved before the calendar choice: the Gregorian month from the 1st');
  assert.equal(host.byKey('renew:Wi-Fi').parentNode.hidden, false);
  assert.equal(host.byKey('renew:usb').parentNode.hidden, true, 'a day: no renew day');
  assert.ok(wifi.byClass('field-label').map((l) => l.textContent).join('|').startsWith('نقش|سهم|سقف حجم'));

  // the period's usage against the cap, and when the period ends
  const bar = wifi.one('mi-bar');
  assert.equal(bar.hidden, false);
  assert.equal(bar.children[0].style.width, '34.2%');
  assert.equal(bar.children[0].className, '');
  const [left, right] = wifi.one('mi-quota').children;
  assert.equal(left.textContent, '34.2 GB از 100.0 GB');
  assert.equal(right.textContent, 'تا ' + h.card.format.dateText(answer().usage['Wi-Fi'].until));
  assert.ok(h.card.format.dateText(answer().usage['Wi-Fi'].until).length > 0);
  // near the cap: amber, and it says what happens at the cap
  const usb = h.row('usb');
  assert.equal(usb.one('mi-bar').children[0].className, 'warn');
  assert.deepEqual(usb.one('mi-quota').children.map((c) => c.textContent), ['2.6 GB از 3.0 GB — نزدیک سقف', 'رسید → کنار گذاشته می‌شود']);
  // a configured internet that is not connected now: dimmed, said, no cap bar
  const gone = h.row('eth0');
  assert.ok(gone.classList.contains('mi-gone'));
  assert.equal(gone.one('mi-off').textContent, '○ الان وصل نیست');
  assert.equal(gone.one('mi-bar').hidden, true);
  assert.equal(host.byKey('quota:eth0').disabled, true, 'no period: nothing to type a cap for');
  assert.deepEqual(gone.one('mi-quota').children.map((c) => c.textContent), ['0 B مصرف شده', 'این ماه']);
  assert.deepEqual(gone.one('mi-spd').children.map((c) => c.textContent), ['تست نشده']);

  assert.equal(host.byClass('mi-splitbox').length, 0, 'the split pickers only in split mode');
  assert.equal(host.one('mi-live').hidden, true, 'the live bars only while connected');
  assert.equal(host.byClass('mi-shared').length, 0);
  assert.deepEqual(host.one('mi-actions').children.map((b) => [b.textContent, b.className, b.disabled]), [
    ['تست سرعت هر اینترنت', 'btn ghost small', false], ['پیدا کردن دوباره', 'btn ghost small', false]
  ]);
  assert.equal(host.one('mi-note').textContent, t('mi.note'));
  assert.match(t('mi.note'), /یک دانلودِ تکی از سرعتِ همان یک اینترنت بیشتر نمی‌شود/);
});

test('the same card in English', async () => {
  const h = harness({ lang: 'en' });
  await h.load();
  const { host } = h;
  assert.equal(host.one('switch-title').textContent, 'Combine internets');
  assert.deepEqual(host.byClass('mi-mode').map((m) => m.children[0].textContent), ['Combine', 'Backup', 'Upload and download apart']);
  assert.equal(h.row('Wi-Fi').one('mi-ok').textContent, '● Online');
  assert.deepEqual(h.row('Wi-Fi').one('mi-quota').children[0].textContent, '34.2 GB of 100.0 GB');
  assert.match(h.row('Wi-Fi').one('mi-quota').children[1].textContent, /^until /);
  assert.deepEqual(host.one('mi-actions').children.map((b) => b.textContent), ['Test each internet’s speed', 'Find again']);
  assert.match(host.one('mi-note').textContent, /One single download is never faster than the one internet it goes over/);
  // a language switch redraws it (app.js setLang calls render)
  h.window.i18n.applyI18n('fa');
  h.card.render();
  assert.equal(host.one('switch-title').textContent, 'ترکیب اینترنت‌ها');
});

test('off: only the switch shows', async () => {
  const h = harness();
  h.state.stored = answer({ settings: { enabled: false } }).settings;
  await h.load(answer({ settings: { enabled: false } }));
  assert.equal(h.host.byKey('enabled').checked, false);
  assert.equal(h.host.one('mi-body').hidden, true);
});

/* ------------------------------ saving ------------------------------ */

test('the switch saves at once — turned on, the internets the card shows become the configured ones', async () => {
  const found = answer({ settings: { enabled: false, links: [] } });
  found.links = found.links.map((l) => Object.assign({}, l, { configured: false }));
  const h = harness();
  h.state.stored = found.settings;
  await h.load(found);
  const sw = h.host.byKey('enabled');
  sw.checked = true;
  sw.dispatch('change');
  await flush();
  assert.deepEqual(h.saves, [{ enabled: true, links: [
    { id: 'Wi-Fi', iface: 'Wi-Fi', name: 'Wi-Fi — Home', role: 'use', weight: 2, quotaGb: 0, quotaPeriod: 'none' },
    { id: 'usb', iface: 'Ethernet 3', name: 'Phone (USB)', role: 'use', weight: 2, quotaGb: 0, quotaPeriod: 'none' },
    { id: 'eth0', iface: 'eth0', name: 'Office cable', role: 'use', weight: 2, quotaGb: 0, quotaPeriod: 'none' }
  ] }], 'a found internet joins in the mix, normal share, no cap');
  assert.equal(h.host.one('mi-body').hidden, false);
  // turned off: only that
  const off = h.host.byKey('enabled');
  off.checked = false;
  off.dispatch('change');
  await flush();
  assert.deepEqual(h.saves[1], { enabled: false });
  assert.equal(h.host.one('mi-body').hidden, true);
});

test('before the internets are read the switch saves only itself — never an empty list over the saved one', async () => {
  const h = harness();
  const sw = h.host.byKey('enabled');
  sw.checked = false;
  sw.dispatch('change');
  await flush();
  assert.deepEqual(h.saves, [{ enabled: false }]);
});

test('a role, a share, a cap and its period each save the whole list with that one change', async () => {
  const h = harness();
  await h.load();
  const role = h.host.byKey('role:usb');
  role.value = 'backup';
  role.dispatch('change');
  await flush();
  assert.equal(h.saves.length, 1);
  assert.deepEqual(h.saves[0].links.map((l) => [l.id, l.role]), [['Wi-Fi', 'use'], ['usb', 'backup'], ['eth0', 'off']]);
  const weight = h.host.byKey('weight:Wi-Fi');
  weight.value = '1';
  weight.dispatch('change');
  await flush();
  assert.equal(h.saves[1].links[0].weight, 1);
  assert.equal(h.saves[1].links[1].role, 'backup', 'the earlier change is kept');
  const quota = h.host.byKey('quota:usb');
  quota.value = '5';
  quota.dispatch('change');
  await flush();
  assert.equal(h.saves[2].links[1].quotaGb, 5);
  const bad = h.host.byKey('quota:usb');
  bad.value = '-2';
  bad.dispatch('change');
  await flush();
  assert.equal(h.saves[3].links[1].quotaGb, 0, 'no negative cap');
  const period = h.host.byKey('period:usb');
  period.value = 'none';
  period.dispatch('change');
  await flush();
  assert.equal(h.saves[4].links[1].quotaPeriod, 'none');
  assert.equal(h.host.byKey('quota:usb').disabled, true);
});

test('a link’s month: the Persian or the Gregorian one, its renew day under the cap — saved with the link, the other links as they were', async () => {
  const res = answer({ settings: { links: [
    { id: 'Wi-Fi', iface: 'Wi-Fi', name: 'Wi-Fi — Home', role: 'use', weight: 3, quotaGb: 100, quotaPeriod: 'month', quotaCalendar: 'jalali', quotaResetDay: 30 },
    { id: 'usb', iface: 'Ethernet 3', name: 'Phone (USB)', role: 'use', weight: 2, quotaGb: 3, quotaPeriod: 'day' },
    { id: 'eth0', iface: 'eth0', name: 'Office cable', role: 'off', weight: 2, quotaGb: 0, quotaPeriod: 'none' }
  ] } });
  const h = harness();
  h.state.stored = res.settings;
  await h.load(res);
  const note = (id) => h.row(id).one('mi-renewnote');
  assert.equal(h.host.byKey('period:Wi-Fi').value, 'jmonth');
  assert.equal(h.host.byKey('renew:Wi-Fi').value, '30');
  assert.equal(h.row('Wi-Fi').one('mi-renew').textContent.startsWith('روز تمدید'), true);
  assert.equal(note('Wi-Fi').hidden, false, 'the Persian 30th: Esfand may have 29 — said');
  assert.equal(note('usb').hidden, true);
  assert.equal(h.host.byKey('renew:eth0').parentNode.hidden, true, 'no cap: no renew day');
  const r = h.host.byKey('renew:Wi-Fi');
  r.value = '12';
  r.dispatch('change');
  await flush();
  assert.deepEqual(h.saves[0].links[0], { id: 'Wi-Fi', iface: 'Wi-Fi', name: 'Wi-Fi — Home', role: 'use', weight: 3, quotaGb: 100, quotaPeriod: 'month', quotaCalendar: 'jalali', quotaResetDay: 12 });
  assert.deepEqual(h.saves[0].links[1], { id: 'usb', iface: 'Ethernet 3', name: 'Phone (USB)', role: 'use', weight: 2, quotaGb: 3, quotaPeriod: 'day' }, 'a link saved before the choice: as it was');
  assert.equal(note('Wi-Fi').hidden, true, 'the 12th is in every month');
  const per = h.host.byKey('period:Wi-Fi');
  per.value = 'month';
  per.dispatch('change');
  await flush();
  assert.deepEqual([h.saves[1].links[0].quotaPeriod, h.saves[1].links[0].quotaCalendar, h.saves[1].links[0].quotaResetDay], ['month', 'gregorian', 12]);
  assert.equal('quotaCalendar' in h.state.stored.links[0], false, 'the service stores the Gregorian month as nothing');
  assert.equal(h.host.byKey('period:Wi-Fi').value, 'month');
  const usb = h.host.byKey('period:usb');
  usb.value = 'jmonth';
  usb.dispatch('change');
  await flush();
  assert.deepEqual([h.saves[2].links[1].quotaPeriod, h.saves[2].links[1].quotaCalendar], ['month', 'jalali']);
  assert.equal(h.host.byKey('renew:usb').parentNode.hidden, false, 'a month now: its renew day');

  const en = harness({ lang: 'en' });
  await en.load();
  assert.deepEqual(en.host.byKey('period:Wi-Fi').children.map((o) => o.textContent), ['GB a month', 'GB a Jalali month', 'GB a day', 'No cap']);
  assert.equal(en.host.byKey('period:Wi-Fi').value, 'month');
});

test('a redraw after a save keeps the focus on the control in use', async () => {
  const h = harness();
  await h.load();
  const role = h.host.byKey('role:usb');
  role.focus();
  role.value = 'backup';
  role.dispatch('change');
  await flush();
  const now = h.host.byKey('role:usb');
  assert.notEqual(now, role, 'the card was redrawn');
  assert.equal(h.document.activeElement, now);
});

test('split mode: picked, it guesses upload over the fastest-up internet and download over the fastest-down; the pickers show only then', async () => {
  const h = harness();
  await h.load();
  h.host.byKey('mode:split').click();
  await flush();
  assert.equal(h.saves[0].mode, 'split');
  assert.deepEqual(h.saves[0].split, { up: 'usb', down: 'Wi-Fi' }, 'the phone uploads at 21.4, the Wi-Fi downloads at 48.2');
  assert.equal(h.saves[0].links.length, 3);
  const box = h.host.one('mi-splitbox');
  assert.equal(box.children[0].textContent, 'آپلود و دانلود جدا');
  const up = h.host.byKey('split:up');
  const down = h.host.byKey('split:down');
  assert.equal(up.value, 'usb');
  assert.equal(down.value, 'Wi-Fi');
  assert.deepEqual(up.children.map((o) => o.textContent), ['انتخاب کنید', 'Wi-Fi — Home — ↑ 3.1', 'Phone (USB) — ↑ 21.4'], 'an internet not used is not offered');
  assert.deepEqual(down.children.map((o) => o.textContent), ['انتخاب کنید', 'Wi-Fi — Home — ↓ 48.2', 'Phone (USB) — ↓ 14.6']);
  assert.equal(box.byClass('hint')[0].textContent, h.t('mi.splitHint'));
  // the same internet twice: said
  down.value = 'usb';
  down.dispatch('change');
  await flush();
  assert.deepEqual(h.saves[1], { split: { down: 'usb' } });
  assert.ok(h.host.one('mi-splitbox').textContent.includes(h.t('mi.splitSame')));
  // back to combine: the pickers go
  h.host.byKey('mode:balance').click();
  await flush();
  assert.equal(h.host.byClass('mi-splitbox').length, 0);
});

test('a save that fails says so and the card goes back to what was saved', async () => {
  const h = harness({ saveFails: true });
  await h.load();
  h.host.byKey('mode:failover').click();
  await flush();
  assert.deepEqual(h.toasts, [[h.t('mi.saveFailed') + ': disk full', 'err']]);
  assert.ok(h.host.byKey('mode:balance').classList.contains('on'));
});

/* ------------------------------ live ------------------------------ */

test('connected: the two live share bars, each internet’s part and speed; the shared-line note; both go with the connection', async () => {
  const h = harness();
  await h.load();
  h.state.connected = true;
  h.card.connection(true);
  assert.equal(h.host.one('mi-live').hidden, true, 'connected, but nothing measured yet');
  assert.equal(h.host.one('mi-shared').textContent, h.t('mi.testShared'), 'a test while connected shares the line — said');
  h.card.live({
    live: { 'Wi-Fi': { up: 1000, down: 3875000 }, usb: { up: 2125000, down: 1500000 } },
    usage: { 'Wi-Fi': Object.assign({}, answer().usage['Wi-Fi'], { bytes: 50 * GIB }), usb: Object.assign({}, answer().usage.usb, { bytes: 3 * GIB, over: true }) }
  });
  const live = h.host.one('mi-live');
  assert.equal(live.hidden, false);
  const [down, up] = live.byClass('mi-box');
  assert.equal(down.children[0].textContent, 'الان — دانلود');
  assert.equal(up.children[0].textContent, 'الان — آپلود');
  assert.deepEqual(down.one('mi-share').children.map((i) => [i.className, i.style.width]), [['mi-c0', '72.1%'], ['mi-c1', '27.9%']]);
  assert.deepEqual(down.one('mi-legend').children.map((s) => s.textContent), ['Wi-Fi — Home 72٪ · 31.0 Mbps', 'Phone (USB) 28٪ · 12.0 Mbps']);
  assert.deepEqual(up.one('mi-share').children.map((i) => i.style.width), ['0.0%', '100.0%']);
  // the usage bars move with the tick, in place
  assert.equal(h.row('Wi-Fi').one('mi-bar').children[0].style.width, '50.0%');
  assert.equal(h.row('usb').one('mi-bar').children[0].className, 'over');
  assert.equal(h.row('usb').one('mi-quota').children[0].textContent, '3.0 GB از 3.0 GB — به سقف رسید، کنار گذاشته شد');
  assert.match(h.row('usb').one('mi-quota').children[1].textContent, /^برمی‌گردد /);
  // disconnected: gone
  h.state.connected = false;
  h.card.connection(false);
  assert.equal(h.host.one('mi-live').hidden, true);
  assert.equal(h.host.byClass('mi-shared').length, 0);
});

/* ------------------------------ test each internet / find again ------------------------------ */

test('"test each internet": one internet at a time, each row saying how far it got, the error per internet', async () => {
  const h = harness();
  await h.load();
  h.host.byKey('test').click();
  await flush();
  assert.deepEqual(h.calls.filter((c) => c[0] === 'test'), [['test', ['Wi-Fi']]], 'the connected ones only, one at a time');
  assert.deepEqual(h.row('Wi-Fi').one('mi-spd').children.map((c) => c.textContent), ['در حال تست…']);
  assert.deepEqual(h.row('usb').one('mi-spd').children.map((c) => c.textContent), ['در صف']);
  assert.equal(h.host.byKey('test').disabled, true);
  assert.equal(h.host.byKey('find').disabled, true);
  h.pending.test[0].resolve([{ id: 'Wi-Fi', ok: true, rttMs: 30, downMbps: 52.04, upMbps: 2.96 }]);
  await flush(); await flush();
  assert.deepEqual(h.row('Wi-Fi').one('mi-spd').children.map((c) => c.textContent), ['↓ 52.0', '↑ 3.0', 'Mbps']);
  assert.deepEqual(h.calls.filter((c) => c[0] === 'test').at(-1), ['test', ['usb']]);
  h.pending.test[1].resolve([{ id: 'usb', ok: false, rttMs: null, downMbps: null, upMbps: null, error: 'download: timeout' }]);
  await flush(); await flush();
  const err = h.row('usb').one('mi-err');
  assert.equal(err.textContent, '✕ download: timeout');
  assert.equal(h.calls.filter((c) => c[0] === 'test').length, 2);
  assert.equal(h.host.byKey('test').disabled, false, 'done');
});

test('"test each internet" with no server to test through: said once, the rest not tried', async () => {
  const h = harness();
  await h.load();
  h.host.byKey('test').click();
  await flush();
  h.pending.test[0].resolve([{ id: 'Wi-Fi', ok: false, code: 'noServer', error: 'select a server first' }]);
  await flush(); await flush();
  assert.deepEqual(h.toasts, [[h.t('mi.err.noServer'), 'err']]);
  assert.equal(h.calls.filter((c) => c[0] === 'test').length, 1);
  assert.equal(h.row('Wi-Fi').one('mi-err').textContent, '✕ ' + h.t('mi.err.noServer'));
});

test('"find again" asks again, turning while it reads (seconds on Windows)', async () => {
  const h = harness();
  await h.load();
  h.host.byKey('find').click();
  assert.equal(h.calls.filter((c) => c[0] === 'get').length, 2);
  const busy = h.host.byKey('find');
  assert.equal(busy.disabled, true);
  assert.equal(busy.getAttribute('aria-busy'), 'true');
  assert.equal(busy.byClass('mi-spin').length, 1);
  assert.ok(busy.textContent.endsWith('در حال پیدا کردن…'));
  h.pending.get[1].resolve(answer({ links: answer().links.slice(0, 1) }));
  await flush(); await flush();
  const done = h.host.byKey('find');
  assert.equal(done.textContent, 'پیدا کردن دوباره');
  assert.equal(done.getAttribute('aria-busy'), 'false');
  assert.equal(h.host.byClass('mi-net').length, 1);
  assert.ok(h.host.textContent.includes(h.t('mi.needTwo')), 'one internet: what to do about it');
});

test('nothing found: said; a back end without the channels hides the card', async () => {
  const h = harness();
  await h.load(answer({ links: [] }));
  assert.ok(h.host.textContent.includes(h.t('mi.noLinks')));
  const old = harness({ api: { multiWanGet: undefined } });
  assert.equal(old.host.hidden, true);
});

/* ------------------------------ strings, classes, markup ------------------------------ */

test('every string the card can show is defined once in Persian and once in English', () => {
  const keys = new Set([...CARD.matchAll(/t\('(mi\.[A-Za-z0-9.]+)'\)/g)].map((m) => m[1]));
  for (const m of ['balance', 'failover', 'split']) { keys.add('mi.mode.' + m); keys.add('mi.mode.' + m + 'Sub'); }
  for (const r of ['use', 'backup', 'off']) keys.add('mi.role.' + r);
  for (const w of [1, 2, 3]) keys.add('mi.share.' + w);
  for (const p of ['month', 'jmonth', 'day', 'none']) keys.add('mi.period.' + p);
  for (const c of ['noServer', 'absent', 'unknown']) keys.add('mi.err.' + c);   // the codes multiwan:test answers
  assert.ok(keys.size > 45, `expected the whole card, found ${keys.size} keys`);
  const bad = [...keys].filter((k) => (I18N.split(`'${k}':`).length - 1) !== 2).sort();
  assert.deepEqual(bad, [], 'not defined exactly once in each of fa and en');
  assert.equal(fa('set.multiWan'), 'ترکیب اینترنت‌ها', 'the apply dialog’s name for it');
});

test('every class the card builds is styled in settings.css — tokens only, logical properties only', () => {
  const css = R('src', 'renderer', 'settings.css');
  const cls = new Set();
  for (const m of CARD.matchAll(/(?:el|button)\('[a-z]+', '([^']+)'/g)) m[1].split(/\s+/).forEach((c) => cls.add(c));
  for (const c of ['mi-c0', 'mi-c1', 'mi-c2', 'mi-c3', 'mi-gone', 'mi-ok', 'mi-off', 'on', 'warn', 'over']) cls.add(c);
  const own = [...cls].filter((c) => c.startsWith('mi-') && c !== 'mi-c');   // 'mi-c' + n: the four below
  assert.ok(own.length >= 25, `found ${own.length}`);
  for (const c of own) assert.match(css, new RegExp('\\.' + c + '(?![\\w-])'), `.${c} has no style`);
  const block = css.slice(css.indexOf('several internets (multiWan.js)'));
  assert.doesNotMatch(block, /#[0-9a-f]{3,8}\b(?![\w-])|rgba?\(/i, 'no literal colours: the skins pick them');
  assert.doesNotMatch(block, /(?:margin|padding|border)-(?:left|right)|text-align:\s*(?:left|right)|\b(?:left|right):/, 'logical properties only: the app runs RTL');
});

test('the markup hosts the card in Settings, loads it before app.js, and the settings sections file it under Connection', () => {
  const html = R('src', 'renderer', 'index.html');
  assert.match(html, /<div class="card" id="multiWanCard" data-module="multiWan"><\/div>/);
  const settings = html.slice(html.indexOf('id="view-settings"'), html.indexOf('<!-- LOGS -->'));
  assert.ok(settings.includes('id="multiWanCard"'), 'inside the Settings view');
  assert.ok(html.indexOf('<script src="multiWan.js"></script>') > html.indexOf('<script src="i18n.js"></script>'));
  assert.ok(html.indexOf('<script src="multiWan.js"></script>') < html.indexOf('<script src="app.js"></script>'));
  const exp = R('src', 'renderer', 'settingsExperience.js');
  assert.match(exp, /const multiWan = document\.getElementById\('multiWanCard'\);/);
  assert.match(exp, /filter\(card => card !== multiWan\)/, 'the positional names keep naming the cards they did');
  assert.match(exp, /\[multiWan,'network'\]/);
  const app = R('src', 'renderer', 'app.js');
  assert.match(app, /window\.multiWanCard\.mount\(\$\('#multiWanCard'\), \{/);
  assert.match(app, /if \(view === 'settings' && window\.multiWanCard && !window\.multiWanCard\.loaded\(\)\) window\.multiWanCard\.refresh\(\);/, 'the internets are read when Settings first opens');
  assert.match(app, /window\.multiWanCard\.live\(state\.connected \? s\.multiWan : null\);/);
  assert.match(app, /window\.multiWanCard\.connection\(live\);/);
  assert.match(app, /const res = await window\.api\.multiWanSet\(partial\);/);
  assert.match(app, /if \(state\.connected && \(state\.pendingReconnect \|\| \[\]\)\.some\(k => !before\.includes\(k\)\)\) await promptApplySettings\(\);/, 'the same "reconnect to apply" offer a settings save brings');
});
