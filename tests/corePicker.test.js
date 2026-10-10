'use strict';
/**
 * The version picker's modal (src/renderer/corePicker.js) — the same renderer
 * on the desktop and on the router's web page. The whole file runs in a vm over
 * a DOM of plain objects; window.api is a fake whose answers the test holds, so
 * every state is driven by hand: loading, the cards and their badges, the two
 * lists, an upgrade, a downgrade older than the suggested version (the warning
 * first), progress, success, an error and Retry, connected, Esc and focus.
 * t() returns the key, so the assertions name keys.
 *
 * What a layout engine has to say (nothing off screen at 390 px, RTL and LTR)
 * is tests/corePickerLayout.test.js.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const R = (...p) => fs.readFileSync(path.join(__dirname, '..', ...p), 'utf8').replace(/\r\n/g, '\n');
const PICKER = R('src', 'renderer', 'corePicker.js');
const I18N = R('src', 'renderer', 'i18n.js');
const CSS = ['styles.css', 'home.css', 'lists.css', 'routing.css', 'settings.css', 'skins.css', 'diagnostics.css'].map((f) => R('src', 'renderer', f)).join('\n');

/* ------------------------------ a DOM of plain objects ------------------------------ */

class FakeText {
  constructor(data) { this.nodeType = 3; this.data = String(data); this.parentNode = null; }
  get textContent() { return this.data; }
}
class FakeEl {
  constructor(doc, tag) {
    this.ownerDocument = doc;
    this.nodeType = 1;
    this.tagName = String(tag).toUpperCase();
    this.childNodes = [];
    this.parentNode = null;
    this.attributes = {};
    this.listeners = {};
    this.hidden = false;
    this.disabled = false;
    this.type = '';
    this.id = '';
    this.title = '';
    this.tabIndex = 0;
    this.dataset = {};
    this.style = { setProperty(k, v) { this[k] = String(v); } };
    this._cls = new Set();
    const cls = this._cls;
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
  get firstElementChild() { return this.children[0] || null; }
  get isConnected() { let x = this; while (x.parentNode) x = x.parentNode; return x === this.ownerDocument.documentElement; }
  appendChild(n) {
    if (n.parentNode) n.parentNode.removeChild(n);
    this.childNodes.push(n);
    n.parentNode = this;
    return n;
  }
  append(...nodes) { for (const n of nodes) this.appendChild(typeof n === 'string' ? new FakeText(n) : n); }
  prepend(...nodes) { const old = this.childNodes; this.childNodes = []; this.append(...nodes); for (const o of old) this.childNodes.push(o); }
  removeChild(n) { const i = this.childNodes.indexOf(n); if (i > -1) this.childNodes.splice(i, 1); n.parentNode = null; return n; }
  remove() { if (this.parentNode) this.parentNode.removeChild(this); }
  replaceChildren(...nodes) { for (const c of this.childNodes) c.parentNode = null; this.childNodes = []; this.append(...nodes); }
  get textContent() { return this.childNodes.map((c) => c.textContent).join(''); }
  set textContent(v) { for (const c of this.childNodes) c.parentNode = null; this.childNodes = []; if (v != null && v !== '') this.appendChild(new FakeText(v)); }
  get innerHTML() { throw new Error('innerHTML read'); }
  set innerHTML(v) { throw new Error(`innerHTML: ${JSON.stringify(String(v).slice(0, 60))} went into the DOM as HTML`); }
  setAttribute(k, v) { this.attributes[k] = String(v); if (k === 'class') this.className = v; if (k === 'id') this.id = String(v); }
  getAttribute(k) { return Object.prototype.hasOwnProperty.call(this.attributes, k) ? this.attributes[k] : null; }
  hasAttribute(k) { return Object.prototype.hasOwnProperty.call(this.attributes, k); }
  removeAttribute(k) { delete this.attributes[k]; }
  addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); }
  removeEventListener(type, fn) { const l = this.listeners[type] || []; const i = l.indexOf(fn); if (i > -1) l.splice(i, 1); }
  /** A bubbling event, as a browser dispatches it. */
  dispatch(type, extra = {}) {
    let stopped = false;
    const ev = Object.assign({ type, target: this, defaultPrevented: false, preventDefault() { this.defaultPrevented = true; }, stopPropagation() { stopped = true; } }, extra);
    for (let n = this; n && !stopped; n = n.parentNode) {
      ev.currentTarget = n;
      if (type === 'click' && n === this && typeof n.onclick === 'function') n.onclick(ev);
      for (const fn of [...((n.listeners || {})[type] || [])]) fn(ev);
    }
    if (!stopped && this.ownerDocument) for (const fn of [...(this.ownerDocument.listeners[type] || [])]) { ev.currentTarget = this.ownerDocument; fn(ev); }
    return ev;
  }
  click() { if (this.disabled || this.hiddenUp()) return; this.dispatch('click'); }
  hiddenUp() { for (let n = this; n && n.nodeType === 1; n = n.parentNode) if (n.hidden) return true; return false; }
  focus() { this.ownerDocument.activeElement = this; }
  blur() { if (this.ownerDocument.activeElement === this) this.ownerDocument.activeElement = this.ownerDocument.body; }
  contains(n) { for (let x = n; x; x = x.parentNode) if (x === this) return true; return false; }
  scrollIntoView() {}
  getBoundingClientRect() { return { top: 0, left: 0, right: 0, bottom: 0, width: 0, height: 0 }; }
  /* test helpers */
  all(pred, out = []) { for (const c of this.childNodes) if (c.nodeType === 1) { if (pred(c)) out.push(c); c.all(pred, out); } return out; }
  byClass(c) { return this.all((n) => n.classList.contains(c)); }
  one(c) { const r = this.byClass(c); assert.equal(r.length, 1, `.${c}: ${r.length} found`); return r[0]; }
  has(c) { return this.byClass(c).length > 0; }
  visible(c) { return this.byClass(c).filter((n) => !n.hiddenUp()); }
}

function fakeDocument() {
  const doc = { listeners: {}, activeElement: null };
  doc.createElement = (tag) => new FakeEl(doc, tag);
  doc.createElementNS = (ns, tag) => { const e = new FakeEl(doc, tag); e.namespaceURI = ns; return e; };
  doc.createTextNode = (s) => new FakeText(s);
  doc.documentElement = new FakeEl(doc, 'html');
  doc.documentElement.dir = 'rtl';
  doc.documentElement.lang = 'fa';
  doc.body = new FakeEl(doc, 'body');
  doc.documentElement.appendChild(doc.body);
  doc.activeElement = doc.body;
  doc.addEventListener = (type, fn) => { (doc.listeners[type] = doc.listeners[type] || []).push(fn); };
  doc.removeEventListener = (type, fn) => { const l = doc.listeners[type] || []; const i = l.indexOf(fn); if (i > -1) l.splice(i, 1); };
  doc.getElementById = (id) => doc.documentElement.all((n) => n.id === id)[0] || null;
  /** A key pressed where the focus is. */
  doc.key = (key, extra = {}) => (doc.activeElement || doc.body).dispatch('keydown', Object.assign({ key }, extra));
  return doc;
}

/* ------------------------------ the picker in a vm ------------------------------ */

const rel = require('./coreReleases');
const { buildCards, SUGGESTED } = require('../src/main/coreVersions');
const { Downloader } = require('../src/main/downloader');
const dl = new Downloader({ destDir: fs.mkdtempSync(path.join(require('node:os').tmpdir(), 'irnf-cp-')), platform: 'win32', arch: 'x64' });
test.after(() => { try { fs.rmSync(dl.destDir, { recursive: true, force: true }); } catch {} });

/** What main answers to cores:versions — built by the real card builder. */
function answer({ component = 'xray-pattn', installed = '26.9.22', prerelease = false, busy = false, releases, installing = null } = {}) {
  const list = releases || (component === 'sing-box' ? rel.singbox() : component === 'xray' ? rel.xtls() : rel.pattn());
  const cards = buildCards({ releases: list, matchAsset: dl.assetMatcher(component), installed, latestTag: component === 'xray' ? 'v26.3.27' : component === 'sing-box' ? 'v1.14.3' : 'v26.10.3', suggested: SUGGESTED[component], prerelease });
  return { ok: true, component, installed, suggested: SUGGESTED[component], latest: component === 'xray-pattn' ? '26.10.3' : '', platform: dl.target(component), prerelease, busy, installing, cards };
}

/** What t() answers in the vm: the key, or for a key with {fields} the key and its fields, so a filled-in string can be checked. */
const TEMPLATES = {
  'cv.title': 'cv.title:{core}', 'cv.installed': 'cv.installed:{v}', 'cv.older': 'cv.older:{v}', 'cv.empty': 'cv.empty:{asset}',
  'cv.installedToast': 'installed:{core} {v}', 'cv.failedToast': 'failed:{core} {v}',
  'cv.lostNot': 'cv.lostNot:{v}', 'cv.otherInstall': 'cv.otherInstall:{core} {v}'
};
const tt = (k, map = {}) => (TEMPLATES[k] || k).replace(/\{(\w+)\}/g, (m, f) => map[f]);

/** Promises the test settles by hand: the api's answers. */
function deferred() { let resolve, reject; const p = new Promise((a, b) => { resolve = a; reject = b; }); return { p, resolve, reject }; }
const flush = () => new Promise((r) => setImmediate(r));

function harness({ busy = false, lang = 'fa' } = {}) {
  const document = fakeDocument();
  const calls = [];
  const pending = { versions: [], install: [] };
  const statusListeners = [];
  const timers = [];
  const toasts = [];
  const installed = [];
  const state = { busy };
  const window = {
    i18n: { t: (k) => TEMPLATES[k] || k, lang },
    api: {
      coreVersions: (component, opts) => { calls.push(['versions', component, JSON.parse(JSON.stringify(opts || {}))]); const d = deferred(); pending.versions.push(d); return d.p; },
      installCoreVersion: (component, tag) => { calls.push(['install', component, tag]); const d = deferred(); pending.install.push(d); return d.p; },
      onStatus: (cb) => statusListeners.push(cb),
      onXrayStatus: (cb) => statusListeners.push(cb)
    }
  };
  const ctx = vm.createContext({
    window, document, console, Intl, Date, Promise, JSON, Math, Number, String, Array, Object, Set, Map,
    setTimeout: (fn, ms) => { timers.push({ fn, ms }); return timers.length; },
    clearTimeout: () => {}
  });
  vm.runInContext(PICKER, ctx, { filename: 'corePicker.js' });
  const opener = document.createElement('button');
  document.body.appendChild(opener);
  const hooks = {
    opener,
    busy: () => state.busy,
    onInstalled: (res) => installed.push(res),
    toast: (msg, kind) => toasts.push([msg, kind || ''])
  };
  const picker = window.corePicker;
  const modal = () => document.getElementById('cvModal');
  const cards = () => modal().byClass('cv-card').filter((c) => !c.classList.contains('cv-skel'));
  const card = (version) => { const c = cards().find((x) => x.one('cv-ver').textContent === 'v' + version); assert.ok(c, `no card v${version}: ${cards().map((x) => x.one('cv-ver').textContent)}`); return c; };
  const actionOf = (c) => c.one('cv-act').children[0];
  const runTimers = () => { while (timers.length) timers.shift().fn(); };
  /** Answer the oldest pending cores:versions with `res`, and let it render. */
  const answerVersions = async (res) => { pending.versions.shift().resolve(res); await flush(); };
  const status = async (busyNow) => { state.busy = busyNow; for (const cb of statusListeners) cb({ state: busyNow ? 'connected' : 'disconnected' }); runTimers(); await flush(); };
  return { document, window, picker, calls, pending, hooks, state, toasts, installed, modal, cards, card, actionOf, runTimers, answerVersions, status, opener, timers };
}

async function opened(component = 'xray-pattn', opts = {}) {
  const h = harness(opts);
  h.opener.focus();
  h.picker.open(component, h.hooks);
  await flush();
  await h.answerVersions(answer(Object.assign({ component }, opts.answer || {})));
  return h;
}

/* ------------------------------ opening ------------------------------ */

test('open: the modal is built once, shows at once with a loading skeleton, and asks for the stable list', async () => {
  const h = harness();
  h.opener.focus();
  h.picker.open('xray-pattn', h.hooks);
  await flush();
  const m = h.modal();
  assert.ok(m, '#cvModal is in the page');
  assert.equal(m.hidden, false);
  assert.equal(h.picker.isOpen(), true);
  assert.ok(m.classList.contains('modal-overlay') && m.classList.contains('cv-overlay'));
  const dialog = m.one('cv-modal');
  assert.equal(dialog.getAttribute('role'), 'dialog');
  assert.equal(dialog.getAttribute('aria-modal'), 'true');
  assert.equal(dialog.getAttribute('aria-labelledby'), 'cvTitle');
  assert.equal(h.document.getElementById('cvTitle').textContent, tt('cv.title', { core: 'Xray-PattN' }));
  assert.equal(m.byClass('cv-skel').length, 4, 'a skeleton while GitHub answers');
  assert.equal(m.one('cv-list').getAttribute('aria-busy'), 'true');
  assert.deepEqual(h.calls, [['versions', 'xray-pattn', { prerelease: false }]]);
  assert.ok(dialog.contains(h.document.activeElement), 'the focus moves into the dialog');
  // a second open of another core reuses the same modal
  h.picker.close();
  h.runTimers();
  h.picker.open('sing-box', h.hooks);
  await flush();
  assert.equal(h.document.documentElement.all((n) => n.id === 'cvModal').length, 1);
  assert.equal(h.document.getElementById('cvTitle').textContent, tt('cv.title', { core: 'sing-box' }));
});

test('the header says what is installed and what this device downloads', async () => {
  const h = await opened('xray-pattn');
  assert.equal(h.modal().one('cv-chip-installed').textContent, tt('cv.installed', { v: 'v26.9.22' }));
  assert.equal(h.modal().one('cv-chip-target').textContent, 'cv.os.win32 · x64');
  assert.equal(h.modal().one('cv-chip-target').title, 'Xray-windows-64.zip');
  const none = await opened('xray', { answer: { installed: '' } });
  assert.equal(none.modal().one('cv-chip-installed').textContent, 'cv.notInstalled');
});

/* ------------------------------ the cards ------------------------------ */

test('the stable list: one card per version, newest first, with its badges, age, size and action', async () => {
  const h = await opened('xray-pattn');
  assert.equal(h.modal().byClass('cv-skel').length, 0);
  assert.equal(h.modal().one('cv-list').getAttribute('aria-busy'), 'false');
  assert.deepEqual(h.cards().map((c) => c.one('cv-ver').textContent), ['v26.10.3', 'v26.9.27', 'v26.9.26', 'v26.9.24', 'v26.9.22', 'v26.9.13']);
  const badges = (c) => c.byClass('cv-badge').map((b) => b.textContent);
  assert.deepEqual(badges(h.card('26.10.3')), ['cv.badge.latest']);
  assert.deepEqual(badges(h.card('26.9.22')), ['cv.badge.suggested', 'cv.badge.installed']);
  assert.deepEqual(badges(h.card('26.9.27')), []);
  assert.ok(h.card('26.9.22').classList.contains('is-installed') && h.card('26.9.22').classList.contains('is-suggested'));
  const act = (v) => { const b = h.actionOf(h.card(v)); return [b.textContent, b.className]; };
  assert.deepEqual(act('26.10.3'), ['cv.act.upgrade', 'btn small cv-btn cv-tonal']);
  assert.deepEqual(act('26.9.22'), ['cv.act.reinstall', 'btn small cv-btn ghost']);
  assert.deepEqual(act('26.9.13'), ['cv.act.downgrade', 'btn small cv-btn cv-amber']);
  const c = h.card('26.9.24');
  assert.equal(c.one('cv-size').textContent, '19.6 MB');
  assert.equal(c.one('cv-size').getAttribute('dir'), 'ltr');
  assert.equal(c.one('cv-ver').getAttribute('dir'), 'ltr');
  assert.ok(c.one('cv-age').textContent.length > 0, 'an age');
  assert.match(c.one('cv-age').title, /2026/, 'the date in the tooltip');
  assert.match(h.actionOf(c).getAttribute('aria-label'), /cv\.act\.upgrade.*v26\.9\.24/);
});

test('With pre-releases asks again with prerelease, marks the pre-releases, and Stable goes back', async () => {
  const h = await opened('xray', { answer: { installed: '26.3.27' } });
  const [stable, pre] = h.modal().one('cv-seg').children;
  assert.equal(stable.getAttribute('aria-pressed'), 'true');
  assert.equal(pre.getAttribute('aria-pressed'), 'false');
  pre.click();
  await flush();
  assert.deepEqual(h.calls.at(-1), ['versions', 'xray', { prerelease: true }]);
  assert.equal(pre.getAttribute('aria-pressed'), 'true');
  assert.ok(pre.classList.contains('active') && !stable.classList.contains('active'));
  assert.equal(h.modal().byClass('cv-skel').length, 0, 'switching keeps the cards on screen while it asks');
  await h.answerVersions(answer({ component: 'xray', installed: '26.3.27', prerelease: true }));
  assert.equal(h.cards().length, 10);
  assert.deepEqual(h.cards().filter((c) => c.classList.contains('is-pre')).map((c) => c.one('cv-ver').textContent), ['v26.9.30', 'v26.9.9', 'v26.9.8', 'v26.7.28']);
  assert.ok(h.card('26.9.30').byClass('cv-badge').some((b) => b.textContent === 'cv.badge.pre'));
  stable.click();
  await flush();
  assert.deepEqual(h.calls.at(-1), ['versions', 'xray', { prerelease: false }]);
  // an answer that comes back after another click is dropped
  pre.click();
  await flush();
  await h.answerVersions(answer({ component: 'xray', installed: '26.3.27', prerelease: false }));   // the stale one
  assert.equal(h.cards().length, 10, 'still the pre-release list');
  await h.answerVersions(answer({ component: 'xray', installed: '26.3.27', prerelease: true }));
  assert.equal(h.cards().length, 10);
});

/* ------------------------------ installing ------------------------------ */

test('Upgrade: installs that tag with progress in its card, then says so and refreshes the list and the page', async () => {
  const h = await opened('xray-pattn');
  h.actionOf(h.card('26.10.3')).click();
  await flush();
  assert.deepEqual(h.calls.at(-1), ['install', 'xray-pattn', 'v26.10.3']);
  const c = h.card('26.10.3');
  assert.ok(c.classList.contains('is-busy'));
  assert.equal(c.visible('cv-progress').length, 1);
  assert.equal(c.one('cv-track').getAttribute('role'), 'progressbar');
  assert.equal(c.one('cv-progress-text').textContent, 'cv.downloading');
  // nothing else can start meanwhile
  assert.ok(h.cards().filter((x) => x !== c).every((x) => h.actionOf(x).disabled));
  assert.ok(h.modal().one('cv-seg').children.every((b) => b.disabled));
  // the existing asset-progress event: the picker takes its own, nobody else's
  assert.equal(h.picker.progress({ component: 'xray-pattn', pct: 42 }), true);
  assert.equal(h.card('26.10.3').one('cv-progress-text').textContent, 'cv.downloading 42%');
  assert.equal(h.card('26.10.3').one('cv-track').getAttribute('aria-valuenow'), '42');
  assert.equal(h.card('26.10.3').one('cv-fill').style.width, '42%');
  assert.equal(h.picker.progress({ component: 'geo', pct: 10 }), false);
  assert.equal(h.picker.progress({ component: 'app', pct: 10 }), false);
  h.picker.progress({ component: 'xray-pattn', pct: 100 });
  assert.equal(h.card('26.10.3').one('cv-progress-text').textContent, 'cv.verifying', 'extracting and running it after the download');
  // done
  const res = { ok: true, component: 'xray-pattn', tag: 'v26.10.3', version: '26.10.3', assets: { 'xray-pattn': true }, tunAvailable: true, xrayReady: true };
  h.pending.install.shift().resolve(res);
  await flush();
  assert.deepEqual(h.installed, [res], 'the page refreshes its rows and versions');
  assert.deepEqual(h.calls.at(-1), ['versions', 'xray-pattn', { prerelease: false }], 'and the list its badges');
  await h.answerVersions(answer({ installed: '26.10.3' }));
  const done = h.card('26.10.3');
  assert.ok(done.classList.contains('is-done'));
  assert.equal(done.one('cv-done').textContent, 'cv.done');
  assert.ok(done.byClass('cv-badge').some((b) => b.textContent === 'cv.badge.installed'));
  assert.equal(h.actionOf(done).textContent, 'cv.act.reinstall');
  assert.equal(h.actionOf(h.card('26.9.22')).textContent, 'cv.act.downgrade');
  assert.ok(h.cards().every((x) => !h.actionOf(x).disabled), 'free again');
  assert.equal(h.picker.progress({ component: 'xray-pattn', pct: 5 }), false, 'no install of its own any more');
  assert.deepEqual(h.toasts, [], 'the modal said it; no toast on top');
});

test('a version older than the suggested one asks first, inside its card — Cancel, or Install anyway', async () => {
  const h = await opened('xray-pattn');
  const btn = h.actionOf(h.card('26.9.13'));
  btn.click();
  await flush();
  assert.equal(h.calls.filter((c) => c[0] === 'install').length, 0, 'nothing installed yet');
  let c = h.card('26.9.13');
  assert.ok(c.classList.contains('is-confirm'));
  assert.equal(c.one('cv-warn').getAttribute('role'), 'alert');
  assert.equal(c.one('cv-warn-text').textContent, tt('cv.older', { v: 'v26.9.22' }));
  assert.equal(h.document.activeElement, c.one('cv-go'), 'the focus is on the choice');
  c.one('cv-cancel').click();
  await flush();
  c = h.card('26.9.13');
  assert.equal(c.has('cv-warn'), false);
  assert.equal(h.document.activeElement, h.actionOf(c));
  h.actionOf(c).click();
  await flush();
  h.card('26.9.13').one('cv-go').click();
  await flush();
  assert.deepEqual(h.calls.at(-1), ['install', 'xray-pattn', 'v26.9.13']);
  assert.ok(h.card('26.9.13').classList.contains('is-busy'));
  // a newer one never asks
  const g = await opened('xray-pattn');
  g.actionOf(g.card('26.9.27')).click();
  await flush();
  assert.deepEqual(g.calls.at(-1), ['install', 'xray-pattn', 'v26.9.27']);
});

test('a failed install says why in its card — the core that was there is untouched — and Retry tries again without asking', async () => {
  const h = await opened('xray-pattn');
  h.actionOf(h.card('26.9.13')).click();
  await flush();
  h.card('26.9.13').one('cv-go').click();
  await flush();
  h.pending.install.shift().resolve({ ok: false, component: 'xray-pattn', tag: 'v26.9.13', error: 'the downloaded Xray-PattN says it is 26.9.12, not 26.9.13 — nothing was replaced', assets: {} });
  await flush();
  const c = h.card('26.9.13');
  assert.ok(c.classList.contains('is-failed'));
  assert.equal(c.one('cv-fail').getAttribute('role'), 'alert');
  assert.equal(c.one('cv-fail-text').textContent, 'cv.failed');
  assert.equal(c.one('cv-fail-why').textContent, 'the downloaded Xray-PattN says it is 26.9.12, not 26.9.13 — nothing was replaced');
  assert.deepEqual(h.installed, [], 'nothing to refresh');
  c.one('cv-retry').click();
  await flush();
  assert.deepEqual(h.calls.at(-1), ['install', 'xray-pattn', 'v26.9.13'], 'straight to the install: the warning was answered');
  // a bridge that throws (the router's page lost the service) is NOT that failure: the answer was lost (review I1)
  h.pending.install.shift().reject(new Error('Failed to fetch'));
  await flush();
  assert.equal(h.card('26.9.13').one('cv-progress-text').textContent, 'cv.checking');
  assert.equal(h.card('26.9.13').has('cv-fail'), false);
});

/* ------------------------------ connected ------------------------------ */

test('connected or connecting: the list shows, every action is off, and the modal says to disconnect first', async () => {
  const h = await opened('xray-pattn', { busy: true });
  const note = h.modal().one('cv-busy');
  assert.equal(note.hidden, false);
  assert.equal(note.textContent, 'cv.busy');
  assert.ok(h.cards().length > 0 && h.cards().every((c) => h.actionOf(c).disabled));
  h.actionOf(h.card('26.10.3')).click();
  await flush();
  assert.equal(h.calls.filter((c) => c[0] === 'install').length, 0);
  // disconnecting while it is open frees them
  await h.status(false);
  await h.answerVersions(answer());
  assert.equal(h.modal().one('cv-busy').hidden, true);
  assert.ok(h.cards().every((c) => !h.actionOf(c).disabled));
  // the service's own word counts too (the router's boot connect waiting for the WAN)
  const s = await opened('xray-pattn', { answer: { busy: true } });
  assert.equal(s.modal().one('cv-busy').hidden, false);
  assert.ok(s.cards().every((c) => s.actionOf(c).disabled));
});

test('refused because a connection started meanwhile: the card is back and the modal says to disconnect first', async () => {
  const h = await opened('xray-pattn');
  h.actionOf(h.card('26.10.3')).click();
  await flush();
  h.pending.install.shift().resolve({ ok: false, refused: 'connected', component: 'xray-pattn', tag: 'v26.10.3' });
  await flush();
  assert.equal(h.modal().one('cv-busy').hidden, false);
  assert.equal(h.card('26.10.3').has('cv-progress'), false);
  assert.ok(h.cards().every((c) => h.actionOf(c).disabled));
  // another install somewhere else (the router's other tab) is said in the card
  const g = await opened('xray-pattn');
  g.actionOf(g.card('26.10.3')).click();
  await flush();
  g.pending.install.shift().resolve({ ok: false, refused: 'installing', component: 'xray-pattn', tag: 'v26.10.3', installing: { component: 'sing-box', tag: 'v1.13.14' } });
  await flush();
  assert.equal(g.card('26.10.3').one('cv-fail-text').textContent, 'cv.oneAtATime');
});

/* ------------------------------ the list could not be read ------------------------------ */

test('GitHub unreachable or rate-limited: a friendly message with the reason, and Retry asks GitHub again', async () => {
  const h = harness();
  h.picker.open('sing-box', h.hooks);
  await flush();
  await h.answerVersions({ ok: false, component: 'sing-box', installed: '1.13.14', suggested: '1.14.3', platform: dl.target('sing-box'), busy: false, installing: null, cards: [], error: 'GitHub: HTTP 403 — API rate limit exceeded for 5.6.7.8', reason: 'rate-limit' });
  const err = h.modal().one('cv-error');
  assert.equal(err.one('cv-empty-title').textContent, 'cv.rateLimited');
  assert.equal(err.one('cv-fail-why').textContent, 'GitHub: HTTP 403 — API rate limit exceeded for 5.6.7.8');
  assert.equal(h.modal().one('cv-chip-installed').textContent, tt('cv.installed', { v: 'v1.13.14' }), 'the header still says what is installed');
  err.one('cv-retry').click();
  await flush();
  assert.deepEqual(h.calls.at(-1), ['versions', 'sing-box', { prerelease: false, force: true }]);
  assert.equal(h.modal().byClass('cv-skel').length, 4);
  await h.answerVersions({ ok: false, cards: [], error: 'getaddrinfo ENOTFOUND api.github.com', reason: 'network', installed: '', suggested: '1.14.3', platform: dl.target('sing-box') });
  assert.equal(h.modal().one('cv-error').one('cv-empty-title').textContent, 'cv.loadFailed');
  h.modal().one('cv-retry').click();
  await flush();
  await h.answerVersions(answer({ component: 'sing-box', installed: '1.13.14' }));
  assert.equal(h.cards().length, 6, 'the six newest stable — 1.13.14 is older than the 30 newest, and no longer the suggested one');
  // nothing for this platform
  const e = await opened('xray', { answer: { releases: [] } });
  assert.equal(e.modal().one('cv-empty').one('cv-empty-title').textContent, tt('cv.empty', { asset: 'Xray-windows-64.zip' }));
});

/* ------------------------------ closing, keys, focus ------------------------------ */

test('Esc, ✕ and the backdrop close it; the focus goes back to the button that opened it; Tab stays inside', async () => {
  const h = await opened('xray-pattn');
  const m = h.modal();
  const dialog = m.one('cv-modal');
  // Tab from the last control goes to the first, Shift+Tab from the first to the last
  const buttons = dialog.all((n) => n.tagName === 'BUTTON' && !n.disabled && !n.hiddenUp());
  buttons.at(-1).focus();
  let ev = h.document.key('Tab');
  assert.equal(ev.defaultPrevented, true);
  assert.equal(h.document.activeElement, buttons[0]);
  ev = h.document.key('Tab', { shiftKey: true });
  assert.equal(h.document.activeElement, buttons.at(-1));
  // Esc closes the warning first, then the modal
  h.actionOf(h.card('26.9.13')).click();
  await flush();
  h.document.key('Escape');
  assert.equal(h.card('26.9.13').has('cv-warn'), false);
  assert.equal(h.picker.isOpen(), true);
  h.document.key('Escape');
  assert.equal(h.picker.isOpen(), false);
  assert.ok(m.classList.contains('cv-leaving'), 'it fades out…');
  h.runTimers();
  assert.equal(m.hidden, true, '…and is gone');
  assert.equal(h.document.activeElement, h.opener);
  assert.equal((h.document.listeners.keydown || []).length, 0, 'no key handler left behind');
  // ✕
  h.picker.open('xray-pattn', h.hooks);
  await flush();
  m.one('cv-close').click();
  h.runTimers();
  assert.equal(m.hidden, true);
  // the backdrop, not the dialog
  h.picker.open('xray-pattn', h.hooks);
  await flush();
  m.one('cv-modal').dispatch('click');
  assert.equal(h.picker.isOpen(), true, 'a click inside is not the backdrop');
  m.dispatch('click');
  h.runTimers();
  assert.equal(m.hidden, true);
  // reopened at once after a close (no event to wait for — see browser-pane-dialog-close)
  h.picker.open('xray', h.hooks);
  h.picker.close();
  h.picker.open('xray', h.hooks);
  h.runTimers();
  assert.equal(m.hidden, false);
  assert.equal(h.picker.isOpen(), true);
});

test('closed during an install: it goes on, its progress stays out of the toasts, and the end is a toast and a refresh', async () => {
  const h = await opened('sing-box', { answer: { installed: '1.14.2' } });
  h.actionOf(h.card('1.14.3')).click();
  await flush();
  h.picker.close();
  h.runTimers();
  assert.equal(h.picker.progress({ component: 'sing-box', pct: 30 }), true, 'still its own: no "Downloading sing-box 30%" toast');
  h.pending.install.shift().resolve({ ok: true, component: 'sing-box', tag: 'v1.14.3', version: '1.14.3', assets: {}, tunAvailable: true, xrayReady: true });
  await flush();
  assert.equal(h.installed.length, 1);
  assert.deepEqual(h.toasts, [[tt('cv.installedToast', { core: 'sing-box', v: 'v1.14.3' }), 'ok']]);
  // reopened while another install runs: the card shows it
  const g = await opened('xray-pattn');
  g.actionOf(g.card('26.9.27')).click();
  await flush();
  g.picker.close();
  g.runTimers();
  g.picker.open('xray-pattn', g.hooks);
  await flush();
  await g.answerVersions(answer());
  assert.ok(g.card('26.9.27').classList.contains('is-busy'));
  g.pending.install.shift().resolve({ ok: false, error: 'HTTP 404' });
  await flush();
  assert.ok(g.card('26.9.27').classList.contains('is-failed'));
  // a failure while closed is a toast
  const f = await opened('xray-pattn');
  f.actionOf(f.card('26.9.27')).click();
  await flush();
  f.picker.close();
  f.pending.install.shift().resolve({ ok: false, error: 'the download was cut off' });
  await flush();
  assert.deepEqual(f.toasts, [[tt('cv.failedToast', { core: 'Xray-PattN', v: 'v26.9.27' }) + ': the download was cut off', 'err']]);
});

/* ------------------------------ review fixes (I1, M1, M2, M3) ------------------------------ */

test('I1: a lost answer (the relay’s 504, a dropped call) is never “untouched” — the card asks the service until it knows how the install ended', async () => {
  const h = await opened('xray-pattn');
  h.actionOf(h.card('26.9.27')).click();
  await flush();
  h.pending.install.shift().reject(new Error('Gateway Timeout'));
  await flush();
  let c = h.card('26.9.27');
  assert.ok(c.classList.contains('is-busy') && !c.classList.contains('is-failed'), 'still going, not failed');
  assert.equal(c.one('cv-progress-text').textContent, 'cv.checking');
  assert.equal(c.has('cv-fail'), false);
  assert.ok(h.cards().filter((x) => x !== c).every((x) => h.actionOf(x).disabled), 'nothing else starts meanwhile');
  assert.equal(h.picker.progress({ component: 'xray-pattn', pct: 80 }), true, 'its progress is still its own');
  assert.equal(h.card('26.9.27').one('cv-progress-text').textContent, 'cv.checking');
  // it asks the service: that tag is still being installed
  h.runTimers();
  await flush();
  assert.deepEqual(h.calls.at(-1), ['versions', 'xray-pattn', { prerelease: false }]);
  await h.answerVersions(answer({ installing: { component: 'xray-pattn', tag: 'v26.9.27' } }));
  assert.equal(h.card('26.9.27').one('cv-progress-text').textContent, 'cv.checking');
  assert.deepEqual(h.installed, []);
  // …then the installed version is the chosen one: done, and the page refreshes
  h.runTimers();
  await flush();
  await h.answerVersions(answer({ installed: '26.9.27' }));
  c = h.card('26.9.27');
  assert.ok(c.classList.contains('is-done'));
  assert.equal(c.one('cv-done').textContent, 'cv.done');
  assert.ok(c.byClass('cv-badge').some((b) => b.textContent === 'cv.badge.installed'), 'the answer it asked for is the list now');
  assert.equal(h.installed.length, 1);
  assert.equal(h.installed[0].version, '26.9.27');
  assert.ok(h.cards().every((x) => !h.actionOf(x).disabled));
});

test('I1: lost, and the service then shows another version installed — said as what is installed now, with Retry; an answer with no ok is lost too', async () => {
  const h = await opened('xray-pattn');
  h.actionOf(h.card('26.9.27')).click();
  await flush();
  h.pending.install.shift().resolve(null);
  await flush();
  assert.equal(h.card('26.9.27').one('cv-progress-text').textContent, 'cv.checking');
  h.runTimers();
  await flush();
  h.pending.versions.shift().reject(new Error('Failed to fetch'));   // the router out of reach for a moment: asked again
  await flush();
  h.runTimers();
  await flush();
  await h.answerVersions(answer({ installed: '26.9.22' }));
  const c = h.card('26.9.27');
  assert.ok(c.classList.contains('is-failed'));
  assert.equal(c.one('cv-fail-text').textContent, tt('cv.lostNot', { v: 'v26.9.22' }));
  assert.equal(c.has('cv-fail-why'), false);
  assert.ok(c.one('cv-retry'));
  assert.deepEqual(h.installed, []);
  // a service that reports a failure is still the "untouched" one
  const g = await opened('xray-pattn');
  g.actionOf(g.card('26.9.27')).click();
  await flush();
  g.pending.install.shift().resolve({ ok: false, component: 'xray-pattn', tag: 'v26.9.27', error: 'HTTP 404', assets: {} });
  await flush();
  assert.equal(g.card('26.9.27').one('cv-fail-text').textContent, 'cv.failed');
  assert.equal(g.timers.length, 0, 'nothing to ask: the service said it');
});

test('M1/M2: the service’s own reasons read in the user’s language — another download of this core, the core file in use', async () => {
  const h = await opened('xray-pattn');
  h.actionOf(h.card('26.9.27')).click();
  await flush();
  h.pending.install.shift().resolve({ ok: false, refused: 'core-busy', component: 'xray-pattn', tag: 'v26.9.27' });
  await flush();
  assert.equal(h.card('26.9.27').one('cv-fail-text').textContent, 'cv.coreBusy');
  assert.equal(h.card('26.9.27').has('cv-fail-why'), false);
  h.card('26.9.27').one('cv-retry').click();
  await flush();
  h.pending.install.shift().resolve({ ok: false, component: 'xray-pattn', tag: 'v26.9.27', reason: 'in-use', error: 'the core file is in use — nothing was replaced', assets: {} });
  await flush();
  assert.equal(h.card('26.9.27').one('cv-fail-text').textContent, 'cv.inUse');
  assert.equal(h.card('26.9.27').has('cv-fail-why'), false, 'no raw EPERM on screen');
});

test('M3: while another install runs — another core in this window, or another client of the router — the modal says so and waits', async () => {
  const h = await opened('xray-pattn');
  h.actionOf(h.card('26.9.27')).click();
  await flush();
  h.picker.close();
  h.runTimers();
  h.picker.open('sing-box', h.hooks);
  await flush();
  await h.answerVersions(answer({ component: 'sing-box', installed: '1.14.2' }));
  const note = h.modal().one('cv-other');
  assert.equal(note.hidden, false);
  assert.equal(note.textContent, tt('cv.otherInstall', { core: 'Xray-PattN', v: 'v26.9.27' }));
  assert.ok(h.cards().every((c) => h.actionOf(c).disabled));
  h.pending.install.shift().resolve({ ok: true, component: 'xray-pattn', tag: 'v26.9.27', version: '26.9.27', assets: {}, tunAvailable: true, xrayReady: true });
  await flush();
  assert.equal(h.modal().one('cv-other').hidden, true, 'free once it ended');
  assert.ok(h.cards().every((c) => !h.actionOf(c).disabled));
  assert.equal(h.toasts.length, 1, 'the other core’s end is a toast');
  // another client's install: the service's word, asked again until it is over
  const g = await opened('xray', { answer: { installed: '26.3.27', installing: { component: 'sing-box', tag: 'v1.13.14' } } });
  assert.equal(g.modal().one('cv-other').hidden, false);
  assert.equal(g.modal().one('cv-other').textContent, tt('cv.otherInstall', { core: 'sing-box', v: 'v1.13.14' }));
  assert.ok(g.cards().every((c) => g.actionOf(c).disabled));
  g.runTimers();
  await flush();
  assert.deepEqual(g.calls.at(-1), ['versions', 'xray', { prerelease: false }], 'asked again a little later');
  await g.answerVersions(answer({ component: 'xray', installed: '26.3.27' }));
  assert.equal(g.modal().one('cv-other').hidden, true);
  assert.ok(g.cards().every((c) => !g.actionOf(c).disabled));
  g.runTimers();
  assert.equal(g.calls.filter((c) => c[0] === 'versions').length, 2, 'no more asking once it is free');
});

/* ------------------------------ the pure helpers ------------------------------ */

test('sizes and ages read like the rest of the app', () => {
  const h = harness();
  const f = h.picker.format;
  assert.equal(f.size(20594290), '19.6 MB');
  assert.equal(f.size(15728640), '15.0 MB');
  assert.equal(f.size(900000), '879 KB');
  assert.equal(f.size(0), '');
  const now = Date.parse('2026-10-03T12:00:00Z');
  assert.equal(f.age('2026-10-03T09:30:00Z', now, 'en'), '2 hours ago');
  assert.equal(f.age('2026-10-02T09:30:00Z', now, 'en'), 'yesterday');
  assert.equal(f.age('2026-09-22T09:30:00Z', now, 'en'), '11 days ago');
  assert.equal(f.age('2026-07-02T09:30:00Z', now, 'en'), '3 months ago');
  assert.equal(f.age('2025-09-05T09:30:00Z', now, 'en'), 'last year');
  assert.match(f.age('2026-09-22T09:30:00Z', now, 'fa'), /روز/, 'Persian words in Persian');
  assert.equal(f.age('not a date', now, 'en'), '');
  assert.equal(f.age(null, now, 'en'), '');
});

/* ------------------------------ the file itself ------------------------------ */

test('the picker writes no HTML string, follows the page’s direction, and every word it shows is a key in both languages', () => {
  assert.doesNotMatch(PICKER, /innerHTML|insertAdjacentHTML|outerHTML/, 'text only: tags and errors come from GitHub and the service');
  assert.doesNotMatch(PICKER, /\.dir\s*=|\.lang\s*=/, 'the page decides the direction');
  const keys = [...new Set([...PICKER.matchAll(/\bt\('((?:cv|comp)\.[A-Za-z0-9.]+)'\)/g)].map((m) => m[1]))];
  for (const k of ['cv.title', 'cv.installed', 'cv.notInstalled', 'cv.stable', 'cv.withPre', 'cv.busy', 'cv.foot', 'cv.close',
    'cv.badge.suggested', 'cv.badge.latest', 'cv.badge.installed', 'cv.badge.pre', 'cv.act.upgrade', 'cv.act.downgrade',
    'cv.act.reinstall', 'cv.act.install', 'cv.older', 'cv.olderGo', 'cv.cancel', 'cv.downloading', 'cv.verifying', 'cv.done',
    'cv.failed', 'cv.retry', 'cv.oneAtATime', 'cv.loadFailed', 'cv.rateLimited', 'cv.empty', 'cv.loading', 'cv.installedToast',
    'cv.failedToast', 'cv.os.win32', 'cv.os.darwin', 'cv.os.linux']) {
    assert.ok(keys.includes(k) || PICKER.includes(`'${k}'`), `corePicker.js never shows ${k}`);
  }
  const all = [...new Set([...keys, ...[...PICKER.matchAll(/'(cv\.[A-Za-z0-9.]+)'/g)].map((m) => m[1])])].filter((k) => !/\.$/.test(k));
  const bad = all.filter((k) => (I18N.split(`'${k}':`).length - 1) !== 2).sort();
  assert.deepEqual(bad, [], 'these keys are not defined exactly once in each of fa and en');
  // a single-quoted i18n string may not carry an apostrophe (v1.7.3's dead UI) — the file uses ’
  for (const k of all) {
    for (const m of I18N.matchAll(new RegExp(`'${k.replace(/\./g, '\\.')}': '((?:[^'\\\\]|\\\\.)*)'`, 'g'))) assert.ok(!/\\'/.test(m[1]), `${k}: an escaped apostrophe`);
  }
});

test('every class the picker builds with is styled, in both themes’ tokens only', () => {
  const cls = new Set();
  for (const m of PICKER.matchAll(/(?:el|node)\(\s*'[a-z0-9]+',\s*'([^']+)'/g)) m[1].split(/\s+/).forEach((c) => c && cls.add(c));
  for (const m of PICKER.matchAll(/\bbutton\(\s*'([^']+)'/g)) m[1].split(/\s+/).forEach((c) => c && cls.add(c));
  for (const m of PICKER.matchAll(/cls: '([^']+)'/g)) cls.add(m[1]);   // the actions' button variants
  for (const m of PICKER.matchAll(/classList\.(?:add|toggle|remove)\(\s*'([A-Za-z0-9_-]+)'/g)) cls.add(m[1]);
  for (const m of PICKER.matchAll(/className = '([^']+)'/g)) m[1].split(/\s+/).forEach((c) => c && cls.add(c));
  assert.ok(cls.size > 30, `expected the whole modal, found ${cls.size}: ${[...cls].join(' ')}`);
  const unstyled = [...cls].filter((c) => !new RegExp('\\.' + c.replace(/-/g, '\\-') + '(?![A-Za-z0-9_-])').test(CSS)).sort();
  assert.deepEqual(unstyled, [], 'these classes have no style');
  // its own rules use the tokens, never a literal colour
  const own = [...CSS.matchAll(/([^{}]*)\{([^}]*)\}/g)].filter((m) => /\.cv-/.test(m[1]));
  assert.ok(own.length > 20);
  for (const m of own) assert.doesNotMatch(m[2], /#[0-9a-f]{3,8}\b|rgba?\(/i, `${m[1].trim()} has a literal colour`);
  // the two tokens it added exist in every palette: two themes of the base, two of each skin
  const SKINS = R('src', 'renderer', 'skins.css');
  const STYLES = R('src', 'renderer', 'styles.css');
  for (const tok of ['--warnSoft', '--infoSoft']) {
    assert.equal(STYLES.split(tok + ':').length - 1, 2, `${tok} in :root and the light theme`);
    assert.equal(SKINS.split(tok + ':').length - 1, 4, `${tok} in both themes of console and legacy`);
  }
});

/* ------------------------------ the page around it (app.js, index.html) ------------------------------ */

const APP = R('src', 'renderer', 'app.js');
const HTML = R('src', 'renderer', 'index.html');
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
const constSource = (name) => { const m = APP.match(new RegExp(`\\nconst ${name} = [\\[{][\\s\\S]*?\\n[\\]}];`)); assert.ok(m, `no const ${name}`); return m[0]; };

/** renderComponents over a page of plain objects: each row's markup, and its two buttons by class. */
function rowsHarness(assets, coreVersions = {}, flavor = null) {
  const made = [];
  const opened = [];
  const downloads = [];
  const mk = () => {
    const btns = {};
    const n = { innerHTML: '', hidden: false, textContent: '', attrs: {}, children: [] };
    n.querySelector = (sel) => {
      const cls = sel.replace(/^\./, '');
      if (!new RegExp(`class="[^"]*\\b${cls}\\b`).test(n.innerHTML)) return null;
      return (btns[cls] = btns[cls] || { cls });
    };
    n.btns = btns;
    n.appendChild = (c) => { n.children.push(c); return c; };
    n.setAttribute = (k, v) => { n.attrs[k] = v; };
    n.getAttribute = (k) => n.attrs[k] ?? null;
    return n;
  };
  const page = new Map();
  const ctx = vm.createContext({
    state: { assets, coreVersions, flavor, tunAvailable: true },
    $: (sel) => { if (!page.has(sel)) page.set(sel, mk()); return page.get(sel); },
    document: { createElement: () => { const n = mk(); made.push(n); return n; } },
    t: (k) => k,
    downloadComponent: (key) => downloads.push(key),
    openCorePicker: (key, btn) => opened.push([key, btn.cls])
  });
  vm.runInContext([constSource('COMPONENTS'), fnSource('escapeHtml'), fnSource('routerTunMissingKey'), fnSource('renderComponents')].join('\n'), ctx);
  ctx.renderComponents();
  const rows = ctx.$('#compList').children;
  return { rows, opened, downloads };
}

test('Required files: the three cores get «انتخاب نسخه» beside an unchanged update button; the other files keep one button', () => {
  const h = rowsHarness({ platform: 'win32', xray: true, 'xray-pattn': true, 'sing-box': false, geoip: true, geosite: true, tun2socks: false, wintun: true },
    { xray: '26.3.27', 'xray-pattn': '26.9.22', 'sing-box': '' });
  const byLabel = (k) => {
    const re = new RegExp(`class="comp-name">${k.replace(/\./g, '\\.')}[ <]`);
    const r = h.rows.find((x) => re.test(x.innerHTML));
    assert.ok(r, k);
    return r;
  };
  for (const [label, key, present] of [['comp.xray', 'xray', true], ['comp.xrayPattn', 'xray-pattn', true], ['comp.singbox', 'sing-box', false]]) {
    const row = byLabel(label);
    assert.match(row.innerHTML, /<button class="btn ghost comp-pick" type="button">cv\.choose<\/button>/, label);
    // the update button: the same classes, words and handler as before
    assert.match(row.innerHTML, present ? /<button class="btn ghost comp-btn">btn\.update<\/button>/ : /<button class="btn primary comp-btn">btn\.download<\/button>/, label);
    assert.ok(row.innerHTML.indexOf('comp-pick') < row.innerHTML.indexOf('comp-btn'), 'Choose version first, the update button ends the row');
    row.btns['comp-pick'].onclick();
    assert.deepEqual(h.opened.at(-1), [key, 'comp-pick']);
    row.btns['comp-btn'].onclick();
    assert.equal(h.downloads.at(-1), key);
  }
  for (const label of ['comp.geo', 'comp.tun2socksLegacy', 'comp.wintun']) assert.doesNotMatch(byLabel(label).innerHTML, /comp-pick|cv\.choose/, label);
  assert.equal(I18N.split("'cv.choose':").length - 1, 2, 'the button’s word in fa and en');
  // the installed versions, sing-box's too once it is there
  assert.match(byLabel('comp.xrayPattn').innerHTML, /<span class="comp-ver">v26\.9\.22<\/span>/);
  const sb = rowsHarness({ platform: 'linux', xray: true, 'sing-box': true }, { 'sing-box': '1.13.14' }, 'openwrt');
  const sbRow = sb.rows.find((x) => x.innerHTML.includes('comp.singboxRouter'));
  assert.match(sbRow.innerHTML, /<span class="comp-ver">v1\.13\.14<\/span>/);
  assert.match(sbRow.innerHTML, /comp-pick/, 'the router’s sing-box has the picker too');
});

test('the page opens the picker with what it needs, and refreshes itself after an install', async () => {
  const calls = [];
  const ctx = vm.createContext({
    state: { connected: false, connecting: false, assets: {}, tunAvailable: false },
    window: { corePicker: { open: (key, hooks) => calls.push(['open', key, hooks]) }, api: { assetsStatus: async () => ({ 'sing-box': true, xray: true }) } },
    anyXrayCore: () => 'from-assets',
    toast: () => {},
    renderComponents: () => calls.push(['rows']),
    updateXrayStatus: (r) => calls.push(['xrayStatus', r]),
    updateTunStatus: () => calls.push(['tunStatus']),
    refreshXrayVersion: () => calls.push(['versions'])
  });
  vm.runInContext(fnSource('openCorePicker'), ctx);
  const btn = { id: 'b' };
  ctx.openCorePicker('sing-box', btn);
  const [, key, hooks] = calls[0];
  assert.equal(key, 'sing-box');
  assert.equal(hooks.opener, btn);
  assert.equal(hooks.toast, ctx.toast);
  assert.equal(hooks.busy(), false);
  ctx.state.connecting = true;
  assert.equal(hooks.busy(), true, 'connecting counts');
  ctx.state.connecting = false;
  ctx.state.connected = true;
  assert.equal(hooks.busy(), true);
  hooks.onInstalled({ ok: true, assets: { 'sing-box': true }, tunAvailable: true, xrayReady: true });
  assert.deepEqual(ctx.state.assets, { 'sing-box': true });
  assert.equal(ctx.state.tunAvailable, true);
  assert.deepEqual(calls.slice(1), [['rows'], ['xrayStatus', true], ['tunStatus'], ['versions']]);
  // an install whose answer was lost and learned from the service (review I1): no assets in hand — read, the rest kept
  calls.length = 0;
  ctx.state.tunAvailable = true;
  await hooks.onInstalled({ ok: true, component: 'sing-box', tag: 'v1.13.14', version: '1.13.14', checked: true });
  assert.deepEqual(JSON.parse(JSON.stringify(ctx.state.assets)), { 'sing-box': true, xray: true });
  assert.equal(ctx.state.tunAvailable, true, 'not said, so not changed');
  assert.deepEqual(calls, [['rows'], ['xrayStatus', 'from-assets'], ['tunStatus'], ['versions']]);
});

test('the versions on the page: sing-box asked too and kept as its number; the core version on Home is still Xray’s', async () => {
  const asked = [];
  const answers = { xray: { ok: true, version: '26.3.27' }, 'xray-pattn': { ok: true, version: '26.9.22' }, 'sing-box': { ok: true, version: 'sing-box version 1.15.0-alpha.10' } };
  const xv = { textContent: '' };
  const ctx = vm.createContext({
    state: { coreVersions: {} },
    window: { api: { xrayVersion: async (id) => { asked.push(id); return answers[id]; } } },
    $: (sel) => (sel === '#xrayVersion' ? xv : null),
    t: (k) => k,
    renderComponents: () => {}
  });
  const coreKeys = APP.match(/\nconst CORE_KEYS = \[[^\n]*\];/);
  assert.ok(coreKeys, 'app.js has no one-line const CORE_KEYS');
  vm.runInContext([coreKeys[0], fnSource('coreVersionText'), fnSource('refreshXrayVersion')].join('\n'), ctx);
  await ctx.refreshXrayVersion();
  assert.deepEqual(asked, ['xray', 'xray-pattn', 'sing-box']);
  assert.deepEqual(JSON.parse(JSON.stringify(ctx.state.coreVersions)), { xray: '26.3.27', 'xray-pattn': '26.9.22', 'sing-box': '1.15.0-alpha.10' });
  assert.equal(ctx.state.xrayVersion, '26.3.27');
  assert.equal(xv.textContent, 'xray.version: 26.3.27');
  // what a core said that has no version in it is kept as it was, as before
  answers.xray = { ok: true, version: 'Xray (unknown build)' };
  await ctx.refreshXrayVersion();
  assert.equal(ctx.state.coreVersions.xray, 'Xray (unknown build)');
  // the update button refreshes them after sing-box too
  assert.match(fnSource('downloadComponent'), /if \(CORE_KEYS\.includes\(key\)\) refreshXrayVersion\(\);/);
});

test('M1: the update button, refused because a version install holds that core, says so in the user’s language', async () => {
  const toasts = [];
  const ctx = vm.createContext({
    state: { assets: { xray: true }, tunAvailable: true },
    window: { api: { downloadAsset: async () => ({ ok: false, error: 'another download or install of this core is running', coreBusy: true, assets: { xray: true } }) } },
    t: (k) => k,
    toast: (msg, kind) => toasts.push([msg, kind || '']),
    renderComponents: () => {}
  });
  vm.runInContext(fnSource('downloadComponent'), ctx);
  const btn = { textContent: 'btn.update', disabled: false };
  await ctx.downloadComponent('xray', btn);
  assert.deepEqual(toasts.at(-1), ['comp.coreBusy', 'warn']);
  assert.equal(btn.disabled, false);
  assert.equal(btn.textContent, 'btn.update');
  assert.equal(I18N.split("'comp.coreBusy':").length - 1, 2, 'in fa and en');
});

test('progress: an install the picker runs shows in its card — not in a toast on top', () => {
  const handler = APP.slice(APP.indexOf('window.api.onAssetProgress((d) => {'), APP.indexOf('/* remove all downloaded runtime files */'));
  assert.match(handler, /if \(window\.corePicker && window\.corePicker\.progress\(d\)\) return;/);
  assert.ok(handler.indexOf("d.component === 'app'") < handler.indexOf('window.corePicker'), 'the app installer’s own branch stays first');
  assert.ok(handler.indexOf('window.corePicker') < handler.indexOf('toast('), 'before the toast');
});

test('index.html loads the picker after i18n.js and before app.js — the router’s page gets it too', () => {
  const scripts = [...HTML.matchAll(/<script src="([^"]+)"><\/script>/g)].map((m) => m[1]);
  assert.ok(scripts.includes('corePicker.js'), scripts.join(', '));
  assert.ok(scripts.indexOf('i18n.js') < scripts.indexOf('corePicker.js') && scripts.indexOf('corePicker.js') < scripts.indexOf('app.js'), scripts.join(', '));
  // the headless server serves every file of src/renderer, and injects web-api.js before i18n.js
  assert.match(R('src', 'server', 'server.js'), /'<script src="web-api\.js"><\/script>\\n {2}<script src="i18n\.js"><\/script>'/);
});
