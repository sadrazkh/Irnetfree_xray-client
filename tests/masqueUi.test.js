'use strict';
/**
 * MASQUE and + WARP in the window and the router's web UI (v1.25.0, task T3;
 * .superpowers/sdd/masque/design.md §6 and the approved sample
 * .superpowers/mockups/masque.html, both git-ignored).
 *
 * The + WARP dialog (its choices → api.addWarp, the steps while it runs, a
 * refusal and the warnings in the window's words, an imported account read
 * back), a MASQUE server's card (its WARP / h3 / h2 tags, JSON on Copy and QR)
 * and the Pro view of one (MASQUE in the picker with its «new» tag, the HTTP
 * version as cards, the WARP card and its switch, the cores it takes, Mux and
 * the other anti-DPI field shown off). app.js reaches into the DOM at load, so
 * — like jsonUi.test.js — its own functions run in a vm over a fake page.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const SF = require('../src/renderer/serverFields');
const W = require('../src/main/warp');
const { createServer } = require('../src/main/parser');

const R = (...p) => fs.readFileSync(path.join(__dirname, '..', ...p), 'utf8').replace(/\r\n/g, '\n');
const APP = R('src', 'renderer', 'app.js');
const HTML = R('src', 'renderer', 'index.html');
const I18N = R('src', 'renderer', 'i18n.js');
const STYLES = R('src', 'renderer', 'styles.css');
const LISTS = R('src', 'renderer', 'lists.css');

/** A top-level (async) function of app.js, as source: a one-liner whole, else up to the `}` in column 0 that closes it. */
function fnSource(name) {
  let start = APP.indexOf(`\nfunction ${name}(`);
  if (start === -1) start = APP.indexOf(`\nasync function ${name}(`);
  assert.ok(start > -1, `app.js has no function ${name}`);
  const eol = APP.indexOf('\n', start + 1);
  if (/\}\s*$/.test(APP.slice(start + 1, eol))) return APP.slice(start, eol);
  const end = APP.indexOf('\n}\n', eol);
  assert.ok(end > -1, `app.js: ${name} does not end in column 0`);
  return APP.slice(start, end + 2);
}
/** A top-level one-line `const NAME = …;` of app.js, as source. */
function constSource(name) {
  const m = APP.match(new RegExp(`\\nconst ${name} = [^\\n]*;\\n`));
  assert.ok(m, `app.js has no const ${name}`);
  return m[0];
}
/** Both languages' tables, as the renderer has them. */
function i18n() {
  const ctx = { window: {}, document: { documentElement: {}, querySelectorAll: () => [] } };
  vm.runInNewContext(I18N, ctx);
  return (lang, key) => { ctx.window.i18n.applyI18n(lang); return ctx.window.i18n.t(key); };
}
const TR = i18n();
const en = (k) => TR('en', k);
const fa = (k) => TR('fa', k);
const plain = (x) => JSON.parse(JSON.stringify(x));
const tick = () => new Promise((r) => setImmediate(r));

/* ------------------------------------ a fake page ------------------------------------ */

const camel = (s) => s.replace(/-([a-z])/g, (m, c) => c.toUpperCase());
/** Enough of an element for edNode / appendSome and the code that reads back what they made. */
function fakeEl(tag) {
  const cls = new Set();
  const parts = {};
  const el = {
    tagName: String(tag || 'div').toUpperCase(), children: [], attrs: {}, dataset: {}, style: {},
    hidden: false, disabled: false, checked: false, value: '', id: '', title: '', html: '', _text: '',
    onclick: null, onchange: null, oninput: null,
    get className() { return [...cls].join(' '); },
    set className(v) { cls.clear(); String(v || '').split(/\s+/).filter(Boolean).forEach((c) => cls.add(c)); },
    classList: {
      add: (...c) => c.forEach((x) => cls.add(x)), remove: (...c) => c.forEach((x) => cls.delete(x)), contains: (c) => cls.has(c),
      toggle: (c, on) => { const v = on === undefined ? !cls.has(c) : !!on; if (v) cls.add(c); else cls.delete(c); return v; }
    },
    get textContent() { return el._text + el.children.map((c) => (typeof c === 'string' ? c : c.textContent)).join(''); },
    set textContent(v) { el._text = String(v == null ? '' : v); el.children = []; },
    set innerHTML(v) { el.html = String(v); el.children = []; },
    get innerHTML() { return el.html; },
    setAttribute(k, v) {
      el.attrs[k] = String(v);
      if (k === 'disabled') el.disabled = true;
      if (k === 'id') el.id = String(v);
      if (k.startsWith('data-')) el.dataset[camel(k.slice(5))] = String(v);
    },
    getAttribute(k) { return k in el.attrs ? el.attrs[k] : null; },
    appendChild(c) { el.children.push(c); return c; },
    append(...cs) { el.children.push(...cs.map((c) => (c && typeof c === 'object' ? c : String(c)))); },
    querySelector(sel) { return parts[sel] || (parts[sel] = fakeEl('span')); },
    remove() {}, scrollIntoView(o) { el.scrolled = o || true; }
  };
  return el;
}
/** Every element under `el` (itself included) that `pred` says yes to. */
function all(el, pred, out = []) {
  if (!el || typeof el !== 'object') return out;
  if (pred(el)) out.push(el);
  for (const c of el.children) all(c, pred, out);
  return out;
}
const one = (el, pred, what) => { const f = all(el, pred); assert.ok(f.length, `nothing found: ${what}`); return f[0]; };
const hasClass = (el, c) => el.className.split(/\s+/).includes(c);

/* ------------------------------------ fixtures ------------------------------------ */

const DEVICE = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const EDGE = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const USQUE = JSON.stringify({
  private_key: DEVICE.privateKey.export({ type: 'sec1', format: 'der' }).toString('base64'),
  endpoint_v4: '162.159.198.1', endpoint_v6: '2606:4700:103::1', endpoint_h2_v4: '162.159.198.2',
  endpoint_pub_key: EDGE.publicKey.export({ type: 'spki', format: 'pem' }), ipv4: '172.16.0.2', ipv6: '2606:4700:110:8a36::2', id: 'dev'
});
const warpServer = (more) => createServer(Object.assign({
  protocol: 'masque', name: '☁ WARP · H3', address: '162.159.198.1', port: '443', sni: 'consumer-masque.cloudflareclient.com',
  warpPrivateKey: DEVICE.privateKey.export({ type: 'pkcs8', format: 'pem' }), warpPublicKey: EDGE.publicKey.export({ type: 'spki', format: 'pem' }),
  warpAddress: '172.16.0.2, 2606:4700:110:8a36::2'
}, more));
const ownServer = (more) => createServer(Object.assign({ protocol: 'masque', name: 'M', address: 'm.example.com', port: '443', masqueHttp: 'h2', masqueUser: 'u', masquePass: 'p' }, more));

/* ------------------------------------ strings ------------------------------------ */

const NEW_KEYS = ['btn.addWarp', 'warp.title', 'warp.lede', 'warp.step1', 'warp.step2', 'warp.wayNew', 'warp.wayImport', 'warp.newLede',
  'warp.routeDirect', 'warp.routeDirectSub', 'warp.routeProxy', 'warp.routeProxySub', 'warp.routeProxyOff', 'warp.tos', 'warp.tosLink',
  'warp.license', 'warp.licensePh', 'warp.licenseHint', 'warp.importLabel', 'warp.importHint', 'warp.chipKey', 'warp.chipKeyP256', 'warp.chipNoKey',
  'warp.chipPub', 'warp.chipNoPub', 'warp.chipNotJson', 'warp.chipNoAccount', 'warp.httpBoth', 'warp.httpBothDesc', 'warp.endpoint', 'warp.epAuto',
  'warp.epV6', 'warp.epCustom', 'warp.epAutoHint', 'warp.epV6Hint', 'warp.address', 'warp.addressHint', 'warp.cover', 'warp.coverPh', 'warp.coverHint',
  'warp.antiDpi', 'warp.antiDpiHint', 'warp.make', 'warp.add', 'warp.working', 'warp.noteTwo', 'warp.noteOne', 'warp.pKey', 'warp.pKeyAt', 'warp.pReg',
  'warp.pEnroll', 'warp.pEnable', 'warp.pLicense', 'warp.pRead', 'warp.pAdd', 'warp.pAddedTwo', 'warp.pAddedOne', 'warp.doneLede', 'warp.doneLedeOne',
  'warp.see', 't.warpAdded', 'srv.copyJson', 'btn.qrJson', 'edit.protoNew', 'masque.h3Desc', 'masque.h2Desc', 'masque.warpTitle', 'masque.warpOff',
  'masque.warpFromSignup', 'masque.warpAuto', 'masque.optional', 'masque.tlsOnly', 'masque.noTransport', 'masque.muxNone', 'masque.muxHint',
  'masque.off', 'masque.noiseOffH2', 'masque.fragmentOffH3', 'masque.certNoteWarp', 'sf.sni.hint.warp', 'sf.fp.hint.h3', 'sf.ech.hint.warp',
  'sf.warpPublicKey.hint.masque', 'sf.warpAddress.hint.masque', 'sf.engine.hint.masque', 'sf.finalMask.hint.masque', 'sfo.fp._',
  'sfg.pattn.masque', 'edit.moreInPro.masque'];

test('every MASQUE and + WARP string: once in fa and once in en, one clean literal (no straight apostrophe), English in en', () => {
  for (const key of NEW_KEYS) {
    assert.equal(I18N.split(`'${key}':`).length - 1, 2, `'${key}' is not defined exactly once in each of fa and en`);
    for (const line of I18N.split('\n').filter((l) => l.includes(`'${key}':`))) {
      const m = line.match(/^\s*'[^']+':\s*'((?:[^'\\]|\\.)*)',?\s*$/);
      assert.ok(m, `${key}: not a single clean string literal — a straight ' inside? ${line.trim().slice(0, 90)}`);
      assert.ok(!/\\'/.test(m[1]), `${key}: use ’ and not an escaped '`);
    }
    assert.ok(fa(key).trim() && en(key).trim(), key);
    assert.doesNotMatch(en(key), /[؀-ۿ]/, `en '${key}' is Persian`);
  }
  // the placeholders the code fills, in both languages
  for (const [key, slots] of [['warp.tos', ['{terms}']], ['warp.epAutoHint', ['{h3}', '{h2}']], ['warp.epV6Hint', ['{h3}', '{h2}']],
    ['masque.warpAuto', ['{host}', '{path}']], ['masque.noTransport', ['{over}']], ['t.warpAdded', ['{names}']], ['edit.moreInPro.masque', ['{link}']]]) {
    for (const s of slots) { assert.ok(fa(key).includes(s), `fa ${key} ${s}`); assert.ok(en(key).includes(s), `en ${key} ${s}`); }
  }
  // every code warp.js answers with reads in both (the dialog shows them)
  for (const c of W.ERROR_CODES) { assert.notEqual(en('warp.err.' + c), 'warp.err.' + c); assert.notEqual(fa('warp.err.' + c), 'warp.err.' + c); }
  for (const c of W.WARNING_CODES) { assert.notEqual(en('warp.warn.' + c), 'warp.warn.' + c); }
  assert.equal(fa('sfp.masque'), 'تونل IP روی HTTP/3', 'the sample’s line under MASQUE in the picker');
});

/* ------------------------------------ the + WARP dialog ------------------------------------ */

// v1.26 (tests/warpWgUi.test.js) split the form by its kind and reads the accounts back: their helpers come too
const DIALOG_FNS = ['edNode', 'appendSome', 'richLine', 'httpCards', 'warpChips', 'warpFresh', 'warpShown', 'openWarp', 'closeWarp', 'warpArgs',
  'warpErrorText', 'warpWarningTexts', 'looksP256', 'warpReadImport', 'warpImportChips', 'warpNum', 'warpField', 'warpSeg', 'warpFormNodes',
  'warpProgressNodes', 'warpFootNodes', 'renderWarp', 'runWarp', 'warpUseChain', 'warpSeeInList',
  'fmtBytes', 'warpLicenses', 'warpCount', 'warpHops', 'warpHop', 'warpStoppedText', 'warpFill', 'warpReadWgImport', 'warpWgImportChips', 'warpBytes',
  'warpDate', 'warpTypeChip', 'warpAccountBody', 'warpAccountBox', 'warpLicenseNodes', 'warpNewNodes', 'warpTwoWg', 'warpTwoMasque', 'warpNoteText',
  'warpRenderFoot'];

function dialogHarness({ lang = 'en', connected = false, addWarp, servers = [] } = {}) {
  const els = new Map();
  const get = (id) => { if (!els.has(id)) { const e = fakeEl('div'); e.id = id; els.set(id, e); } return els.get(id); };
  get('warpModal').hidden = true;
  const calls = [];
  const store = new Map();
  const ctx = vm.createContext({
    $: (sel) => get(String(sel).replace(/^#/, '')),
    $$: (sel) => (sel === '#serverList .server-card' ? (ctx.cards || []) : []),
    document: { createElement: fakeEl },
    t: (k) => TR(lang, k),
    toast: (msg, kind) => calls.push(['toast', msg, kind || '']),
    state: { servers, connected, selectedServerId: null },
    renderServers: () => calls.push(['renderServers']), renderPicker() {}, renderChains() {}, renderPool() {}, renderAdvanced() {},
    showView: (v) => calls.push(['showView', v]),
    selectServer: (id) => calls.push(['selectServer', id]),
    srvById: (id) => ctx.state.servers.find((s) => s.id === id),
    groupKey: (subId) => (subId ? 'sub:' + subId : 'manual'),
    foldedGroups: new Set(), setGroupFolded: (k, f) => calls.push(['fold', k, f]),
    localStorage: { getItem: (k) => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, String(v)) },
    window: {
      i18n: { lang },
      api: {
        addWarp: addWarp || (async () => ({ ok: false, code: 'failed', error: 'no stub' })),
        openExternal: (url) => calls.push(['openExternal', url])
      }
    },
    atob: (s) => Buffer.from(s, 'base64').toString('latin1'),
    JSON, String, Array, Object, Set, Promise, Error, Number, Boolean
  });
  vm.runInContext([
    'let warpForm = null;',
    ...['WARP_SEEN_KEY', 'WARP_TERMS_URL', 'WARP_EDGES', 'WARP_WG_EDGE', 'WARP_LICENSE_RE', 'WARP_IMPORT_PH', 'WARP_WG_IMPORT_PH', 'P256_OID'].map(constSource),
    ...DIALOG_FNS.map(fnSource),
    'function form() { return warpForm; }'
  ].join('\n'), ctx);
  return { ctx, get, calls, store, form: () => ctx.form() };
}
const buttonsOf = (el) => all(el, (e) => e.tagName === 'BUTTON');

test('+ WARP: the button sits beside + WireGuard; the dialog is a modal of its own; opening it closes the other add boxes and the «new» dot', () => {
  assert.match(HTML, /id="btnWgOpen" data-i18n="btn\.addWg">\+ WireGuard<\/button>\s*<button class="btn ghost" id="btnWarpOpen" data-i18n="btn\.addWarp">\+ WARP<\/button>/);
  assert.match(HTML, /<div class="modal-overlay" id="warpModal" hidden>\s*<div class="modal warp-modal" role="dialog"/);
  for (const id of ['warpTitle', 'warpClose', 'warpBody', 'warpFoot']) assert.match(HTML, new RegExp(`id="${id}"`));
  assert.match(APP, /\$\('#btnWarpOpen'\)\.onclick = openWarp;/);
  assert.match(APP, /\$\('#warpClose'\)\.onclick = closeWarp;/);
  assert.match(APP, /if \(warpShown\(\)\) renderWarp\(\);/, 'a language switch draws the open dialog again');

  const h = dialogHarness();
  for (const id of ['importBox', 'wgBox', 'proxyBox']) h.get(id).hidden = false;
  h.get('btnWarpOpen').classList.add('is-new');
  h.ctx.openWarp();
  for (const id of ['importBox', 'wgBox', 'proxyBox']) assert.equal(h.get(id).hidden, true, `#${id} closes: one add form at a time`);
  assert.equal(h.get('warpModal').hidden, false);
  assert.equal(hasClass(h.get('btnWarpOpen'), 'is-new'), false);
  assert.equal(h.store.get('irnf.warpSeen'), '1');
  h.ctx.closeWarp();
  assert.equal(h.ctx.warpShown(), false);
});

test('+ WARP, a new account: the sample’s two steps — via the connection off (with why) while not connected, the terms link, the cards (both by default), and what Make sends', async () => {
  let sent = null;
  const h = dialogHarness({ addWarp: async (a) => { sent = plain(a); return { ok: false, code: 'busy', error: 'x' }; } });
  h.ctx.openWarp();
  // WireGuard is the default kind since v1.26 (tests/warpWgUi.test.js): MASQUE is picked first
  one(h.get('warpBody'), (e) => e.dataset.warp === 'kind:masque', 'MASQUE').onclick();
  const body = h.get('warpBody');
  const foot = h.get('warpFoot');
  const text = body.textContent;
  for (const k of ['warp.step1', 'warp.step2', 'warp.wayNew', 'warp.wayImport', 'warp.routeDirect', 'warp.routeProxy', 'warp.routeProxyOff', 'warp.tosLink', 'warp.license', 'warp.cover', 'warp.antiDpi']) {
    assert.ok(text.includes(en(k)), `the dialog says ${k}`);
  }
  const radios = all(body, (e) => e.tagName === 'INPUT' && e.attrs.type === 'radio');
  assert.deepEqual(radios.map((r) => [r.attrs.value, r.disabled, r.checked]), [['direct', false, true], ['proxy', true, false]], 'through the connection only when there is one');
  one(body, (e) => e.tagName === 'BUTTON' && e.textContent === en('warp.tosLink'), 'the terms link').onclick();
  assert.deepEqual(h.calls.find((c) => c[0] === 'openExternal'), ['openExternal', 'https://www.cloudflare.com/application/terms/']);
  const cards = all(body, (e) => hasClass(e, 'ed-http-opt'));
  assert.deepEqual(cards.map((c) => [c.dataset.http, hasClass(c, 'on')]), [['h3', false], ['h2', false], ['both', true]], 'both is the default');
  assert.deepEqual(buttonsOf(foot).map((b) => b.textContent), [en('warp.make'), en('btn.cancel')]);
  assert.ok(foot.textContent.includes(en('warp.noteTwo')));
  // the endpoint line names Cloudflare's edges, left-to-right
  const bdis = all(body, (e) => e.tagName === 'BDI').map((e) => e.textContent);
  assert.ok(bdis.includes('162.159.198.1') && bdis.includes('162.159.198.2'));

  // choices: HTTP/3 only, IPv6, a license, a cover domain, anti-DPI off
  cards[0].onclick();
  assert.ok(h.get('warpFoot').textContent.includes(en('warp.noteOne')));
  one(h.get('warpBody'), (e) => e.dataset.warp === 'endpoint:v6', 'IPv6').onclick();
  assert.ok(all(h.get('warpBody'), (e) => e.tagName === 'BDI').some((e) => e.textContent === '2606:4700:103::1'));
  const input = (id) => one(h.get('warpBody'), (e) => e.id === id, id);
  input('warp-licenses').value = ' abcdEFGH-12345678-ijklmnop ';
  input('warp-licenses').oninput();
  input('warp-cover').value = 'www.example.com';
  input('warp-cover').oninput();
  const sw = input('warp-antiDpi');
  sw.checked = false;
  sw.onchange();
  one(h.get('warpFoot'), (e) => e.id === 'warpGo', 'Make').onclick();
  await tick();
  assert.deepEqual(sent, { kind: 'masque', mode: 'new', via: 'direct', count: 1, licenses: ['abcdEFGH-12345678-ijklmnop'], http: 'h3', endpoint: 'v6', cover: 'www.example.com', antiDpi: false });
  // connected: the second route can be chosen, and is sent
  const c = dialogHarness({ connected: true, addWarp: async (a) => { sent = plain(a); return { ok: false, code: 'busy' }; } });
  c.ctx.openWarp();
  one(c.get('warpBody'), (e) => e.dataset.warp === 'kind:masque', 'MASQUE').onclick();
  const proxy = all(c.get('warpBody'), (e) => e.tagName === 'INPUT' && e.attrs.value === 'proxy')[0];
  assert.equal(proxy.disabled, false);
  assert.ok(c.get('warpBody').textContent.includes(en('warp.routeProxySub')));
  proxy.checked = true;
  proxy.onchange();
  await c.ctx.runWarp();
  assert.deepEqual(sent, { kind: 'masque', mode: 'new', via: 'proxy', count: 1, licenses: [], http: 'both', endpoint: 'auto', cover: '', antiDpi: true });
});

test('warpArgs, MASQUE: the dialog’s state as servers:addWarp takes it — its kind, the count and the keys as a list; an import carries its text and no route, a clean IP its address', () => {
  const { ctx } = dialogHarness();
  const f = (o) => plain(ctx.warpArgs(Object.assign(ctx.warpFresh(), { kind: 'masque' }, o)));
  assert.deepEqual(f({}), { kind: 'masque', mode: 'new', via: 'direct', count: 1, licenses: [], http: 'both', endpoint: 'auto', cover: '', antiDpi: true });
  assert.deepEqual(f({ licenses: ' abcdEFGH-12345678-ijklmnop \n\n  ', count: '3' }).licenses, ['abcdEFGH-12345678-ijklmnop']);
  assert.equal(f({ count: '3' }).count, 3);
  assert.ok(!('license' in f({ licenses: 'abcdEFGH-12345678-ijklmnop' })), 'the pre-1.26 single license is never sent: licenses replaces it');
  assert.deepEqual(f({ way: 'import', importText: '{"a":1}', route: 'proxy', licenses: 'x', count: '4', endpoint: 'custom', address: ' 188.114.97.6:2408 ', http: 'h2', cover: ' a.example ' }),
    { kind: 'masque', mode: 'import', importText: '{"a":1}', http: 'h2', endpoint: 'custom', address: '188.114.97.6:2408', cover: 'a.example', antiDpi: true });
  assert.equal(f({ http: 'h4', endpoint: 'moon' }).http, 'both', 'only what warp.js knows');
  assert.equal(f({ endpoint: 'moon' }).endpoint, 'auto');
});

test('+ WARP, while servers:addWarp runs: the steps pending, Make off; then done — the list redrawn, «See in the list» selects the first new server', async () => {
  let release;
  const added = [{ id: 'w1', name: '☁ WARP · H3' }, { id: 'w2', name: '☁ WARP · H2' }];
  const h = dialogHarness({
    servers: [{ id: 'old', name: 'Old' }],
    addWarp: () => new Promise((r) => { release = () => r({ ok: true, servers: [{ id: 'old', name: 'Old' }, ...added], added, account: { id: 'dev' }, warnings: [] }); })
  });
  h.ctx.openWarp();
  h.form().kind = 'masque';
  const run = h.ctx.runWarp();
  const list = one(h.get('warpBody'), (e) => hasClass(e, 'warp-progress'), 'the steps');
  assert.equal(list.attrs['aria-busy'], 'true');
  const lines = list.children.map((li) => li.textContent);
  for (const k of ['warp.pKey', 'warp.pReg', 'warp.pEnroll', 'warp.pEnable', 'warp.pAdd']) assert.ok(lines.some((l) => l.includes(en(k))), k);
  assert.ok(lines.every((l) => l.startsWith('◌')), 'pending, every one: the call does not stream');
  assert.ok(lines.some((l) => l.includes('api.cloudflareclient.com')));
  const go = one(h.get('warpFoot'), (e) => e.id === 'warpGo', 'Make');
  assert.equal(go.disabled, true);
  assert.equal(go.textContent, en('warp.working'));
  await h.ctx.runWarp();   // a second click while it runs does nothing
  release();
  await run;
  assert.equal(h.form().phase, 'done');
  assert.deepEqual(h.ctx.state.servers.map((s) => s.id), ['old', 'w1', 'w2']);
  assert.equal(h.ctx.state.selectedServerId, 'w1', 'nothing was selected: the first new one is');
  assert.ok(h.calls.some((c) => c[0] === 'renderServers'));
  const done = one(h.get('warpBody'), (e) => hasClass(e, 'warp-progress'), 'the steps');
  assert.ok(done.children.every((li) => li.textContent.startsWith('✓')));
  assert.ok(done.textContent.includes(en('warp.pAddedTwo')) && done.textContent.includes('☁ WARP · H3 / ☁ WARP · H2'));
  assert.ok(h.get('warpBody').textContent.includes(en('warp.doneLede').replace(/\*\*/g, '')));
  assert.deepEqual(buttonsOf(h.get('warpFoot')).map((b) => b.textContent), [en('warp.see'), en('tb.close')]);
  // the list: shown, the first new server selected and scrolled to
  const card = fakeEl('div'); card.dataset.srvId = 'w1';
  h.ctx.cards = [card];
  one(h.get('warpFoot'), (e) => e.id === 'warpSee', 'See').onclick();
  assert.equal(h.get('warpModal').hidden, true);
  assert.deepEqual(h.calls.filter((c) => c[0] === 'showView' || c[0] === 'selectServer'), [['showView', 'servers'], ['selectServer', 'w1']]);
  assert.ok(card.scrolled);
  // opened again after it finished: a fresh form
  h.ctx.openWarp();
  assert.equal(h.form().phase, 'form');
});

test('+ WARP, import: no network — the real servers:addWarp handler and createServer make both servers; the account read back as chips while it is pasted', async () => {
  let list = [];
  const handler = W.warpHandler({ createServer, connected: () => false, getServers: () => list, setServers: (l) => { list = l; } });
  const h = dialogHarness({ lang: 'fa', addWarp: handler });
  h.ctx.openWarp();
  one(h.get('warpBody'), (e) => e.dataset.warp === 'kind:masque', 'MASQUE').onclick();
  one(h.get('warpBody'), (e) => e.dataset.warp === 'way:import', 'Import').onclick();
  assert.equal(buttonsOf(h.get('warpFoot'))[0].textContent, fa('warp.add'));
  const ta = one(h.get('warpBody'), (e) => e.id === 'warp-importText', 'the text box');
  assert.equal(ta.tagName, 'TEXTAREA');
  assert.ok(ta.attrs.placeholder.includes('"private_key"'));
  const chips = () => one(h.get('warpBody'), (e) => hasClass(e, 'ed-chips-read'), 'chips').children.map((c) => [c.className, c.textContent]);
  ta.value = '{"private_key": ';
  ta.oninput();
  assert.deepEqual(chips(), [['dim', fa('warp.chipNotJson')]]);
  ta.value = USQUE;
  ta.oninput();
  assert.deepEqual(chips(), [['', fa('warp.chipKeyP256')], ['', fa('warp.chipPub')], ['info', 'IPv4 172.16.0.2'], ['info', 'IPv6 2606:4700:110:8a36::2']]);
  await h.ctx.runWarp();
  assert.equal(h.form().phase, 'done', h.form().error);
  assert.deepEqual(list.map((s) => [s.name, s.protocol, s.address]), [['☁ WARP · H3', 'masque', '162.159.198.1'], ['☁ WARP · H2', 'masque', '162.159.198.2']]);
  assert.deepEqual(h.ctx.state.servers.map((s) => s.name), list.map((s) => s.name));
  const steps = one(h.get('warpBody'), (e) => hasClass(e, 'warp-progress'), 'steps');
  assert.equal(steps.children.length, 2, 'an import: read the account, add the servers');
  assert.ok(steps.children[0].textContent.includes(fa('warp.pRead')));
  assert.equal(h.ctx.warpNum(1), '۱', 'Persian digits in Persian');
});

test('+ WARP, refused: back to the form with the reason in the window’s words ({msg} = the detail); unknown codes and a thrown call are “failed”; closed meanwhile, a toast', async () => {
  const answers = [
    [{ ok: false, code: 'blocked', error: 'Could not reach api.cloudflareclient.com: ECONNRESET', detail: 'ECONNRESET' }, en('warp.err.blocked').replace('{msg}', 'ECONNRESET')],
    [{ ok: false, code: 'rejected', error: 'x', detail: 'Invalid public key' }, 'Cloudflare refused the request: Invalid public key'],
    [{ ok: false, code: 'badCover', error: 'The cover domain must be a domain name' }, en('warp.err.badCover')],
    [{ ok: false, code: 'nonsense', error: 'odd' }, en('warp.err.failed').replace('{msg}', 'odd')]
  ];
  for (const [res, want] of answers) {
    const h = dialogHarness({ addWarp: async () => res });
    h.ctx.openWarp();
    Object.assign(h.form(), { kind: 'masque', cover: 'kept.example' });
    await h.ctx.runWarp();
    assert.equal(h.form().phase, 'form');
    assert.equal(one(h.get('warpBody'), (e) => hasClass(e, 'warp-error'), 'the reason').textContent, want);
    assert.equal(one(h.get('warpBody'), (e) => e.id === 'warp-cover', 'cover').value, 'kept.example', 'what was typed stays');
  }
  const thrown = dialogHarness({ addWarp: async () => { throw new Error('bridge down'); } });
  thrown.ctx.openWarp();
  await thrown.ctx.runWarp();
  assert.equal(thrown.form().error, en('warp.err.failed').replace('{msg}', 'bridge down'));
  // the dialog closed while it ran: the end comes as a toast
  const closed = dialogHarness({ addWarp: async () => ({ ok: false, code: 'rateLimited', error: '429' }) });
  closed.ctx.openWarp();
  const p = closed.ctx.runWarp();
  closed.ctx.closeWarp();
  await p;
  assert.deepEqual(closed.calls.filter((c) => c[0] === 'toast'), [['toast', en('warp.err.rateLimited'), 'err']]);
  const ok = dialogHarness({ addWarp: async () => ({ ok: true, servers: [], added: [{ id: 'a', name: '☁ WARP · H2' }], warnings: [] }) });
  ok.ctx.openWarp();
  const q = ok.ctx.runWarp();
  ok.ctx.closeWarp();
  await q;
  assert.deepEqual(ok.calls.filter((c) => c[0] === 'toast'), [['toast', en('t.warpAdded').replace('{names}', '☁ WARP · H2'), 'ok']]);
});

test('+ WARP, made with warnings: Cloudflare left WARP off, the WARP+ key refused — the step says so and the warning is shown, in the window’s words', async () => {
  const h = dialogHarness({
    addWarp: async () => ({ ok: true, servers: [], added: [{ id: 'a', name: '☁ WARP · H3' }],
      warnings: [{ code: 'warpNotEnabled', message: 'still off' }, { code: 'licenseFailed', cause: 'rejected', message: 'Invalid license' }] })
  });
  h.ctx.openWarp();
  Object.assign(h.form(), { kind: 'masque', licenses: 'abcdEFGH-12345678-ijklmnop', http: 'h3' });
  await h.ctx.runWarp();
  const steps = one(h.get('warpBody'), (e) => hasClass(e, 'warp-progress'), 'steps').children.map((li) => li.textContent);
  assert.ok(steps.find((l) => l.includes(en('warp.pEnable'))).startsWith('!'));
  assert.ok(steps.find((l) => l.includes(en('warp.pLicense'))).startsWith('!'));
  assert.ok(steps.find((l) => l.includes(en('warp.pAddedOne'))).startsWith('✓'));
  const warns = all(h.get('warpBody'), (e) => hasClass(e, 'ed-warn')).map((e) => e.textContent);
  assert.deepEqual(warns, [en('warp.warn.warpNotEnabled'), en('warp.warn.licenseFailed').replace('{msg}', 'Invalid license')]);
  assert.ok(h.get('warpBody').textContent.includes(en('warp.doneLedeOne')));
});

test('warpReadImport: usque’s config.json, an Xray WARP outbound (alone, in a config, its warp object) — the keys seen, P-256 recognised; not JSON, no account said', () => {
  const { ctx } = dialogHarness();
  const r = plain(ctx.warpReadImport(USQUE));
  assert.deepEqual(r, { key: true, p256: true, pub: true, addrs: ['172.16.0.2', '2606:4700:110:8a36::2'] });
  const ob = warpServer().outbound;
  const share = JSON.stringify({ remarks: 'W', outbounds: [Object.assign({ tag: 'proxy' }, ob)] });
  assert.deepEqual(plain(ctx.warpReadImport(share)), { key: true, p256: true, pub: true, addrs: ['172.16.0.2/32', '2606:4700:110:8a36::2/128'] });
  assert.equal(ctx.warpReadImport(JSON.stringify(ob)).p256, true);
  assert.equal(ctx.warpReadImport(JSON.stringify({ warp: ob.streamSettings.masqueSettings.warp })).pub, true);
  const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 1024 }).privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');
  assert.equal(ctx.warpReadImport(JSON.stringify({ private_key: rsa, endpoint_pub_key: 'x', ipv4: '1.2.3.4' })).p256, false);
  assert.deepEqual(plain(ctx.warpReadImport('{"private_key": "")')), { notJson: true });
  assert.deepEqual(plain(ctx.warpReadImport('{"outbounds": [{"protocol": "vless"}]}')), { noAccount: true });
  assert.equal(ctx.warpReadImport('   '), null);
});

/* ------------------------------------ the server card ------------------------------------ */

function cardHarness() {
  const ctx = vm.createContext({
    window: { ServerFields: SF }, document: { createElement: fakeEl },
    state: { activeServerId: null, connected: false, selectedServerId: null, pings: {} },
    t: en, pingResultLabel: () => ({ cls: '', txt: '—' }), usageLabel: () => '', connectGlyph: (b) => b,
    selectServer() {}, pingServer() {}, copyServerLink() {}, showServerQr() {}, openEdit() {}, connect() {}, deleteServer() {}, clearUsageFor() {},
    String
  });
  vm.runInContext(['escapeHtml', 'sfTable', 'srvTags', 'serverCard'].map(fnSource).join('\n'), ctx);
  return ctx;
}

test('a MASQUE server’s card: WARP and its HTTP version beside the name, derived from the outbound; Copy and QR say they give JSON; the badge’s colour', () => {
  const ctx = cardHarness();
  assert.deepEqual(plain(ctx.srvTags(warpServer())), ['WARP', 'h3']);
  assert.deepEqual(plain(ctx.srvTags(warpServer({ masqueHttp: 'h2' }))), ['WARP', 'h2']);
  assert.deepEqual(plain(ctx.srvTags(ownServer())), ['h2']);
  assert.deepEqual(plain(ctx.srvTags({ protocol: 'vless', outbound: {} })), []);
  const card = ctx.serverCard(Object.assign(warpServer(), { id: 'w1' })).innerHTML;
  assert.match(card, /<span class="proto-badge proto-masque">masque<\/span>/);
  assert.match(card, /<span class="srv-tags"><span class="srv-tag warp" dir="ltr">WARP<\/span><span class="srv-tag" dir="ltr">h3<\/span><\/span>/);
  assert.match(card, new RegExp(`class="icon-btn copy-srv" data-i18n-title="srv\\.copyJson" title="${en('srv.copyJson')}"`));
  assert.match(card, new RegExp(`class="icon-btn qr-srv" data-i18n-title="btn\\.qrJson" title="${en('btn.qrJson').replace(/[()]/g, '\\$&')}"`));
  const vless = ctx.serverCard({ id: 'v', name: 'V', protocol: 'vless', address: 'a', port: 1, outbound: {} }).innerHTML;
  assert.doesNotMatch(vless, /srv-tags/);
  assert.match(vless, /data-i18n-title="btn\.copy" title="copy"/);
  // the QR of a MASQUE server takes the JSON path (ASCII escapes, the size limit), as a JSON server's
  assert.match(fnSource('showServerQr'), /const isJson = !!srv && \(srv\.source === 'json' \|\| srv\.protocol === 'masque'\);/);
  // the badge: in styles.css beside the others, the same in the picker, chains and the pool (they all write proto-<protocol>)
  assert.match(STYLES, /\.proto-hysteria2 \{[^}]*\}\n\.proto-masque \{ color: var\(--accentInk\); border-color: var\(--accentLine\); background: var\(--accentSoft\); \}/);
  assert.ok((APP.match(/proto-\$\{escapeHtml\(s\.protocol\)\}/g) || []).length >= 4);
  for (const sel of ['.srv-tags', '.srv-tag.warp', '.modal.warp-modal', '.warp-progress', '.ed-http-opt', '.ed-card-head', '.ed-chips-read', '.btn.is-new::after']) {
    assert.ok(LISTS.includes(sel + ' ') || LISTS.includes(sel + '{') || LISTS.includes(sel + ','), `lists.css has no ${sel}`);
  }
});

/* ------------------------------------ the Pro view ------------------------------------ */

const PRO_FNS = ['sfTable', 'edNode', 'appendSome', 'richLine', 'httpCards', 'offField', 'fieldExtras', 'fieldGrid', 'fieldNode', 'fieldHead', 'fieldLabel',
  'fieldHint', 'groupLabel', 'optionLabel', 'fieldShown', 'draftCtx', 'masqueWarpOn', 'masqueWarpCard', 'setMasqueWarp', 'masqueProtocolPane',
  'masqueNoTransport', 'masqueTlsOnly', 'renderEditTabs', 'renderEditPro', 'draftChanged', 'newDraft', 'draftOf', 'readServerFields',
  'encryptionChips', 'newUuid', 'show'];

function proHarness(lang = 'en') {
  const els = new Map();
  const get = (id) => { if (!els.has(id)) { const e = fakeEl('div'); e.id = id; els.set(id, e); } return els.get(id); };
  const ctx = vm.createContext({
    $: (sel) => get(String(sel).replace(/^#/, '')), window: { ServerFields: SF }, document: { createElement: fakeEl },
    t: (k) => TR(lang, k), renderSimpleExtras() {}, crypto: crypto.webcrypto, JSON, String, Array, Object, Number, Uint8Array, Set
  });
  vm.runInContext([
    "let editDraft = null; let editView = 'pro'; let editTab = 'protocol'; let editNew = false; let editBad = null; let editOriginal = null; let editClearPin = false;",
    ...['PROTO_NAMES', 'NEW_PROTOCOLS', 'WARP_FIELDS'].map(constSource),
    ...PRO_FNS.map(fnSource),
    'function open(s, tab) { editDraft = s ? draftOf(s) : newDraft("masque"); editNew = !s; editTab = tab; renderEditPro(); return editDraft; }',
    'function tab(t) { editTab = t; renderEditPro(); }'
  ].join('\n'), ctx);
  return { ctx, pane: () => get('edProPane'), tabs: () => get('edTabs') };
}
const fieldEl = (pane, id) => one(pane, (e) => e.dataset.field === id, `field ${id}`);

test('Pro, Basics: MASQUE in the protocol picker with the sample’s «new» tag — for a new server (+ Manual) and fixed for one that exists', () => {
  const h = proHarness('fa');
  h.ctx.open(null, 'basics');
  const protos = all(h.pane(), (e) => hasClass(e, 'ed-proto'));
  assert.deepEqual(protos.map((b) => b.dataset.proto), SF.PROTOCOLS);
  const m = protos.find((b) => b.dataset.proto === 'masque');
  assert.equal(hasClass(m, 'on'), true);
  assert.ok(all(m, (e) => hasClass(e, 'ed-new')).length === 1 && m.textContent.includes(fa('edit.protoNew')), 'the «new» tag');
  assert.ok(m.textContent.includes('MASQUE') && m.textContent.includes(fa('sfp.masque')));
  assert.equal(protos.filter((b) => all(b, (e) => hasClass(e, 'ed-new')).length).length, 1, 'only MASQUE is new');
  // picked from another protocol: a MASQUE draft
  protos.find((b) => b.dataset.proto === 'vless').onclick();
  all(h.pane(), (e) => hasClass(e, 'ed-proto')).find((b) => b.dataset.proto === 'masque').onclick();
  assert.equal(h.ctx.draftCtx().protocol, 'masque');
  // an existing server keeps its protocol
  h.ctx.open(warpServer(), 'basics');
  const fixed = all(h.pane(), (e) => hasClass(e, 'ed-proto')).filter((b) => b.attrs['aria-disabled'] === 'true');
  assert.equal(fixed.length, SF.PROTOCOLS.length - 1);
  assert.match(LISTS, /\.ed-protos \{ display: grid; grid-template-columns: repeat\(3, minmax\(0, 1fr\)\);/, 'nine protocols, three by three');
});

test('Pro, Protocol: the HTTP version as cards, the WARP card — its switch off clears and keeps its fields, on gives them back — and the tabs: Transport off with why, MASQUE · WARP', () => {
  const h = proHarness('en');
  const d = h.ctx.open(warpServer(), 'protocol');
  const http = fieldEl(h.pane(), 'masqueHttp');
  assert.deepEqual(all(http, (e) => hasClass(e, 'ed-http-opt')).map((c) => [c.dataset.http, hasClass(c, 'on')]), [['h3', true], ['h2', false]]);
  const card = fieldEl(h.pane(), 'warp');
  assert.ok(hasClass(card, 'ed-card') && card.textContent.includes(en('masque.warpTitle')));
  for (const id of ['warpPrivateKey', 'warpPublicKey', 'warpAddress']) fieldEl(card, id);
  assert.equal(one(fieldEl(card, 'warpPrivateKey'), (e) => e.id === 'edf-warpPrivateKey', 'key').tagName, 'TEXTAREA', 'a key is two lines of monospace');
  assert.equal(all(card, (e) => hasClass(e, 'ed-sub')).length, 0, 'no group heading inside the card that is its own');
  assert.ok(h.pane().textContent.includes('cloudflareaccess.com'), 'WARP’s own host and path, said');
  assert.equal(all(h.pane(), (e) => e.dataset.field === 'masqueUser').length, 0);
  const tabs = all(h.tabs(), (e) => e.dataset.tab);
  assert.ok(tabs.find((b) => b.dataset.tab === 'protocol').textContent.includes('MASQUE · WARP'));
  const transport = tabs.find((b) => b.dataset.tab === 'transport');
  assert.equal(transport.attrs['aria-disabled'], 'true');
  assert.equal(transport.attrs.title, en('masque.noTransport').replace(/\*\*/g, '').replace('{over}', 'QUIC (HTTP/3)'));
  const key = d.warpPrivateKey;

  // off: the account's fields go (kept aside), a server of one's own's come
  const sw = one(card, (e) => e.id === 'edf-warp', 'the switch');
  assert.equal(sw.checked, true);
  sw.checked = false;
  sw.onchange();
  const off = vm.runInContext('editDraft', h.ctx);
  assert.deepEqual([off.warpPrivateKey, off.warpPublicKey, off.warpAddress, off._warpOn], ['', '', '', false]);
  assert.equal(all(fieldEl(h.pane(), 'warp'), (e) => e.dataset.field === 'warpPrivateKey').length, 0);
  fieldEl(h.pane(), 'masqueUser');
  fieldEl(h.pane(), 'masquePath');
  // a user typed, then WARP on again: the account back, the user put aside (WARP takes none)
  off.masqueUser = 'alice';
  const sw2 = one(fieldEl(h.pane(), 'warp'), (e) => e.id === 'edf-warp', 'the switch');
  sw2.checked = true;
  sw2.onchange();
  const on = vm.runInContext('editDraft', h.ctx);
  assert.equal(on.warpPrivateKey, key);
  assert.equal(on.masqueUser, '');
  assert.equal(on._stash.masqueUser, 'alice');
  // HTTP/2 picked: the cards follow, and the Transport tab's line
  all(fieldEl(h.pane(), 'masqueHttp'), (e) => hasClass(e, 'ed-http-opt'))[1].onclick();
  assert.equal(vm.runInContext('editDraft.masqueHttp', h.ctx), 'h2');
  assert.ok(all(h.tabs(), (e) => e.dataset.tab === 'transport')[0].attrs.title.includes('TCP (HTTP/2)'));
});

test('Pro, Security: TLS only, said; the WARP hints and the certificate note; the fingerprint may be the core’s own; useSystemCA there', () => {
  const h = proHarness('en');
  h.ctx.open(warpServer(), 'security');
  const p = h.pane();
  assert.ok(p.textContent.includes(en('masque.tlsOnly')));
  const segs = all(p, (e) => hasClass(e, 'seg-btn'));
  assert.deepEqual(segs.map((b) => [b.textContent, hasClass(b, 'active')]), [['TLS', true]]);
  assert.ok(fieldEl(p, 'sni').textContent.includes(en('sf.sni.hint.warp')));
  assert.ok(fieldEl(p, 'ech').textContent.includes(en('sf.ech.hint.warp')));
  assert.ok(all(p, (e) => hasClass(e, 'ed-gridnote')).some((e) => e.textContent === en('masque.certNoteWarp')));
  fieldEl(p, 'useSystemCA');
  assert.equal(all(p, (e) => e.dataset.field === 'allowInsecure').length, 0, 'never allowInsecure: the core refuses it with MASQUE');
  const fp = one(fieldEl(p, 'fp'), (e) => e.tagName === 'SELECT', 'fp');
  assert.equal(fp.children[0].attrs.value, '');
  assert.equal(fp.children[0].textContent, en('sfo.fp._'));
  assert.equal(fp.value, '', 'no fingerprint stays none');
  assert.ok(fieldEl(p, 'fp').textContent.includes(en('sf.fp.hint.h3')));
});

test('Pro, Advanced: the cores MASQUE runs on (no sing-box), Mux shown off with why, the anti-DPI field of its HTTP version and the other one off', () => {
  const h = proHarness('en');
  h.ctx.open(warpServer({ noise: 'random' }), 'advanced');
  let p = h.pane();
  const engine = one(fieldEl(p, 'engine'), (e) => e.tagName === 'SELECT', 'engine');
  assert.deepEqual(engine.children.map((o) => o.attrs.value), ['xray', 'xray-pattn']);
  assert.ok(fieldEl(p, 'engine').textContent.includes(en('sf.engine.hint.masque')));
  const offs = all(p, (e) => hasClass(e, 'ed-f') && all(e, (x) => x.tagName === 'SELECT' && x.disabled).length > 0);
  assert.deepEqual(offs.map((e) => all(e, (x) => hasClass(x, 'ed-key'))[0].textContent), ['mux', 'fragment']);
  assert.ok(offs[0].textContent.includes(en('masque.muxHint')) && offs[1].textContent.includes(en('masque.fragmentOffH3')));
  fieldEl(p, 'noise');
  fieldEl(p, 'remoteDNS');
  assert.ok(p.textContent.includes(en('sfg.pattn.masque')) && !p.textContent.includes(en('sfg.pattn')), 'MASQUE’s finalmask is no patterniha’s');
  // HTTP/2: the fragment, and noise off
  h.ctx.open(ownServer({ fragment: 'tlshello,100-200,10-20' }), 'advanced');
  p = h.pane();
  fieldEl(p, 'fragment');
  assert.equal(all(p, (e) => e.dataset.field === 'noise').length, 0);
  assert.ok(p.textContent.includes(en('masque.noiseOffH2')));
  // another protocol keeps sing-box, and no Mux note
  const v = proHarness('en');
  vm.runInContext('editDraft = newDraft("vless"); editTab = "advanced"; renderEditPro();', v.ctx);
  assert.ok(one(fieldEl(v.pane(), 'engine'), (e) => e.tagName === 'SELECT', 'engine').children.some((o) => o.attrs.value === 'sing-box'));
  assert.ok(!v.pane().textContent.includes(en('masque.muxHint')));
});

test('the Simple form’s MASQUE markup, and its wiring: the HTTP cards, the WARP summary or a user and password, one anti-DPI field, no sing-box', () => {
  for (const id of ['edMasqueRow', 'edMasqueHttp', 'edMasqueAuth', 'edWarpCard', 'edWarpChips', 'edMasqueCred', 'edMasqueUser', 'edMasquePass',
    'edFragmentWrap', 'edNoiseWrap', 'edEngineHint', 'edEngineHintMasque']) assert.match(HTML, new RegExp(`id="${id}"`), id);
  assert.match(HTML, /data-masque-http="h3"><span><bdi dir="ltr">HTTP\/3<\/bdi><\/span><small data-i18n="masque\.h3Desc">/);
  assert.match(HTML, /data-masque-http="h2"><span><bdi dir="ltr">HTTP\/2<\/bdi><\/span><small data-i18n="masque\.h2Desc">/);
  assert.match(HTML, /id="edEngineHintMasque" data-i18n="sf\.engine\.hint\.masque" hidden/);
  assert.match(APP, /for \(const b of document\.querySelectorAll\('#edMasqueHttp \[data-masque-http\]'\)\) b\.onclick = \(\) => setMasqueHttpForm\(b\.dataset\.masqueHttp\);/);
  const open = fnSource('openEdit');
  assert.match(open, /show\('#edCredWrap', !isProxy && !isMasque\);/);
  assert.match(open, /if \(singbox\) \{ singbox\.hidden = isMasque; singbox\.disabled = isMasque; \}/);
  assert.match(fnSource('fillSimple'), /renderMasqueSimple\(\);/);
  assert.match(fnSource('fillMoreInPro'), /'edit\.moreInPro\.masque'/);
});
