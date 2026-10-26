'use strict';
/**
 * v1.26.0 — WARP on WireGuard for a Chain, several accounts at once, the
 * account read back (.superpowers/sdd/warp-wg/design.md §1-3 and §8,
 * git-ignored). The + WARP dialog's kind (WireGuard by default, or MASQUE),
 * the count and the WARP+ keys read back as they are typed, a WireGuard
 * import, the Chain's first hop or the direct endpoint and noise, what Make
 * sends, the steps while it runs, one box per account when done (a batch that
 * stopped early, a key refused, a key taken on a free account), the cards'
 * WARP / WARP+ tags and the editor's read-only «WARP account».
 *
 * window.api.addWarp is a stub with canned answers in the shape of design §2:
 * nothing here reaches warp.js, let alone Cloudflare. app.js reaches into the
 * DOM at load, so — like masqueUi.test.js, whose harness this copies — its own
 * functions run in a vm over a fake page.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const SF = require('../src/renderer/serverFields');

const R = (...p) => fs.readFileSync(path.join(__dirname, '..', ...p), 'utf8').replace(/\r\n/g, '\n');
const APP = R('src', 'renderer', 'app.js');
const HTML = R('src', 'renderer', 'index.html');
const I18N = R('src', 'renderer', 'i18n.js');
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
const fill = (s, vals) => s.replace(/\{(\w+)\}/g, (m, k) => (k in vals ? String(vals[k]) : m));
const bare = (s) => s.replace(/\*\*/g, '');

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
const byId = (el, id) => one(el, (e) => e.id === id, '#' + id);
const seg = (el, key) => one(el, (e) => e.dataset.warp === key, key);

/* ------------------------------------ the dialog ------------------------------------ */

const DIALOG_FNS = ['edNode', 'appendSome', 'richLine', 'httpCards', 'warpChips', 'fmtBytes', 'warpFresh', 'warpShown', 'openWarp', 'closeWarp',
  'warpLicenses', 'warpCount', 'serverGroups', 'groupKey', 'warpHops', 'warpHop', 'warpArgs', 'warpErrorText', 'warpWarningTexts', 'warpStoppedText', 'warpFill', 'looksP256',
  'warpReadImport', 'warpImportChips', 'warpReadWgImport', 'warpWgImportChips', 'warpNum', 'warpBytes', 'warpDate', 'warpTypeChip', 'warpAccountBody',
  'warpAccountBox', 'renderWarpAccount', 'warpField', 'warpSeg', 'warpLicenseNodes', 'warpNewNodes', 'warpTwoWg', 'warpTwoMasque', 'warpFormNodes',
  'warpProgressNodes', 'warpNoteText', 'warpFootNodes', 'warpRenderFoot', 'renderWarp', 'runWarp', 'warpUseChain', 'warpSeeInList'];

const SERVERS = [
  { id: 's1', name: 'DE', protocol: 'vless' },
  { id: 's2', name: 'NL', protocol: 'trojan' },
  { id: 'px', name: 'Office proxy', protocol: 'http' },
  { id: 's3', name: 'FI', protocol: 'shadowsocks' }
];
const CHAINS = [
  { id: 'c1', name: 'DE→NL', members: ['s1', 's2'] },
  { id: 'c2', name: 'Empty', members: [] },
  { id: 'c3', name: 'Ends on HTTP', members: ['s1', 'px'] }
];

function dialogHarness({ lang = 'en', connected = false, addWarp, servers = SERVERS, chains = CHAINS, selected = null } = {}) {
  const els = new Map();
  const get = (id) => { if (!els.has(id)) { const e = fakeEl('div'); e.id = id; els.set(id, e); } return els.get(id); };
  get('warpModal').hidden = true;
  const calls = [];
  const sent = [];
  const ctx = vm.createContext({
    $: (sel) => get(String(sel).replace(/^#/, '')),
    $$: () => [],
    document: { createElement: fakeEl },
    t: (k) => TR(lang, k),
    toast: (msg, kind) => calls.push(['toast', msg, kind || '']),
    state: { servers: plain(servers), chains: plain(chains), connected, selectedServerId: selected },
    renderServers: () => calls.push(['renderServers']), renderPicker() {}, renderChains: () => calls.push(['renderChains']), renderPool() {}, renderAdvanced() {},
    showView: (v) => calls.push(['showView', v]), selectServer: (id) => calls.push(['selectServer', id]), srvById: () => null, groupKey: () => 'manual', foldedGroups: new Set(), setGroupFolded() {},
    localStorage: { getItem: () => null, setItem() {} },
    window: {
      i18n: { lang },
      api: {
        addWarp: async (a) => { sent.push(plain(a)); return addWarp ? addWarp(a) : { ok: false, code: 'failed', error: 'no stub' }; },
        openExternal() {}
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
  const body = () => get('warpBody');
  const foot = () => get('warpFoot');
  const input = (id) => byId(body(), id);
  const type = (id, value) => { const i = input(id); i.value = value; i.oninput(); };
  return { ctx, get, calls, sent, body, foot, input, type, form: () => ctx.form(), lang };
}
const KEYS = ['abcdEFGH-12345678-ijklMNOP', 'qrstUVWX-87654321-yzabCDEF', 'mnopQRST-11112222-uvwxGHIJ'];

/* ------------------------------------ strings ------------------------------------ */

const NEW_KEYS = ['warp.titleWg', 'warp.kind', 'warp.kindWg', 'warp.kindMasque', 'warp.ledeWg', 'warp.count', 'warp.countHint', 'warp.lcFreeOne',
  'warp.lcAllFree', 'warp.lcOneKeyOne', 'warp.lcOneKey', 'warp.lcEach', 'warp.lcSplit', 'warp.lcRaised', 'warp.lcExtra', 'warp.lcBadLine',
  'warp.importLabelWg', 'warp.importHintWg', 'warp.chipWgConf', 'warp.chipWgLink', 'warp.chipWgNone', 'warp.useChain', 'warp.useDirect', 'warp.hop',
  'warp.hopHint', 'warp.hopNone', 'warp.useDirectHint', 'warp.epAutoHintWg', 'warp.epAutoHintWgImport', 'warp.epV6HintWg', 'warp.addressHintWg',
  'warp.antiDpiWg', 'warp.antiDpiWgHint', 'warp.noteN', 'warp.noteChainOne', 'warp.noteChain', 'warp.pKeyWg', 'warp.pAccount', 'warp.pAddChain',
  'warp.pAddedN', 'warp.pChainOne', 'warp.pChainsN', 'warp.pBatch', 'warp.doneLedeChain', 'warp.doneLedeMany', 'warp.stopped', 'warp.acctTitle',
  'warp.acctLicense', 'warp.licApplied', 'warp.licRefused', 'warp.licNone', 'warp.licStillFree', 'warp.acctPremium', 'warp.acctQuota', 'warp.acctUsage',
  'warp.acctDevices', 'warp.acctChain', 'warp.acctChecked', 'warp.acctImported', 'warp.acctFieldsHint', 'warp.goChain', 'warp.type.free', 'warp.type.limited',
  'warp.type.unlimited', 'warp.type.team', 'warp.type.unknown', 'warp.err.badHop', 'warp.err.badConf', 'warp.warn.accountUnread',
  // reworded for a list of keys
  'warp.license', 'warp.licensePh', 'warp.licenseHint'];

test('v1.26 strings: once in fa and once in en, one clean literal each (no straight apostrophe), English in en, the slots the code fills in both', () => {
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
  for (const [key, slots] of [['warp.lcAllFree', ['{n}']], ['warp.lcOneKey', ['{n}']], ['warp.lcEach', ['{n}']], ['warp.lcSplit', ['{n}', '{plus}', '{free}']],
    ['warp.lcExtra', ['{n}']], ['warp.lcBadLine', ['{line}']], ['warp.epAutoHintWg', ['{v4}']], ['warp.epAutoHintWgImport', ['{v4}']], ['warp.epV6HintWg', ['{v6}']],
    ['warp.addressHintWg', ['{v4}', '{v6}']], ['warp.noteN', ['{n}']], ['warp.noteChain', ['{n}']], ['warp.pAddedN', ['{n}']], ['warp.pChainsN', ['{n}']],
    ['warp.pBatch', ['{n}']], ['warp.stopped', ['{made}', '{wanted}', '{reason}']], ['warp.licApplied', ['{tail}']], ['warp.licRefused', ['{msg}']],
    ['warp.err.badConf', ['{msg}']], ['warp.warn.accountUnread', ['{msg}']]]) {
    for (const s of slots) { assert.ok(fa(key).includes(s), `fa ${key} ${s}`); assert.ok(en(key).includes(s), `en ${key} ${s}`); }
  }
  // the owner's words (design §2, §8), verbatim
  assert.deepEqual(['free', 'limited', 'unlimited', 'team', 'unknown'].map((k) => fa('warp.type.' + k)),
    ['رایگان', 'WARP+ (حجمی)', 'WARP+ نامحدود', 'تیمی (Zero Trust)', 'نامشخص']);
  assert.deepEqual([fa('warp.kindWg'), fa('warp.kindMasque'), fa('warp.useChain'), fa('warp.useDirect'), fa('warp.count'), fa('warp.license')],
    ['WireGuard — برای Chain', 'MASQUE', 'Chain با یک کانفیگ', 'مستقیم', 'تعداد حساب', 'کلیدهای WARP+']);
  assert.equal(fa('warp.licStillFree'), 'قبول شد، ولی حساب هنوز رایگان است');
  assert.equal(fill(fa('warp.lcSplit'), { n: '۳', plus: '۲', free: '۱' }), '۳ حساب: ۲ با WARP+، ۱ رایگان', 'the design’s own read-back');
  // Cloudflare's three numbers are glossed, never called what is left
  for (const k of ['warp.acctPremium', 'warp.acctQuota', 'warp.acctUsage', 'warp.acctFieldsHint']) {
    assert.doesNotMatch(en(k), /remain|left/i, `en ${k}`);
    assert.doesNotMatch(fa(k), /باقی|مانده/, `fa ${k}`);
  }
});

/* ------------------------------------ the kind, and the Chain ------------------------------------ */

test('+ WARP opens on WireGuard for a Chain: the kind first, its title and lede; MASQUE one click away with its own title and HTTP cards', () => {
  const h = dialogHarness({ selected: 's2' });
  h.ctx.openWarp();
  const kinds = all(h.body(), (e) => e.dataset.warp && e.dataset.warp.startsWith('kind:'));
  assert.deepEqual(kinds.map((b) => [b.dataset.warp, b.textContent, hasClass(b, 'active')]),
    [['kind:wireguard', en('warp.kindWg'), true], ['kind:masque', en('warp.kindMasque'), false]]);
  assert.equal(h.body().children[0].attrs['aria-label'], en('warp.kind'), 'the kind comes first');
  assert.equal(h.get('warpTitle').textContent, en('warp.titleWg'));
  assert.ok(h.body().textContent.includes(bare(en('warp.ledeWg'))));
  assert.equal(all(h.body(), (e) => hasClass(e, 'ed-http-opt')).length, 0, 'no HTTP version for WireGuard');
  assert.deepEqual(all(h.body(), (e) => e.dataset.warp && e.dataset.warp.startsWith('use:')).map((b) => [b.dataset.warp, hasClass(b, 'active'), b.disabled]),
    [['use:chain', true, false], ['use:direct', false, false]], 'a Chain by default');
  assert.equal(h.foot().textContent.includes(en('warp.noteChainOne')), true, 'one server and one chain');
  seg(h.body(), 'kind:masque').onclick();
  assert.equal(h.get('warpTitle').textContent, en('warp.title'));
  assert.equal(all(h.body(), (e) => hasClass(e, 'ed-http-opt')).length, 3);
  assert.ok(h.foot().textContent.includes(en('warp.noteTwo')));
  assert.equal(h.ctx.warpFresh().kind, 'wireguard');
});

test('the Chain’s first hop: the servers but an HTTP proxy, the chains (marked, as chain:<id>) whose last hop carries UDP; the selected server by default; a pick survives the select being built again', async () => {
  const h = dialogHarness({ selected: 's2', addWarp: async () => ({ ok: false, code: 'busy' }) });
  h.ctx.openWarp();
  const sel = () => byId(h.body(), 'warp-chainWith');
  assert.equal(sel().tagName, 'SELECT');
  assert.deepEqual(all(sel(), (e) => e.tagName === 'OPTION').map((o) => [o.attrs.value, o.textContent]),
    [['s1', 'DE'], ['s2', 'NL'], ['s3', 'FI'], ['chain:c1', '⛓ DE→NL']], 'no HTTP proxy, no empty chain, no chain ending on one');
  // each under its pile, so a hop says where it comes from
  assert.deepEqual(sel().children.map((g) => [g.tagName, g.attrs.label, g.children.length]),
    [['OPTGROUP', '✎ ' + en('srv.manual'), 3], ['OPTGROUP', '⛓ ' + en('pile.chains'), 1]]);
  assert.equal(sel().value, 's2', 'the selected server');
  assert.deepEqual(all(sel(), (o) => o.tagName === 'OPTION' && 'selected' in o.attrs).map((o) => o.attrs.value), ['s2']);
  assert.ok(h.body().textContent.includes(en('warp.hopHint')));
  // a pick, then the form drawn again (another tab of step 1 and back): the pick, not the first option
  sel().value = 'chain:c1';
  sel().onchange();
  seg(h.body(), 'way:import').onclick();
  seg(h.body(), 'way:new').onclick();
  assert.equal(sel().value, 'chain:c1');
  assert.deepEqual(all(sel(), (o) => o.tagName === 'OPTION' && 'selected' in o.attrs).map((o) => o.attrs.value), ['chain:c1']);
  byId(h.foot(), 'warpGo').onclick();
  await new Promise((r) => setImmediate(r));
  assert.deepEqual(h.sent[0], { kind: 'wireguard', mode: 'new', via: 'direct', count: 1, licenses: [], use: 'chain', chainWith: 'chain:c1' });

  // the selection an HTTP proxy: the first option; a chain selected: that chain
  const px = dialogHarness({ selected: 'px' });
  px.ctx.openWarp();
  assert.equal(byId(px.body(), 'warp-chainWith').value, 's1');
  const ch = dialogHarness({ selected: 'c1' });
  ch.ctx.openWarp();
  assert.equal(byId(ch.body(), 'warp-chainWith').value, 'chain:c1');
  // a pick that is gone (the server deleted meanwhile): back to the default
  const gone = dialogHarness({ selected: 's3' });
  gone.ctx.openWarp();
  gone.form().chainWith = 'deleted';
  assert.equal(plain(gone.ctx.warpArgs(gone.form())).chainWith, 's3');
});

test('a chain is offered only when main would take it: every hop a saved server (no group, none gone), the last not an HTTP proxy', () => {
  const chains = CHAINS.concat([
    { id: 'c4', name: 'Ends on a group', members: ['s1', 'grp-a'] },
    { id: 'c5', name: 'A group first', members: ['grp-a', 's2'] },
    { id: 'c6', name: 'A hop deleted', members: ['deleted', 's3'] }
  ]);
  const h = dialogHarness({ chains, selected: 's1' });
  h.ctx.openWarp();
  assert.deepEqual(all(byId(h.body(), 'warp-chainWith'), (e) => e.tagName === 'OPTION').map((o) => o.attrs.value), ['s1', 's2', 's3', 'chain:c1'],
    'resolveHop (warp.js) refuses each of c4–c6: “A server of that chain is no longer there”');
  // the same answer main's own resolveHop gives, chain by chain
  const { resolveHop } = require('../src/main/warp.js');
  for (const c of chains) {
    let ok = true;
    try { resolveHop('chain:' + c.id, SERVERS, chains); } catch { ok = false; }
    assert.equal(plain(h.ctx.warpHops()).some((o) => o.value === 'chain:' + c.id), ok, c.name);
  }
});

test('nothing to chain through (only an HTTP proxy): said, the Chain choice off, and direct — its endpoint and the noise switch', () => {
  const h = dialogHarness({ servers: [{ id: 'px', name: 'P', protocol: 'http' }], chains: [] });
  h.ctx.openWarp();
  const chain = seg(h.body(), 'use:chain');
  assert.equal(chain.disabled, true);
  assert.equal(hasClass(seg(h.body(), 'use:direct'), 'active'), true);
  assert.equal(h.form().use, 'direct');
  assert.ok(all(h.body(), (e) => hasClass(e, 'warn') && e.textContent === en('warp.hopNone')).length === 1);
  assert.equal(all(h.body(), (e) => e.id === 'warp-chainWith').length, 0);
  byId(h.body(), 'warp-wgAntiDpi');
  chain.onclick();
  assert.equal(h.form().use, 'direct', 'an option that is off cannot be picked');
  assert.ok(h.foot().textContent.includes(en('warp.noteOne')));
});

test('direct: Cloudflare’s WireGuard edge named (v4, v6 on 2408), a clean IP of one’s own, the noise switch — and what Make sends for each', () => {
  const h = dialogHarness();
  h.ctx.openWarp();
  seg(h.body(), 'use:direct').onclick();
  const bdis = () => all(h.body(), (e) => e.tagName === 'BDI').map((e) => e.textContent);
  assert.ok(bdis().includes('162.159.192.1:2408'));
  assert.ok(h.body().textContent.includes(en('warp.useDirectHint')));
  seg(h.body(), 'wgEndpoint:v6').onclick();
  assert.ok(bdis().includes('[2606:4700:d0::a29f:c001]:2408'));
  assert.deepEqual(plain(h.ctx.warpArgs(h.form())), { kind: 'wireguard', mode: 'new', via: 'direct', count: 1, licenses: [], use: 'direct', endpoint: 'v6', antiDpi: true });
  seg(h.body(), 'wgEndpoint:custom').onclick();
  assert.equal(h.input('warp-wgAddress').attrs.placeholder, '162.159.192.1:2408');
  assert.ok(bdis().includes('[2606:4700:d0::a29f:c001]:2408'), 'the address hint names both forms');
  h.type('warp-wgAddress', ' 188.114.97.6:2408 ');
  const sw = h.input('warp-wgAntiDpi');
  sw.checked = false;
  sw.onchange();
  assert.deepEqual(plain(h.ctx.warpArgs(h.form())),
    { kind: 'wireguard', mode: 'new', via: 'direct', count: 1, licenses: [], use: 'direct', endpoint: 'custom', address: '188.114.97.6:2408', antiDpi: false });
  // a Chain sends its hop and none of these; MASQUE's own fields never go with WireGuard
  const a = plain(h.ctx.warpArgs(Object.assign({}, h.form(), { use: 'chain' })));
  assert.deepEqual(Object.keys(a).sort(), ['chainWith', 'count', 'kind', 'licenses', 'mode', 'use', 'via']);
  assert.equal(h.ctx.warpArgs(Object.assign(h.ctx.warpFresh(), { use: 'moon' })).use, 'chain');
});

/* ------------------------------------ many accounts, the keys ------------------------------------ */

test('the count and the WARP+ keys, read back as typed: one key for every account, several one each and the rest free, more keys raise the count; a bad line by its number; never a key in full', () => {
  const h = dialogHarness({ lang: 'fa', selected: 's1' });
  h.ctx.openWarp();
  const count = h.input('warp-count');
  assert.deepEqual([count.attrs.type, count.attrs.min, count.attrs.max, count.value], ['number', '1', '10', '1']);
  const ta = h.input('warp-licenses');
  assert.equal(ta.tagName, 'TEXTAREA');
  assert.ok(ta.attrs.placeholder.includes('\n'), 'one key a line');
  const read = () => one(h.body(), (e) => hasClass(e, 'warp-lc'), 'the read-back');
  const said = () => read().children[0].textContent;
  const chips = () => one(read(), (e) => hasClass(e, 'ed-chips-read'), 'chips').children.map((c) => [c.className, c.textContent]);
  assert.equal(said(), fa('warp.lcFreeOne'));

  h.type('warp-count', '3');
  assert.equal(said(), fill(fa('warp.lcAllFree'), { n: '۳' }));
  assert.ok(h.foot().textContent.includes(fill(fa('warp.noteChain'), { n: '۳' })), 'the foot follows as it is typed');
  h.type('warp-licenses', KEYS[0]);
  assert.equal(said(), fill(fa('warp.lcOneKey'), { n: '۳' }));
  h.type('warp-licenses', `${KEYS[0]}\n  ${KEYS[1]}  \n`);
  assert.equal(said(), '۳ حساب: ۲ با WARP+، ۱ رایگان');
  assert.deepEqual(chips(), [['info', '…MNOP'], ['info', '…CDEF']]);
  // more keys than the count: as many accounts as keys, said so
  h.type('warp-count', '2');
  h.type('warp-licenses', KEYS.join('\n'));
  assert.equal(said(), fill(fa('warp.lcEach'), { n: '۳' }) + ' ' + fa('warp.lcRaised'));
  assert.ok(h.foot().textContent.includes(fill(fa('warp.noteChain'), { n: '۳' })));
  // a malformed line, by its number in the box (blank lines count, as the user sees them)
  h.type('warp-licenses', `${KEYS[0]}\n\nnot-a-key-ABCD`);
  assert.deepEqual(chips(), [['info', '…MNOP'], ['bad', fill(fa('warp.lcBadLine'), { line: '۳' })]]);
  for (const k of [...KEYS, 'not-a-key-ABCD']) assert.ok(!h.body().textContent.includes(k), 'a key is never shown in full');
  // more than ten keys: ten accounts, the rest said unused
  const twelve = Array.from({ length: 12 }, (_, i) => `aaaaaaaa-bbbbbbbb-cccccc${String(i).padStart(2, '0')}`);
  h.type('warp-licenses', twelve.join('\n'));
  assert.ok(said().startsWith(fill(fa('warp.lcEach'), { n: '۱۰' })));
  assert.ok(said().endsWith(fill(fa('warp.lcExtra'), { n: '۲' })));
  assert.deepEqual(chips().slice(9).map((c) => c[0]), ['info', 'dim', 'dim']);
  const a = plain(h.ctx.warpArgs(h.form()));
  assert.equal(a.count, 10);
  assert.deepEqual(a.licenses, twelve, 'every key goes, trimmed; warp.js gives the first ten out');
  // en, and a count out of range
  const e = dialogHarness();
  e.ctx.openWarp();
  e.type('warp-count', '3');
  e.type('warp-licenses', `${KEYS[0]}\n${KEYS[1]}`);
  assert.equal(one(e.body(), (x) => hasClass(x, 'warp-lc'), 'read-back').children[0].textContent, '3 accounts: 2 with WARP+, 1 free');
  for (const [v, n] of [['0', 1], ['', 1], ['-4', 1], ['2.7', 2], ['50', 10], ['x', 1]]) assert.equal(e.ctx.warpCount({ way: 'new', count: v, licenses: '' }), n, `count ${JSON.stringify(v)}`);
  assert.equal(e.ctx.warpCount({ way: 'import', count: '5', licenses: KEYS.join('\n') }), 1, 'an import is one account');
  assert.equal(e.ctx.warpNum(10), '10');
  assert.equal(h.ctx.warpNum(10), '۱۰', 'Persian digits, every one');
});

test('while it runs, WireGuard: the X25519 key, the sign-up, warp_enabled, the WARP+ key (only with keys), the account read, the servers and chains — pending; several accounts said one after another', async () => {
  let release;
  const h = dialogHarness({ selected: 's1', addWarp: () => new Promise((r) => { release = r; }) });
  h.ctx.openWarp();
  h.type('warp-count', '3');
  h.type('warp-licenses', KEYS[0]);
  const run = h.ctx.runWarp();
  const list = one(h.body(), (e) => hasClass(e, 'warp-progress'), 'the steps');
  const lines = list.children.map((li) => li.textContent);
  assert.deepEqual(lines.map((l) => l.replace(/^◌ /, '')), [
    en('warp.pKeyWg') + en('warp.pKeyAt'), en('warp.pReg') + 'api.cloudflareclient.com', en('warp.pEnable') + 'warp_enabled',
    en('warp.pLicense') + 'license', en('warp.pAccount') + 'account · devices', en('warp.pAddChain') + 'WARP · Chain']);
  assert.ok(lines.every((l) => l.startsWith('◌')), 'pending, every one: the call does not stream');
  assert.ok(!lines.some((l) => l.includes(en('warp.pEnroll'))), 'no P-256 key to enroll for WireGuard');
  assert.ok(h.body().textContent.includes(fill(en('warp.pBatch'), { n: 3 })));
  assert.deepEqual(h.sent[0], { kind: 'wireguard', mode: 'new', via: 'direct', count: 3, licenses: [KEYS[0]], use: 'chain', chainWith: 's1' });
  release({ ok: false, code: 'busy' });
  await run;
  // no keys: no WARP+ step; one account: no batch line
  const one1 = dialogHarness({ addWarp: () => new Promise(() => {}) });
  one1.ctx.openWarp();
  seg(one1.body(), 'use:direct').onclick();
  one1.ctx.runWarp();
  const steps = one(one1.body(), (e) => hasClass(e, 'warp-progress'), 'steps').children.map((li) => li.textContent);
  assert.ok(!steps.some((l) => l.includes(en('warp.pLicense'))));
  assert.ok(steps[steps.length - 1].includes(en('warp.pAdd')) && steps[steps.length - 1].includes('WARP · WireGuard'));
  assert.ok(!one1.body().textContent.includes(fill(en('warp.pBatch'), { n: 1 })));
});

/* ------------------------------------ done: the accounts ------------------------------------ */

const CHECKED = '2026-10-19T08:30:00.000Z';
const W1 = { id: 'w1', name: '☁ WARP 1', protocol: 'wireguard', warp: { kind: 'wireguard', type: 'unlimited', warpPlus: true } };
const W2 = { id: 'w2', name: '☁ WARP 2', protocol: 'wireguard', warp: { kind: 'wireguard', type: 'free', warpPlus: false } };
const W3 = { id: 'w3', name: '☁ WARP 3', protocol: 'wireguard', warp: { kind: 'wireguard', type: 'free', warpPlus: false } };
/** A batch of four that stopped after three (design §2, §7): a key taken, a key taken on a free account, a key refused and the account unread. */
const BATCH = {
  ok: true,
  servers: [...SERVERS, W1, W2, W3],
  chains: [...CHAINS, { id: 'k1', name: 'DE → ☁ WARP 1', members: ['s1', 'w1'] }, { id: 'k2', name: 'DE → ☁ WARP 2', members: ['s1', 'w2', 'gone'] },
    { id: 'k3', name: 'DE → ☁ WARP 3', members: ['s1', 'w3'] }],
  added: [W1, W2, W3],
  addedChains: [{ id: 'k1', name: 'DE → ☁ WARP 1', members: ['s1', 'w1'] }, { id: 'k2', name: 'DE → ☁ WARP 2', members: ['s1', 'w2'] },
    { id: 'k3', name: 'DE → ☁ WARP 3', members: ['s1', 'w3'] }],
  accounts: [
    { name: '☁ WARP 1', serverIds: ['w1'], chainId: 'k1', chainName: 'DE → ☁ WARP 1', warnings: [],
      info: { kind: 'wireguard', deviceId: 'd1', type: 'unlimited', warpPlus: true, premiumData: 24598562000, quota: 1099511627776, usage: 0, role: 'child',
        referralCount: 0, devices: 2, license: 'applied', licenseTail: 'MNOP', licenseError: '', checkedAt: CHECKED } },
    { name: '☁ WARP 2', serverIds: ['w2'], chainId: 'k2', chainName: 'DE → ☁ WARP 2', warnings: [],
      info: { kind: 'wireguard', deviceId: 'd2', type: 'free', warpPlus: false, premiumData: 0, quota: 0, usage: 0, role: 'child', referralCount: 0,
        devices: 1, license: 'applied', licenseTail: 'CDEF', licenseError: '', checkedAt: CHECKED } },
    { name: '☁ WARP 3', serverIds: ['w3'], chainId: 'k3', chainName: 'DE → ☁ WARP 3',
      warnings: [{ code: 'licenseFailed', message: 'Invalid license' }, { code: 'accountUnread', message: 'GET /account: 500' }],
      info: { kind: 'wireguard', deviceId: 'd3', type: '', warpPlus: false, premiumData: null, quota: null, usage: null, role: '', referralCount: null,
        devices: null, license: 'refused', licenseTail: 'GHIJ', licenseError: 'Invalid license', checkedAt: CHECKED } }
  ],
  warnings: [{ code: 'licenseFailed', message: 'Invalid license', name: '☁ WARP 3' }, { code: 'accountUnread', message: 'GET /account: 500', name: '☁ WARP 3' }],
  stopped: { code: 'rateLimited', error: 'Cloudflare answered 429', detail: '429 Too Many Requests', made: 3, wanted: 4 }
};
/** A row of an account box, by its label: [the technical key, the value, the value's class]. */
const boxText = (box, label, tr = en) => {
  const dts = box.children.find((c) => c.tagName === 'DL').children;
  const i = dts.findIndex((c) => c.tagName === 'DT' && c.children[0].textContent === tr(label));
  assert.ok(i > -1, `no row ${label}`);
  return [dts[i].children[2].textContent, dts[i + 1].textContent, dts[i + 1].className];
};

test('done, a batch that stopped: the alert «k of n made — why»; one box per account — type, the key taken / refused / taken on a free account, Cloudflare’s numbers by their own names, devices, its chain, its warnings; the lists updated', async () => {
  const h = dialogHarness({ selected: 's1', addWarp: async () => BATCH });
  h.ctx.openWarp();
  h.type('warp-count', '4');
  h.type('warp-licenses', KEYS.join('\n'));
  await h.ctx.runWarp();
  assert.equal(h.form().phase, 'done', h.form().error);
  const body = h.body();
  // the alert, first after the steps
  const alert = one(body, (e) => e.attrs.role === 'alert' && hasClass(e, 'ed-warn'), 'the alert');
  assert.equal(alert.textContent, `3 of 4 accounts made — ${en('warp.err.rateLimited')}`);
  // the steps: three servers, three chains, the key and the account read marked
  const steps = one(body, (e) => hasClass(e, 'warp-progress'), 'steps').children.map((li) => li.textContent);
  assert.ok(steps.find((l) => l.includes(en('warp.pLicense'))).startsWith('!'));
  assert.ok(steps.find((l) => l.includes(en('warp.pAccount'))).startsWith('!'));
  assert.ok(steps.find((l) => l.includes(en('warp.pEnable'))).startsWith('✓'));
  assert.ok(steps.some((l) => l.includes(fill(en('warp.pAddedN'), { n: 3 })) && l.includes('☁ WARP 1 / ☁ WARP 2 / ☁ WARP 3')));
  assert.ok(steps.some((l) => l.includes(fill(en('warp.pChainsN'), { n: 3 })) && l.includes('DE → ☁ WARP 1')));
  assert.ok(body.textContent.includes(bare(en('warp.doneLedeChain'))));
  // the boxes
  const boxes = all(body, (e) => hasClass(e, 'warp-acct'));
  assert.equal(boxes.length, 3);
  const head = (b) => b.children[0];
  assert.deepEqual(boxes.map((b) => [one(head(b), (e) => hasClass(e, 'ttl'), 'name').textContent, one(head(b), (e) => hasClass(e, 'warp-acct-type'), 'type').textContent]),
    [['☁ WARP 1', en('warp.type.unlimited')], ['☁ WARP 2', en('warp.type.free')], ['☁ WARP 3', en('warp.type.unknown')]]);
  // 1: a key taken, by its last four; Cloudflare's numbers human, the bytes in the tooltip; two devices; its chain
  assert.deepEqual(boxText(boxes[0], 'warp.acctLicense'), ['license', 'Accepted (…MNOP)', 'ok']);
  assert.deepEqual(boxText(boxes[0], 'warp.acctPremium'), ['premium_data', '22.9 GB', '']);
  assert.deepEqual(boxText(boxes[0], 'warp.acctQuota'), ['quota', '1.0 TB', '']);
  assert.deepEqual(boxText(boxes[0], 'warp.acctUsage'), ['usage', '0 B', '']);
  assert.deepEqual(boxText(boxes[0], 'warp.acctDevices'), ['devices', '2', '']);
  assert.deepEqual(boxText(boxes[0], 'warp.acctChain'), ['chainName', 'DE → ☁ WARP 1', '']);
  assert.equal(one(boxes[0], (e) => e.tagName === 'BDI' && e.textContent === '22.9 GB', 'premium').attrs.title, '24598562000 B');
  assert.equal(all(boxes[0], (e) => hasClass(e, 'ed-warn')).length, 0);
  // 2: a key taken while the account stays free — its own note
  assert.deepEqual(boxText(boxes[1], 'warp.acctLicense'), ['license', 'Accepted (…CDEF)', 'ok']);
  assert.deepEqual(all(boxes[1], (e) => hasClass(e, 'ed-warn')).map((e) => e.textContent), [en('warp.licStillFree')]);
  // 3: refused in Cloudflare's words; nothing read (—); its warnings in the window's words
  assert.deepEqual(boxText(boxes[2], 'warp.acctLicense'), ['license', 'Refused: Invalid license', 'bad']);
  for (const k of ['warp.acctPremium', 'warp.acctQuota', 'warp.acctUsage', 'warp.acctDevices']) assert.equal(boxText(boxes[2], k)[1], '—', k);
  assert.deepEqual(all(boxes[2], (e) => hasClass(e, 'ed-warn')).map((e) => e.textContent),
    [fill(en('warp.warn.licenseFailed'), { msg: 'Invalid license' }), fill(en('warp.warn.accountUnread'), { msg: 'GET /account: 500' })]);
  // each warning once: in its box, not again flattened
  assert.equal(all(body, (e) => e.textContent === fill(en('warp.warn.licenseFailed'), { msg: 'Invalid license' }) && hasClass(e, 'ed-warn')).length, 1);
  assert.ok(body.textContent.includes(en('warp.acctFieldsHint')));
  assert.doesNotMatch(body.textContent, /remain/i);
  for (const k of KEYS) assert.ok(!body.textContent.includes(k), 'no key in full');
  // the lists: every server, the chains (hops that are gone dropped), drawn again
  assert.deepEqual(h.ctx.state.servers.map((s) => s.id), ['s1', 's2', 'px', 's3', 'w1', 'w2', 'w3']);
  assert.deepEqual(plain(h.ctx.state.chains.slice(3)), [{ id: 'k1', name: 'DE → ☁ WARP 1', members: ['s1', 'w1'] },
    { id: 'k2', name: 'DE → ☁ WARP 2', members: ['s1', 'w2'] }, { id: 'k3', name: 'DE → ☁ WARP 3', members: ['s1', 'w3'] }]);
  assert.ok(h.calls.some((c) => c[0] === 'renderChains') && h.calls.some((c) => c[0] === 'renderServers'));
  // a chain made: «Select the chain» first — the first new chain selected, the home page shown, one press from connecting
  assert.deepEqual(h.foot().children.filter((b) => b.tagName === 'BUTTON').map((b) => b.textContent), [en('warp.goChain'), en('warp.see'), en('tb.close')]);
  byId(h.foot(), 'warpUseChain').onclick();
  assert.equal(h.get('warpModal').hidden, true);
  assert.deepEqual(h.calls.filter((c) => c[0] === 'showView' || c[0] === 'selectServer'), [['showView', 'home'], ['selectServer', 'k1']]);
  // in Persian: the alert's numbers in Persian digits
  const p = dialogHarness({ lang: 'fa', addWarp: async () => BATCH });
  p.ctx.openWarp();
  await p.ctx.runWarp();
  assert.equal(one(p.body(), (e) => e.attrs.role === 'alert' && hasClass(e, 'ed-warn'), 'alert').textContent, `۳ از ۴ حساب ساخته شد — ${fa('warp.err.rateLimited')}`);
  // closed while it ran: the stop comes as a toast
  const c = dialogHarness({ addWarp: async () => BATCH });
  c.ctx.openWarp();
  const q = c.ctx.runWarp();
  c.ctx.closeWarp();
  await q;
  assert.deepEqual(c.calls.filter((x) => x[0] === 'toast'), [['toast', `3 of 4 accounts made — ${en('warp.err.rateLimited')}`, 'err']]);
});

test('an account box never shows more of a key than its last four characters, and says none or unknown plainly', () => {
  const { ctx } = dialogHarness();
  const box = ctx.warpAccountBox({ name: 'X', info: { type: 'limited', license: 'applied', licenseTail: KEYS[0] } });
  assert.ok(!box.textContent.includes(KEYS[0]) && box.textContent.includes('…MNOP'));
  assert.equal(one(box, (e) => hasClass(e, 'warp-acct-type'), 'type').textContent, en('warp.type.limited'));
  const none = ctx.warpAccountBox({ name: 'Y', info: { type: 'team', license: 'none' } });
  assert.ok(none.textContent.includes(en('warp.licNone')) && none.textContent.includes(en('warp.type.team')));
  assert.ok(ctx.warpAccountBox({ name: 'Z' }).textContent.includes(en('warp.type.unknown')), 'no info: unknown, not a crash');
});

test('a WireGuard import: a .conf, a wireguard:// link or nothing usable read back (never the key); what Add sends; done, the account said imported', async () => {
  const conf = '[Interface]\nPrivateKey = cGFzc3dvcmQtcGFzc3dvcmQtcGFzc3dvcmQtcGFzcw==\nAddress = 172.16.0.2/32, 2606:4700:110:8a36::2/128\n\n[Peer]\nPublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=\nEndpoint = engage.cloudflareclient.com:2408\n';
  const imported = { id: 'wi', name: '☁ WARP', protocol: 'wireguard', warp: { kind: 'wireguard', imported: true } };
  const h = dialogHarness({ selected: 's1', addWarp: async () => ({ ok: true, servers: [...SERVERS, imported], added: [imported],
    accounts: [{ name: '☁ WARP', serverIds: ['wi'], chainId: null, chainName: null, info: { kind: 'wireguard', imported: true }, warnings: [] }], warnings: [] }) });
  h.ctx.openWarp();
  seg(h.body(), 'way:import').onclick();
  assert.equal(h.foot().children[0].textContent, en('warp.add'));
  const ta = h.input('warp-wgImport');
  assert.equal(ta.tagName, 'TEXTAREA');
  assert.ok(ta.attrs.placeholder.startsWith('[Interface]'));
  const chips = () => one(h.body(), (e) => hasClass(e, 'ed-chips-read'), 'chips').children.map((c) => [c.className, c.textContent]);
  h.type('warp-wgImport', 'hello');
  assert.deepEqual(chips(), [['bad', en('warp.chipWgNone')]]);
  h.type('warp-wgImport', 'wireguard://c2VjcmV0LWtleQ%3D%3D@162.159.192.1:2408?publickey=bmXOC&address=172.16.0.2%2F32#W');
  assert.deepEqual(chips(), [['', en('warp.chipWgLink')], ['info', 'Endpoint 162.159.192.1:2408']]);
  assert.ok(!h.body().textContent.includes('c2VjcmV0LWtleQ'), 'the link’s key is not shown');
  h.type('warp-wgImport', conf);
  assert.deepEqual(chips(), [['', en('warp.chipWgConf')], ['info', 'Endpoint engage.cloudflareclient.com:2408'], ['info', 'IPv4 172.16.0.2'], ['info', 'IPv6 2606:4700:110:8a36::2']]);
  assert.deepEqual(plain(h.ctx.warpReadWgImport('[Interface]\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = x')).key, false);
  assert.ok(!h.body().textContent.includes('cGFzc3dvcmQ'), 'nor the .conf’s');
  seg(h.body(), 'use:direct').onclick();
  assert.ok(h.body().textContent.includes(fill(en('warp.epAutoHintWgImport'), { v4: '162.159.192.1:2408' })));
  seg(h.body(), 'use:chain').onclick();
  await h.ctx.runWarp();
  assert.deepEqual(h.sent[0], { kind: 'wireguard', mode: 'import', importText: conf, use: 'chain', chainWith: 's1' });
  const steps = one(h.body(), (e) => hasClass(e, 'warp-progress'), 'steps').children.map((li) => li.textContent);
  assert.equal(steps.length, 2, 'an import: read it, add the server');
  assert.ok(steps[0].includes(en('warp.pRead')) && steps[0].includes('.conf · wireguard://'));
  const box = one(h.body(), (e) => hasClass(e, 'warp-acct'), 'the box');
  assert.ok(box.textContent.includes(en('warp.acctImported')));
  assert.equal(all(box, (e) => hasClass(e, 'warp-acct-type') || e.tagName === 'DL').length, 0, 'nothing known: no type, no lines');
  assert.ok(!h.body().textContent.includes(en('warp.acctFieldsHint')), 'no numbers to explain');
  // MASQUE's import stays its own: its text box (and what was pasted for WireGuard is not carried over)
  const m = dialogHarness();
  m.ctx.openWarp();
  m.form().wgImport = conf;
  seg(m.body(), 'way:import').onclick();
  seg(m.body(), 'kind:masque').onclick();
  assert.equal(m.input('warp-importText').value, '');
  assert.equal(all(m.body(), (e) => e.id === 'warp-wgImport').length, 0);
  assert.equal(plain(m.ctx.warpArgs(m.form())).importText, '');
});

test('refusals new in v1.26 in the window’s words: badHop (the hop gone, an HTTP proxy, an empty chain), badConf with the parser’s reason; back to the form, the choices kept', async () => {
  for (const [res, want] of [
    [{ ok: false, code: 'badHop', error: 'The first hop is an HTTP proxy' }, en('warp.err.badHop')],
    [{ ok: false, code: 'badConf', error: 'x', detail: 'no [Peer] section' }, fill(en('warp.err.badConf'), { msg: 'no [Peer] section' })]
  ]) {
    const h = dialogHarness({ selected: 's3', addWarp: async () => res });
    h.ctx.openWarp();
    h.type('warp-count', '2');
    await h.ctx.runWarp();
    assert.equal(h.form().phase, 'form');
    assert.equal(one(h.body(), (e) => hasClass(e, 'warp-error'), 'the reason').textContent, want);
    assert.equal(h.input('warp-count').value, '2');
    assert.equal(byId(h.body(), 'warp-chainWith').value, 's3');
  }
});

test('MASQUE with several accounts: n accounts × one or two servers in the foot, and the account boxes too', async () => {
  const added = [{ id: 'm1', name: '☁ WARP 1 · H3' }, { id: 'm2', name: '☁ WARP 1 · H2' }, { id: 'm3', name: '☁ WARP 2 · H3' }, { id: 'm4', name: '☁ WARP 2 · H2' }];
  const h = dialogHarness({ addWarp: async () => ({ ok: true, servers: added, added,
    accounts: [{ name: '☁ WARP 1', serverIds: ['m1', 'm2'], chainId: null, chainName: null, info: { kind: 'masque', type: 'free', license: 'none' }, warnings: [] },
      { name: '☁ WARP 2', serverIds: ['m3', 'm4'], chainId: null, chainName: null, info: { kind: 'masque', type: 'free', license: 'none' }, warnings: [] }], warnings: [] }) });
  h.ctx.openWarp();
  seg(h.body(), 'kind:masque').onclick();
  h.type('warp-count', '2');
  assert.ok(h.foot().textContent.includes(fill(en('warp.noteN'), { n: 4 })));
  all(h.body(), (e) => hasClass(e, 'ed-http-opt'))[0].onclick();
  assert.ok(h.foot().textContent.includes(en('warp.noteTwo')), 'two accounts, HTTP/3 only: two servers');
  all(h.body(), (e) => hasClass(e, 'ed-http-opt'))[2].onclick();
  await h.ctx.runWarp();
  assert.deepEqual(h.sent[0], { kind: 'masque', mode: 'new', via: 'direct', count: 2, licenses: [], http: 'both', endpoint: 'auto', cover: '', antiDpi: true });
  const steps = one(h.body(), (e) => hasClass(e, 'warp-progress'), 'steps').children.map((li) => li.textContent);
  assert.ok(steps.some((l) => l.includes(fill(en('warp.pAddedN'), { n: 4 })) && l.endsWith('☁ WARP 1 · H3 / ☁ WARP 1 · H2 / ☁ WARP 2 · H3 / …')));
  assert.equal(all(h.body(), (e) => hasClass(e, 'warp-acct')).length, 2);
  assert.ok(h.body().textContent.includes(bare(en('warp.doneLede'))));
});

/* ------------------------------------ the card, the editor ------------------------------------ */

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

test('the card: WARP for a server made from a WARP account (WireGuard too), WARP+ for a WARP+ one — MASQUE keeps its h3 / h2', () => {
  const ctx = cardHarness();
  const wg = (warp) => ({ id: 'w', name: 'W', protocol: 'wireguard', address: '162.159.192.1', port: 2408, outbound: { protocol: 'wireguard', settings: {} }, warp });
  assert.deepEqual(plain(ctx.srvTags(wg({ kind: 'wireguard', type: 'free', warpPlus: false }))), ['WARP']);
  assert.deepEqual(plain(ctx.srvTags(wg({ kind: 'wireguard', type: 'unlimited', warpPlus: true }))), ['WARP+']);
  assert.deepEqual(plain(ctx.srvTags(wg({ kind: 'wireguard', imported: true }))), ['WARP']);
  assert.deepEqual(plain(ctx.srvTags(wg(undefined))), [], 'a WireGuard of one’s own: nothing');
  const masque = { protocol: 'masque', outbound: { streamSettings: { tlsSettings: { alpn: ['h3'] }, masqueSettings: { warp: { privateKey: 'k' } } } } };
  assert.deepEqual(plain(ctx.srvTags(Object.assign({}, masque, { warp: { kind: 'masque', warpPlus: true } }))), ['WARP+', 'h3']);
  assert.deepEqual(plain(ctx.srvTags(masque)), ['WARP', 'h3'], 'a v1.25 MASQUE WARP (no account stored): WARP still');
  const card = ctx.serverCard(wg({ kind: 'wireguard', warpPlus: true })).innerHTML;
  assert.match(card, /<span class="srv-tags"><span class="srv-tag warp" dir="ltr">WARP\+<\/span><\/span>/);
});

function editorHarness(lang = 'en') {
  const els = new Map();
  const get = (id) => { if (!els.has(id)) { const e = fakeEl('div'); e.id = id; els.set(id, e); } return els.get(id); };
  const ctx = vm.createContext({
    $: (sel) => get(String(sel).replace(/^#/, '')), document: { createElement: fakeEl }, t: (k) => TR(lang, k),
    window: { i18n: { lang } }, String, Array, Object, Number
  });
  vm.runInContext(['edNode', 'appendSome', 'richLine', 'fmtBytes', 'warpNum', 'warpBytes', 'warpDate', 'warpTypeChip', 'warpAccountBody', 'renderWarpAccount']
    .map(fnSource).join('\n'), ctx);
  return { ctx, box: () => get('edWarpAcct') };
}

test('the editor’s «WARP account»: read-only above both views, from server.warp with the time it was read; an imported one says its details are unknown; any other server, none', () => {
  assert.match(HTML, /<div class="modal-body" id="editBody">\s*<!--[^>]*-->\s*<div class="ed-card ed-warp-acct" id="edWarpAcct" data-module="warp" hidden><\/div>\s*<div class="ed-simple" id="edSimple">/);
  assert.match(fnSource('openEdit'), /renderWarpAccount\(s\.source === 'json' \? null : s\);/);
  assert.match(fnSource('openNewServer'), /renderWarpAccount\(null\);/);
  const h = editorHarness();
  h.ctx.renderWarpAccount({ id: 'w', protocol: 'wireguard', warp: BATCH.accounts[0].info });
  const box = h.box();
  assert.equal(box.hidden, false);
  const head = box.children[0];
  assert.ok(head.textContent.includes(en('warp.acctTitle')) && head.textContent.includes('WireGuard') && head.textContent.includes(en('warp.type.unlimited')));
  assert.deepEqual(boxText(box, 'warp.acctLicense'), ['license', 'Accepted (…MNOP)', 'ok']);
  assert.deepEqual(boxText(box, 'warp.acctDevices'), ['devices', '2', '']);
  const when = new Intl.DateTimeFormat('en-GB', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(CHECKED));
  assert.deepEqual(boxText(box, 'warp.acctChecked'), ['checkedAt', when, '']);
  assert.ok(box.textContent.includes(en('warp.acctFieldsHint')));
  // a key taken on a free account: the note here too; MASQUE named as such
  h.ctx.renderWarpAccount({ id: 'm', protocol: 'masque', warp: Object.assign({}, BATCH.accounts[1].info, { kind: 'masque' }) });
  assert.ok(h.box().children[0].textContent.includes('MASQUE'));
  assert.deepEqual(all(h.box(), (e) => hasClass(e, 'ed-warn')).map((e) => e.textContent), [en('warp.licStillFree')]);
  // imported: one line, nothing else
  h.ctx.renderWarpAccount({ id: 'i', protocol: 'wireguard', warp: { kind: 'wireguard', imported: true } });
  assert.equal(h.box().hidden, false);
  assert.ok(h.box().textContent.includes(en('warp.acctImported')));
  assert.equal(all(h.box(), (e) => e.tagName === 'DL').length, 0);
  // no account (a server of one's own, a v1.25 MASQUE WARP, a JSON one, a new one): hidden and empty
  for (const s of [{ protocol: 'wireguard' }, { protocol: 'masque', warp: {} }, null]) {
    h.ctx.renderWarpAccount(s);
    assert.equal(h.box().hidden, true);
    assert.equal(h.box().children.length, 0);
  }
  // Persian: the date in Persian, the devices in Persian digits
  const p = editorHarness('fa');
  p.ctx.renderWarpAccount({ id: 'w', protocol: 'wireguard', warp: BATCH.accounts[0].info });
  assert.equal(boxText(p.box(), 'warp.acctChecked', fa)[1], new Intl.DateTimeFormat('fa-IR', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(CHECKED)));
  assert.equal(p.box().children.find((c) => c.tagName === 'DL').children.find((c, i, a) => a[i - 1] && a[i - 1].tagName === 'DT' && a[i - 1].textContent.includes('devices')).textContent, '۲');
  assert.equal(h.ctx.warpDate('not a date'), '—');
  assert.equal(h.ctx.warpDate(''), '—');
});

test('the stylesheet has the v1.26 boxes', () => {
  for (const sel of ['.warp-lc', '.warp-accts', '.warp-acct-rows', '.warp-acct-type', '.ed-warp-acct', '.warp-modal .seg-btn:disabled', '.warp-modal .hint.warn']) {
    assert.ok(LISTS.includes(sel + ' ') || LISTS.includes(sel + '{') || LISTS.includes(sel + ','), `lists.css has no ${sel}`);
  }
});
