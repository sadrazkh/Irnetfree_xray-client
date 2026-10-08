'use strict';
/**
 * JSON servers in the window and the router's web UI (JSON configs, task J2).
 *
 * A server imported from an Xray / sing-box JSON carries `source: 'json'`, its
 * config in `json`, a `jsonMode` ('full' | 'raw') and `jsonInfo` (what full
 * mode does not use). The renderer — the desktop window's AND the router's web
 * UI — shows a JSON tag on its card, edits the config itself instead of the
 * link fields, copies and QR-codes the JSON, and takes pasted JSON in the add
 * box. The records here are made up in the test: the fields come from the main
 * process (tests/jsonImport.test.js owns their shape).
 *
 * app.js reaches into the DOM at load, so — like groupFastest.test.js — its own
 * functions are compiled in a vm over fakes, and its wiring is read as text.
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

/**
 * A top-level (async) function of app.js, as source: a one-liner whole, else up
 * to the `}` in column 0 that closes it. (Counting braces would stumble on the
 * `[{]` of a regex or a '{' in a string.)
 */
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
/** One language's value of a key, from i18n.js (fa is the first table, en the second). */
function str(lang, key) {
  const enAt = I18N.indexOf('\n  en: {');
  assert.ok(enAt > 0, 'i18n.js has no en table');
  const part = lang === 'fa' ? I18N.slice(0, enAt) : I18N.slice(enAt);
  const m = part.match(new RegExp(`'${key.replace(/\./g, '\\.')}': '((?:[^'\\\\]|\\\\.)*)'`));
  assert.ok(m, `${lang} has no '${key}'`);
  return m[1].replace(/\\'/g, "'");
}
/** Out of the vm's realm, so deepEqual compares values and not prototypes. */
const plain = (x) => JSON.parse(JSON.stringify(x));
const tick = () => new Promise((r) => setImmediate(r));

/** English strings, as the window shows them (a key that is not in the table stays its own name). */
const en = (key) => { try { return str('en', key); } catch { return key; } };

/** Just enough of an element: children, attributes, classes, a click, an innerHTML that can be cleared. */
function fakeEl(tag) {
  const el = {
    tagName: String(tag || 'div').toUpperCase(), children: [], attrs: {}, dataset: {}, hidden: false, disabled: false,
    textContent: '', title: '', className: '', type: '', id: '', dir: '', value: '', onclick: null, html: '', scrollTop: 0,
    classList: {
      toggle(c, on) {
        const set = new Set(el.className.split(/\s+/).filter(Boolean));
        if (on === undefined ? !set.has(c) : on) set.add(c); else set.delete(c);
        el.className = [...set].join(' ');
      },
      contains: (c) => el.className.split(/\s+/).includes(c)
    },
    appendChild(c) { el.children.push(c); return c; },
    // innerHTML is only ever a template here; the parts it names are looked up by selector
    parts: {},
    querySelector(sel) { return el.parts[sel] || (el.parts[sel] = fakeEl('span')); },
    setAttribute(k, v) { el.attrs[k] = String(v); },
    getAttribute(k) { return k in el.attrs ? el.attrs[k] : null; },
    scrollIntoView() { el.scrolled = true; },
    set innerHTML(v) { el.html = v; if (v === '') el.children = []; },
    get innerHTML() { return el.html; }
  };
  return el;
}
const hasClass = (el, cls) => el.className.split(/\s+/).includes(cls);
/** All text under an element, in document order. */
const textOf = (el) => [el.textContent, ...el.children.map(textOf)].filter(Boolean).join(' ');
const walk = (el, fn) => { fn(el); el.children.forEach((c) => walk(c, fn)); };

/* ------------------------------------ strings ------------------------------------ */

const NEW_KEYS = ['srv.jsonBadge', 'ed.jsonMode', 'ed.jsonFull', 'ed.jsonRaw', 'ed.jsonFullHelp', 'ed.jsonRawHelp', 'ed.jsonEditor',
  'ed.jsonCopy', 'ed.jsonNotApplied', 'ed.jsonNaRules', 'ed.jsonNaAll', 'ed.jsonNaBalancer', 'ed.jsonNaDns', 'ed.jsonNaBalancers', 'ed.jsonNaObservatory',
  'ed.jsonInvalid', 'ed.jsonNotObject', 'qr.tooLarge'];

test('every JSON string exists once in fa and once in en, with no straight apostrophe inside a single-quoted string', () => {
  for (const key of NEW_KEYS) {
    assert.equal(I18N.split(`'${key}':`).length - 1, 2, `'${key}' is not defined exactly once in each of fa and en`);
    // the whole entry up to its comma/end of line must be ONE string literal: an inner ' ends it early
    const entries = I18N.split('\n').filter((l) => l.includes(`'${key}':`));
    assert.equal(entries.length, 2, key);
    for (const line of entries) {
      const m = line.match(/^\s*'[^']+':\s*'((?:[^'\\]|\\.)*)',?\s*$/);
      assert.ok(m, `${key}: not a single clean string literal — a straight ' inside? ${line.trim().slice(0, 90)}`);
      assert.ok(!/\\'/.test(m[1]), `${key}: use ’ and not an escaped '`);
    }
    assert.ok(str('fa', key).length > 0 && str('en', key).length > 0, key);
  }
  // the count placeholder is in both languages
  assert.match(str('fa', 'ed.jsonNaRules'), /\{n\}/);
  assert.match(str('en', 'ed.jsonNaRules'), /\{n\}/);
  assert.equal(str('en', 'srv.jsonBadge'), 'JSON');
  assert.equal(str('fa', 'srv.jsonBadge'), 'JSON');
});

test('the markup’s JSON strings are keys i18n.js knows, and every id the new code reaches exists', () => {
  const ids = new Set([...HTML.matchAll(/id="([^"]+)"/g)].map((m) => m[1]));
  for (const id of ['edNameRow', 'edAddrWrap', 'edJsonWrap', 'edLinkFields', 'edJsonMode', 'edJsonHelp', 'edJsonInfo', 'edJson',
    'edJsonError', 'edJsonCopy', 'qrCopy', 'qrLink', 'qrImage']) assert.ok(ids.has(id), `#${id} is missing`);
  const used = new Set();
  const block = HTML.slice(HTML.indexOf('id="edJsonWrap"'), HTML.indexOf('id="edLinkFields"'));
  for (const m of block.matchAll(/data-i18n(?:-ph|-title)?="([^"]+)"/g)) used.add(m[1]);
  assert.ok(used.size >= 5, 'the JSON block should be translated');
  for (const k of used) assert.equal(I18N.split(`'${k}':`).length - 1, 2, `${k} is not in both languages`);
});

/* ------------------------------------ the markup ------------------------------------ */

test('the link fields sit in one wrapper that the JSON form can hide; the name stays outside it', () => {
  const at = (needle) => { const i = HTML.indexOf(needle); assert.ok(i > -1, needle); return i; };
  const name = at('id="edName"'), json = at('id="edJsonWrap"'), links = at('id="edLinkFields"');
  assert.ok(name < json && json < links, 'name, then the JSON block, then the link fields');
  assert.ok(at('id="edAddrWrap"') < json, 'the address cell is in the name row, before the JSON block');
  const end = HTML.indexOf('class="modal-foot"', links);
  const linkBlock = HTML.slice(links, end);
  for (const id of ['edPort', 'edCred', 'edNetwork', 'edSecurity', 'edSni', 'edPath', 'edFp', 'edPbk', 'edHy2Obfs', 'edEch',
    'edInsecure', 'edProxyUser', 'edWgPub', 'edEngine', 'edFragment', 'edNoise', 'edCipherSuites', 'edFinalMask']) {
    assert.ok(linkBlock.includes(`id="${id}"`), `#${id} must be inside #edLinkFields, or a JSON server would show it`);
  }
  assert.ok(!linkBlock.includes('id="edName"') && !linkBlock.includes('id="edJson"'));
  // a hand-moved block must still be balanced: as many closings as openings, in the whole page
  const strip = (s) => s.replace(/<!--[\s\S]*?-->/g, '').replace(/<script[\s\S]*?<\/script>/g, '');
  const body = strip(HTML);
  assert.equal((body.match(/<div[\s>]/g) || []).length, (body.match(/<\/div>/g) || []).length, 'unbalanced <div>s in index.html');
});

test('the editor is a monospace, left-to-right textarea in both languages, and the mode switch is a labelled radio group', () => {
  const ta = HTML.match(/<textarea id="edJson"[^>]*>/);
  assert.ok(ta, 'no #edJson textarea');
  assert.match(ta[0], /dir="ltr"/, 'JSON is code: LTR even in Persian');
  assert.match(ta[0], /spellcheck="false"/);
  assert.match(ta[0], /wrap="off"/, 'a long line scrolls instead of wrapping into something else');
  const rule = CSS.match(/\.ed-json-text\s*\{([^}]*)\}/);
  assert.ok(rule, 'no .ed-json-text rule');
  assert.match(rule[1], /font-family:\s*var\(--mono\)/);
  assert.match(rule[1], /direction:\s*ltr/);
  assert.match(rule[1], /text-align:\s*left/);
  const seg = HTML.match(/<div class="seg" id="edJsonMode"[^>]*>([\s\S]*?)<\/div>/);
  assert.ok(seg, 'no #edJsonMode');
  assert.match(seg[0], /role="radiogroup"/);
  assert.match(seg[0], /aria-labelledby="edJsonModeLabel"/);
  assert.deepEqual([...seg[1].matchAll(/data-json-mode="([^"]+)"/g)].map((m) => m[1]), ['full', 'raw']);
  assert.equal([...seg[1].matchAll(/type="button"/g)].length, 2, 'never a submit');
});

test('the stylesheet covers what the JSON surfaces use', () => {
  for (const sel of ['.proto-json', '.json-badge', '.json-badge.raw', '.grid2.single', '.ed-json', '.ed-fields', '.ed-json-list', '.ed-json-rules']) {
    assert.ok(CSS.includes(sel), `${sel} has no style`);
  }
  // logical properties only: the card and the form are right-to-left in Persian
  const lists = R('src', 'renderer', 'lists.css');
  const block = lists.slice(lists.indexOf('JSON configs'));
  assert.ok(block.length > 300, 'the JSON section of lists.css');
  assert.doesNotMatch(block, /margin-(left|right)|padding-(left|right)|\b(left|right):\s*\d/);
  assert.match(block, /margin-inline-start/);
});

/* ------------------------------------ the card ------------------------------------ */

function cardHarness() {
  const src = ['escapeHtml', 'serverCard'].map(fnSource).join('\n');
  const ctx = vm.createContext({
    document: { createElement: fakeEl },
    state: { activeServerId: null, connected: false, selectedServerId: null, pings: {} },
    t: en,
    pingResultLabel: () => ({ cls: '', txt: '—' }),
    usageLabel: () => '',
    connectGlyph: (b) => b,
    selectServer() {}, pingServer() {}, copyServerLink() {}, showServerQr() {}, openEdit() {}, connect() {}, deleteServer() {}, clearUsageFor() {},
    String
  });
  vm.runInContext(src, ctx);
  return ctx;
}
const linkServer = { id: 'l1', name: 'DE-1', protocol: 'vless', address: 'de.example.com', port: 443 };
const jsonServer = (extra) => Object.assign({}, linkServer, { id: 'j1', name: 'DE-2', source: 'json', jsonMode: 'full', json: { remarks: 'DE-2', outbounds: [] } }, extra);

test('a JSON server’s card carries a JSON badge (a proto-badge) beside its address; Raw is told apart; a link server’s card has none', () => {
  const ctx = cardHarness();
  const card = ctx.serverCard(jsonServer());
  const badge = card.innerHTML.match(/<span class="([^"]*)" title="([^"]*)">([^<]*)<\/span>(?=<\/div>)/);
  assert.ok(badge, `no JSON badge at the end of the address line: ${card.innerHTML}`);
  assert.match(badge[1], /\bproto-badge\b/);
  assert.match(badge[1], /\bjson-badge\b/);
  assert.doesNotMatch(badge[1], /\braw\b/);
  assert.equal(badge[3], 'JSON');
  assert.equal(badge[2], 'Full', 'on hover: how it runs');
  assert.match(card.innerHTML, /<div class="srv-addr">de\.example\.com:443 <span/, 'beside the address, not in the name (which ellipsizes)');

  const raw = ctx.serverCard(jsonServer({ jsonMode: 'raw' }));
  assert.match(raw.innerHTML, /class="proto-badge proto-json json-badge raw" title="Raw">JSON</);

  const plainCard = ctx.serverCard(linkServer);
  assert.doesNotMatch(plainCard.innerHTML, /json/i, 'a link server’s card is as it was');
  assert.match(plainCard.innerHTML, /data-i18n-title="btn\.copy" title="copy"/);
});

test('a JSON server’s Copy button says it copies JSON; the protocol badge stays first', () => {
  const ctx = cardHarness();
  const card = ctx.serverCard(jsonServer());
  assert.match(card.innerHTML, /class="icon-btn copy-srv" data-i18n-title="ed\.jsonCopy" title="Copy JSON"/);
  // card.querySelector('.proto-badge') is the first one in the markup: the protocol, which selects the server
  const first = card.innerHTML.match(/<span class="(proto-badge[^"]*)"/);
  assert.equal(first[1], 'proto-badge proto-vless');
});

test('a hostile remark or address cannot break out of the card', () => {
  const ctx = cardHarness();
  const card = ctx.serverCard(jsonServer({ name: '<img src=x onerror=alert(1)>', address: '"><b>' }));
  assert.doesNotMatch(card.innerHTML, /<img|<b>/);
});

/* ------------------------------------ the edit form ------------------------------------ */

const INFO = {
  rules: [{ match: 'geosite:private', to: 'direct' }, { match: 'geoip:ir', to: 'direct' }, { match: '*', to: 'proxy' }],
  dns: true, balancers: 1, observatory: true
};
const CONFIG = {
  remarks: 'DE-2',
  outbounds: [{ tag: 'proxy', protocol: 'vless', settings: { vnext: [{ address: 'de.example.com', port: 443, users: [{ id: 'u', encryption: 'none' }] }] } }, { tag: 'direct', protocol: 'freedom' }],
  routing: { rules: [{ type: 'field', outboundTag: 'proxy', network: 'tcp,udp' }] }
};
/** INFO's rules as the edit form says them in English: the core's `*` is "everything else". */
const RULE_LINES = ['geosite:private → direct', 'geoip:ir → direct', 'everything else → proxy'];
const J = (extra) => Object.assign({}, linkServer, {
  id: 'j1', name: 'DE-2', source: 'json', jsonMode: 'full', json: CONFIG, jsonInfo: INFO
}, extra);

function editHarness({ servers, updateServer } = {}) {
  const els = new Map();
  const get = (id) => { if (!els.has(id)) { const e = fakeEl('div'); e.id = id; els.set(id, e); } return els.get(id); };
  const segButtons = ['full', 'raw'].map((m) => { const b = fakeEl('button'); b.dataset.jsonMode = m; if (m === 'full') b.className = 'seg-btn active'; else b.className = 'seg-btn'; return b; });
  const calls = [];
  const lists = { '#edJsonMode .seg-btn': segButtons };
  const ctx = vm.createContext({
    $: (sel) => get(String(sel).replace(/^#/, '')),
    $$: (sel) => lists[sel] || [],
    document: { createElement: fakeEl },
    t: en,
    toast: (msg, kind) => calls.push(['toast', msg, kind || '']),
    toastAction: (msg, label) => calls.push(['toastAction', msg, label]),
    copyText: async (text) => calls.push(['copyText', text]),
    state: { servers: servers || [J()], editingId: null, connected: false, activeServerId: null },
    // the link form, which a JSON server never reaches
    readServerFields: () => ({}), fillEditForm() {}, updateSpoofLabels() {}, collectEditFields: () => ({ name: 'link' }),
    setPending() {}, serverInLivePlan: () => false, doReconnect() {},
    renderServers: () => calls.push(['renderServers']), renderPicker() {}, renderChains() {}, renderPool() {}, renderAdvanced() {},
    window: { api: { updateServer: updateServer || (async () => ({ ok: true, servers: [] })) } },
    JSON, String, Array, Error
  });
  // the module-level state app.js keeps for the open form, then the real functions over it
  vm.runInContext([
    "let editOriginal = null; let editClearPin = false; let editJsonMode = 'full';",
    ...['show', 'closeEdit', 'setEditKind', 'showJsonError', 'jsonRuleText', 'renderJsonInfo', 'setJsonMode', 'refreshJsonFormLang', 'openEditJson',
      'collectJsonFields', 'copyEditJson', 'openEdit', 'saveEdit'].map(fnSource)
  ].join('\n'), ctx);
  return { ctx, get, calls, segButtons, mode: () => vm.runInContext('editJsonMode', ctx) };
}

test('opening a JSON server: the link fields go, the JSON form comes — the name, the mode, the pretty config', () => {
  const h = editHarness();
  h.ctx.openEdit('j1');
  assert.equal(h.get('edLinkFields').hidden, true, 'the link fields are not shown for a JSON server');
  assert.equal(h.get('edAddrWrap').hidden, true, 'nor the address next to the name');
  assert.equal(hasClass(h.get('edNameRow'), 'single'), true, 'the name takes the row');
  assert.equal(h.get('edJsonWrap').hidden, false);
  assert.equal(h.get('edName').value, 'DE-2');
  assert.equal(h.get('edJson').value, JSON.stringify(CONFIG, null, 2), 'the editor holds the pretty JSON');
  assert.equal(h.get('editModal').hidden, false);
  assert.equal(h.ctx.state.editingId, 'j1');
  assert.equal(h.get('edJsonError').hidden, true);
  // Full is on; its one line is the full-mode line
  assert.equal(h.mode(), 'full');
  assert.equal(h.get('edJsonHelp').textContent, en('ed.jsonFullHelp'));
  assert.deepEqual(h.segButtons.map((b) => [b.dataset.jsonMode, hasClass(b, 'active'), b.getAttribute('aria-checked')]),
    [['full', true, 'true'], ['raw', false, 'false']]);
});

test('Raw: its one line says the app’s DNS, leak guard and routing do not apply, and the not-applied summary goes', () => {
  const h = editHarness({ servers: [J({ jsonMode: 'raw' })] });
  h.ctx.openEdit('j1');
  assert.equal(h.mode(), 'raw');
  assert.equal(h.get('edJsonHelp').textContent, en('ed.jsonRawHelp'));
  assert.match(en('ed.jsonRawHelp'), /DNS.*leak guard.*routing/i);
  assert.equal(h.get('edJsonInfo').hidden, true, 'raw runs all of it, so there is nothing "not applied"');
  assert.deepEqual(h.segButtons.map((b) => hasClass(b, 'active')), [false, true]);
  // switching to Full brings the summary back, and back again
  h.ctx.setJsonMode('full');
  assert.equal(h.get('edJsonInfo').hidden, false);
  assert.equal(h.get('edJsonHelp').textContent, en('ed.jsonFullHelp'));
  h.ctx.setJsonMode('raw');
  assert.equal(h.get('edJsonInfo').hidden, true);
  assert.equal(h.get('edJsonHelp').textContent, en('ed.jsonRawHelp'));
  // anything but 'raw' is full
  h.ctx.setJsonMode(undefined);
  assert.equal(h.mode(), 'full');
});

test('Full: the not-applied summary lists the rule count, each “match → to”, and a line for DNS, balancers and observatory when they are there', () => {
  const h = editHarness();
  h.ctx.openEdit('j1');
  const box = h.get('edJsonInfo');
  assert.equal(box.hidden, false);
  const text = textOf(box);
  assert.match(text, new RegExp(en('ed.jsonNotApplied').replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  assert.match(text, /Its own routing — 3 rule\(s\):/, 'the count');
  for (const line of RULE_LINES) assert.ok(text.includes(line), line);
  assert.ok(!text.includes('* →'), 'the core’s * token is never printed raw');
  assert.match(text, /Its own DNS settings/);
  assert.match(text, /Its own balancers/);
  assert.match(text, /Its own observatory/);
  // each rule is a text node of its own, left-to-right inside the right-to-left page
  const bdis = [];
  walk(box, (e) => { if (e.tagName === 'BDI') bdis.push(e); });
  assert.equal(bdis.length, 3);
  assert.ok(bdis.every((b) => b.dir === 'ltr'));
  assert.deepEqual(bdis.map((b) => b.textContent), RULE_LINES);

  // only what is true gets a line
  const h2 = editHarness({ servers: [J({ jsonInfo: { rules: [], dns: false, balancers: 0, observatory: false } })] });
  h2.ctx.openEdit('j1');
  assert.equal(h2.get('edJsonInfo').hidden, true, 'nothing unused: no summary at all');
  const h3 = editHarness({ servers: [J({ jsonInfo: { rules: [{ match: 'geoip:ir', to: 'direct' }], dns: true, balancers: 0, observatory: false } })] });
  h3.ctx.openEdit('j1');
  const t3 = textOf(h3.get('edJsonInfo'));
  assert.match(t3, /1 rule\(s\)/);
  assert.match(t3, /DNS/);
  assert.doesNotMatch(t3, /balancers|observatory/);
  // a record without jsonInfo (an older store) opens without it
  const h4 = editHarness({ servers: [J({ jsonInfo: undefined })] });
  h4.ctx.openEdit('j1');
  assert.equal(h4.get('edJsonInfo').hidden, true);
});

test('a language switch with the JSON form open says its help line and summary again; with no JSON form open it does nothing', () => {
  const h = editHarness();
  h.ctx.openEdit('j1');
  assert.equal(h.get('edJsonHelp').textContent, en('ed.jsonFullHelp'));
  const fa = (key) => { try { return str('fa', key); } catch { return key; } };
  h.ctx.t = fa;                       // setLang('fa') has changed what t() answers
  h.ctx.refreshJsonFormLang();
  assert.equal(h.get('edJsonHelp').textContent, fa('ed.jsonFullHelp'));
  const text = textOf(h.get('edJsonInfo'));
  assert.ok(text.includes(fa('ed.jsonNotApplied')), 'the summary heading');
  assert.ok(text.includes(fa('ed.jsonNaDns')), 'and its lines');
  assert.ok(text.includes('geoip:ir → direct'), 'the rules themselves are the config’s own text and stay');
  // Raw stays Raw
  h.ctx.setJsonMode('raw');
  h.ctx.t = en;
  h.ctx.refreshJsonFormLang();
  assert.equal(h.mode(), 'raw');
  assert.equal(h.get('edJsonHelp').textContent, en('ed.jsonRawHelp'));
  assert.equal(h.get('edJsonInfo').hidden, true);

  // no form open (also: setLang runs at start-up, before any edit state exists): nothing is touched
  const idle = editHarness();
  idle.ctx.refreshJsonFormLang();
  assert.equal(idle.get('edJsonHelp').textContent, '');
  // a link form open: not this form's business
  const link = Object.assign({}, linkServer, { id: 'l1' });
  const l = editHarness({ servers: [link] });
  l.ctx.openEdit('l1');
  l.ctx.refreshJsonFormLang();
  assert.equal(l.get('edJsonHelp').textContent, '');
  // and setLang calls it
  assert.match(fnSource('setLang'), /refreshJsonFormLang\(\);/);
});

test('the core’s neutral rule tokens are said in words, in both languages: * = everything else, balancer:<tag> = balancer <tag>, empty = —', () => {
  const info = {
    rules: [
      { match: 'geosite:private', to: 'direct' },
      { match: 'geoip:ir + port 443', to: 'direct' },
      { match: 'domain:example.com', to: 'balancer:auto' },
      { match: 'inbound api', to: '' },
      { match: '*', to: 'proxy' },
      { match: '*', to: 'balancer:my balancer' }
    ],
    dns: false, balancers: 1, observatory: false
  };
  const want = {
    en: ['geosite:private → direct', 'geoip:ir + port 443 → direct', 'domain:example.com → balancer auto', 'inbound api → —',
      'everything else → proxy', 'everything else → balancer my balancer'],
    fa: ['geosite:private → direct', 'geoip:ir + port 443 → direct', 'domain:example.com → بالانسر auto', 'inbound api → —',
      'بقیهٔ ترافیک → proxy', 'بقیهٔ ترافیک → بالانسر my balancer']
  };
  assert.equal(str('en', 'ed.jsonNaAll'), 'everything else');
  assert.equal(str('fa', 'ed.jsonNaAll'), 'بقیهٔ ترافیک');
  assert.equal(str('en', 'ed.jsonNaBalancer'), 'balancer {tag}');
  assert.equal(str('fa', 'ed.jsonNaBalancer'), 'بالانسر {tag}');
  for (const lang of ['en', 'fa']) {
    const h = editHarness({ servers: [J({ jsonInfo: info })] });
    h.ctx.t = (key) => { try { return str(lang, key); } catch { return key; } };
    h.ctx.openEdit('j1');
    const bdis = [];
    walk(h.get('edJsonInfo'), (e) => { if (e.tagName === 'BDI') bdis.push(e); });
    assert.deepEqual(bdis.map((b) => b.textContent), want[lang], lang);
    assert.ok(bdis.every((b) => b.dir === 'ltr'), `${lang}: each rule stays left-to-right`);
    assert.ok(!bdis.some((b) => /^\*|balancer:/.test(b.textContent)), `${lang}: no raw token left`);
  }
  // a rule missing its fields does not print "undefined"
  const h = editHarness({ servers: [J({ jsonInfo: { rules: [{}, null, { match: '*' }], dns: false, balancers: 0, observatory: false } })] });
  h.ctx.openEdit('j1');
  const texts = [];
  walk(h.get('edJsonInfo'), (e) => { if (e.tagName === 'BDI') texts.push(e.textContent); });
  assert.deepEqual(texts, ['? → —', '? → —', 'everything else → —']);
});

test('the config’s own text goes in as text, never as markup', () => {
  const h = editHarness({ servers: [J({ jsonInfo: { rules: [{ match: '<img src=x onerror=alert(1)>', to: '"><b>' }], dns: false, balancers: 0, observatory: false } })] });
  h.ctx.openEdit('j1');
  const box = h.get('edJsonInfo');
  walk(box, (e) => assert.equal(e.html, '', 'no innerHTML was written with the record’s text'));
  assert.ok(textOf(box).includes('<img src=x onerror=alert(1)> → "><b>'));
});

test('opening a link server after a JSON one brings the link form back', () => {
  const link = Object.assign({}, linkServer, { id: 'l1' });
  const h = editHarness({ servers: [J(), link] });
  h.ctx.openEdit('j1');
  assert.equal(h.get('edLinkFields').hidden, true);
  h.ctx.openEdit('l1');
  assert.equal(h.get('edLinkFields').hidden, false);
  assert.equal(h.get('edAddrWrap').hidden, false);
  assert.equal(h.get('edJsonWrap').hidden, true);
  assert.equal(hasClass(h.get('edNameRow'), 'single'), false);
});

test('Save sends { name, jsonMode, json } — the edited text, parsed — and closes on success', async () => {
  const sent = [];
  const h = editHarness({ updateServer: async (id, fields) => { sent.push([id, plain(fields)]); return { ok: true, servers: [J({ name: 'Renamed' })] }; } });
  h.ctx.openEdit('j1');
  h.get('edName').value = 'Renamed';
  h.ctx.setJsonMode('raw');
  const edited = Object.assign({}, CONFIG, { remarks: 'Renamed' });
  h.get('edJson').value = JSON.stringify(edited, null, 4);
  await h.ctx.saveEdit();
  assert.deepEqual(sent, [['j1', { name: 'Renamed', jsonMode: 'raw', json: edited }]]);
  assert.deepEqual(Object.keys(sent[0][1]).sort(), ['json', 'jsonMode', 'name'], 'exactly those three');
  assert.equal(h.get('editModal').hidden, true, 'closed');
  assert.equal(h.ctx.state.servers[0].name, 'Renamed', 'the list the main process answered');
  assert.ok(h.calls.some((c) => c[0] === 'toast' && c[1] === en('t.serverUpdated') && c[2] === 'ok'));
  assert.ok(h.calls.some((c) => c[0] === 'renderServers'));
});

test('a refused save shows ed.jsonInvalid and the reason, and the form stays open', async () => {
  const h = editHarness({ updateServer: async () => ({ ok: false, error: 'no proxy outbound left in this config', servers: [J()] }) });
  h.ctx.openEdit('j1');
  h.get('editModal').hidden = false;
  await h.ctx.saveEdit();
  const err = h.get('edJsonError');
  assert.equal(err.hidden, false);
  assert.equal(err.textContent, `${en('ed.jsonInvalid')}: no proxy outbound left in this config`);
  assert.equal(h.get('editModal').hidden, false, 'not closed');
  assert.equal(h.ctx.state.editingId, 'j1', 'still editing');
  assert.ok(h.calls.some((c) => c[0] === 'toast' && c[2] === 'err' && c[1] === err.textContent), 'and said in a toast too');
  assert.ok(!h.calls.some((c) => c[0] === 'renderServers'), 'nothing was re-rendered as if it had saved');

  // no reason given: the heading alone
  const h2 = editHarness({ updateServer: async () => ({ ok: false }) });
  h2.ctx.openEdit('j1');
  await h2.ctx.saveEdit();
  assert.equal(h2.get('edJsonError').textContent, en('ed.jsonInvalid'));

  // the next attempt clears the old reason before it asks again
  const answers = [{ ok: false, error: 'first' }, { ok: true, servers: [J()] }];
  const h3 = editHarness({ updateServer: async () => answers.shift() });
  h3.ctx.openEdit('j1');
  await h3.ctx.saveEdit();
  assert.equal(h3.get('edJsonError').hidden, false);
  await h3.ctx.saveEdit();
  assert.equal(h3.get('edJsonError').hidden, true, 'cleared');
  assert.equal(h3.get('editModal').hidden, true, 'and this one saved');
});

test('text that is not a JSON object never leaves the window: the parse error, or ed.jsonNotObject, is shown and nothing is sent', async () => {
  let sent = 0;
  const h = editHarness({ updateServer: async () => { sent++; return { ok: true, servers: [] }; } });
  h.ctx.openEdit('j1');
  h.get('edJson').value = '{ "outbounds": [ ';
  await h.ctx.saveEdit();
  assert.equal(sent, 0);
  assert.ok(h.get('edJsonError').textContent.startsWith(en('ed.jsonInvalid') + ': '));
  assert.ok(h.get('edJsonError').textContent.length > en('ed.jsonInvalid').length + 2, 'with the parser’s reason');
  for (const bad of ['[1, 2]', 'null', '42', '"text"', '']) {
    h.get('edJson').value = bad;
    await h.ctx.saveEdit();
    assert.equal(sent, 0, `${JSON.stringify(bad)} must not be sent`);
    assert.equal(h.get('editModal').hidden, false);
  }
  h.get('edJson').value = '[1, 2]';
  await h.ctx.saveEdit();
  assert.equal(h.get('edJsonError').textContent, `${en('ed.jsonInvalid')}: ${en('ed.jsonNotObject')}`);
});

test('a JSON save skips the link form’s own checks (its hidden inputs may hold anything)', async () => {
  const sent = [];
  const h = editHarness({ updateServer: async (id, f) => { sent.push(plain(f)); return { ok: true, servers: [J()] }; } });
  h.ctx.openEdit('j1');
  // stale values left in the hidden link form by an earlier edit of a link server
  h.get('edFinalMask').value = '{ not json';
  h.get('edPqv').value = 'short';
  h.get('edPqvRow').hidden = false;
  await h.ctx.saveEdit();
  assert.equal(sent.length, 1, 'saved');
  assert.deepEqual(Object.keys(sent[0]).sort(), ['json', 'jsonMode', 'name']);
  assert.ok(!h.calls.some((c) => c[0] === 'toast' && (c[1] === en('edit.finalMaskBad') || c[1] === en('edit.pqvBad'))));
});

test('a link server still saves through the link form, and a refusal there is still the plain “failed” toast', async () => {
  const sent = [];
  const link = Object.assign({}, linkServer, { id: 'l1' });
  const h = editHarness({ servers: [link], updateServer: async (id, f) => { sent.push([id, plain(f)]); return { ok: false }; } });
  h.ctx.openEdit('l1');
  await h.ctx.saveEdit();
  assert.deepEqual(sent, [['l1', { name: 'link' }]], 'collectEditFields’s fields, as before');
  assert.ok(h.calls.some((c) => c[0] === 'toast' && c[2] === 'err' && c[1] === en('t.failed')));
  assert.equal(h.get('editModal').hidden, false, 'and the form stays');
});

test('Copy JSON copies what is in the editor, edits included', async () => {
  const h = editHarness();
  h.ctx.openEdit('j1');
  h.get('edJson').value = '{"edited":true}';
  await h.ctx.copyEditJson();
  assert.deepEqual(h.calls.filter((c) => c[0] === 'copyText'), [['copyText', '{"edited":true}']]);
  assert.ok(h.calls.some((c) => c[0] === 'toast' && c[2] === 'ok'));
});

test('the JSON form is wired: the switch sets the mode, Copy JSON copies, the form’s save is the same button', () => {
  assert.match(APP, /\$\$\('#edJsonMode \.seg-btn'\)\.forEach\(\(b\) => \{ b\.onclick = \(\) => setJsonMode\(b\.dataset\.jsonMode\); \}\);/);
  assert.match(APP, /\$\('#edJsonCopy'\)\.onclick = copyEditJson;/);
  assert.match(APP, /\$\('#editSave'\)\.onclick = saveEdit;/);
  // a JSON server is recognised by its source, before the link form reads its record
  const open = fnSource('openEdit');
  assert.ok(open.indexOf("s.source === 'json'") > -1 && open.indexOf("s.source === 'json'") < open.indexOf('readServerFields'));
  const save = fnSource('saveEdit');
  assert.ok(save.indexOf("source === 'json'") > -1 && save.indexOf("source === 'json'") < save.indexOf('collectEditFields'));
});

/* ------------------------------------ the QR ------------------------------------ */

function qrHarness({ servers, link, qrThrows = false }) {
  const els = new Map();
  const get = (id) => { if (!els.has(id)) { const e = fakeEl('div'); e.id = id; els.set(id, e); } return els.get(id); };
  const drawn = [];
  const calls = [];
  const ctx = vm.createContext({
    $: (sel) => get(String(sel).replace(/^#/, '')),
    t: en,
    toast: (msg, kind) => calls.push(['toast', msg, kind || '']),
    state: { servers },
    qrcode: () => ({
      addData(text) { drawn.push(text); },
      make() { if (qrThrows) throw new Error('code length overflow'); },
      createSvgTag() { return '<svg viewBox="0 0 10 10"></svg>'; }
    }),
    window: { api: { serverLink: async () => link } },
    JSON, String, Error
  });
  vm.runInContext([constSource('QR_JSON_MAX_BYTES'), ...['qrJsonText', 'showServerQr'].map(fnSource)].join('\n'), ctx);
  return { ctx, get, drawn, calls };
}
const PRETTY = (config) => JSON.stringify(config, null, 2);
/** A config whose minified JSON is exactly `bytes` long (ASCII). */
function configOfSize(bytes) {
  const head = '{"p":"';
  const pad = bytes - head.length - 2;
  assert.ok(pad > 0);
  return JSON.parse(head + 'x'.repeat(pad) + '"}');
}

test('QR of a JSON server: the minified JSON when it fits (1,700 bytes at most)', async () => {
  const h = qrHarness({ servers: [J()], link: PRETTY(CONFIG) });
  await h.ctx.showServerQr('j1');
  assert.deepEqual(h.drawn, [JSON.stringify(CONFIG)], 'minified, one line, exactly the config');
  assert.equal(h.get('qrLink').value, JSON.stringify(CONFIG), 'and that is what Copy in the dialog copies');
  assert.match(h.get('qrImage').innerHTML, /^<svg /);
  assert.equal(h.get('qrModal').hidden, false);
  assert.equal(h.get('qrCopy').textContent, en('ed.jsonCopy'), 'the dialog’s button says what it copies');

  // the edge: 1,700 fits, 1,701 does not (and well under is drawn too)
  const fit = configOfSize(1700);
  assert.equal(JSON.stringify(fit).length, 1700);
  const a = qrHarness({ servers: [J()], link: PRETTY(fit) });
  await a.ctx.showServerQr('j1');
  assert.equal(a.drawn.length, 1, '1,700 bytes is drawn');
  assert.deepEqual(a.drawn, [JSON.stringify(fit)]);
  assert.match(a.get('qrImage').innerHTML, /^<svg /);
  const over = configOfSize(1701);
  const b = qrHarness({ servers: [J()], link: PRETTY(over) });
  await b.ctx.showServerQr('j1');
  assert.equal(b.drawn.length, 0, '1,701 bytes is not even offered to the encoder');
  assert.ok(b.get('qrImage').innerHTML.includes(en('qr.tooLarge')));
  assert.ok(!b.get('qrImage').innerHTML.includes('<svg'));
  // what used to fit (2,900) no longer does
  const old = qrHarness({ servers: [J()], link: PRETTY(configOfSize(2900)) });
  await old.ctx.showServerQr('j1');
  assert.equal(old.drawn.length, 0);
});

test('QR of a JSON server too large for a code: the qr.tooLarge message, the dialog still opens, and the JSON stays there to copy', async () => {
  const big = configOfSize(5000);
  const h = qrHarness({ servers: [J()], link: PRETTY(big) });
  await h.ctx.showServerQr('j1');
  assert.equal(h.drawn.length, 0);
  assert.ok(h.get('qrImage').innerHTML.includes(en('qr.tooLarge')), h.get('qrImage').innerHTML);
  assert.ok(!h.get('qrImage').innerHTML.includes('<svg'));
  assert.equal(h.get('qrLink').value, PRETTY(big), 'the readable JSON, ready for Copy');
  assert.equal(h.get('qrModal').hidden, false);
  assert.match(en('qr.tooLarge'), /Copy/);
});

test('the QR text is plain ASCII: a Persian remark or an emoji survives (the encoder keeps one byte per character) and parses back to the same config', async () => {
  const cfg = Object.assign({}, CONFIG, { remarks: 'آلمان 🇩🇪 · DE-1' });
  const h = qrHarness({ servers: [J({ json: cfg })], link: PRETTY(cfg) });
  await h.ctx.showServerQr('j1');
  assert.equal(h.drawn.length, 1);
  assert.ok(/^[\x00-\x7f]*$/.test(h.drawn[0]), 'every character fits in a byte');
  assert.deepEqual(JSON.parse(h.drawn[0]), cfg, 'and reads back the same');
  // the size is counted on what is encoded: escapes are longer than the letters they stand for
  assert.ok(h.drawn[0].length > JSON.stringify(cfg).length);
});

test('QR of a link server is as it was: the link itself, and the old message when the library refuses it', async () => {
  const link = 'vless://u@de.example.com:443?type=ws#DE';
  const ok = qrHarness({ servers: [Object.assign({}, linkServer, { id: 'l1' })], link });
  await ok.ctx.showServerQr('l1');
  assert.deepEqual(ok.drawn, [link]);
  assert.equal(ok.get('qrLink').value, link);
  assert.equal(ok.get('qrCopy').textContent, en('qr.copy'));

  const bad = qrHarness({ servers: [Object.assign({}, linkServer, { id: 'l1' })], link, qrThrows: true });
  await bad.ctx.showServerQr('l1');
  assert.ok(bad.get('qrImage').innerHTML.includes(en('qr.tooBig')));
  assert.ok(!bad.get('qrImage').innerHTML.includes(en('qr.tooLarge')));
  assert.equal(bad.get('qrLink').value, link);
});

test('the largest JSON the app draws (1,700 bytes) keeps 2 px per module in the QR box — the same bar qrShare.test.js sets for links', () => {
  assert.equal(Number(APP.match(/const QR_JSON_MAX_BYTES = (\d+);/)[1]), 1700);
  const ctx = vm.createContext({ window: {}, self: {} });
  vm.runInContext(R('src', 'renderer', 'vendor', 'qrcode.js'), ctx);
  const qrcode = ctx.qrcode || ctx.window.qrcode;
  const qr = qrcode(0, 'L');
  qr.addData(JSON.stringify(configOfSize(1700)));
  qr.make();
  assert.equal(qr.getModuleCount(), 137, 'version 30');
  assert.match(qr.createSvgTag({ cellSize: 4, margin: 16, scalable: true }), /viewBox/);
  // What the CSS grants the code: the .qr-image cap less its own padding (the quiet zone, 4 modules a side, is inside it).
  // Only if that is the rule in force: a second .qr-image width in a later sheet (lists.css once had 232px) wins the
  // cascade and squeezed every code to 208px.
  assert.equal([...CSS.matchAll(/\.qr-image\s*\{[^}]*\bwidth:/g)].length, 1, '.qr-image must set its width in one place only');
  const cap = Number(CSS.match(/\.qr-image\s*\{[^}]*width:\s*min\(\s*(\d+)px/)[1]);
  const pad = Number((CSS.match(/\.qr-image\s*\{[^}]*padding:\s*(\d+)px/) || [0, 0])[1]);
  const pxPerModule = (cap - pad * 2) / (qr.getModuleCount() + 8);
  assert.ok(pxPerModule >= 2, `${pxPerModule.toFixed(2)} px per module — under 2 px a phone camera cannot resolve it`);
  // and the old limit is what this one exists to keep out
  const bigger = qrcode(0, 'L');
  bigger.addData(JSON.stringify(configOfSize(2900)));
  bigger.make();
  assert.ok((cap - pad * 2) / (bigger.getModuleCount() + 8) < 2, '2,900 bytes (version 40) is what the limit exists to keep out');
  // the escape stays below the byte-per-character trap: 'ا' & 0xff would be an apostrophe
  assert.equal('ا'.charCodeAt(0) & 0xff, 0x27);
});

/* ------------------------------------ the add box ------------------------------------ */

function importHarness(reply) {
  const calls = [];
  const state = { servers: [], selectedServerId: null, subscriptions: [] };
  const ctx = vm.createContext({
    state, t: en,
    toast: (msg, kind) => calls.push(['toast', msg, kind || '']),
    renderServers() {}, renderPicker() {}, renderSubs() {}, renderChains() {}, renderPool() {},
    window: {
      api: {
        importServers: async (text) => { calls.push(['importServers', text]); return typeof reply === 'function' ? reply(text) : reply; },
        addSub: async (url) => { calls.push(['addSub', url]); return { added: 3 }; },
        listSubs: async () => [], listServers: async () => state.servers
      }
    },
    String, JSON, Array
  });
  vm.runInContext([constSource('HTTP_PROXY_LINK'), ...['looksLikeJsonText', 'importErrorReason', 'smartImport'].map(fnSource)].join('\n'), ctx);
  return { ctx, calls, state };
}
const imported = (n) => ({ servers: Array.from({ length: n }, (_, i) => ({ id: 's' + i })), added: n, errors: [] });

test('pasted JSON goes to importServers exactly as typed — pretty-printed, indented, nothing filtered or joined', async () => {
  const pretty = JSON.stringify([CONFIG, Object.assign({}, CONFIG, { remarks: 'DE-3' })], null, 2);
  assert.ok(pretty.startsWith('[\n  {'), 'the shape that a line-by-line import would have mangled');
  const h = importHarness(imported(2));
  await h.ctx.smartImport(pretty);
  assert.deepEqual(h.calls.filter((c) => c[0] === 'importServers'), [['importServers', pretty]]);
  assert.ok(!h.calls.some((c) => c[0] === 'addSub'), 'never read as subscription URLs');

  const one = JSON.stringify(CONFIG, null, 2);
  const h2 = importHarness(imported(1));
  await h2.ctx.smartImport(one);
  assert.deepEqual(h2.calls.filter((c) => c[0] === 'importServers'), [['importServers', one]]);
  // a minified one, with whitespace around it
  const h3 = importHarness(imported(1));
  const min = JSON.stringify(CONFIG);
  await h3.ctx.smartImport('  ' + min + '\n');
  assert.deepEqual(h3.calls.filter((c) => c[0] === 'importServers'), [['importServers', min]], 'only the outer whitespace goes, as for every paste');
  assert.equal(h3.state.servers.length, 1);
  assert.equal(h3.state.selectedServerId, 's0');
});

test('the add box says what it did with JSON: the count, the first reason, or that nothing was found', async () => {
  const h = importHarness(imported(5));
  await h.ctx.smartImport('{"outbounds":[]}');
  assert.deepEqual(h.calls.pop(), ['toast', `5 ${en('t.serversAdded')}`, 'ok']);

  const withErr = importHarness({ servers: [{ id: 'a' }], added: 1, errors: [{ line: 'tuic', error: 'unsupported protocol: tuic' }] });
  await withErr.ctx.smartImport('{"outbounds":[]}');
  assert.deepEqual(withErr.calls.pop(), ['toast', `1 ${en('t.serversAdded')} (1 ${en('t.errors')}: unsupported protocol: tuic)`, 'ok']);

  const none = importHarness({ servers: [], added: 0, errors: [] });
  await none.ctx.smartImport('{"outbounds":[]}');
  assert.deepEqual(none.calls.pop(), ['toast', en('t.nothingFound'), 'err']);

  const refused = importHarness({ servers: [], added: 0, errors: [{ line: '', error: 'invalid JSON: Unexpected end of JSON input' }] });
  await refused.ctx.smartImport('{ "outbounds": [');
  assert.deepEqual(refused.calls.pop(), ['toast', `${en('t.failed')}: invalid JSON: Unexpected end of JSON input`, 'err']);
});

test('links, subscriptions and a WireGuard .conf still take their own paths', async () => {
  // links: split by line, joined back, sent once
  const links = importHarness(imported(2));
  await links.ctx.smartImport('  vless://a@h:1#A  \n\nvmess://B\n');
  assert.deepEqual(links.calls.filter((c) => c[0] === 'importServers'), [['importServers', 'vless://a@h:1#A\nvmess://B']]);

  // a subscription URL is added as one, not imported
  const sub = importHarness(imported(0));
  await sub.ctx.smartImport('https://sub.example.com/x');
  assert.deepEqual(sub.calls.filter((c) => c[0] === 'addSub'), [['addSub', 'https://sub.example.com/x']]);
  assert.ok(!sub.calls.some((c) => c[0] === 'importServers'));

  // a WireGuard .conf is also a "[" document — the WireGuard branch has it first, with its own message
  const wg = '[Interface]\nPrivateKey = k\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = p\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 0.0.0.0/0';
  const h = importHarness(imported(1));
  await h.ctx.smartImport(wg);
  assert.deepEqual(h.calls.filter((c) => c[0] === 'importServers'), [['importServers', wg]]);
  assert.deepEqual(h.calls.pop(), ['toast', en('t.wgAdded'), 'ok']);
});

test('a refusal on the link path now carries its reason (Clash YAML’s “use the subscription link”)', async () => {
  const clash = 'Clash YAML is not supported — use the subscription link';
  const h = importHarness({ servers: [], added: 0, errors: [{ line: 'proxies:', error: clash }] });
  await h.ctx.smartImport('proxies:\n  - name: a');
  assert.deepEqual(h.calls.filter((c) => c[0] === 'importServers'), [['importServers', 'proxies:\n- name: a']]);
  const [, msg, kind] = h.calls.pop();
  assert.equal(kind, 'err');
  assert.ok(msg.includes(clash), msg);
  assert.ok(msg.startsWith(en('t.nothingFound')) || msg.startsWith('0 '), msg);
  // a long reason is cut, not allowed to fill the screen
  const long = importHarness({ servers: [], added: 0, errors: [{ line: 'x', error: 'z'.repeat(400) }] });
  assert.ok(long.ctx.importErrorReason([{ error: 'z'.repeat(400) }]).length <= 140);
  assert.equal(long.ctx.importErrorReason([]), '');
  assert.equal(long.ctx.importErrorReason(undefined), '');
  assert.equal(long.ctx.importErrorReason(['plain text']), 'plain text');
});

test('the global paste takes a pasted JSON config too (one that has outbounds)', () => {
  assert.match(APP, /\|\| \(looksLikeJsonText\(text\) && text\.includes\('"outbounds"'\)\);/, 'the paste handler knows a JSON config when it sees one');
  const h = importHarness(imported(0));
  assert.equal(h.ctx.looksLikeJsonText('{ "a": 1 }'), true);
  assert.equal(h.ctx.looksLikeJsonText('  \n[ {'), true);
  assert.equal(h.ctx.looksLikeJsonText('vless://x'), false);
  assert.equal(h.ctx.looksLikeJsonText('[Interface]'), true, 'a hint only — the WireGuard branch is checked first by smartImport');
  assert.equal(h.ctx.looksLikeJsonText(undefined), false);
  // nothing in the add path drops a "{" or a "[" line
  const imp = fnSource('smartImport');
  assert.doesNotMatch(imp, /filter\([^)]*[\[{]/);
});
