'use strict';
/**
 * v1.28.0 — the Chains & groups page and a group's members in the flow
 * (.superpowers/sdd/groups-ui/design.md, git-ignored; the owner approved the
 * sample .superpowers/mockups/chains-groups.html as it is).
 *
 *  §1 the page: two tabs with their counts, the head button following the tab,
 *     open / close all; every chain and group card folds to its head (a click
 *     on it, not on its buttons or the name being typed); tab and open state
 *     remembered (localStorage, in try/catch); the card of what is connected —
 *     and of a group that runs — opens by itself, once per connection. The
 *     chain editor's «افزودن حلقه» and the group editor's «+ کانفیگ»: piles like
 *     the Servers page (hand-added, each subscription by name, the groups
 *     last), a subscription folded when there is more than one pile, a server
 *     already in the chain dimmed, a search that unfolds what matches. A group
 *     card, live: its speed and share bar on the head, a row per config —
 *     health dot, address, speed, delay, share — a dead one red, a missing
 *     one grey; a row goes to its server. Not connected: no speeds or shares.
 *  §2 the flow: a node whose outbound carries a running group (its tag, or
 *     `<tag>-h…` for a group on a chain's hop) gets a share bar inside its box
 *     and «alive/total»; hover opens the box, a click pins it, a click outside
 *     or Esc closes it, Enter toggles; rows go to their server, the foot to the
 *     group's card.
 *  §3 the stats event's `groups`; without it nothing changes.
 *
 * Like groupsUi.test.js, app.js's own functions run in a vm over a fake page;
 * nothing here reaches main or the network.
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
const LISTS = R('src', 'renderer', 'lists.css');
const HOME = R('src', 'renderer', 'home.css');
const ROUTING = R('src', 'renderer', 'routing.css');

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

/* ------------------------------------ a fake page ------------------------------------ */

const camel = (k) => k.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
const hasClass = (el, cls) => String(el.className || '').split(/\s+/).includes(cls);
function parseCompound(s) {
  const out = { tag: null, id: null, classes: [], attrs: [] };
  const re = /([a-zA-Z][\w-]*)|#([\w-]+)|\.([\w-]+)|\[([\w-]+)(?:="([^"]*)")?\]/g;
  for (let m = re.exec(s); m; m = re.exec(s)) {
    if (m[1]) out.tag = m[1].toUpperCase();
    else if (m[2]) out.id = m[2];
    else if (m[3]) out.classes.push(m[3]);
    else out.attrs.push([m[4], m[5]]);
  }
  return out;
}
function matchesCompound(el, c) {
  if (c.tag && el.tagName !== c.tag) return false;
  if (c.id && el.id !== c.id) return false;
  if (!c.classes.every((x) => hasClass(el, x))) return false;
  for (const [k, v] of c.attrs) {
    const val = k.startsWith('data-') ? el.dataset[camel(k.slice(5))] : el.attrs[k];
    if (val === undefined || val === null) return false;
    if (v !== undefined && String(val) !== v) return false;
  }
  return true;
}
function matchesSel(el, sel) {
  const parts = sel.trim().split(/\s+/).map(parseCompound);
  if (!matchesCompound(el, parts[parts.length - 1])) return false;
  let i = parts.length - 2;
  for (let node = el.parentNode; i >= 0 && node; node = node.parentNode) if (matchesCompound(node, parts[i])) i--;
  return i < 0;
}
const kids = (el) => el.children.filter((c) => c && typeof c === 'object');
const walk = (el, fn) => { for (const c of kids(el)) { fn(c); walk(c, fn); } };
function all(el, pred, out = []) {
  for (const c of kids(el)) { if (pred(c)) out.push(c); all(c, pred, out); }
  return out;
}
const byCls = (el, cls) => all(el, (e) => hasClass(e, cls));
const one = (el, cls) => { const f = byCls(el, cls); assert.ok(f.length, 'nothing found: .' + cls); return f[0]; };

/**
 * Just enough of an element for the code under test: children (text as
 * strings) with parents and siblings, classes, attributes (data-* in dataset),
 * listeners, a box (`rect`) and a size (`size`), a selector engine — and, for a
 * node built from an innerHTML template, its named parts (as groupsUi.test.js).
 */
function fakeEl(tag, doc) {
  const el = {
    tagName: String(tag || 'div').toUpperCase(), children: [], parentNode: null, attrs: {}, dataset: {}, style: {},
    hidden: false, disabled: false, title: '', className: '', id: '', dir: '', value: '', type: '', _text: '', tabIndex: -1,
    onclick: null, onkeydown: null, oninput: null, onscroll: null, listeners: {}, rect: null, size: null, scrollTop: 0, html: '', parts: {},
    get textContent() { return el._text + el.children.map((c) => (typeof c === 'string' ? c : c.textContent)).join(''); },
    set textContent(v) { el._text = String(v == null ? '' : v); for (const c of kids(el)) c.parentNode = null; el.children = []; },
    classList: {
      toggle(c, on) {
        const set = new Set(String(el.className || '').split(/\s+/).filter(Boolean));
        const want = on === undefined ? !set.has(c) : !!on;
        if (want) set.add(c); else set.delete(c);
        el.className = [...set].join(' ');
        return want;
      },
      add: (...c) => c.forEach((x) => el.classList.toggle(x, true)),
      remove: (...c) => c.forEach((x) => el.classList.toggle(x, false)),
      contains: (c) => hasClass(el, c)
    },
    appendChild(c) { if (c.parentNode) c.remove(); el.children.push(c); c.parentNode = el; return c; },
    append(...cs) { for (const c of cs) { if (c && typeof c === 'object') el.appendChild(c); else el.children.push(String(c)); } },
    insertBefore(c, ref) {
      if (c.parentNode) c.remove();
      const i = el.children.indexOf(ref);
      el.children.splice(i < 0 ? el.children.length : i, 0, c);
      c.parentNode = el;
      return c;
    },
    get nextSibling() { if (!el.parentNode) return null; const s = el.parentNode.children; return s[s.indexOf(el) + 1] || null; },
    remove() { if (el.parentNode) { el.parentNode.children = el.parentNode.children.filter((x) => x !== el); el.parentNode = null; } },
    contains(n) { for (let x = n; x; x = x.parentNode) if (x === el) return true; return false; },
    get isConnected() { let x = el; while (x.parentNode) x = x.parentNode; return !!x.isRoot; },
    setAttribute(k, v) {
      el.attrs[k] = String(v);
      if (k === 'disabled') el.disabled = true;
      if (k === 'hidden') el.hidden = true;
      if (k === 'tabindex') el.tabIndex = Number(v);
      if (['id', 'dir', 'title', 'type', 'value'].includes(k)) el[k] = String(v);
      if (k.startsWith('data-')) el.dataset[camel(k.slice(5))] = String(v);
    },
    getAttribute(k) { return k in el.attrs ? el.attrs[k] : null; },
    removeAttribute(k) { delete el.attrs[k]; if (k === 'tabindex') el.tabIndex = -1; if (k.startsWith('data-')) delete el.dataset[camel(k.slice(5))]; },
    addEventListener(type, fn) { (el.listeners[type] = el.listeners[type] || []).push(fn); },
    fire(type, ev = {}) { for (const fn of el.listeners[type] || []) fn(Object.assign({ target: el, preventDefault() {} }, ev)); },
    getBoundingClientRect() { return el.rect || { left: 0, top: 0, right: 0, bottom: 0, width: 0, height: 0 }; },
    get offsetWidth() { return el.size ? el.size[0] : 0; },
    get offsetHeight() { return el.size ? el.size[1] : 0; },
    focus() { if (doc) doc.activeElement = el; },
    querySelectorAll(sel) {
      const sels = sel.split(',');
      const out = [];
      walk(el, (n) => { if (sels.some((s) => matchesSel(n, s))) out.push(n); });
      return out;
    },
    querySelector(sel) {
      const found = el.querySelectorAll(sel)[0];
      if (found) return found;
      const m = sel.match(/^\.([\w-]+)$/);
      const tokens = new Set([...el.html.matchAll(/class="([^"]*)"/g)].flatMap((x) => x[1].split(/\s+/)));
      if (m && tokens.has(m[1])) {
        if (!el.parts[sel]) { const p = fakeEl('span', doc); p.className = m[1]; p.parentNode = el; el.parts[sel] = p; }
        return el.parts[sel];
      }
      return null;
    },
    set innerHTML(v) { el.html = String(v); el.children = []; el.parts = {}; el._text = ''; },
    get innerHTML() { return el.html; }
  };
  return el;
}

/** A page: a root, elements by id under it, `$`/`$$` as app.js uses them, a document with listeners. */
function fakePage(dir = 'ltr') {
  const doc = { activeElement: null, listeners: {}, documentElement: { dir } };
  const root = fakeEl('html', doc);
  root.isRoot = true;
  const body = fakeEl('body', doc);
  root.appendChild(body);
  doc.body = body;
  doc.createElement = (tag) => fakeEl(tag, doc);
  doc.addEventListener = (type, fn) => { (doc.listeners[type] = doc.listeners[type] || []).push(fn); };
  doc.fire = (type, ev) => { for (const fn of doc.listeners[type] || []) fn(ev); };
  const els = new Map();
  const get = (id) => {
    if (!els.has(id)) { const e = fakeEl('div', doc); e.id = id; els.set(id, e); body.appendChild(e); }
    return els.get(id);
  };
  const $ = (sel) => { const m = String(sel).match(/^#([\w-]+)$/); return m ? get(m[1]) : null; };
  const $$ = (sel) => { const m = String(sel).match(/^#([\w-]+)\s+(.+)$/); return m ? get(m[1]).querySelectorAll(m[2]) : []; };
  return { get, $, $$, document: doc, root, body };
}

/** Timers the test runs by hand. */
function fakeTimers() {
  let n = 0;
  const due = new Map();
  return {
    setTimeout: (fn) => { due.set(++n, fn); return n; },
    clearTimeout: (id) => { due.delete(id); },
    flush() { const fns = [...due.values()]; due.clear(); fns.forEach((f) => f()); },
    get pending() { return due.size; }
  };
}

/** localStorage: a map — or one that throws on every call (a private window, blocked site data). */
function fakeStorage(seed = {}, throws = false) {
  const m = new Map(Object.entries(seed));
  const no = () => { throw new Error('SecurityError: storage is disabled'); };
  return { map: m, getItem: (k) => (throws ? no() : m.has(k) ? m.get(k) : null), setItem: (k, v) => (throws ? no() : m.set(k, String(v))) };
}

/* ------------------------------------ the store ------------------------------------ */

const SUBS = [{ id: 'sub-a', name: 'Sub A' }, { id: 'sub-b', name: 'Sub B' }];
const SERVERS = [
  { id: 'm1', name: 'UK', protocol: 'vless', address: 'uk.example.com', port: 443 },
  { id: 'm2', name: 'CDN', protocol: 'vless', address: 'cdn.example.org', port: 443 },
  { id: 'a1', name: 'A-DE', protocol: 'vless', address: 'a1.sub-a.example', port: 443, subId: 'sub-a' },
  { id: 'a2', name: 'A-NL', protocol: 'vless', address: 'a2.sub-a.example', port: 8443, subId: 'sub-a' },
  { id: 'b1', name: 'B-US', protocol: 'trojan', address: 'b1.sub-b.example', port: 443, subId: 'sub-b' }
];
const GROUPS = [
  { id: 'g-cdn', name: 'CDN x3', strategy: 'roundRobin', members: [{ id: 'm2', address: '104.16.1.1' }, { id: 'm2', address: '104.17.2.2', port: 2053 }, { id: 'm2' }] },
  { id: 'g-eu', name: 'EU mix', strategy: 'leastPing', members: [{ id: 'a1' }, { id: 'gone' }, { id: 'a2' }, { id: 'b1' }] },
  { id: 'g-asia', name: 'Asia', strategy: 'random', members: [{ id: 'b1' }] }
];
const CHAINS = [{ id: 'c1', name: 'UK → CDN', members: ['m1', 'g-cdn'] }, { id: 'c2', name: 'Empty', members: [] }];

/** The running groups as the stats event carries them (design §3). */
function cdnRun(tag = 'out-g-cdn') {
  return { tag, groupId: 'g-cdn', name: 'CDN x3', strategy: 'roundRobin', members: [
    { id: 'm2', name: 'CDN', address: '104.16.1.1', port: 443, up: 100, down: 2000, upSpeed: 100, downSpeed: 1500, alive: true, delay: 84 },
    { id: 'm2', name: 'CDN', address: '104.17.2.2', port: 2053, up: 100, down: 2000, upSpeed: 100, downSpeed: 1400, alive: true, delay: 97 },
    { id: 'm2', name: 'CDN', address: 'cdn.example.org', port: 443, up: 50, down: 1000, upSpeed: 50, downSpeed: 1000, alive: null, delay: null }] };
}
function euRun(tag = 'out-chain-c9-h1') {
  return { tag, groupId: 'g-eu', name: 'EU mix', strategy: 'leastPing', members: [
    { id: 'a1', name: 'A-DE', address: 'a1.sub-a.example', port: 443, up: 10, down: 900, upSpeed: 20, downSpeed: 2000, alive: true, delay: 61 },
    { id: 'a2', name: 'A-NL', address: 'a2.sub-a.example', port: 8443, up: 0, down: 0, upSpeed: 0, downSpeed: 0, alive: true, delay: 88 },
    { id: 'b1', name: 'B-US', address: 'b1.sub-b.example', port: 443, up: 0, down: 0, upSpeed: 0, downSpeed: 0, alive: false, delay: null }] };
}

/* ------------------------------------ the harness ------------------------------------ */

const PAGE_FNS = ['loadCgState', 'saveCgState', 'cgCanGroups', 'cgTab', 'cgApplyTab', 'cgSetTab', 'cgIsOpen', 'cgCardOf', 'cgPaintCard', 'cgPaintAll',
  'cgSetOpen', 'cgAll', 'cgReveal', 'cgPrune', 'cgAutoOpen', 'cgWireHead', 'cgChainSum', 'cgFillPicker', 'cgPile', 'cgPickRow', 'revealServer',
  'renderChains', 'renderGroups', 'groupCard', 'openGroupCard', 'openChainCard', 'grpServerPanel'];
const GM_FNS = ['gmNum', 'groupsForTags', 'gmSum', 'gmShares', 'gmAggregate', 'gmPair', 'gmShade', 'gmBarInto', 'gmMs', 'gmCardRow', 'gmFillRow',
  'gmFillCard', 'gmApplyCards', 'gmMark', 'gmDecorate', 'gmDecorateFlows', 'gmPopEl', 'gmHover', 'gmOpen', 'gmClose', 'gmToggle', 'gmPopRow',
  'gmFillPopRow', 'gmRenderPop', 'gmPlace', 'gmOnStats', 'gmOnStatus'];
const HELPERS = ['edNode', 'appendSome', 'warpNum', 'srvById', 'grpById', 'grpLive', 'grpCountText', 'grpAddrText', 'chainMembers', 'fmtBytes', 'fmtSpeed',
  'flowArrow', 'serverGroups', 'groupKey', 'loadFoldedGroups', 'setGroupFolded', 'pingResultLabel', 'fmtMs', 'pingClass', 'connectGlyph'];

/** The box's wiring (a click outside, Esc, scroll and resize), as app.js has it at its top level. */
function boxWiring() {
  const a = APP.indexOf('// the box: a click outside a pinned one closes it');
  const b = APP.indexOf("window.addEventListener('resize', () => gmPlace());");
  assert.ok(a > -1 && b > a, 'the box’s wiring is in app.js');
  return APP.slice(a, b) + "window.addEventListener('resize', () => gmPlace());\n";
}

function harness({ lang = 'en', dir = lang === 'fa' ? 'rtl' : 'ltr', storage = fakeStorage(), groupsApi = true, servers = SERVERS, groups = GROUPS, chains = CHAINS } = {}) {
  const page = fakePage(dir);
  const calls = [];
  const timers = fakeTimers();
  const win = {
    i18n: { lang }, innerWidth: 1000, innerHeight: 800, listeners: {},
    addEventListener(type, fn) { (win.listeners[type] = win.listeners[type] || []).push(fn); },
    api: Object.assign({ setChains: async (l) => { calls.push(['setChains', plain(l)]); } }, groupsApi ? { setGroups: async (l) => l } : {})
  };
  const state = { servers: plain(servers), subscriptions: plain(SUBS), groups: plain(groups), chains: plain(chains), pings: {}, profiles: null,
    connected: false, connecting: false, activeServerId: null, selectedServerId: null };
  const ctx = vm.createContext({
    state, t: (k) => TR(lang, k), $: page.$, $$: page.$$, document: page.document, window: win, localStorage: storage,
    setTimeout: timers.setTimeout, clearTimeout: timers.clearTimeout, requestAnimationFrame: (fn) => fn(),
    escapeHtml: (s) => String(s), usageLabel: () => '',
    showView: (v) => calls.push(['view', v]), flashInto: (el, f) => calls.push(['flash', el ? (el.dataset.srvId || el.dataset.groupId || el.dataset.chainId) : null, f || '']),
    renderServers: () => calls.push(['renderServers']), renderPicker: () => {}, renderAdvanced: () => {}, renderPool: () => {},
    pingServer: () => {}, connect: () => {}, shareRouting: () => {}, openGroupEditor: () => {}, deleteGroup: () => {},
    renderGroupEditor: () => calls.push(['renderGroupEditor']), persistChains: () => calls.push(['persistChains']),
    profileLive: () => !!ctx.rfLive,
    String, Array, Object, Number, Math, JSON, Set, Map, Date, Error, Promise
  });
  const prelude = [
    "const CG_KEY = 'irnetfree.chainsGroups';", "const FOLDED_KEY = 'irnetfree.foldedGroups';",
    "const GROUP_STRATEGIES = ['roundRobin', 'leastPing', 'random'];",
    // var, not const / let: the test reads and sets them on the context
    'var cgState = loadCgState(); var cgSearch = {}; var foldedGroups = loadFoldedGroups();',
    'var cgConnKey = null; var cgOpened = new Set(); var gmLive = []; var gmPop = null; var hfModel = null; var rfModel = null;'
  ].join('\n');
  vm.runInContext(prelude + '\n' + [...new Set([...PAGE_FNS, ...GM_FNS, ...HELPERS])].map(fnSource).join('\n') + '\n' + boxWiring(), ctx);
  return { ctx, page, state, calls, timers, win, storage, lang };
}

/** A tick of the stats event. */
const tick = (h, groups, extra = {}) => h.ctx.gmOnStats(Object.assign({ upSpeed: 1, downSpeed: 1, per: { proxy: { up: 1, down: 1, upSpeed: 1, downSpeed: 1 } } }, groups ? { groups } : {}, extra));
/** Connected to `id`, as the status event leaves it (renderTrafficPath → gmOnStatus). */
const connect = (h, id) => { h.state.connected = true; h.state.activeServerId = id; h.ctx.gmOnStatus('connected'); };
const disconnect = (h) => { h.state.connected = false; h.ctx.gmOnStatus('disconnected'); };
const card = (h, kind, id) => (kind === 'g' ? kids(h.page.get('groupsWrap')).find((c) => c.dataset.groupId === id) : kids(h.page.get('chainsWrap')).find((c) => c.dataset.chainId === id));
const rowsOf = (c) => byCls(c, 'gm-row');
const shown = (el) => !el.hidden;

/* ------------------------------------ strings and markup ------------------------------------ */

const NEW_KEYS = [...new Set([
  ...[...APP.matchAll(/'((?:cg|gm)\.[A-Za-z.]*[A-Za-z])'/g)].map((m) => m[1]),
  ...[...HTML.matchAll(/data-i18n(?:-ph|-title)?="((?:cg|gm)\.[^"]+)"/g)].map((m) => m[1]),
  'chain.available', 'chain.intro', 'grp.intro'
])];

test('v1.28 strings: once in fa and once in en, one clean literal each (no straight apostrophe), English in en, Persian in fa; the owner’s words', () => {
  assert.ok(NEW_KEYS.length >= 18, `only ${NEW_KEYS.length} keys found`);
  for (const key of NEW_KEYS) {
    assert.equal(I18N.split(`'${key}':`).length - 1, 2, `'${key}' is not defined exactly once in each of fa and en`);
    for (const line of I18N.split('\n').filter((l) => l.includes(`'${key}':`))) {
      const m = line.slice(line.indexOf(`'${key}':`)).match(/^'[^']+':\s*'((?:[^'\\]|\\.)*)'/);
      assert.ok(m, `${key}: not a single clean string literal — a straight ' inside? ${line.trim().slice(0, 90)}`);
      assert.ok(!/\\'/.test(m[1]), `${key}: use ’ and not an escaped '`);
    }
    assert.ok(fa(key).trim() && en(key).trim(), key);
    assert.doesNotMatch(en(key), /[؀-ۿ]/, `en '${key}' is Persian`);
    assert.notEqual(fa(key), en(key), `${key}: fa is the English text`);
  }
  for (const s of ['{alive}', '{total}']) { assert.ok(fa('gm.health').includes(s)); assert.ok(en('gm.health').includes(s)); }
  // the sample's words, verbatim
  assert.equal(fa('chain.available'), 'افزودن حلقه');
  assert.deepEqual([fa('cg.openAll'), fa('cg.closeAll'), fa('cg.add'), fa('cg.inChain')], ['همه را باز کن', 'همه را ببند', '+ افزودن', 'در زنجیره است']);
  assert.equal(fa('gm.dead'), 'جواب نمی‌دهد — تا وقتی جواب بدهد کنار گذاشته شده');
  assert.equal(fa('gm.missingWhy'), 'از فهرست سرورها پاک شده — در ویرایش گروه بردارش');
  assert.equal(fa('gm.popHint'), 'روی هر عضو بزن: می‌روی به همان کانفیگ');
  assert.equal(fa('gm.openGroup'), 'باز کردن گروه ←');
  assert.equal(en('gm.openGroup'), 'Open the group →', 'its arrow points the way the page reads');
  assert.equal(fa('chain.intro'), 'هر زنجیره یک کانفیگ است: سرورها پشت سر هم. روی هر کارت بزن تا باز شود و حلقه‌هایش را عوض کنی.');
});

test('the markup: two tabs with their counts, open / close all, a pane each, the head button of each tab — the groups’ hidden until its tab is on', () => {
  const view = HTML.slice(HTML.indexOf('<section class="view" id="view-chain">'), HTML.indexOf('</section>', HTML.indexOf('id="view-chain"')));
  const head = view.slice(0, view.indexOf('</div>\n        </div>'));
  assert.match(head, /id="btnAddChain" data-i18n="chain\.new">/);
  assert.match(head, /<button class="btn primary" hidden id="btnAddGroup" data-i18n="grp\.new">\+ گروه تازه<\/button>/, 'in the page’s head, hidden until its tab');
  assert.match(view, /<div class="seg" role="tablist" id="cgTabs">/);
  assert.match(view, /<button class="seg-btn active" type="button" role="tab" id="cgTabChains" aria-selected="true" aria-controls="cgPaneChains">[^\n]*<span data-i18n="chain\.sec">زنجیره‌ها<\/span> <span class="cg-count" id="cgCountChains">/);
  assert.match(view, /<button class="seg-btn" type="button" role="tab" id="cgTabGroups" aria-selected="false" aria-controls="cgPaneGroups">[^\n]*<span class="cg-count" id="cgCountGroups">/);
  assert.match(view, /id="cgOpenAll" data-i18n="cg\.openAll">همه را باز کن</);
  assert.match(view, /id="cgCloseAll" data-i18n="cg\.closeAll">همه را ببند</);
  assert.match(view, /<div class="cg-pane" id="cgPaneChains" role="tabpanel" aria-labelledby="cgTabChains">/);
  assert.match(view, /<div class="cg-pane" id="cgPaneGroups" role="tabpanel" aria-labelledby="cgTabGroups" hidden>/);
  const chains = view.slice(view.indexOf('id="cgPaneChains"'), view.indexOf('id="cgPaneGroups"'));
  for (const id of ['chainsWrap', 'chainsEmpty']) assert.ok(chains.includes(`id="${id}"`), id);
  assert.ok(view.slice(view.indexOf('id="cgPaneGroups"')).includes('id="groupsSection"'), 'the groups’ section inside its pane');
  // the wiring
  for (const [id, call] of [['cgTabChains', "cgSetTab('chains')"], ['cgTabGroups', "cgSetTab('groups')"], ['cgOpenAll', 'cgAll(true)'], ['cgCloseAll', 'cgAll(false)']]) {
    assert.ok(APP.includes(`$('#${id}').onclick = () => ${call};`), id);
  }
});

/* ------------------------------------ the tabs, remembered ------------------------------------ */

test('the tabs: the pane and head button of the one on show, counts (Persian digits in Persian), remembered — and no groups tab on a back end without them', () => {
  const h = harness({ lang: 'fa' });
  h.ctx.renderChains();
  const g = (id) => h.page.get(id);
  assert.deepEqual([g('cgTabChains').className, g('cgTabChains').attrs['aria-selected'], g('cgTabGroups').attrs['aria-selected']], ['active', 'true', 'false']);
  assert.deepEqual([g('cgPaneChains').hidden, g('cgPaneGroups').hidden, g('btnAddChain').hidden, g('btnAddGroup').hidden], [false, true, false, true]);
  assert.deepEqual([g('cgCountChains').textContent, g('cgCountGroups').textContent], ['۲', '۳']);
  h.ctx.cgSetTab('groups');
  assert.deepEqual([g('cgTabGroups').className, g('cgTabGroups').attrs['aria-selected'], g('cgTabChains').attrs['aria-selected']], ['active', 'true', 'false']);
  assert.deepEqual([g('cgPaneChains').hidden, g('cgPaneGroups').hidden, g('btnAddChain').hidden, g('btnAddGroup').hidden], [true, false, true, false]);
  assert.equal(JSON.parse(h.storage.map.get('irnetfree.chainsGroups')).tab, 'groups', 'remembered');
  // the next window starts on it, with the cards as they were left
  h.ctx.cgSetOpen('g:g-eu', true);
  const again = harness({ storage: fakeStorage(Object.fromEntries(h.storage.map)) });
  assert.equal(again.ctx.cgTab(), 'groups');
  assert.equal(again.ctx.cgIsOpen('g:g-eu'), true);
  assert.equal(again.ctx.cgIsOpen('g:g-cdn'), false, 'folded until opened');
  // a back end without groups: no groups tab, the chains’ on show whatever was remembered
  const old = harness({ groupsApi: false, storage: fakeStorage(Object.fromEntries(h.storage.map)) });
  old.ctx.renderChains();
  assert.equal(old.ctx.cgTab(), 'chains');
  assert.deepEqual([old.page.get('cgTabGroups').hidden, old.page.get('cgPaneGroups').hidden, old.page.get('btnAddGroup').hidden, old.page.get('groupsSection').hidden], [true, true, true, true]);
});

test('remembering never breaks the page: unreadable storage, storage that throws, junk in it — the defaults, and every change still works', () => {
  for (const storage of [fakeStorage({ 'irnetfree.chainsGroups': '{not json' }), fakeStorage({}, true),
    fakeStorage({ 'irnetfree.chainsGroups': JSON.stringify({ tab: 'nope', open: { 'c:c1': 'yes', 'g:g-eu': true }, pick: [1] }) })]) {
    const h = harness({ storage });
    assert.equal(h.ctx.cgTab(), 'chains');
    assert.equal(h.ctx.cgIsOpen('c:c1'), false, 'only true and false are kept');
    h.ctx.renderChains();
    h.ctx.cgSetTab('groups');
    h.ctx.cgSetOpen('g:g-cdn', true);
    assert.equal(h.ctx.cgIsOpen('g:g-cdn'), true);
    assert.equal(hasClass(card(h, 'g', 'g-cdn'), 'open'), true);
  }
  assert.equal(harness({ storage: fakeStorage({ 'irnetfree.chainsGroups': JSON.stringify({ open: { 'g:g-eu': true } }) }) }).ctx.cgIsOpen('g:g-eu'), true);
  // a chain or group that is gone is forgotten
  const h = harness({ storage: fakeStorage({ 'irnetfree.chainsGroups': JSON.stringify({ open: { 'c:old': true, 'g:old': false, 'c:c1': true } }) }) });
  h.ctx.renderChains();
  assert.deepEqual(Object.keys(JSON.parse(h.storage.map.get('irnetfree.chainsGroups')).open), ['c:c1']);
});

/* ------------------------------------ folding cards ------------------------------------ */

test('a card folds to its head: a click on the head or its chevron toggles it, never one on its buttons or the name being typed; open / close all take the tab on show', () => {
  const h = harness();
  h.ctx.renderChains();
  const c = card(h, 'g', 'g-cdn');
  const head = one(c, 'chain-card-head');
  const chev = one(c, 'cg-chev');
  assert.deepEqual([hasClass(c, 'cg-card'), hasClass(c, 'open'), chev.attrs['aria-expanded'], chev.textContent], [true, false, 'false', '◀']);
  assert.equal(chev.attrs['aria-label'], en('cg.toggle'));
  head.onclick({ target: head });
  assert.deepEqual([hasClass(c, 'open'), chev.attrs['aria-expanded']], [true, 'true']);
  head.onclick({ target: one(c, 'grp-name') });
  assert.equal(hasClass(c, 'open'), false, 'its name');
  head.onclick({ target: chev });
  assert.equal(hasClass(c, 'open'), true, 'its chevron');
  for (const cls of ['grp-edit', 'ch-connect', 'grp-ping', 'grp-del']) {
    head.onclick({ target: one(c, cls) });
    assert.equal(hasClass(c, 'open'), true, cls + ' is a button of its own');
  }
  // a chain's name is typed in its head: a click there is not a fold
  const ch = card(h, 'c', 'c1');
  const chead = ch.querySelector('.chain-card-head');
  const input = fakeEl('input');
  input.parentNode = chead;
  chead.onclick({ target: input });
  assert.equal(hasClass(ch, 'open'), false);
  chead.onclick({ target: chead });
  assert.equal(hasClass(ch, 'open'), true);
  // open / close all: the tab on show only
  h.ctx.cgAll(false);
  assert.equal(hasClass(ch, 'open'), false);
  assert.equal(hasClass(c, 'open'), true, 'the groups’ tab is not on show');
  h.ctx.cgSetTab('groups');
  h.ctx.cgAll(true);
  assert.ok(kids(h.page.get('groupsWrap')).every((x) => hasClass(x, 'open')));
  assert.equal(hasClass(ch, 'open'), false);
  // the flow's way to a card: its tab and the card open
  h.ctx.openChainCard('c2');
  assert.equal(h.ctx.cgTab(), 'chains');
  assert.equal(hasClass(card(h, 'c', 'c2'), 'open'), true);
  assert.deepEqual(h.calls.slice(-2), [['view', 'chain'], ['flash', 'c2', '.chain-name']]);
  h.ctx.openGroupCard('g-asia');
  assert.equal(h.ctx.cgTab(), 'groups');
  assert.equal(hasClass(card(h, 'g', 'g-asia'), 'open'), true);
});

test('the folded head says it all: a chain its hops in the reading direction, a group how many configs and how it spreads them', () => {
  const h = harness();
  h.ctx.renderChains();
  const sum = (id) => card(h, 'c', id).querySelector('.cg-sum');
  assert.equal(sum('c1').textContent, 'UK → ⧉ CDN x3');
  assert.deepEqual(kids(sum('c1')).map((b) => b.tagName), ['B', 'B'], 'each hop bold, isolated (CSS)');
  assert.equal(sum('c2').textContent, en('cg.noHops'));
  assert.equal(byCls(card(h, 'g', 'g-eu'), 'grp-meta')[0].textContent, `3 configs · ${en('grp.st.leastPing')}`);
  const p = harness({ lang: 'fa' });
  p.ctx.renderChains();
  assert.equal(card(p, 'c', 'c1').querySelector('.cg-sum').textContent, 'UK ← ⧉ CDN x3', 'Persian reads right to left');
  assert.equal(byCls(card(p, 'g', 'g-eu'), 'grp-meta')[0].textContent, `۳ کانفیگ · ${fa('grp.st.leastPing')}`);
});

test('the card of what is connected opens by itself — the chain or group connected and any group that runs — once per connection; closed by hand it stays closed', () => {
  const h = harness();
  h.ctx.renderChains();
  assert.ok(kids(h.page.get('chainsWrap')).every((c) => !hasClass(c, 'open')), 'folded until opened');
  connect(h, 'c1');
  assert.equal(hasClass(card(h, 'c', 'c1'), 'open'), true, 'the chain connected');
  // a tick: the group on its hop runs — its card opens too
  tick(h, [cdnRun('proxy')]);
  assert.equal(hasClass(card(h, 'g', 'g-cdn'), 'open'), true, 'the group running');
  assert.equal(hasClass(card(h, 'g', 'g-eu'), 'open'), false);
  // closed by hand: the next ticks leave it closed
  h.ctx.cgSetOpen('c:c1', false);
  h.ctx.cgSetOpen('g:g-cdn', false);
  tick(h, [cdnRun('proxy')]);
  h.ctx.renderChains();
  assert.equal(hasClass(card(h, 'c', 'c1'), 'open'), false);
  assert.equal(hasClass(card(h, 'g', 'g-cdn'), 'open'), false);
  // a new connection: what it uses opens again
  disconnect(h);
  assert.equal(hasClass(card(h, 'c', 'c1'), 'open'), false, 'a disconnect folds nothing and opens nothing');
  connect(h, 'g-eu');
  assert.equal(hasClass(card(h, 'g', 'g-eu'), 'open'), true, 'the group connected');
  connect(h, 'c1');
  assert.equal(hasClass(card(h, 'c', 'c1'), 'open'), true);
});

/* ------------------------------------ the pick list ------------------------------------ */

test('the pick list in piles like the Servers page: hand-added first, each subscription by its name, the groups last; a subscription folded while there are several piles; folds remembered', () => {
  const h = harness();
  const list = fakeEl('div');
  const picked = [];
  const fill = (o = {}) => h.ctx.cgFillPicker(list, Object.assign({ withGroups: true, isIn: (id) => id === 'm1' || id === 'g-cdn', inText: en('cg.inChain'), onPick: (id) => picked.push(id) }, o));
  assert.equal(fill(), 8, 'five servers, three groups');
  const piles = kids(list);
  assert.deepEqual(piles.map((p) => [p.dataset.group, hasClass(p, 'folded')]), [['manual', false], ['sub:sub-a', true], ['sub:sub-b', true], ['groups', false]]);
  const head = (p) => one(p, 'srv-group-toggle');
  assert.deepEqual(piles.map((p) => [one(p, 'srv-group-name').textContent, one(p, 'srv-group-count').textContent, head(p).attrs['aria-expanded']]),
    [[en('srv.manual'), '2', 'true'], ['Sub A', '2', 'false'], ['Sub B', '1', 'false'], [en('grp.title'), '3', 'true']]);
  // a folded pile builds nothing until it is opened (a 300-server subscription costs one row)
  assert.equal(byCls(piles[1], 'cg-pick').length, 0);
  assert.equal(one(piles[1], 'srv-group-body').hidden, true);
  head(piles[1]).onclick();
  assert.deepEqual(byCls(piles[1], 'cg-pick').map((r) => r.dataset.srv), ['a1', 'a2']);
  assert.equal(hasClass(piles[1], 'folded'), false);
  assert.equal(JSON.parse(h.storage.map.get('irnetfree.chainsGroups')).pick['sub:sub-a'], false, 'remembered');
  head(piles[0]).onclick();
  fill();
  assert.deepEqual(kids(list).map((p) => [p.dataset.group, hasClass(p, 'folded')]), [['manual', true], ['sub:sub-a', false], ['sub:sub-b', true], ['groups', false]], 'drawn again as left');
  // the rows: badge, name, address (left to right), «+ Add» — one in it dimmed and saying so; a group its count
  const rows = byCls(list, 'cg-pick');
  const a1 = rows.find((r) => r.dataset.srv === 'a1');
  assert.deepEqual(kids(a1).map((c) => [c.className, c.textContent]), [['proto-badge proto-vless', 'vless'], ['srv-name', 'A-DE'], ['cg-addr', 'a1.sub-a.example:443'], ['cg-add', en('cg.add')]]);
  assert.equal(one(a1, 'cg-addr').dir, 'ltr');
  a1.onclick();
  assert.deepEqual(picked, ['a1']);
  const gcdn = rows.find((r) => r.dataset.srv === 'g-cdn');
  assert.deepEqual([hasClass(gcdn, 'in'), one(gcdn, 'cg-add').disabled, one(gcdn, 'cg-add').textContent, gcdn.onclick], [true, true, en('cg.inChain'), null]);
  assert.equal(one(rows.find((r) => r.dataset.srv === 'g-eu'), 'cg-addr').textContent, '3 configs', 'a group: how many of its configs are here');
  // one pile only: open, there is nothing to tell apart
  const solo = harness({ servers: SERVERS.slice(0, 2) });
  const l2 = fakeEl('div');
  solo.ctx.cgFillPicker(l2, { onPick() {} });
  assert.deepEqual(kids(l2).map((p) => [p.dataset.group, hasClass(p, 'folded')]), [['manual', false]]);
  // a subscription alone, its servers in it: open as well
  const subOnly = harness({ servers: SERVERS.slice(2, 4) });
  const l3 = fakeEl('div');
  subOnly.ctx.cgFillPicker(l3, { onPick() {} });
  assert.deepEqual(kids(l3).map((p) => [p.dataset.group, hasClass(p, 'folded')]), [['sub:sub-a', false]]);
});

test('a search shows only what matches — by name or address — and unfolds the piles that hold it, without remembering that; nothing found is said', () => {
  const h = harness();
  const list = fakeEl('div');
  const fill = (query) => h.ctx.cgFillPicker(list, { query, withGroups: true, onPick() {} });
  assert.equal(fill('b-us'), 1);
  assert.deepEqual(kids(list).map((p) => [p.dataset.group, hasClass(p, 'folded'), byCls(p, 'cg-pick').map((r) => r.dataset.srv)]), [['sub:sub-b', false, ['b1']]]);
  assert.equal(fill('SUB-A.EXAMPLE'), 2, 'an address, any case');
  assert.deepEqual(kids(list).map((p) => p.dataset.group), ['sub:sub-a']);
  // a fold during a search is the search's
  one(kids(list)[0], 'srv-group-toggle').onclick();
  assert.equal(h.storage.map.has('irnetfree.chainsGroups'), false, 'nothing remembered');
  assert.equal(fill('mix'), 1);
  assert.deepEqual(kids(list).map((p) => p.dataset.group), ['groups']);
  assert.equal(fill('nothing like it'), 0);
  assert.equal(list.textContent, en('ss.none'));
  // cleared: the folds as remembered again
  fill('');
  assert.deepEqual(kids(list).map((p) => [p.dataset.group, hasClass(p, 'folded')]), [['manual', false], ['sub:sub-a', true], ['sub:sub-b', true], ['groups', false]]);
});

test('the chain editor: «افزودن حلقه» with its own search and scroll, a server already in the chain dimmed — its search survives the redraw a pick makes', () => {
  const h = harness({ lang: 'fa' });
  h.ctx.renderChains();
  const c1 = card(h, 'c', 'c1');
  assert.match(c1.innerHTML, /<span class="field-label">افزودن حلقه<\/span>/);
  assert.match(c1.innerHTML, /<input class="input cg-search" dir="auto" placeholder="جستجوی کانفیگ…" aria-label="افزودن حلقه" \/>/);
  assert.match(c1.innerHTML, /<div class="cg-body">[\s\S]*<div class="cg-picker-list"><\/div>/, 'everything but the head folds away');
  const list = c1.querySelector('.cg-picker-list');
  assert.equal(list.dataset.chain, 'c1');
  const rows = byCls(list, 'cg-pick');
  assert.deepEqual(rows.map((r) => [r.dataset.srv, hasClass(r, 'in')]), [['m1', true], ['m2', false], ['g-cdn', true], ['g-eu', false], ['g-asia', false]], 'subscriptions folded, the hand-added and the groups open');
  assert.equal(one(rows[0], 'cg-add').textContent, 'در زنجیره است');
  assert.equal(one(rows[3], 'cg-addr').textContent, '۳ کانفیگ', 'Persian digits in Persian');
  rows[1].onclick();
  assert.deepEqual(h.state.chains[0].members, ['m1', 'g-cdn', 'm2']);
  assert.deepEqual(h.calls.at(-1), ['persistChains']);
  // the search: kept by chain across a redraw
  const search = c1.querySelector('.cg-search');
  search.value = 'A-';
  search.oninput();
  assert.deepEqual(byCls(list, 'cg-pick').map((r) => r.dataset.srv), ['a1', 'a2']);
  h.ctx.renderChains();
  const again = card(h, 'c', 'c1');
  assert.equal(again.querySelector('.cg-search').value, 'A-');
  assert.deepEqual(byCls(again.querySelector('.cg-picker-list'), 'cg-pick').map((r) => r.dataset.srv), ['a1', 'a2']);
});

test('the group editor’s «+ کانفیگ» is the same list in piles: servers only, one already in it as itself not offered, the rest of its behaviour as before', () => {
  const h = harness();
  const f = { members: [{ id: 'm2' }, { id: 'a1', address: '1.1.1.1' }], search: '', error: '' };
  const panel = h.ctx.grpServerPanel(f);
  const list = one(panel, 'cg-picker-list');
  assert.ok(hasClass(list, 'grp-pool'));
  assert.deepEqual(kids(list).map((p) => p.dataset.group), ['manual', 'sub:sub-a', 'sub:sub-b'], 'no groups pile');
  one(kids(list)[1], 'srv-group-toggle').onclick();
  assert.deepEqual(byCls(list, 'cg-pick').map((r) => r.dataset.srv), ['m1', 'a1', 'a2'], 'm2 is in it as itself; a1 only at its own address');
  byCls(list, 'cg-pick')[0].onclick();
  assert.deepEqual(plain(f.members).at(-1), { id: 'm1' });
  assert.deepEqual(h.calls.at(-1), ['renderGroupEditor']);
  const search = byCls(panel, 'cg-search')[0];
  search.value = 'nl';
  search.oninput();
  assert.deepEqual(byCls(list, 'cg-pick').map((r) => r.dataset.srv), ['a2']);
  // all in: said
  const full = harness({ servers: SERVERS.slice(0, 1) });
  const done = full.ctx.grpServerPanel({ members: [{ id: 'm1' }], search: '', error: '' });
  assert.equal(one(done, 'cg-picker-list').textContent, en('grp.allIn'));
});

/* ------------------------------------ a group card, live ------------------------------------ */

test('gmShares: whole percents summing to 100 — by speed while anything moves, else by bytes; nothing gone through yet: all 0', () => {
  const h = harness();
  const s = (list) => plain(h.ctx.gmShares(list));
  assert.deepEqual(s(cdnRun().members), [39, 36, 25]);
  assert.deepEqual(s([{ downSpeed: 1 }, { downSpeed: 1 }, { downSpeed: 1 }]), [34, 33, 33]);
  assert.deepEqual(s([{ down: 300, up: 100 }, { down: 100 }, null]), [80, 20, 0], 'idle: by the bytes since connecting; a missing one 0');
  assert.deepEqual(s([{}, { downSpeed: 0 }]), [0, 0]);
  assert.deepEqual(s([{ downSpeed: -5, upSpeed: NaN }, { downSpeed: 'x' }]), [0, 0], 'nonsense is nothing');
  for (const list of [[7, 7, 7, 7, 7, 7, 7], [1, 1e9], [3, 5, 11, 13, 17], [0, 0, 1]]) {
    const out = s(list.map((v) => ({ downSpeed: v })));
    assert.equal(out.reduce((a, b) => a + b, 0), 100, JSON.stringify(list));
  }
});

test('a group card, live: its speed and a share bar on its head; a row per config — health, address, speed, delay, share (summing to 100); a dead one red, a missing one grey; none of it while not running', () => {
  const h = harness();
  h.ctx.renderGroups();
  const cdn = card(h, 'g', 'g-cdn');
  const eu = card(h, 'g', 'g-eu');
  const line = one(cdn, 'gm-live');
  // not connected: rows without speeds or shares, nothing on the head
  assert.equal(line.hidden, true);
  assert.deepEqual(rowsOf(cdn).map((r) => [r.className, shown(one(r, 'gm-rate')), shown(one(r, 'gm-share')), shown(one(r, 'gm-ms')), shown(one(r, 'gm-why'))]),
    [['gm-row idle own', false, false, false, false], ['gm-row idle own', false, false, false, false], ['gm-row idle', false, false, false, false]]);
  assert.deepEqual(rowsOf(eu).map((r) => r.className), ['gm-row idle', 'gm-row missing', 'gm-row idle', 'gm-row idle']);
  assert.equal(one(rowsOf(eu)[1], 'gm-why').textContent, en('gm.missingWhy'));
  assert.equal(shown(one(rowsOf(eu)[1], 'gm-why')), true, 'a missing one says so, connected or not');
  // a tick while disconnected changes nothing
  tick(h, [cdnRun()]);
  assert.equal(h.ctx.gmLive.length, 0);
  // connected: the head and the rows
  connect(h, '__advanced__:rp');
  tick(h, [cdnRun(), euRun()]);
  assert.equal(line.hidden, false);
  assert.deepEqual([one(line, 'dn').textContent, one(line, 'up').textContent, line.dir], ['↓ 3.8 KB/s', '↑ 250 B/s', 'ltr']);
  assert.deepEqual(kids(one(line, 'gm-bar')).map((i) => i.style.width), ['39%', '36%', '25%'], 'a segment per config');
  const r = rowsOf(cdn);
  assert.deepEqual(r.map((x) => [x.className, one(x, 'dn').textContent, one(x, 'up').textContent, one(x, 'gm-ms').textContent, byCls(x, 'gm-share')[0].children[1].textContent]),
    [['gm-row own', '↓ 1.5 KB/s', '↑ 100 B/s', '84 ms', '39%'], ['gm-row own', '↓ 1.4 KB/s', '↑ 100 B/s', '97 ms', '36%'], ['gm-row unknown', '↓ 1000 B/s', '↑ 50 B/s', '—', '25%']]);
  assert.equal(r.map((x) => parseInt(byCls(x, 'gm-share')[0].children[1].textContent, 10)).reduce((a, b) => a + b, 0), 100);
  assert.equal(all(r[0], (e) => e.tagName === 'I')[0].style.width, '39%');
  assert.deepEqual([one(r[0], 'gm-dot').title, one(r[2], 'gm-dot').title], [en('gm.alive'), en('gm.unknown')]);
  assert.deepEqual(r.map((x) => [one(x, 'gm-rate').dir, one(x, 'gm-ms').dir, one(x, 'gm-share').dir, all(x, (e) => e.tagName === 'BDI')[0].dir]),
    [['ltr', 'ltr', 'ltr', 'ltr'], ['ltr', 'ltr', 'ltr', 'ltr'], ['ltr', 'ltr', 'ltr', 'ltr']], 'figures and addresses left to right');
  // a member by its place among those here: the gone one between is skipped
  const e = rowsOf(eu);
  assert.deepEqual(e.map((x) => x.className), ['gm-row', 'gm-row missing', 'gm-row', 'gm-row dead']);
  assert.deepEqual(e.map((x) => shown(one(x, 'gm-share')) ? byCls(x, 'gm-share')[0].children[1].textContent : null), ['100%', null, '0%', null]);
  assert.deepEqual([one(e[3], 'gm-why').textContent, shown(one(e[3], 'gm-why')), shown(one(e[3], 'gm-rate')), one(e[3], 'gm-dot').title], [en('gm.dead'), true, false, en('gm.dead')]);
  // the group not running: as before
  assert.equal(one(card(h, 'g', 'g-asia'), 'gm-live').hidden, true);
  assert.deepEqual(rowsOf(card(h, 'g', 'g-asia')).map((x) => x.className), ['gm-row idle']);
  // a tick without `groups` (a config with none): nothing runs
  tick(h, null);
  assert.equal(line.hidden, true);
  assert.deepEqual(rowsOf(cdn).map((x) => x.className), ['gm-row idle own', 'gm-row idle own', 'gm-row idle']);
  // disconnected: gone at once
  tick(h, [cdnRun()]);
  disconnect(h);
  assert.equal(line.hidden, true);
  assert.equal(h.ctx.gmLive.length, 0);
});

test('the payload as given: only groups with a members list, only members that are objects — junk drawn as nothing, never as an empty row', () => {
  const h = harness();
  const n = homeFlow(h);
  connect(h, '__advanced__:rp');
  const run = cdnRun();
  run.members.splice(1, 0, null, 'x', 7);
  tick(h, [run, null, 'junk', { tag: 'out-g-cdn' }, { tag: 'proxy', members: 'no' }]);
  assert.deepEqual(plain(h.ctx.gmLive).map((g) => [g.tag, g.members.length]), [['out-g-cdn', 3]]);
  assert.equal(run.members.length, 6, 'the event itself is left as it came');
  n.cdn.onclick();
  assert.equal(byCls(h.ctx.gmPop.el, 'gm-row').length, 3);
  assert.equal(one(n.cdn, 'gm-health').textContent, '3/3');
});

test('a group that runs in two places (a rule’s target and a chain’s hop) is one card: each member summed over both, alive where either answers', () => {
  const h = harness();
  connect(h, '__advanced__:rp');
  const second = cdnRun('out-chain-c1-h1');
  second.members[2].alive = true;
  second.members[0].alive = false;
  second.members[0].delay = 40;
  h.ctx.gmLive = [cdnRun(), second];
  const agg = plain(h.ctx.gmAggregate('g-cdn'));
  assert.deepEqual(agg.members.map((m) => [m.downSpeed, m.down, m.alive, m.delay]), [[3000, 4000, true, 40], [2800, 4000, true, 97], [2000, 2000, true, null]]);
  assert.deepEqual([agg.downSpeed, agg.upSpeed], [7800, 500]);
  assert.equal(h.ctx.gmAggregate('g-asia'), null);
});

test('a row goes to its server on the Servers page — its pile unfolded, the card lit; a missing one goes nowhere', () => {
  const h = harness({ storage: fakeStorage({ 'irnetfree.foldedGroups': JSON.stringify(['sub:sub-a']) }) });
  h.ctx.renderGroups();
  const eu = card(h, 'g', 'g-eu');
  const [a1, gone] = rowsOf(eu);
  assert.deepEqual([a1.attrs.role, a1.attrs.tabindex, a1.title], ['button', '0', en('gm.goTo')]);
  assert.deepEqual([gone.attrs.role, gone.onclick], [undefined, null]);
  const srvCard = fakeEl('div');
  srvCard.className = 'server-card';
  srvCard.dataset.srvId = 'a1';
  h.page.get('serverList').appendChild(srvCard);
  a1.onclick();
  assert.deepEqual(h.calls.slice(-3), [['view', 'servers'], ['renderServers'], ['flash', 'a1', '']]);
  assert.equal(h.ctx.foldedGroups.has('sub:sub-a'), false, 'unfolded');
  h.calls.length = 0;
  a1.onkeydown({ key: 'Enter', preventDefault() {} });
  assert.deepEqual(h.calls, [['view', 'servers'], ['flash', 'a1', '']], 'Enter as well; the pile already open');
  assert.equal(h.ctx.revealServer('nope'), false);
});

/* ------------------------------------ the flow ------------------------------------ */

test('the matching rule (design §3): a node carries a running group when one of its tags is the group’s, or the group sits on a hop of it (`<tag>-h…`)', () => {
  const h = harness();
  const G = (tag) => ({ tag, groupId: 'g', members: [] });
  const list = ['proxy', 'proxy-h0', 'proxy-h12', 'proxyh1', 'proxy-x', 'out-chain-c1', 'out-chain-c1-h1', 'out-chain-c10', 'out-chain-c1@s1', 'out-g-cdn'].map(G);
  const tags = (ts) => plain(h.ctx.groupsForTags(ts, list)).map((g) => g.tag);
  assert.deepEqual(tags(['proxy', 'out-chain-c1']), ['proxy', 'proxy-h0', 'proxy-h12', 'out-chain-c1', 'out-chain-c1-h1']);
  assert.deepEqual(tags(['out-g-cdn']), ['out-g-cdn']);
  assert.deepEqual(tags(['out-chain-c1@s1']), ['out-chain-c1@s1'], 'through a base: its own tag');
  assert.deepEqual(tags(['direct']), []);
  assert.deepEqual(tags([]), []);
  assert.deepEqual(plain(h.ctx.groupsForTags(['proxy'], [{ tag: 'proxy' }, { tag: 7, members: [] }, null, { tag: 'proxy', members: [] }])).length, 1, 'only what has a tag and members');
  assert.deepEqual(plain(h.ctx.groupsForTags(['proxy'], undefined)), []);
});

/** The home flow on screen, as buildHomeFlow draws its targets: ico, label, traffic. */
function homeFlow(h) {
  const host = h.page.get('trafficPath');
  host.textContent = '';
  const node = (key, label, cls = 'mf-node mf-target lane-p') => {
    const el = fakeEl('div', h.page.document);
    el.className = cls;
    el.dataset.key = key;
    el.title = label + ' — hops';
    for (const [c, txt] of [['mf-ico', '⧉'], ['mf-label', label], ['pr-traffic', '—']]) { const s = fakeEl('span'); s.className = c; s.textContent = txt; el.appendChild(s); }
    el.rect = { left: 100, right: 400, top: 50, bottom: 80, width: 300, height: 30 };
    host.appendChild(el);
    return el;
  };
  const nodes = { direct: node('t:direct', 'Direct'), cdn: node('t:g-cdn', 'CDN x3'), chain: node('t:chain:c1', 'UK → CDN'), base: node('b:s1', 'Base', 'mf-node mf-base') };
  h.ctx.hfModel = {
    targets: [{ key: 't:direct', kind: 'direct', tags: ['direct'], hue: null }, { key: 't:g-cdn', kind: 'group', tags: ['out-g-cdn'], hue: 268 },
      { key: 't:chain:c1', kind: 'chain', tags: ['out-chain-c1'], hue: 38 }],
    bases: [{ key: 'b:s1', kind: 'base', tags: ['base-s1'] }]
  };
  return nodes;
}

test('a node carrying a running group: «alive/total» after its name and a share bar inside its box, keyboard-reachable; the rest untouched — and all of it gone once the group is', () => {
  const h = harness({ lang: 'fa', dir: 'rtl' });
  const n = homeFlow(h);
  connect(h, '__advanced__:rp');
  tick(h, [cdnRun(), euRun('out-chain-c1-h1')]);
  const order = (el) => kids(el).map((c) => c.className);
  assert.deepEqual(order(n.cdn), ['mf-ico', 'mf-label', 'gm-health', 'pr-traffic', 'gm-bar gm-node-bar'], 'the count right after its name, the bar last');
  assert.ok(hasClass(n.cdn, 'is-group'));
  assert.deepEqual([one(n.cdn, 'gm-health').textContent, one(n.cdn, 'gm-health').dir], ['۳/۳', 'ltr'], 'not checked yet is not dead');
  assert.equal(one(n.cdn, 'gm-health').title, '۳ از ۳ کانفیگ جواب می‌دهند');
  assert.equal(one(n.chain, 'gm-health').textContent, '۲/۳', 'a group on the chain’s hop');
  assert.deepEqual(kids(one(n.cdn, 'gm-node-bar')).map((i) => [i.style.width, i.style.background]),
    [['39%', 'hsl(268 72% 64%)'], ['36%', 'hsl(268 72% 50%)'], ['25%', 'hsl(268 72% 38%)']], 'in shades of its lane');
  assert.deepEqual(kids(one(n.chain, 'gm-node-bar')).map((i) => i.style.width), ['100%'], 'a member with no share has no segment');
  assert.equal(one(n.cdn, 'gm-node-bar').attrs['aria-hidden'], 'true');
  assert.deepEqual([n.cdn.attrs.role, n.cdn.attrs.tabindex, n.cdn.attrs['aria-haspopup'], n.cdn.attrs['aria-expanded'], n.cdn.title], ['button', '0', 'dialog', 'false', ''],
    'a button for the keyboard; no tooltip on top of the box');
  assert.equal(hasClass(n.direct, 'is-group') || hasClass(n.base, 'is-group'), false);
  assert.deepEqual(order(n.direct), ['mf-ico', 'mf-label', 'pr-traffic']);
  // the next tick updates in place
  const bar = one(n.cdn, 'gm-node-bar');
  const run = cdnRun();
  run.members[2].alive = false;
  tick(h, [run, euRun('out-chain-c1-h1')]);
  assert.equal(one(n.cdn, 'gm-node-bar'), bar);
  assert.equal(one(n.cdn, 'gm-health').textContent, '۲/۳');
  // not running any more: as it was
  tick(h, null);
  assert.deepEqual(order(n.cdn), ['mf-ico', 'mf-label', 'pr-traffic']);
  assert.deepEqual([hasClass(n.cdn, 'is-group'), n.cdn.attrs.role, n.cdn.attrs.tabindex, n.cdn.attrs['aria-haspopup'], n.cdn.title, n.cdn.onclick],
    [false, undefined, undefined, undefined, 'CDN x3 — hops', null]);
});

test('the routing page’s tree: a node marked only while its profile is the one up; marked, its click pins the box — unmarked, its own click (its editor) is back', () => {
  const h = harness();
  const host = h.page.get('rpFlow');
  const b = fakeEl('button', h.page.document);
  b.className = 'rf-node rf-target to-proxy';
  b.dataset.key = 't:g-cdn';
  for (const [c, txt] of [['rf-ico', '⧉'], ['rf-label', 'CDN x3'], ['rf-traffic', '']]) { const s = fakeEl('span'); s.className = c; s.textContent = txt; b.appendChild(s); }
  b.rect = { left: 10, right: 210, top: 10, bottom: 50, width: 200, height: 40 };
  const own = () => 'editor';
  b.onclick = own;
  host.appendChild(b);
  h.ctx.rfModel = { profileId: 'rp', targets: [{ key: 't:g-cdn', kind: 'group', tags: ['out-g-cdn'] }], bases: [] };
  connect(h, '__advanced__:other');
  tick(h, [cdnRun()]);
  assert.equal(hasClass(b, 'is-group'), false, 'another profile is up');
  h.ctx.rfLive = true;
  tick(h, [cdnRun()]);
  assert.deepEqual(kids(b).map((c) => c.className), ['rf-ico', 'rf-label', 'gm-health', 'rf-traffic', 'gm-bar gm-node-bar']);
  assert.equal(b.attrs.role, undefined, 'a button already');
  b.onclick();
  assert.equal(h.ctx.gmPop.pinned, true);
  assert.equal(h.ctx.gmPop.node, b);
  tick(h, null);
  assert.equal(b.onclick, own, 'its own click back');
  assert.equal(h.ctx.gmPop.el.hidden, true, 'its box closed with it');
});

test('the box: hover opens it, leaving closes it a moment later (not while over the box), a click pins it, a second click, a click outside or Esc closes it, Enter toggles it', () => {
  const h = harness();
  const n = homeFlow(h);
  connect(h, '__advanced__:rp');
  tick(h, [cdnRun(), euRun('out-chain-c1-h1')]);
  n.cdn.fire('mouseenter');
  const p = h.ctx.gmPop;
  assert.equal(p.el.hidden, false);
  assert.equal(p.el.parentNode, h.page.body, 'above the page, never inside the panel');
  assert.deepEqual([p.el.attrs.role, p.el.attrs['aria-label'], p.pinned, n.cdn.attrs['aria-expanded'], hasClass(n.cdn, 'pinned')], ['dialog', 'CDN x3', false, 'true', false]);
  n.cdn.fire('mouseleave');
  p.el.fire('mouseenter');
  h.timers.flush();
  assert.equal(p.el.hidden, false, 'over the box: it stays');
  p.el.fire('mouseleave');
  h.timers.flush();
  assert.equal(p.el.hidden, true, 'off both: closed');
  assert.equal(n.cdn.attrs['aria-expanded'], 'false');
  // click: pinned — leaving does not close it
  n.cdn.fire('mouseenter');
  n.cdn.onclick();
  assert.deepEqual([p.pinned, hasClass(n.cdn, 'pinned')], [true, true]);
  n.cdn.fire('mouseleave');
  h.timers.flush();
  assert.equal(p.el.hidden, false);
  // another node hovered meanwhile: the pinned box stays where it is
  n.chain.fire('mouseenter');
  assert.equal(p.node, n.cdn);
  // a click inside the box or on its node is not "outside"
  h.page.document.fire('click', { target: p.el.children[1] });
  h.page.document.fire('click', { target: n.cdn.children[1] });
  assert.equal(p.el.hidden, false);
  h.page.document.fire('click', { target: h.page.get('somewhereElse') });
  assert.deepEqual([p.el.hidden, hasClass(n.cdn, 'pinned')], [true, false], 'a click outside closes it');
  // a second click on the node closes it
  n.cdn.onclick();
  assert.equal(p.el.hidden, false);
  n.cdn.onclick();
  assert.equal(p.el.hidden, true);
  // Enter toggles, Esc closes and gives the keyboard back to the node
  n.chain.onkeydown({ key: 'Enter', preventDefault() {} });
  assert.deepEqual([p.el.hidden, p.pinned, p.node], [false, true, n.chain]);
  h.page.document.fire('keydown', { key: 'Escape' });
  assert.equal(p.el.hidden, true);
  assert.equal(h.page.document.activeElement, n.chain);
  n.chain.onkeydown({ key: ' ', preventDefault() {} });
  n.chain.onkeydown({ key: 'Enter', preventDefault() {} });
  assert.equal(p.el.hidden, true, 'Space opens, Enter closes');
  h.page.document.fire('keydown', { key: 'Escape' });
  assert.equal(p.el.hidden, true, 'Esc with nothing open: nothing');
});

test('the box’s content: per group its name, strategy and speed, a row per member — name, address, ↓, share; a dead one says why; the foot opens the group; a row goes to its server', () => {
  const h = harness();
  const n = homeFlow(h);
  connect(h, '__advanced__:rp');
  tick(h, [cdnRun(), euRun('out-chain-c1-h1')]);
  n.chain.onclick();
  const p = h.ctx.gmPop;
  const head = one(p.el, 'gm-pop-head');
  assert.deepEqual(kids(head).map((c) => c.textContent), ['⧉ EU mix', en('grp.st.leastPing'), '↓ 2.0 KB/s↑ 20 B/s']);
  assert.equal(one(head, 'gm-live').dir, 'ltr');
  const rows = byCls(p.el, 'gm-row');
  assert.deepEqual(rows.map((r) => [r.className, one(r, 'cn-name').textContent, all(r, (e) => e.tagName === 'BDI')[0].textContent, one(r, 'dn').textContent,
    one(r, 'gm-share').children[1].textContent, shown(one(r, 'gm-why'))]), [
    ['gm-row', 'A-DE', 'a1.sub-a.example:443', '↓ 2.0 KB/s', '100%', false],
    ['gm-row', 'A-NL', 'a2.sub-a.example:8443', '↓ 0 B/s', '0%', false],
    ['gm-row dead', 'B-US', 'b1.sub-b.example:443', '↓ 0 B/s', '0%', true]]);
  assert.equal(one(rows[2], 'gm-why').textContent, en('gm.dead'));
  const foot = one(p.el, 'gm-pop-foot');
  assert.deepEqual(kids(foot).map((c) => c.textContent), [en('gm.popHint'), en('gm.openGroup')]);
  // a tick: figures in place — a row with the keyboard on it keeps it
  const first = rows[0];
  const run = euRun('out-chain-c1-h1');
  run.members[0].downSpeed = 4096;
  tick(h, [cdnRun(), run]);
  assert.equal(byCls(p.el, 'gm-row')[0], first);
  assert.equal(one(first, 'dn').textContent, '↓ 4.0 KB/s');
  // a row: its server on the Servers page, the box closed
  const srvCard = fakeEl('div');
  srvCard.className = 'server-card';
  srvCard.dataset.srvId = 'a1';
  h.page.get('serverList').appendChild(srvCard);
  first.onclick();
  assert.equal(p.el.hidden, true);
  assert.deepEqual(h.calls.slice(-2), [['view', 'servers'], ['flash', 'a1', '']]);
  // the foot: the group's card, on its tab, open
  n.chain.onclick();
  kids(one(p.el, 'gm-pop-foot'))[1].onclick();
  assert.equal(p.el.hidden, true);
  assert.equal(h.ctx.cgTab(), 'groups');
  assert.equal(h.ctx.cgIsOpen('g:g-eu'), true);
  assert.deepEqual(h.calls.slice(-2), [['view', 'chain'], ['flash', null, '.grp-edit']]);
  // a member whose server is gone: a row that goes nowhere
  const lost = euRun('out-chain-c1-h1');
  lost.members[1].id = 'deleted';
  tick(h, [cdnRun(), lost]);
  n.chain.onclick();
  const gone = byCls(p.el, 'gm-row')[1];
  assert.deepEqual([hasClass(gone, 'gone'), gone.attrs.role, gone.attrs.tabindex], [true, undefined, undefined]);
  h.calls.length = 0;
  gone.onclick();
  assert.deepEqual(h.calls, []);
  assert.equal(p.el.hidden, false);
  // two groups on one node: a head each, a way to each card
  h.ctx.gmLive = [cdnRun('out-chain-c1'), euRun('out-chain-c1-h1')];
  h.ctx.gmDecorateFlows();
  assert.deepEqual(byCls(p.el, 'gm-pop-head').map((x) => one(x, 'grp-meta').textContent), [en('grp.st.roundRobin'), en('grp.st.leastPing')]);
  assert.deepEqual(kids(one(p.el, 'gm-pop-foot')).slice(1).map((b) => b.textContent), ['⧉ CDN x3 →', '⧉ EU mix →']);
  assert.equal(p.el.attrs['aria-label'], 'CDN x3 · EU mix');
});

test('the box sits under its node — its reading edge — inside the window; above it when there is no room below; it follows a redrawn flow and closes when its node is gone', () => {
  const h = harness();
  const n = homeFlow(h);
  connect(h, '__advanced__:rp');
  tick(h, [cdnRun()]);
  n.cdn.onclick();
  const p = h.ctx.gmPop;
  p.el.size = [390, 170];
  h.ctx.gmPlace();
  assert.deepEqual([p.el.style.left, p.el.style.top], ['100px', '88px'], 'English: under it, from its left');
  h.page.document.documentElement.dir = 'rtl';
  h.ctx.gmPlace();
  assert.equal(p.el.style.left, '10px', 'Persian: from its right edge');
  n.cdn.rect = { left: 100, right: 400, top: 700, bottom: 730, width: 300, height: 30 };
  h.ctx.gmPlace();
  assert.equal(p.el.style.top, '522px', 'no room below: above');
  h.win.innerWidth = 300;
  n.cdn.rect = { left: 20, right: 290, top: 50, bottom: 80, width: 270, height: 30 };
  p.el.size = [284, 170];
  h.page.document.documentElement.dir = 'ltr';
  h.ctx.gmPlace();
  assert.equal(p.el.style.left, '8px', 'a narrow window: inside it');
  // the window scrolled or resized: placed again (the wiring)
  assert.equal(h.win.listeners.scroll.length, 1);
  assert.equal(h.win.listeners.resize.length, 1);
  // the flow drawn again: the box goes to the new node of the same key, still pinned
  const fresh = homeFlow(h);
  h.ctx.gmDecorateFlows();
  assert.equal(p.node, fresh.cdn);
  assert.deepEqual([hasClass(fresh.cdn, 'pinned'), fresh.cdn.attrs['aria-expanded'], p.el.hidden], [true, 'true', false]);
  // its page left (no box on screen): closed
  fresh.cdn.rect = { left: 0, right: 0, top: 0, bottom: 0, width: 0, height: 0 };
  h.ctx.gmPlace();
  assert.equal(p.el.hidden, true);
  // the flow drawn again without it: closed
  n.cdn.onclick();
  h.page.get('trafficPath').textContent = '';
  h.ctx.gmDecorateFlows();
  assert.equal(p.el.hidden, true);
});

/* ------------------------------------ the wiring and the styles ------------------------------------ */

test('the wiring: the stats event feeds `groups` after the per-tag speeds (which go on without it), a status draws them, the routing tree marks its nodes when drawn', () => {
  assert.match(APP, /if \(s\.per\) applyPathTraffic\(s\.per\);\n[^\n]*\n\s*if \(s\.per\) applyFlowTraffic\(s\.per\);\n[^\n]*\n\s*gmOnStats\(s\);\n\}\);/);
  assert.match(fnSource('renderTrafficPath'), /drawHomeFlowSoon\(\);\n(\s*\/\/[^\n]*\n)*\s*gmOnStatus\(stateStr\);\n\}$/);
  assert.match(fnSource('renderFlowTree'), /applyFlowTraffic\(lastPerOutbound\);\n(\s*\/\/[^\n]*\n)*\s*gmDecorateFlows\(\);\n\s*drawFlowSoon\(\);/);
  assert.match(fnSource('gmOnStats'), /state\.connected && s && Array\.isArray\(s\.groups\)/, 'only while connected, only an array');
  assert.match(fnSource('renderGroups'), /cgPrune\(\);\n\s*cgApplyTab\(\);\n\}$/);
  assert.match(fnSource('openGroupCard'), /showView\('chain'\);\n\s*cgReveal\('groups', 'g:' \+ gid\);/);
  assert.match(fnSource('openChainCard'), /showView\('chain'\);\n\s*cgReveal\('chains', 'c:' \+ cid\);/);
  // the page's choices are read once, in try/catch
  assert.match(APP, /\nconst CG_KEY = 'irnetfree\.chainsGroups';\nconst cgState = loadCgState\(\);\n/);
  assert.match(fnSource('loadCgState'), /try \{[\s\S]*localStorage\.getItem\(CG_KEY\)[\s\S]*\} catch \{ return \{ tab: 'chains', open: \{\}, pick: \{\} \}; \}/);
  assert.match(fnSource('saveCgState'), /try \{ localStorage\.setItem\(CG_KEY, JSON\.stringify\(cgState\)\); \} catch/);
  // a new chain opens, so its hops can be added
  assert.match(APP, /\$\('#btnAddChain'\)\.onclick = \(\) => \{[\s\S]*?cgSetOpen\('c:' \+ id, true\);\n\s*persistChains\(\);\n\};/);
});

test('the styles: the node’s bar sits inside its box (absolute — the box and the flow’s lines stay put), the box is fixed above the page, a folded card is its head, the pick list scrolls on its own; tokens only', () => {
  assert.match(HOME, /\.mf-node\.is-group \{ position: relative; cursor: pointer; \}/);
  assert.match(HOME, /\.mf-node\.is-group > \.gm-node-bar \{ position: absolute; inset-inline: 10px; bottom: 3px; width: auto; height: 3px;/);
  assert.match(ROUTING, /\.rf-node\.is-group > \.gm-node-bar \{ position: absolute;/);
  assert.match(HOME, /\.gm-pop \{\s*position: fixed; z-index: 30;/);
  assert.match(HOME, /\.gm-pop\[hidden\] \{ display: none; \}/);
  assert.match(LISTS, /\.cg-card:not\(\.open\) \.cg-body \{ display: none; \}/);
  assert.match(LISTS, /\.cg-picker-list \{ max-height: 300px; overflow: auto;/);
  assert.match(LISTS, /\.cg-pick\.in \{ opacity: \.45;/);
  assert.match(LISTS, /\.gm-row\.dead \{ background: var\(--dangerSoft\);/);
  assert.match(LISTS, /\.cg-title \.chain-name \{\s*flex: 0 0 auto;/, 'the name input in a column: no 200px tall box');
  // the chevron: along the line folded (either direction), down when open
  assert.match(LISTS, /\[dir="ltr"\] \.cg-chev \{ transform: scaleX\(-1\); \}\n\.cg-card\.open \.cg-chev \{ transform: rotate\(-90deg\); \}/);
  const blocks = [LISTS.slice(LISTS.indexOf('the chains & groups page (v1.28)')), HOME.slice(HOME.indexOf('A node that carries a running group'), HOME.indexOf('@container homepath')),
    ROUTING.slice(ROUTING.indexOf('a node carrying a running group (v1.28)'), ROUTING.indexOf('.rf-node.is-group.pinned') + 80)];
  for (const css of blocks) {
    assert.ok(css.length > 100);
    assert.doesNotMatch(css, /#[0-9a-fA-F]{3,8}\b|rgba?\(/, 'colours are the skin’s tokens');
    assert.doesNotMatch(css, /(?:^|[\s;{])(?:margin|padding)-(?:left|right)\s*:|(?:^|[\s;{])(?:left|right)\s*:/m, 'logical properties only');
  }
});
