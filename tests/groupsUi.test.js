'use strict';
/**
 * v1.27.0 — Groups in the window (.superpowers/sdd/groups/design.md §1, §2 and
 * §5, git-ignored). A group is several saved servers used together as one
 * config. The Chain page becomes «زنجیره و گروه» with a «گروه‌ها» section: a
 * card per group (⧉ its name, «n configs», how it spreads the connections, its
 * delay; ping, connect, edit, delete) and «+ گروه تازه». The editor: the name,
 * the three strategies (roundRobin by default), + Config from the servers only,
 * + Clean IPs on ONE server (a bad line said by its number and not added), a
 * member whose server is gone shown as missing, Save → setGroups in §1's shape.
 * And every picker that offers a server or a chain offers a group too, by its
 * bare id — the home picker, a rule's target and the default, a profile's via
 * and base, the pool, a chain's hops.
 *
 * window.api is a stub with recorded calls: nothing here reaches main. app.js
 * reaches into the DOM at load, so — like warpWgUi.test.js and routingUi.test.js,
 * whose harnesses this follows — its own functions run in a vm over a fake page.
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
/** Out of the vm's realm, so deepEqual compares values and not prototypes. */
const plain = (x) => JSON.parse(JSON.stringify(x));
const tick = () => new Promise((r) => setImmediate(r));

/* ------------------------------------ a fake page ------------------------------------ */

const camel = (k) => k.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
const hasClass = (el, cls) => String(el.className || '').split(/\s+/).includes(cls);
/** One compound selector (tag, #id, .class, [attr], [attr="v"]). */
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

/**
 * Just enough of an element: children (text as strings) with parents, classes,
 * attributes (data-* in dataset), a selector engine over the real children —
 * and, for a node built from an innerHTML template, its named parts (looked up
 * by the classes the template carries), as in routingUi.test.js.
 */
function fakeEl(tag) {
  const el = {
    tagName: String(tag || 'div').toUpperCase(), children: [], parentNode: null, attrs: {}, dataset: {}, style: {},
    hidden: false, disabled: false, selected: false, title: '', className: '', type: '', id: '', dir: '', value: '', _text: '',
    checked: false, onclick: null, onchange: null, oninput: null, html: '', parts: {}, listeners: {},
    get textContent() { return el._text + el.children.map((c) => (typeof c === 'string' ? c : c.textContent)).join(''); },
    set textContent(v) { el._text = String(v == null ? '' : v); el.children = []; },
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
    appendChild(c) { el.children.push(c); if (c && typeof c === 'object') c.parentNode = el; return c; },
    append(...cs) { cs.forEach((c) => (c && typeof c === 'object' ? el.appendChild(c) : el.children.push(String(c)))); },
    remove() { if (el.parentNode) el.parentNode.children = el.parentNode.children.filter((x) => x !== el); },
    setAttribute(k, v) {
      el.attrs[k] = String(v);
      if (k === 'disabled') el.disabled = true;
      if (k === 'selected') el.selected = true;
      // the attributes a browser reflects into the properties app.js reads
      if (['id', 'dir', 'title', 'type', 'value'].includes(k)) el[k] = String(v);
      if (k.startsWith('data-')) el.dataset[camel(k.slice(5))] = String(v);
    },
    getAttribute(k) { return k in el.attrs ? el.attrs[k] : null; },
    addEventListener(type, fn) { el.listeners[type] = fn; },
    scrollIntoView() {}, focus() { el.focused = true; },
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
        if (!el.parts[sel]) { const p = fakeEl('span'); p.className = m[1]; p.parentNode = el; el.parts[sel] = p; }
        return el.parts[sel];
      }
      return null;
    },
    set innerHTML(v) { el.html = String(v); el.children = []; el.parts = {}; el._text = ''; },
    get innerHTML() { return el.html; }
  };
  return el;
}
/** Every element under `el` that `pred` says yes to. */
function all(el, pred, out = []) {
  for (const c of kids(el)) { if (pred(c)) out.push(c); all(c, pred, out); }
  return out;
}
const one = (el, pred, what) => { const f = all(el, pred); assert.ok(f.length, `nothing found: ${what}`); return f[0]; };
const byId = (el, id) => one(el, (e) => e.id === id, '#' + id);
const byCls = (el, cls) => all(el, (e) => hasClass(e, cls));

/** A page: elements by id, `$`/`$$` as app.js uses them, document.createElement. */
function fakePage() {
  const els = new Map();
  const get = (id) => { if (!els.has(id)) { const e = fakeEl('div'); e.id = id; els.set(id, e); } return els.get(id); };
  const $ = (sel) => { const m = String(sel).match(/^#([\w-]+)$/); return m ? get(m[1]) : null; };
  const $$ = (sel) => { const m = String(sel).match(/^#([\w-]+)\s+(.+)$/); return m ? get(m[1]).querySelectorAll(m[2]) : []; };
  return { get, $, $$, document: { createElement: fakeEl, activeElement: null, documentElement: { dir: 'ltr' } } };
}

/* ------------------------------------ the store ------------------------------------ */

const SERVERS = [
  { id: 's1', name: 'DE', protocol: 'vless', address: 'de.example.com', port: 443 },
  { id: 's2', name: 'CDN', protocol: 'vless', address: 'cdn.example.org', port: 443 },
  { id: 's3', name: 'Office WG', protocol: 'wireguard', address: '10.0.0.1', port: 51820 }
];
const GROUPS = [
  { id: 'grp-a', name: 'Fast', strategy: 'roundRobin', members: [{ id: 's2', address: '104.16.1.1' }, { id: 's2', address: '2606:4700::6810:1', port: 2053 }, { id: 's1' }] },
  { id: 'grp-gone', name: 'Old', strategy: 'leastPing', members: [{ id: 'deleted-1' }, { id: 'deleted-2', address: '1.1.1.1' }] }
];
const CHAINS = [{ id: 'c1', name: 'DE→WG', members: ['s1', 's3'] }];
const PRELUDE = constSource('ADV_ID') + constSource('POOL_ID') + constSource('TARGET_BASE') + constSource('GROUP_STRATEGIES');

/* ------------------------------------ the groups harness ------------------------------------ */

const GROUP_FNS = ['srvById', 'grpMember', 'normalizeUiGroup', 'loadGroups', 'newGroupId', 'grpById', 'grpCountText', 'grpLive', 'grpAddrText',
  'grpMemberNames', 'grpConnText', 'renderGroups', 'groupCard', 'openGroupCard', 'afterGroupsChanged', 'persistGroups', 'deleteGroup', 'grpShown',
  'openGroupEditor', 'closeGroupEditor', 'grpIsV4', 'grpIsV6', 'grpIsHost', 'grpParseAddress', 'grpParseAddresses', 'grpAddIps', 'grpNameNode',
  'grpStrategyNode', 'grpMembersNode', 'grpServerPanel', 'grpIpPanel', 'renderGroupEditor', 'saveGroupEditor', 'edNode', 'appendSome', 'richLine', 'warpNum',
  'pingResultLabel', 'fmtMs', 'pingClass', 'connectGlyph'];

function harness({ lang = 'en', groups = GROUPS, servers = SERVERS, chains = CHAINS, setGroups, api = {}, confirm = () => true } = {}) {
  const page = fakePage();
  page.get('grpModal').hidden = true;
  const calls = [];
  const sent = [];
  const state = { servers: plain(servers), groups: plain(groups), chains: plain(chains), pings: {}, selectedServerId: null, connecting: false };
  const ctx = vm.createContext({
    state, t: (k) => TR(lang, k), $: page.$, $$: page.$$, document: page.document,
    toast: (msg, kind) => calls.push(['toast', msg, kind || '']),
    usageLabel: () => '',
    pingServer: (id) => calls.push(['ping', id]), connect: (id) => calls.push(['connect', id]),
    showView: (v) => calls.push(['view', v]), flashInto: (el, f) => calls.push(['flash', el && el.dataset.groupId, f]),
    renderChains: () => calls.push(['renderChains']), renderPicker: () => calls.push(['renderPicker']), renderAdvanced: () => calls.push(['renderAdvanced']),
    renderPool: () => calls.push(['renderPool']), refreshConnLabels: () => calls.push(['refreshConnLabels']),
    window: {
      i18n: { lang },
      confirm: (msg) => { calls.push(['confirm', msg]); return confirm(msg); },
      api: Object.assign({
        setGroups: async (list) => { sent.push(plain(list)); return setGroups ? setGroups(list) : plain(list); },
        setChains: async (list) => { calls.push(['setChains', plain(list)]); return list; }
      }, api)
    },
    URL, String, Array, Object, Number, Math, Date, JSON, Set, Promise, Error
  });
  vm.runInContext(PRELUDE + 'let grpForm = null;\n' + GROUP_FNS.map(fnSource).join('\n') + '\nfunction form() { return grpForm; }', ctx);
  const body = () => page.get('grpBody');
  const foot = () => page.get('grpFoot');
  const type = (id, value) => { const i = byId(body(), id); i.value = value; i.oninput(); };
  return { ctx, page, state, calls, sent, body, foot, type, form: () => ctx.form(), lang };
}

/* ------------------------------------ strings ------------------------------------ */

const GRP_KEYS = [...new Set([
  ...[...APP.matchAll(/'(grp\.[A-Za-z.]*[A-Za-z])'/g)].map((m) => m[1]),
  ...[...HTML.matchAll(/data-i18n(?:-ph|-title)?="(grp\.[^"]+)"/g)].map((m) => m[1]),
  ...['roundRobin', 'leastPing', 'random'].flatMap((s) => ['grp.st.' + s, 'grp.stLine.' + s]),
  'chain.sec', 'chain.title', 'nav.chain'
])];

test('v1.27 strings: once in fa and once in en, one clean literal each (no straight apostrophe), English in en, Persian in fa, the slots the code fills in both', () => {
  assert.ok(GRP_KEYS.length >= 45, `only ${GRP_KEYS.length} keys found`);
  for (const key of GRP_KEYS) {
    assert.equal(I18N.split(`'${key}':`).length - 1, 2, `'${key}' is not defined exactly once in each of fa and en`);
    for (const line of I18N.split('\n').filter((l) => l.includes(`'${key}':`))) {
      // a line may hold two keys ('chain.title': …, 'chain.enable': …): read this key’s literal only
      const m = line.slice(line.indexOf(`'${key}':`)).match(/^'[^']+':\s*'((?:[^'\\]|\\.)*)'/);
      assert.ok(m, `${key}: not a single clean string literal — a straight ' inside? ${line.trim().slice(0, 90)}`);
      assert.ok(!/\\'/.test(m[1]), `${key}: use ’ and not an escaped '`);
    }
    assert.ok(fa(key).trim() && en(key).trim(), key);
    assert.doesNotMatch(en(key), /[؀-ۿ]/, `en '${key}' is Persian`);
    assert.notEqual(fa(key), en(key), `${key}: fa is the English text`);
  }
  for (const [key, slots] of [['grp.count', ['{n}']], ['grp.newName', ['{n}']], ['grp.ipsRead', ['{n}']], ['grp.ipsBadLine', ['{line}']],
    ['grp.ipsAdded', ['{n}']], ['grp.ipsDup', ['{n}']], ['grp.ipsNotAdded', ['{lines}']], ['grp.err.save', ['{msg}']], ['grp.confirmDelete', ['{name}']],
    ['grp.ipsHint', ['{forms}']]]) {
    for (const s of slots) { assert.ok(fa(key).includes(s), `fa ${key} ${s}`); assert.ok(en(key).includes(s), `en ${key} ${s}`); }
  }
  // the owner’s words (design §5 and the brief), verbatim
  assert.deepEqual([fa('nav.chain'), fa('chain.title'), en('nav.chain'), en('chain.title')], ['زنجیره و گروه', 'زنجیره و گروه', 'Chains & groups', 'Chains & groups']);
  assert.deepEqual([fa('grp.title'), fa('grp.new'), fa('grp.addServer'), fa('grp.addIps')], ['گروه‌ها', '+ گروه تازه', '+ کانفیگ', '+ IP تمیز']);
  assert.equal(`${fa('grp.st.roundRobin')} — ${fa('grp.stLine.roundRobin')}`, 'پخش بین همه — سرعت جمعی: هر اتصال تازه از یکی');
  assert.equal(`${fa('grp.st.leastPing')} — ${fa('grp.stLine.leastPing')}`, 'سریع‌ترین — همه از کم‌تأخیرترین سالم، بقیه جایگزین');
  assert.equal(fa('grp.st.random'), 'تصادفی');
  assert.equal(fa('grp.countOne'), '۱ کانفیگ', 'Persian digits in Persian');
  // the hint under the members: at least one; the same exit for speed; a login tied to an IP
  for (const k of ['grp.hint']) {
    assert.match(en(k), /at least one/);
    assert.match(en(k), /same exit IP/);
    assert.match(en(k), /clean IPs/);
    assert.match(en(k), /sign in again/);
    assert.match(fa(k), /دست‌کم یک کانفیگ/);
    assert.match(fa(k), /IP تمیز/);
  }
});

/* ------------------------------------ the markup ------------------------------------ */

test('the markup: the Chain page is «زنجیره و گروه», its groups section after the chains, and the editor dialog starts hidden', () => {
  const view = HTML.slice(HTML.indexOf('<section class="view" id="view-chain">'), HTML.indexOf('</section>', HTML.indexOf('id="view-chain"')));
  assert.match(view, /<h2 data-i18n="chain\.title">زنجیره و گروه<\/h2>/);
  assert.match(HTML, /<span data-i18n="nav\.chain">زنجیره و گروه<\/span>/);
  for (const id of ['groupsSection', 'btnAddGroup', 'groupsWrap', 'groupsEmpty']) assert.ok(view.includes(`id="${id}"`), `#${id} inside #view-chain`);
  assert.ok(view.indexOf('id="chainsWrap"') < view.indexOf('id="groupsSection"'), 'the groups below the chains');
  assert.match(view, /<span class="sec-label" data-i18n="grp\.title">گروه‌ها<\/span>/);
  assert.match(view, /id="btnAddGroup" data-i18n="grp\.new">\+ گروه تازه<\/button>/);
  assert.match(HTML, /<div class="modal-overlay" id="grpModal" hidden>\s*<div class="modal grp-modal" role="dialog" aria-modal="true" aria-labelledby="grpTitle">/);
  for (const id of ['grpTitle', 'grpClose', 'grpBody', 'grpFoot']) assert.ok(HTML.includes(`id="${id}"`), `#${id}`);
  // the wiring
  assert.match(APP, /\$\('#btnAddGroup'\)\.onclick = \(\) => openGroupEditor\(null\);/);
  assert.match(APP, /\$\('#grpClose'\)\.onclick = closeGroupEditor;/);
  assert.match(fnSource('renderChains'), /\n {2}renderGroups\(\);\n\}$/, 'every redraw of the chains draws the groups (a server gone shows there too)');
  assert.match(fnSource('setLang'), /if \(grpShown\(\)\) renderGroupEditor\(\);/);
});

/* ------------------------------------ a group is a target ------------------------------------ */

test('a group id is a target like a server id: srvById gives the record main makes (protocol group, its size) while one of its members is here; with none it is gone', () => {
  const h = harness();
  assert.deepEqual(plain(h.ctx.srvById('grp-a')), { id: 'grp-a', name: 'Fast', protocol: 'group', address: '', port: 0, group: { strategy: 'roundRobin', size: 3 } });
  assert.equal(h.ctx.srvById('grp-gone'), undefined, 'no member left: no longer exists');
  assert.equal(h.ctx.srvById('s2').name, 'CDN', 'a server is still itself');
  assert.equal(h.ctx.srvById('nope'), undefined);
  h.state.servers = h.state.servers.filter((s) => s.id !== 's2');
  assert.equal(h.ctx.srvById('grp-a').group.size, 1, 'a member that is gone is skipped, the group stays a group');
  h.state.groups = undefined;
  assert.equal(h.ctx.srvById('grp-a'), undefined, 'a back end without groups');
});

test('loadGroups and normalizeUiGroup: init’s data, else the bridge, else none; §1’s shape and nothing else', async () => {
  const h = harness();
  const raw = [{ id: 'grp-x', name: 'X', strategy: 'weird', extra: 1, members: [{ id: 's1', port: 8443 }, { id: 's2', address: ' 1.2.3.4 ', port: '2053', x: 1 }, { id: 's2', address: 'h.example', port: 70000 }, null, {}] }, null, { name: 'no id' }];
  assert.deepEqual(plain(await h.ctx.loadGroups({ groups: raw })), [{ id: 'grp-x', name: 'X', strategy: 'roundRobin',
    members: [{ id: 's1' }, { id: 's2', address: '1.2.3.4', port: 2053 }, { id: 's2', address: 'h.example' }] }], 'a port only with its address, and only 1-65535');
  h.ctx.window.api.listGroups = async () => [{ id: 'grp-y', name: 'Y', strategy: 'random', members: [] }];
  assert.deepEqual(plain(await h.ctx.loadGroups({})), [{ id: 'grp-y', name: 'Y', strategy: 'random', members: [] }], 'asked when init did not say');
  h.ctx.window.api.listGroups = async () => { throw new Error('unknown channel: groups:list'); };
  assert.deepEqual(plain(await h.ctx.loadGroups({})), []);
  delete h.ctx.window.api.listGroups;
  assert.deepEqual(plain(await h.ctx.loadGroups(null)), []);
  for (const s of ['roundRobin', 'leastPing', 'random']) assert.equal(h.ctx.normalizeUiGroup({ id: 'g', strategy: s }).strategy, s);
});

/* ------------------------------------ the section and the cards ------------------------------------ */

test('the section: one card per group — ⧉ name, «n configs · strategy», its delay, its configs with the address each is dialled at; a gone config said so; a group with none left cannot be connected', () => {
  const h = harness();
  h.state.pings['grp-a'] = { tcp: { ok: false, na: true }, real: { ok: true, ms: 182 }, upload: { ok: true, ms: 640 } };
  h.ctx.renderGroups();
  assert.equal(h.page.get('groupsSection').hidden, false);
  assert.equal(h.page.get('groupsEmpty').hidden, true);
  const cards = byCls(h.page.get('groupsWrap'), 'grp-card');
  assert.deepEqual(cards.map((c) => c.dataset.groupId), ['grp-a', 'grp-gone']);
  const [a, gone] = cards;
  assert.ok(hasClass(a, 'card') && hasClass(a, 'chain-card'), 'built like a chain card');
  assert.equal(one(a, (e) => hasClass(e, 'proto-group'), 'badge').textContent, '⧉');
  assert.equal(byCls(a, 'grp-name')[0].textContent, 'Fast');
  assert.equal(byCls(a, 'grp-meta')[0].textContent, `3 configs · ${en('grp.st.roundRobin')}`);
  // the delay as a chain card shows it: the real one and the upload (a group has no TCP handshake of its own)
  assert.deepEqual(byCls(a, 'chain-ping').map((e) => [e.dataset.pingReal || e.dataset.pingUp, e.textContent, e.className]),
    [['grp-a', '182', 'chain-ping ping-good'], ['grp-a', '640', 'chain-ping ping-bad']]);
  assert.equal(byCls(a, 'chain-ping')[0].dataset.pbase, 'chain-ping', 'applyPingDisplays rewrites it in place');
  // its configs: the server's name, and its own address when it has one, else the server's
  assert.deepEqual(byCls(a, 'grp-chip').map((c) => [byCls(c, 'cn-name')[0].textContent, byCls(c, 'grp-addr')[0].textContent, hasClass(c, 'own')]),
    [['CDN', '104.16.1.1', true], ['CDN', '[2606:4700::6810:1]:2053', true], ['DE', 'de.example.com:443', false]]);
  assert.equal(byCls(a, 'grp-addr')[0].dir, 'ltr');
  assert.equal(one(a, (e) => hasClass(e, 'ch-connect'), '▶').disabled, false);
  // a group whose servers are all gone: said, each config missing, nothing to connect
  assert.ok(hasClass(gone, 'grp-dead'));
  assert.equal(byCls(gone, 'grp-meta')[0].textContent, `0 configs · ${en('grp.st.leastPing')}`);
  assert.deepEqual(byCls(gone, 'grp-chip').map((c) => [hasClass(c, 'missing'), byCls(c, 'cn-name')[0].textContent]), [[true, en('grp.missing')], [true, en('grp.missing')]]);
  assert.equal(byCls(gone, 'grp-addr')[0].textContent, '1.1.1.1', 'a gone config with its own address keeps showing it');
  assert.equal(one(gone, (e) => hasClass(e, 'ch-connect'), '▶').disabled, true);
  assert.equal(one(gone, (e) => hasClass(e, 'grp-ping'), '⚡').disabled, true);
  assert.equal(one(gone, (e) => hasClass(e, 'chain-min'), 'the warning').textContent, en('grp.noneLive'));
  // Persian: the count in Persian digits, the strategy in Persian
  const p = harness({ lang: 'fa' });
  p.ctx.renderGroups();
  assert.equal(byCls(byCls(p.page.get('groupsWrap'), 'grp-card')[0], 'grp-meta')[0].textContent, `۳ کانفیگ · ${fa('grp.st.roundRobin')}`);
  // none: the empty line; a back end that cannot store groups: no section at all
  const none = harness({ groups: [] });
  none.ctx.renderGroups();
  assert.equal(none.page.get('groupsEmpty').hidden, false);
  assert.equal(byCls(none.page.get('groupsWrap'), 'grp-card').length, 0);
  const old = harness({ api: { setGroups: undefined } });
  old.ctx.renderGroups();
  assert.equal(old.page.get('groupsSection').hidden, true);
});

test('the card’s buttons: ⚡ tests it, ▶ connects it (selecting it, as a chain card does), ✎ opens the editor on it, 🗑 asks first — then the list goes without it and the chains that held it drop it', async () => {
  const h = harness({ chains: [...CHAINS, { id: 'c2', name: 'via group', members: ['grp-a', 's3'] }] });
  h.ctx.renderGroups();
  const card = byCls(h.page.get('groupsWrap'), 'grp-card')[0];
  const btn = (cls) => one(card, (e) => e.tagName === 'BUTTON' && hasClass(e, cls), cls);
  btn('grp-ping').onclick();
  btn('ch-connect').onclick();
  assert.deepEqual(h.calls.splice(0), [['ping', 'grp-a'], ['connect', 'grp-a']]);
  assert.equal(btn('ch-connect').textContent, '▶');
  assert.equal(btn('grp-edit').title, en('grp.edit'));
  btn('grp-edit').onclick();
  assert.equal(h.page.get('grpModal').hidden, false);
  assert.equal(h.form().id, 'grp-a');
  assert.equal(h.page.get('grpTitle').textContent, en('grp.editTitle'));
  h.ctx.closeGroupEditor();
  // delete: asked, refused — nothing happens
  const keep = harness({ confirm: () => false });
  assert.equal(await keep.ctx.deleteGroup('grp-a'), false);
  assert.equal(keep.sent.length, 0);
  // asked, yes: the chain drops it, the list is saved without it, the selection goes
  h.state.selectedServerId = 'grp-a';
  h.state.pings['grp-a'] = { real: { ok: true, ms: 1 } };
  btn('grp-del').onclick();
  await tick(); await tick();
  assert.deepEqual(h.calls.find((c) => c[0] === 'confirm'), ['confirm', 'Delete the group “Fast”?']);
  assert.deepEqual(h.calls.find((c) => c[0] === 'setChains')[1].map((c) => c.members), [['s1', 's3'], ['s3']]);
  assert.deepEqual(h.sent, [[GROUPS[1]]]);
  assert.deepEqual(plain(h.state.groups).map((g) => g.id), ['grp-gone']);
  assert.equal(h.state.selectedServerId, null, 'keepSelectionValid takes it from here');
  assert.equal(h.state.pings['grp-a'], undefined);
  assert.ok(h.calls.some((c) => c[0] === 'toast' && c[1] === en('grp.deleted')));
  // the flow tree’s click on a group: its card, flashed
  h.ctx.openGroupCard('grp-gone');
  assert.deepEqual(h.calls.slice(-2), [['view', 'chain'], ['flash', 'grp-gone', '.grp-edit']]);
});

/* ------------------------------------ the editor ------------------------------------ */

test('the editor, new: a name, roundRobin by default and one plain line for each strategy; nothing is saved without a config', async () => {
  const h = harness();
  h.ctx.openGroupEditor(null);
  assert.equal(h.page.get('grpModal').hidden, false);
  assert.equal(h.page.get('grpTitle').textContent, en('grp.newTitle'));
  assert.equal(byId(h.body(), 'grp-name').value, 'Group 3');
  const strats = all(h.body(), (e) => e.dataset.grp && e.dataset.grp.startsWith('strategy:'));
  assert.deepEqual(strats.map((b) => [b.dataset.grp, hasClass(b, 'on'), b.attrs['aria-checked'], b.children[0].textContent, b.children[1].textContent]), [
    ['strategy:roundRobin', true, 'true', en('grp.st.roundRobin'), en('grp.stLine.roundRobin')],
    ['strategy:leastPing', false, 'false', en('grp.st.leastPing'), en('grp.stLine.leastPing')],
    ['strategy:random', false, 'false', en('grp.st.random'), en('grp.stLine.random')]]);
  assert.equal(one(h.body(), (e) => e.attrs.role === 'radiogroup', 'the group').attrs['aria-label'], en('grp.strategy'));
  strats[1].onclick();
  assert.equal(h.form().strategy, 'leastPing');
  assert.equal(hasClass(all(h.body(), (e) => e.dataset.grp === 'strategy:leastPing')[0], 'on'), true, 'drawn again with the choice');
  // the configs: none yet, the hint under them
  assert.equal(byCls(h.body(), 'grp-members')[0].textContent, en('grp.noMembers'));
  assert.ok(byCls(h.body(), 'grp-hint')[0].textContent === en('grp.hint'));
  // Save with none: said, nothing sent, the dialog stays
  h.type('grp-name', 'Mine');
  assert.equal(await h.ctx.saveGroupEditor(), false);
  assert.equal(h.sent.length, 0);
  assert.equal(one(h.body(), (e) => e.attrs.role === 'alert', 'the reason').textContent, en('grp.err.noMember'));
  assert.equal(h.page.get('grpModal').hidden, false);
  assert.equal(byId(h.body(), 'grp-name').value, 'Mine', 'the name kept');
  // Persian: the default name in Persian digits; the foot’s two buttons
  const p = harness({ lang: 'fa', groups: [] });
  p.ctx.openGroupEditor(null);
  assert.equal(byId(p.body(), 'grp-name').value, 'گروه ۱');
  assert.deepEqual(kids(p.foot()).map((b) => [b.id, b.textContent]), [['grpSave', fa('grp.save')], ['grpCancel', fa('btn.cancel')]]);
  byId(p.foot(), 'grpCancel').onclick();
  assert.equal(p.page.get('grpModal').hidden, true);
  assert.equal(p.form(), null);
});

test('+ Config offers servers only — never a chain or a group — searchable; one already in it as itself is not offered again', () => {
  const h = harness();
  h.ctx.openGroupEditor(null);
  byId(h.body(), 'grpAddServer').onclick();
  assert.equal(byId(h.body(), 'grpAddServer').attrs['aria-expanded'], 'true');
  const offered = () => all(h.body(), (e) => hasClass(e, 'pool-item')).map((b) => b.dataset.srv);
  assert.deepEqual(offered(), ['s1', 's2', 's3'], 'servers only: no c1, no grp-a');
  assert.equal(all(h.body(), (e) => hasClass(e, 'pool-item'))[0].textContent, 'vlessDE+ ' + en('grp.addOne'));
  all(h.body(), (e) => e.dataset.srv === 's2')[0].onclick();
  assert.deepEqual(plain(h.form().members), [{ id: 's2' }]);
  assert.deepEqual(offered(), ['s1', 's3'], 'the one added is not offered again');
  h.type('grp-search', 'office');
  assert.deepEqual(offered(), ['s3']);
  h.type('grp-search', '');
  all(h.body(), (e) => e.dataset.srv === 's1')[0].onclick();
  all(h.body(), (e) => e.dataset.srv === 's3')[0].onclick();
  assert.deepEqual(offered(), []);
  assert.equal(one(h.body(), (e) => hasClass(e, 'grp-pool'), 'the list').textContent, en('grp.allIn'));
  // the rows: each its server’s name and address, a remove each
  const rows = byCls(h.body(), 'grp-member');
  assert.deepEqual(rows.map((r) => [byCls(r, 'grp-mname')[0].textContent, byCls(r, 'grp-addr')[0].textContent]),
    [['CDN', 'cdn.example.org:443'], ['DE', 'de.example.com:443'], ['Office WG', '10.0.0.1:51820']]);
  one(rows[1], (e) => hasClass(e, 'cn-remove'), '✕').onclick();
  assert.deepEqual(plain(h.form().members), [{ id: 's2' }, { id: 's3' }]);
  assert.deepEqual(offered(), ['s1'], 'removed: offered again');
});

test('grpParseAddress: ip, ip:port, [v6]:port, a bare v6, a host name (and :port) — anything else is not an address', () => {
  const h = harness();
  const read = (s) => plain(h.ctx.grpParseAddress(s));
  for (const [line, want] of [
    ['104.16.1.1', { address: '104.16.1.1' }], [' 104.17.2.2:2053 ', { address: '104.17.2.2', port: 2053 }],
    ['[2606:4700::1]:443', { address: '2606:4700::1', port: 443 }], ['[2606:4700::1]', { address: '2606:4700::1' }],
    ['2606:4700::6810:85e5', { address: '2606:4700::6810:85e5' }], ['::ffff:1.2.3.4', { address: '::ffff:1.2.3.4' }],
    ['cdn.example.com', { address: 'cdn.example.com' }], ['cdn.example.com:8443', { address: 'cdn.example.com', port: 8443 }],
    ['xn--mgbai9azgqp6j.xn--mgbai9a', { address: 'xn--mgbai9azgqp6j.xn--mgbai9a' }]
  ]) assert.deepEqual(read(line), want, line);
  for (const bad of ['1.2.3.999', '1.2.3', '1.2.3.4:0', '1.2.3.4:70000', '1.2.3.4:', '[2606:4700::1]:99999', '[1.2.3.4]:443', '2606:4700:::1',
    'not an ip', 'example', '-bad.example.com', 'a..b', 'http://1.2.3.4', '1.2.3.4 443', '[::1', 'host:port']) {
    assert.equal(h.ctx.grpParseAddress(bad), false, bad);
  }
  assert.equal(h.ctx.grpParseAddress('   '), null, 'a blank line is no line');
  assert.deepEqual(plain(h.ctx.grpParseAddresses('1.1.1.1\n\nbad!\r\n[::1]:53')), { items: [{ line: 1, address: '1.1.1.1' }, { line: 4, address: '::1', port: 53 }], bad: [3] },
    'blank lines count, as the user sees them');
});

test('+ Clean IPs: ONE server, an address a line — read back as typed, a bad line by its number and not added; what was not read stays to be fixed; the same one twice is not added', () => {
  const h = harness({ lang: 'fa' });
  h.ctx.openGroupEditor(null);
  byId(h.body(), 'grpAddIps').onclick();
  const sel = byId(h.body(), 'grp-ipServer');
  assert.equal(sel.tagName, 'SELECT');
  assert.deepEqual(kids(sel).map((o) => [o.attrs.value, o.textContent]), [['s1', 'DE'], ['s2', 'CDN'], ['s3', 'Office WG']], 'servers only');
  assert.equal(sel.value, 's1', 'the first server when the group has none yet');
  sel.value = 's2';
  sel.onchange();
  const ta = byId(h.body(), 'grp-ips');
  assert.equal(ta.tagName, 'TEXTAREA');
  assert.equal(ta.dir, 'ltr');
  assert.ok(ta.attrs.placeholder.split('\n').length >= 3, 'one a line');
  const chips = () => kids(one(h.body(), (e) => hasClass(e, 'grp-ipread'), 'the read-back')).map((c) => [c.className, c.textContent]);
  h.type('grp-ips', '104.16.1.1\n104.17.2.2:2053\nnot an ip!\n\n[2606:4700::1]:443\ncdn.example.com\n1.2.3.999');
  assert.deepEqual(chips(), [['info', '۴ آدرس'], ['bad', 'خط ۳ خوانده نشد'], ['bad', 'خط ۷ خوانده نشد']]);
  byId(h.body(), 'grpIpsAdd').onclick();
  assert.deepEqual(plain(h.form().members), [
    { id: 's2', address: '104.16.1.1' }, { id: 's2', address: '104.17.2.2', port: 2053 },
    { id: 's2', address: '2606:4700::1', port: 443 }, { id: 's2', address: 'cdn.example.com' }], 'one member a line, on the server picked');
  assert.equal(byId(h.body(), 'grp-ips').value, 'not an ip!\n1.2.3.999', 'what was not read stays in the box');
  assert.deepEqual(chips(), [['bad', 'خط ۱ خوانده نشد'], ['bad', 'خط ۲ خوانده نشد']]);
  assert.equal(one(h.body(), (e) => hasClass(e, 'grp-ipnote'), 'the note').textContent, '۴ آدرس اضافه شد. این خط‌ها اضافه نشدند: ۳، ۷');
  assert.equal(byId(h.body(), 'grp-ipServer').value, 's2', 'the server stays picked');
  // the rows: the server’s name and each one’s own address
  assert.deepEqual(byCls(h.body(), 'grp-member').map((r) => [byCls(r, 'grp-mname')[0].textContent, byCls(r, 'grp-addr')[0].textContent, hasClass(r, 'own')]), [
    ['CDN', '104.16.1.1', true], ['CDN', '104.17.2.2:2053', true], ['CDN', '[2606:4700::1]:443', true], ['CDN', 'cdn.example.com', true]]);
  // the same addresses again: not added twice
  h.type('grp-ips', '104.16.1.1\n104.17.2.2:2053\n104.17.2.2:443');
  byId(h.body(), 'grpIpsAdd').onclick();
  assert.equal(h.form().members.length, 5);
  assert.deepEqual(plain(h.form().members[4]), { id: 's2', address: '104.17.2.2', port: 443 }, 'another port is another member');
  assert.equal(one(h.body(), (e) => hasClass(e, 'grp-ipnote'), 'note').textContent, '۱ آدرس اضافه شد. ۲ آدرس از قبل در گروه بود.');
  assert.equal(byId(h.body(), 'grp-ips').value, '');
  // in English, a group with members already: the first member’s server is the default
  const e = harness();
  e.ctx.openGroupEditor('grp-a');
  byId(e.body(), 'grpAddIps').onclick();
  assert.equal(byId(e.body(), 'grp-ipServer').value, 's2');
  assert.deepEqual(kids(byId(e.body(), 'grp-ipServer')).filter((o) => o.selected).map((o) => o.attrs.value), ['s2']);
  e.type('grp-ips', 'x\n1.1.1.1\ny');
  assert.deepEqual(kids(one(e.body(), (x) => hasClass(x, 'grp-ipread'), 'read')).map((c) => c.textContent), ['Addresses read: 1', 'Line 1 not read', 'Line 3 not read']);
  byId(e.body(), 'grpIpsAdd').onclick();
  assert.equal(one(e.body(), (x) => hasClass(x, 'grp-ipnote'), 'note').textContent, 'Added: 1. Not added, lines: 1, 3');
  // the forms in the hint stay left-to-right inside a Persian line
  const hint = one(h.body(), (x) => x.tagName === 'P' && x.textContent.includes('[v6]:port'), 'the hint');
  assert.deepEqual(plain(one(hint, (x) => x.tagName === 'BDI', 'bdi').attrs), { dir: 'ltr' });
  assert.equal(hint.textContent, fa('grp.ipsHint').replace('{forms}', 'ip, ip:port, [v6]:port'));
  // no server at all: nothing to put an address on
  const empty = harness({ servers: [], groups: [] });
  empty.ctx.openGroupEditor(null);
  byId(empty.body(), 'grpAddIps').onclick();
  assert.equal(all(empty.body(), (x) => x.id === 'grp-ips').length, 0);
  assert.ok(one(empty.body(), (x) => hasClass(x, 'grp-panel'), 'panel').textContent.includes(en('grp.noServers')));
});

test('Save: setGroups gets the whole list in §1’s shape exactly; its answer becomes the list; the dialog closes and everything that lists targets is drawn again', async () => {
  const h = harness({ setGroups: (list) => plain(list).map((g) => Object.assign(g, { name: g.name.toUpperCase() })) });
  h.ctx.openGroupEditor(null);
  h.type('grp-name', '  Speed  ');
  all(h.body(), (e) => e.dataset.grp === 'strategy:random')[0].onclick();
  byId(h.body(), 'grpAddServer').onclick();
  all(h.body(), (e) => e.dataset.srv === 's1')[0].onclick();
  byId(h.body(), 'grpAddIps').onclick();
  byId(h.body(), 'grp-ipServer').value = 's2';
  byId(h.body(), 'grp-ipServer').onchange();
  h.type('grp-ips', '104.16.1.1\n[2606:4700::1]:2053');
  byId(h.body(), 'grpIpsAdd').onclick();
  h.calls.length = 0;
  assert.equal(await h.ctx.saveGroupEditor(), true);
  assert.equal(h.sent.length, 1);
  const [list] = h.sent;
  assert.deepEqual(list.slice(0, 2), plain(GROUPS), 'the others as they were, in their order');
  const g = list[2];
  assert.match(g.id, /^grp-[0-9a-z]+[0-9a-f]{4}$/, 'grp-<base36 time><4 hex>');
  assert.deepEqual(Object.keys(g), ['id', 'name', 'strategy', 'members']);
  assert.deepEqual({ name: g.name, strategy: g.strategy, members: g.members }, { name: 'Speed', strategy: 'random',
    members: [{ id: 's1' }, { id: 's2', address: '104.16.1.1' }, { id: 's2', address: '2606:4700::1', port: 2053 }] });
  for (const m of g.members) assert.ok(Object.values(m).every((v) => v !== undefined && v !== null), 'no empty keys');
  // the answer is the truth
  assert.deepEqual(plain(h.state.groups).map((x) => x.name), ['FAST', 'OLD', 'SPEED']);
  assert.equal(h.page.get('grpModal').hidden, true);
  assert.deepEqual(h.calls.filter((c) => c[0] !== 'toast').map((c) => c[0]), ['renderChains', 'renderPicker', 'renderAdvanced', 'renderPool', 'refreshConnLabels']);
  assert.deepEqual(h.calls.find((c) => c[0] === 'toast'), ['toast', en('grp.saved'), 'ok']);
  // an answer of { groups } is read the same; a bare ok keeps what was sent
  const wrapped = harness({ setGroups: (l) => ({ ok: true, groups: plain(l).slice(0, 1) }) });
  wrapped.ctx.openGroupEditor('grp-a');
  await wrapped.ctx.saveGroupEditor();
  assert.deepEqual(plain(wrapped.state.groups).map((x) => x.id), ['grp-a']);
});

test('edit: a config whose server is gone is shown missing and kept until removed; Save replaces the group where it was; a refusal keeps the dialog open and the list as it was', async () => {
  const h = harness({ groups: [GROUPS[1], { id: 'grp-b', name: 'B', strategy: 'leastPing', members: [{ id: 'gone-9', address: '9.9.9.9', port: 443 }, { id: 's3' }] }] });
  h.state.pings['grp-b'] = { real: { ok: true, ms: 50 } };
  h.ctx.openGroupEditor('grp-b');
  assert.equal(byId(h.body(), 'grp-name').value, 'B');
  assert.equal(hasClass(all(h.body(), (e) => e.dataset.grp === 'strategy:leastPing')[0], 'on'), true);
  const rows = () => byCls(h.body(), 'grp-member');
  assert.deepEqual(rows().map((r) => [hasClass(r, 'missing'), byCls(r, 'grp-mname')[0].textContent, (byCls(r, 'grp-addr')[0] || {}).textContent]),
    [[true, en('grp.missing'), '9.9.9.9:443'], [false, 'Office WG', '10.0.0.1:51820']]);
  assert.equal(one(rows()[0], (e) => hasClass(e, 'proto-badge'), 'badge').textContent, '?');
  // edits do not touch the stored group until Save
  all(h.body(), (e) => e.dataset.grp === 'strategy:roundRobin')[0].onclick();
  assert.equal(h.state.groups[1].strategy, 'leastPing');
  await h.ctx.saveGroupEditor();
  assert.deepEqual(h.sent[0].map((x) => x.id), ['grp-gone', 'grp-b'], 'in place');
  assert.deepEqual(h.sent[0][1], { id: 'grp-b', name: 'B', strategy: 'roundRobin', members: [{ id: 'gone-9', address: '9.9.9.9', port: 443 }, { id: 's3' }] },
    'the missing config kept: only its remove takes it out');
  assert.equal(h.state.pings['grp-b'], undefined, 'its configs may have changed: the old delay goes');
  // removed, then saved
  h.ctx.openGroupEditor('grp-b');
  one(rows()[0], (e) => hasClass(e, 'cn-remove'), '✕').onclick();
  assert.deepEqual(plain(h.form().members), [{ id: 's3' }]);
  await h.ctx.saveGroupEditor();
  assert.deepEqual(h.sent[1][1].members, [{ id: 's3' }]);
  // only missing configs left: not saved, said
  const dead = harness();
  dead.ctx.openGroupEditor('grp-gone');
  assert.equal(await dead.ctx.saveGroupEditor(), false);
  assert.equal(dead.sent.length, 0);
  assert.equal(one(dead.body(), (e) => e.attrs.role === 'alert', 'why').textContent, en('grp.err.noMember'));
  // a refusal: said in a toast, the dialog stays, nothing changes
  const no = harness({ setGroups: () => ({ ok: false, error: 'disk full' }) });
  no.ctx.openGroupEditor('grp-a');
  all(no.body(), (e) => e.dataset.grp === 'strategy:random')[0].onclick();
  assert.equal(await no.ctx.saveGroupEditor(), false);
  assert.deepEqual(no.calls.find((c) => c[0] === 'toast'), ['toast', 'The group was not saved: disk full', 'err']);
  assert.equal(no.page.get('grpModal').hidden, false);
  assert.equal(no.state.groups[0].strategy, 'roundRobin');
  const boom = harness({ setGroups: () => { throw new Error('No handler registered for groups:set'); } });
  boom.ctx.openGroupEditor('grp-a');
  assert.equal(await boom.ctx.saveGroupEditor(), false);
  assert.match(boom.calls.find((c) => c[0] === 'toast')[1], /No handler registered/);
});

/* ------------------------------------ the pickers ------------------------------------ */

const MODEL_FNS = ['profileOfSel', 'profileReady', 'advSelName', 'terminalTarget', 'takesNoVia', 'atBase', 'appRouteRules', 'geoReady', 'normalizeUiProfile',
  'ruleVia', 'refProblem', 'ruleProblem', 'profileBroken', 'refName', 'flowModel', 'outboundTagFor', 'baseKeyOf', 'viaTagFor', 'baseTagFor', 'chainById',
  'chainMembers', 'chainReady', 'srvById', 'isChainId', 'targetLabel', 'poolTargetOptions', 'targetOptionList', 'profileTargetOptions', 'viaOptionList',
  'baseOptionList', 'selectable', 'advancedReady', 'poolTargetValid', 'poolEnabledValid', 'poolReady', 'resolveSelection', 'homeFlowModel', 'laneHue',
  'serverInLivePlan', 'grpById', 'grpLive', 'grpCountText', 'grpConnText', 'grpMemberNames', 'grpAddrText', 'warpNum'];

function modelHarness(over = {}) {
  const work = { id: 'rp-work', name: 'Work', rules: [{ type: 'domain', value: 'video.example', target: 'grp-a' }, { type: 'ip', value: '10.0.0.0/8', target: 'grp-gone' }],
    def: 'grp-a', defVia: 'inherit', useMode: false, base: 'grp-a' };
  const state = Object.assign({ servers: plain(SERVERS), groups: plain(GROUPS), chains: plain(CHAINS), pool: [], settings: { advancedRouting: true, routingMode: 'global' },
    profiles: [work], pings: {}, connected: false, activeServerId: null, assets: { geoip: true, geosite: true } }, over);
  const ctx = vm.createContext({ state, t: en, window: { i18n: { lang: 'en' } }, String, Array, Object, JSON, Math, Set, Number });
  vm.runInContext(PRELUDE + MODEL_FNS.map(fnSource).join('\n'), ctx);
  return { ctx, state, work };
}
const values = (opts) => plain(opts).map((o) => o.value);

test('every routing picker offers a group by its bare id, «⧉ name»: a rule’s target and the default, a profile’s via and base, the pool — and never one that is gone', () => {
  const { ctx, work } = modelHarness();
  const grp = { value: 'grp-a', label: '⧉ Fast' };
  assert.deepEqual(plain(ctx.poolTargetOptions()), [{ value: 's1', label: 'DE' }, { value: 's2', label: 'CDN' }, { value: 's3', label: 'Office WG' },
    { value: 'chain:c1', label: '⛓ DE→WG' }, grp], 'the pool (and the via and base pickers built on it)');
  assert.deepEqual(values(ctx.targetOptionList()), ['s1', 's2', 's3', 'chain:c1', 'grp-a', 'direct', 'block'], 'a rule’s target and the default');
  assert.deepEqual(plain(ctx.targetOptionList())[4], grp);
  assert.deepEqual(values(ctx.profileTargetOptions(work, 's1')).slice(0, 1), ['base'], 'exit at the base first, then the rest');
  assert.ok(values(ctx.profileTargetOptions(work, 's1')).includes('grp-a'));
  assert.deepEqual(values(ctx.viaOptionList(work, 's1')), ['inherit', 'none', 's2', 's3', 'chain:c1', 'grp-a'], 'a via: never the target itself');
  assert.ok(!values(ctx.viaOptionList(work, 'grp-a')).includes('grp-a'), 'nor a group as its own via');
  assert.equal(plain(ctx.viaOptionList(work, 's1'))[0].label, en('rp.viaInherit').replace('{base}', '⧉ Fast'), 'the base named «⧉ name»');
  assert.deepEqual(values(ctx.baseOptionList('grp-a')), ['', 's1', 's2', 's3', 'chain:c1', 'grp-a'], 'the base');
  // nothing anywhere is 'group:<id>', and a gone group is offered nowhere
  for (const list of [ctx.poolTargetOptions(), ctx.targetOptionList(), ctx.viaOptionList(work, 's1'), ctx.baseOptionList('')]) {
    assert.ok(!values(list).some((v) => /^group:|grp-gone/.test(v)), JSON.stringify(values(list)));
  }
  // a gone one already picked: said as a gone one, like a deleted server
  assert.equal(plain(ctx.baseOptionList('grp-gone')).pop().label, '⚠ —');
  assert.equal(ctx.poolTargetValid('grp-a'), true);
  assert.equal(ctx.poolTargetValid('grp-gone'), false);
});

test('names: «⧉ name» where a target is labelled, the plain name where its icon says it; the flow tree and the home path know a group; Home’s line names it', () => {
  const { ctx, state, work } = modelHarness();
  assert.equal(ctx.targetLabel('grp-a'), '⧉ Fast');
  assert.equal(ctx.targetLabel('grp-gone'), '—');
  assert.equal(ctx.refName('grp-a'), 'Fast');
  assert.equal(ctx.refProblem('grp-a'), '');
  assert.equal(ctx.refProblem('grp-gone'), 'rp.why.serverGone', 'a group that is gone: as a deleted server');
  // the routing page's flow: a rule and the default on a group, through a group as the base
  const m = plain(ctx.flowModel(work));
  assert.deepEqual(m.bases.map((b) => [b.key, b.why]), [['b:grp-a', '']]);
  // (a gone group is no longer a group: drawn as a gone server is, in the danger colour with its reason)
  assert.deepEqual(m.targets.map((x) => [x.key, x.kind, x.why]), [['t:grp-a', 'group', ''], ['t:grp-gone@grp-a', 'server', 'rp.why.serverGone'], ['t:direct', 'direct', '']]);
  assert.equal(m.targets.find((x) => x.key === 't:grp-a').tags[0], 'out-grp-a', 'its outbound is out-<id>, as a server’s');
  assert.equal(m.targets.find((x) => x.key === 't:grp-gone@grp-a').tags[0], 'out-grp-gone@grp-a', 'through a group as the base: <target>@<base id>');
  // the home path for a selected group: the group as the target, its traffic on its own outbound
  state.settings.advancedRouting = false;
  const home = plain(ctx.homeFlowModel('grp-a'));
  const def = home.targets.find((x) => x.ref === 'grp-a');
  assert.deepEqual([def.kind, def.tags], ['group', ['proxy', 'out-grp-a']]);
  // the pool's path too
  ctx.poolEnabledValid = () => [{ name: 'P', socksPort: 60001, target: 'grp-a' }];
  assert.equal(plain(ctx.homeFlowModel('__pool__')).targets[0].kind, 'group');
  // Home's line, and a tooltip of its configs
  assert.equal(ctx.grpConnText('grp-a'), `⧉ Fast (3 configs · ${en('grp.st.roundRobin')})`);
  assert.equal(ctx.grpMemberNames('grp-a'), 'CDN @ 104.16.1.1 · CDN @ [2606:4700::6810:1]:2053 · DE');
  assert.match(fnSource('setConnUI'), /\} else if \(\(state\.groups \|\| \[\]\)\.some\(g => g && g\.id === effId\)\) \{\n\s*\/\/[^\n]*\n\s*srv\.textContent = grpConnText\(effId\);/);
  // the flow tree's icon, and its click opens the group's card
  assert.match(fnSource('flowRefNode'), /n\.kind === 'group' \? '⧉'/);
  assert.match(fnSource('buildHomeFlow'), /tg\.kind === 'group' \? '⧉'/);
  assert.match(fnSource('flowNodeClick'), /if \(!n\.why && \(state\.groups \|\| \[\]\)\.some\(g => g && g\.id === ref\)\) return openGroupCard\(ref\);\n\s*if \(!n\.why && !terminalTarget\(ref\)\) return openEdit\(ref\);/);
});

test('an edit of a server a live group dials is an edit of the live plan — the group itself, a chain through it, a rule on it', () => {
  const { ctx, state } = modelHarness({ connected: true, activeServerId: 'grp-a' });
  assert.equal(ctx.serverInLivePlan('s2'), true, 'a member');
  assert.equal(ctx.serverInLivePlan('s3'), false);
  state.chains = [{ id: 'c9', name: 'x', members: ['grp-a', 's3'] }];
  state.activeServerId = 'c9';
  assert.equal(ctx.serverInLivePlan('s1'), true, 'a member of a group that is a hop');
  state.activeServerId = '__advanced__:rp-work';
  assert.equal(ctx.serverInLivePlan('s2'), true, 'a member of a group a rule goes to');
  assert.equal(ctx.serverInLivePlan('s3'), false);
});

test('a group that is gone (deleted, or every config of it deleted): its selection falls back, like a deleted server’s', () => {
  const { ctx, state } = modelHarness();
  assert.equal(ctx.selectable('grp-a'), true);
  assert.equal(ctx.selectable('grp-gone'), false, 'no member left');
  assert.equal(ctx.selectable('grp-deleted'), false);
  assert.equal(ctx.resolveSelection(['grp-a', null, 's1'], ctx.selectable, state.servers), 'grp-a', 'a group is a selection that survives a restart');
  state.groups = state.groups.filter((g) => g.id !== 'grp-a');
  assert.equal(ctx.resolveSelection(['grp-a', null, 's3'], ctx.selectable, state.servers), 's3', 'deleted: the last connection made');
  assert.equal(ctx.resolveSelection(['grp-a', null, 'grp-gone'], ctx.selectable, state.servers), 's1', 'then the first server');
  // the rule on it is said gone, as on a deleted server
  assert.equal(ctx.ruleProblem({ target: 'grp-gone' }, { base: null }), 'rp.why.serverGone');
});

/* ------------------------------------ the home picker ------------------------------------ */

function pickerHarness(selected) {
  const page = fakePage();
  const picked = [];
  const state = { servers: plain(SERVERS), groups: plain(GROUPS), subscriptions: [], chains: [], pool: [], settings: {}, selectedServerId: selected, connecting: false,
    pings: { 'grp-a': { tcp: { ok: false, na: true }, real: { ok: true, ms: 230 } } } };
  const ctx = vm.createContext({
    state, $: page.$, document: page.document, t: en, escapeHtml: (s) => String(s), window: { i18n: { lang: 'en' } },
    keepSelectionValid: () => {}, serverGroups: () => [], chainById: () => undefined, anyChainReady: () => false, advancedReady: () => false,
    poolReady: () => false, poolEnabledValid: () => [], pingLabel: () => ({ txt: '—', cls: '' }),
    closePicker: () => {}, connectAuto: () => {}, selectServer: (id) => picked.push(id), pingServer: () => {}, pingAllVisible: () => {},
    String, Array
  });
  vm.runInContext(PRELUDE + ['renderPicker', 'srvById', 'grpCountText', 'warpNum', 'pingResultLabel', 'fmtMs', 'pingClass'].map(fnSource).join('\n'), ctx);
  ctx.renderPicker();
  return { page, picked, rows: kids(page.get('pickerMenu')).filter((c) => hasClass(c, 'picker-item')) };
}

test('the home picker: a row per group «⧉ name · n configs» that selects its bare id; selected, the button draws it like a chain, with its real delay', () => {
  const h = pickerHarness('s1');
  const grpRows = h.rows.filter((r) => /proto-group/.test(r.innerHTML));
  assert.equal(grpRows.length, 1, 'the gone group has no row');
  assert.match(grpRows[0].innerHTML, /<span class="proto-badge proto-group">⧉<\/span><span class="pi-name">Fast · 3 configs<\/span>/);
  assert.ok(hasClass(grpRows[0], 'picker-special'), 'among the chains, above the servers');
  assert.ok(h.rows.indexOf(grpRows[0]) < h.rows.findIndex((r) => /proto-vless/.test(r.innerHTML)));
  assert.match(grpRows[0].innerHTML, /data-ping-real="grp-a">230</, 'its delay in the row');
  grpRows[0].onclick();
  assert.deepEqual(h.picked, ['grp-a'], 'the bare id — never group:<id>');
  const sel = pickerHarness('grp-a');
  assert.deepEqual([sel.page.get('pickerProto').textContent, sel.page.get('pickerProto').className, sel.page.get('pickerName').textContent, sel.page.get('pickerPing').textContent],
    ['⧉', 'proto-badge proto-group', 'Fast', '230']);
  assert.ok(hasClass(sel.rows.find((r) => /proto-group/.test(r.innerHTML)), 'active'));
  // Ping all takes the groups too
  assert.match(fnSource('pingAllVisible'), /\(state\.groups \|\| \[\]\)\.filter\(g => srvById\(g\.id\)\)\.map\(g => g\.id\)/);
});

/* ------------------------------------ the chain editor ------------------------------------ */

test('the chain editor offers groups as hops (⧉, by their bare id); a group hop counts, is drawn ⧉ and is saved in the chain', async () => {
  const page = fakePage();
  const saved = [];
  const state = { servers: plain(SERVERS), groups: plain(GROUPS), chains: [{ id: 'c1', name: 'One hop', members: ['s1'] }], pings: {}, profiles: null, selectedServerId: null, connecting: false };
  const ctx = vm.createContext({
    state, $: page.$, $$: page.$$, document: page.document, t: en, escapeHtml: (s) => String(s), window: { i18n: { lang: 'en' }, api: { setChains: async (l) => { saved.push(plain(l)); } } },
    usageLabel: () => '', connect() {}, pingServer() {}, shareRouting() {}, renderGroups() {}, renderPicker() {}, renderAdvanced() {}, renderPool() {},
    String, Array, Object, Number
  });
  vm.runInContext(PRELUDE + ['renderChains', 'persistChains', 'srvById', 'grpCountText', 'warpNum', 'pingResultLabel', 'fmtMs', 'pingClass', 'connectGlyph',
    'chainMembers', 'chainReady'].map(fnSource).join('\n'), ctx);
  ctx.renderChains();
  const card = kids(page.get('chainsWrap'))[0];
  const pool = card.querySelector('.chain-pool');
  const rows = kids(pool).filter((r) => hasClass(r, 'pool-item'));
  assert.deepEqual(rows.map((r) => r.dataset.name), ['CDN', 'Office WG', 'Fast'], 'the servers not in it, then the groups (the gone one not)');
  assert.match(rows[2].innerHTML, /<span class="proto-badge proto-group">⧉<\/span>\s*<span class="pi-name">Fast · 3 configs<\/span>/);
  rows[2].onclick();
  await tick();
  assert.deepEqual(saved[0], [{ id: 'c1', name: 'One hop', members: ['s1', 'grp-a'] }], 'its bare id, kept by the prune');
  assert.equal(ctx.chainReady(state.chains[0]), true, 'a group hop counts: two hops');
  const nodes = kids(kids(page.get('chainsWrap'))[0].querySelector('.chain-nodes')).filter((n) => hasClass(n, 'chain-node'));
  assert.match(nodes[1].innerHTML, /<span class="proto-badge proto-group">⧉<\/span>\s*<span class="cn-name">Fast<\/span>/);
  // its group gone (every config deleted): the hop goes, as a deleted server’s does
  state.groups[0].members = [{ id: 'nope' }];
  ctx.renderChains();
  assert.deepEqual(plain(state.chains[0].members), ['s1']);
});

/* ------------------------------------ the rest of the wiring ------------------------------------ */

test('init loads the groups before the chains (a chain keeps a group hop); a backup, the WARP chains and an import keep one too', () => {
  const init = fnSource('init');
  const at = init.indexOf('state.groups = await loadGroups(data);');
  assert.ok(at > -1 && at < init.indexOf('state.chains = '), 'the groups first');
  assert.ok(at < init.indexOf('resolveSelection('), 'a group selection survives a restart');
  assert.match(init, /members: \(c\.members \|\| \[\]\)\.filter\(id => state\.servers\.some\(s => s\.id === id\) \|\| state\.groups\.some\(g => g\.id === id\)\)/);
  assert.match(APP, /\n {2}groups: \[\],\n/, 'state.groups starts empty');
  const backup = APP.slice(APP.indexOf("$('#backupFile').onchange"), APP.indexOf("let updateInfo = null;"));
  assert.ok(backup.indexOf('state.groups = await loadGroups(data);') > -1 && backup.indexOf('state.groups = await loadGroups(data);') < backup.indexOf('state.chains = '));
  for (const fn of ['runWarp', 'refreshAfterImport']) assert.match(fnSource(fn), /\|\| \(state\.groups \|\| \[\]\)\.some\(\(?g\)? => g && g\.id === id\)/, fn);
  // someone with a group is a pro user: the page that holds it is not hidden from them
  assert.match(fnSource('defaultUiMode'), /\(state\.groups \|\| \[\]\)\.length > 0/);
  // the selected group is not marked in a subscription’s pile
  assert.match(fnSource('refreshSelection'), /selSrv && selSrv\.protocol !== 'group' \? groupKey\(selSrv\.subId\) : null/);
});

test('the stylesheet has the group pieces', () => {
  for (const sel of ['.proto-group', '.grp-section', '.grp-sec .head-actions', '.grp-title', '.grp-name', '.grp-meta', '.grp-chips', '.grp-chip', '.grp-addr',
    '.grp-member', '.grp-mname', '.grp-tools', '.grp-panel', '.grp-pool', '.grp-ipnote', '.modal.grp-modal', '.grp-chip.missing']) {
    assert.ok(LISTS.includes(sel + ' ') || LISTS.includes(sel + '{') || LISTS.includes(sel + ','), `lists.css has no ${sel}`);
  }
});
