'use strict';
/**
 * Routing profiles in the window and the router's web UI (task R3).
 *
 * Several advanced routings ("profiles"), each with its own rules, default and
 * an optional base its proxy targets dial through; the flow tree that draws a
 * profile as rules → targets → bases; one 🧭 picker row per profile; and the
 * irnetfree://routing/ share links (Copy link, and the import preview). The
 * main process owns the profiles (routing:profiles…, task R1/R2): on a back
 * end without them the routing page must stay today's single advanced routing.
 *
 * The store here is the shared fixture (tests/fixtures/routing/
 * profile-payload.json) with its local keys as ids: servers s1…s4, chain c1,
 * the profile "Work" — base s1, two rules through it, two direct, a chain with
 * no base, and the default s1 directly.
 *
 * app.js reaches into the DOM at load, so — like jsonUi.test.js — its own
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
const ROUTING_CSS = R('src', 'renderer', 'routing.css');
const PAYLOAD = JSON.parse(R('tests', 'fixtures', 'routing', 'profile-payload.json'));
const LINK = R('tests', 'fixtures', 'routing', 'profile-link.txt').trim();

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
/** One language's value of a key (fa is the first table, en the second). */
function str(lang, key) {
  const enAt = I18N.indexOf('\n  en: {');
  assert.ok(enAt > 0, 'i18n.js has no en table');
  const part = lang === 'fa' ? I18N.slice(0, enAt) : I18N.slice(enAt);
  const m = part.match(new RegExp(`'${key.replace(/\./g, '\\.')}': '((?:[^'\\\\]|\\\\.)*)'`));
  assert.ok(m, `${lang} has no '${key}'`);
  return m[1].replace(/\\'/g, "'");
}
const en = (key) => { try { return str('en', key); } catch { return key; } };
const fa = (key) => { try { return str('fa', key); } catch { return key; } };
/** Out of the vm's realm, so deepEqual compares values and not prototypes. */
const plain = (x) => JSON.parse(JSON.stringify(x));
const tick = () => new Promise((r) => setImmediate(r));

/* ------------------------------------ a fake page ------------------------------------ */

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
const camel = (k) => k.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
function matchesCompound(el, c) {
  if (c.tag && el.tagName !== c.tag) return false;
  if (c.id && el.id !== c.id) return false;
  const cls = String(el.className || '').split(/\s+/);
  if (!c.classes.every((x) => cls.includes(x))) return false;
  for (const [k, v] of c.attrs) {
    const val = k.startsWith('data-') ? el.dataset[camel(k.slice(5))] : el.attrs[k];
    if (val === undefined || val === null) return false;
    if (v !== undefined && String(val) !== v) return false;
  }
  return true;
}
/** A selector with descendant combinators, matched against `el` and its ancestors. */
function matchesSel(el, sel) {
  const parts = sel.trim().split(/\s+/).map(parseCompound);
  if (!matchesCompound(el, parts[parts.length - 1])) return false;
  let i = parts.length - 2;
  for (let node = el.parentNode; i >= 0 && node; node = node.parentNode) if (matchesCompound(node, parts[i])) i--;
  return i < 0;
}
const walk = (el, fn) => { for (const c of el.children) { fn(c); walk(c, fn); } };
const textOf = (el) => [el.textContent, ...el.children.map(textOf)].filter(Boolean).join(' ');
const hasClass = (el, cls) => String(el.className || '').split(/\s+/).includes(cls);

/**
 * Just enough of an element: children with parents, classes, attributes,
 * dataset, a selector engine over the real children — and, for a node built
 * from an innerHTML template, its named parts (looked up by the classes the
 * template carries), as in jsonUi.test.js.
 */
function fakeEl(tag) {
  const el = {
    tagName: String(tag || 'div').toUpperCase(), children: [], parentNode: null, attrs: {}, dataset: {}, style: {},
    hidden: false, disabled: false, textContent: '', title: '', className: '', type: '', id: '', dir: '', value: '',
    checked: false, onclick: null, onchange: null, oninput: null, html: '', parts: {},
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
    appendChild(c) {
      if (c && c.isFragment) { const kids = c.children.splice(0); kids.forEach((k) => el.appendChild(k)); return c; }
      el.children.push(c); c.parentNode = el; return c;
    },
    append(...c) { c.forEach((x) => el.appendChild(x)); },
    replaceChildren(...c) { el.children = []; c.forEach((x) => el.appendChild(x)); },
    remove() { if (el.parentNode) el.parentNode.children = el.parentNode.children.filter((x) => x !== el); },
    setAttribute(k, v) { el.attrs[k] = String(v); },
    getAttribute(k) { return k in el.attrs ? el.attrs[k] : null; },
    insertAdjacentElement() {},
    scrollIntoView(o) { el.scrolled = o || {}; },
    focus() { el.focused = true; },
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
    set innerHTML(v) { el.html = String(v); el.children = []; el.parts = {}; },
    get innerHTML() { return el.html; }
  };
  return el;
}

/** A page: elements by id, `$`/`$$` as app.js uses them, document.createElement. */
function fakePage() {
  const els = new Map();
  const get = (id) => { if (!els.has(id)) { const e = fakeEl('div'); e.id = id; els.set(id, e); } return els.get(id); };
  const $ = (sel) => {
    const m = String(sel).match(/^#([\w-]+)$/);
    return m ? get(m[1]) : null;
  };
  const $$ = (sel) => {
    const m = String(sel).match(/^#([\w-]+)\s+(.+)$/);
    return m ? get(m[1]).querySelectorAll(m[2]) : [];
  };
  const document = {
    createElement: fakeEl,
    createDocumentFragment: () => Object.assign(fakeEl('#fragment'), { isFragment: true }),
    querySelector: () => null,
    activeElement: null
  };
  return { get, $, $$, document };
}

/** Compile these app.js functions (and the prelude) in a context of fakes. */
function compile(names, globals, prelude = '') {
  const ctx = vm.createContext(globals);
  vm.runInContext(prelude + '\n' + names.map(fnSource).join('\n'), ctx);
  return ctx;
}

/* ------------------------------------ the store ------------------------------------ */

/** The fixture's servers and chain under their payload keys, and its profile as "rp-work". */
function store() {
  const servers = PAYLOAD.servers.map((s) => ({ id: s.key, name: s.name, protocol: s.link.split(':')[0], address: 'x.example', port: 443 }));
  const chains = PAYLOAD.chains.map((c) => ({ id: c.key, name: c.name, members: c.members.slice() }));
  const work = Object.assign({ id: 'rp-work' }, JSON.parse(JSON.stringify(PAYLOAD.profile)));
  // targets in the payload are sN / chain:cN — the same strings as these ids
  const def = { id: 'rp-default', name: 'Advanced routing', rules: [{ type: 'ip', value: '10.0.0.0/8', target: 's2' }], def: 's1', defVia: 'inherit', useMode: false, base: null };
  return { servers, chains, work, def };
}

const PRELUDE_CONSTS = constSource('ADV_ID') + constSource('POOL_ID') + constSource('RULE_TYPES') + constSource('QR_JSON_MAX_BYTES');
const MODEL_FNS = ['profileOfSel', 'profileReady', 'advSelName', 'terminalTarget', 'normalizeUiProfile', 'ruleVia', 'refProblem', 'ruleProblem',
  'profileBroken', 'refName', 'flowModel', 'outboundTagFor', 'baseKeyOf', 'viaTagFor', 'baseTagFor', 'chainById', 'chainMembers', 'chainReady',
  'srvById', 'isChainId', 'targetLabel', 'poolTargetOptions'];

function modelHarness(over = {}) {
  const s = store();
  const state = Object.assign({ servers: s.servers, chains: s.chains, pool: [], settings: { advancedRouting: true }, profiles: [s.def, s.work], profileSel: 'rp-work', connected: false, activeServerId: null }, over);
  const ctx = compile(MODEL_FNS, { state, t: en, String, Array, Object, JSON, Math, Set }, PRELUDE_CONSTS);
  return { ctx, state, s };
}

/* ------------------------------------ strings ------------------------------------ */

const RP_KEYS = [...new Set([
  ...[...APP.matchAll(/'(rp\.[A-Za-z.]*[A-Za-z])'/g)].map((m) => m[1]),
  ...[...HTML.matchAll(/data-i18n(?:-ph|-title)?="(rp\.[^"]+)"/g)].map((m) => m[1]),
  'set.routingProfiles', 'set.chains'
])];

test('every routing-profile string exists once in fa and once in en, as one clean literal with no straight apostrophe', () => {
  assert.ok(RP_KEYS.length >= 45, `only ${RP_KEYS.length} keys found`);
  for (const key of RP_KEYS) {
    assert.equal(I18N.split(`'${key}':`).length - 1, 2, `'${key}' is not defined exactly once in each of fa and en`);
    const lines = I18N.split('\n').filter((l) => l.includes(`'${key}':`));
    for (const line of lines) {
      const m = line.match(/^\s*'[^']+':\s*'((?:[^'\\]|\\.)*)',?\s*$/);
      assert.ok(m, `${key}: not a single clean string literal — a straight ' inside? ${line.trim().slice(0, 90)}`);
      assert.ok(!/\\'/.test(m[1]), `${key}: use ’ and not an escaped '`);
    }
    assert.ok(str('fa', key).length > 0 && str('en', key).length > 0, key);
    // the Persian table is Persian (a copy of the English would pass every check above)
    assert.notEqual(str('fa', key), str('en', key), `${key}: fa is the English text`);
  }
  // the placeholders are in both languages
  for (const [key, ph] of [['rp.newName', '{n}'], ['rp.shareWarn', '{n}'], ['rp.confirmDelete', '{name}'], ['rp.viaBase', '{base}'],
    ['rp.viaInherit', '{base}'], ['rp.importFailed', '{reason}'], ['rp.imported', '{servers}'], ['rp.imported', '{chains}'], ['rp.imported', '{profiles}']]) {
    assert.ok(str('fa', key).includes(ph), `fa ${key} lacks ${ph}`);
    assert.ok(str('en', key).includes(ph), `en ${key} lacks ${ph}`);
  }
  // the words the owner approved for the tree
  assert.equal(en('rp.everythingElse'), 'everything else');
  assert.equal(en('rp.viaBase'), 'via {base}');
  assert.equal(fa('rp.viaBase'), 'از طریق {base}');
  assert.equal(en('rp.copyLink'), 'Copy link');
});

/* ------------------------------------ the bridges ------------------------------------ */

test('the six bridges are in the preload AND the router’s web-api, on the channels R1/R2 serve', () => {
  const preload = R('src', 'preload', 'preload.js');
  const web = R('src', 'server', 'web-api.js');
  const want = [
    ['routingProfiles', '', 'routing:profiles', ''],
    ['setRoutingProfiles', 'profiles', 'routing:setProfiles', ', profiles'],
    ['shareRoutingProfile', 'id', 'routing:shareProfile', ', id'],
    ['shareChain', 'id', 'routing:shareChain', ', id'],
    ['routingImportPreview', 'text', 'routing:importPreview', ', text'],
    ['routingImport', 'text', 'routing:import', ', text']
  ];
  for (const [name, arg, channel, pass] of want) {
    const esc = (x) => x.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    assert.match(preload, new RegExp(`\\n {2}${name}: \\(${arg}\\) => ipcRenderer\\.invoke\\('${esc(channel)}'${esc(pass)}\\),`), `preload: ${name}`);
    assert.match(web, new RegExp(`\\n {4}${name}: \\(${arg}\\) => invoke\\('${esc(channel)}'${esc(pass)}\\),`), `web-api: ${name}`);
  }
});

/* ------------------------------------ the markup ------------------------------------ */

test('the markup has every element the new code reaches, translated, and stays balanced', () => {
  const ids = new Set([...HTML.matchAll(/id="([^"]+)"/g)].map((m) => m[1]));
  for (const id of ['rpBar', 'rpList', 'btnRpAdd', 'rpEmpty', 'rpHead', 'rpName', 'rpDefBadge', 'btnRpDefault', 'btnRpDup', 'btnRpShare',
    'btnRpDel', 'rpFlowWrap', 'rpFlow', 'rpFlowLive', 'advEditor', 'advDefVia', 'advDefViaMount', 'advBaseRow', 'advBaseMount', 'advBaseWhy',
    'rpShareModal', 'rpShareTitle', 'rpShareClose', 'rpShareWarn', 'rpShareQr', 'rpShareLink', 'rpShareCopy',
    'rpImportModal', 'rpImportClose', 'rpImportSum', 'rpImportGo', 'rpImportCancel']) assert.ok(ids.has(id), `#${id} is missing`);
  // every #id the new section reaches with $('#…') exists in the page
  const section = APP.slice(APP.indexOf('/* ----------------------------- routing profiles'), APP.indexOf('/* ----------------------------- live traffic stats'));
  assert.ok(section.length > 10000, 'the routing profiles section of app.js');
  for (const m of section.matchAll(/\$\('#([\w-]+)'\)/g)) assert.ok(ids.has(m[1]), `app.js reaches #${m[1]}, which index.html does not have`);
  for (const m of section.matchAll(/\$\$\('#([\w-]+) /g)) assert.ok(ids.has(m[1]), `app.js reaches #${m[1]}, which index.html does not have`);
  // the profile UI starts hidden: a back end without profiles never shows it
  for (const id of ['rpBar', 'rpHead', 'rpFlowWrap', 'advDefVia', 'advBaseRow', 'rpShareModal', 'rpImportModal']) {
    assert.match(HTML, new RegExp(`id="${id}"[^>]*\\shidden`), `#${id} must start hidden`);
  }
  // the editor wraps today's rule editor, which stays in it
  const editor = HTML.slice(HTML.indexOf('id="advEditor"'), HTML.indexOf('<!-- /advEditor -->'));
  for (const id of ['advRules', 'btnAddRule', 'advDefaultMount', 'optAdvUseMode', 'procOpts', 'btnSaveAdv']) assert.ok(editor.includes(`id="${id}"`), `#${id} inside #advEditor`);
  // the default's via and the base sit next to the default target
  const def = HTML.indexOf('id="advDefaultMount"');
  assert.ok(def < HTML.indexOf('id="advDefVia"') && HTML.indexOf('id="advDefVia"') < HTML.indexOf('id="advBaseRow"'));
  assert.ok(HTML.indexOf('id="advBaseRow"') < HTML.indexOf('id="optAdvUseMode"'));
  const strip = (s) => s.replace(/<!--[\s\S]*?-->/g, '').replace(/<script[\s\S]*?<\/script>/g, '');
  const body = strip(HTML);
  assert.equal((body.match(/<div[\s>]/g) || []).length, (body.match(/<\/div>/g) || []).length, 'unbalanced <div>s in index.html');
  // the dialogs' own strings
  for (const k of ['btn.import', 'btn.cancel', 'qr.copy', 'qr.tooBig']) assert.equal(I18N.split(`'${k}':`).length - 1, 2, k);
});

test('the styles: logical properties and tokens only, a mirrored grid with an SVG under it, and a stacked layout for a narrow column', () => {
  const block = ROUTING_CSS.slice(ROUTING_CSS.indexOf('routing profiles'));
  assert.ok(block.length > 2000, 'the routing profiles section of routing.css');
  assert.doesNotMatch(block, /margin-(left|right)|padding-(left|right)|border-(left|right)|(^|[^-])\b(left|right):\s*\d/m, 'logical properties only (RTL)');
  assert.doesNotMatch(block, /#[0-9a-f]{3,8}\b|rgba?\(/i, 'tokens only — the skin picks the colours');
  for (const sel of ['.rp-tab', '.rp-tab.active', '.rp-head', '.adv-via', '.adv-base', '.adv-warn', '.adv-rule.danger', '.rf', '.rf.no-bases', '.rf-node',
    '.rf-node.danger', '.rf-edges', '.rf-edge', '.rf-edge.danger', '.rf.live', '.rf-traffic', '.rf-to', '.rp-im-row', '.rp-share-warn']) {
    assert.ok(block.includes(sel), `${sel} has no style`);
  }
  assert.match(block, /\.rf\s*\{[^}]*display:\s*grid/);
  assert.match(block, /\.rf-edges\s*\{[^}]*position:\s*absolute;[^}]*inset:\s*0/);
  const narrow = block.match(/@container routecol \(max-width: 560px\) \{([\s\S]*?)\n\}/);
  assert.ok(narrow, 'a stacked layout for the narrow column');
  assert.match(narrow[1], /\.rf-edges \{ display: none; \}/);
  assert.match(narrow[1], /\.rf-to \{ display: block;/, 'each rule says where it leads instead of a line');
  assert.match(block, /prefers-reduced-motion/);
  // "03–04" stays a left-to-right range in Persian (it read 04–03 in the live check)
  assert.match(block, /\.rf-idx \{[^}]*direction: ltr; unicode-bidi: isolate;/);
  // the dialogs sit outside #view-routing, where the --rt scale is not declared
  const dialogs = block.slice(block.indexOf('.qr-body .rp-share-warn'));
  assert.doesNotMatch(dialogs, /var\(--rt-/);
  assert.match(R('src', 'renderer', 'home.css'), /\.path-rule \.pr-via \{/);
});

/* ------------------------------------ selections ------------------------------------ */

test('selections: "__advanced__:<id>" connects that profile, plain "__advanced__" the first, and only a profile with rules or a default is offered', () => {
  const s = store();
  const empty = { id: 'rp-empty', name: 'Empty', rules: [], def: '', defVia: 'inherit', useMode: false, base: null };
  const state = { servers: s.servers, chains: s.chains, pool: [], settings: { advancedRouting: true }, profiles: [s.def, s.work, empty] };
  const ctx = compile(['selectable', 'advancedReady', 'profileOfSel', 'profileReady', 'advSelName', 'chainById', 'isChainId', 'chainMembers', 'chainReady',
    'srvById', 'poolTargetValid', 'poolEnabledValid', 'poolReady'], { state, t: en, String }, PRELUDE_CONSTS);
  assert.equal(ctx.profileOfSel('__advanced__').id, 'rp-default', 'the old selection still resolves: the first profile');
  assert.equal(ctx.profileOfSel('__advanced__:rp-work').id, 'rp-work');
  assert.equal(ctx.profileOfSel('__advanced__:gone'), null);
  assert.equal(ctx.profileOfSel('s1'), null);
  assert.equal(ctx.profileOfSel(null), null);
  assert.equal(ctx.selectable('__advanced__'), true);
  assert.equal(ctx.selectable('__advanced__:rp-work'), true);
  assert.equal(ctx.selectable('__advanced__:rp-empty'), false, 'no rules and no default: nothing to connect');
  assert.equal(ctx.selectable('__advanced__:gone'), false);
  assert.equal(ctx.selectable('s1'), true);
  assert.equal(ctx.advSelName('__advanced__'), 'Advanced routing');
  assert.equal(ctx.advSelName('__advanced__:rp-work'), 'Work');
  assert.equal(ctx.advSelName('__advanced__:gone'), en('picker.advanced'));
  // the "show advanced routing" switch still decides
  state.settings.advancedRouting = false;
  assert.equal(ctx.selectable('__advanced__'), false);
  assert.equal(ctx.selectable('__advanced__:rp-work'), false);
  assert.equal(ctx.advancedReady(), false);
  // the first profile is what plain "__advanced__" means: an empty first one cannot be connected that way
  state.settings.advancedRouting = true;
  state.profiles = [empty, s.work];
  assert.equal(ctx.selectable('__advanced__'), false);
  assert.equal(ctx.advancedReady(), true, 'but advanced routing as a whole is there');

  // a back end without profiles: today's settings decide, and a profile id means nothing
  state.profiles = null;
  state.settings = { advancedRouting: true, routeRules: [{ type: 'ip', value: '1.2.3.4', target: 's1' }] };
  assert.equal(ctx.selectable('__advanced__'), true);
  assert.equal(ctx.selectable('__advanced__:rp-work'), false);
  assert.equal(ctx.advSelName('__advanced__'), en('picker.advanced'));
  state.settings = { advancedRouting: true };
  assert.equal(ctx.selectable('__advanced__'), false);
});

test('init loads the profiles before it resolves the stored selection, so "__advanced__:<id>" survives a restart', () => {
  const init = fnSource('init');
  const load = init.indexOf('state.profiles = await loadRoutingProfiles(data);');
  assert.ok(load > -1);
  assert.ok(load > init.indexOf('state.pool = ') && load < init.indexOf('resolveSelection('));
  assert.match(APP, /\n {2}profiles: null,\n/, 'null until loaded: today’s routing page');
});

test('loadRoutingProfiles: init’s data when main sends it, else the bridge; null when the back end has none', async () => {
  const run = async (api, data) => {
    const ctx = compile(['loadRoutingProfiles', 'normalizeUiProfile', 'terminalTarget'], { window: { api }, String, Array, Object }, '');
    return ctx.loadRoutingProfiles(data);
  };
  assert.equal(await run({}, {}), null, 'no bridge');
  assert.equal(await run({ routingProfiles: async () => { throw new Error("No handler registered for 'routing:profiles'"); } }, {}), null, 'Electron without the handler');
  assert.equal(await run({ routingProfiles: async () => { throw new Error('unknown channel: routing:profiles'); } }, {}), null, 'the service without it');
  assert.equal(await run({ routingProfiles: async () => ({}) }, {}), null);
  const got = await run({ routingProfiles: async () => ({ profiles: [{ id: 'rp-default', name: 'A', rules: [{ type: 'ip', value: 'x', target: 'direct', via: 's1' }] }] }) }, {});
  assert.deepEqual(plain(got), [{ id: 'rp-default', name: 'A', rules: [{ type: 'ip', value: 'x', target: 'direct' }], def: '', defVia: 'inherit', useMode: false, base: null }],
    'normalized: direct never takes a via');
  const fromInit = await run({ routingProfiles: async () => { throw new Error('not asked'); } }, { routingProfiles: [{ id: 'rp-x', name: 'X', rules: [] }] });
  assert.equal(fromInit[0].id, 'rp-x');
});

test('normalizeUiProfile: a via only where it means something, the rest coerced, unknown fields kept', () => {
  const { ctx } = modelHarness();
  const n = plain(ctx.normalizeUiProfile({
    id: 'rp-a', name: 'A', extra: 7, useMode: 1, base: 's1', def: 'direct', defVia: 's2',
    rules: [{ type: 'domain', value: 'a', target: 's2', via: 'inherit' }, { type: 'domain', value: 'b', target: 's3', via: 'none' },
      { type: 'port', value: 443, target: 'block', via: 's1' }, null]
  }));
  assert.deepEqual(n, {
    id: 'rp-a', name: 'A', extra: 7, useMode: true, base: 's1', def: 'direct', defVia: 'inherit',
    rules: [{ type: 'domain', value: 'a', target: 's2' }, { type: 'domain', value: 'b', target: 's3', via: 'none' }, { type: 'port', value: '443', target: 'block' }]
  });
  assert.deepEqual(plain(ctx.normalizeUiProfile(null)), { id: '', name: '', rules: [], def: '', defVia: 'inherit', useMode: false, base: null });
});

test('the effective via: inherit takes the base, none and direct/block take nothing, an explicit one is itself — and a target is never its own base', () => {
  const { ctx } = modelHarness();
  const prof = { base: 's1' };
  assert.equal(ctx.ruleVia({ target: 's2' }, prof), 's1');
  assert.equal(ctx.ruleVia({ target: 's2', via: 'inherit' }, prof), 's1');
  assert.equal(ctx.ruleVia({ target: 's2', via: 'none' }, prof), null);
  assert.equal(ctx.ruleVia({ target: 's2', via: 'chain:c1' }, prof), 'chain:c1');
  assert.equal(ctx.ruleVia({ target: 's2' }, { base: null }), null);
  assert.equal(ctx.ruleVia({ target: 'direct', via: 's3' }, prof), null);
  assert.equal(ctx.ruleVia({ target: 'block' }, prof), null);
  assert.equal(ctx.ruleVia({ target: 's1' }, prof), null, 'the base itself dials directly');
});

test('the tags of a target through a base and of a base are the ones the builder gives them', () => {
  const { ctx } = modelHarness();
  assert.equal(ctx.viaTagFor('s2', 's1'), 'out-s2@s1');
  assert.equal(ctx.viaTagFor('chain:c1', 's1'), 'out-chain-c1@s1');
  assert.equal(ctx.viaTagFor('s2', 'chain:c9'), 'out-s2@chain-c9');
  assert.equal(ctx.baseTagFor('s1'), 'base-s1');
  assert.equal(ctx.baseTagFor('chain:c9'), 'base-chain-c9');
  // and without a via, today's
  assert.equal(ctx.outboundTagFor('s2'), 'out-s2');
  assert.equal(ctx.outboundTagFor('chain:c1'), 'out-chain-c1');
});

/* ------------------------------------ the flow tree as data ------------------------------------ */

test('the fixture’s flow: rules (two direct ones grouped) → targets → ONE base with both of its incoming edges; the default is “everything else”', () => {
  const { ctx, s } = modelHarness();
  const m = plain(ctx.flowModel(s.work));
  assert.deepEqual(m.groups.map((g) => [g.key, g.idxs, g.target, g.via]), [
    ['g0', [0], 's2', 's1'],
    ['g1', [1], 's3', 's1'],
    ['g2', [2, 3], 'direct', null],
    ['g4', [4], 'chain:c1', null],
    ['def', [], 's1', null]
  ]);
  assert.equal(m.groups[4].isDefault, true);
  assert.deepEqual(m.groups[2].items.map((i) => i.type), ['domain', 'ip'], 'one node, both rules');
  assert.deepEqual(m.targets.map((t) => [t.key, t.kind, t.tags[0]]), [
    ['t:s2@s1', 'server', 'out-s2@s1'],
    ['t:s3@s1', 'server', 'out-s3@s1'],
    ['t:direct', 'direct', 'direct'],
    ['t:chain:c1', 'chain', 'out-chain-c1'],
    ['t:s1', 'server', 'out-s1']
  ], 's1 as the default (no via) and s1 as the base are two outbounds, two nodes');
  assert.deepEqual(m.bases.map((b) => [b.key, b.tags[0], b.into]), [['b:s1', 'base-s1', 2]], 'drawn once, both targets point at it');
  assert.deepEqual(m.edges.map((e) => `${e.from}>${e.to}`), [
    'g0>t:s2@s1', 'g1>t:s3@s1', 'g2>t:direct', 'g4>t:chain:c1', 'def>t:s1', 't:s2@s1>b:s1', 't:s3@s1>b:s1'
  ]);
  assert.ok(m.edges.every((e) => !e.danger), 'nothing is gone');
  assert.ok(!m.edges.some((e) => e.from === 't:direct'), 'direct ends where it is');
  assert.equal(m.profileId, 'rp-work');
});

test('a gone server, base or chain is a danger node with its reason, and so is every edge into it', () => {
  const h = modelHarness();
  h.state.servers = h.state.servers.filter((x) => x.id !== 's1' && x.id !== 's4');   // the base and a chain hop
  const m = plain(h.ctx.flowModel(h.s.work));
  const node = (k) => m.targets.concat(m.bases).find((n) => n.key === k);
  assert.equal(node('b:s1').why, 'rp.why.baseGone');
  assert.equal(node('t:s1').why, 'rp.why.serverGone');
  assert.equal(node('t:chain:c1').why, 'rp.why.chainGone', 'one hop left is no chain');
  assert.equal(node('t:s2@s1').why, '', 'the target itself is fine');
  const danger = m.edges.filter((e) => e.danger).map((e) => `${e.from}>${e.to}`);
  assert.deepEqual(danger, ['g4>t:chain:c1', 'def>t:s1', 't:s2@s1>b:s1', 't:s3@s1>b:s1']);
  // and the rule editor's note for each rule
  assert.equal(h.ctx.ruleProblem(h.s.work.rules[0], h.s.work), 'rp.why.baseGone');
  assert.equal(h.ctx.ruleProblem(h.s.work.rules[2], h.s.work), '');
  assert.equal(h.ctx.ruleProblem(h.s.work.rules[4], h.s.work), 'rp.why.chainGone');
  assert.equal(h.ctx.profileBroken(h.s.work), true);
  assert.equal(modelHarness().ctx.profileBroken(store().work), false);
});

test('a chain base: its tags, and an explicit via overriding the profile’s base', () => {
  const { ctx } = modelHarness();
  const p = { id: 'rp-c', rules: [{ type: 'domain', value: 'a.example', target: 's2' }, { type: 'domain', value: 'b.example', target: 's3', via: 's4' }], def: 'direct', base: 'chain:c1' };
  const m = plain(ctx.flowModel(p));
  assert.deepEqual(m.targets.map((t) => [t.key, t.tags[0]]), [['t:s2@chain:c1', 'out-s2@chain-c1'], ['t:s3@s4', 'out-s3@s4'], ['t:direct', 'direct']]);
  assert.deepEqual(m.bases.map((b) => [b.key, b.tags[0]]), [['b:chain:c1', 'base-chain-c1'], ['b:s4', 'base-s4']]);
  // a value still being typed is not a rule yet; the same target with another base is another node
  const q = { id: 'rp-q', base: 's1', rules: [{ type: 'ip', value: ' ', target: 's2' }, { type: 'ip', value: '1.1.1.1', target: 's2' }, { type: 'ip', value: '2.2.2.2', target: 's2', via: 'none' }], def: '' };
  const n = plain(ctx.flowModel(q));
  assert.deepEqual(n.groups.map((g) => g.key), ['g1', 'g2', 'def']);
  assert.deepEqual(n.targets.map((t) => t.key), ['t:s2@s1', 't:s2', 't:s1']);
  assert.equal(n.groups[2].target, 's1', 'no default: the first server, as the builder takes it');
  assert.equal(n.groups[2].via, null, 'which is the base itself: it dials directly');
  // the same target and base on consecutive rules is one node, whichever way the via is written
  const r = { id: 'rp-r', base: null, rules: [{ type: 'ip', value: '1.1.1.1', target: 's2' }, { type: 'ip', value: '2.2.2.2', target: 's2', via: 'none' }], def: 'direct' };
  assert.deepEqual(plain(ctx.flowModel(r)).groups.map((g) => [g.key, g.idxs]), [['g0', [0, 1]], ['def', []]]);
});

test('the edges are S-curves from the source’s far side to the target’s near side — mirrored in RTL', () => {
  const ctx = compile(['flowEdgePaths'], { Math }, '');
  const rects = { a: { left: 10, right: 110, top: 20, height: 20 }, b: { left: 200, right: 300, top: 60, height: 40 } };
  const box = { left: 10, top: 10 };
  const [ltr] = plain(ctx.flowEdgePaths([{ from: 'a', to: 'b', danger: true }], rects, box, false));
  assert.deepEqual(ltr, { from: 'a', to: 'b', danger: true, d: 'M100 20 C145 20 145 70 190 70' });
  // right-to-left: the rules column is on the right, so a line leaves a node by its left side
  const rtlRects = { a: { left: 200, right: 300, top: 20, height: 20 }, b: { left: 10, right: 110, top: 60, height: 40 } };
  const [rtl] = plain(ctx.flowEdgePaths([{ from: 'a', to: 'b' }], rtlRects, box, true));
  assert.equal(rtl.d, 'M190 20 C145 20 145 70 100 70');
  assert.deepEqual(plain(ctx.flowEdgePaths([{ from: 'a', to: 'gone' }], rects, box, false)), [], 'a node not on screen draws nothing');
});

/* ------------------------------------ the flow tree on screen ------------------------------------ */

function treeHarness(over = {}) {
  const s = store();
  const page = fakePage();
  const calls = [];
  const state = Object.assign({ servers: s.servers, chains: s.chains, pool: [], settings: { advancedRouting: true }, profiles: [s.def, s.work],
    profileSel: 'rp-work', connected: false, activeServerId: null }, over);
  const ctx = compile([...MODEL_FNS, 'advDraft', 'renderFlowTree', 'flowRuleNode', 'flowRefNode', 'flowButton', 'spanIn', 'applyFlowTraffic', 'profileLive',
    'ruleTypeIcon', 'ruleSummary', 'fmtBytes', 'fmtSpeed', 'flowNodeClick', 'flashInto', 'focusAdvRow', 'openChainCard'], {
    state, t: en, $: page.$, $$: page.$$, document: page.document,
    drawFlowSoon: () => calls.push(['draw']),
    openEdit: (id) => calls.push(['openEdit', id]),
    showView: (v) => calls.push(['view', v]),
    setTimeout: () => 0,
    String, Array, Object, JSON, Math, Set, Number
  }, PRELUDE_CONSTS + 'let rpDraft = null; let rfModel = null; let lastPerOutbound = {};');
  return { ctx, state, page, calls, s, flow: () => page.get('rpFlow') };
}
const nodesOf = (host) => host.querySelectorAll('.rf-node');
const byKey = (host, key) => nodesOf(host).find((n) => n.dataset.key === key);

test('the tree on screen: three columns of buttons, keyed for their edges, the danger colour and its reason where something is gone', () => {
  const h = treeHarness();
  h.ctx.renderFlowTree();
  assert.equal(h.page.get('rpFlowWrap').hidden, false);
  const grid = h.flow().children[0];
  assert.equal(hasClass(grid, 'rf'), true);
  assert.equal(hasClass(grid, 'no-bases'), false);
  const heads = grid.querySelectorAll('.rf-head').map((x) => x.textContent);
  assert.deepEqual(heads, ['Rules', 'Targets', 'Bases']);
  assert.deepEqual(nodesOf(h.flow()).map((n) => n.dataset.key), ['g0', 'g1', 'g2', 'g4', 'def', 't:s2@s1', 't:s3@s1', 't:direct', 't:chain:c1', 't:s1', 'b:s1']);
  assert.ok(nodesOf(h.flow()).every((n) => n.tagName === 'BUTTON' && n.type === 'button'), 'keyboard-reachable, never a submit');
  assert.ok(nodesOf(h.flow()).every((n) => n.getAttribute('aria-label')), 'an accessible name for every node');
  // the grouped rule: its two rules, both type icons, a short value summary (left-to-right)
  const g2 = byKey(h.flow(), 'g2');
  assert.equal(g2.querySelector('.rf-idx').textContent, '03–04');
  assert.equal(g2.querySelector('.rf-ico').textContent, '🌐📍');
  assert.equal(g2.querySelector('.rf-label').textContent, 'geosite:category-ir, geoip:ir');
  assert.equal(g2.querySelector('.rf-label').dir, 'ltr');
  assert.equal(g2.querySelector('.rf-to').textContent, '→ Direct', 'the words that stand in for the line when the columns stack');
  const g0 = byKey(h.flow(), 'g0');
  assert.equal(g0.querySelector('.rf-label').textContent, 'corp.example, intranet.example');
  assert.equal(g0.title, 'corp.example, intranet.example → Corp WG · via 🇩🇪 Base DE');
  const def = byKey(h.flow(), 'def');
  assert.equal(hasClass(def, 'rf-default'), true);
  assert.equal(def.querySelector('.rf-label').textContent, 'everything else');
  // a target through the base says so; the base says it is one
  const t2 = byKey(h.flow(), 't:s2@s1');
  assert.equal(t2.querySelector('.rf-sub').textContent, 'via 🇩🇪 Base DE');
  assert.equal(t2.querySelector('.rf-traffic').dataset.tags, 'out-s2@s1');
  assert.equal(hasClass(byKey(h.flow(), 't:direct'), 'to-direct'), true);
  const base = byKey(h.flow(), 'b:s1');
  assert.equal(hasClass(base, 'rf-base'), true);
  assert.equal(base.querySelector('.rf-tag').textContent, 'Base');
  assert.equal(base.querySelector('.rf-traffic').dataset.tags, 'base-s1');
  assert.ok(h.calls.some((c) => c[0] === 'draw'), 'the lines are drawn once the boxes are laid out');
  assert.equal(nodesOf(h.flow()).filter((n) => hasClass(n, 'danger')).length, 0);

  // the base deleted: its node in the danger colour, with the reason in words
  h.state.servers = h.state.servers.filter((x) => x.id !== 's1');
  h.ctx.renderFlowTree();
  const gone = byKey(h.flow(), 'b:s1');
  assert.equal(hasClass(gone, 'danger'), true);
  assert.equal(gone.querySelector('.rf-why').textContent, '⚠ ' + en('rp.why.baseGone'));
  assert.equal(gone.querySelector('.rf-label').textContent, '—');
  assert.match(gone.title, /no longer exists/);
});

test('without a base the tree has two columns; without profiles there is no tree at all', () => {
  const h = treeHarness({ profileSel: 'rp-default' });
  h.ctx.renderFlowTree();
  assert.equal(hasClass(h.flow().children[0], 'no-bases'), true);
  assert.deepEqual(h.flow().children[0].querySelectorAll('.rf-head').map((x) => x.textContent), ['Rules', 'Targets']);
  const off = treeHarness({ profiles: null });
  off.page.get('rpFlowWrap').hidden = true;
  off.ctx.renderFlowTree();
  assert.equal(off.page.get('rpFlowWrap').hidden, true);
  assert.equal(off.flow().children.length, 0);
});

test('a node opens what it stands for: a rule its row, a server its editor, a chain its card; direct, block and a gone base what uses them', () => {
  const h = treeHarness();
  // the rule editor's rows, as renderAdvanced numbers them
  const rules = h.page.get('advRules');
  for (let i = 0; i < 5; i++) { const r = fakeEl('div'); r.className = 'adv-rule'; r.dataset.idx = String(i); rules.appendChild(r); }
  const defRow = fakeEl('div'); defRow.className = 'adv-default'; h.page.get('advBody').appendChild(defRow);
  const card = fakeEl('div'); card.className = 'card chain-card'; card.dataset.chainId = 'c1'; h.page.get('chainsWrap').appendChild(card);
  h.ctx.renderFlowTree();
  byKey(h.flow(), 'g4').onclick();
  assert.equal(hasClass(rules.children[4], 'flash'), true);
  assert.ok(rules.children[4].scrolled);
  byKey(h.flow(), 'def').onclick();
  assert.equal(hasClass(defRow, 'flash'), true);
  byKey(h.flow(), 't:s2@s1').onclick();
  byKey(h.flow(), 'b:s1').onclick();
  assert.deepEqual(h.calls.filter((c) => c[0] === 'openEdit'), [['openEdit', 's2'], ['openEdit', 's1']]);
  byKey(h.flow(), 't:chain:c1').onclick();
  assert.deepEqual(h.calls.filter((c) => c[0] === 'view'), [['view', 'chain']]);
  assert.equal(hasClass(card, 'flash'), true);
  byKey(h.flow(), 't:direct').onclick();
  assert.equal(hasClass(rules.children[2], 'flash'), true, 'direct has no editor: the first rule that sends there');
  // a gone base: its picker
  h.state.servers = h.state.servers.filter((x) => x.id !== 's1');
  h.ctx.renderFlowTree();
  byKey(h.flow(), 'b:s1').onclick();
  assert.equal(hasClass(h.page.get('advBaseRow'), 'flash'), true);
  assert.equal(h.calls.filter((c) => c[0] === 'openEdit').length, 2, 'nothing to edit for a server that is gone');
});

test('each branch shows its live speed — only while that profile is the one connected', () => {
  const per = {
    'out-s2@s1': { up: 2048, down: 4096, upSpeed: 1024, downSpeed: 2048 },
    'base-s1': { up: 9000, down: 9000, upSpeed: 3072, downSpeed: 5120 },
    'out-s1': { up: 1, down: 1, upSpeed: 0, downSpeed: 0 }
  };
  const live = treeHarness({ connected: true, activeServerId: '__advanced__:rp-work' });
  live.ctx.renderFlowTree();
  live.ctx.applyFlowTraffic(per);
  assert.equal(byKey(live.flow(), 't:s2@s1').querySelector('.rf-traffic').textContent, '↓2.0 KB/s ↑1.0 KB/s');
  assert.equal(byKey(live.flow(), 't:s2@s1').querySelector('.rf-traffic').title, '↓4.0 KB ↑2.0 KB');
  assert.equal(byKey(live.flow(), 'b:s1').querySelector('.rf-traffic').textContent, '↓5.0 KB/s ↑3.0 KB/s');
  assert.equal(byKey(live.flow(), 't:s3@s1').querySelector('.rf-traffic').textContent, '', 'nothing reported: nothing shown');
  assert.equal(hasClass(live.flow().children[0], 'live'), true);
  assert.equal(live.page.get('rpFlowLive').hidden, false);
  // plain "__advanced__" connected: that is the FIRST profile, not this one
  const other = treeHarness({ connected: true, activeServerId: '__advanced__' });
  other.ctx.renderFlowTree();
  other.ctx.applyFlowTraffic(per);
  assert.equal(byKey(other.flow(), 't:s2@s1').querySelector('.rf-traffic').textContent, '');
  assert.equal(hasClass(other.flow().children[0], 'live'), false);
  assert.equal(other.page.get('rpFlowLive').hidden, true);
  const first = treeHarness({ connected: true, activeServerId: '__advanced__', profileSel: 'rp-default' });
  first.ctx.renderFlowTree();
  first.ctx.applyFlowTraffic({ 'out-s2': { up: 0, down: 0, upSpeed: 0, downSpeed: 1024 } });
  assert.equal(byKey(first.flow(), 't:s2').querySelector('.rf-traffic').textContent, '↓1.0 KB/s ↑0 B/s');
  // disconnected: nothing live
  const idle = treeHarness();
  idle.ctx.renderFlowTree();
  idle.ctx.applyFlowTraffic(per);
  assert.equal(byKey(idle.flow(), 't:s2@s1').querySelector('.rf-traffic').textContent, '');
  // the wiring: the stats tick, and every status change (renderTrafficPath)
  assert.match(APP, /if \(s\.per\) applyPathTraffic\(s\.per\);\n[^\n]*\n\s*if \(s\.per\) applyFlowTraffic\(s\.per\);/);
  assert.match(fnSource('renderTrafficPath'), /applyPathTraffic\(lastPerOutbound\);\n[^\n]*\n\s*applyFlowTraffic\(lastPerOutbound\);/);
});

/* ------------------------------------ the routing page ------------------------------------ */

function pageHarness(over = {}) {
  const s = store();
  const page = fakePage();
  const calls = [];
  const selects = [];
  const state = Object.assign({ servers: s.servers, chains: s.chains, pool: [], settings: { advancedRouting: true, routingMode: 'global' },
    profiles: [s.def, s.work], profileSel: 'rp-work', connected: false, activeServerId: null, procList: [], pendingReconnect: [] }, over);
  const ctx = compile([...MODEL_FNS, 'advDraft', 'renderAdvanced', 'renderProfileBar', 'renderProfileExtras', 'viaOptionList', 'baseOptionList',
    'targetOptionList', 'spanIn', 'profileLive', 'escapeHtml'], {
    state, t: en, $: page.$, $$: page.$$, document: page.document,
    makeSearchSelect: (o) => {
      const el = fakeEl('div');
      el.className = 'ss';
      el.opts = o;
      el.getValue = () => (el.picked !== undefined ? el.picked : o.value);
      el.pick = (v) => { el.picked = v; if (o.onChange) o.onChange(v); };
      selects.push(el);
      return el;
    },
    renderFlowTree: () => calls.push(['tree']),
    renderFlowSoon: () => calls.push(['treeSoon']),
    renderDefaultSuggest: () => {}, wgSuggestEl: () => null, wgOfTarget: () => null, processOptions: () => '', loadProcList: () => {},
    String, Array, Object, JSON, Math, Set
  }, PRELUDE_CONSTS + 'let rpDraft = null; let advDefaultSel = null;');
  return { ctx, state, page, calls, selects, s, el: page.get };
}
const ruleRows = (h) => h.el('advRules').children.filter((c) => hasClass(c, 'adv-rule'));

test('the routing page with profiles: the list (★ the default), the edited one’s head, its rules each with a via picker on a proxy target', () => {
  const h = pageHarness();
  h.ctx.renderAdvanced();
  assert.equal(h.el('rpBar').hidden, false);
  assert.equal(h.el('rpHead').hidden, false);
  assert.equal(h.el('advEditor').hidden, false);
  const tabs = h.el('rpList').children;
  assert.deepEqual(tabs.map((b) => b.querySelector('.rp-tab-name').textContent), ['Advanced routing', 'Work']);
  assert.deepEqual(tabs.map((b) => hasClass(b, 'active')), [false, true]);
  assert.deepEqual(tabs.map((b) => b.getAttribute('aria-selected')), ['false', 'true']);
  assert.ok(tabs[0].querySelector('.rp-tab-def'), 'the first is the default');
  assert.equal(tabs[1].querySelector('.rp-tab-def'), null);
  assert.equal(h.el('rpName').value, 'Work');
  assert.equal(h.el('rpDefBadge').hidden, true, 'Work is not the default…');
  assert.equal(h.el('btnRpDefault').hidden, false, '…and can be made it');
  assert.equal(h.el('btnRpDel').disabled, false);
  assert.equal(h.el('btnRpShare').getAttribute('aria-label'), 'Copy link');

  const rows = ruleRows(h);
  assert.equal(rows.length, 5);
  assert.deepEqual(rows.map((r) => r.dataset.idx), ['0', '1', '2', '3', '4'], 'the tree opens a row by its index');
  assert.deepEqual(rows.map((r) => /adv-via-mount/.test(r.innerHTML)), [true, true, false, false, true], 'direct never takes a via');
  const via0 = rows[0].querySelector('.adv-via-mount').children[0];
  assert.equal(via0.opts.value, 'inherit');
  assert.deepEqual(plain(via0.opts.options.slice(0, 2)), [{ value: 'inherit', label: 'The routing’s base (🇩🇪 Base DE)' }, { value: 'none', label: 'Directly — no base' }]);
  assert.ok(!via0.opts.options.some((o) => o.value === 's2'), 'a target is never its own via');
  assert.ok(via0.opts.options.some((o) => o.value === 'chain:c1') && via0.opts.options.some((o) => o.value === 's1'));
  assert.ok(!via0.opts.options.some((o) => o.value === 'direct' || o.value === 'block'));
  const via4 = rows[4].querySelector('.adv-via-mount').children[0];
  assert.equal(via4.opts.value, 'none');
  // a via picked lands in the draft (the rule edits wait for Save)
  via0.pick('s4');
  assert.equal(h.ctx.advDraft().rules[0].via, 's4');
  assert.equal(h.state.profiles[1].rules[0].via, 'inherit', 'the saved profile is untouched until Save');

  // the default target, its via and the base, next to each other
  assert.equal(h.el('advDefVia').hidden, false);
  const defVia = h.el('advDefViaMount').children[0];
  assert.equal(defVia.opts.value, 'none');
  assert.equal(h.el('advBaseRow').hidden, false);
  const base = h.el('advBaseMount').children[0];
  assert.equal(base.opts.value, 's1');
  assert.deepEqual(plain(base.opts.options[0]), { value: '', label: 'No base' });
  base.pick('');
  assert.equal(h.ctx.advDraft().base, null);
  const inheritNow = ruleRows(h)[1].querySelector('.adv-via-mount').children[0];
  assert.equal(inheritNow.opts.options[0].label, 'The routing’s base (none set)', 'the inherit label follows the base');
  assert.ok(h.calls.filter((c) => c[0] === 'tree').length >= 2, 'the tree follows every render');
});

test('a direct default has no via; a gone base or target marks its rule and the base row in the danger colour', () => {
  const h = pageHarness();
  h.state.profiles[1] = Object.assign({}, h.state.profiles[1], { def: 'direct' });
  h.state.servers = h.state.servers.filter((x) => x.id !== 's1');
  h.ctx.renderAdvanced();
  assert.equal(h.el('advDefVia').hidden, true);
  const rows = ruleRows(h);
  assert.equal(hasClass(rows[0], 'danger'), true);
  const warn = h.el('advRules').children.filter((c) => hasClass(c, 'adv-warn'));
  assert.equal(warn.length, 2, 'the two rules through the gone base');
  assert.equal(warn[0].textContent, '⚠ ' + en('rp.why.baseGone'));
  assert.equal(hasClass(rows[2], 'danger'), false);
  assert.equal(h.el('advBaseWhy').hidden, false);
  const base = h.el('advBaseMount').children[0];
  assert.ok(base.opts.options.some((o) => o.value === 's1' && /^⚠ /.test(o.label)), 'the gone base stays shown, marked');
  assert.equal(hasClass(h.el('rpList').children[1], 'danger'), true, 'its tab too');
});

test('a back end without profiles: today’s routing page — no list, no via, no base, the rules from the settings', () => {
  const h = pageHarness({ profiles: null, settings: { advancedRouting: true, routeRules: [{ type: 'domain', value: 'a.example', target: 's2' }], routeDefault: 's1' } });
  for (const id of ['rpBar', 'rpHead', 'advDefVia', 'advBaseRow']) h.el(id).hidden = true;
  h.ctx.renderAdvanced();
  assert.equal(h.el('rpBar').hidden, true);
  assert.equal(h.el('rpHead').hidden, true);
  assert.equal(h.el('advEditor').hidden, false);
  assert.equal(h.el('advDefVia').hidden, true);
  assert.equal(h.el('advBaseRow').hidden, true);
  const rows = ruleRows(h);
  assert.equal(rows.length, 1);
  assert.doesNotMatch(rows[0].innerHTML, /adv-via/);
  assert.equal(h.el('advRules').children.filter((c) => hasClass(c, 'adv-warn')).length, 0);
  assert.equal(h.selects.find((x) => x.opts.value === 's1').opts.options.length, h.state.servers.length + 1 + 2, 'the default picker as today');
});

test('profiles but none left: the list and its “New routing” stay, the editor goes', () => {
  const h = pageHarness({ profiles: [] });
  h.ctx.renderAdvanced();
  assert.equal(h.el('rpBar').hidden, false);
  assert.equal(h.el('rpEmpty').hidden, false);
  assert.equal(h.el('rpHead').hidden, true);
  assert.equal(h.el('advEditor').hidden, true);
  assert.equal(ruleRows(h).length, 0);
});

/* ------------------------------------ the list's operations ------------------------------------ */

function opsHarness({ reply, confirm = () => true, connected = false } = {}) {
  const s = store();
  const calls = [];
  const state = { servers: s.servers, chains: s.chains, pool: [], settings: { advancedRouting: true }, profiles: [s.def, s.work].map((p) => JSON.parse(JSON.stringify(p))),
    profileSel: 'rp-work', connected, pendingReconnect: [] };
  const page = fakePage();
  page.get('optAdvUseMode').checked = false;
  const ctx = compile(['normalizeUiProfile', 'terminalTarget', 'advDraft', 'draftKey', 'draftDirty', 'confirmDiscardDraft', 'persistProfiles', 'patchProfile',
    'saveProfileDraft', 'addProfile', 'renameProfile', 'duplicateProfile', 'deleteProfile', 'makeDefaultProfile', 'selectProfileForEdit',
    'uniqueProfileName', 'newProfileId'], {
    state, t: en, $: page.$,
    window: {
      confirm: (msg) => { calls.push(['confirm', msg]); return confirm(msg); },
      api: {
        setRoutingProfiles: async (list) => {
          calls.push(['set', plain(list)]);
          return reply ? reply(list) : { ok: true, profiles: list, pendingReconnect: [] };
        }
      }
    },
    toast: (msg, kind) => calls.push(['toast', msg, kind || '']),
    setPending: (keys) => { state.pendingReconnect = keys; calls.push(['pending', plain(keys)]); },
    promptApplySettings: async () => calls.push(['prompt']),
    afterProfilesChanged: () => calls.push(['rendered']),
    renderAdvanced: () => calls.push(['renderAdvanced']), renderProfileBar: () => calls.push(['bar']),
    String, Array, Object, JSON, Math, Set, Date
  }, PRELUDE_CONSTS + 'let rpDraft = null; let advDefaultSel = null;');
  const sets = () => calls.filter((c) => c[0] === 'set').map((c) => c[1]);
  return { ctx, state, calls, sets, page };
}

test('add, duplicate, rename, make default, delete — each written at once through routing:setProfiles', async () => {
  const h = opsHarness();
  await h.ctx.addProfile();
  let list = h.sets().pop();
  assert.equal(list.length, 3);
  const added = list[2];
  assert.match(added.id, /^rp-[a-z0-9]+$/, 'rp-<base36 time><rand>');
  assert.match(added.id, /^[\w-]+$/);
  assert.equal(added.name, 'Routing 3');
  assert.equal(added.def, 's1', 'a default from the start: it shows in the picker');
  assert.deepEqual([added.rules, added.defVia, added.useMode, added.base], [[], 'inherit', false, null]);
  assert.equal(h.state.profileSel, added.id, 'the new one is edited next');

  await h.ctx.duplicateProfile('rp-work');
  list = h.sets().pop();
  assert.deepEqual(list.map((p) => p.name), ['Advanced routing', 'Work', 'Work (2)', 'Routing 3'], 'right after the original');
  assert.notEqual(list[2].id, 'rp-work');
  assert.deepEqual(list[2].rules, list[1].rules);
  assert.equal(list[2].base, 's1');
  await h.ctx.duplicateProfile('rp-work');
  assert.equal(h.sets().pop()[2].name, 'Work (3)');

  h.state.profileSel = 'rp-work';
  await h.ctx.renameProfile('rp-work', '  Advanced routing ');
  assert.equal(h.sets().pop().find((p) => p.id === 'rp-work').name, 'Advanced routing (2)', 'names stay apart in the picker');
  assert.equal(h.page.get('rpName').value, 'Advanced routing (2)', 'the field shows the name it got');
  const before = h.sets().length;
  await h.ctx.renameProfile('rp-work', '   ');
  assert.equal(h.sets().length, before, 'an empty name is not a rename');

  await h.ctx.makeDefaultProfile('rp-work');
  assert.equal(h.sets().pop()[0].id, 'rp-work', 'the default is the first');
  const n = h.sets().length;
  await h.ctx.makeDefaultProfile('rp-work');
  assert.equal(h.sets().length, n, 'already the default: nothing written');
});

test('delete asks first, names the profile, and never takes the last one', async () => {
  let answer = false;
  const h = opsHarness({ confirm: () => answer });
  await h.ctx.deleteProfile('rp-work');
  assert.equal(h.sets().length, 0, 'cancelled: nothing written');
  assert.equal(h.calls.find((c) => c[0] === 'confirm')[1], 'Delete the routing “Work”? Its rules go with it; the servers and chains stay.');
  answer = true;
  await h.ctx.deleteProfile('rp-work');
  assert.deepEqual(h.sets().pop().map((p) => p.id), ['rp-default']);
  assert.equal(h.state.profileSel, 'rp-default');
  const confirms = h.calls.filter((c) => c[0] === 'confirm').length;
  await h.ctx.deleteProfile('rp-default');
  assert.equal(h.sets().length, 1, 'the last one stays');
  assert.equal(h.calls.filter((c) => c[0] === 'confirm').length, confirms, 'without even asking');
  assert.deepEqual(h.calls.pop(), ['toast', en('rp.lastOne'), 'warn']);
});

test('Save writes the draft: rules trimmed and the empty ones dropped, vias kept only where they mean something, the base, the default and its via', async () => {
  const h = opsHarness();
  const d = h.ctx.advDraft();
  d.rules[0].value = '  corp.example  ';
  d.rules[3].via = 's4';                       // a direct rule: no via
  d.rules.push({ type: 'ip', value: '', target: 's2' });
  d.rules.push({ type: 'port', value: '8443', target: 'chain:c1', via: 's2' });
  d.base = 'chain:c1';
  d.defVia = 'inherit';
  assert.equal(h.ctx.draftDirty(), true);
  const saved = await h.ctx.saveProfileDraft();
  assert.equal(saved.length, 6);
  const work = h.sets().pop().find((p) => p.id === 'rp-work');
  assert.deepEqual(work, {
    id: 'rp-work', name: 'Work', useMode: false, base: 'chain:c1', def: 's1', defVia: 'inherit',
    rules: [
      { type: 'domain', value: 'corp.example', target: 's2' },
      { type: 'domain', value: 'geosite:netflix', target: 's3' },
      { type: 'domain', value: 'geosite:category-ir', target: 'direct' },
      { type: 'ip', value: 'geoip:ir', target: 'direct' },
      { type: 'port', value: '5060', target: 'chain:c1', via: 'none' },
      { type: 'port', value: '8443', target: 'chain:c1', via: 's2' }
    ]
  });
  assert.equal(h.ctx.draftDirty(), false, 'the draft is what was saved');
  assert.ok(h.calls.some((c) => c[0] === 'rendered'));
});

test('a refused save keeps the draft and says why; a save of the live profile offers the reconnect once', async () => {
  const bad = opsHarness({ reply: () => ({ ok: false, error: 'base gone' }) });
  bad.ctx.advDraft().rules.pop();
  assert.equal(await bad.ctx.saveProfileDraft(), null);
  assert.deepEqual(bad.calls.pop(), ['toast', 'Failed: base gone', 'err']);
  assert.equal(bad.state.profiles[1].rules.length, 5, 'nothing changed');
  assert.equal(bad.ctx.draftDirty(), true, 'the edit is still there to fix and save');

  const live = opsHarness({ connected: true, reply: (list) => ({ ok: true, profiles: list, pendingReconnect: ['routingProfiles'] }) });
  live.ctx.advDraft().rules.pop();
  await live.ctx.saveProfileDraft();
  assert.deepEqual(live.calls.filter((c) => c[0] === 'pending' || c[0] === 'prompt'), [['pending', ['routingProfiles']], ['prompt']]);
  live.ctx.advDraft().rules.pop();
  await live.ctx.saveProfileDraft();
  assert.equal(live.calls.filter((c) => c[0] === 'prompt').length, 1, 'already pending: the banner is the reminder');
});

test('leaving a profile with unsaved edits asks first; a rename and “apply the routing mode” are saved at once and leave the draft alone', async () => {
  let answer = false;
  const h = opsHarness({ confirm: () => answer });
  h.ctx.advDraft().rules.pop();
  h.ctx.selectProfileForEdit('rp-default');
  assert.equal(h.state.profileSel, 'rp-work', 'cancelled');
  assert.equal(h.calls.filter((c) => c[0] === 'confirm')[0][1], en('rp.discard'));
  await h.ctx.patchProfile('rp-work', { useMode: true });
  assert.equal(h.sets().pop().find((p) => p.id === 'rp-work').useMode, true);
  assert.equal(h.ctx.advDraft().rules.length, 4, 'the unsaved rule edit is still in the draft');
  assert.equal(h.ctx.advDraft().useMode, true);
  answer = true;
  h.ctx.selectProfileForEdit('rp-default');
  assert.equal(h.state.profileSel, 'rp-default');
  assert.equal(h.ctx.advDraft().id, 'rp-default');
});

/* ------------------------------------ the home picker ------------------------------------ */

function pickerHarness({ profiles, selected, settings = { advancedRouting: true } }) {
  const s = store();
  const els = new Map();
  const $ = (sel) => { if (!els.has(sel)) els.set(sel, fakeEl('div')); return els.get(sel); };
  const menu = $('#pickerMenu');
  const rows = [];
  const picked = [];
  const ctx = compile(['renderPicker', 'profileOfSel', 'profileReady', 'advSelName', 'advancedReady'], {
    state: { servers: s.servers.slice(0, 1), subscriptions: [], chains: [], pool: [], settings, pings: {}, selectedServerId: selected, connecting: false, profiles },
    $, document: { createElement: (tag) => { const e = fakeEl(tag); rows.push(e); return e; } },
    t: en, escapeHtml: (x) => String(x),
    keepSelectionValid: () => {}, serverGroups: () => [],
    chainById: () => undefined, anyChainReady: () => false, poolReady: () => false, poolEnabledValid: () => [],
    pingLabel: () => ({ txt: '—', cls: '' }), pingResultLabel: () => ({ txt: '—', cls: '' }),
    closePicker: () => {}, connectAuto: () => {}, selectServer: (id) => picked.push(id), pingServer: () => {}, pingAllVisible: () => {},
    String, Array
  }, PRELUDE_CONSTS);
  ctx.renderPicker();
  const items = menu.children.filter((c) => hasClass(c, 'picker-item'));
  return { ctx, $, items, picked, adv: items.filter((c) => /proto-advanced/.test(c.innerHTML)) };
}

test('the home picker: one “🧭 <name>” row per profile with rules or a default, each selecting "__advanced__:<id>"', () => {
  const s = store();
  const empty = { id: 'rp-empty', name: 'Empty', rules: [], def: '', defVia: 'inherit', useMode: false, base: null };
  const h = pickerHarness({ profiles: [s.def, empty, s.work], selected: 's1' });
  assert.equal(h.adv.length, 2);
  assert.match(h.adv[0].innerHTML, /<span class="proto-badge proto-advanced">🧭<\/span><span class="pi-name">Advanced routing<\/span>/);
  assert.match(h.adv[1].innerHTML, /<span class="pi-name">Work<\/span>/);
  h.adv[1].onclick();
  h.adv[0].onclick();
  assert.deepEqual(h.picked, ['__advanced__:rp-work', '__advanced__:rp-default']);
  // the old plain selection marks the first profile's row, and the button names it
  const old = pickerHarness({ profiles: [s.def, s.work], selected: '__advanced__' });
  assert.deepEqual(old.adv.map((r) => hasClass(r, 'active')), [true, false]);
  assert.equal(old.$('#pickerName').textContent, 'Advanced routing');
  assert.equal(old.$('#pickerProto').textContent, '🧭');
  const named = pickerHarness({ profiles: [s.def, s.work], selected: '__advanced__:rp-work' });
  assert.deepEqual(named.adv.map((r) => hasClass(r, 'active')), [false, true]);
  assert.equal(named.$('#pickerName').textContent, 'Work');
  // the switch is off: no rows
  assert.equal(pickerHarness({ profiles: [s.def, s.work], selected: 's1', settings: {} }).adv.length, 0);
});

test('the home picker without profiles: today’s single “Advanced routing” row on "__advanced__"', () => {
  const h = pickerHarness({ profiles: null, selected: 's1', settings: { advancedRouting: true, routeRules: [{ type: 'ip', value: 'x', target: 's1' }] } });
  assert.equal(h.adv.length, 1);
  assert.match(h.adv[0].innerHTML, /<span class="pi-name">Advanced routing<\/span>/);
  h.adv[0].onclick();
  assert.deepEqual(h.picked, ['__advanced__']);
});

test('the rest of the window knows a profile selection: no ping for it, its name on Home, its plan in the live check', () => {
  assert.match(fnSource('quickPing'), /if \(!id \|\| id === ADV_ID \|\| id === POOL_ID \|\| String\(id\)\.startsWith\(ADV_ID \+ ':'\)\) return;/);
  assert.match(fnSource('selectServer'), /!String\(id\)\.startsWith\(ADV_ID \+ ':'\)/);
  assert.match(fnSource('setConnUI'), /\} else if \(effId === ADV_ID \|\| String\(effId\)\.startsWith\(ADV_ID \+ ':'\)\) \{\n\s*srv\.textContent = '🧭 ' \+ advSelName\(effId\);/);
  assert.match(fnSource('isPseudo'), /String\(id\)\.startsWith\(ADV_ID \+ ':'\)/);

  // an edit of a server the live profile dials — as a target, a via, or its base — is an edit of the live plan
  const s = store();
  const extra = { id: 'rp-x', name: 'X', rules: [{ type: 'ip', value: 'x', target: 's3', via: 's2' }], def: 'direct', defVia: 'inherit', base: null };
  const state = { servers: s.servers.concat([{ id: 's9' }]), chains: s.chains, chain: [], pool: [], settings: {}, profiles: [s.def, s.work, extra], connected: true, activeServerId: '__advanced__:rp-work' };
  const ctx = compile(['serverInLivePlan', 'profileOfSel'], { state, String, Array }, PRELUDE_CONSTS);
  assert.equal(ctx.serverInLivePlan('s1'), true, 'the base');
  assert.equal(ctx.serverInLivePlan('s4'), true, 'a hop of the chain target');
  assert.equal(ctx.serverInLivePlan('s9'), false);
  state.activeServerId = '__advanced__:rp-x';
  assert.equal(ctx.serverInLivePlan('s2'), true, 'an explicit via');
  assert.equal(ctx.serverInLivePlan('s1'), false);
  state.activeServerId = '__advanced__';
  assert.equal(ctx.serverInLivePlan('s2'), true, 'plain "__advanced__": the first profile');
  assert.equal(ctx.serverInLivePlan('s3'), false);
});

/* ------------------------------------ the home path ------------------------------------ */

test('the home screen’s small path: a profile’s lines say “via <base>” and count the outbound through it', () => {
  const s = store();
  const page = fakePage();
  page.get('statIp').textContent = '—';
  const ctx = compile(['renderTrafficPath', 'pathRule', 'pathNode', 'pathLink', 'trafficSpan', 'targetLabel', 'outboundTagFor', 'baseKeyOf', 'viaTagFor',
    'profileOfSel', 'ruleVia', 'terminalTarget', 'chainById', 'chainMembers', 'srvById'], {
    state: { servers: s.servers, chains: s.chains, pool: [], settings: { tunMode: false, routeRules: [], routeDefault: 'direct' },
      profiles: [s.def, s.work], selectedServerId: '__advanced__:rp-work', activeServerId: null },
    t: en, $: page.$, document: page.document,
    applyPathTraffic: () => {}, applyFlowTraffic: () => {}, poolEnabledValid: () => [],
    String, Array, Object
  }, PRELUDE_CONSTS + 'let lastPerOutbound = {};');
  ctx.renderTrafficPath('disconnected');
  const host = page.get('trafficPath');
  const rules = host.children.find((c) => hasClass(c, 'path-rules'));
  const lines = rules.children;
  assert.equal(lines.length, 6, 'four rules, "+1 more", the default');
  const via = (row) => row.children.find((c) => hasClass(c, 'pr-via'));
  const tags = (row) => row.children.find((c) => hasClass(c, 'pr-traffic')).dataset.tags;
  assert.equal(via(lines[0]).textContent, 'via 🇩🇪 Base DE');
  assert.equal(tags(lines[0]), 'out-s2@s1');
  assert.equal(via(lines[2]), undefined, 'direct: no via');
  assert.equal(tags(lines[2]), 'direct');
  const def = lines[5];
  assert.equal(hasClass(def, 'is-default'), true);
  assert.equal(via(def), undefined, 'the default dials s1 itself (defVia none)');
  assert.equal(tags(def), 'out-s1');
  // the plain selection draws the first profile
  ctx.state.selectedServerId = '__advanced__';
  ctx.renderTrafficPath('disconnected');
  const first = page.get('trafficPath').children.find((c) => hasClass(c, 'path-rules')).children;
  assert.equal(first.length, 2);
  assert.equal(tags(first[0]), 'out-s2');
});

/* ------------------------------------ share ------------------------------------ */

function shareHarness(reply) {
  const page = fakePage();
  const calls = [];
  const ctx = compile(['shareRouting', 'openShareModal', 'shareQrFits', 'escapeHtml', 'draftDirty', 'draftKey', 'normalizeUiProfile', 'terminalTarget'], {
    state: { profiles: [] }, t: en, $: page.$,
    window: {
      api: {
        shareRoutingProfile: async (id) => { calls.push(['shareProfile', id]); return reply(id); },
        shareChain: async (id) => { calls.push(['shareChain', id]); return reply(id); }
      }
    },
    qrcode: () => {
      let data = '';
      return { addData: (x) => { data = x; }, make: () => {}, createSvgTag: () => { calls.push(['qr', data]); return '<svg class="qr"></svg>'; } };
    },
    toast: (msg, kind) => calls.push(['toast', msg, kind || '']),
    String, Array, Number, JSON, Object
  }, PRELUDE_CONSTS + 'let rpDraft = null;');
  page.get('rpShareModal').hidden = true;   // as the page starts
  return { ctx, page, calls, el: page.get };
}

test('Copy link: the warning that server details are inside, a QR when the link is ≤ 1,700 bytes, the link to copy', async () => {
  const h = shareHarness(() => ({ ok: true, link: LINK, bytes: LINK.length, servers: [{}, {}, {}, {}] }));
  await h.ctx.shareRouting('profile', 'rp-work');
  assert.deepEqual(h.calls[0], ['shareProfile', 'rp-work']);
  assert.equal(h.el('rpShareModal').hidden, false);
  assert.equal(h.el('rpShareTitle').textContent, 'Share routing');
  assert.equal(h.el('rpShareWarn').textContent, '⚠ This link carries 4 server(s) in full — addresses, keys and passwords. Share it only with people you trust.');
  assert.deepEqual(h.calls.find((c) => c[0] === 'qr'), ['qr', LINK], 'the fixture link (804 bytes) is QR-coded');
  assert.equal(h.el('rpShareLink').value, LINK);

  // a chain's
  const c = shareHarness(() => ({ ok: true, link: 'irnetfree://routing/abc', servers: 2 }));
  await c.ctx.shareRouting('chain', 'c1');
  assert.deepEqual(c.calls[0], ['shareChain', 'c1']);
  assert.equal(c.el('rpShareTitle').textContent, 'Share chain');
  assert.match(c.el('rpShareWarn').textContent, /carries 2 server/);

  // the limit, both sides of it
  const at = 'irnetfree://routing/' + 'A'.repeat(1700 - 20);
  const over = at + 'A';
  const ok = shareHarness(() => ({ ok: true, link: at, servers: 1 }));
  await ok.ctx.shareRouting('profile', 'p');
  assert.ok(ok.calls.some((x) => x[0] === 'qr'), '1,700 bytes: a QR');
  const big = shareHarness(() => ({ ok: true, link: over, servers: 1 }));
  await big.ctx.shareRouting('profile', 'p');
  assert.ok(!big.calls.some((x) => x[0] === 'qr'), '1,701 bytes: no QR');
  assert.match(big.el('rpShareQr').innerHTML, new RegExp(en('qr.tooBig').replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  assert.equal(big.el('rpShareLink').value, over, 'Copy still has it');
  assert.equal(big.ctx.shareQrFits(at), true);
  assert.equal(big.ctx.shareQrFits(over), false);

  // refused
  const no = shareHarness(() => ({ ok: false, error: 'no such profile' }));
  await no.ctx.shareRouting('profile', 'gone');
  assert.equal(no.el('rpShareModal').hidden, true, 'no dialog for a link that was not made');
  assert.deepEqual(no.calls.pop(), ['toast', 'Failed: no such profile', 'err']);
  // the wiring: the chain card's button, the profile head's, the Copy
  assert.match(APP, /if \(shareBtn\) shareBtn\.onclick = \(\) => \{ if \(ready\) shareRouting\('chain', chain\.id\); \};/);
  assert.match(APP, /\$\('#btnRpShare'\)\.onclick = \(\) => shareRouting\('profile', state\.profileSel\);/);
  assert.match(APP, /\$\('#rpShareCopy'\)\.onclick = \(\) => \{ copyText\(\$\('#rpShareLink'\)\.value\); toast\(t\('t\.copied'\), 'ok'\); \};/);
  // the chain card offers it only with profiles (the same back end writes both)
  assert.match(fnSource('renderChains'), /const share = Array\.isArray\(state\.profiles\)/);
});

/* ------------------------------------ import ------------------------------------ */

function importHarness({ preview, imported, after = {} } = {}) {
  const s = store();
  const page = fakePage();
  const calls = [];
  const state = { servers: [], chains: [], subscriptions: [], selectedServerId: null, settings: { advancedRouting: true }, profiles: [s.def], profileSel: 'rp-default' };
  const ctx = compile(['smartImport', 'looksLikeJsonText', 'importErrorReason', 'openRoutingImport', 'renderImportSummary', 'runRoutingImport', 'closeRoutingImport',
    'refreshAfterImport', 'importCount', 'importNames', 'spanIn', 'loadRoutingProfiles', 'normalizeUiProfile', 'terminalTarget', 'draftDirty', 'draftKey'], {
    state, t: en, $: page.$, document: page.document,
    window: {
      api: {
        importServers: async (text) => { calls.push(['importServers', text]); return { servers: [], added: 0, errors: [] }; },
        routingImportPreview: async (text) => { calls.push(['preview', text]); if (preview instanceof Error) throw preview; return preview; },
        routingImport: async (text) => { calls.push(['import', text]); return imported; },
        listServers: async () => { calls.push(['listServers']); return after.servers || s.servers; },
        listChains: async () => { calls.push(['listChains']); return after.chains || s.chains; },
        routingProfiles: async () => { calls.push(['routingProfiles']); return { profiles: after.profiles || [s.def, s.work] }; }
      }
    },
    toast: (msg, kind) => calls.push(['toast', msg, kind || '']),
    renderServers: () => calls.push(['render', 'servers']), renderPicker: () => calls.push(['render', 'picker']), renderSubs() {},
    renderChains: () => calls.push(['render', 'chains']), renderPool: () => calls.push(['render', 'pool']),
    renderAdvanced: () => calls.push(['render', 'advanced']), refreshConnLabels: () => {},
    showView: (v) => calls.push(['view', v]),
    String, Array, Object, JSON, Number
  }, PRELUDE_CONSTS + constSource('HTTP_PROXY_LINK') + "let rpDraft = null; let rpImportText = '';");
  page.get('rpImportModal').hidden = true;   // as the page starts
  return { ctx, state, page, calls, el: page.get };
}
const SUMMARY = { kind: 'profile', name: 'Work', rules: 5, chains: 1, serversNew: 2, serversExisting: 2, unreadable: [] };

test('a pasted or added irnetfree://routing/ link opens its preview — never the server import — and Import writes it and refreshes the lists', async () => {
  const h = importHarness({ preview: { ok: true, summary: SUMMARY }, imported: { ok: true, profileId: 'rp-work', added: { servers: 2, chains: 1, profiles: 1 } } });
  await h.ctx.smartImport('  ' + LINK + '\n');
  assert.deepEqual(h.calls[0], ['preview', LINK]);
  assert.ok(!h.calls.some((c) => c[0] === 'importServers' || c[0] === 'import'), 'nothing written before the preview is accepted');
  assert.equal(h.el('rpImportModal').hidden, false);
  const rows = h.el('rpImportSum').children;
  assert.deepEqual(rows.map((r) => [r.querySelector('.rp-im-k').textContent, r.querySelector('.rp-im-v').textContent]), [
    ['What', 'Routing'], ['Name', 'Work'], ['Rules', '5'], ['Chains', '1'], ['Servers already here (reused)', '2'], ['New servers', '2']
  ]);

  const ok = await h.ctx.runRoutingImport();
  assert.equal(ok, true);
  assert.deepEqual(h.calls.find((c) => c[0] === 'import'), ['import', LINK]);
  assert.equal(h.el('rpImportModal').hidden, true);
  for (const c of ['listServers', 'listChains', 'routingProfiles']) assert.ok(h.calls.some((x) => x[0] === c), `${c} refreshed`);
  assert.equal(h.state.servers.length, 4);
  assert.deepEqual(plain(h.state.chains), [{ id: 'c1', name: 'NL→US', members: ['s4', 's3'] }]);
  assert.deepEqual(h.state.profiles.map((p) => p.id), ['rp-default', 'rp-work']);
  assert.equal(h.state.profileSel, 'rp-work', 'the imported routing is the one shown');
  for (const r of ['servers', 'picker', 'chains', 'pool', 'advanced']) assert.ok(h.calls.some((c) => c[0] === 'render' && c[1] === r), `${r} redrawn`);
  assert.ok(h.calls.some((c) => c[0] === 'view' && c[1] === 'routing'));
  assert.deepEqual(h.calls.filter((c) => c[0] === 'toast').pop(), ['toast', 'Imported: 2 server(s), 1 chain(s), 1 routing(s)', 'ok']);
  assert.equal(await h.ctx.runRoutingImport(), false, 'once');
});

test('the preview lists what could not be read, in the danger colour; a chain link shows no rules', async () => {
  const sum = Object.assign({}, SUMMARY, { serversNew: [{ key: 's3', name: 'Netflix US' }], unreadable: [{ key: 's9', name: 'Odd', error: 'unsupported protocol: tuic' }] });
  const h = importHarness({ preview: { ok: true, summary: sum } });
  await h.ctx.openRoutingImport(LINK);
  const rows = h.el('rpImportSum').children;
  const bad = rows[rows.length - 1];
  assert.equal(hasClass(bad, 'danger'), true);
  assert.equal(bad.querySelector('.rp-im-k').textContent, en('rp.imUnreadable'));
  assert.deepEqual(bad.querySelector('.rp-im-names').children.map((b) => [b.tagName, b.textContent]), [['BDI', 'Odd: unsupported protocol: tuic']]);
  const fresh = rows.find((r) => r.querySelector('.rp-im-k').textContent === 'New servers');
  assert.equal(fresh.querySelector('.rp-im-v').textContent, '1');
  assert.equal(fresh.querySelector('.rp-im-names').children[0].textContent, 'Netflix US');

  const chain = importHarness({ preview: { ok: true, summary: { kind: 'chain', name: 'NL→US', chains: 1, serversNew: 2, serversExisting: 0, unreadable: [] } } });
  await chain.ctx.openRoutingImport(LINK);
  const keys = chain.el('rpImportSum').children.map((r) => r.querySelector('.rp-im-k').textContent);
  assert.deepEqual(keys, ['What', 'Name', 'Chains', 'Servers already here (reused)', 'New servers']);
  assert.equal(chain.el('rpImportSum').children[0].querySelector('.rp-im-v').textContent, 'Chain');
});

test('malformed, oversized or unknown-version text is refused with its reason, and nothing is imported', async () => {
  for (const preview of [{ ok: false, error: 'unknown version 2' }, new Error('decoded text is larger than 64 KB'), { ok: true }]) {
    const h = importHarness({ preview });
    const opened = await h.ctx.openRoutingImport(LINK);
    assert.equal(opened, false);
    assert.equal(h.el('rpImportModal').hidden, true, 'no preview of what could not be read');
    const [, msg, kind] = h.calls.filter((c) => c[0] === 'toast').pop();
    assert.equal(kind, 'err');
    assert.ok(msg.startsWith('This routing link was not imported: '), msg);
    if (preview.error) assert.ok(msg.endsWith(preview.error), msg);
    if (preview instanceof Error) assert.ok(msg.endsWith(preview.message), msg);
    assert.equal(await h.ctx.runRoutingImport(), false);
    assert.ok(!h.calls.some((c) => c[0] === 'import'));
  }
  // the import itself refused
  const h = importHarness({ preview: { ok: true, summary: SUMMARY }, imported: { ok: false, error: 'store is read-only' } });
  await h.ctx.openRoutingImport(LINK);
  assert.equal(await h.ctx.runRoutingImport(), false);
  assert.deepEqual(h.calls.filter((c) => c[0] === 'toast').pop(), ['toast', 'This routing link was not imported: store is read-only', 'err']);
  assert.equal(h.el('rpImportModal').hidden, false, 'the preview stays up');
});

test('the add box, the paste handler and smartImport all know the link; other text takes its old paths', async () => {
  const paste = APP.split('\n').find((l) => l.includes('const looksImportable = '));
  assert.ok(paste.endsWith('|hy2:\\/\\/|irnetfree:\\/\\/routing\\/)/im.test(text.trim())'), 'the paste handler takes a routing link');
  assert.match(fnSource('smartImport'), /if \(\/\^irnetfree:\\\/\\\/routing\\\/\/i\.test\(text\)\) return openRoutingImport\(text\);/);
  assert.ok(fnSource('smartImport').indexOf('openRoutingImport') < fnSource('smartImport').indexOf('importServers'), 'checked before any other path');
  const h = importHarness({});
  await h.ctx.smartImport('vless://a@h:1#A');
  assert.deepEqual(h.calls.filter((c) => c[0] === 'preview' || c[0] === 'importServers'), [['importServers', 'vless://a@h:1#A']]);
  // the dialog's buttons
  assert.match(APP, /\$\('#rpImportGo'\)\.onclick = \(\) => runRoutingImport\(\);/);
  assert.match(APP, /\$\('#rpImportCancel'\)\.onclick = closeRoutingImport;/);
});
