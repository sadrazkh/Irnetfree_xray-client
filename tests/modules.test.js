'use strict';
/**
 * The extensions («افزونه‌ها», src/renderer/modules.js): the registry — the ids,
 * where each exists, what each needs —, what a store counts as in use, the
 * once-only migration (a store from before gets what it uses, a fresh one
 * none, asked twice the same), install / remove with what one needs and the
 * refusal while another needs it; the markup's data-module, the one CSS rule,
 * the server editor's fields, the strings in both languages at their anchor,
 * both DEFAULT_SETTINGS, main.js's wiring (read as text: Electron does not load
 * here) and the two bridges; and the config the builder writes with the
 * extensions off — byte for byte today's, multiWan built as disabled.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const MODS = require('../src/renderer/modules');
const B = require('../src/main/configBuilder');
const F = require('./fixtures');

const R = (...p) => fs.readFileSync(path.join(__dirname, '..', ...p), 'utf8').replace(/\r\n/g, '\n');
const HTML = R('src', 'renderer', 'index.html');
const MAIN = R('src', 'main', 'main.js');
const SVC = R('src', 'server', 'service.js');
const I18N = R('src', 'renderer', 'i18n.js');
const CSS = R('src', 'renderer', 'styles.css');

const IDS = ['chains', 'groups', 'warp', 'pool', 'advancedRouting', 'echOutbound', 'antiDpi', 'lanShare', 'multiWan', 'remoteRelay', 'lanUsers'];
const D = 'desktop', RT = 'router', AN = 'android';

/* ------------------------------------ the registry ------------------------------------ */

test('the registry: the contract’s eleven ids, where each exists, what each needs, an icon, a category and both languages', () => {
  assert.deepEqual(MODS.MODULES.map((m) => m.id), IDS);
  const where = Object.fromEntries(MODS.MODULES.map((m) => [m.id, m.platforms]));
  assert.deepEqual(where, {
    chains: [D, RT, AN], groups: [D, RT, AN], warp: [D, RT, AN], pool: [D, RT, AN], advancedRouting: [D, RT, AN],
    echOutbound: [D, RT, AN], antiDpi: [D, RT, AN], lanShare: [D, AN], multiWan: [D, RT], remoteRelay: [RT], lanUsers: [D, RT]
  });
  // only what truly depends: a WARP on WireGuard is made as a chain's exit
  assert.deepEqual(Object.fromEntries(MODS.MODULES.filter((m) => m.requires.length).map((m) => [m.id, m.requires])), { warp: ['chains'] });
  for (const m of MODS.MODULES) {
    assert.ok(MODS.CATEGORIES.includes(m.category), m.id);
    assert.ok(m.icon && [...m.icon].length <= 2, `${m.id}: one emoji`);
    for (const l of ['fa', 'en']) for (const k of ['name', 'desc', 'hides']) assert.ok(String(m[l][k] || '').trim(), `${m.id}.${l}.${k}`);
    assert.match(m.fa.name + m.fa.desc, /[؀-ۿ]/, `${m.id}: Persian`);
    for (const r of m.requires) assert.ok(IDS.includes(r), `${m.id} needs a known id`);
  }
  // every category has something on every platform the renderer runs on
  for (const p of [D, RT]) for (const c of MODS.CATEGORIES) assert.ok(MODS.MODULES.some((m) => m.category === c && m.platforms.includes(p)), `${p}: ${c}`);
});

test('isOn / available / requiresOf / dependentsOf / normalizeModules', () => {
  assert.equal(MODS.isOn({ modules: { chains: true } }, 'chains'), true);
  for (const s of [{}, null, { modules: { chains: 'yes' } }, { modules: { chains: false } }, { modules: [] }]) assert.equal(MODS.isOn(s, 'chains'), false, JSON.stringify(s));
  assert.equal(MODS.isOn({ modules: { nonsense: true } }, 'nonsense'), false, 'an unknown id is never on');
  assert.equal(MODS.available('multiWan', 'desktop'), true);
  assert.equal(MODS.available('multiWan', 'android'), false);
  assert.equal(MODS.available('remoteRelay', 'desktop'), false);
  assert.equal(MODS.available('lanShare', 'router'), false, 'the router shares its LAN by being the router');
  assert.equal(MODS.available('nonsense', 'desktop'), false);
  assert.deepEqual(MODS.requiresOf('warp'), ['chains']);
  assert.deepEqual(MODS.requiresOf('chains'), []);
  assert.deepEqual(MODS.dependentsOf('chains'), ['warp']);
  assert.deepEqual(MODS.dependentsOf('warp'), []);
  assert.deepEqual(MODS.normalizeModules({ chains: true, groups: false, warp: 1, junk: true, pool: true }), { chains: true, pool: true });
  assert.deepEqual(MODS.normalizeModules('x'), {});
});

/* ------------------------------------ in use ------------------------------------ */

const UUID = '11111111-2222-3333-4444-555555555555';
const vless = (id, ob) => ({ id, protocol: 'vless', outbound: Object.assign({ protocol: 'vless', streamSettings: { security: 'tls', tlsSettings: {} } }, ob) });

test('inUseOf: what each extension counts, 0 for none — and every id answered', () => {
  const none = MODS.inUseOf({});
  assert.deepEqual(Object.keys(none), IDS);
  assert.ok(Object.values(none).every((n) => n === 0));
  assert.deepEqual(MODS.inUseOf(null), none);
  const servers = [
    vless('a'),
    { id: 'm', protocol: 'masque', outbound: { protocol: 'masque' } },
    { id: 'w', protocol: 'wireguard', warp: { type: 'free' }, outbound: { protocol: 'wireguard' } },
    vless('e', { streamSettings: { security: 'tls', tlsSettings: { echOutbound: { protocol: 'direct' } } } }),
    vless('f', { _fragment: 'tlshello,100-200,10-20' }),
    vless('n', { _noise: 'rand:50-100:0' }),
    vless('c', { streamSettings: { security: 'tls', tlsSettings: { cipherSuites: 'TLS_AES_256_GCM_SHA384' } } }),
    vless('fm', { streamSettings: { security: 'tls', tlsSettings: {}, finalmask: { tcp: [{ type: 'fragment' }] } } }),
    // Hysteria2's salamander is stored as finalmask too: no anti-DPI field of the editor's
    { id: 'h', protocol: 'hysteria2', outbound: { protocol: 'hysteria', streamSettings: { finalmask: { udp: [{ type: 'salamander' }] } } } },
    vless('blank', { _fragment: '', streamSettings: { tlsSettings: { echOutbound: '' }, finalmask: {} } })
  ];
  const u = MODS.inUseOf({
    servers,
    chains: [{ id: 'c1', members: [] }, { id: 'c2', members: [] }],
    groups: [{ id: 'grp-1', members: [] }],
    pool: [{ id: 'px-1' }, { id: 'px-2' }, { id: 'px-3' }],
    routingProfiles: [{ id: 'rp-default', rules: [{ type: 'ip', value: '1.1.1.1', target: 'a' }] }, { id: 'rp-2', rules: [], def: 'direct' }, { id: 'rp-3', rules: [] }],
    settings: { allowLan: true, multiWan: { enabled: true }, advancedRouting: false },
    lanUsers: { users: [{ id: 'usr-1' }, { id: 'usr-2' }] },
    remote: { relay: { enabled: true, relayUrl: 'https://relay.example' }, cloudflared: { enabled: false } }
  });
  assert.deepEqual(u, {
    chains: 2, groups: 1, warp: 2, pool: 3,
    advancedRouting: 1,        // off: the profiles besides rp-default that hold something
    echOutbound: 1, antiDpi: 4, lanShare: 1, multiWan: 1, remoteRelay: 1, lanUsers: 2
  });
  // advanced routing on: every profile with rules or a default, at least one
  assert.equal(MODS.inUseOf({ settings: { advancedRouting: true }, routingProfiles: [] }).advancedRouting, 1);
  assert.equal(MODS.inUseOf({ settings: { advancedRouting: true }, routingProfiles: [{ id: 'rp-default', rules: [{}] }, { id: 'x', def: 'direct' }] }).advancedRouting, 2);
  // a global fragment setting (Android's) counts; "off" or disabled does not
  assert.equal(MODS.inUseOf({ settings: { fragment: { enabled: true, packets: 'tlshello' } } }).antiDpi, 1);
  assert.equal(MODS.inUseOf({ settings: { fragment: { enabled: false } } }).antiDpi, 0);
  assert.equal(MODS.inUseOf({ settings: { fragment: 'off' } }).antiDpi, 0);
  // the relay and the Cloudflare Tunnel, each set up
  assert.equal(MODS.inUseOf({ remote: { relay: { enabled: false, relayUrl: '' }, cloudflared: { enabled: true } } }).remoteRelay, 1);
  assert.equal(MODS.inUseOf({ remote: { relay: { relayUrl: 'https://r.example' }, cloudflared: { enabled: true } } }).remoteRelay, 2);
  // junk in the lists is not counted
  assert.equal(MODS.inUseOf({ chains: [null, 'x', { id: 'c' }], lanUsers: { users: 'x' } }).chains, 1);
});

/* ------------------------------------ the migration ------------------------------------ */

test('migrateModules: a store from before gets what it uses (with what that needs), a fresh one none; migrated already: what it has; the same however often asked', () => {
  const old = { routingMode: 'global', allowLan: true };
  const data = { servers: [{ id: 'm', protocol: 'masque', outbound: { protocol: 'masque' } }], chains: [], groups: [{ id: 'g' }], pool: [], settings: old };
  const m = MODS.migrateModules(old, data);
  assert.deepEqual(m, { chains: true, groups: true, warp: true, lanShare: true }, 'WARP brings the chains it needs');
  assert.deepEqual(MODS.migrateModules(old, data), m, 'idempotent: asked again, the same');
  // a fresh store: nothing in use, nothing on
  assert.deepEqual(MODS.migrateModules({}, {}), {});
  assert.deepEqual(MODS.migrateModules(undefined, undefined), {});
  // migrated already: what it has, whatever it uses — a removal made by hand stays removed
  assert.deepEqual(MODS.migrateModules({ modulesMigrated: true, modules: { pool: true, junk: true } }, data), { pool: true });
  assert.deepEqual(MODS.migrateModules({ modulesMigrated: true }, data), {});
  // the settings' own keys count when the data has none of its own
  assert.deepEqual(MODS.migrateModules({ multiWan: { enabled: true } }, {}), { multiWan: true });
  // what an older store had installed (a half-written one) is kept
  assert.deepEqual(MODS.migrateModules({ modules: { pool: true } }, {}), { pool: true });
});

/* ------------------------------------ install / remove ------------------------------------ */

test('setModule: install brings what it needs; removing one another installed one needs is refused (blockedBy); one in use may go; unknown or not here: nothing changes', () => {
  assert.deepEqual(MODS.setModule({}, 'warp', true, D), { modules: { warp: true, chains: true } });
  assert.deepEqual(MODS.setModule({ chains: true, warp: true }, 'chains', false, D), { modules: { chains: true, warp: true }, blockedBy: ['warp'] });
  assert.deepEqual(MODS.setModule({ chains: true, warp: true }, 'warp', false, D), { modules: { chains: true } });
  assert.deepEqual(MODS.setModule({ chains: true }, 'chains', false, D), { modules: {} });
  assert.deepEqual(MODS.setModule({ pool: true }, 'pool', true, D), { modules: { pool: true } }, 'installing one installed changes nothing');
  assert.deepEqual(MODS.setModule({ pool: true }, 'nonsense', true, D), { modules: { pool: true }, error: 'unknown' });
  assert.deepEqual(MODS.setModule({}, 'remoteRelay', true, D), { modules: {}, error: 'unavailable' });
  assert.deepEqual(MODS.setModule({}, 'lanShare', true, RT), { modules: {}, error: 'unavailable' });
  assert.deepEqual(MODS.setModule({}, 'remoteRelay', true, RT), { modules: { remoteRelay: true } });
  // the input is never changed in place
  const cur = { chains: true };
  MODS.setModule(cur, 'warp', true, D);
  assert.deepEqual(cur, { chains: true });
});

test('attrOf / hiddenBy: one body attribute per extension; an element of several hides only when all are off', () => {
  assert.equal(MODS.attrOf('advancedRouting'), 'data-mod-advanced-routing');
  assert.equal(MODS.attrOf('chains'), 'data-mod-chains');
  assert.equal(MODS.attrOf('lanUsers'), 'data-mod-lan-users');
  assert.equal(MODS.hiddenBy('chains', { chains: true }), true);
  assert.equal(MODS.hiddenBy('chains groups', { chains: true }), false);
  assert.equal(MODS.hiddenBy('chains groups', { chains: true, groups: true }), true);
  assert.equal(MODS.hiddenBy(null, { chains: true }), false);
  assert.equal(MODS.hiddenBy('', { chains: true }), false);
  assert.equal(MODS.hiddenBy('pool', null), false);
});

/* ------------------------------------ the markup and the one rule ------------------------------------ */

test('the markup names what each extension draws, and one CSS rule hides each while it is off', () => {
  const tagOf = (id) => { const m = HTML.match(new RegExp(`<[^>]*\\bid="${id}"[^>]*>`)); assert.ok(m, `#${id}`); return m[0]; };
  const want = {
    'view-chain': 'chains groups', cgTabChains: 'chains', cgPaneChains: 'chains', btnAddChain: 'chains',
    cgTabGroups: 'groups', cgPaneGroups: 'groups', btnAddGroup: 'groups', grpModal: 'groups',
    'view-pool': 'pool', btnWarpOpen: 'warp', warpModal: 'warp', edWarpAcct: 'warp',
    edFragmentRow: 'antiDpi', edNoiseCustomRow: 'antiDpi', edPattWrap: 'antiDpi', edHideSniRow: 'antiDpi', edHideSniFmNote: 'antiDpi',
    multiWanCard: 'multiWan', lanInfo: 'lanShare', gwRemoteRow: 'remoteRelay'
  };
  for (const [id, mod] of Object.entries(want)) assert.match(tagOf(id), new RegExp(`data-module="${mod}"`), id);
  assert.match(HTML, /<button class="nav-item pro-only" data-view="chain" data-module="chains groups"/);
  assert.match(HTML, /<button class="nav-item pro-only" data-view="pool" data-module="pool"/);
  assert.match(HTML, /<div class="card" data-module="advancedRouting">\s*<div class="switch-row">\s*<div>\s*<div class="switch-title" data-i18n="adv\.title">/);
  assert.match(HTML, /<div class="switch-row" data-module="lanShare">\s*<div><div class="switch-title" data-i18n="lan\.title">/);
  // every data-module in the markup names extensions of the registry
  for (const m of HTML.matchAll(/data-module="([^"]+)"/g)) for (const id of m[1].split(' ')) assert.ok(IDS.includes(id), m[0]);
  // the rule: one selector per extension, and the page of both, display none
  const rule = CSS.slice(CSS.indexOf('body[data-mod-chains="off"]'), CSS.indexOf('{ display: none !important; }', CSS.indexOf('body[data-mod-chains="off"]')));
  for (const id of IDS) assert.ok(rule.includes(`body[${MODS.attrOf(id)}="off"] [data-module="${id}"]`), id);
  assert.ok(rule.includes('body[data-mod-chains="off"][data-mod-groups="off"] [data-module="chains groups"]'));
  // the Extensions page itself is never an extension, nor pro-only: a simple-mode user installs too
  assert.match(HTML, /<button class="nav-item" data-view="modules" data-i18n-title="nav\.modules">\s*<span class="nav-ico">⊞<\/span><span data-i18n="nav\.modules">افزونه‌ها<\/span>/);
  assert.match(HTML, /<section class="view" id="view-modules">\s*<div class="view-head"><h2 data-i18n="mod\.title">افزونه‌ها<\/h2><\/div>\s*<p class="hint" data-i18n="mod\.intro">[^<]+<\/p>\s*<div class="mod-list" id="modList"><\/div>/);
  // Settings: one line to it, not a .card (settingsExperience.js files the cards by their order)
  assert.match(HTML, /<div class="view-head"><h2 data-i18n="settings\.title">تنظیمات<\/h2><\/div>\s*<!--[^>]*-->\s*<p class="mod-pointer" id="modPointer"><span data-i18n="mod\.pointer">[^<]+<\/span> <button type="button" class="cg-link" id="btnOpenModules" data-i18n="mod\.open">/);
  // the registry and the page load before app.js
  const at = (s) => HTML.indexOf(`<script src="${s}"></script>`);
  assert.ok(at('modules.js') > at('i18n.js') && at('extensions.js') > at('modules.js') && at('app.js') > at('extensions.js'));
});

test('the server editor: echOutbound is the ECH outbound extension’s, fragment / noise / cipherSuites / finalMask the anti-DPI one’s — and nothing else is any', () => {
  const SF = require('../src/renderer/serverFields');
  const own = Object.fromEntries(SF.FIELDS.filter((f) => f.module).map((f) => [f.id, f.module]));
  assert.deepEqual(own, { echOutbound: 'echOutbound', fragment: 'antiDpi', noise: 'antiDpi', cipherSuites: 'antiDpi', finalMask: 'antiDpi' });
  // Android's generated copy does not carry the key: the generator writes the same file as before
  const gen = require('child_process').spawnSync(process.execPath, [path.join(__dirname, '..', 'scripts', 'gen-android-server-fields.js'), '--check'], { encoding: 'utf8' });
  assert.equal(gen.status, 0, gen.stdout + gen.stderr);
});

/* ------------------------------------ strings ------------------------------------ */

test('every string of the page in both languages, placed right after set.multiWan in each (the anchor the merge keeps)', () => {
  const enAt = I18N.indexOf('\n  en: {');
  const keys = ['set.modules', 'nav.modules', 'mod.title', 'mod.intro', 'mod.count', 'mod.cat.connection', 'mod.cat.routing', 'mod.cat.network', 'mod.cat.security',
    'mod.installed', 'mod.install', 'mod.remove', 'mod.inUse', 'mod.needs', 'mod.neededBy', 'mod.confirmRemove', 'mod.blocked',
    'mod.done.install', 'mod.done.installWith', 'mod.done.remove', 'mod.failed', 'mod.pointer', 'mod.open', 'mod.sep'];
  for (const [part, from] of [[I18N.slice(0, enAt), 0], [I18N.slice(enAt), enAt]]) {
    void from;
    const anchor = part.indexOf("'set.multiWan':");
    const next = part.indexOf("'mi.title':");
    assert.ok(anchor > -1 && next > anchor);
    const block = part.slice(anchor, next);
    for (const k of keys) assert.equal(block.split(`'${k}':`).length - 1, 1, `${k} between set.multiWan and mi.title`);
  }
  // the real t(), each language
  const ctx = { window: {}, document: { documentElement: {}, querySelectorAll: () => [] } };
  vm.runInNewContext(I18N, ctx);
  for (const lang of ['fa', 'en']) {
    ctx.window.i18n.applyI18n(lang);
    for (const k of keys) assert.notEqual(ctx.window.i18n.t(k), k, `${lang}: ${k}`);
  }
  ctx.window.i18n.applyI18n('fa');
  assert.equal(ctx.window.i18n.t('nav.modules'), 'افزونه‌ها');
  ctx.window.i18n.applyI18n('en');
  assert.equal(ctx.window.i18n.t('nav.modules'), 'Extensions');
});

/* ------------------------------------ settings and wiring ------------------------------------ */

test('both DEFAULT_SETTINGS: no extension installed, migrated already (a new store never migrates)', () => {
  const { DEFAULT_SETTINGS } = require('../src/server/service');
  assert.deepEqual(DEFAULT_SETTINGS.modules, {});
  assert.equal(DEFAULT_SETTINGS.modulesMigrated, true);
  const block = MAIN.slice(MAIN.indexOf('const DEFAULT_SETTINGS = {'));
  const body = block.slice(0, block.indexOf('\n};'));
  assert.match(body, /\n {2}modules: \{\},\n {2}modulesMigrated: true,\n/, 'main.js has the same');
  // a reconnect key, compared as the builder reads it
  assert.ok(require('../src/main/settingsMeta').RECONNECT_KEYS.includes('modules'));
});

test('main.js: the migration where the others run, a backup brings its extensions, modules:get / modules:set as the router answers them', () => {
  for (const [f, src] of [['main.js', MAIN], ['service.js', SVC]]) {
    assert.match(src, /getRoutingProfiles\(\);\s+\/\/ today's advanced routing becomes profile rp-default, once\n\s*migrateModulesStore\(\);/, `${f}: after the profiles are in`);
    assert.match(src, /groups: r\.next\.groups, settings: r\.next\.settings \}\);\n\s*installModulesInUse\(\);/, `${f}: after a backup restore`);
    assert.match(src, /const fresh = !raw \|\| raw === DEFAULT_SETTINGS;\n\s*if \(!fresh && raw\.modulesMigrated === true\) return;/, `${f}: once`);
  }
  assert.match(MAIN, /ipcMain\.handle\('modules:get', \(\) => \{/);
  assert.match(MAIN, /ipcMain\.handle\('modules:set', \(e, arg\) => \{/);
  assert.match(MAIN, /platform: 'desktop' \}/);
  assert.match(SVC, /'modules:get': \(\) => \{/);
  assert.match(SVC, /'modules:set': \(arg\) => \{/);
});

test('both bridges expose the same two calls', () => {
  const preload = R('src', 'preload', 'preload.js');
  const web = R('src', 'server', 'web-api.js');
  assert.match(preload, /modulesGet: \(\) => ipcRenderer\.invoke\('modules:get'\),/);
  assert.match(preload, /modulesSet: \(arg\) => ipcRenderer\.invoke\('modules:set', arg\),/);
  assert.match(web, /modulesGet: \(\) => invoke\('modules:get'\),/);
  assert.match(web, /modulesSet: \(arg\) => invoke\('modules:set', arg\),/);
});

/* ------------------------------------ the config, off ------------------------------------ */

const LINKS = [
  { id: 'Wi-Fi', iface: 'Wi-Fi', name: 'Home', role: 'use', weight: 2 },
  { id: 'Ethernet 2', iface: 'Ethernet 2', name: 'Phone', role: 'use', weight: 1 }
];
const MW = { enabled: true, mode: 'balance', links: LINKS, split: { up: '', down: '' } };
const ALL_OFF = { modules: {}, modulesMigrated: true };
const json = (c) => JSON.stringify(c);

test('the config with every extension off is byte for byte the config without any: single, chain, pool, advanced', () => {
  const VLESS = F.VLESS_WS_TLS;
  const TROJAN = F.TROJAN_TCP_TLS;
  const plans = [
    { mode: 'single', server: VLESS },
    { mode: 'chain', chain: [VLESS, TROJAN] },
    { mode: 'pool', entries: [{ id: 'px-1', target: VLESS.id, socksPort: 60001, httpPort: 0 }], primary: VLESS.id, serversById: { [VLESS.id]: VLESS }, chainsById: {}, chain: [] }
  ];
  for (const plan of plans) {
    const build = B.buildConfig;
    assert.equal(json(build(plan, F.settings(ALL_OFF))), json(build(plan, F.settings())), plan.mode);
    // and every one installed changes nothing either: none of them is a setting the builder reads but multiWan
    const all = { modules: Object.fromEntries(IDS.map((id) => [id, true])) };
    assert.equal(json(build(plan, F.settings(all))), json(build(plan, F.settings())), plan.mode + ' (all on)');
  }
});

test('multiWan not installed builds as multiWan disabled — byte for byte; installed, the internets are used; settings with no `modules` (a caller of the builder by hand) are not asked', () => {
  const plan = { mode: 'single', server: F.VLESS_WS_TLS };
  const off = B.buildConfig(plan, F.settings(Object.assign({ multiWan: MW }, ALL_OFF)));
  const disabled = B.buildConfig(plan, F.settings(Object.assign({ multiWan: Object.assign({}, MW, { enabled: false }) }, ALL_OFF)));
  assert.equal(json(off), json(disabled), 'off is disabled, byte for byte');
  assert.equal(json(off), json(B.buildConfig(plan, F.settings())), '…and today’s config');
  assert.equal(off.multiWanSplit, null);
  const on = B.buildConfig(plan, F.settings({ multiWan: MW, modules: { multiWan: true } }));
  assert.notEqual(json(on), json(off));
  assert.ok(json(on).includes('"interface":"Wi-Fi"') && json(on).includes('"interface":"Ethernet 2"'), 'bound to each internet');
  assert.equal(json(B.buildConfig(plan, F.settings({ multiWan: MW }))), json(on), 'no modules at all: as before this version');
});

test('settingsMeta: an extension removed or installed waits for a reconnect only where it reaches the config', () => {
  const { pendingReconnectKeys, snapshotApplied } = require('../src/main/settingsMeta');
  const base = F.settings({ multiWan: Object.assign({}, MW, { enabled: false }), modules: {} });
  const applied = snapshotApplied(base);
  assert.deepEqual(pendingReconnectKeys(applied, Object.assign({}, base, { modules: { chains: true, groups: true, warp: true, pool: true } })), [], 'pages only');
  assert.deepEqual(pendingReconnectKeys(applied, Object.assign({}, base, { modules: { multiWan: true } })), [], 'several internets are off anyway');
  assert.deepEqual(pendingReconnectKeys(applied, Object.assign({}, base, { modules: { lanUsers: true } })), ['modules']);
  const mwBase = Object.assign({}, base, { multiWan: MW, modules: { multiWan: true } });
  assert.deepEqual(pendingReconnectKeys(snapshotApplied(mwBase), Object.assign({}, mwBase, { modules: {} })), ['modules'], 'several internets running: removing it changes the config');
});
