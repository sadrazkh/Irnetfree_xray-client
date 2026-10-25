'use strict';
/**
 * Several internets — the three channels 'multiwan:get', 'multiwan:set' and
 * 'multiwan:test' in the router's service (the real service over the gateway
 * fakes; the machine's internets and their speed tests are the test's: nothing
 * is listed, spawned or measured), the data caps fed by the real stats poller
 * (over a fake /debug/vars on a loopback port of the OS's choosing), main.js's
 * wiring (read as text: Electron does not load here), the two bridges the one
 * renderer talks through, and the default both processes start from.
 */
process.env.IRNETFREE_PLATFORM = 'openwrt';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const vm = require('node:vm');
const H = require('./serviceHarness');
const { makeProxyServer } = require('../src/main/parser');
const { normalizeMultiWan } = require('../src/main/multiWan');

process.setMaxListeners(60);   // every service registers its own exit hook
test.after(() => H.cleanupDirs());

const R = (...p) => fs.readFileSync(path.join(__dirname, '..', ...p), 'utf8').replace(/\r\n/g, '\n');
const { SERVER, until } = H;
const GIB = 1024 ** 3;
const at = (y, mo, d, h = 12) => new Date(y, mo - 1, d, h, 0, 0).getTime();

/** What netLinks.listLinks finds on this "router": the cable WAN and a phone's USB tether. */
const FOUND = [
  { id: 'wan', iface: 'eth1', name: 'wan', kind: 'ethernet', address: '10.0.0.2', gateway: '10.0.0.1', metric: 10 },
  { id: 'usb0', iface: 'usb0', name: 'wwan', kind: 'usb', address: '192.168.42.129', gateway: '192.168.42.1', metric: 20 }
];

/** A service with the internets and the speed tests faked; `seen` records what they were asked. */
function start(store = {}, extra = {}) {
  const seen = { list: [], tests: [] };
  const s = H.start(store, Object.assign({
    listLinks: async (o) => { seen.list.push(o); return FOUND.map((l) => Object.assign({}, l)); },
    testAll: async (o) => {
      seen.tests.push(o);
      return o.links.map((l) => (l.id === 'wan'
        ? { id: 'wan', ok: true, rttMs: 41, downMbps: 48.2, upMbps: 3.1, error: '' }
        : { id: l.id, ok: false, rttMs: null, downMbps: null, upMbps: null, error: 'download: timeout' }));
    }
  }, extra));
  return Object.assign(s, { seen });
}

/* ------------------------------ multiwan:get ------------------------------ */

test('router: multiwan:get answers the settings normalized, the internets found merged with the configured ones, the usage and (disconnected) no live figures', async (t) => {
  const s = start({ settings: { multiWan: { enabled: true, links: [{ id: 'wan', iface: 'eth1', name: 'Cable', quotaGb: 50, quotaPeriod: 'month' }, { id: 'lte', iface: 'wwan0', name: 'LTE stick' }] } } });
  t.after(() => s.service.shutdown());
  const res = await s.service.invoke('multiwan:get');
  assert.deepEqual(Object.keys(res).sort(), ['links', 'live', 'settings', 'usage']);
  assert.deepEqual(res.settings, normalizeMultiWan({ enabled: true, links: [{ id: 'wan', iface: 'eth1', name: 'Cable', quotaGb: 50, quotaPeriod: 'month' }, { id: 'lte', iface: 'wwan0', name: 'LTE stick' }] }));
  assert.deepEqual(res.links.map((l) => [l.id, l.name, l.present, l.configured, l.kind]), [
    ['wan', 'Cable', true, true, 'ethernet'],
    ['lte', 'LTE stick', false, true, 'other'],
    ['usb0', 'wwan', true, false, 'usb']
  ]);
  assert.equal(res.links[0].address, '10.0.0.2');
  assert.equal(res.links[0].gateway, '10.0.0.1');
  assert.equal(res.usage.wan.quotaBytes, 50 * GIB);
  assert.equal(res.usage.wan.bytes, 0);
  assert.match(res.usage.wan.period, /^\d{4}-\d{2}$/);
  assert.ok(res.usage.wan.until > res.usage.wan.since);
  assert.deepEqual(res.live, {});
  assert.deepEqual(s.seen.list, [{}], 'on a router nothing is passed: netLinks finds out itself');
});

test('router: a fresh store answers the empty shape — off, balance, no links', async (t) => {
  const s = start();
  t.after(() => s.service.shutdown());
  const res = await s.service.invoke('multiwan:get');
  assert.deepEqual(res.settings, { enabled: false, mode: 'balance', links: [], split: { up: '', down: '' } });
});

/* ------------------------------ multiwan:set ------------------------------ */

test('router: multiwan:set saves a part, normalized and whole, and answers like settings:set', async (t) => {
  const s = start();
  t.after(() => s.service.shutdown());
  const res = await s.service.invoke('multiwan:set', { enabled: true, links: [{ id: 'wan', iface: 'eth1', name: 'Cable', weight: 9, quotaGb: -3, role: 'nonsense' }, { id: 'wan', iface: 'eth9' }] });
  assert.deepEqual(res.pendingReconnect, [], 'nothing connected: nothing pending');
  assert.equal(res.multiWan.enabled, true);
  assert.deepEqual(res.multiWan.links, [{ id: 'wan', iface: 'eth1', name: 'Cable', role: 'use', weight: 3, quotaGb: 0, quotaPeriod: 'none' }], 'clamped, validated, deduped');
  assert.deepEqual(res.settings.multiWan, res.multiWan, 'the whole settings come back, as settings:set answers');
  assert.deepEqual((await s.service.invoke('settings:get')).multiWan, res.multiWan, 'persisted');
  // a later part keeps the rest; split merges key by key
  const r2 = await s.service.invoke('multiwan:set', { mode: 'split', split: { up: 'usb0' } });
  assert.equal(r2.multiWan.enabled, true);
  assert.equal(r2.multiWan.links.length, 1);
  assert.deepEqual(r2.multiWan.split, { up: 'usb0', down: '' });
  const r3 = await s.service.invoke('multiwan:set', { split: { down: 'wan' } });
  assert.deepEqual(r3.multiWan.split, { up: 'usb0', down: 'wan' });
  const raw = JSON.parse(fs.readFileSync(path.join(s.dir, 'store.json'), 'utf8'));
  assert.deepEqual(raw.settings.multiWan, r3.multiWan, 'on disk');
});

test('router: while connected a change to multiWan waits for a reconnect — a cap alone does not', async (t) => {
  const links = [{ id: 'wan', iface: 'eth1', name: 'Cable' }, { id: 'usb0', iface: 'usb0', name: 'Phone' }];
  const s = start({ settings: { multiWan: { enabled: true, links } } });
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  const cap = await s.service.invoke('multiwan:set', { links: [links[0], Object.assign({}, links[1], { quotaGb: 3, quotaPeriod: 'day' })] });
  assert.deepEqual(cap.pendingReconnect, [], 'the quota applies a cap itself');
  const mode = await s.service.invoke('multiwan:set', { mode: 'failover' });
  assert.deepEqual(mode.pendingReconnect, ['multiWan']);
  assert.deepEqual(await s.service.invoke('settings:pending'), ['multiWan']);
  const back = await s.service.invoke('multiwan:set', { mode: 'balance' });
  assert.deepEqual(back.pendingReconnect, [], 'back to what is running');
});

/* ------------------------------ multiwan:test ------------------------------ */

test('router: multiwan:test measures each asked internet through the selected config, one call to netLinks.testAll, the throwaway core the pings use', async (t) => {
  const s = start({ settings: { multiWan: { enabled: true, links: [{ id: 'wan', iface: 'eth1', name: 'Cable' }, { id: 'lte', iface: 'wwan0', name: 'LTE stick' }] } } });
  t.after(() => s.service.shutdown());
  // nothing selected yet: refused before anything runs, said as a code the card words
  const none = await s.service.invoke('multiwan:test', ['wan']);
  assert.deepEqual(none, [{ id: 'wan', ok: false, rttMs: null, downMbps: null, upMbps: null, code: 'noServer', error: 'select a server first' }]);
  assert.equal(s.seen.tests.length, 0);

  await s.service.invoke('selection:set', SERVER.id);
  await s.service.invoke('multiwan:get');   // "find again" read the list a moment ago
  const res = await s.service.invoke('multiwan:test', ['usb0', 'lte', 'wan', 'ghost']);
  assert.deepEqual(res.map((r) => [r.id, r.ok, r.code || '', r.error || '']), [
    ['usb0', false, '', 'download: timeout'],
    ['lte', false, 'absent', 'not connected now'],
    ['wan', true, '', ''],
    ['ghost', false, 'unknown', 'no such internet']
  ], 'in the order asked; what testAll said, per internet');
  assert.equal(res[2].downMbps, 48.2);
  assert.equal(typeof res[2].at, 'number');
  assert.equal(s.seen.tests.length, 1, 'one call — netLinks runs them one after another');
  const call = s.seen.tests[0];
  assert.deepEqual(call.links.map((l) => [l.id, l.iface]), [['usb0', 'usb0'], ['wan', 'eth1']], 'only the connected ones');
  assert.equal(call.server.id, SERVER.id);
  assert.equal(call.buildTestConfig, require('../src/main/configBuilder').buildTestConfig);
  assert.equal(call.dataDir, s.dir);
  await assert.rejects(call.startTest({}), /no test cores here/, 'the core manager’s own startTest (the fake refuses)');
  assert.equal(s.seen.list.length, 2, 'the test took the list multiwan:get had just read — no second read in between');
  // the last result per internet is kept for the window
  const after = await s.service.invoke('multiwan:get');
  assert.deepEqual(after.links.find((l) => l.id === 'wan').test.downMbps, 48.2);
  assert.equal(after.links.find((l) => l.id === 'usb0').test.error, 'download: timeout');
  assert.equal(after.links.find((l) => l.id === 'lte').test, null, 'a refusal is not a test result');
});

/* ------------------------------ the data caps, end to end ------------------------------ */

test('router: the stats tick counts each internet; one over its cap is set aside with ONE reload, and the next day it is back', async (t) => {
  // the core's metrics endpoint: whatever the test says the counters are
  let counters = {};
  const metrics = http.createServer((req, res) => { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ stats: { outbound: counters } })); });
  await new Promise((r) => metrics.listen(0, '127.0.0.1', r));
  t.after(() => metrics.close());
  // A group the core runs, whose members' ids carry '#<link>'. With the builder
  // wired to multiWan.applyMultiWan it makes those ids itself; without it (this
  // worktree's stub) the servers' own ids stand in for them.
  const wired = /applyMultiWan\(/.test(R('src', 'main', 'configBuilder.js'));
  const idA = wired ? 'srv-a' : 'a#wan';
  const idB = wired ? 'srv-b' : 'b#usb0';
  const A = Object.assign(makeProxyServer({ type: 'socks', address: '192.0.2.20', port: 1080, name: 'A' }), { id: idA });
  const B = Object.assign(makeProxyServer({ type: 'socks', address: '192.0.2.21', port: 1080, name: 'B' }), { id: idB });
  let now = at(2026, 10, 25, 12);
  const s = start({
    servers: [A, B],
    groups: [{ id: 'grp-mw', name: 'MW', strategy: 'roundRobin', members: [{ id: idA }, { id: idB }] }],
    settings: { apiPort: metrics.address().port, multiWan: { enabled: true, links: [{ id: 'wan', iface: 'eth1', name: 'Cable', quotaGb: 1, quotaPeriod: 'day' }, { id: 'usb0', iface: 'usb0', name: 'Phone' }] } }
  }, { now: () => now, timing: Object.assign({}, H.fakes.deps(H.fakes.makeState()).timing, { routerStatsMs: 40 }) });
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', 'grp-mw');
  const x = s.state.xray;
  const map = x.starts[0].config.groupTags;
  assert.ok(map && map.length === 1, 'the group runs');
  // the cable's first member carries 2 GB down, the phone's first 510 bytes — whatever the copies are
  const { linkOfMemberId } = require('../src/main/multiWan');
  const firstOf = (link) => map[0].members.findIndex((m) => linkOfMemberId(m.id) === link);
  assert.ok(firstOf('wan') > -1 && firstOf('usb0') > -1, JSON.stringify(map[0].members.map((m) => m.id)));
  counters = { [`${map[0].tag}~gm${firstOf('wan')}`]: { uplink: 1000, downlink: 2 * GIB }, [`${map[0].tag}~gm${firstOf('usb0')}`]: { uplink: 10, downlink: 500 } };

  await until(() => x.starts.length === 2, 'the reload without the internet over its cap');
  counters = {};   // a fresh core counts from zero
  assert.ok(s.logs.some((l) => /Multi-internet: “Cable” reached its cap \(1 GB today\)/.test(l.line)), JSON.stringify(s.logs.map((l) => l.line)));
  await until(() => s.logs.some((l) => l.line === 'Multi-internet: the core reloaded without the internets over their cap'), 'the reload’s own line');
  const live = await s.service.invoke('multiwan:get');
  assert.equal(live.usage.wan.over, true);
  assert.ok(live.usage.wan.bytes >= 2 * GIB);
  assert.equal(live.usage.usb0.bytes, 510);
  // the stats event carries the figures for the live bars while several internets carry the connection
  assert.ok(s.events.some(([ch, p]) => ch === 'stats' && p.multiWan && p.multiWan.live && p.multiWan.live.wan), 'stats carry multiWan.live');
  // more ticks: still over, already built without it — nothing more
  await new Promise((r) => setTimeout(r, 300));
  assert.equal(x.starts.length, 2, 'one reload, not one a tick');
  assert.equal(s.logs.filter((l) => /reached its cap/.test(l.line)).length, 1, 'said once');

  // past midnight: a new day, the cable is back — said, and one reload
  now = at(2026, 10, 26, 0) + 5000;
  await until(() => x.starts.length === 3, 'the reload with every internet back');
  assert.ok(s.logs.some((l) => /“Cable” is back in use/.test(l.line)));
  await new Promise((r) => setTimeout(r, 300));
  assert.equal(x.starts.length, 3);
  assert.equal((await s.service.invoke('multiwan:get')).usage.wan.over, false);

  // the bytes are written beside the totals, in the usage file — never the main store
  await s.service.invoke('disconnect');
  await s.service.shutdown();
  const saved = JSON.parse(fs.readFileSync(path.join(s.dir, 'usage.json'), 'utf8'));
  assert.equal(saved.multiWanUsage.usb0.bytes, 510);
  assert.equal(saved.multiWanUsage.wan.period, '2026-10-26');
  assert.equal(JSON.parse(fs.readFileSync(path.join(s.dir, 'store.json'), 'utf8')).multiWanUsage, undefined);
});

/* ------------------------------ main.js, as text ------------------------------ */

const MAIN = R('src', 'main', 'main.js');
const SVC = R('src', 'server', 'service.js');
/** A function of a source, as source (its first `function name(`). */
function fnOf(src, name) {
  const at0 = src.search(new RegExp(`\\n\\s*(async )?function ${name}\\(`));
  assert.ok(at0 > -1, `no function ${name}`);
  let depth = 0, j = src.indexOf('{', src.indexOf(')', at0));
  for (; j < src.length; j++) {
    if (src[j] === '{') depth++;
    else if (src[j] === '}' && --depth === 0) break;
  }
  return src.slice(at0, j + 1);
}

test('desktop: main registers the three channels with the router’s shapes', () => {
  const reg = fnOf(MAIN, 'registerIpc');
  assert.match(reg, /ipcMain\.handle\('multiwan:get', async \(\) => \{/);
  assert.match(reg, /return \{ settings: mw, links, usage: mwQuota \? mwQuota\.usage\(\) : \{\}, live \};/);
  assert.match(reg, /ipcMain\.handle\('multiwan:set', \(e, partial\) => \{/);
  assert.match(reg, /return \{ settings: next, multiWan, pendingReconnect: pendingKeys\(\) \};/);
  assert.match(reg, /ipcMain\.handle\('multiwan:test', async \(e, ids\) => \{/);
  assert.match(reg, /netLinks\.testAll\(\{ links: runnable, server: target, buildTestConfig, startTest: \(cfg\) => xray\.startTest\(cfg, engine\), dataDir: dataDir\(\) \}\)/);
  assert.match(reg, /listNetLinks\(\{ fresh: false \}\)/, 'a test takes the list just read');
});

test('desktop and router: the connect and the reload build with multiWanSkip, and hold the caps to what that core was built without', () => {
  for (const [f, src] of [['main.js', MAIN], ['service.js', SVC]]) {
    for (const fn of ['connectOnce', 'rebuildActiveConfig']) {
      const body = fnOf(src, fn);
      assert.match(body, /const mwSkip = mwQuota(?: \? mwQuota\.skip\(\) : \[\]|\.skip\(\));\n\s*settings = Object\.assign\(\{\}, settings, \{ multiWanSkip: mwSkip \}\);/, `${f} ${fn}: the skip list in the effective settings`);
      assert.match(body, /mwQuota\.reset\(mwSkip\);/, `${f} ${fn}: the fresh core is told`);
      assert.match(body, /liveMwSplit = config\.multiWanSplit \|\| null;/, `${f} ${fn}: the split list kept (not enumerable: the diagnostics copy lacks it)`);
      // multiWanSkip goes in before the build
      assert.ok(body.indexOf('multiWanSkip: mwSkip') < body.indexOf('buildActive(serverId, settings)'), `${f} ${fn}: before buildActive`);
    }
    assert.match(src, /mwQuota\.tick\(vars, stats\.groupMap, liveMwSplit\);/, `${f}: the raw counters feed the quota each tick`);
    assert.match(src, /if \(Object\.keys\(mwLive\)\.length\) s\.multiWan = \{ live: mwLive, usage: mwQuota\.usage\(\) \};/, `${f}: the stats event carries the live figures`);
    assert.match(src, /reload: \(why\) => queueReload\(why\),/, `${f}: the reload goes through the one queue`);
    assert.match(src, /pending: \(\) => pendingKeys\(\),/, `${f}: a pending change waits`);
    assert.match(src, /usage: usageStore\.get\('multiWanUsage', \{\}\),/, `${f}: read from the usage file`);
    assert.match(src, /usageStore\.setLazy\('multiWanUsage', mwQuota\.saved\(\)\);/, `${f}: written there, with the totals`);
  }
  // the reload keeps building from what the live connection was built with: multiWan included (a reconnect key)
  assert.ok(require('../src/main/settingsMeta').RECONNECT_KEYS.includes('multiWan'));
});

test('the router’s service answers the same channels', () => {
  assert.match(SVC, /'multiwan:get': async \(\) => \{/);
  assert.match(SVC, /'multiwan:set': \(partial\) => \{/);
  assert.match(SVC, /'multiwan:test': async \(ids\) => \{/);
  assert.match(SVC, /const testLinks = deps\.testAll \|\| \(\(o\) => netLinks\.testAll\(o\)\);/);
});

/* ------------------------------ the two bridges ------------------------------ */

test('both bridges expose the same three calls', () => {
  const preload = R('src', 'preload', 'preload.js');
  const web = R('src', 'server', 'web-api.js');
  assert.match(preload, /multiWanGet: \(\) => ipcRenderer\.invoke\('multiwan:get'\),/);
  assert.match(preload, /multiWanSet: \(partial\) => ipcRenderer\.invoke\('multiwan:set', partial\),/);
  assert.match(preload, /multiWanTest: \(ids\) => ipcRenderer\.invoke\('multiwan:test', ids\),/);
  assert.match(web, /multiWanGet: \(\) => invoke\('multiwan:get'\),/);
  assert.match(web, /multiWanSet: \(partial\) => invoke\('multiwan:set', partial\),/);
  assert.match(web, /multiWanTest: \(ids\) => invoke\('multiwan:test', ids\),/);
});

/* ------------------------------ the default ------------------------------ */

test('both DEFAULT_SETTINGS start from the same empty multiWan — the normalized shape, off', () => {
  const { DEFAULT_SETTINGS } = require('../src/server/service');
  const empty = normalizeMultiWan({});
  assert.deepEqual(DEFAULT_SETTINGS.multiWan, empty);
  assert.deepEqual(empty, { enabled: false, mode: 'balance', links: [], split: { up: '', down: '' } });
  const block = MAIN.slice(MAIN.indexOf('const DEFAULT_SETTINGS = {'));
  const head = block.indexOf('\n  multiWan: {');
  assert.ok(head > -1 && head < block.indexOf('\n};'), 'main.js DEFAULT_SETTINGS has multiWan');
  const text = block.slice(head + '\n  multiWan: '.length, block.indexOf('\n  },', head) + '\n  }'.length);
  assert.deepEqual(JSON.parse(JSON.stringify(vm.runInNewContext('(' + text + ')'))), empty, 'main.js: the same value');
});
