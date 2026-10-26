'use strict';
/**
 * v1.16.2's router changes never reach a desktop or a headless Linux server
 * (the owner's rule for the round). The same service, NOT on a router: a store
 * shaped exactly like the one the router repairs is left as it is, the core
 * runs the desktop's DNS block, and nothing about open files is read or said.
 * Proxy mode (tunMode off): nothing here may touch this machine's network.
 */
delete process.env.IRNETFREE_PLATFORM;
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createService } = require('../src/server/service');
const { isOpenwrt } = require('../src/main/openwrtNet');
const fakes = require('./gatewayFakes');
const { SERVER, PORTS } = require('./serviceHarness');

process.setMaxListeners(60);

const DESKTOP = Object.assign({
  autoUpdateSubs: false, autoUpdateAssets: 'off', tunMode: false, systemProxy: false, lang: 'en', blockAds: false,
  // the shape the router repairs: public in-country resolvers, QUIC and connect-at-start off
  routingMode: 'bypass-ir', dnsDirect: ['1.1.1.1', '8.8.8.8'], dnsRemote: ['https://1.1.1.1/dns-query', 'https://1.0.0.1/dns-query'],
  lanBlockQuic: false, autoConnect: false, killSwitch: true, launchAtLogin: true
}, PORTS);

const any = () => { throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' }); };
/** A /proc that would answer for every pid — the desktop must not even ask. */
const asked = [];
const readProc = (p) => { if (/\/limits$/.test(p)) { asked.push(p); return 'Max open files            4096                 4096                 files\n'; } return any(); };
const listProc = (p) => { asked.push(p); return ['0', '1', '2']; };

test('a desktop service: no repair, the desktop DNS block, no open-files lines', { skip: isOpenwrt() && 'this machine is a router' }, async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-desk-'));
  const seeded = { servers: [SERVER], settings: DESKTOP };
  fs.writeFileSync(path.join(dir, 'store.json'), JSON.stringify(seeded));
  const state = fakes.makeState();
  const syslog = [];
  const service = createService({ dataDir: dir, deps: fakes.deps(state, { readProc, listProc, syslog: (l, x) => syslog.push(x) }) });
  const logs = [];
  service.onEvent((ch, p) => { if (ch === 'log') logs.push(p); });
  t.after(async () => { await service.shutdown(); fs.rmSync(dir, { recursive: true, force: true }); });

  // the store: not one of the router's repairs, not its marker
  const disk = JSON.parse(fs.readFileSync(path.join(dir, 'store.json'), 'utf8'));
  assert.equal('routerRepair' in disk, false);
  // the desktop's own one-time port mark (settingsMigrate.js) and the extensions' (modules.js:
  // none in use, none installed), nothing of the router's
  assert.deepEqual(disk.settings, Object.assign({}, DESKTOP, { portsMoved: true, modules: {}, modulesMigrated: true }), 'the settings as they were');

  await service.invoke('connect', SERVER.id);
  const dns = state.xray.starts[0].config.dns;
  for (const k of ['enableParallelQuery', 'serveStale', 'serveExpiredTTL']) assert.equal(k in dns, false, k);
  assert.ok(dns.servers.every(x => typeof x !== 'object' || !('timeoutMs' in x)), JSON.stringify(dns.servers));
  assert.ok(dns.servers.includes('https://1.1.1.1/dns-query'), 'the DoH entries as plain strings, as v1.16.1 wrote them');

  state.xray.log('[Error] transport/internet: socket: too many open files');
  assert.ok(!logs.some(l => /Open files|Out of open files/.test(l.line)), logs.map(l => l.line).join('\n'));
  assert.doesNotMatch((await service.diagnostics()).text, /^open files/m);
  assert.deepEqual(asked, [], 'no /proc/<pid>/limits or fd/ read on a desktop');
  assert.ok(!syslog.some(l => /Router settings repaired/.test(l)));
});

// The router's upkeep (routerUpkeep.test.js) stays on the router: no tunnel
// watchdog, and the weekly asset update never runs under a live connection —
// not in the router's quiet hours either.
test('a desktop service: no tunnel watchdog, and no asset update under a live connection at 03:30 either', { skip: isOpenwrt() && 'this machine is a router' }, async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-desk-'));
  const afternoon = new Date(2026, 9, 20, 14, 0).getTime();
  fs.writeFileSync(path.join(dir, 'store.json'), JSON.stringify({ servers: [SERVER], assetsCheckedAt: afternoon, settings: Object.assign({}, DESKTOP, { autoUpdateAssets: 'geo' }) }));
  const state = fakes.makeState();
  let now = afternoon;
  let probes = 0;
  const downloads = [];
  const service = createService({ dataDir: dir, deps: fakes.deps(state, {
    readProc, listProc,
    now: () => now,
    probeTunnel: async () => { probes++; return false; },
    downloader: () => ({ download: async (c) => { downloads.push(c); return { ok: true }; }, latestVersion: async () => '99.0.0' }),
    timing: Object.assign({}, fakes.deps(state).timing, { tunnelWatchMs: 20, tunnelRecheckMs: 5, assetFirstMs: 10, assetEveryMs: 20 })
  }) });
  const logs = [];
  service.onEvent((ch, p) => { if (ch === 'log') logs.push(p); });
  t.after(async () => { await service.shutdown(); fs.rmSync(dir, { recursive: true, force: true }); });

  await service.invoke('connect', SERVER.id);
  now = new Date(2026, 9, 28, 3, 30).getTime();   // a week on, in the router's quiet hours
  await new Promise((r) => setTimeout(r, 200));
  assert.deepEqual(downloads, [], 'never under a live connection on a desktop');
  assert.equal(probes, 0, 'no watchdog');
  assert.equal(state.xray.starts.length, 1);
  assert.ok(!logs.some((l) => /Tunnel watchdog|quiet hours/.test(l.line)), logs.map((l) => l.line).join('\n'));
  // disconnected: the weekly run as it always was
  await service.invoke('disconnect');
  const deadline = Date.now() + 4000;
  while (!downloads.length && Date.now() < deadline) await new Promise((r) => setTimeout(r, 10));
  assert.deepEqual(downloads, ['geo']);
});

test('main.js (the Electron app) carries none of it', () => {
  const main = fs.readFileSync(path.join(__dirname, '..', 'src', 'main', 'main.js'), 'utf8');
  for (const s of ['routerRepair', 'routerDnsTuning', 'udpTimeout', 'openFiles', 'ROUTER_UDP_TIMEOUT_S']) assert.ok(!main.includes(s), s);
});
