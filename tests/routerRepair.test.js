'use strict';
/**
 * v1.16.2 — the one-time repair of a router's settings that a desktop backup
 * overwrote before v1.16.1 kept the router's own on a restore (fix 9). The
 * owner's AC-1304 connected with bypass-ir's in-country DNS set to 1.1.1.1 and
 * 8.8.8.8 (the router's own menu offers Iranian resolvers only), and a desktop
 * backup also carries lanBlockQuic:false and autoConnect:false — the desktop
 * has no QUIC switch and no "connect at start" default of the router's.
 *
 * Once, at the first start of v1.16.2 (`routerRepair` in the store), and only
 * with a desktop's trace in the stored settings: QUIC refused again, connect
 * at start on again, the in-country DNS back to the default pair when every
 * entry is a public resolver. Said once at warn (syslog, LuCI's log). Nothing
 * else is touched.
 */
process.env.IRNETFREE_PLATFORM = 'openwrt';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const H = require('./serviceHarness');

process.setMaxListeners(60);
test.after(() => H.cleanupDirs());

const onDisk = (s) => JSON.parse(fs.readFileSync(path.join(s.dir, 'store.json'), 'utf8'));
const repairLines = (s) => s.syslog.filter(([, l]) => /Router settings repaired once/.test(l)).map(([, l]) => l);
const SHECAN = ['178.22.122.100', '185.51.200.2'];

/** The owner's router, as v1.16.1 left it (field log; .superpowers/sdd check of the desktop's store). */
const OWNER = {
  routingMode: 'bypass-ir', dnsDirect: ['1.1.1.1', '8.8.8.8'], dnsRemote: ['https://1.1.1.1/dns-query', 'https://1.0.0.1/dns-query'],
  lanBlockQuic: false, autoConnect: false, killSwitch: true, enableSniffing: false, allowLan: true, socksPort: 30808
};

test('the owner\'s router: QUIC refused again, connect at start on again, the in-country DNS back to the default pair — once, said at warn', async (t) => {
  const s = H.start({ routerRepair: undefined, settings: OWNER });
  t.after(() => s.service.shutdown());
  const st = await s.service.invoke('settings:get');
  assert.equal(st.lanBlockQuic, true);
  assert.equal(st.autoConnect, true);
  assert.deepEqual(st.dnsDirect, SHECAN);
  for (const k of ['routingMode', 'dnsRemote', 'killSwitch', 'enableSniffing', 'allowLan', 'socksPort']) assert.deepEqual(st[k], OWNER[k], `${k} is the owner's`);
  const disk = onDisk(s);
  assert.equal(disk.routerRepair, 1);
  assert.equal(disk.settings.lanBlockQuic, true, 'written, not overlaid');
  assert.deepEqual(disk.settings.dnsDirect, SHECAN);
  assert.deepEqual(repairLines(s), ['irnetfree: [warn] Router settings repaired once (a desktop backup restored before v1.16.1 had overwritten them): QUIC (UDP 443) from the LAN is refused again; "Connect when the router starts" is on again; the in-country DNS is 178.22.122.100, 185.51.200.2 instead of the public 1.1.1.1, 8.8.8.8 — each can be set back under Settings']);
  assert.ok(s.service.logTail(50).some(l => /\[warn\] Router settings repaired once/.test(l)), 'in LuCI\'s log too');
});

test('it runs once: a value the user sets back afterwards stays, and the next start says nothing', async (t) => {
  const s = H.start({ routerRepair: undefined, settings: OWNER });
  await s.service.invoke('settings:set', { lanBlockQuic: false, dnsDirect: ['1.1.1.1', '8.8.8.8'] });
  await s.service.shutdown();
  const again = H.startIn(s.dir);
  t.after(() => again.service.shutdown());
  const st = await again.service.invoke('settings:get');
  assert.equal(st.lanBlockQuic, false, 'the user\'s own choice after the repair');
  assert.deepEqual(st.dnsDirect, ['1.1.1.1', '8.8.8.8']);
  assert.deepEqual(repairLines(again), []);
});

test('no desktop trace (an Iranian in-country pair, nothing only a restore can set): nothing changes, the key is written, nothing said', async (t) => {
  const s = H.start({ routerRepair: undefined, settings: { dnsDirect: SHECAN, lanBlockQuic: false, autoConnect: false, routingMode: 'bypass-ir' } });
  t.after(() => s.service.shutdown());
  const st = await s.service.invoke('settings:get');
  assert.equal(st.lanBlockQuic, false, 'turned off on the router itself — LuCI and the web UI have the switch');
  assert.equal(st.autoConnect, false);
  assert.equal(onDisk(s).routerRepair, 1);
  assert.deepEqual(repairLines(s), []);
});

test('a mixed in-country list is no trace: left as it is, and the connect warning still names the public entry', async (t) => {
  const s = H.start({ routerRepair: undefined, settings: { routingMode: 'bypass-ir', dnsDirect: ['178.22.122.100', '8.8.8.8'], lanBlockQuic: false } });
  t.after(() => s.service.shutdown());
  const st = await s.service.invoke('settings:get');
  assert.deepEqual(st.dnsDirect, ['178.22.122.100', '8.8.8.8']);
  assert.equal(st.lanBlockQuic, false);
  assert.deepEqual(repairLines(s), []);
});

test('another desktop trace (systemProxy:true, hidden on a router since v1.13.0): QUIC and connect at start repaired, an Iranian DNS pair and the trace itself left', async (t) => {
  const s = H.start({ routerRepair: undefined, settings: { systemProxy: true, dnsDirect: SHECAN, lanBlockQuic: false, autoConnect: false } });
  t.after(() => s.service.shutdown());
  const disk = onDisk(s).settings;
  assert.equal(disk.lanBlockQuic, true);
  assert.equal(disk.autoConnect, true);
  assert.deepEqual(disk.dnsDirect, SHECAN);
  assert.equal(disk.systemProxy, true, 'a trace, not a repair: it does nothing on a router');
  assert.deepEqual(repairLines(s), ['irnetfree: [warn] Router settings repaired once (a desktop backup restored before v1.16.1 had overwritten them): QUIC (UDP 443) from the LAN is refused again; "Connect when the router starts" is on again — each can be set back under Settings']);
});

test('a fresh install: the router\'s defaults, the key written, nothing said', async (t) => {
  const dir = fs.mkdtempSync(path.join(require('node:os').tmpdir(), 'irnf-svc-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const s = H.startIn(dir);
  t.after(() => s.service.shutdown());
  const disk = onDisk(s);
  assert.equal(disk.routerDefaultsApplied, true);
  assert.equal(disk.routerRepair, 1);
  assert.equal(disk.settings.lanBlockQuic, true);
  assert.equal(disk.settings.autoConnect, true);
  assert.deepEqual(repairLines(s), []);
});
