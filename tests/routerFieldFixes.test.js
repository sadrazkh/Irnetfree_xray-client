'use strict';
/**
 * The service's half of the owner's first-install findings on the AC-1304
 * (v1.16.0 → v1.16.1, `.superpowers/sdd/v1.16/field-report.md` §3 and D3):
 * what a router may not be switched to, the warnings that were false there,
 * a backup from the desktop, a server edit that is not live yet, a core that
 * dies before its SOCKS port opens, the core's version, missing geo files, and
 * the in-country resolvers that no longer leave the tunnel for the whole LAN.
 *
 * The real service over the gateway fakes (tests/gatewayFakes.js): nothing is
 * spawned or bound, the machine's network is never touched.
 */
process.env.IRNETFREE_PLATFORM = 'openwrt';
const test = require('node:test');
const assert = require('node:assert/strict');
const H = require('./serviceHarness');

process.setMaxListeners(60);   // every service registers its own exit hook
test.after(() => H.cleanupDirs());

const { SERVER, SERVER_B, until, sleep, connectedCount } = H;
const lines = (s) => s.logs.map((l) => `[${l.level}] ${l.line}`);

/* ----------------------------- fix 5: TUN is not a choice on a router ----------------------------- */

test('fix 5: on a router TUN is forced on — a stored or a sent "off" is overridden, and the answer says so', async (t) => {
  const s = H.start({ settings: { tunMode: false } });
  t.after(() => s.service.shutdown());
  assert.equal((await s.service.invoke('settings:get')).tunMode, true, 'a stored off (a desktop backup) is not honoured');
  const res = await s.service.invoke('settings:set', { tunMode: false });
  assert.equal(res.settings.tunMode, true, 'the answer already says the switch has no effect here');
  assert.equal((await s.service.invoke('app:init')).settings.tunMode, true);
});

test('fix 5: a router whose store says tunMode:false still builds the whole-network tunnel — "proxy only" there was the LAN going direct', async (t) => {
  const s = H.start({ settings: { tunMode: false } });
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  assert.equal(connectedCount(s), 1);
  assert.equal(s.statuses.find(x => x.state === 'connected').tun, true);
  assert.ok(s.state.events.includes('gateway:start'));
});

/* ----------------------------- fix 7: warnings that were false on a router ----------------------------- */

test('fix 7: the strict leak guard on a router is sing-box’s strict_route — no "tun2socks backend" warning', async (t) => {
  const s = H.start({ settings: { leakGuard: 'strict' } });
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  assert.equal(connectedCount(s), 1);
  assert.ok(!s.logs.some(l => /tun2socks backend/.test(l.line)), lines(s).join('\n'));
  assert.ok(!s.syslog.some(([, l]) => /tun2socks backend/.test(l)), 'nor in syslog');
});

/* ----------------------------- fix 9: a desktop backup restored on a router ----------------------------- */

const ROUTER_KEPT = ['tunMode', 'tunBackend', 'tunAppMode', 'tunApps', 'systemProxy', 'launchAtLogin', 'leakGuard', 'blockUdpInProxyMode', 'autoConnect', 'lanBlockQuic', 'killSwitch'];
const DESKTOP = {
  tunMode: false, tunBackend: 'tun2socks', tunAppMode: 'exclude', tunApps: ['chrome.exe'], systemProxy: true, launchAtLogin: true,
  leakGuard: 'off', blockUdpInProxyMode: true, autoConnect: false, lanBlockQuic: false, killSwitch: true,
  routingMode: 'bypass-ir', dnsDirect: ['8.8.8.8', '1.1.1.1'], lang: 'en'
};

test('fix 9: a desktop backup restored on a router keeps the router’s own settings — and says so at warn, in English', async (t) => {
  const s = H.start({ settings: { autoConnect: true, lanBlockQuic: true, killSwitch: false, leakGuard: 'standard', tunAppMode: 'off', tunApps: [], systemProxy: false, launchAtLogin: false, blockUdpInProxyMode: false, tunBackend: 'sing-box' } });
  t.after(() => s.service.shutdown());
  const before = await s.service.invoke('settings:get');
  const bundle = { app: 'IRNetFree', format: 1, version: '1.16.0', servers: [], subscriptions: [], chains: [], pool: [], settings: DESKTOP, usage: {} };
  const r = await s.service.invoke('backup:import', JSON.stringify(bundle));
  assert.equal(r.ok, true);
  const after = await s.service.invoke('settings:get');
  for (const k of ROUTER_KEPT) assert.deepEqual(after[k], before[k], `${k} stays the router’s`);
  assert.equal(after.routingMode, 'bypass-ir', 'the rest of the backup is restored');
  assert.deepEqual(after.dnsDirect, ['8.8.8.8', '1.1.1.1']);
  assert.deepEqual(r.kept, ROUTER_KEPT, 'the answer names what was kept — every one of them differed here (for the renderer’s own words)');
  const warn = s.logs.filter(l => l.level === 'warn' && /^Backup restored on a router/.test(l.line));
  assert.deepEqual(warn.map(l => l.line), ['Backup restored on a router: desktop-only settings were kept as the router needs them (TUN, system proxy, per-app routing, leak guard, connect at start, QUIC refusal, kill switch)']);
  assert.ok(s.syslog.some(([, l]) => /\[warn\] Backup restored on a router/.test(l)), 'a warn reaches syslog');
  // the store itself holds the router's values, not the desktop's under a forced overlay
  const onDisk = JSON.parse(require('node:fs').readFileSync(require('node:path').join(s.dir, 'store.json'), 'utf8')).settings;
  assert.equal(onDisk.tunMode, true);
  assert.equal(onDisk.autoConnect, true);
  assert.equal(onDisk.killSwitch, false);
});

test('fix 9: a router’s own backup restored on it changes none of those keys — and says nothing about them', async (t) => {
  const s = H.start({ settings: { autoConnect: true, lanBlockQuic: true } });
  t.after(() => s.service.shutdown());
  const own = await s.service.invoke('backup:export');
  const r = await s.service.invoke('backup:import', own);
  assert.equal(r.ok, true);
  assert.deepEqual(r.kept, []);
  assert.ok(!s.logs.some(l => /Backup restored on a router/.test(l.line)), lines(s).join('\n'));
});

/* ----------------------------- fix 8: "the whole-network tunnel", not "the gateway" ----------------------------- */

test('fix 8: no sing-box on the router — the refusal names the whole-network tunnel, in both languages', async (t) => {
  for (const [lang, re] of [
    ['en', /^The whole-network tunnel needs sing-box and nft on the router: opkg install sing-box nftables \(or Settings → Required files for sing-box\)$/],
    ['fa', /^تونل کل شبکه روی روتر به sing-box و nft نیاز دارد: opkg install sing-box nftables \(یا sing-box از تنظیمات → فایل‌های موردنیاز\)$/]
  ]) {
    const s = H.start({ settings: { lang } });
    t.after(() => s.service.shutdown());
    s.state.singboxMissing = true;
    await assert.rejects(s.service.invoke('connect', SERVER.id), (e) => re.test(e.message) || assert.fail(e.message));
  }
});
