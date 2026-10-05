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

test('fix 9: a router’s backup restored on a reset router brings its kill switch and connect-at-start back — the keep list is for desktop backups', async (t) => {
  // The usual reason to restore on a router: it was reset or re-flashed, and
  // the fresh defaults (kill switch off, connect at start on) must give way to
  // what the owner had. Keeping them silently dropped his kill switch, and the
  // warn line blamed a desktop file that did not exist (review of v1.16.1).
  const old = H.start({ settings: { killSwitch: true, autoConnect: false, lanBlockQuic: false, routingMode: 'bypass-ir' } });
  t.after(() => old.service.shutdown());
  const text = await old.service.invoke('backup:export');
  assert.equal(JSON.parse(text).flavor, 'openwrt', 'a router’s backup says where it was made');
  const fresh = H.start({ settings: { killSwitch: false, autoConnect: true, lanBlockQuic: true, routingMode: 'global' } });
  t.after(() => fresh.service.shutdown());
  const r = await fresh.service.invoke('backup:import', text);
  assert.equal(r.ok, true);
  assert.deepEqual(r.kept, []);
  const after = await fresh.service.invoke('settings:get');
  assert.equal(after.killSwitch, true);
  assert.equal(after.autoConnect, false);
  assert.equal(after.lanBlockQuic, false);
  assert.equal(after.routingMode, 'bypass-ir');
  assert.ok(!fresh.logs.some(l => /Backup restored on a router/.test(l.line)), lines(fresh).join('\n'));
  // a bundle with no mark (a desktop's, or one from before the mark) is a desktop backup
  const unmarked = Object.assign(JSON.parse(text), { flavor: undefined });
  const fresh2 = H.start({ settings: { killSwitch: false, autoConnect: true, lanBlockQuic: true } });
  t.after(() => fresh2.service.shutdown());
  const r2 = await fresh2.service.invoke('backup:import', JSON.stringify(unmarked));
  assert.deepEqual(r2.kept.sort(), ['autoConnect', 'killSwitch', 'lanBlockQuic']);
  assert.equal((await fresh2.service.invoke('settings:get')).killSwitch, false);
});

/* ----------------------------- fix 18: a server edit is not live until a reconnect ----------------------------- */

test('fix 18: editing the live server is a pending change — reported, and a Connect on it rebuilds instead of "already connected"', async (t) => {
  const s = H.start();
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  assert.deepEqual(await s.service.invoke('settings:pending'), []);
  const r = await s.service.invoke('servers:update', { id: SERVER.id, fields: { port: 1081 } });
  assert.equal(r.ok, true);
  assert.equal(r.live, true, 'the answer says the edited server is in the live connection');
  assert.deepEqual(r.pendingReconnect, ['servers']);
  assert.deepEqual(await s.service.invoke('settings:pending'), ['servers']);
  assert.deepEqual((await s.service.invoke('app:init')).pendingReconnect, ['servers']);
  // the Connect the user presses to apply it (web UI or LuCI) is not a silent no-op any more
  const again = await s.service.invoke('connect', SERVER.id);
  assert.notEqual(again.already, true);
  assert.equal(connectedCount(s), 2, 'rebuilt with the edit');
  assert.equal(s.state.xray.starts.at(-1).config.outbounds.length > 0, true);
  assert.deepEqual(await s.service.invoke('settings:pending'), [], 'the rebuild applied it');
  assert.equal((await s.service.invoke('connect', SERVER.id)).already, true, 'and the next Connect is the no-op again');
});

test('fix 18: a rename of the live server, or a Save with nothing changed (the edit dialog sends every field), is no pending change — the next Connect stays the no-op', async (t) => {
  // review of v1.16.1: either one asked for a reconnect, and a LuCI Connect then
  // rebuilt the gateway — a 20-40 s LAN outage — for a config that did not change
  const { editFields } = require('../src/main/parser');
  const s = H.start();
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  const stored = (await s.service.invoke('servers:list')).find((x) => x.id === SERVER.id);
  const same = await s.service.invoke('servers:update', { id: SERVER.id, fields: editFields(stored) });
  assert.equal(same.ok, true);
  assert.equal(same.live, false, 'nothing that is dialled changed');
  assert.deepEqual(same.pendingReconnect, []);
  const renamed = await s.service.invoke('servers:update', { id: SERVER.id, fields: { name: 'ci-upstream (renamed)' } });
  assert.equal(renamed.server.name, 'ci-upstream (renamed)', 'the rename is saved');
  assert.equal(renamed.live, false, 'a name is never in the config');
  assert.deepEqual(await s.service.invoke('settings:pending'), []);
  assert.equal((await s.service.invoke('connect', SERVER.id)).already, true);
  assert.equal(connectedCount(s), 1);
  // …while a change of what is dialled still is one
  const moved = await s.service.invoke('servers:update', { id: SERVER.id, fields: { port: 1081 } });
  assert.equal(moved.live, true);
  assert.deepEqual(moved.pendingReconnect, ['servers']);
});

test('fix 18: editing a server the live connection does not use changes nothing pending; a settings key and an edit are both reported', async (t) => {
  const s = H.start();
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  const r = await s.service.invoke('servers:update', { id: SERVER_B.id, fields: { name: 'other' } });
  assert.equal(r.live, false);
  assert.deepEqual(r.pendingReconnect, []);
  assert.equal((await s.service.invoke('connect', SERVER.id)).already, true);
  await s.service.invoke('servers:update', { id: SERVER.id, fields: { address: '192.0.2.12' } });
  await s.service.invoke('settings:set', { routingMode: 'bypass-ir' });
  assert.deepEqual((await s.service.invoke('settings:pending')).sort(), ['routingMode', 'servers']);
  await s.service.invoke('vpn:reconnect');
  assert.deepEqual(await s.service.invoke('settings:pending'), []);
});

test('fix 18: a hop of the live chain counts as the live connection; nothing is pending while disconnected', async (t) => {
  const chain = { id: 'ch-1', name: 'two hops', members: [SERVER.id, SERVER_B.id] };
  const s = H.start({ chains: [chain] });
  t.after(() => s.service.shutdown());
  assert.equal((await s.service.invoke('servers:update', { id: SERVER_B.id, fields: { port: 1082 } })).live, false, 'disconnected: nothing is live');
  assert.deepEqual(await s.service.invoke('settings:pending'), []);
  await s.service.invoke('connect', chain.id);
  assert.equal(connectedCount(s), 1);
  const r = await s.service.invoke('servers:update', { id: SERVER_B.id, fields: { port: 1083 } });
  assert.equal(r.live, true);
  assert.deepEqual(r.pendingReconnect, ['servers']);
  await s.service.invoke('disconnect');
  assert.deepEqual(await s.service.invoke('settings:pending'), [], 'gone with the connection');
});

/* ----------------------------- fix 20: refusals the A7 used to hide ----------------------------- */

test('fix 20: the router gives the core’s config check ~30 s before it counts as unverified', async (t) => {
  let given = null;
  const s = H.start({}, { xray: (o) => { given = o; return H.fakes.deps(H.fakes.makeState()).xray(o); } });
  t.after(() => s.service.shutdown());
  assert.equal(given.testTimeoutMs, 30000);
});

/** deps.waitForLocalPort for a core that dies while the gateway waits for its SOCKS port — the first time; later cores bind. */
function dyingCore(s, lines) {
  let calls = 0;
  return async (port, ms, opts) => {
    if (++calls > 1) return true;
    s.state.xray.crash(lines);
    const deadline = Date.now() + Math.min(ms, 2000);
    while (Date.now() < deadline && !(opts && typeof opts.stop === 'function' && opts.stop())) await sleep(5);
    return false;
  };
}

test('fix 20: a core that exits while the gateway waits for its port fails the connect with the core’s own last lines — no tunnel into a dead port', async (t) => {
  const s = H.start({}, { waitForLocalPort: (...a) => wait(...a) });
  const wait = dyingCore(s, ['2026/10/02 10:00:00 [Warning] core: Xray 26.3.27 started', 'panic: runtime error: index out of range [3] with length 3']);
  t.after(() => s.service.shutdown());
  const t0 = Date.now();
  await assert.rejects(s.service.invoke('connect', SERVER.id), (e) => {
    // how it ended, and the panic's own line (not the lines after it)
    assert.match(e.message, /^The core exited \(code=- signal=SIGKILL\) before it opened 127\.0\.0\.1:47808 — the whole-network tunnel was not started\. Its last lines: panic: runtime error: index out of range \[3\] with length 3( mem:.*)?$/);
    return true;
  });
  assert.ok(Date.now() - t0 < 1500, 'aborted when the core went, not after the 20 s wait');
  assert.equal(s.state.events.includes('gateway:start'), false, 'no gateway routing the LAN into a SOCKS port nobody will open');
  assert.ok(!s.logs.some(l => /starting the gateway anyway/.test(l.line)), lines(s).join('\n'));
  assert.equal(s.service.connSnapshot().state, 'error');
  assert.equal((await s.service.invoke('app:init')).activeServerId, null);
  await sleep(50);
  assert.equal(s.state.xray.starts.length, 1, 'a connect by hand that failed is not rebuilt behind the user’s back');
});

test('fix 20: the same abort in Persian, and a core that printed nothing still says so', async (t) => {
  const s = H.start({ settings: { lang: 'fa' } }, { waitForLocalPort: (...a) => wait(...a) });
  const wait = dyingCore(s, []);
  t.after(() => s.service.shutdown());
  await assert.rejects(s.service.invoke('connect', SERVER.id), /^Error: هسته پیش از باز کردن 127\.0\.0\.1:47808 بسته شد \(code=- signal=SIGKILL\) — تونل کل شبکه راه‌اندازی نشد\. آخرین خطوط آن: \(چیزی چاپ نکرد\)( mem:.*)?$/);
});

test('fix 20: a finalmask server the official core refuses, with no Xray-PattN installed, says what to install — in both languages', async (t) => {
  for (const [lang, re] of [
    ['en', /^This server needs Xray-PattN — install it under Settings → Required files \(the official core refuses it: infra\/conf: LengthMin can't be 0\)$/],
    ['fa', /^این سرور به Xray-PattN نیاز دارد — از تنظیمات ← فایل‌های موردنیاز نصبش کن \(هستهٔ رسمی آن را رد می‌کند: infra\/conf: LengthMin can't be 0\)$/]
  ]) {
    const s = H.start({ settings: { lang } });
    t.after(() => s.service.shutdown());
    s.state.check = { ok: false, error: 'infra/conf: LengthMin can\'t be 0', plaintextRejected: false, pattnNeeded: true };
    await assert.rejects(s.service.invoke('connect', SERVER.id), (e) => re.test(e.message) || assert.fail(e.message));
    assert.equal(s.state.xray.starts.length, 0, 'nothing started');
    assert.ok(s.logs.some(l => l.level === 'error' && /Config rejected by xray: infra\/conf: LengthMin/.test(l.line)), 'the core’s own words stay in the log');
  }
});

test('fix 20: a finalmask server on an official core too old to know finalmask (it passes -test and would drop the mask) says what to install — in both languages', async (t) => {
  for (const [lang, re] of [
    ['en', /^This server needs Xray-PattN — install it under Settings → Required files \(the official core 24\.12\.31 does not know finalmask and would run it without its mask\)$/],
    ['fa', /^این سرور به Xray-PattN نیاز دارد — از تنظیمات ← فایل‌های موردنیاز نصبش کن \(هستهٔ رسمی 24\.12\.31 finalmask را نمی‌شناسد و آن را بدون ماسکش اجرا می‌کرد\)$/]
  ]) {
    const s = H.start({ settings: { lang } });
    t.after(() => s.service.shutdown());
    s.state.check = { ok: false, pattnNeeded: true, finalmaskIgnored: true, coreVersion: '24.12.31', error: 'xray 24.12.31 does not know finalmask (26.3.27 and newer do) — it would run this server without its mask', plaintextRejected: false };
    await assert.rejects(s.service.invoke('connect', SERVER.id), (e) => re.test(e.message) || assert.fail(e.message));
    assert.equal(s.state.xray.starts.length, 0, 'nothing started');
  }
});

test('v1.18: an ECH server on an official core older than 25.8.3 (the feed’s 25.1.30), no Xray-PattN: refused in plain words — in both languages', async (t) => {
  const check = { ok: false, echUnsupported: true, coreVersion: '25.1.30', plaintextRejected: false, error: 'xray 25.1.30 does not know ECH (25.8.3 and newer do) — it would connect without it' };
  for (const [lang, want] of [
    ['en', 'This server uses ECH, which Xray 25.1.30 does not know (it would connect without it) — update Xray under Settings → Required files'],
    ['fa', 'این سرور از ECH استفاده می‌کند و Xray 25.1.30 آن را نمی‌شناسد (بدون ECH وصل می‌شد) — از تنظیمات ← فایل‌های موردنیاز، Xray را به‌روز کن']
  ]) {
    const s = H.start({ settings: { lang } });
    t.after(() => s.service.shutdown());
    s.state.check = check;
    await assert.rejects(s.service.invoke('connect', SERVER.id), (e) => e.message === want || assert.fail(e.message));
    assert.equal(s.state.xray.starts.length, 0, 'nothing started');
  }
});

test('fix 20: a core that is still running when the 20 s are up is still given the gateway (a slow bind is not a death)', async (t) => {
  const s = H.start({}, { waitForLocalPort: async () => false });
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  assert.equal(connectedCount(s), 1);
  assert.ok(s.logs.some(l => l.level === 'warn' && /has not opened 127\.0\.0\.1:47808 after 20s — starting the gateway anyway/.test(l.line)));
});

/* ----------------------------- fix 21: an official core older than the DNS plan ----------------------------- */

const OLD_CORE_EN = 'The xray core is 24.12.31; the LAN\'s DNS is verified on 26.3.27 and newer — download the core under Settings → Required files';
const OLD_CORE_FA = 'هستهٔ xray نسخهٔ 24.12.31 است؛ DNS شبکه روی 26.3.27 و بالاتر آزموده شده — هسته را از تنظیمات ← فایل‌های موردنیاز دانلود کن';

test('fix 21: a router connecting on an official core older than 26.3.27 (the feed’s 24.12.31) says so at warn, in the user’s language', async (t) => {
  for (const [lang, want] of [['en', OLD_CORE_EN], ['fa', OLD_CORE_FA]]) {
    const s = H.start({ settings: { lang } });
    t.after(() => s.service.shutdown());
    s.state.coreVersions = { xray: '24.12.31' };
    await s.service.invoke('connect', SERVER.id);
    assert.equal(connectedCount(s), 1, 'a warning, not a refusal');
    assert.deepEqual(s.logs.filter(l => /26\.3\.27/.test(l.line)).map(l => [l.level, l.line]), [['warn', want]]);
    assert.ok(s.syslog.some(([, l]) => l.includes(want)), 'it reaches syslog');
  }
});

test('fix 21: 26.3.27 and newer (compared as numbers), an unreadable version, or a config on Xray-PattN: not a word', async (t) => {
  for (const [versions, engine] of [[{ xray: '26.3.27' }, null], [{ xray: '26.10.1' }, null], [{ xray: '' }, null], [{ xray: 'Xray (unknown build)' }, null], [{ xray: '24.12.31' }, 'xray-pattn']]) {
    const s = H.start({ servers: [Object.assign({}, SERVER, engine ? { engine } : {})] });
    t.after(() => s.service.shutdown());
    s.state.coreVersions = versions;
    await s.service.invoke('connect', SERVER.id);
    assert.equal(connectedCount(s), 1);
    assert.ok(!s.logs.some(l => /verified on 26\.3\.27/.test(l.line)), JSON.stringify(versions) + ' ' + engine + ': ' + lines(s).join('\n'));
  }
});

/* ----------------------------- fix 22: missing geo files reach the log ----------------------------- */

test('fix 22: bypass-ir with no geo files is a warn line too (syslog, LuCI → Log) — not only a toast', async (t) => {
  const s = H.start({ settings: { routingMode: 'bypass-ir' } });
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  const connected = s.statuses.find(x => x.state === 'connected');
  assert.match(connected.geoWarn || '', /Geo files \(geoip\/geosite\) are missing/, 'the toast is still there');
  assert.ok(s.logs.some(l => l.level === 'warn' && l.line === connected.geoWarn), lines(s).join('\n'));
  assert.ok(s.syslog.some(([, l]) => /\[warn\] Geo files \(geoip\/geosite\) are missing/.test(l)));
});

/* ----------------------------- D3: the in-country resolvers stay in the tunnel for the LAN ----------------------------- */

const fs = require('node:fs');
const path = require('node:path');
const { DNS_TAG } = require('../src/main/dnsBuilder');
/** geoip.dat / geosite.dat where the service looks first (an empty file is "present" to it) — bypass-ir then builds the in-country resolver. */
function withGeo(s) {
  for (const f of ['geoip.dat', 'geosite.dat']) fs.writeFileSync(path.join(s.dir, 'bin', f), '');
}

test('D3: bypass-ir on a router — the in-country resolvers are NOT cut out of the whole-LAN tunnel; the server is', async (t) => {
  // route_exclude_address took them out of table 2022 for every device and
  // every port: dnsmasq's upstream (Shecan, or a restored 8.8.8.8) then left in
  // plain text by the ISP, and filtered names came back poisoned (field report D3).
  const s = H.start({ settings: { routingMode: 'bypass-ir', dnsDirect: ['178.22.122.100', '185.51.200.2'] } });
  t.after(() => s.service.shutdown());
  withGeo(s);
  await s.service.invoke('connect', SERVER.id);
  assert.equal(connectedCount(s), 1);
  const inner = s.state.inners.find(i => i.active);
  assert.ok(inner.bypass.includes('192.0.2.10'), 'the entry server stays off the tunnel: ' + JSON.stringify(inner.bypass));
  for (const ip of ['178.22.122.100', '185.51.200.2']) assert.ok(!inner.bypass.includes(ip), `${ip} must stay in the tunnel for the LAN: ${JSON.stringify(inner.bypass)}`);
  // …and the core's own query to them still leaves direct, bound to the WAN device (SO_BINDTODEVICE escapes table 2022)
  const config = s.state.xray.starts[0].config;
  const rule = config.routing.rules.find(r => Array.isArray(r.inboundTag) && r.inboundTag.includes(DNS_TAG) && r.outboundTag === 'direct' && Array.isArray(r.ip));
  assert.ok(rule, 'the DNS module’s rule to the in-country resolvers');
  assert.deepEqual(rule.ip, ['178.22.122.100', '185.51.200.2']);
  assert.equal(rule.port, '53');
  const direct = config.outbounds.find(o => o.tag === 'direct');
  assert.equal(direct.streamSettings.sockopt.interface, 'eth0', 'the direct dial is bound to the WAN device the gateway found');
  // the remote control still learns which resolvers the core dials direct
  assert.deepEqual(s.service.directResolvers(), ['178.22.122.100', '185.51.200.2']);
  // …and the router's OWN lookups through them (the relay agent's) leave by the WAN: a rule for this
  // process's user from lo only — LAN devices and dnsmasq (its own user) stay in the tunnel (review of v1.16.1)
  for (const ip of ['178.22.122.100', '185.51.200.2']) {
    assert.ok(s.state.commands.includes(`ip -4 rule add pref 8997 iif lo uidrange 0-0 to ${ip}/32 ipproto udp dport 53 lookup main`), s.state.commands.filter(c => /8997/.test(c)).join('\n'));
  }
  // what a dnsmasq drop-in binds to so its query skips the tunnel the same way (cloudflared's edge discovery)
  assert.equal(s.service.directDevice(), 'eth0', 'the device the live direct dials are bound to');
});

test('D3: directDevice() with no live connection is the main table’s default route — never our own tunnel; null with none', async (t) => {
  let route = 'Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n'
    + 'br-lan\tC0A80100\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n'
    + 'IRNetFree\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n'
    + 'pppoe-wan\t00000000\t0100000A\t0003\t0\t0\t10\t00000000\t0\t0\t0\n'
    + 'wan\t00000000\t0102A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n';
  const s = H.start({}, { readProc: (p) => { if (p === '/proc/net/route') return route; throw new Error('ENOENT'); } });
  t.after(() => s.service.shutdown());
  assert.equal(s.service.directDevice(), 'wan', 'the lowest metric of the up default routes, our TUN skipped');
  route = route.split('\n').filter(l => !/^wan\t/.test(l)).join('\n');
  assert.equal(s.service.directDevice(), 'pppoe-wan');
  route = 'Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n';
  assert.equal(s.service.directDevice(), null);
});

test('D3: dnsmasq running as the service’s own user — the own-lookup rule is not laid, and the log says why', async (t) => {
  const s = H.start({ settings: { routingMode: 'bypass-ir', dnsDirect: ['178.22.122.100', '185.51.200.2'] } });
  t.after(() => s.service.shutdown());
  withGeo(s);
  s.state.procUids = { dnsmasq: [0] };
  await s.service.invoke('connect', SERVER.id);
  assert.equal(connectedCount(s), 1);
  assert.ok(!s.state.commands.some(c => /uidrange/.test(c)));
  assert.ok(s.logs.some(l => l.level === 'warn' && /dnsmasq runs as uid 0/.test(l.line)), lines(s).join('\n'));
});

test('D3: public anycast resolvers as the in-country DNS of a bypass mode (a desktop backup\'s 8.8.8.8, 1.1.1.1) are said at warn on every connect, in the user\'s language', async (t) => {
  // field report D3: dnsDirect is not kept on a restore, so a desktop's
  // [8.8.8.8, 1.1.1.1] silently became the "in-country" resolver bypass-ir asks
  // in plain text from Iran — filtered, poisoned, and every name told to the ISP
  for (const [lang, re] of [
    ['en', /^\[warn\] The in-country DNS of bypass-ir holds public resolvers \(8\.8\.8\.8, 1\.1\.1\.1\): they are asked in plain text from inside the country, where they are filtered or answer poisoned — put in-country resolvers in the direct DNS list$/],
    ['fa', /^\[warn\] DNS داخلی bypass-ir رزولورهای عمومی دارد \(8\.8\.8\.8, 1\.1\.1\.1\): از داخل کشور بی‌رمز پرسیده می‌شوند، جایی که فیلتر شده‌اند یا جواب مسموم می‌دهند — رزولورهای داخل کشور را در فهرست DNS مستقیم بگذار$/]
  ]) {
    const s = H.start({ settings: { lang, routingMode: 'bypass-ir', dnsDirect: ['8.8.8.8', '1.1.1.1'] } });   // the desktop's own, restored
    t.after(() => s.service.shutdown());
    withGeo(s);
    await s.service.invoke('connect', SERVER.id);
    assert.equal(connectedCount(s), 1, 'a warning, not a refusal');
    assert.equal(lines(s).filter((l) => re.test(l)).length, 1, lines(s).join('\n'));
  }
  // in-country resolvers, or global mode (where none is asked direct): nothing said
  for (const settings of [{ routingMode: 'bypass-ir', dnsDirect: ['178.22.122.100', '185.51.200.2'] }, { routingMode: 'global', dnsDirect: ['8.8.8.8'] }]) {
    const s = H.start({ settings });
    t.after(() => s.service.shutdown());
    withGeo(s);
    await s.service.invoke('connect', SERVER.id);
    assert.ok(!lines(s).some((l) => /public resolvers/.test(l)), lines(s).join('\n'));
  }
});

test('D3: WireGuard endpoints and pinned entry addresses are still kept off the tunnel', async (t) => {
  const named = Object.assign({}, SERVER, { id: 'srv-named', address: 'upstream.invalid' });
  named.outbound = JSON.parse(JSON.stringify(SERVER.outbound));
  named.outbound.settings.servers[0].address = 'upstream.invalid';
  const s = H.start({ servers: [named], settings: { routingMode: 'bypass-ir' } }, { resolveHost: async () => ({ ips: ['198.51.100.7'], source: 'os', suspect: [] }) });
  t.after(() => s.service.shutdown());
  withGeo(s);
  await s.service.invoke('connect', 'srv-named');
  const inner = s.state.inners.find(i => i.active);
  assert.ok(inner.bypass.includes('198.51.100.7'), 'the pinned address of the entry name: ' + JSON.stringify(inner.bypass));
  assert.ok(!inner.bypass.includes('178.22.122.100'));
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
