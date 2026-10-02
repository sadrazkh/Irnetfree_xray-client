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

/* ----------------------------- fix 18: a server edit is not live until a reconnect ----------------------------- */

test('fix 18: editing the live server is a pending change — reported, and a Connect on it rebuilds instead of "already connected"', async (t) => {
  const s = H.start();
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  assert.deepEqual(await s.service.invoke('settings:pending'), []);
  const r = await s.service.invoke('servers:update', { id: SERVER.id, fields: { name: 'ci-upstream (edited)' } });
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

test('fix 18: editing a server the live connection does not use changes nothing pending; a settings key and an edit are both reported', async (t) => {
  const s = H.start();
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  const r = await s.service.invoke('servers:update', { id: SERVER_B.id, fields: { name: 'other' } });
  assert.equal(r.live, false);
  assert.deepEqual(r.pendingReconnect, []);
  assert.equal((await s.service.invoke('connect', SERVER.id)).already, true);
  await s.service.invoke('servers:update', { id: SERVER.id, fields: { name: 'x' } });
  await s.service.invoke('settings:set', { routingMode: 'bypass-ir' });
  assert.deepEqual((await s.service.invoke('settings:pending')).sort(), ['routingMode', 'servers']);
  await s.service.invoke('vpn:reconnect');
  assert.deepEqual(await s.service.invoke('settings:pending'), []);
});

test('fix 18: a hop of the live chain counts as the live connection; nothing is pending while disconnected', async (t) => {
  const chain = { id: 'ch-1', name: 'two hops', members: [SERVER.id, SERVER_B.id] };
  const s = H.start({ chains: [chain] });
  t.after(() => s.service.shutdown());
  assert.equal((await s.service.invoke('servers:update', { id: SERVER_B.id, fields: { name: 'b' } })).live, false, 'disconnected: nothing is live');
  assert.deepEqual(await s.service.invoke('settings:pending'), []);
  await s.service.invoke('connect', chain.id);
  assert.equal(connectedCount(s), 1);
  const r = await s.service.invoke('servers:update', { id: SERVER_B.id, fields: { name: 'second hop' } });
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
    assert.match(e.message, /^The core exited before it opened 127\.0\.0\.1:47808 — the whole-network tunnel was not started\. Its last lines: .*panic: runtime error: index out of range/);
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
  await assert.rejects(s.service.invoke('connect', SERVER.id), /^Error: هسته پیش از باز کردن 127\.0\.0\.1:47808 بسته شد — تونل کل شبکه راه‌اندازی نشد\. آخرین خطوط آن: \(چیزی چاپ نکرد\)$/);
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
