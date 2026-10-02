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
