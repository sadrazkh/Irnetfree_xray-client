'use strict';
/**
 * v1.16.2 — the router's DNS block (dnsBuilder.routerDnsTuning) is what the
 * router's core is checked with and started with, at every connect and every
 * rebuild; the desktop's is not touched (desktopRouterGuards.test.js,
 * desktopPin.test.js). The real service over the gateway fakes.
 */
process.env.IRNETFREE_PLATFORM = 'openwrt';
const test = require('node:test');
const assert = require('node:assert/strict');
const H = require('./serviceHarness');

process.setMaxListeners(60);
test.after(() => H.cleanupDirs());

const { SERVER, until, connectedCount } = H;

function assertTuned(dns, what) {
  assert.ok(dns && Array.isArray(dns.servers), what);
  assert.deepEqual(dns.servers.filter(x => typeof x === 'object' && /^https:/.test(x.address)),
    [{ address: 'https://1.1.1.1/dns-query', timeoutMs: 8000 }, { address: 'https://8.8.8.8/dns-query', timeoutMs: 8000 }], what);
  assert.equal(dns.enableParallelQuery, true, what);
  assert.equal(dns.serveStale, true, what);
  assert.equal(dns.serveExpiredTTL, 86400, what);
}

test('a router\'s core is checked and started with the router\'s DNS block — at the connect and at the rebuild after a crash', async (t) => {
  const s = H.start({}, { timing: { bootDelayMs: 5, bootEveryMs: 20, bootSlowAfter: 1000, bootSlowMs: 20, routerBackoffMs: [5, 5, 10], crashWindowMs: 0 } });
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  assertTuned(s.state.xray.validated[0].config.dns, 'what xray -test is given');
  assertTuned(s.state.xray.starts[0].config.dns, 'what the core runs');
  s.state.xray.crash();
  await until(() => connectedCount(s) === 2, 'the rebuild');
  assertTuned(s.state.xray.starts.at(-1).config.dns, 'the rebuilt core');
});
