'use strict';
/**
 * On a router a device behind it may run its own VPN client: an address, and in the
 * TLS a name that belongs to someone else. Sniffing that replaced the address sent it
 * to that someone else, so every Reality, camouflaged or pinned config behind the
 * router died. Measured on real cores: scripts/probe-domain-routing.js. On a router the
 * name only chooses the route, and the address stays; the switch still turns it off.
 */
process.env.IRNETFREE_PLATFORM = 'openwrt';
const test = require('node:test');
const assert = require('node:assert/strict');
const H = require('./serviceHarness');
const { buildConfig } = require('../src/main/configBuilder');
const F = require('./fixtures');

process.setMaxListeners(60);
test.after(() => H.cleanupDirs());
const { SERVER, start } = H;
const sniffingOf = (cfg, tag = 'socks-in') => cfg.inbounds.find((i) => i.tag === tag).sniffing;

test('a router reads the name for its rules and keeps the address it was sent to', async (t) => {
  const s = start({ settings: {} });
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  const sniffing = sniffingOf(s.state.xray.starts[0].config);
  assert.equal(sniffing.enabled, true);
  assert.equal(sniffing.routeOnly, true);
  assert.deepEqual(sniffing.destOverride, ['http', 'tls', 'quic']);
});

test('a router\'s sniffing switch still turns it off', async (t) => {
  const s = start({ settings: { enableSniffing: false } });
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  assert.deepEqual(sniffingOf(s.state.xray.starts[0].config), { enabled: false });
});

test('a desktop still replaces the address: a poisoned or stale answer is rescued by the name', () => {
  const c = buildConfig({ mode: 'single', server: F.VLESS_WS_TLS }, F.settings({}));
  assert.equal(sniffingOf(c).routeOnly, false);
});
