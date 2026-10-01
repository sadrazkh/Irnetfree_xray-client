'use strict';
/**
 * setRemoteBypass (v1.16 A10, spec R8/C2): the destinations the remote
 * control uses — the relay, Cloudflare's tunnel edge — never ride the tunnel.
 * The service keeps a list per owner and applies the union: while the
 * gateway is up one `ip rule … pref 8997 to <cidr> lookup main` per cidr
 * (added and removed live, swept with the gateway's own rules), and the next
 * core config carries a direct rule for the names and the addresses.
 * feat/remote's agent and cloudflared code against exactly this.
 */
process.env.IRNETFREE_PLATFORM = 'openwrt';
const test = require('node:test');
const assert = require('node:assert/strict');
const H = require('./serviceHarness');

process.setMaxListeners(60);
test.after(() => H.cleanupDirs());
const { SERVER, until } = H;

const added = (s) => s.state.commands.filter(l => /^ip -[46] rule add pref 8997 /.test(l));
const removed = (s) => s.state.commands.filter(l => /^ip -[46] rule del pref 8997 to /.test(l));
const directRules = (cfg) => cfg.routing.rules.filter(r => r.outboundTag === 'direct' && ((r.domain || []).some(d => d.startsWith('full:')) || (r.ip || []).some(ip => /^(203\.0\.113|2606:4700)/.test(ip))));

test('while the gateway is up the rules are added live, a replaced list removes what left, and the next config carries the direct rules', async (t) => {
  const s = H.start();
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  assert.deepEqual(added(s), [], 'nothing to bypass yet');
  assert.deepEqual(directRules(s.state.xray.starts[0].config), []);

  await s.service.setRemoteBypass('relay', { hosts: ['relay.example'], cidrs: ['203.0.113.7', '2606:4700::/32'] });
  assert.deepEqual(added(s), ['ip -4 rule add pref 8997 to 203.0.113.7/32 lookup main', 'ip -6 rule add pref 8997 to 2606:4700::/32 lookup main']);
  assert.deepEqual(s.service.remoteBypass(), { hosts: ['relay.example'], cidrs: ['203.0.113.7/32', '2606:4700::/32'] });

  // the second owner's list joins the union; a cidr both name is laid once
  await s.service.setRemoteBypass('cloudflared', { hosts: ['edge.example'], cidrs: ['203.0.113.7/32', '198.51.100.0/24'] });
  assert.deepEqual(added(s).slice(2), ['ip -4 rule add pref 8997 to 198.51.100.0/24 lookup main']);
  assert.deepEqual(s.service.remoteBypass(), { hosts: ['relay.example', 'edge.example'], cidrs: ['203.0.113.7/32', '2606:4700::/32', '198.51.100.0/24'] });

  // the relay's list replaced: 2606:4700::/32 leaves, 203.0.113.7 stays (cloudflared still names it)
  await s.service.setRemoteBypass('relay', { hosts: ['relay.example'], cidrs: ['203.0.113.9'] });
  assert.deepEqual(removed(s), ['ip -6 rule del pref 8997 to 2606:4700::/32 lookup main']);
  assert.ok(added(s).includes('ip -4 rule add pref 8997 to 203.0.113.9/32 lookup main'));

  // the next core config (a rebuild) carries a direct rule for the names and one for the addresses
  await s.service.invoke('vpn:reconnect');
  await until(() => s.statuses.filter(x => x.state === 'connected').length >= 2, 'the rebuild');
  const cfg = s.state.xray.starts.at(-1).config;
  const rules = directRules(cfg);
  // the union in owner order (the relay's key kept its place when its list was replaced), then cloudflared's
  assert.deepEqual(rules.map(r => r.domain || r.ip), [['full:relay.example', 'full:edge.example'], ['203.0.113.9/32', '203.0.113.7/32', '198.51.100.0/24']]);
  // …and the rebuilt gateway laid the rules again (its teardown swept them)
  assert.ok(s.state.commands.includes('ip -4 rule del pref 8997'), 'swept with the gateway');
  const after = s.state.commands.lastIndexOf('ip -4 rule del pref 8997');
  assert.ok(s.state.commands.slice(after).includes('ip -4 rule add pref 8997 to 198.51.100.0/24 lookup main'), 'laid again on the new gateway');

  // an owner's empty list takes its destinations out; junk never reaches ip
  await s.service.setRemoteBypass('cloudflared', { hosts: [], cidrs: [] });
  await s.service.setRemoteBypass('relay', { hosts: ['relay.example'], cidrs: ['not an address', '203.0.113.9'] });
  assert.deepEqual(s.service.remoteBypass(), { hosts: ['relay.example'], cidrs: ['203.0.113.9/32'] });
  assert.ok(!s.state.commands.some(l => /not an address/.test(l)));
  await assert.rejects(s.service.setRemoteBypass('someone', { hosts: [], cidrs: [] }), /owner/);
});

test('with the gateway down the list is only remembered — laid when the gateway comes up, and in its first config', async (t) => {
  const s = H.start();
  t.after(() => s.service.shutdown());
  await s.service.setRemoteBypass('relay', { hosts: ['relay.example'], cidrs: ['203.0.113.7/32'] });
  assert.deepEqual(added(s), []);
  await s.service.invoke('connect', SERVER.id);
  assert.deepEqual(added(s), ['ip -4 rule add pref 8997 to 203.0.113.7/32 lookup main']);
  assert.deepEqual(directRules(s.state.xray.starts[0].config).map(r => r.domain || r.ip), [['full:relay.example'], ['203.0.113.7/32']]);
  // the RPC form (the smoke, and any token holder) is the same call
  assert.deepEqual(await s.service.invoke('remote:bypass', { owner: 'relay', hosts: [], cidrs: ['198.51.100.1'] }), { ok: true, hosts: [], cidrs: ['198.51.100.1/32'] });
  assert.ok(added(s).includes('ip -4 rule add pref 8997 to 198.51.100.1/32 lookup main'));
  assert.ok(removed(s).includes('ip -4 rule del pref 8997 to 203.0.113.7/32 lookup main'));
});

test('directResolvers: the in-country, route-excluded resolvers of the live config — else the plain addresses of the setting', async (t) => {
  const s = H.start({ settings: { routingMode: 'bypass-ir', dnsDirect: ['178.22.122.100', 'https://dns.example/dns-query', '185.51.200.2'] } });
  t.after(() => s.service.shutdown());
  assert.deepEqual(s.service.directResolvers(), ['178.22.122.100', '185.51.200.2'], 'not connected: the setting’s plain addresses, a DoH URL is not a resolver address');
  await s.service.invoke('connect', SERVER.id);
  const live = s.service.directResolvers();
  assert.ok(live.length >= 1 && live.every(ip => /^\d+\.\d+\.\d+\.\d+$/.test(ip)), JSON.stringify(live));
  // exactly what the running config dials direct — and when this config carries no such rule (no geo
  // files here, so the country bypass that wants an in-country resolver is skipped), the setting's addresses
  const ofConfig = require('../src/main/configBuilder').resolverBypassIpsOf(s.state.xray.starts[0].config);
  assert.deepEqual(live, ofConfig.length ? ofConfig : ['178.22.122.100', '185.51.200.2']);
  await s.service.invoke('disconnect');
  assert.deepEqual(s.service.directResolvers(), ['178.22.122.100', '185.51.200.2'], 'nothing live: the setting again');
});
