'use strict';
/**
 * What the tunnel leaves out for a WireGuard. Only what the core dials by itself: a stored WireGuard that no rule uses, or
 * one that rides a base or a chain, is dialled by nothing here, and left out of the tunnel it takes every site on its address
 * with it: a company's sites on the machine of its WireGuard stopped opening under advanced routing, and only there, and a
 * device's own WireGuard behind a router died the same way. Chains and advanced rules themselves must not change.
 */
process.env.IRNETFREE_PLATFORM = 'openwrt';   // the gateway the harness fakes

const test = require('node:test');
const assert = require('node:assert');
const { buildConfig, pinnedEntryIps } = require('../src/main/configBuilder');
const { parseLink } = require('../src/main/parser');
const H = require('./serviceHarness');

const WG_IP = '203.0.113.50';
const WG_HOST = 'vpnhost.example.test';
const key = (c) => encodeURIComponent(c.repeat(43) + '=');
const WG = Object.assign(parseLink(`wireguard://${key('A')}@${WG_HOST}:51820?publickey=${key('B')}&address=10.0.0.2/32&allowedips=0.0.0.0/0#vpnhost`), { id: 'wg-corp' });
const BASE_SRV = Object.assign(parseLink('vless://11111111-1111-1111-1111-111111111111@198.51.100.7:443?type=tcp&security=none#base'), { id: 'base-srv' });
const OTHER = Object.assign(parseLink('vless://11111111-1111-1111-1111-111111111111@198.51.100.8:443?type=tcp&security=none#other'), { id: 'other-srv' });
const ALL = [BASE_SRV, OTHER, WG];
const SETTINGS = { socksPort: 1, httpPort: 2, apiPort: 3, geoAssets: false, blockAds: false, enableSniffing: true, routingMode: 'global', wgEndpointIps: { [WG_HOST]: WG_IP } };
const advanced = (rules, extra = {}) => Object.assign({ mode: 'advanced', serversById: Object.fromEntries(ALL.map((s) => [s.id, s])), chainsById: {}, chain: [], rules, def: BASE_SRV.id, base: BASE_SRV.id, defVia: 'inherit', useMode: false }, extra);

test('the config itself carries the chained WireGuard as before: through its hop, with the address it was given', () => {
  const c = buildConfig(advanced([{ type: 'ip', value: '10.0.0.0/8', target: WG.id }]), SETTINGS);
  const wg = c.outbounds.find((o) => o.protocol === 'wireguard');
  assert.ok(wg, 'the WireGuard is in the config');
  assert.equal(wg.streamSettings.sockopt.dialerProxy.startsWith('base-'), true, 'it rides the base');
  assert.ok(String(wg.settings.peers[0].endpoint).startsWith(WG_IP + ':'), 'with the address resolved for it');
  assert.ok(c.routing.rules.some((r) => r.outboundTag === wg.tag && (r.ip || []).includes('10.0.0.0/8')), 'and the rule goes to it');
});

test('a WireGuard no rule uses, or one on a base, leaves its address inside the tunnel', () => {
  const unused = advanced([]);
  assert.deepEqual(pinnedEntryIps(buildConfig(unused, SETTINGS), [BASE_SRV.address], SETTINGS), []);
  const onBase = advanced([{ type: 'ip', value: '10.0.0.0/8', target: WG.id }]);
  assert.deepEqual(pinnedEntryIps(buildConfig(onBase, SETTINGS), [BASE_SRV.address], SETTINGS), []);
});

test('a WireGuard the core dials by itself stays out of the tunnel, or it would loop into the one it carries', () => {
  const direct = advanced([{ type: 'ip', value: '10.0.0.0/8', target: WG.id, via: 'none' }]);
  assert.deepEqual(pinnedEntryIps(buildConfig(direct, SETTINGS), [BASE_SRV.address, WG_HOST], SETTINGS), [WG_IP]);
  const single = { mode: 'single', server: WG };
  assert.deepEqual(pinnedEntryIps(buildConfig(single, SETTINGS), [WG_HOST], SETTINGS), [WG_IP]);
  // on a core that writes another shape: the plan's own entry says it
  assert.deepEqual(pinnedEntryIps({ endpoints: [] }, [WG_HOST], SETTINGS), [WG_IP]);
});

test('a chain: first hop out of the tunnel, a later hop inside it', () => {
  const later = { mode: 'chain', chain: [BASE_SRV, WG], name: 'c' };
  assert.deepEqual(pinnedEntryIps(buildConfig(later, SETTINGS), [BASE_SRV.address], SETTINGS), []);
  const first = { mode: 'chain', chain: [WG, BASE_SRV], name: 'c' };
  assert.deepEqual(pinnedEntryIps(buildConfig(first, SETTINGS), [WG_HOST], SETTINGS), [WG_IP]);
});

test('a dialer of its own (noise) is still the core dialling by itself; an entry server\'s names stay as they were', () => {
  const config = { outbounds: [{ tag: 'w', protocol: 'wireguard', settings: { peers: [{ endpoint: WG_IP + ':51820' }] }, streamSettings: { sockopt: { dialerProxy: 'dpi-1' } } }, { tag: 'dpi-1', protocol: 'freedom', settings: {} }] };
  assert.deepEqual(pinnedEntryIps(config, [], {}), [WG_IP]);
  assert.deepEqual(pinnedEntryIps(null, ['a.test'], { entryHostIps: { 'a.test': ['192.0.2.1', '192.0.2.2'] } }), ['192.0.2.1', '192.0.2.2']);
  assert.deepEqual(pinnedEntryIps({ outbounds: [] }, [], undefined), []);
});

/** A service with these servers and one routing profile; what its tunnel was told to leave out. */
async function bypassOf(t, rules, selection = '__advanced__:p1') {
  const profile = { id: 'p1', name: 'P', rules, def: BASE_SRV.id, defVia: 'inherit', base: BASE_SRV.id, useMode: false };
  const s = H.start({ servers: ALL, routingProfiles: [profile], settings: { advancedRouting: true, tunMode: true } }, {
    resolveHost: async (h) => ({ ips: [h === WG_HOST ? WG_IP : '198.51.100.99'], source: 'os' }),
    pathReadsHello: async () => false
  });
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', selection);
  const bypass = s.state.inners.at(-1).bypass;
  await s.service.invoke('disconnect');
  return bypass;
}

test('the router\'s service: an advanced plan that never uses the stored WireGuard does not cut its address out', async (t) => {
  const bypass = await bypassOf(t, []);
  assert.ok(!bypass.includes(WG_IP), 'its address stays in the tunnel, with every site on it');
  assert.ok(bypass.includes(BASE_SRV.address), 'the base it really dials is out, as before');
});

test('the router\'s service: a WireGuard chained on the base stays in the tunnel; dialled by itself it stays out', async (t) => {
  const chained = await bypassOf(t, [{ type: 'ip', value: '10.0.0.0/8', target: WG.id }]);
  assert.ok(!chained.includes(WG_IP));
  assert.ok(chained.includes(BASE_SRV.address));
  const direct = await bypassOf(t, [{ type: 'ip', value: '10.0.0.0/8', target: WG.id, via: 'none' }]);
  assert.ok(direct.includes(WG_IP), 'the core dials it: out of the tunnel');
});
