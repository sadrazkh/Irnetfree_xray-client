'use strict';
/**
 * Xray config-builder tests.
 *
 * The order of `routing.rules` is load-bearing (xray takes the FIRST match), so
 * most assertions here are about order, not just presence.
 *
 * The Android side has its own port of this file
 * (android/.../core/ConfigBuilder.kt) that MUST produce the same shape — when
 * you change anything here, change it there too.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { buildConfig, buildTestConfig, buildMultiTestConfig, buildRoutingRules, buildChainOutbounds, resolverBypassIps, resolverBypassIpsOf, wgResolvers, wgEndpointHosts, wgResolverAddresses, entryHosts, withHosts } = require('../src/main/configBuilder');
const {
  server, settings, ruleTags, outboundTagged, vlessWithMarkers,
  VLESS_WS_TLS, TROJAN_TCP_TLS, SS_TCP, WG_BAD_MASK, WG_CORP
} = require('./fixtures');

const single = (server) => ({ mode: 'single', server: server || VLESS_WS_TLS });

/* ----------------------------- inbounds ----------------------------- */

test('single: inbounds are socks / http only — metrics replaces the api inbound', () => {
  const c = buildConfig(single(), settings({ socksPort: 1080, httpPort: 1081, apiPort: 1085 }));

  assert.deepEqual(c.inbounds.map(i => [i.tag, i.port, i.protocol]), [
    ['socks-in', 1080, 'socks'],
    ['http-in', 1081, 'http']
  ]);
  assert.deepEqual(c.inbounds[0].settings, { auth: 'noauth', udp: true });
  // the stats endpoint is a listener, not an inbound, so nothing can collide with it
  assert.deepEqual(c.metrics, { tag: 'metrics', listen: '127.0.0.1:1085' });
  assert.equal(c.api, undefined);
  // the counters still have to be collected
  assert.deepEqual(c.stats, {});
  assert.equal(c.policy.system.statsOutboundUplink, true);
  assert.equal(c.policy.system.statsOutboundDownlink, true);
});

test('no plan emits an api routing rule any more', () => {
  const plans = [
    single(),
    { mode: 'chain', chain: [VLESS_WS_TLS, TROJAN_TCP_TLS] },
    advancedPlan({ rules: [{ type: 'domain', value: 'a.com', target: 'sv-vless' }] }),
    poolPlan([{ id: 'e1', target: 'sv-trojan', socksPort: 60001 }])
  ];
  for (const p of plans) {
    const c = buildConfig(p, settings());
    assert.equal(c.routing.rules.some(r => r.outboundTag === 'api'), false, p.mode);
    assert.equal(c.inbounds.some(i => i.tag === 'api'), false, p.mode);
    assert.equal(c.metrics.listen, '127.0.0.1:10085', p.mode);
  }
});

test('allowLan flips the socks/http listen address', () => {
  const off = buildConfig(single(), settings({ allowLan: false }));
  assert.deepEqual(off.inbounds.map(i => i.listen), ['127.0.0.1', '127.0.0.1']);

  const on = buildConfig(single(), settings({ allowLan: true }));
  assert.deepEqual(on.inbounds.map(i => i.listen), ['0.0.0.0', '0.0.0.0']);
  // the metrics listener is never exposed to the LAN
  assert.equal(on.metrics.listen, '127.0.0.1:10085');
});

test('enableSniffing toggles destOverride on the proxy inbounds', () => {
  const on = buildConfig(single(), settings({ enableSniffing: true }));
  assert.deepEqual(on.inbounds[0].sniffing, { enabled: true, destOverride: ['http', 'tls', 'quic'], routeOnly: false });

  const off = buildConfig(single(), settings({ enableSniffing: false }));
  assert.deepEqual(off.inbounds[0].sniffing, { enabled: false });
});

test('dns and log level come from settings (unmanaged: the list verbatim)', () => {
  const c = buildConfig(single(), settings({ dnsRemote: ['9.9.9.9'], logLevel: 'debug' }));
  assert.deepEqual(c.dns, { servers: ['9.9.9.9'], queryStrategy: 'UseIPv4' });
  assert.equal(c.log.loglevel, 'debug');
  assert.equal(c.outbounds.some(o => o.tag === 'dns-out'), false);
});

test('ipv6 off keeps the direct outbound on IPv4; on lets it use both', () => {
  const off = buildConfig(single(), settings());
  assert.equal(outboundTagged(off, 'direct').settings.domainStrategy, 'UseIPv4');
  const on = buildConfig(single(), settings({ ipv6: true }));
  assert.equal(outboundTagged(on, 'direct').settings.domainStrategy, 'UseIP');
  assert.equal(on.dns.queryStrategy, 'UseIP');
});

/* ----------------------------- simple routing ----------------------------- */

test('global mode: ads, private bypass, then catch-all to proxy', () => {
  const c = buildConfig(single(), settings({ routingMode: 'global', blockAds: true }));
  assert.deepEqual(ruleTags(c), ['block', 'direct', 'proxy']);

  const last = c.routing.rules.at(-1);
  assert.deepEqual(last, { type: 'field', port: '0-65535', outboundTag: 'proxy' });
});

test('direct mode sends the catch-all to direct', () => {
  const c = buildConfig(single(), settings({ routingMode: 'direct' }));
  assert.equal(c.routing.rules.at(-1).outboundTag, 'direct');
});

test('bypass-ir adds domain + ip direct rules before the catch-all', () => {
  const c = buildConfig(single(), settings({ routingMode: 'bypass-ir', blockAds: false }));
  assert.deepEqual(ruleTags(c), ['direct', 'direct', 'direct', 'proxy']);
  assert.deepEqual(c.routing.rules[1].domain, ['geosite:category-ir', 'regexp:.*\\.ir$']);
  assert.deepEqual(c.routing.rules[2].ip, ['geoip:ir']);
});

test('bypass-cn adds the china geo rules', () => {
  const c = buildConfig(single(), settings({ routingMode: 'bypass-cn', blockAds: false }));
  assert.deepEqual(c.routing.rules[1].domain, ['geosite:cn']);
  assert.deepEqual(c.routing.rules[2].ip, ['geoip:cn']);
});

test('the private-range bypass never depends on geoip.dat', () => {
  // geoip:private would make xray refuse to start when the .dat file is absent,
  // so the ranges are always literal.
  for (const geoAssets of [true, false]) {
    const c = buildConfig(single(), settings({ geoAssets }));
    const priv = c.routing.rules.find(r => r.outboundTag === 'direct' && r.ip);
    assert.ok(priv.ip.includes('127.0.0.0/8'), 'loopback missing');
    assert.ok(priv.ip.includes('192.168.0.0/16'), 'LAN missing');
    assert.ok(priv.ip.includes('fc00::/7'), 'IPv6 ULA missing');
    assert.ok(!priv.ip.some(v => /^geoip:/.test(v)), 'must not use a geoip token');
  }
});

/* --------------------- missing geo assets (no .dat files) --------------------- */

test('geoAssets:false drops the ad-block rule', () => {
  const c = buildConfig(single(), settings({ blockAds: true, geoAssets: false }));
  assert.deepEqual(ruleTags(c), ['direct', 'proxy']);
});

test('geoAssets:false degrades bypass-ir to plain global routing', () => {
  const c = buildConfig(single(), settings({ routingMode: 'bypass-ir', blockAds: false, geoAssets: false }));
  assert.deepEqual(ruleTags(c), ['direct', 'proxy']);
  assert.equal(c.routing.rules.at(-1).outboundTag, 'proxy');
});

test('geoAssets:false strips geo tokens out of custom rules but keeps the rest', () => {
  const custom = [{ outboundTag: 'direct', domain: 'geosite:cn, example.com', ip: 'geoip:cn, 8.8.8.8' }];

  const withGeo = buildConfig(single(), settings({ customRules: custom }));
  const wg = withGeo.routing.rules.find(r => r.domain && r.domain.includes('example.com'));
  assert.deepEqual(wg.domain, ['geosite:cn', 'example.com']);
  assert.deepEqual(wg.ip, ['geoip:cn', '8.8.8.8']);

  const noGeo = buildConfig(single(), settings({ customRules: custom, geoAssets: false }));
  const ng = noGeo.routing.rules.find(r => r.domain && r.domain.includes('example.com'));
  assert.deepEqual(ng.domain, ['example.com']);
  assert.deepEqual(ng.ip, ['8.8.8.8']);
});

test('custom rules sit before the catch-all so they actually take effect', () => {
  const c = buildConfig(single(), settings({
    blockAds: false,
    customRules: [{ outboundTag: 'direct', domain: 'intranet.local' }]
  }));
  const idx = c.routing.rules.findIndex(r => r.domain && r.domain.includes('intranet.local'));
  assert.ok(idx > -1, 'custom rule missing');
  assert.equal(idx, c.routing.rules.length - 2, 'custom rule must be the last rule before the catch-all');
});

test('rule values split on both "," and "|"', () => {
  // the settings page writes `domain, a.com|b.com, proxy`, so a value arriving
  // here as a raw string must split the same way ConfigBuilder.kt does
  const custom = buildConfig(single(), settings({
    blockAds: false,
    customRules: [{ outboundTag: 'direct', domain: 'a.com|b.com, c.com' }]
  }));
  assert.deepEqual(custom.routing.rules.find(r => r.domain).domain, ['a.com', 'b.com', 'c.com']);

  const adv = buildConfig(advancedPlan({
    rules: [{ type: 'ip', value: '1.1.1.1|2.2.2.2', target: 'sv-vless' }]
  }), settings({ blockAds: false }));
  assert.deepEqual(adv.routing.rules[0].ip, ['1.1.1.1', '2.2.2.2']);
});

test('a custom rule with no domain/ip/port is dropped', () => {
  const c = buildConfig(single(), settings({ customRules: [{ outboundTag: 'direct' }, { domain: 'x.com' }] }));
  assert.deepEqual(ruleTags(c), ['block', 'direct', 'proxy']);
});

/* ----------------------------- chains ----------------------------- */

test('chain: each hop dials through the previous one, exit keeps the routing tag', () => {
  const outs = buildChainOutbounds([VLESS_WS_TLS, TROJAN_TCP_TLS, SS_TCP], 'proxy');

  assert.deepEqual(outs.map(o => o.tag), ['proxy-h0', 'proxy-h1', 'proxy']);
  assert.equal(outs[0].streamSettings.sockopt, undefined);
  assert.equal(outs[1].streamSettings.sockopt.dialerProxy, 'proxy-h0');
  assert.equal(outs[2].streamSettings.sockopt.dialerProxy, 'proxy-h1');
});

test('chain hop tags are namespaced so two chains can coexist', () => {
  const a = buildChainOutbounds([VLESS_WS_TLS, TROJAN_TCP_TLS], 'out-chain-a');
  const b = buildChainOutbounds([SS_TCP, TROJAN_TCP_TLS], 'out-chain-b');
  const tags = [...a, ...b].map(o => o.tag);
  assert.equal(new Set(tags).size, tags.length, 'tag collision between chains');
});

test('chain: the source outbounds are never mutated', () => {
  const before = JSON.stringify(VLESS_WS_TLS);
  buildChainOutbounds([VLESS_WS_TLS, TROJAN_TCP_TLS], 'proxy');
  assert.equal(JSON.stringify(VLESS_WS_TLS), before);
});

test('chain plan builds proxy hops plus direct and block', () => {
  const c = buildConfig({ mode: 'chain', chain: [VLESS_WS_TLS, TROJAN_TCP_TLS] }, settings());
  assert.deepEqual(c.outbounds.map(o => o.tag), ['proxy-h0', 'proxy', 'direct', 'block']);
});

/* ----------------------------- advanced routing ----------------------------- */

function advancedPlan(over) {
  return Object.assign({
    mode: 'advanced',
    serversById: { 'sv-vless': VLESS_WS_TLS, 'sv-trojan': TROJAN_TCP_TLS, 'sv-wg': WG_BAD_MASK },
    chainsById: { c1: [VLESS_WS_TLS, TROJAN_TCP_TLS] },
    chain: [],
    rules: [],
    def: 'direct'
  }, over || {});
}

test('advanced: user rules win over the private-range bypass', () => {
  // A database on an internal range must reach the chosen config, not go direct.
  const c = buildConfig(advancedPlan({
    rules: [{ type: 'ip', value: '10.20.0.0/16', target: 'sv-wg' }],
    def: 'sv-vless'
  }), settings({ blockAds: false }));

  const userIdx = c.routing.rules.findIndex(r => r.ip && r.ip.includes('10.20.0.0/16'));
  const privIdx = c.routing.rules.findIndex(r => r.ip && r.ip.includes('192.168.0.0/16'));
  assert.ok(userIdx > -1 && privIdx > -1);
  assert.ok(userIdx < privIdx, 'user rules must come before the private bypass');
  assert.equal(c.routing.rules[userIdx].outboundTag, 'out-sv-wg');
});

test('advanced: rule targets become deduplicated outbounds', () => {
  const c = buildConfig(advancedPlan({
    rules: [
      { type: 'domain', value: 'a.com, b.com', target: 'sv-vless' },
      { type: 'domain', value: 'c.com', target: 'sv-vless' },   // same target -> one outbound
      { type: 'port', value: '80,443', target: 'sv-trojan' }
    ],
    def: 'direct'
  }), settings({ blockAds: false }));

  assert.deepEqual(c.outbounds.map(o => o.tag), ['out-sv-vless', 'out-sv-trojan', 'direct', 'block']);
  assert.deepEqual(c.routing.rules[0].domain, ['a.com', 'b.com']);
  assert.equal(c.routing.rules[2].port, '80,443');
  assert.equal(c.routing.rules.at(-1).outboundTag, 'direct');
});

test('advanced: a chain: target expands into namespaced chain outbounds', () => {
  const c = buildConfig(advancedPlan({
    rules: [{ type: 'domain', value: 'x.com', target: 'chain:c1' }]
  }), settings({ blockAds: false }));

  assert.deepEqual(c.outbounds.map(o => o.tag), ['out-chain-c1-h0', 'out-chain-c1', 'direct', 'block']);
  assert.equal(c.routing.rules[0].outboundTag, 'out-chain-c1');
});

/* --------- advanced routing + a simple routing mode on top (v0.15) --------- */

test('advanced: without advancedUseMode the routing mode is ignored, as before', () => {
  const c = buildConfig(advancedPlan({
    rules: [{ type: 'ip', value: '10.20.0.0/16', target: 'sv-wg' }], def: 'sv-vless'
  }), settings({ routingMode: 'bypass-ir', blockAds: false }));

  assert.equal(c.routing.rules.some(r => (r.domain || []).includes('geosite:category-ir')), false);
  assert.equal(c.routing.rules.some(r => (r.ip || []).includes('geoip:ir')), false);
});

test('advanced: advancedUseMode lays the bypass under the user rules and above the default', () => {
  const c = buildConfig(advancedPlan({
    rules: [{ type: 'ip', value: '10.20.0.0/16', target: 'sv-wg' }], def: 'sv-vless'
  }), settings({ routingMode: 'bypass-ir', advancedUseMode: true, blockAds: false }));

  const rules = c.routing.rules;
  const user = rules.findIndex(r => (r.ip || []).includes('10.20.0.0/16'));
  const priv = rules.findIndex(r => (r.ip || []).includes('192.168.0.0/16'));
  const site = rules.findIndex(r => (r.domain || []).includes('geosite:category-ir'));
  const gip = rules.findIndex(r => (r.ip || []).includes('geoip:ir'));

  assert.ok(user > -1 && priv > -1 && site > -1 && gip > -1, 'every rule is present');
  // the corporate rule still wins; the country bypass sits under it, and the
  // catch-all still goes to the advanced default (NOT to 'proxy')
  assert.ok(user < priv && priv < site && site < gip, `order was ${JSON.stringify(rules.map(r => r.outboundTag))}`);
  assert.equal(rules[site].outboundTag, 'direct');
  assert.equal(rules[gip].outboundTag, 'direct');
  assert.equal(rules.at(-1).port, '0-65535');
  assert.equal(rules.at(-1).outboundTag, 'out-sv-vless');
});

test('advanced: advancedUseMode with the global mode adds no geo rules', () => {
  const c = buildConfig(advancedPlan({ def: 'sv-vless' }),
    settings({ routingMode: 'global', advancedUseMode: true, blockAds: false }));

  assert.equal(c.routing.rules.some(r => (r.ip || []).includes('geoip:ir')), false);
  assert.equal(c.routing.rules.at(-1).outboundTag, 'out-sv-vless');
});

test('advanced: advancedUseMode never routes the catch-all away from the default', () => {
  // 'direct' mode ends the simple list with a direct catch-all — under advanced
  // routing the default target is the user's, so that tail must be dropped.
  const c = buildConfig(advancedPlan({ def: 'sv-vless' }),
    settings({ routingMode: 'direct', advancedUseMode: true, blockAds: false }));

  assert.equal(c.routing.rules.at(-1).outboundTag, 'out-sv-vless');
  assert.equal(c.routing.rules.filter(r => r.port === '0-65535').length, 1);
});

test('advanced: advancedUseMode drops the geo rules when the geo files are missing', () => {
  const c = buildConfig(advancedPlan({ def: 'sv-vless' }),
    settings({ routingMode: 'bypass-ir', advancedUseMode: true, blockAds: false, geoAssets: false }));

  assert.equal(c.routing.rules.some(r => JSON.stringify(r).includes('geosite:')), false);
  assert.equal(c.routing.rules.some(r => JSON.stringify(r).includes('geoip:')), false);
});

test('advanced: a one-member chain collapses to a single outbound', () => {
  const c = buildConfig(advancedPlan({
    chainsById: { solo: [VLESS_WS_TLS] },
    rules: [{ type: 'domain', value: 'x.com', target: 'chain:solo' }]
  }), settings({ blockAds: false }));
  assert.deepEqual(c.outbounds.map(o => o.tag), ['out-chain-solo', 'direct', 'block']);
});

// A target that no longer exists (a server deleted, or replaced by a
// subscription refresh; a chain removed or emptied) used to route `direct`:
// "connected" with the traffic it was meant to protect leaving in the clear.
test('advanced: a rule whose target no longer exists is skipped — its traffic follows the default', () => {
  const c = buildConfig(advancedPlan({
    chainsById: { c1: [VLESS_WS_TLS, TROJAN_TCP_TLS], emptied: [] },
    rules: [
      { type: 'domain', value: 'x.com', target: 'no-such-server' },
      { type: 'domain', value: 'y.com', target: 'chain:missing' },
      { type: 'domain', value: 'w.com', target: 'chain:emptied' },
      { type: 'domain', value: 'v.com', target: 'chain' },          // the legacy chain, empty here
      { type: 'domain', value: 'z.com', target: 'block' }
    ],
    def: 'sv-vless'
  }), settings({ blockAds: false }));

  assert.deepEqual(ruleTags(c), ['block', 'direct', 'out-sv-vless']);
  assert.deepEqual(c.routing.rules[0].domain, ['z.com']);
  assert.equal(c.routing.rules.some(r => r.domain && r.domain.some(d => /^[xywv]\.com$/.test(d))), false);
  assert.deepEqual(c.outbounds.map(o => o.tag), ['out-sv-vless', 'direct', 'block']);
});

test('advanced: an empty rule target is still direct, and direct / block defaults are untouched', () => {
  const c = buildConfig(advancedPlan({ rules: [{ type: 'domain', value: 'x.com', target: '' }], def: 'direct' }), settings({ blockAds: false }));
  assert.deepEqual(ruleTags(c), ['direct', 'direct', 'direct']);
  assert.equal(buildConfig(advancedPlan({ def: 'block' }), settings({ blockAds: false })).routing.rules.at(-1).outboundTag, 'block');
});

test('advanced: a default that no longer exists is an error, never a silent direct', () => {
  for (const def of ['also-missing', 'chain:missing', 'chain:emptied', 'chain']) {
    const plan = advancedPlan({ chainsById: { emptied: [] }, def });
    assert.throws(() => buildConfig(plan, settings({ lang: 'en' })), /default target .*no longer exists/i, def);
    assert.throws(() => buildConfig(plan, settings({ lang: 'fa' })), /پیش‌فرض/, def + ' (fa)');
  }
});

test('advanced: rules with no usable values are skipped entirely', () => {
  const c = buildConfig(advancedPlan({
    rules: [
      { type: 'domain', value: '   ', target: 'sv-vless' },
      { type: 'nonsense', value: 'a.com', target: 'sv-vless' },
      null
    ]
  }), settings({ blockAds: false }));
  assert.deepEqual(ruleTags(c), ['direct', 'direct']);
});

test('advanced: geoAssets:false drops geo tokens and any rule left empty', () => {
  const c = buildConfig(advancedPlan({
    rules: [
      { type: 'ip', value: 'geoip:ir, 5.5.5.5', target: 'sv-vless' },
      { type: 'domain', value: 'geosite:cn', target: 'sv-trojan' }   // becomes empty -> dropped
    ]
  }), settings({ blockAds: false, geoAssets: false }));

  const ipRule = c.routing.rules.find(r => r.ip && r.ip.includes('5.5.5.5'));
  assert.deepEqual(ipRule.ip, ['5.5.5.5']);
  assert.equal(c.routing.rules.some(r => r.domain), false);
});

// reg.tagFor() REGISTERS the target's outbound, so it must not run for a rule
// that is about to be dropped — otherwise an unused server's address and
// credentials get written into config.json (and a `chain:` target materializes
// its whole chain) for a rule that routes nothing.
test('advanced: a dropped rule leaves no orphan outbound behind', () => {
  const cases = {
    'all geo tokens stripped': { type: 'domain', value: 'geosite:cn', target: 'sv-trojan' },
    'blank value': { type: 'domain', value: '  ', target: 'sv-trojan' },
    'unknown rule type': { type: 'nonsense', value: 'a.com', target: 'sv-trojan' }
  };
  for (const [name, rule] of Object.entries(cases)) {
    const c = buildConfig(advancedPlan({ rules: [rule] }), settings({ blockAds: false, geoAssets: false }));
    assert.deepEqual(c.outbounds.map(o => o.tag), ['direct', 'block'], name);
  }
});

test('advanced: a dropped chain rule does not materialize the chain', () => {
  const c = buildConfig(advancedPlan({
    rules: [{ type: 'ip', value: 'geoip:ir', target: 'chain:c1' }]
  }), settings({ blockAds: false, geoAssets: false }));
  assert.deepEqual(c.outbounds.map(o => o.tag), ['direct', 'block']);
});

test('advanced: a surviving rule still registers its outbound', () => {
  // the guard above must not swing too far the other way
  const c = buildConfig(advancedPlan({
    rules: [{ type: 'ip', value: 'geoip:ir, 5.5.5.5', target: 'sv-trojan' }]
  }), settings({ blockAds: false, geoAssets: false }));
  assert.deepEqual(c.outbounds.map(o => o.tag), ['out-sv-trojan', 'direct', 'block']);
  assert.equal(c.routing.rules[0].outboundTag, 'out-sv-trojan');
});

/* ----------------------------- proxy pool ----------------------------- */

function poolPlan(entries, primary) {
  return {
    mode: 'pool',
    entries,
    primary: primary || 'sv-vless',
    serversById: { 'sv-vless': VLESS_WS_TLS, 'sv-trojan': TROJAN_TCP_TLS },
    chainsById: { c1: [VLESS_WS_TLS, TROJAN_TCP_TLS] },
    chain: []
  };
}

test('pool: standard ports keep serving the primary exit', () => {
  const c = buildConfig(poolPlan([
    { id: 'e1', name: 'A', target: 'sv-trojan', socksPort: 60001, httpPort: 60002 }
  ]), settings());

  assert.deepEqual(c.inbounds.map(i => [i.tag, i.port]), [
    ['socks-in', 10808], ['http-in', 10809],
    ['ps-e1', 60001], ['ph-e1', 60002]
  ]);

  const stdRule = c.routing.rules.find(r => Array.isArray(r.inboundTag) && r.inboundTag.includes('socks-in'));
  assert.equal(stdRule.outboundTag, 'out-sv-vless');
  const e1Rule = c.routing.rules.find(r => Array.isArray(r.inboundTag) && r.inboundTag.includes('ps-e1'));
  assert.equal(e1Rule.outboundTag, 'out-sv-trojan');
  // catch-all still goes to the primary so nothing is left unrouted
  assert.equal(c.routing.rules.at(-1).outboundTag, 'out-sv-vless');
});

test('pool: private bypass comes before the per-inbound rules', () => {
  const c = buildConfig(poolPlan([{ id: 'e1', target: 'sv-trojan', socksPort: 60001 }]), settings());
  const privIdx = c.routing.rules.findIndex(r => r.ip && r.ip.includes('192.168.0.0/16'));
  const inIdx = c.routing.rules.findIndex(r => r.inboundTag && r.inboundTag.includes('ps-e1'));
  assert.ok(privIdx < inIdx);
});

test('pool: duplicate and out-of-range ports are skipped', () => {
  const c = buildConfig(poolPlan([
    { id: 'dup', target: 'sv-trojan', socksPort: 10808 },   // collides with the std socks port
    { id: 'bad', target: 'sv-trojan', socksPort: 99999 },
    { id: 'ok', target: 'sv-trojan', socksPort: 60001 }
  ]), settings());

  const ports = c.inbounds.map(i => i.port);
  assert.equal(new Set(ports).size, ports.length, 'duplicate port bound twice');
  assert.deepEqual(c.inbounds.map(i => i.tag), ['socks-in', 'http-in', 'ps-ok']);
});

test('pool: a chain: entry gets its own chain outbounds', () => {
  const c = buildConfig(poolPlan([{ id: 'e1', target: 'chain:c1', socksPort: 60001 }]), settings());
  assert.ok(c.outbounds.some(o => o.tag === 'out-chain-c1-h0'));
  assert.ok(c.outbounds.some(o => o.tag === 'out-chain-c1'));
});

test('pool: a pool port equal to apiPort is skipped so the metrics listener keeps its port', () => {
  const c = buildConfig(poolPlan([
    { id: 'clash', target: 'sv-trojan', socksPort: 10085 },   // == apiPort
    { id: 'ok', target: 'sv-trojan', socksPort: 60001 }
  ]), settings({ apiPort: 10085 }));

  const ports = c.inbounds.map(i => i.port);
  assert.equal(new Set(ports).size, ports.length, 'a port is bound twice');
  assert.deepEqual(c.inbounds.map(i => i.tag), ['socks-in', 'http-in', 'ps-ok']);
  assert.equal(ports.includes(10085), false, 'a pool inbound stole the metrics port');
  assert.equal(c.metrics.listen, '127.0.0.1:10085');
});

/* ----------------------------- WireGuard ----------------------------- */

test('wireguard: a wrong interface mask is coerced to /32 at build time', () => {
  const c = buildConfig(single(WG_BAD_MASK), settings());
  assert.deepEqual(outboundTagged(c, 'proxy').settings.address, ['10.13.13.2/32']);
});

test('wireguard dialed through a chain keeps the default dialer buffer (v1.7.2)', () => {
  // The `bufferSize: 0` of Xray-core #2850 is gone: level 0 is every connection
  // of the config, so it throttled the WHOLE plan whenever a chained WireGuard
  // was in it, and both cores pass scripts/probe-wg-chain.js without it.
  // Pinned so nobody puts it back by habit.
  const chained = buildConfig({ mode: 'chain', chain: [VLESS_WS_TLS, WG_BAD_MASK] }, settings());
  assert.equal('bufferSize' in chained.policy.levels['0'], false);
  assert.deepEqual(chained.policy.levels['0'], { statsUserUplink: true, statsUserDownlink: true });

  const standalone = buildConfig(single(WG_BAD_MASK), settings());
  assert.equal('bufferSize' in standalone.policy.levels['0'], false);
});

/* --------------------------- anti-DPI (fragment / noise) --------------------------- */

test('fragment marker becomes a freedom dialer and is stripped from the outbound', () => {
  const s = vlessWithMarkers('sv-frag', { _fragment: 'tlshello,100-200,10-20' });
  const c = buildConfig(single(s), settings());

  const proxy = outboundTagged(c, 'proxy');
  assert.equal('_fragment' in proxy, false, 'marker leaked into the config');
  assert.equal(proxy.streamSettings.sockopt.dialerProxy, 'dpi-1');

  assert.deepEqual(outboundTagged(c, 'dpi-1'), {
    tag: 'dpi-1',
    protocol: 'freedom',
    settings: { domainStrategy: 'AsIs', fragment: { packets: 'tlshello', length: '100-200', interval: '10-20' } }
  });
});

test('fragment length min is clamped to 1 (xray rejects 0)', () => {
  const s = vlessWithMarkers('sv-frag0', { _fragment: '1-3,0-100,0' });
  const c = buildConfig(single(s), settings());
  assert.deepEqual(outboundTagged(c, 'dpi-1').settings.fragment, {
    packets: '1-3', length: '1-100', interval: '0-0'
  });
});

test('a bare fragment marker falls back to the tlshello defaults', () => {
  const s = vlessWithMarkers('sv-fragd', { _fragment: 'tlshello' });
  const c = buildConfig(single(s), settings());
  assert.deepEqual(outboundTagged(c, 'dpi-1').settings.fragment, {
    packets: 'tlshello', length: '100-200', interval: '10-20'
  });
});

test('identical anti-DPI settings share one dialer, different ones get their own', () => {
  const a = vlessWithMarkers('sv-a', { _fragment: 'tlshello,100-200,10-20' });
  const b = vlessWithMarkers('sv-b', { _fragment: 'tlshello,100-200,10-20' });
  const d = vlessWithMarkers('sv-d', { _fragment: '1-3,10-20,5' });

  const c = buildConfig({
    mode: 'advanced',
    serversById: { 'sv-a': a, 'sv-b': b, 'sv-d': d },
    chainsById: {}, chain: [],
    rules: [
      { type: 'domain', value: 'a.com', target: 'sv-a' },
      { type: 'domain', value: 'b.com', target: 'sv-b' },
      { type: 'domain', value: 'd.com', target: 'sv-d' }
    ],
    def: 'direct'
  }, settings({ blockAds: false }));

  assert.equal(outboundTagged(c, 'out-sv-a').streamSettings.sockopt.dialerProxy, 'dpi-1');
  assert.equal(outboundTagged(c, 'out-sv-b').streamSettings.sockopt.dialerProxy, 'dpi-1');
  assert.equal(outboundTagged(c, 'out-sv-d').streamSettings.sockopt.dialerProxy, 'dpi-2');
  assert.equal(c.outbounds.filter(o => /^dpi-/.test(o.tag)).length, 2);
});

test('noise presets expand into xray noises entries', () => {
  const s = vlessWithMarkers('sv-noise', { _noise: 'faketls' });
  const c = buildConfig(single(s), settings());
  assert.deepEqual(outboundTagged(c, 'dpi-1').settings.noises, [
    { type: 'rand', packet: '100-200', delay: '0' },
    { type: 'rand', packet: '40-80', delay: '10-20' }
  ]);
});

test('malformed noise entries are dropped', () => {
  const s = vlessWithMarkers('sv-noise2', { _noise: 'bogus:1:0;rand:50-100:0;rand::5' });
  const c = buildConfig(single(s), settings());
  assert.deepEqual(outboundTagged(c, 'dpi-1').settings.noises, [
    { type: 'rand', packet: '50-100', delay: '0' }
  ]);
});

test('a chained inner hop is not given a second dialer', () => {
  const hop = vlessWithMarkers('sv-hop', { _fragment: 'tlshello,100-200,10-20' });
  const exit = vlessWithMarkers('sv-exit', { _fragment: 'tlshello,100-200,10-20' });
  const c = buildConfig({ mode: 'chain', chain: [hop, exit] }, settings());

  // the first hop touches the wire, so it gets the dpi dialer …
  assert.equal(outboundTagged(c, 'proxy-h0').streamSettings.sockopt.dialerProxy, 'dpi-1');
  // … the exit already dials through the hop and must keep doing so
  assert.equal(outboundTagged(c, 'proxy').streamSettings.sockopt.dialerProxy, 'proxy-h0');
  assert.equal(c.outbounds.filter(o => /^dpi-/.test(o.tag)).length, 1);
});

test('outbounds without markers are left untouched', () => {
  const c = buildConfig(single(), settings());
  assert.equal(c.outbounds.some(o => /^dpi-/.test(o.tag)), false);
  assert.equal(outboundTagged(c, 'proxy').streamSettings.sockopt, undefined);
});

/* ----------------------------- legacy plan shapes ----------------------------- */

test('a bare server object is treated as a single-server plan', () => {
  const c = buildConfig(VLESS_WS_TLS, settings());
  assert.deepEqual(c.outbounds.map(o => o.tag), ['proxy', 'direct', 'block']);
});

test('a bare array is treated as a chain', () => {
  const c = buildConfig([VLESS_WS_TLS, TROJAN_TCP_TLS], settings());
  assert.deepEqual(c.outbounds.map(o => o.tag), ['proxy-h0', 'proxy', 'direct', 'block']);
});

/* ----------------------------- test config ----------------------------- */

test('buildTestConfig: single server on a throwaway socks port', () => {
  const c = buildTestConfig(VLESS_WS_TLS, 47123);
  assert.equal(c.log.loglevel, 'none');
  assert.deepEqual(c.inbounds[0], {
    tag: 'socks-in', port: 47123, listen: '127.0.0.1', protocol: 'socks',
    settings: { auth: 'noauth', udp: false }
  });
  assert.deepEqual(c.outbounds.map(o => o.tag), ['proxy', 'direct']);
  assert.deepEqual(c.routing, { rules: [{ type: 'field', inboundTag: ['socks-in'], outboundTag: 'proxy' }] });
});

test('buildTestConfig: a chain target is measured end to end', () => {
  const c = buildTestConfig([VLESS_WS_TLS, TROJAN_TCP_TLS], 47124);
  assert.deepEqual(c.outbounds.map(o => o.tag), ['proxy-h0', 'proxy', 'direct']);
  // With no routing the core sends everything to the FIRST outbound — the
  // entry hop alone — so a chain with a dead exit measured green. The test
  // inbound goes to the exit, which dials through every hop before it.
  assert.deepEqual(c.routing, { rules: [{ type: 'field', inboundTag: ['socks-in'], outboundTag: 'proxy' }] });
  assert.equal(outboundTagged(c, 'proxy').streamSettings.sockopt.dialerProxy, 'proxy-h0');
});

test('buildTestConfig: the fragment dialer is applied so the ping matches reality', () => {
  const s = vlessWithMarkers('sv-t', { _fragment: 'tlshello,100-200,10-20' });
  const c = buildTestConfig(s, 47125);
  assert.equal(c.outbounds.find(o => o.tag === 'proxy').streamSettings.sockopt.dialerProxy, 'dpi-1');
  assert.ok(c.outbounds.some(o => o.tag === 'dpi-1'));
});

/* ----------------------------- buildRoutingRules ----------------------------- */

test('buildRoutingRules: private/LAN bypass precedes the catch-all, which is last', () => {
  for (const mode of ['global', 'bypass-ir', 'bypass-cn', 'direct']) {
    for (const geo of [true, false]) {
      const rules = buildRoutingRules(mode, true, geo);
      const priv = rules.findIndex(r => r.ip && r.ip.includes('127.0.0.0/8'));
      assert.ok(priv > -1, `${mode}/${geo}: no private bypass`);
      assert.ok(priv < rules.length - 1, `${mode}/${geo}: private bypass must not be last`);
      assert.equal(rules.at(-1).port, '0-65535', `${mode}/${geo}: no catch-all`);
      assert.equal(rules.some(r => r.outboundTag === 'api'), false, `${mode}/${geo}: api rule leaked`);
    }
  }
});

/* ----------------------------- managed DNS ----------------------------- */

const MANAGED = { dnsManaged: true, dnsRemote: ['https://1.1.1.1/dns-query'], dnsDirect: ['178.22.122.100'] };
const DNS_RULES_GLOBAL = [
  { type: 'field', inboundTag: ['dns-internal'], outboundTag: 'proxy' },
  { type: 'field', port: '53', network: 'tcp,udp', outboundTag: 'dns-out' }
];

test('managed single: the DNS rules come FIRST, then the usual list', () => {
  const c = buildConfig(single(), settings(Object.assign({ blockAds: false }, MANAGED)));
  assert.deepEqual(c.routing.rules.slice(0, 2), DNS_RULES_GLOBAL);
  // the rest is exactly what the unmanaged config produces
  const plain = buildConfig(single(), settings({ blockAds: false }));
  assert.deepEqual(c.routing.rules.slice(2), plain.routing.rules);
  assert.deepEqual(c.dns.tag, 'dns-internal');
  assert.ok(c.outbounds.some(o => o.tag === 'dns-out' && o.protocol === 'dns'));
});

test('the hijack precedes the private-IP bypass, or a query to the tunnel peer would go direct', () => {
  const c = buildConfig(single(), settings(MANAGED));
  const hijack = c.routing.rules.findIndex(r => r.outboundTag === 'dns-out');
  const priv = c.routing.rules.findIndex(r => r.ip && r.ip.includes('10.0.0.0/8'));
  assert.ok(hijack > -1 && priv > -1);
  assert.ok(hijack < priv);
});

test('managed bypass-ir: the in-country resolver rides direct and the domestic rules still follow', () => {
  const c = buildConfig(single(), settings(Object.assign({ routingMode: 'bypass-ir', blockAds: false }, MANAGED)));
  assert.deepEqual(c.routing.rules[0], { type: 'field', inboundTag: ['dns-internal'], ip: ['178.22.122.100'], port: '53', outboundTag: 'direct' });
  assert.deepEqual(c.routing.rules[1], { type: 'field', inboundTag: ['dns-internal'], outboundTag: 'proxy' });
  assert.equal(c.routing.rules[2].outboundTag, 'dns-out');
  assert.equal(c.dns.servers[0].address, '178.22.122.100');
  assert.deepEqual(c.dns.servers[0].expectedIPs, ['geoip:ir']);
});

/*
 * The strict leak guard drops the plain-UDP in-country resolver at build time:
 * sing-box's strict_route blocks port 53 off the tunnel, so a query to
 * 178.22.122.100:53 dialled `direct` would time out on every domestic name
 * instead of resolving it. DoH survives (port 443) and geoip still routes the
 * answer, so the bypass keeps working. Only under TUN — in proxy mode nothing
 * blocks :53 and the resolver is the fast path it always was.
 */
test('strict under TUN drops the UDP direct resolver — and its bypass route with it', () => {
  const strict = { tunMode: true, leakGuard: 'strict', routingMode: 'bypass-ir' };
  const c = buildConfig(single(), settings(Object.assign({}, MANAGED, strict)));
  assert.equal(JSON.stringify(c.dns).includes('178.22.122.100'), false, 'the UDP resolver is gone');
  assert.deepEqual(c.routing.rules[0], { type: 'field', inboundTag: ['dns-internal'], outboundTag: 'proxy' },
    'with nothing to send direct, the resolver rule is the plain one');
  assert.deepEqual(resolverBypassIps(single(), settings(Object.assign({}, MANAGED, strict))), [],
    'nothing to bypass, so nothing punches a hole in the firewall either');

  // a DoH direct resolver is untouched: it rides port 443, which strict allows
  const doh = { dnsManaged: true, dnsRemote: ['https://1.1.1.1/dns-query'], dnsDirect: ['https://178.22.122.100/dns-query'] };
  const d = buildConfig(single(), settings(Object.assign({}, doh, strict)));
  assert.equal(d.dns.servers[0].address, 'https://178.22.122.100/dns-query');
  assert.deepEqual(resolverBypassIps(single(), settings(Object.assign({}, doh, strict))), ['178.22.122.100']);
});

test('strict without TUN, and TUN without strict, change nothing', () => {
  const base = settings(Object.assign({ routingMode: 'bypass-ir' }, MANAGED));
  const golden = JSON.stringify(buildConfig(single(), base));
  for (const s of [
    { leakGuard: 'strict' },                        // proxy mode: nothing blocks :53
    { tunMode: true, leakGuard: 'standard' },
    { tunMode: true, leakGuard: 'off' },
    { tunMode: true }
  ]) {
    assert.equal(JSON.stringify(buildConfig(single(), Object.assign({}, base, s))), golden, JSON.stringify(s));
    assert.deepEqual(resolverBypassIps(single(), Object.assign({}, base, s)), ['178.22.122.100']);
  }
});

test('strict under TUN drops the UDP resolver an advanced plan asked for', () => {
  const strict = Object.assign({ tunMode: true, leakGuard: 'strict', blockAds: false }, MANAGED);
  const plan = advancedPlan({
    rules: [{ type: 'domain', value: 'geosite:category-ir', target: 'direct' }],
    def: 'sv-vless'
  });
  assert.equal(buildConfig(plan, settings(MANAGED)).dns.servers[0].address, '178.22.122.100', 'without strict it is there');
  assert.equal(JSON.stringify(buildConfig(plan, settings(strict))).includes('178.22.122.100'), false);
  assert.deepEqual(resolverBypassIps(plan, settings(strict)), []);
});

test('managed bypass-ir without geo files carries no geo token at all', () => {
  const c = buildConfig(single(), settings(Object.assign({ routingMode: 'bypass-ir', geoAssets: false }, MANAGED)));
  assert.equal(JSON.stringify(c).includes('geosite:'), false);
  assert.equal(JSON.stringify(c).includes('geoip:'), false);
});

// Without the geo files bypass-ir IS global routing (see "geoAssets:false
// degrades bypass-ir to plain global routing"), so the domestic resolver has
// nothing left to serve — and it is the only thing in the config that would
// still speak cleartext UDP to an Iranian server. It goes, and with it the hole
// the TUN layer would have punched for it.
test('managed bypass-ir without geo files keeps no domestic resolver, and nothing is excluded from the tunnel for one', () => {
  const s = settings(Object.assign({ routingMode: 'bypass-ir', geoAssets: false }, MANAGED));
  const c = buildConfig(single(), s);
  assert.equal(JSON.stringify(c).includes('178.22.122.100'), false, 'no Iranian resolver in the config');
  assert.deepEqual(c.routing.rules.slice(0, 2), DNS_RULES_GLOBAL, 'no direct rule for a resolver that is not there');
  assert.deepEqual(resolverBypassIps(single(), s), [], 'and no route/firewall hole for one either');
});

test('managed direct mode: the resolver’s traffic goes direct too', () => {
  const c = buildConfig(single(), settings(Object.assign({ routingMode: 'direct' }, MANAGED)));
  assert.deepEqual(c.routing.rules[0], { type: 'field', inboundTag: ['dns-internal'], outboundTag: 'direct' });
});

test('managed chain: same rules, exit is the chain’s proxy tag', () => {
  const c = buildConfig({ mode: 'chain', chain: [VLESS_WS_TLS, TROJAN_TCP_TLS] }, settings(Object.assign({ blockAds: false }, MANAGED)));
  assert.deepEqual(c.routing.rules.slice(0, 2), DNS_RULES_GLOBAL);
  assert.deepEqual(c.outbounds.map(o => o.tag), ['proxy-h0', 'proxy', 'direct', 'block', 'dns-out']);
});

test('managed advanced: the resolver follows the default target, before the user rules', () => {
  const c = buildConfig(advancedPlan({
    rules: [{ type: 'domain', value: 'a.com', target: 'sv-trojan' }],
    def: 'sv-vless'
  }), settings(Object.assign({ blockAds: false }, MANAGED)));
  assert.deepEqual(c.routing.rules[0], { type: 'field', inboundTag: ['dns-internal'], outboundTag: 'out-sv-vless' });
  assert.equal(c.routing.rules[1].outboundTag, 'dns-out');
  assert.deepEqual(c.routing.rules[2].domain, ['a.com']);
  assert.ok(c.outbounds.some(o => o.tag === 'dns-out'));
});

test('managed advanced: a category-ir → direct rule gets the in-country resolver', () => {
  const c = buildConfig(advancedPlan({
    rules: [{ type: 'domain', value: 'geosite:category-ir', target: 'direct' }],
    def: 'sv-vless'
  }), settings(Object.assign({ blockAds: false }, MANAGED)));
  assert.equal(c.dns.servers[0].address, '178.22.122.100');
  assert.deepEqual(c.routing.rules[0].ip, ['178.22.122.100']);
});

// main.js picks the plan mode from the connect target, not from
// settings.advancedRouting, so the store may carry advanced rules the plan
// being built does not use — and the other way round. The plan decides.
test('managed advanced: the resolver follows the plan’s rules, not the rules saved in settings', () => {
  const c = buildConfig(advancedPlan({
    rules: [{ type: 'domain', value: 'a.com', target: 'sv-trojan' }],
    def: 'sv-vless'
  }), settings(Object.assign({
    blockAds: false,
    advancedRouting: true,
    routeRules: [{ type: 'domain', value: 'geosite:category-ir', target: 'direct' }]
  }, MANAGED)));
  assert.equal(typeof c.dns.servers[0], 'string', 'no in-country resolver without a direct category-ir rule in the plan');
  assert.deepEqual(c.routing.rules[0], { type: 'field', inboundTag: ['dns-internal'], outboundTag: 'out-sv-vless' });
});

test('managed single: saved advanced rules bring no resolver along; routingMode decides', () => {
  const saved = { advancedRouting: true, routeRules: [{ type: 'domain', value: 'geosite:category-ir', target: 'direct' }] };
  const global = buildConfig(single(), settings(Object.assign({ routingMode: 'global' }, saved, MANAGED)));
  assert.equal(typeof global.dns.servers[0], 'string');
  assert.deepEqual(global.routing.rules[0], { type: 'field', inboundTag: ['dns-internal'], outboundTag: 'proxy' });
  const ir = buildConfig(single(), settings(Object.assign({ routingMode: 'bypass-ir' }, saved, MANAGED)));
  assert.equal(ir.dns.servers[0].address, '178.22.122.100');
});

test('managed pool: the resolver follows the primary exit; per-inbound rules are untouched', () => {
  const c = buildConfig(poolPlan([{ id: 'e1', target: 'sv-trojan', socksPort: 60001 }]), settings(MANAGED));
  assert.deepEqual(c.routing.rules[0], { type: 'field', inboundTag: ['dns-internal'], outboundTag: 'out-sv-vless' });
  assert.equal(c.routing.rules[1].outboundTag, 'dns-out');
  const e1 = c.routing.rules.find(r => r.inboundTag && r.inboundTag.includes('ps-e1'));
  assert.equal(e1.outboundTag, 'out-sv-trojan');
  assert.ok(c.outbounds.some(o => o.tag === 'dns-out'));
  assert.equal(c.dns.tag, 'dns-internal');
});

// Pool emits no bypass rules at all, so an in-country resolver would only hand
// the primary exit an Iranian IP to dial from abroad (geo-fenced sites refuse
// it) — and its UDP query would ride `direct`. routingMode is not the pool's.
test('managed pool ignores routingMode: no in-country resolver for rules it never emits', () => {
  const c = buildConfig(poolPlan([{ id: 'e1', target: 'sv-trojan', socksPort: 60001 }]), settings(Object.assign({ routingMode: 'bypass-ir' }, MANAGED)));
  assert.equal(typeof c.dns.servers[0], 'string');
  assert.deepEqual(c.routing.rules[0], { type: 'field', inboundTag: ['dns-internal'], outboundTag: 'out-sv-vless' });
  assert.equal(JSON.stringify(c.routing.rules).includes('178.22.122.100'), false);
});

// An allow-list (rules → server, default → block) is a legitimate setup; the
// resolver's DoH must still leave somewhere, and the blackhole is the one
// outbound that can never answer. Use the first proxy the rules name.
test('managed advanced with a block default: the resolver exits through the first proxy the rules use', () => {
  const c = buildConfig(advancedPlan({
    rules: [{ type: 'domain', value: 'a.com', target: 'direct' }, { type: 'domain', value: 'b.com', target: 'sv-trojan' }],
    def: 'block'
  }), settings(Object.assign({ blockAds: false }, MANAGED)));
  assert.deepEqual(c.routing.rules[0], { type: 'field', inboundTag: ['dns-internal'], outboundTag: 'out-sv-trojan' });
  // the catch-all is still the blackhole the user asked for
  assert.equal(c.routing.rules[c.routing.rules.length - 1].outboundTag, 'block');
  const onlyDirect = buildConfig(advancedPlan({
    rules: [{ type: 'domain', value: 'a.com', target: 'direct' }],
    def: 'block'
  }), settings(Object.assign({ blockAds: false }, MANAGED)));
  assert.deepEqual(onlyDirect.routing.rules[0], { type: 'field', inboundTag: ['dns-internal'], outboundTag: 'direct' });
});

// Under TUN every `direct` dial to a public address re-enters the tunnel via
// the split routes; the TUN layer must give the in-country resolver a bypass
// route exactly like the server addresses. This is the list it needs.
test('resolverBypassIps: the direct resolver addresses the TUN layer must route past the tunnel', () => {
  assert.deepEqual(resolverBypassIps(single(), settings(Object.assign({ routingMode: 'bypass-ir' }, MANAGED))), ['178.22.122.100']);
  assert.deepEqual(resolverBypassIps(single(), settings(Object.assign({ routingMode: 'global' }, MANAGED))), []);
  assert.deepEqual(resolverBypassIps(single(), settings({ routingMode: 'bypass-ir', dnsManaged: false })), []);
  assert.deepEqual(resolverBypassIps(advancedPlan({
    rules: [{ type: 'domain', value: 'geosite:category-ir', target: 'direct' }], def: 'sv-vless'
  }), settings(MANAGED)), ['178.22.122.100']);
  assert.deepEqual(resolverBypassIps(poolPlan([{ id: 'e1', target: 'sv-trojan', socksPort: 60001 }]), settings(Object.assign({ routingMode: 'bypass-ir' }, MANAGED))), []);
});

/**
 * The same list, read out of the config that is actually running instead of
 * rebuilt from the plan. Every entry becomes a route exclusion and, at the
 * strict level, a hole in a firewall that otherwise blocks everything off the
 * tunnel — so a name here that the config does not have is a hole for nothing,
 * and a name missing here is a resolver whose query loops back into the hijack.
 * Rebuilding cannot guarantee either: buildActive() hands buildConfig a
 * `geoAssets` flag it computes from the files on disk and which the settings
 * object never carries, so the two derivations can disagree exactly when the
 * geo files are missing.
 */
test('resolverBypassIpsOf: the same answer, taken from the built config', () => {
  const cases = [
    [single(), settings(Object.assign({ routingMode: 'bypass-ir' }, MANAGED))],
    [single(), settings(Object.assign({ routingMode: 'global' }, MANAGED))],
    [single(), settings(Object.assign({ routingMode: 'bypass-ir', dnsRemote: ['192.168.1.1', 'https://1.1.1.1/dns-query'] }, MANAGED))],
    [single(), settings({ routingMode: 'bypass-ir', dnsManaged: false })],
    [advancedPlan({ rules: [{ type: 'domain', value: 'geosite:category-ir', target: 'direct' }], def: 'sv-vless' }), settings(MANAGED)],
    [corpPlan({ rules: [{ type: 'domain', value: 'geosite:category-ir', target: 'direct' }] }), managed()],
    [poolPlan([{ id: 'e1', target: 'sv-trojan', socksPort: 60001 }]), settings(Object.assign({ routingMode: 'bypass-ir' }, MANAGED))],
    [single(), settings(Object.assign({ routingMode: 'bypass-ir', tunMode: true, leakGuard: 'strict' }, MANAGED))]
  ];
  for (const [plan, s] of cases) {
    assert.deepEqual(resolverBypassIpsOf(buildConfig(plan, s)), resolverBypassIps(plan, s), JSON.stringify(s.routingMode));
  }
});

test('resolverBypassIpsOf: no hole for a resolver the geo-less config never built', () => {
  const s = settings(Object.assign({ routingMode: 'bypass-ir' }, MANAGED));
  // what buildActive() really does: the flag goes to buildConfig and nowhere else
  const config = buildConfig(single(), Object.assign({}, s, { geoAssets: false }));
  assert.deepEqual(resolverBypassIpsOf(config), []);
  assert.deepEqual(resolverBypassIps(single(), s), ['178.22.122.100'], 'the plan-derived list cannot see the missing files');
});

test('resolverBypassIpsOf: a config with no routing section, or another core’s format, is simply empty', () => {
  assert.deepEqual(resolverBypassIpsOf(null), []);
  assert.deepEqual(resolverBypassIpsOf({}), []);
  assert.deepEqual(resolverBypassIpsOf({ route: { final: 'proxy' }, dns: { servers: [] } }), [], 'a sing-box config');
});

// xray's router resolves a hostname under IPIfNonMatch only when NO rule matched
// on the first pass — and every plan ends with a port:0-65535 catch-all, which
// always matches. So an `ip:` rule (geoip:ir, the private-LAN bypass, a corporate
// range) never fired for a browser connection that carries a hostname. IPOnDemand
// resolves exactly when an ip condition is evaluated. Only with managed DNS: the
// legacy list may be a dead plain-UDP resolver, and a lookup that times out
// before every connection is worse than an unmatched rule.
test('managed DNS: ip rules must fire for hostnames, so the router resolves on demand', () => {
  const plans = {
    single: single(),
    chain: { mode: 'chain', chain: [VLESS_WS_TLS, TROJAN_TCP_TLS] },
    advanced: advancedPlan({ rules: [{ type: 'ip', value: '10.0.0.0/8', target: 'sv-trojan' }], def: 'sv-vless' })
  };
  for (const [name, plan] of Object.entries(plans)) {
    assert.equal(buildConfig(plan, settings(MANAGED)).routing.domainStrategy, 'IPOnDemand', name);
    assert.equal(buildConfig(plan, settings({ dnsManaged: false })).routing.domainStrategy, 'IPIfNonMatch', name + ' unmanaged');
  }
});

test('buildTestConfig is untouched by DNS management (no hijack, no tag)', () => {
  const c = buildTestConfig(VLESS_WS_TLS, 47130);
  assert.equal(c.dns, undefined);
  assert.equal(c.outbounds.some(o => o.tag === 'dns-out'), false);
});

/* ----------------------------- DNS follows the target ----------------------------- */

// The owner's setup: client → VLESS → corporate WireGuard as a chain, one rule
// sending the company ranges to it. Internal names are known only to the
// company resolver the .conf names — which is reachable ONLY through that
// tunnel. The resolver must be in the list, and its query must leave through
// the chain, not the VLESS the exit rule points at.
// skipFallback (v1.7.3): pinned to its search domains, never the fallback for
// the names the tunnel itself needs (dnsBuilder.test.js says why).
const CORP_SERVER = { address: '192.168.60.1', domains: ['domain:tes.systems'], expectedIPs: ['192.168.0.0/16', '10.0.0.0/8'], skipFallback: true };
const CORP_RULE = (tag) => ({ type: 'field', inboundTag: ['dns-internal'], ip: ['192.168.60.1'], outboundTag: tag });

function corpPlan(over) {
  return advancedPlan(Object.assign({
    serversById: { 'sv-vless': VLESS_WS_TLS, 'sv-trojan': TROJAN_TCP_TLS, 'sv-wgcorp': WG_CORP },
    chainsById: { c1: [VLESS_WS_TLS, WG_CORP] },
    rules: [{ type: 'ip', value: '192.168.0.0/16', target: 'chain:c1' }],
    def: 'sv-vless'
  }, over || {}));
}
const managed = (over) => settings(Object.assign({ blockAds: false }, MANAGED, over || {}));

test('advanced: a chain ending in a corporate WireGuard brings its resolver, asked through the chain', () => {
  const c = buildConfig(corpPlan(), managed());
  assert.deepEqual(c.dns.servers, ['https://1.1.1.1/dns-query', CORP_SERVER]);
  assert.deepEqual(c.routing.rules[0], CORP_RULE('out-chain-c1'));
  assert.deepEqual(c.routing.rules[1], { type: 'field', inboundTag: ['dns-internal'], outboundTag: 'out-sv-vless' });
  assert.equal(c.routing.rules[2].outboundTag, 'dns-out');
  // the user's own rule still follows, to the same chain
  assert.deepEqual(c.routing.rules[3], { type: 'field', ip: ['192.168.0.0/16'], outboundTag: 'out-chain-c1' });
});

test('advanced: the WireGuard itself as a rule target, or the chain as the default, each name their own tag', () => {
  const direct = buildConfig(corpPlan({ rules: [{ type: 'ip', value: '10.0.0.0/8', target: 'sv-wgcorp' }] }), managed());
  assert.deepEqual(direct.routing.rules[0], CORP_RULE('out-sv-wgcorp'));

  const def = buildConfig(corpPlan({ rules: [{ type: 'domain', value: 'a.com', target: 'sv-trojan' }], def: 'chain:c1' }), managed());
  assert.deepEqual(def.routing.rules[0], CORP_RULE('out-chain-c1'));
  assert.deepEqual(def.routing.rules[1], { type: 'field', inboundTag: ['dns-internal'], outboundTag: 'out-chain-c1' });
});

test('advanced with a block default: the resolver rule still names the WireGuard, the exit the redirected proxy', () => {
  const c = buildConfig(corpPlan({
    rules: [{ type: 'domain', value: 'a.com', target: 'sv-trojan' }, { type: 'ip', value: '10.0.0.0/8', target: 'sv-wgcorp' }],
    def: 'block'
  }), managed());
  assert.deepEqual(c.routing.rules[0], CORP_RULE('out-sv-wgcorp'));
  assert.deepEqual(c.routing.rules[1], { type: 'field', inboundTag: ['dns-internal'], outboundTag: 'out-sv-trojan' });
  assert.equal(c.routing.rules.at(-1).outboundTag, 'block');
});

test('single / chain: the exit carries the resolver when a corporate WireGuard is the last hop', () => {
  const one = buildConfig(single(WG_CORP), managed());
  assert.deepEqual(one.dns.servers.at(-1), CORP_SERVER);
  assert.deepEqual(one.routing.rules[0], CORP_RULE('proxy'));
  assert.deepEqual(one.routing.rules[1], { type: 'field', inboundTag: ['dns-internal'], outboundTag: 'proxy' });

  const last = buildConfig({ mode: 'chain', chain: [VLESS_WS_TLS, WG_CORP] }, managed());
  assert.deepEqual(last.dns.servers.at(-1), CORP_SERVER);
  assert.deepEqual(last.routing.rules[0], CORP_RULE('proxy'));

  // the WireGuard as a middle hop exits somewhere else: its resolver is not on the way
  const middle = buildConfig({ mode: 'chain', chain: [WG_CORP, VLESS_WS_TLS] }, managed());
  assert.deepEqual(middle.dns.servers, ['https://1.1.1.1/dns-query']);
  assert.deepEqual(middle.routing.rules[0], { type: 'field', inboundTag: ['dns-internal'], outboundTag: 'proxy' });
});

test('routingMode direct: the exit is off the tunnel, so the corporate resolver is not offered', () => {
  const c = buildConfig(single(WG_CORP), managed({ routingMode: 'direct' }));
  assert.deepEqual(c.dns.servers, ['https://1.1.1.1/dns-query']);
  assert.deepEqual(c.routing.rules[0], { type: 'field', inboundTag: ['dns-internal'], outboundTag: 'direct' });
});

test('pool: a corporate WireGuard entry brings no resolver', () => {
  const plan = poolPlan([{ id: 'e1', target: 'sv-wgcorp', socksPort: 60001 }], 'sv-wgcorp');
  plan.serversById['sv-wgcorp'] = WG_CORP;
  const c = buildConfig(plan, managed());
  assert.deepEqual(c.dns.servers, ['https://1.1.1.1/dns-query']);
  assert.equal(JSON.stringify(c.routing.rules).includes('192.168.60.1'), false);
});

test('advanced: two rules to the same chain → one corporate server, one rule', () => {
  const c = buildConfig(corpPlan({
    rules: [{ type: 'ip', value: '192.168.0.0/16', target: 'chain:c1' }, { type: 'ip', value: '10.0.0.0/8', target: 'chain:c1' }]
  }), managed());
  assert.equal(c.dns.servers.filter(s => s.address === '192.168.60.1').length, 1);
  assert.equal(c.routing.rules.filter(r => r.ip && r.ip.includes('192.168.60.1')).length, 1);
});

test('resolverBypassIps: the corporate resolver is not routed past the tunnel — it rides the target', () => {
  assert.deepEqual(resolverBypassIps(corpPlan(), managed()), []);
  assert.deepEqual(resolverBypassIps(corpPlan({ rules: [{ type: 'domain', value: 'geosite:category-ir', target: 'direct' }] }), managed()), ['178.22.122.100']);
});

test('wgResolverAddresses: every resolver the plan\x27s WireGuard servers bring, in every plan shape, deduplicated', () => {
  // What the connect path names when managed DNS is off and these are dropped.
  assert.deepEqual(wgResolverAddresses({ mode: 'single', server: WG_CORP }), WG_CORP.dns);
  assert.deepEqual(wgResolverAddresses({ mode: 'chain', chain: [VLESS_WS_TLS, WG_CORP] }), WG_CORP.dns);
  assert.deepEqual(wgResolverAddresses({ mode: 'advanced', serversById: { a: VLESS_WS_TLS }, chainsById: { c: [VLESS_WS_TLS, WG_CORP] }, rules: [], def: 'a' }), WG_CORP.dns);
  assert.deepEqual(wgResolverAddresses({ mode: 'single', server: WG_BAD_MASK }), [], 'a WireGuard without dns brings nothing');
  assert.deepEqual(wgResolverAddresses({ mode: 'single', server: VLESS_WS_TLS }), []);
  const twice = { mode: 'advanced', serversById: { w: WG_CORP }, chainsById: { c: [VLESS_WS_TLS, WG_CORP] }, rules: [], def: 'w' };
  assert.deepEqual(wgResolverAddresses(twice), WG_CORP.dns, 'named twice, listed once');
});

test('wgResolvers: expectedIPs come from AllowedIPs minus the full-tunnel entries; no dns → nothing', () => {
  assert.deepEqual(wgResolvers(WG_CORP, 'out-x'), [
    { address: '192.168.60.1', outboundTag: 'out-x', expectedIPs: ['192.168.0.0/16', '10.0.0.0/8'], domains: ['domain:tes.systems'] }
  ]);
  const full = Object.assign({}, WG_BAD_MASK, { dns: ['10.13.13.1'] });   // allowedIPs 0.0.0.0/0, ::/0
  assert.deepEqual(wgResolvers(full, 'out-x'), [{ address: '10.13.13.1', outboundTag: 'out-x', expectedIPs: [], domains: [] }]);
  assert.deepEqual(wgResolvers(WG_BAD_MASK, 'out-x'), []);
  assert.deepEqual(wgResolvers(Object.assign({}, WG_CORP, { dns: [] }), 'out-x'), []);
  assert.deepEqual(wgResolvers(Object.assign({}, VLESS_WS_TLS, { dns: ['1.2.3.4'] }), 'out-x'), []);
  assert.deepEqual(wgResolvers(null, 'out-x'), []);
});

test('wgResolvers: a record whose top-level protocol is missing still counts as WireGuard', () => {
  // The outbound is the truth — the top-level field is a copy of it kept for
  // the list UI. A record that lost it (an old store, a hand-edited import)
  // used to lose its corporate resolver SILENTLY: every internal name then
  // resolved over the public DoH and the company sites simply did not open.
  const noProto = JSON.parse(JSON.stringify(WG_CORP));
  delete noProto.protocol;
  assert.deepEqual(wgResolvers(noProto, 'out-x'), wgResolvers(WG_CORP, 'out-x'));
  assert.equal(wgResolvers(noProto, 'out-x').length, 1);
});

test('a split-tunnel WireGuard is recognised without the top-level protocol too', () => {
  // isSplitTunnelWg decides which outbound may carry the resolver's own DoH
  // query: a split tunnel drops it, so the exit must be something else.
  const noProto = JSON.parse(JSON.stringify(WG_CORP));
  delete noProto.protocol;
  const c = buildConfig(advancedPlan({
    serversById: { 'sv-vless': VLESS_WS_TLS, 'sv-wgcorp': noProto },
    rules: [{ type: 'ip', value: '10.0.0.0/8', target: 'sv-wgcorp' }, { type: 'domain', value: 'a.com', target: 'sv-vless' }],
    def: 'block'
  }), settings({ dnsManaged: true, dnsRemote: ['https://1.1.1.1/dns-query'] }));

  const exitRule = c.routing.rules.find(r => r.inboundTag && !r.ip);
  assert.equal(exitRule.outboundTag, 'out-sv-vless', 'the split tunnel must not be asked to carry the public resolver');
});

/* --------------------------- phase 2b review fixes --------------------------- */

// The pool emits no user ip rule (only the private bypass), and on demand every
// entry's hostname connections would wait on the PRIMARY's DoH — a dead primary
// costing the other entries ~8 s per new name. Entries stay independent.
test('pool keeps IPIfNonMatch: its entries must not wait on the primary’s DNS for every hostname', () => {
  const c = buildConfig(poolPlan([{ id: 'e1', target: 'sv-trojan', socksPort: 60001 }]), settings(MANAGED));
  assert.equal(c.routing.domainStrategy, 'IPIfNonMatch');
});

const CORP_IDS = { 'sv-vless': VLESS_WS_TLS, 'sv-trojan': TROJAN_TCP_TLS, 'sv-wgcorp': WG_CORP };
const exitRuleOf = (c) => c.routing.rules.find(r => r.inboundTag && !r.ip).outboundTag;

// A split-tunnel WireGuard drops anything outside its AllowedIPs, so DoH to
// 1.1.1.1 would die inside it: 8 s per internal name before the corporate
// resolver is even asked. The fallback exit must skip such a target.
test('managed advanced, block default: the resolver never exits through a split-tunnel WireGuard', () => {
  const split = (over) => advancedPlan(Object.assign({
    serversById: CORP_IDS, chainsById: { c1: [VLESS_WS_TLS, WG_CORP] },
    rules: [{ type: 'ip', value: '192.168.0.0/16', target: 'chain:c1' }], def: 'block'
  }, over || {}));
  assert.equal(exitRuleOf(buildConfig(split(), settings(MANAGED))), 'direct');
  const withProxy = buildConfig(split({
    rules: [{ type: 'ip', value: '192.168.0.0/16', target: 'chain:c1' }, { type: 'domain', value: 'b.com', target: 'sv-trojan' }]
  }), settings(MANAGED));
  assert.equal(exitRuleOf(withProxy), 'out-sv-trojan');
  // the corporate resolver still rides its own chain, first
  assert.deepEqual(withProxy.routing.rules[0], { type: 'field', inboundTag: ['dns-internal'], ip: ['192.168.60.1'], outboundTag: 'out-chain-c1' });
  // a full-tunnel WireGuard can carry DoH, so it is an acceptable exit
  const full = buildConfig(split({ chainsById: { c1: [VLESS_WS_TLS, WG_BAD_MASK] } }), settings(MANAGED));
  assert.equal(exitRuleOf(full), 'out-chain-c1');
});

test('the same resolver reached directly and through a chain: the chain carries the query', () => {
  // the WireGuard's UDP endpoint is what the chain exists to avoid; rule order
  // must not decide which one the resolver uses
  const c = buildConfig(advancedPlan({
    serversById: CORP_IDS, chainsById: { c1: [VLESS_WS_TLS, WG_CORP] },
    rules: [{ type: 'ip', value: '10.0.0.0/8', target: 'sv-wgcorp' }, { type: 'ip', value: '192.168.0.0/16', target: 'chain:c1' }],
    def: 'sv-vless'
  }), settings(MANAGED));
  assert.equal(c.routing.rules[0].outboundTag, 'out-chain-c1');
  assert.equal(c.dns.servers.filter(x => x && x.address === '192.168.60.1').length, 1);
});

/* ----------------------------- certificate pinning (allowInsecure is gone) ----------------------------- */

const PIN = 'ab11bf7ac877baa539294f5a3c864b8ed43e6fe3a9a8230fc2db7fff85c27fde';
/** The fixture as an Iranian link imports it (allowInsecure=1), optionally with a stored pin. */
function insecure(server, over) {
  const s = JSON.parse(JSON.stringify(server));
  s.outbound.streamSettings.tlsSettings.allowInsecure = true;
  return Object.assign(s, over || {});
}
const tlsOf = (c, tag) => outboundTagged(c, tag).streamSettings.tlsSettings;

test('allowInsecure is never emitted — the core rejects it whether true or false', () => {
  for (const s of [VLESS_WS_TLS, insecure(VLESS_WS_TLS)]) {
    const tls = tlsOf(buildConfig(single(s), settings()), 'proxy');
    assert.equal('allowInsecure' in tls, false);
    assert.equal('pinnedPeerCertSha256' in tls, false, 'no pin on the record → the core verifies normally');
    assert.equal(tls.serverName, 'a.example.com', 'the rest of tlsSettings is untouched');
    assert.equal(tls.fingerprint, 'chrome');
  }
});

test('a record with a pin emits pinnedPeerCertSha256 in the canonical form, in place of allowInsecure', () => {
  const colons = PIN.toUpperCase().match(/../g).join(':');
  for (const stored of [PIN, colons]) {
    const tls = tlsOf(buildConfig(single(insecure(VLESS_WS_TLS, { certPin: stored })), settings()), 'proxy');
    assert.equal(tls.pinnedPeerCertSha256, PIN);
    assert.equal('allowInsecure' in tls, false);
  }
});

test('a junk certPin is ignored rather than handed to the core', () => {
  const tls = tlsOf(buildConfig(single(insecure(VLESS_WS_TLS, { certPin: 'not-a-hash' })), settings()), 'proxy');
  assert.equal('pinnedPeerCertSha256' in tls, false);
});

test('the pin follows its server: a chain’s first hop, an advanced target, a pool exit, a chain: target', () => {
  const first = insecure(VLESS_WS_TLS, { certPin: PIN });
  const chain = buildConfig({ mode: 'chain', chain: [first, TROJAN_TCP_TLS] }, settings());
  assert.equal(tlsOf(chain, 'proxy-h0').pinnedPeerCertSha256, PIN);
  assert.equal('pinnedPeerCertSha256' in tlsOf(chain, 'proxy'), false, 'the exit has no pin of its own');
  assert.equal('allowInsecure' in tlsOf(chain, 'proxy'), false);

  const exit = insecure(TROJAN_TCP_TLS, { certPin: PIN });
  const adv = buildConfig(advancedPlan({
    serversById: { 'sv-vless': VLESS_WS_TLS, 'sv-trojan': exit },
    chainsById: { c1: [VLESS_WS_TLS, exit] },
    rules: [{ type: 'domain', value: 'a.com', target: 'sv-trojan' }, { type: 'domain', value: 'b.com', target: 'chain:c1' }],
    def: 'sv-vless'
  }), settings());
  assert.equal(tlsOf(adv, 'out-sv-trojan').pinnedPeerCertSha256, PIN);
  assert.equal(tlsOf(adv, 'out-chain-c1').pinnedPeerCertSha256, PIN, 'the same server as a chain exit');
  assert.equal('pinnedPeerCertSha256' in tlsOf(adv, 'out-chain-c1-h0'), false);
  assert.equal('pinnedPeerCertSha256' in tlsOf(adv, 'out-sv-vless'), false);

  const pool = buildConfig({
    mode: 'pool', entries: [{ id: 'e1', target: 'sv-trojan', socksPort: 60001 }], primary: 'sv-vless',
    serversById: { 'sv-vless': VLESS_WS_TLS, 'sv-trojan': exit }, chainsById: {}, chain: []
  }, settings());
  assert.equal(tlsOf(pool, 'out-sv-trojan').pinnedPeerCertSha256, PIN);
});

test('buildTestConfig carries the pin, so a ping does not fail where a connect works', () => {
  const pinned = insecure(VLESS_WS_TLS, { certPin: PIN });
  assert.equal(tlsOf(buildTestConfig(pinned, 47140), 'proxy').pinnedPeerCertSha256, PIN);
  assert.equal('allowInsecure' in tlsOf(buildTestConfig(insecure(VLESS_WS_TLS), 47141), 'proxy'), false);
  const chain = buildTestConfig([pinned, TROJAN_TCP_TLS], 47142);
  assert.equal(tlsOf(chain, 'proxy-h0').pinnedPeerCertSha256, PIN);
  assert.equal('allowInsecure' in tlsOf(chain, 'proxy'), false);
});

test('pinning never touches the stored record: the link keeps allowInsecure for export', () => {
  const s = insecure(VLESS_WS_TLS, { certPin: PIN });
  const before = JSON.stringify(s);
  buildConfig(single(s), settings());
  buildTestConfig(s, 47143);
  buildConfig({ mode: 'chain', chain: [s, TROJAN_TCP_TLS] }, settings());
  assert.equal(JSON.stringify(s), before);
  assert.equal(s.outbound.streamSettings.tlsSettings.allowInsecure, true);
});

/* ------------------------ direct-outbound binding (TUN) ------------------------ */
// Under TUN the OS default route is the tunnel, so every outbound that dials the
// network ITSELF must be bound to the physical NIC (sockopt.interface) or its
// dial re-enters the TUN and loops. main.js derives `directInterface` at connect
// time, only under tunMode; without it nothing here may change.

const sockoptOf = (c, tag) => (outboundTagged(c, tag).streamSettings || {}).sockopt || {};
const BOUND = { directInterface: 'Wi-Fi' };

test('golden guard: without directInterface no sockopt.interface appears anywhere', () => {
  const frag = vlessWithMarkers('sv-frag', { _fragment: 'tlshello,100-200,10-20' });
  const plans = [
    single(), single(frag), single(WG_BAD_MASK), single(WG_CORP),
    { mode: 'chain', chain: [VLESS_WS_TLS, TROJAN_TCP_TLS] },
    { mode: 'chain', chain: [VLESS_WS_TLS, WG_BAD_MASK] },
    advancedPlan({ rules: [{ type: 'domain', value: 'a.com', target: 'sv-trojan' }, { type: 'ip', value: '10.20.0.0/16', target: 'chain:c1' }], def: 'sv-vless' }),
    poolPlan([{ id: 'e1', target: 'sv-trojan', socksPort: 60001, httpPort: 60002 }])
  ];
  for (const p of plans) {
    for (const s of [settings(), managed(), settings({ directInterface: '' }), settings({ directInterface: '   ' }), settings({ directInterface: null }), settings({ directInterface: 7 })]) {
      const text = JSON.stringify(buildConfig(p, s));
      assert.equal(text.includes('"interface"'), false, `${p.mode}: ${JSON.stringify(s.directInterface)} bound something`);
    }
  }
  assert.equal(JSON.stringify(buildTestConfig(frag, 47150)).includes('"interface"'), false, 'a ping runs without TUN');
  assert.equal(JSON.stringify(buildTestConfig([VLESS_WS_TLS, TROJAN_TCP_TLS], 47151)).includes('"interface"'), false);
});

test('single: proxy, direct and the dpi dialer are bound; block and dns-out are not', () => {
  const s = vlessWithMarkers('sv-frag', { _fragment: 'tlshello,100-200,10-20' });
  const c = buildConfig(single(s), managed(BOUND));
  assert.equal(sockoptOf(c, 'direct').interface, 'Wi-Fi');
  assert.equal(sockoptOf(c, 'dpi-1').interface, 'Wi-Fi', 'the dialer is what touches the wire');
  // the proxy dials THROUGH dpi-1, so binding it would be wrong
  assert.deepEqual(sockoptOf(c, 'proxy'), { dialerProxy: 'dpi-1' });
  assert.equal('streamSettings' in outboundTagged(c, 'block'), false);
  assert.equal('streamSettings' in outboundTagged(c, 'dns-out'), false);
  // a plain proxy with no dialer dials itself
  const plain = buildConfig(single(), managed(BOUND));
  assert.deepEqual(sockoptOf(plain, 'proxy'), { interface: 'Wi-Fi' });
  assert.equal(outboundTagged(plain, 'proxy').streamSettings.security, 'tls', 'the rest of streamSettings is untouched');
});

test('chain: the first hop is bound, the hop behind it keeps dialing through it', () => {
  const c = buildConfig({ mode: 'chain', chain: [VLESS_WS_TLS, TROJAN_TCP_TLS] }, settings(BOUND));
  assert.deepEqual(sockoptOf(c, 'proxy-h0'), { interface: 'Wi-Fi' });
  assert.deepEqual(sockoptOf(c, 'proxy'), { dialerProxy: 'proxy-h0' });
  assert.deepEqual(sockoptOf(c, 'direct'), { interface: 'Wi-Fi' });
});

test('advanced: every top-level outbound is bound; a chain hop behind a hop is not', () => {
  const c = buildConfig(advancedPlan({
    rules: [
      { type: 'domain', value: 'a.com', target: 'sv-trojan' },
      { type: 'ip', value: '10.20.0.0/16', target: 'chain:c1' },
      { type: 'ip', value: '10.30.0.0/16', target: 'sv-wg' }
    ],
    def: 'sv-vless'
  }), managed(BOUND));
  for (const tag of ['out-sv-trojan', 'out-chain-c1-h0', 'out-sv-wg', 'out-sv-vless', 'direct']) {
    assert.equal(sockoptOf(c, tag).interface, 'Wi-Fi', tag);
  }
  assert.deepEqual(sockoptOf(c, 'out-chain-c1'), { dialerProxy: 'out-chain-c1-h0' });
  assert.equal('streamSettings' in outboundTagged(c, 'block'), false);
  assert.equal('streamSettings' in outboundTagged(c, 'dns-out'), false);
});

test('pool: every exit and direct are bound; block and dns-out are not', () => {
  const c = buildConfig(poolPlan([
    { id: 'e1', target: 'sv-trojan', socksPort: 60001 },
    { id: 'e2', target: 'chain:c1', socksPort: 60003 }
  ]), managed(BOUND));
  for (const tag of ['out-sv-vless', 'out-sv-trojan', 'out-chain-c1-h0', 'direct']) {
    assert.equal(sockoptOf(c, tag).interface, 'Wi-Fi', tag);
  }
  assert.deepEqual(sockoptOf(c, 'out-chain-c1'), { dialerProxy: 'out-chain-c1-h0' });
  assert.equal('streamSettings' in outboundTagged(c, 'block'), false);
  assert.equal('streamSettings' in outboundTagged(c, 'dns-out'), false);
});

test('WireGuard dialled directly is bound (its empty sockopt kept); behind a chain it is not', () => {
  const direct = buildConfig(single(WG_BAD_MASK), settings(BOUND));
  assert.deepEqual(sockoptOf(direct, 'proxy'), { interface: 'Wi-Fi' });
  const chained = buildConfig({ mode: 'chain', chain: [VLESS_WS_TLS, WG_BAD_MASK] }, settings(BOUND));
  assert.deepEqual(sockoptOf(chained, 'proxy'), { dialerProxy: 'proxy-h0' });
  assert.deepEqual(sockoptOf(chained, 'proxy-h0'), { interface: 'Wi-Fi' });
  assert.equal('bufferSize' in chained.policy.levels['0'], false, 'no per-connection buffer cap for a chained WireGuard (v1.7.2)');
});

test('binding does not depend on managed DNS, and the interface name is taken as given', () => {
  const c = buildConfig(single(), settings({ dnsManaged: false, directInterface: 'Ethernet 2' }));
  assert.deepEqual(sockoptOf(c, 'proxy'), { interface: 'Ethernet 2' });
  assert.deepEqual(sockoptOf(c, 'direct'), { interface: 'Ethernet 2' });
  assert.equal(c.outbounds.some(o => o.tag === 'dns-out'), false);
  const mac = buildConfig(single(), settings({ directInterface: 'en0' }));
  assert.equal(sockoptOf(mac, 'direct').interface, 'en0');
});

test('binding never touches the stored record', () => {
  const s = JSON.parse(JSON.stringify(WG_BAD_MASK));
  const before = JSON.stringify(s);
  buildConfig(single(s), settings(BOUND));
  buildConfig({ mode: 'chain', chain: [VLESS_WS_TLS, s] }, settings(BOUND));
  assert.equal(JSON.stringify(s), before);
  assert.equal(VLESS_WS_TLS.outbound.streamSettings.sockopt, undefined);
});

/* --------------------- WireGuard endpoints as addresses --------------------- */

/** WG_CORP with another endpoint, for the "already an address" cases. */
function wgAt(endpoint) {
  const s = JSON.parse(JSON.stringify(WG_CORP));
  s.outbound.settings.peers[0].endpoint = endpoint;
  return s;
}

// The patterniha fork does not resolve a WireGuard peer's endpoint with Xray's
// own DNS: dialled directly it asks the OS resolver ("Unable to update bind:
// lookup <host>: no such host") and through a chain it hands the bare hostname
// to the next hop. Either way a config whose endpoint is a name — every
// .conf-imported corporate WireGuard — never brings its tunnel up on that core,
// while everything else keeps working. Resolving the endpoint before the config
// is written makes both cores behave the same and takes the tunnel's own
// bootstrap off the DNS it is supposed to carry.
test('a WireGuard endpoint hostname is replaced by the address the connect resolved', () => {
  const c = buildConfig(single(WG_CORP), settings({ wgEndpointIps: { 'cobra.example': '203.0.113.7' } }));
  assert.equal(outboundTagged(c, 'proxy').settings.peers[0].endpoint, '203.0.113.7:42421');
  // the stored record keeps its hostname — the address is re-resolved next time
  assert.equal(WG_CORP.outbound.settings.peers[0].endpoint, 'cobra.example:42421');
});

test('an endpoint is left alone when nothing resolved it, and an IPv6 address is bracketed', () => {
  const plain = buildConfig(single(WG_CORP), settings());
  assert.equal(outboundTagged(plain, 'proxy').settings.peers[0].endpoint, 'cobra.example:42421');
  const other = buildConfig(single(WG_CORP), settings({ wgEndpointIps: { 'elsewhere.example': '1.2.3.4' } }));
  assert.equal(outboundTagged(other, 'proxy').settings.peers[0].endpoint, 'cobra.example:42421');
  const v6 = buildConfig(single(WG_CORP), settings({ wgEndpointIps: { 'cobra.example': '2001:db8::1' } }));
  assert.equal(outboundTagged(v6, 'proxy').settings.peers[0].endpoint, '[2001:db8::1]:42421');
});

test('every plan shape resolves it: a chain hop, an advanced target, a pool entry', () => {
  const map = { wgEndpointIps: { 'cobra.example': '203.0.113.7' } };
  const chain = buildConfig({ mode: 'chain', chain: [VLESS_WS_TLS, WG_CORP] }, settings(map));
  assert.equal(outboundTagged(chain, 'proxy').settings.peers[0].endpoint, '203.0.113.7:42421');
  const adv = buildConfig(advancedPlan({
    serversById: { 'sv-vless': VLESS_WS_TLS, 'sv-wgcorp': WG_CORP },
    rules: [{ type: 'ip', value: '10.0.0.0/8', target: 'sv-wgcorp' }], def: 'sv-vless'
  }), settings(map));
  assert.equal(outboundTagged(adv, 'out-sv-wgcorp').settings.peers[0].endpoint, '203.0.113.7:42421');
  const poolWg = Object.assign(poolPlan([{ id: 'e1', target: 'sv-wgcorp', socksPort: 60001 }], 'sv-wgcorp'),
    { serversById: { 'sv-vless': VLESS_WS_TLS, 'sv-wgcorp': WG_CORP } });
  const pool = buildConfig(poolWg, settings(map));
  assert.equal(outboundTagged(pool, 'out-sv-wgcorp').settings.peers[0].endpoint, '203.0.113.7:42421');
});

test('wgEndpointHosts: the names a connect has to resolve before it builds the config', () => {
  assert.deepEqual(wgEndpointHosts({ mode: 'single', server: WG_CORP }), ['cobra.example']);
  assert.deepEqual(wgEndpointHosts({ mode: 'chain', chain: [VLESS_WS_TLS, WG_CORP] }), ['cobra.example']);
  assert.deepEqual(wgEndpointHosts(advancedPlan({
    serversById: { 'sv-vless': VLESS_WS_TLS, 'sv-wgcorp': WG_CORP, 'sv-wg': WG_BAD_MASK },
    chainsById: { c1: [VLESS_WS_TLS, WG_CORP] },
    rules: [{ type: 'ip', value: '10.0.0.0/8', target: 'chain:c1' }], def: 'sv-wg'
  })), ['cobra.example', 'd.example.com']);
  // an endpoint that is already an address needs nothing
  assert.deepEqual(wgEndpointHosts({ mode: 'single', server: wgAt('198.51.100.9:51820') }), []);
  assert.deepEqual(wgEndpointHosts({ mode: 'single', server: wgAt('[2001:db8::1]:51820') }), []);
  assert.deepEqual(wgEndpointHosts({ mode: 'single', server: VLESS_WS_TLS }), []);
});

// Measured on this machine with both cores: a WireGuard peer whose AllowedIPs
// is a SPLIT list ("192.168.0.0/16, 10.0.0.0/8" — what every corporate .conf
// carries) gets no traffic at all on the patterniha fork; not even a handshake
// leaves. Widen it to the whole address space and the fork behaves exactly like
// the official core. Nothing is lost by that: `allowedIPs` here is not a
// firewall, it only says what this outbound may carry, and WE decide what
// reaches it — the routing rules, built from the very same list. The record
// keeps the real ranges, which is what the routing suggestion and the DNS
// expectedIPs read.
test('a WireGuard peer carries whatever is routed to it, whatever its AllowedIPs said', () => {
  const c = buildConfig(single(WG_CORP), settings());
  assert.deepEqual(outboundTagged(c, 'proxy').settings.peers[0].allowedIPs, ['0.0.0.0/0', '::/0']);
  // the stored record is untouched: the chip and the resolver still see the ranges
  assert.deepEqual(WG_CORP.outbound.settings.peers[0].allowedIPs, ['192.168.0.0/16', '10.0.0.0/8']);
  assert.deepEqual(wgResolvers(WG_CORP, 'out-x')[0].expectedIPs, ['192.168.0.0/16', '10.0.0.0/8']);
  // and in every shape that can carry one
  const chain = buildConfig({ mode: 'chain', chain: [VLESS_WS_TLS, WG_CORP] }, settings());
  assert.deepEqual(outboundTagged(chain, 'proxy').settings.peers[0].allowedIPs, ['0.0.0.0/0', '::/0']);
  const adv = buildConfig(advancedPlan({
    serversById: { 'sv-vless': VLESS_WS_TLS, 'sv-wgcorp': WG_CORP },
    rules: [{ type: 'ip', value: '10.0.0.0/8', target: 'sv-wgcorp' }], def: 'sv-vless'
  }), settings());
  assert.deepEqual(outboundTagged(adv, 'out-sv-wgcorp').settings.peers[0].allowedIPs, ['0.0.0.0/0', '::/0']);
});

/* --------------------- entry servers answered from the config --------------------- */
// With no sockopt.domainStrategy, xray asks the OPERATING SYSTEM for a server it
// dials by name (transport/internet/dialer.go). Under TUN that resolver is the
// tunnel itself — the Windows leak guard holds every physical adapter on
// loopback, the router's dnsmasq forwards into the gateway — so the core's
// question about its own server waits on that very server: a recursion only the
// OS cache hid, and every guard apply flushes the cache. The connect resolves
// the entry names first (entryHosts) and hands them in as `entryHostIps`; the
// config answers them from dns.hosts and has the dialer ask xray's DNS, never
// the OS. The NAME stays where it is — SNI, Host and REALITY read their own.

const PINS = { entryHostIps: { 'a.example.com': ['203.0.113.10'], 'b.example.com': ['203.0.113.20'] } };
const pinnedStrategy = (c) => c.outbounds.filter(o => o.streamSettings && o.streamSettings.sockopt && 'domainStrategy' in o.streamSettings.sockopt).map(o => o.tag);

/** The owner's first hop: VLESS over xhttp with REALITY, addressed by name (or by `address`). */
function xhttpReality(address) {
  return server('sv-xhttp', 'xhttp REALITY', 'vless', address || 'edge.example.net', 443, {
    protocol: 'vless',
    settings: { vnext: [{ address: address || 'edge.example.net', port: 443, users: [{ id: 'uuid-x', encryption: 'none', flow: '' }] }] },
    streamSettings: {
      network: 'xhttp', security: 'reality',
      xhttpSettings: { path: '/x', mode: 'auto' },
      realitySettings: { serverName: 'www.microsoft.com', fingerprint: 'chrome', publicKey: 'pk', shortId: 'ab' }
    }
  });
}

test('golden guard: without entryHostIps no dns.hosts and no sockopt.domainStrategy anywhere', () => {
  const frag = vlessWithMarkers('sv-frag', { _fragment: 'tlshello,100-200,10-20' });
  const plans = [
    single(), single(frag), single(WG_CORP),
    { mode: 'chain', chain: [VLESS_WS_TLS, TROJAN_TCP_TLS] },
    advancedPlan({ rules: [{ type: 'domain', value: 'a.com', target: 'sv-trojan' }, { type: 'ip', value: '10.20.0.0/16', target: 'chain:c1' }], def: 'sv-vless' }),
    poolPlan([{ id: 'e1', target: 'sv-trojan', socksPort: 60001, httpPort: 60002 }])
  ];
  for (const p of plans) {
    for (const base of [settings(), managed(), settings(BOUND)]) {
      const golden = JSON.stringify(buildConfig(p, base));
      assert.equal('hosts' in buildConfig(p, base).dns, false, p.mode);
      assert.deepEqual(pinnedStrategy(buildConfig(p, base)), [], p.mode);
      for (const none of [{}, null, 'x', 7, { 'a.example.com': [] }, { 'a.example.com': ['not-an-ip'] }, { 'elsewhere.example': ['203.0.113.9'] }]) {
        assert.equal(JSON.stringify(buildConfig(p, Object.assign({}, base, { entryHostIps: none }))), golden,
          `${p.mode}: ${JSON.stringify(none)} changed the config`);
      }
    }
  }
});

test('single: the server’s name is answered from dns.hosts and dialled through xray’s DNS — the name itself stays', () => {
  const c = buildConfig(single(), settings(PINS));
  assert.deepEqual(c.dns.hosts, { 'a.example.com': ['203.0.113.10'] }, 'only the names this config dials');
  assert.deepEqual(sockoptOf(c, 'proxy'), { domainStrategy: 'UseIPv4' });
  const o = outboundTagged(c, 'proxy');
  assert.equal(o.settings.vnext[0].address, 'a.example.com', 'never the address in place of the name');
  assert.equal(o.streamSettings.tlsSettings.serverName, 'a.example.com');
  assert.equal(o.streamSettings.wsSettings.headers.Host, 'a.example.com');
  // managed DNS off (the owner's mode): the user's list is kept, the hosts join it
  assert.deepEqual(c.dns.servers, ['1.1.1.1', '8.8.8.8']);
  assert.equal(c.dns.queryStrategy, 'UseIPv4');
  // managed: the resolver plan is untouched around it
  const m = buildConfig(single(), managed(PINS));
  const plain = buildConfig(single(), managed());
  assert.deepEqual(m.dns.hosts, { 'a.example.com': ['203.0.113.10'] });
  const { hosts, ...rest } = m.dns;
  assert.deepEqual(rest, plain.dns);
  assert.deepEqual(m.routing, plain.routing);
  assert.deepEqual(sockoptOf(m, 'direct'), {}, 'the direct outbound resolves as it always did');
});

test('every entry protocol shape: vnext, servers, and the flat address', () => {
  const trojan = buildConfig(single(TROJAN_TCP_TLS), settings(PINS));
  assert.deepEqual(trojan.dns.hosts, { 'b.example.com': ['203.0.113.20'] });
  assert.equal(sockoptOf(trojan, 'proxy').domainStrategy, 'UseIPv4');
  const ss = buildConfig(single(SS_TCP), settings({ entryHostIps: { 'c.example.com': ['203.0.113.30'] } }));
  assert.equal(sockoptOf(ss, 'proxy').domainStrategy, 'UseIPv4');
  const flat = server('sv-flat', 'flat', 'vless', 'f.example.com', 443,
    { protocol: 'vless', settings: { address: 'f.example.com', port: 443, id: 'uuid-f', encryption: 'none' }, streamSettings: { network: 'tcp' } });
  const f = buildConfig(single(flat), settings({ entryHostIps: { 'f.example.com': ['203.0.113.40'] } }));
  assert.deepEqual(f.dns.hosts, { 'f.example.com': ['203.0.113.40'] });
  assert.equal(sockoptOf(f, 'proxy').domainStrategy, 'UseIPv4');
});

test('IPv6: UseIP — still an IPv4 address when the name has one; an IPv6-only name only with IPv6 on', () => {
  const both = { entryHostIps: { 'a.example.com': ['2001:db8::10', '203.0.113.10', '203.0.113.11'] } };
  const v4 = buildConfig(single(), settings(both));
  assert.deepEqual(v4.dns.hosts, { 'a.example.com': ['203.0.113.10', '203.0.113.11'] });
  assert.equal(sockoptOf(v4, 'proxy').domainStrategy, 'UseIPv4');
  const v6on = buildConfig(single(), settings(Object.assign({ ipv6: true }, both)));
  assert.deepEqual(v6on.dns.hosts, { 'a.example.com': ['203.0.113.10', '203.0.113.11'] },
    'the core picks one address at random with no fallback: never hand it the family a network is likelier to lack');
  assert.equal(sockoptOf(v6on, 'proxy').domainStrategy, 'UseIP');

  const only6 = { entryHostIps: { 'a.example.com': ['2001:db8::10'] } };
  const off = buildConfig(single(), settings(only6));
  assert.equal('hosts' in off.dns, false, 'IPv4-only DNS could never answer it: left to the OS as before');
  assert.deepEqual(sockoptOf(off, 'proxy'), {});
  const on = buildConfig(single(), settings(Object.assign({ ipv6: true }, only6)));
  assert.deepEqual(on.dns.hosts, { 'a.example.com': ['2001:db8::10'] });
  assert.equal(sockoptOf(on, 'proxy').domainStrategy, 'UseIP');

  // a single address as a string, and junk beside a good one
  const str = buildConfig(single(), settings({ entryHostIps: { 'a.example.com': '203.0.113.10' } }));
  assert.deepEqual(str.dns.hosts, { 'a.example.com': ['203.0.113.10'] });
  const junk = buildConfig(single(), settings({ entryHostIps: { 'a.example.com': ['a.example.com', '', null, '203.0.113.10'] } }));
  assert.deepEqual(junk.dns.hosts, { 'a.example.com': ['203.0.113.10'] });
});

test('chain: the first hop is pinned; the hop behind it hands its name to that hop, as before', () => {
  const c = buildConfig({ mode: 'chain', chain: [VLESS_WS_TLS, TROJAN_TCP_TLS] }, settings(PINS));
  assert.deepEqual(c.dns.hosts, { 'a.example.com': ['203.0.113.10'] },
    'resolving an inner hop here would put its name on this network’s resolver');
  assert.deepEqual(sockoptOf(c, 'proxy-h0'), { domainStrategy: 'UseIPv4' });
  assert.deepEqual(sockoptOf(c, 'proxy'), { dialerProxy: 'proxy-h0' });
});

test('advanced: every target’s entry is pinned — a server, a chain’s first hop — and nothing behind a hop', () => {
  const c = buildConfig(advancedPlan({
    rules: [{ type: 'domain', value: 'a.com', target: 'sv-trojan' }, { type: 'ip', value: '10.20.0.0/16', target: 'chain:c1' }],
    def: 'sv-vless'
  }), managed(PINS));
  assert.deepEqual(c.dns.hosts, { 'b.example.com': ['203.0.113.20'], 'a.example.com': ['203.0.113.10'] });
  assert.deepEqual(pinnedStrategy(c).sort(), ['out-chain-c1-h0', 'out-sv-trojan', 'out-sv-vless']);
  assert.deepEqual(sockoptOf(c, 'out-chain-c1'), { dialerProxy: 'out-chain-c1-h0' });
});

test('pool: the primary and every entry are pinned', () => {
  const c = buildConfig(poolPlan([
    { id: 'e1', target: 'sv-trojan', socksPort: 60001 },
    { id: 'e2', target: 'chain:c1', socksPort: 60003 }
  ]), managed(PINS));
  assert.deepEqual(Object.keys(c.dns.hosts).sort(), ['a.example.com', 'b.example.com']);
  assert.deepEqual(pinnedStrategy(c).sort(), ['out-chain-c1-h0', 'out-sv-trojan', 'out-sv-vless']);
  assert.deepEqual(sockoptOf(c, 'out-chain-c1'), { dialerProxy: 'out-chain-c1-h0' });
});

test('anti-DPI and TUN binding: the pin sits beside the dialer and the interface — and the dpi dialer resolves through xray’s DNS too', () => {
  const frag = vlessWithMarkers('sv-frag', { _fragment: 'tlshello,100-200,10-20' });
  // The lookup happens BEFORE the dialerProxy redirect (dialer.go), so the
  // freedom dialer is normally handed an address. When it is handed the NAME
  // instead (a lookup that failed, a core that resolves later), an AsIs dialer
  // asked the OS — the very recursion the pin exists for. Whichever of the two
  // resolves first, the answer comes from dns.hosts.
  const c = buildConfig(single(frag), settings(PINS));
  assert.deepEqual(sockoptOf(c, 'proxy'), { dialerProxy: 'dpi-1', domainStrategy: 'UseIPv4' });
  assert.deepEqual(sockoptOf(c, 'dpi-1'), {});
  assert.equal(outboundTagged(c, 'dpi-1').settings.domainStrategy, 'UseIPv4');
  assert.deepEqual(outboundTagged(c, 'dpi-1').settings.fragment, { packets: 'tlshello', length: '100-200', interval: '10-20' }, 'the dialer is otherwise the same');
  const v6 = buildConfig(single(frag), settings(Object.assign({ ipv6: true }, PINS)));
  assert.equal(outboundTagged(v6, 'dpi-1').settings.domainStrategy, 'UseIP');
  const bound = buildConfig(single(frag), managed(Object.assign({}, PINS, BOUND)));
  assert.deepEqual(sockoptOf(bound, 'proxy'), { dialerProxy: 'dpi-1', domainStrategy: 'UseIPv4' });
  assert.deepEqual(sockoptOf(bound, 'dpi-1'), { interface: 'Wi-Fi' });
  assert.equal(outboundTagged(bound, 'dpi-1').settings.domainStrategy, 'UseIPv4');
  const plain = buildConfig(single(), managed(Object.assign({}, PINS, BOUND)));
  assert.deepEqual(sockoptOf(plain, 'proxy'), { domainStrategy: 'UseIPv4', interface: 'Wi-Fi' });
  // nothing pinned: the dialer asks as it always did
  assert.equal(outboundTagged(buildConfig(single(frag), settings()), 'dpi-1').settings.domainStrategy, 'AsIs');
});

test('a pinned and an unpinned outbound with the same anti-DPI settings get a dialer each', () => {
  // One shared dialer with a strategy would send the UNPINNED name to xray's
  // own resolvers — which sit behind the very proxy it is dialling.
  const frag = vlessWithMarkers('sv-frag', { _fragment: 'tlshello,100-200,10-20' });
  const other = vlessWithMarkers('sv-other', { _fragment: 'tlshello,100-200,10-20' });
  other.outbound.settings.vnext[0].address = 'c.example.com';   // nothing resolved it
  const c = buildConfig(advancedPlan({
    serversById: { 'sv-frag': frag, 'sv-other': other },
    rules: [{ type: 'domain', value: 'a.com', target: 'sv-other' }],
    def: 'sv-frag'
  }), settings(PINS));
  const pinned = sockoptOf(c, 'out-sv-frag');
  const unpinned = sockoptOf(c, 'out-sv-other');
  assert.equal(pinned.domainStrategy, 'UseIPv4');
  assert.equal('domainStrategy' in unpinned, false);
  assert.notEqual(pinned.dialerProxy, unpinned.dialerProxy);
  assert.equal(outboundTagged(c, pinned.dialerProxy).settings.domainStrategy, 'UseIPv4');
  assert.equal(outboundTagged(c, unpinned.dialerProxy).settings.domainStrategy, 'AsIs');
  assert.equal(c.outbounds.filter(o => /^dpi-/.test(o.tag)).length, 2);
  // two pinned ones still share one
  const both = buildConfig(advancedPlan({
    serversById: { 'sv-frag': frag, 'sv-other': other },
    rules: [{ type: 'domain', value: 'a.com', target: 'sv-other' }],
    def: 'sv-frag'
  }), settings({ entryHostIps: { 'a.example.com': ['203.0.113.10'], 'c.example.com': ['203.0.113.30'] } }));
  assert.equal(sockoptOf(both, 'out-sv-frag').dialerProxy, sockoptOf(both, 'out-sv-other').dialerProxy);
  assert.equal(both.outbounds.filter(o => /^dpi-/.test(o.tag)).length, 1);
});

test('withHosts: the pins join whatever hosts the DNS plan carries — they never replace them, and win for their own names', () => {
  const dns = { tag: 'dns-internal', hosts: { 'corp.local': ['10.0.0.5'], 'a.example.com': ['192.0.2.1'] }, servers: ['1.1.1.1'] };
  const out = withHosts(dns, { 'a.example.com': ['203.0.113.10'] });
  assert.deepEqual(out.hosts, { 'corp.local': ['10.0.0.5'], 'a.example.com': ['203.0.113.10'] });
  assert.deepEqual(Object.keys(out), ['hosts', 'tag', 'servers'], 'hosts first, as before');
  assert.deepEqual(dns.hosts, { 'corp.local': ['10.0.0.5'], 'a.example.com': ['192.0.2.1'] }, 'the plan itself is not written to');
  assert.equal(withHosts(dns, null), dns, 'nothing pinned: the plan as it is');
  assert.deepEqual(withHosts({ servers: ['1.1.1.1'] }, { 'a.example.com': ['203.0.113.10'] }),
    { hosts: { 'a.example.com': ['203.0.113.10'] }, servers: ['1.1.1.1'] });
});

test('an address, a name nothing resolved, and a WireGuard are left exactly as they were', () => {
  const ip = xhttpReality('198.51.100.4');
  const c = buildConfig(single(ip), settings({ entryHostIps: { '198.51.100.4': ['198.51.100.4'] } }));
  assert.equal('hosts' in c.dns, false);
  assert.deepEqual(sockoptOf(c, 'proxy'), {});
  // the peer endpoint has its own path (wgEndpointIps) and is not doubled here
  const wg = buildConfig(single(WG_CORP), settings({ entryHostIps: { 'cobra.example': ['198.51.100.21'] }, wgEndpointIps: { 'cobra.example': '198.51.100.21' } }));
  assert.equal('hosts' in wg.dns, false);
  assert.deepEqual(sockoptOf(wg, 'proxy'), {});
  assert.equal(outboundTagged(wg, 'proxy').settings.peers[0].endpoint, '198.51.100.21:42421');
});

test('the owner’s corporate chain: hosts for the xhttp hop’s name — only when it is a name', () => {
  const plan = (xhttp) => ({
    mode: 'advanced', chain: [],
    serversById: { 'sv-xhttp': xhttp, 'sv-wgcorp': WG_CORP },
    chainsById: { tes: [xhttp, WG_CORP] },
    rules: [{ type: 'ip', value: '192.168.0.0/16, 10.0.0.0/8, 192.168.45.0/24', target: 'chain:tes' }],
    def: 'sv-xhttp'
  });
  const owner = { tunMode: true, leakGuard: 'standard', killSwitch: true, systemProxy: false, routingMode: 'bypass-ir', directInterface: 'Wi-Fi', wgEndpointIps: { 'cobra.example': '198.51.100.21' } };
  const named = plan(xhttpReality());
  assert.deepEqual(entryHosts(named), ['edge.example.net'], 'the WireGuard behind the hop is not an entry');
  for (const dns of [{ dnsManaged: false }, MANAGED]) {
    const c = buildConfig(named, settings(Object.assign({ entryHostIps: { 'edge.example.net': ['203.0.113.30'] } }, owner, dns)));
    assert.deepEqual(c.dns.hosts, { 'edge.example.net': ['203.0.113.30'] });
    for (const tag of ['out-sv-xhttp', 'out-chain-tes-h0']) {
      assert.deepEqual(sockoptOf(c, tag), { interface: 'Wi-Fi', domainStrategy: 'UseIPv4' }, tag);
      assert.equal(outboundTagged(c, tag).settings.vnext[0].address, 'edge.example.net');
      assert.equal(outboundTagged(c, tag).streamSettings.realitySettings.serverName, 'www.microsoft.com');
    }
    const wg = outboundTagged(c, 'out-chain-tes');
    assert.deepEqual(wg.streamSettings.sockopt, { dialerProxy: 'out-chain-tes-h0' });
    assert.equal(wg.settings.peers[0].endpoint, '198.51.100.21:42421');
  }
  // a first hop that is already an address: nothing to resolve, nothing to pin
  const literal = plan(xhttpReality('203.0.113.30'));
  assert.deepEqual(entryHosts(literal), []);
  const c = buildConfig(literal, settings(Object.assign({ entryHostIps: {} }, owner)));
  assert.equal('hosts' in c.dns, false);
  assert.deepEqual(pinnedStrategy(c), []);
});

test('entryHosts: every entry the plan dials by name — never a hop behind one, a WireGuard, an address, or an unused server', () => {
  assert.deepEqual(entryHosts(single()), ['a.example.com']);
  assert.deepEqual(entryHosts(VLESS_WS_TLS), ['a.example.com'], 'a bare server is a single plan');
  assert.deepEqual(entryHosts({ mode: 'chain', chain: [VLESS_WS_TLS, TROJAN_TCP_TLS] }), ['a.example.com']);
  assert.deepEqual(entryHosts([TROJAN_TCP_TLS, VLESS_WS_TLS]), ['b.example.com']);
  assert.deepEqual(entryHosts(advancedPlan({
    serversById: { 'sv-vless': VLESS_WS_TLS, 'sv-trojan': TROJAN_TCP_TLS, 'sv-ss': SS_TCP, 'sv-wg': WG_BAD_MASK },
    chainsById: { c1: [TROJAN_TCP_TLS, VLESS_WS_TLS] },
    rules: [
      { type: 'ip', value: '10.0.0.0/8', target: 'chain:c1' },
      { type: 'ip', value: '10.1.0.0/16', target: 'sv-wg' },
      { type: 'ip', value: '10.2.0.0/16', target: 'gone' },
      { type: 'domain', value: 'x.com', target: 'direct' },
      null
    ],
    def: 'sv-vless'
  })), ['b.example.com', 'a.example.com'], 'sv-ss is in the store but routed to by nothing');
  assert.deepEqual(entryHosts(poolPlan([{ id: 'e1', target: 'sv-trojan', socksPort: 60001 }, { id: 'e2', target: 'chain:c1', socksPort: 60002 }])),
    ['a.example.com', 'b.example.com']);
  assert.deepEqual(entryHosts(single(WG_CORP)), []);
  assert.deepEqual(entryHosts(single(xhttpReality('203.0.113.30'))), []);
  assert.deepEqual(entryHosts(single(xhttpReality('2001:db8::30'))), []);
  assert.deepEqual(entryHosts({ mode: 'single' }), []);
});

test('pinning never touches the stored record', () => {
  const s = vlessWithMarkers('sv-frag', { _fragment: 'tlshello' });
  const before = JSON.stringify(s);
  buildConfig(single(s), settings(Object.assign({}, PINS, BOUND)));
  buildConfig({ mode: 'chain', chain: [s, TROJAN_TCP_TLS] }, managed(PINS));
  assert.equal(JSON.stringify(s), before);
  assert.equal(VLESS_WS_TLS.outbound.streamSettings.sockopt, undefined);
});

/* --------------------------- the multi-target latency test --------------------------- */

test('buildMultiTestConfig: one inbound per target, routed to its own outbound, no tag collisions', () => {
  // "Test all" used to spawn a core per server; one core serves them all,
  // each on its own loopback port, each routed to its own outbound.
  const c = buildMultiTestConfig(
    [VLESS_WS_TLS, [TROJAN_TCP_TLS, SS_TCP], vlessWithMarkers('sv-frag', { _fragment: 'tlshello,100-200,10-20' })],
    [40001, 40002, 40003]);
  assert.deepEqual(c.inbounds.map(i => [i.tag, i.port, i.listen, i.protocol]), [
    ['test-in-0', 40001, '127.0.0.1', 'socks'],
    ['test-in-1', 40002, '127.0.0.1', 'socks'],
    ['test-in-2', 40003, '127.0.0.1', 'socks']
  ]);
  assert.deepEqual(c.inbounds[0].settings, { auth: 'noauth', udp: false });
  assert.deepEqual(c.routing.rules, [
    { type: 'field', inboundTag: ['test-in-0'], outboundTag: 'test-out-0' },
    { type: 'field', inboundTag: ['test-in-1'], outboundTag: 'test-out-1' },
    { type: 'field', inboundTag: ['test-in-2'], outboundTag: 'test-out-2' }
  ]);
  const tags = c.outbounds.map(o => o.tag);
  assert.equal(new Set(tags).size, tags.length, 'every outbound tag unique: ' + tags.join(','));
  // the chain: exit tagged for its inbound, hop chained under the same prefix
  assert.ok(tags.includes('test-out-1') && tags.includes('test-out-1-h0'));
  assert.equal(outboundTagged(c, 'test-out-1').streamSettings.sockopt.dialerProxy, 'test-out-1-h0');
  // the fragment dialer exists and the fragmented target dials through it
  const dpi = tags.find(t => t.startsWith('dpi-'));
  assert.ok(dpi, 'a dpi dialer for the fragmented target');
  assert.equal(outboundTagged(c, 'test-out-2').streamSettings.sockopt.dialerProxy, dpi);
  assert.equal(c.log.loglevel, 'none');
  assert.equal(tags[tags.length - 1], 'direct');
  assert.equal(c.dns, undefined, 'no DNS plan: a ping runs without TUN');
});

test('buildMultiTestConfig with nothing to test is an empty, valid shape', () => {
  const c = buildMultiTestConfig([], []);
  assert.deepEqual(c.inbounds, []);
  assert.deepEqual(c.routing.rules, []);
  assert.deepEqual(c.outbounds.map(o => o.tag), ['direct']);
});

/* ----------------------------- ECH fetched from DNS, and pins from the link ----------------------------- */

const { echResolverIpsOf, echQueryOf } = require('../src/main/configBuilder');

/** The fixture with an ECH config list (and anything else) on its TLS. */
function withTls(base, tls, over) {
  const s = JSON.parse(JSON.stringify(base));
  Object.assign(s.outbound.streamSettings.tlsSettings, tls);
  return Object.assign(s, over || {});
}

test('echQueryOf: the DNS forms, the name before the +, a base64 list is no query', () => {
  assert.deepEqual(echQueryOf('cloudflare-ech.com+udp://1.1.1.1'), { name: 'cloudflare-ech.com', server: 'udp://1.1.1.1', scheme: 'udp', host: '1.1.1.1', port: null });
  assert.deepEqual(echQueryOf('https://dns.google/dns-query'), { name: '', server: 'https://dns.google/dns-query', scheme: 'https', host: 'dns.google', port: null });
  assert.equal(echQueryOf('a.example+udp://[2606:4700::1111]:53').host, '2606:4700::1111');
  assert.equal(echQueryOf('AEX+/xyz=='), null, 'a + in base64 is not a query');
  assert.equal(echQueryOf(''), null);
});

test('ECH under TUN: the core\'s own query is bound to the NIC, for a hop behind another hop too', () => {
  const ech = withTls(VLESS_WS_TLS, { echConfigList: 'cloudflare-ech.com+udp://1.1.1.1' });
  const c = buildConfig({ mode: 'chain', chain: [TROJAN_TCP_TLS, ech] }, settings({ directInterface: 'Wi-Fi' }));
  assert.deepEqual(tlsOf(c, 'proxy').echSockopt, { interface: 'Wi-Fi' });
  assert.equal(tlsOf(c, 'proxy').echConfigList, 'cloudflare-ech.com+udp://1.1.1.1');
  assert.equal(tlsOf(c, 'proxy-h0').echSockopt, undefined, 'no ECH there, nothing to bind');
  // without TUN nothing is bound, and a base64 list never is
  assert.equal(tlsOf(buildConfig(single(ech), settings()), 'proxy').echSockopt, undefined);
  const b64 = withTls(VLESS_WS_TLS, { echConfigList: 'AEXX' });
  assert.equal(tlsOf(buildConfig(single(b64), settings({ directInterface: 'Wi-Fi' })), 'proxy').echSockopt, undefined);
});

test('ECH under the strict guard: UDP to a public resolver becomes DoH on the same address; the hole is named', () => {
  const ech = withTls(VLESS_WS_TLS, { echConfigList: 'cloudflare-ech.com+udp://1.1.1.1' });
  const strict = buildConfig(single(ech), settings({ tunMode: true, leakGuard: 'strict', directInterface: 'Ethernet' }));
  assert.equal(tlsOf(strict, 'proxy').echConfigList, 'cloudflare-ech.com+https://1.1.1.1/dns-query');
  assert.deepEqual(echResolverIpsOf(strict), ['1.1.1.1']);
  // standard guard: left as the link said it
  const std = buildConfig(single(ech), settings({ tunMode: true, leakGuard: 'standard', directInterface: 'Ethernet' }));
  assert.equal(tlsOf(std, 'proxy').echConfigList, 'cloudflare-ech.com+udp://1.1.1.1');
  // an unknown resolver, or a port other than 53, is not guessed at
  const other = withTls(VLESS_WS_TLS, { echConfigList: 'x.example+udp://5.6.7.8' });
  assert.equal(tlsOf(buildConfig(single(other), settings({ tunMode: true, leakGuard: 'strict' })), 'proxy').echConfigList, 'x.example+udp://5.6.7.8');
  assert.deepEqual(echResolverIpsOf(buildConfig(single(VLESS_WS_TLS), settings())), []);
});

test('ECH from a DoH server by NAME: the name is an entry host, answered from the config', () => {
  const ech = withTls(VLESS_WS_TLS, { echConfigList: 'cloudflare-ech.com+https://dns.google/dns-query' });
  assert.deepEqual(entryHosts(single(ech)), ['a.example.com', 'dns.google']);
  assert.deepEqual(entryHosts({ mode: 'chain', chain: [TROJAN_TCP_TLS, ech] }), ['b.example.com', 'dns.google'], 'a hop behind another asks it directly too');
  const c = buildConfig(single(ech), settings({ entryHostIps: { 'a.example.com': ['1.2.3.4'], 'dns.google': ['8.8.8.8', '8.8.4.4'] }, directInterface: 'Wi-Fi' }));
  assert.deepEqual(c.dns.hosts['dns.google'], ['8.8.8.8', '8.8.4.4']);
  assert.deepEqual(tlsOf(c, 'proxy').echSockopt, { domainStrategy: 'UseIPv4', interface: 'Wi-Fi' });
});

test('pins: the link\'s pcs and the one learnt on first use are emitted together, deduplicated', () => {
  const both = withTls(VLESS_WS_TLS, { pinnedPeerCertSha256: 'cd'.repeat(32) }, { certPin: PIN });
  assert.equal(tlsOf(buildConfig(single(both), settings()), 'proxy').pinnedPeerCertSha256, 'cd'.repeat(32) + ',' + PIN);
  const same = withTls(VLESS_WS_TLS, { pinnedPeerCertSha256: PIN.toUpperCase() }, { certPin: PIN });
  assert.equal(tlsOf(buildConfig(single(same), settings()), 'proxy').pinnedPeerCertSha256, PIN);
  const linkOnly = withTls(VLESS_WS_TLS, { pinnedPeerCertSha256: 'cd'.repeat(32), verifyPeerCertByName: 'real.example' });
  const tls = tlsOf(buildConfig(single(linkOnly), settings()), 'proxy');
  assert.equal(tls.pinnedPeerCertSha256, 'cd'.repeat(32));
  assert.equal(tls.verifyPeerCertByName, 'real.example');
});

/* ----------------------------- v1.18: mux, decided per server ----------------------------- */
// `muxServerIds` (main.js / service.js, decided by src/main/mux.js): the
// servers whose OWN outbound carries mux — a single server, an advanced
// plan's server targets, a pool's exits. Never a chain's hops, never an
// outbound that cannot carry it (muxEligible), and without the setting not a
// byte of any config changes.

const { MUX } = require('../src/main/mux');
const muxOf = (c, tag) => outboundTagged(c, tag).mux;
/** A copy of `s` under another id whose outbound is `protocol` over `network` (ws/grpc), TLS kept. */
function retyped(s, id, network, protocol) {
  const out = JSON.parse(JSON.stringify(s));
  out.id = id;
  out.name = id;
  if (protocol) out.outbound.protocol = protocol;
  const st = out.outbound.streamSettings;
  st.network = network;
  delete st.wsSettings;
  if (network === 'ws') st.wsSettings = { path: '/ws', headers: { Host: out.address } };
  if (network === 'grpc') st.grpcSettings = { serviceName: 'svc', multiMode: false };
  return out;
}
const TROJAN_WS = retyped(TROJAN_TCP_TLS, 'sv-trojan-ws', 'ws');
const VLESS_GRPC = retyped(VLESS_WS_TLS, 'sv-grpc', 'grpc');
const VISION = (() => {
  const s = retyped(VLESS_WS_TLS, 'sv-vision', 'tcp');
  s.outbound.settings.vnext[0].users[0].flow = 'xtls-rprx-vision';
  return s;
})();

test('mux: the single ws+tls server named in muxServerIds carries the mux object on its proxy outbound — and nothing else changes', () => {
  for (const base of [settings(), managed(), settings(BOUND), settings(PINS), managed(Object.assign({}, BOUND, PINS))]) {
    const plain = buildConfig(single(), base);
    const c = buildConfig(single(), Object.assign({}, base, { muxServerIds: ['sv-vless'] }));
    assert.deepEqual(muxOf(c, 'proxy'), MUX);
    assert.notEqual(muxOf(c, 'proxy'), MUX, 'a copy — the frozen object never goes into a config');
    const { mux, ...rest } = outboundTagged(c, 'proxy');
    assert.deepEqual(rest, outboundTagged(plain, 'proxy'), 'the outbound is otherwise the one built without it');
    assert.deepEqual(Object.assign({}, c, { outbounds: c.outbounds.map((o) => (o.tag === 'proxy' ? rest : o)) }), plain, 'and so is the rest of the config');
    assert.deepEqual(c.outbounds.filter((o) => o.mux).map((o) => o.tag), ['proxy'], 'direct, block, dns-out and the dialers never');
  }
  // Trojan and VMess over ws, httpupgrade
  assert.deepEqual(muxOf(buildConfig(single(TROJAN_WS), settings({ muxServerIds: ['sv-trojan-ws'] })), 'proxy'), MUX);
  const vmess = retyped(VLESS_WS_TLS, 'sv-vmess', 'ws', 'vmess');
  assert.deepEqual(muxOf(buildConfig(single(vmess), settings({ muxServerIds: ['sv-vmess'] })), 'proxy'), MUX);
  const hu = retyped(VLESS_WS_TLS, 'sv-hu', 'httpupgrade');
  hu.outbound.streamSettings.httpupgradeSettings = { path: '/up', host: 'a.example.com' };
  assert.deepEqual(muxOf(buildConfig(single(hu), settings({ muxServerIds: ['sv-hu'] })), 'proxy'), MUX);
});

test('mux: with the anti-DPI dialer the proxy carries mux and still dials through it; the dialer carries none', () => {
  const frag = vlessWithMarkers('sv-frag', { _fragment: 'tlshello,100-200,10-20' });
  const c = buildConfig(single(frag), managed({ muxServerIds: ['sv-frag'] }));
  assert.deepEqual(muxOf(c, 'proxy'), MUX);
  assert.equal(sockoptOf(c, 'proxy').dialerProxy, 'dpi-1');
  assert.equal(muxOf(c, 'dpi-1'), undefined);
});

test('mux: a server muxServerIds does not name gets none', () => {
  const c = buildConfig(single(), settings({ muxServerIds: ['sv-trojan-ws', 'sv-other'] }));
  assert.equal(muxOf(c, 'proxy'), undefined);
});

test('mux: a chain’s hops never carry it — not even when every hop is named', () => {
  const ids = { muxServerIds: ['sv-vless', 'sv-trojan-ws'] };
  const c = buildConfig({ mode: 'chain', chain: [VLESS_WS_TLS, TROJAN_WS] }, settings(ids));
  assert.deepEqual(c.outbounds.filter((o) => 'mux' in o), []);
  const plain = buildConfig({ mode: 'chain', chain: [VLESS_WS_TLS, TROJAN_WS] }, settings());
  assert.equal(JSON.stringify(c), JSON.stringify(plain));
});

test('mux: an outbound that cannot carry it never gets it, named or not — TCP, gRPC, Vision, Shadowsocks, WireGuard', () => {
  for (const s of [TROJAN_TCP_TLS, VLESS_GRPC, VISION, SS_TCP, WG_BAD_MASK]) {
    const c = buildConfig(single(s), settings({ muxServerIds: [s.id] }));
    assert.equal(JSON.stringify(c), JSON.stringify(buildConfig(single(s), settings())), s.id);
  }
});

test('mux: advanced — a named server target and the default carry it; the same server as a chain hop does not', () => {
  const plan = advancedPlan({
    serversById: { 'sv-vless': VLESS_WS_TLS, 'sv-trojan': TROJAN_TCP_TLS, 'sv-trojan-ws': TROJAN_WS },
    chainsById: { c1: [VLESS_WS_TLS, TROJAN_WS] },
    rules: [{ type: 'domain', value: 'a.com', target: 'sv-trojan-ws' }, { type: 'domain', value: 'b.com', target: 'sv-trojan' }, { type: 'ip', value: '10.20.0.0/16', target: 'chain:c1' }],
    def: 'sv-vless'
  });
  const c = buildConfig(plan, managed({ muxServerIds: ['sv-vless', 'sv-trojan-ws', 'sv-trojan'] }));
  assert.deepEqual(c.outbounds.filter((o) => o.mux).map((o) => o.tag).sort(), ['out-sv-trojan-ws', 'out-sv-vless']);
  assert.deepEqual(muxOf(c, 'out-sv-vless'), MUX);
  assert.equal(muxOf(c, 'out-chain-c1-h0'), undefined, 'the chain’s VLESS hop');
  assert.equal(muxOf(c, 'out-chain-c1'), undefined, 'the chain’s Trojan-ws exit');
  // only what is named
  const one = buildConfig(plan, managed({ muxServerIds: ['sv-trojan-ws'] }));
  assert.deepEqual(one.outbounds.filter((o) => o.mux).map((o) => o.tag), ['out-sv-trojan-ws']);
});

test('mux: pool — the primary and a named exit carry it; a chain: entry does not', () => {
  const plan = {
    mode: 'pool', primary: 'sv-vless', chain: [],
    entries: [{ id: 'e1', target: 'sv-trojan-ws', socksPort: 60001 }, { id: 'e2', target: 'chain:c1', socksPort: 60002 }, { id: 'e3', target: 'sv-trojan', socksPort: 60003 }],
    serversById: { 'sv-vless': VLESS_WS_TLS, 'sv-trojan': TROJAN_TCP_TLS, 'sv-trojan-ws': TROJAN_WS },
    chainsById: { c1: [VLESS_WS_TLS, TROJAN_WS] }
  };
  const c = buildConfig(plan, managed({ muxServerIds: ['sv-vless', 'sv-trojan-ws', 'sv-trojan'] }));
  assert.deepEqual(c.outbounds.filter((o) => o.mux).map((o) => o.tag).sort(), ['out-sv-trojan-ws', 'out-sv-vless']);
});

test('golden guard: without muxServerIds — absent, empty or not a list — every config is byte-identical', () => {
  const frag = vlessWithMarkers('sv-frag', { _fragment: 'tlshello,100-200,10-20' });
  const plans = [
    single(), single(frag), single(TROJAN_WS), single(WG_CORP),
    { mode: 'chain', chain: [VLESS_WS_TLS, TROJAN_WS] },
    advancedPlan({ rules: [{ type: 'domain', value: 'a.com', target: 'sv-trojan' }, { type: 'ip', value: '10.20.0.0/16', target: 'chain:c1' }], def: 'sv-vless' }),
    poolPlan([{ id: 'e1', target: 'sv-trojan', socksPort: 60001, httpPort: 60002 }])
  ];
  for (const p of plans) {
    for (const base of [settings(), managed(), settings(BOUND), settings(PINS)]) {
      const golden = JSON.stringify(buildConfig(p, base));
      assert.equal(golden.includes('"mux"'), false, p.mode);
      for (const none of [undefined, null, [], 'sv-vless', { 'sv-vless': true }, 7]) {
        assert.equal(JSON.stringify(buildConfig(p, Object.assign({}, base, { muxServerIds: none }))), golden,
          `${p.mode}: muxServerIds ${JSON.stringify(none)} changed the config`);
      }
    }
  }
});

test('golden guard: the default settings — mux off, the owner’s choice — never put mux into any config, whatever the plan', () => {
  const { DEFAULT_SETTINGS } = require('../src/server/service');
  assert.equal(DEFAULT_SETTINGS.mux, 'off');
  const frag = vlessWithMarkers('sv-frag', { _fragment: 'tlshello,100-200,10-20' });
  const plans = [
    single(), single(frag), single(TROJAN_WS),
    { mode: 'chain', chain: [VLESS_WS_TLS, TROJAN_WS] },
    advancedPlan({ rules: [{ type: 'domain', value: 'a.com', target: 'sv-trojan' }], def: 'sv-vless' }),
    poolPlan([{ id: 'e1', target: 'sv-trojan', socksPort: 60001, httpPort: 60002 }])
  ];
  for (const p of plans) {
    const fresh = Object.assign({}, DEFAULT_SETTINGS, { geoAssets: true });
    assert.equal(JSON.stringify(buildConfig(p, fresh)).includes('"mux"'), false, p.mode);
  }
});

test('buildTestConfig: a latency test never carries mux, and is as it was without the pins a mux probe hands it', () => {
  const frag = vlessWithMarkers('sv-frag', { _fragment: 'tlshello,100-200,10-20' });
  for (const target of [VLESS_WS_TLS, TROJAN_WS, frag, [VLESS_WS_TLS, TROJAN_WS]]) {
    const before = JSON.stringify(buildTestConfig(target, 47160));
    assert.equal(before.includes('"mux"'), false);
    assert.equal(JSON.stringify(buildTestConfig(target, 47160, undefined)), before);
    assert.equal(JSON.stringify(buildTestConfig(target, 47160, {})), before, 'no pins, nothing changes');
    assert.equal(JSON.stringify(buildTestConfig(target, 47160, { entryHostIps: { 'elsewhere.example': ['203.0.113.9'] } })), before, 'pins for other names');
  }
});

test('buildTestConfig with the connect’s pins (a mux probe): the server’s name answered from dns.hosts — the name itself stays', () => {
  // A probe runs inside a connect, and under TUN a rebuild's held guard
  // answers no name (see pinEntryHosts): the probe's core dials the address
  // the connect already resolved, like the live core will.
  const c = buildTestConfig(VLESS_WS_TLS, 47161, { entryHostIps: PINS.entryHostIps, ipv6: false });
  assert.deepEqual(c.dns, { hosts: { 'a.example.com': ['203.0.113.10'] } });
  assert.deepEqual(sockoptOf(c, 'proxy'), { domainStrategy: 'UseIPv4' });
  assert.equal(outboundTagged(c, 'proxy').settings.vnext[0].address, 'a.example.com');
  // with the anti-DPI dialer the strategy rides the dialer too, as in the live config
  const frag = vlessWithMarkers('sv-frag', { _fragment: 'tlshello,100-200,10-20' });
  const f = buildTestConfig(frag, 47162, { entryHostIps: PINS.entryHostIps, ipv6: true });
  assert.deepEqual(sockoptOf(f, 'proxy'), { domainStrategy: 'UseIP', dialerProxy: 'dpi-1' });
  assert.equal(outboundTagged(f, 'dpi-1').settings.domainStrategy, 'UseIP');
  assert.deepEqual(f.dns, { hosts: { 'a.example.com': ['203.0.113.10'] } });
  // a chain: the first hop only, as in the live config
  const ch = buildTestConfig([VLESS_WS_TLS, TROJAN_TCP_TLS], 47163, { entryHostIps: PINS.entryHostIps });
  assert.deepEqual(ch.dns, { hosts: { 'a.example.com': ['203.0.113.10'] } });
  assert.deepEqual(sockoptOf(ch, 'proxy'), { dialerProxy: 'proxy-h0' });
});

/* ------------------------- JSON servers: full mode and raw mode ------------------------- */
// docs/superpowers/specs/2026-10-08-json-configs-design.md. A JSON server's
// main outbound is its outbound everywhere; the outbounds it dials through
// (extraOutbounds) are written next to it, each tagged `<outboundTag>~<tag>`
// with every dialerProxy / proxySettings.tag that named it rewritten — so two
// JSON servers in one config never collide. Raw mode runs the config itself.

const JSON_FIX = (f) => require('fs').readFileSync(require('path').join(__dirname, 'fixtures/json', f), 'utf8');
const jsonServer = (f, id, i = 0) => Object.assign(require('../src/main/jsonImport').importJson(JSON_FIX(f)).servers[i], { id });
const tagsOf = (c) => c.outbounds.map((o) => o.tag);

test('JSON full mode, single: the fragment helper beside the proxy as proxy~fragment, the dialerProxy rewritten, the helper verbatim', () => {
  const s = jsonServer('xray-fragment.json', 'js-frag');
  const c = buildConfig(single(s), settings());
  assert.deepEqual(tagsOf(c), ['proxy', 'proxy~fragment', 'direct', 'block']);
  assert.equal(outboundTagged(c, 'proxy').streamSettings.sockopt.dialerProxy, 'proxy~fragment');
  const fixtureHelper = JSON.parse(JSON_FIX('xray-fragment.json')).outbounds[1];
  assert.deepEqual(outboundTagged(c, 'proxy~fragment'), Object.assign({}, fixtureHelper, { tag: 'proxy~fragment' }));
  assert.equal(s.outbound.streamSettings.sockopt.dialerProxy, 'fragment', 'the stored record is not changed');
  assert.equal(s.extraOutbounds[0].tag, 'fragment');
  assert.equal(outboundTagged(c, 'proxy').settings.vnext[0].address, 'edge1.example.com');
});

test('JSON full mode: an advanced-routing target’s helpers are out-<id>~<tag>; two JSON servers in one config never collide', () => {
  const a = jsonServer('xray-fragment.json', 'ja');
  const b = jsonServer('xray-fragment.json', 'jb');
  const c = buildConfig(advancedPlan({
    serversById: { ja: a, jb: b, 'sv-vless': VLESS_WS_TLS },
    rules: [{ type: 'domain', value: 'a.com', target: 'jb' }], def: 'ja'
  }), settings());
  const tags = tagsOf(c);
  assert.equal(new Set(tags).size, tags.length, 'every tag once');
  assert.deepEqual(tags.filter((t) => t.includes('~')).sort(), ['out-ja~fragment', 'out-jb~fragment']);
  assert.equal(outboundTagged(c, 'out-ja').streamSettings.sockopt.dialerProxy, 'out-ja~fragment');
  assert.equal(outboundTagged(c, 'out-jb').streamSettings.sockopt.dialerProxy, 'out-jb~fragment');
  // a pool exit the same way
  const p = buildConfig({ mode: 'pool', entries: [{ id: 'e1', target: 'jb', socksPort: 60001 }], primary: 'ja', serversById: { ja: a, jb: b }, chainsById: {}, chain: [] }, settings());
  assert.deepEqual(tagsOf(p).filter((t) => t.includes('~')), ['out-ja~fragment', 'out-jb~fragment']);
});

test('JSON full mode: a two-hop chain through proxySettings — its hop rewritten to proxy~hop1 (as the dialerProxy the cores now take), hop1’s dialerProxy → proxy~frag, the mux kept', () => {
  const s = jsonServer('xray-chain.json', 'js-chain');
  const c = buildConfig(single(s), settings());
  assert.deepEqual(tagsOf(c), ['proxy', 'proxy~hop1', 'proxy~frag', 'direct', 'block']);
  // Xray 26 refuses proxySettings at load: "removed and migrated to streamSettings.sockopt.dialerProxy"
  assert.equal(outboundTagged(c, 'proxy').proxySettings, undefined);
  assert.deepEqual(outboundTagged(c, 'proxy').streamSettings.sockopt, { dialerProxy: 'proxy~hop1' });
  assert.deepEqual(s.outbound.proxySettings, { tag: 'hop1' }, 'the stored record keeps it as written');
  assert.deepEqual(outboundTagged(c, 'proxy').mux, { enabled: true, concurrency: 8 });
  assert.equal(outboundTagged(c, 'proxy~hop1').streamSettings.sockopt.dialerProxy, 'proxy~frag');
  assert.equal(outboundTagged(c, 'proxy~frag').settings.fragment.packets, '1-3');
});

test('JSON full mode in a chain: as a later hop it dials through the hop before and brings none of its helpers; as the first hop it keeps them', () => {
  const frag = jsonServer('xray-fragment.json', 'jf');
  const ch = jsonServer('xray-chain.json', 'jc');
  const later = buildConfig({ mode: 'chain', chain: [VLESS_WS_TLS, frag] }, settings());
  assert.deepEqual(tagsOf(later), ['proxy-h0', 'proxy', 'direct', 'block']);
  assert.deepEqual(outboundTagged(later, 'proxy').streamSettings.sockopt, { dialerProxy: 'proxy-h0' });
  const later2 = buildConfig({ mode: 'chain', chain: [VLESS_WS_TLS, ch] }, settings());
  assert.deepEqual(tagsOf(later2), ['proxy-h0', 'proxy', 'direct', 'block']);
  assert.equal(outboundTagged(later2, 'proxy').proxySettings, undefined, 'its own hop is dropped with its helpers');
  assert.equal(outboundTagged(later2, 'proxy').streamSettings.sockopt.dialerProxy, 'proxy-h0');
  const first = buildConfig({ mode: 'chain', chain: [frag, TROJAN_TCP_TLS] }, settings());
  assert.deepEqual(tagsOf(first), ['proxy-h0', 'proxy-h0~fragment', 'proxy', 'direct', 'block']);
  assert.equal(outboundTagged(first, 'proxy-h0').streamSettings.sockopt.dialerProxy, 'proxy-h0~fragment');
  assert.equal(outboundTagged(first, 'proxy').streamSettings.sockopt.dialerProxy, 'proxy-h0');
});

test('JSON full mode under TUN: the helpers that dial themselves are bound to the NIC, the ones behind another outbound are not', () => {
  const c = buildConfig(single(jsonServer('xray-fragment.json', 'jf')), settings({ directInterface: 'Wi-Fi' }));
  assert.deepEqual(outboundTagged(c, 'proxy~fragment').streamSettings.sockopt, { tcpNoDelay: true, interface: 'Wi-Fi' });
  assert.deepEqual(outboundTagged(c, 'proxy').streamSettings.sockopt, { dialerProxy: 'proxy~fragment' });
  const ch = buildConfig(single(jsonServer('xray-chain.json', 'jc')), settings({ directInterface: 'Wi-Fi' }));
  assert.deepEqual(outboundTagged(ch, 'proxy~frag').streamSettings, { sockopt: { interface: 'Wi-Fi' } });
  assert.deepEqual(outboundTagged(ch, 'proxy~hop1').streamSettings.sockopt, { dialerProxy: 'proxy~frag' });
  assert.deepEqual(outboundTagged(ch, 'proxy').streamSettings.sockopt, { dialerProxy: 'proxy~hop1' });
});

test('JSON full mode: a latency test and the multi-target test carry the helpers too — the main outbound cannot dial without them', () => {
  const s = jsonServer('xray-fragment.json', 'jf');
  const t = buildTestConfig(s, 47200);
  assert.deepEqual(tagsOf(t), ['proxy', 'proxy~fragment', 'direct']);
  assert.equal(outboundTagged(t, 'proxy').streamSettings.sockopt.dialerProxy, 'proxy~fragment');
  const m = buildMultiTestConfig([s, VLESS_WS_TLS, [s, TROJAN_TCP_TLS]], [1, 2, 3]);
  assert.deepEqual(tagsOf(m), ['test-out-0', 'test-out-0~fragment', 'test-out-1', 'test-out-2-h0', 'test-out-2-h0~fragment', 'test-out-2', 'direct']);
});

test('JSON servers the plan does not route to change nothing: link-only configs are byte-identical with them in the store', () => {
  const j = jsonServer('xray-chain.json', 'jc');
  const withJson = (x) => Object.assign({}, x, { serversById: Object.assign({ jc: j }, x.serversById) });
  for (const p of [advancedPlan({ rules: [{ type: 'domain', value: 'a.com', target: 'sv-trojan' }], def: 'sv-vless' }), poolPlan([{ id: 'e1', target: 'sv-trojan', socksPort: 60001 }])]) {
    for (const over of [{}, { directInterface: 'eth0', dnsManaged: true }, { entryHostIps: { 'a.example.com': ['203.0.113.1'] } }]) {
      assert.equal(JSON.stringify(buildConfig(withJson(p), settings(over))), JSON.stringify(buildConfig(p, settings(over))), p.mode);
    }
  }
});

test('buildRawConfig: the config itself, with the app’s own inbounds, its log level, and the stats the meter reads', () => {
  const { buildRawConfig } = require('../src/main/configBuilder');
  const s = jsonServer('xray-fragment.json', 'jf');
  const fx = JSON.parse(JSON_FIX('xray-fragment.json'));
  const set = settings({ socksPort: 2080, httpPort: 2081, apiPort: 2085, logLevel: 'debug' });
  const c = buildRawConfig(s, set);
  assert.deepEqual(c.inbounds, buildConfig(single(s), set).inbounds, 'the same inbounds buildConfig makes for these settings');
  assert.equal(c.log.loglevel, 'debug');
  assert.deepEqual(c.routing, fx.routing);
  assert.deepEqual(c.dns, fx.dns);
  assert.deepEqual(c.outbounds, fx.outbounds, 'every outbound as written, tags and all');
  assert.equal(c.remarks, fx.remarks);
  assert.deepEqual(c.metrics, { tag: 'metrics', listen: '127.0.0.1:2085' });
  assert.deepEqual(c.stats, {});
  assert.equal(c.policy.system.statsOutboundUplink, true);
  assert.deepEqual(s.json, fx, 'the record is not changed');
  // a balancer and its observatory run as written
  const b = jsonServer('xray-balancer.json', 'jb');
  const bfx = JSON.parse(JSON_FIX('xray-balancer.json'));
  const bc = buildRawConfig(b, settings());
  assert.deepEqual(bc.routing, bfx.routing);
  assert.deepEqual(bc.routing.balancers, bfx.routing.balancers);
  assert.deepEqual(bc.observatory, bfx.observatory);
  assert.deepEqual(bc.outbounds, bfx.outbounds);
  // a subscription config: its own socks inbound on 10808 is replaced, never added to
  const sub = jsonServer('xray-subscription.json', 'js');
  assert.deepEqual(buildRawConfig(sub, settings()).inbounds.map((i) => i.tag), ['socks-in', 'http-in']);
  // a hop through proxySettings, which Xray 26 refuses at load, goes as the dialerProxy it was migrated to
  const ch = buildRawConfig(jsonServer('xray-chain.json', 'jc'), settings());
  const cfx = JSON.parse(JSON_FIX('xray-chain.json'))[0];
  assert.equal(outboundTagged(ch, 'proxy').proxySettings, undefined);
  assert.deepEqual(outboundTagged(ch, 'proxy').streamSettings, Object.assign({}, cfx.outbounds[0].streamSettings, { sockopt: { dialerProxy: 'hop1' } }));
  assert.deepEqual(ch.outbounds.slice(1), cfx.outbounds.slice(1), 'every other outbound as written');
  assert.deepEqual(ch.routing, cfx.routing);
});

test('buildRawConfig writes what the cores take: no allowInsecure anywhere, the learnt pin on the main outbound, a WireGuard endpoint as the address it was resolved to', () => {
  const { buildRawConfig } = require('../src/main/configBuilder');
  // the owner's subscription: every server carries "allowInsecure": false
  const sub = jsonServer('xray-subscription.json', 'js');
  assert.equal(JSON.stringify(sub.json).includes('allowInsecure'), true);
  const c = buildRawConfig(sub, settings());
  assert.equal(JSON.stringify(c).includes('allowInsecure'), false);
  const fxTls = JSON.parse(JSON_FIX('xray-subscription.json'))[2].outbounds[0].streamSettings.tlsSettings;
  const { allowInsecure, ...rest } = fxTls;
  assert.equal(allowInsecure, false);
  assert.deepEqual(outboundTagged(c, 'proxy').streamSettings.tlsSettings, rest, 'only the removed key goes');
  // a server that asked for allowInsecure: its learnt pin, as in full mode (applyCertPin), joined to the config's own
  const pin = 'ab11bf7ac877baa539294f5a3c864b8ed43e6fe3a9a8230fc2db7fff85c27fde';
  const own = 'cd'.repeat(32);
  const insecure = JSON.parse(JSON.stringify(sub));
  insecure.json.outbounds[0].streamSettings.tlsSettings.allowInsecure = true;
  insecure.json.outbounds[0].streamSettings.tlsSettings.pinnedPeerCertSha256 = own;
  insecure.outbound.streamSettings.tlsSettings.allowInsecure = true;
  insecure.outbound.streamSettings.tlsSettings.pinnedPeerCertSha256 = own;
  insecure.certPin = pin;
  const p = outboundTagged(buildRawConfig(insecure, settings()), 'proxy').streamSettings.tlsSettings;
  assert.equal(p.allowInsecure, undefined);
  assert.equal(p.pinnedPeerCertSha256, `${own},${pin}`);
  // the pin is the main outbound's server's: a helper with TLS of its own never gets it
  const chain = jsonServer('xray-chain.json', 'jc');
  chain.certPin = pin;
  const hop = outboundTagged(buildRawConfig(chain, settings()), 'hop1').streamSettings.tlsSettings;
  assert.equal(hop.pinnedPeerCertSha256, undefined);
  // WireGuard: the endpoint name the connect resolved (settings.wgEndpointIps), as full mode writes it
  const wg = jsonServer('xray-wireguard.json', 'jw');
  const w = buildRawConfig(wg, settings({ wgEndpointIps: { 'wg.example.com': '198.51.100.7' } }));
  assert.equal(outboundTagged(w, 'wg').settings.peers[0].endpoint, '198.51.100.7:51820');
  assert.equal(outboundTagged(buildRawConfig(wg, settings()), 'wg').settings.peers[0].endpoint, 'wg.example.com:51820', 'nothing resolved: as written');
  assert.equal(wg.json.outbounds[0].settings.peers[0].endpoint, 'wg.example.com:51820', 'the record is not changed');
});

test('buildRawConfig under TUN: every outbound that dials itself is bound to the NIC — nothing else changes', () => {
  const { buildRawConfig } = require('../src/main/configBuilder');
  const s = jsonServer('xray-fragment.json', 'jf');
  const c = buildRawConfig(s, settings({ directInterface: 'Wi-Fi' }));
  const so = (tag) => (outboundTagged(c, tag).streamSettings || {}).sockopt;
  assert.deepEqual(so('proxy'), { dialerProxy: 'fragment' });
  assert.deepEqual(so('fragment'), { tcpNoDelay: true, interface: 'Wi-Fi' });
  assert.deepEqual(so('direct'), { interface: 'Wi-Fi' });
  assert.equal(so('block'), undefined);
  assert.deepEqual(c.routing, JSON.parse(JSON_FIX('xray-fragment.json')).routing);
});

test('raw mode is for a single-server connect only: rawServerOf and the notes the connect logs once', () => {
  const { rawServerOf, rawModeNotes } = require('../src/main/configBuilder');
  const raw = Object.assign(jsonServer('xray-fragment.json', 'jr'), { jsonMode: 'raw', name: 'R' });
  const full = jsonServer('xray-chain.json', 'jc');
  assert.equal(rawServerOf(single(raw)), raw);
  assert.equal(rawServerOf(single(full)), null);
  assert.equal(rawServerOf(single(VLESS_WS_TLS)), null);
  assert.equal(rawServerOf({ mode: 'chain', chain: [raw, VLESS_WS_TLS] }), null);
  assert.deepEqual(rawModeNotes(single(raw)), [{ line: 'Running "R" exactly as written (raw JSON) — the app\'s DNS management, leak guard and routing mode do not apply', level: 'info' }]);
  assert.deepEqual(rawModeNotes(single(full)), []);
  assert.deepEqual(rawModeNotes(single(VLESS_WS_TLS)), []);
  const note = [{ line: '"R" is set to run raw, but a chain/routing target uses its full form', level: 'warn' }];
  assert.deepEqual(rawModeNotes({ mode: 'chain', chain: [VLESS_WS_TLS, raw] }), note);
  assert.deepEqual(rawModeNotes(advancedPlan({ serversById: { jr: raw, 'sv-vless': VLESS_WS_TLS }, rules: [{ type: 'domain', value: 'a.com', target: 'jr' }], def: 'jr' })), note, 'once, however often it is routed to');
  assert.deepEqual(rawModeNotes(advancedPlan({ serversById: { jr: raw, 'sv-vless': VLESS_WS_TLS }, def: 'sv-vless' })), [], 'not routed to: nothing to say');
  // in a chain the raw server is built in its full form
  const c = buildConfig({ mode: 'chain', chain: [raw, VLESS_WS_TLS] }, settings());
  assert.deepEqual(tagsOf(c), ['proxy-h0', 'proxy-h0~fragment', 'proxy', 'direct', 'block']);
});

/* ------------------- JSON servers: what this machine dials itself ------------------- */
// A JSON server's entries are the proxy outbounds of [main, ...helpers] that
// dial by themselves — directly, or through a freedom helper (a fragment or
// noise dialer dials the address of whoever dialled through it). One that
// dials through another proxy (the chain fixture's exit, behind hop1) is
// reached by that proxy, never from here.

test('entry addresses: the chain fixture is entered at its hop, the fragment fixture at its own server; a link server at its address as always', () => {
  const { entryAddressesOf } = require('../src/main/configBuilder');
  const ch = jsonServer('xray-chain.json', 'jc');
  const fr = jsonServer('xray-fragment.json', 'jf');
  assert.deepEqual(entryAddressesOf(ch), ['hop.example.com']);
  assert.deepEqual(entryAddressesOf(fr), ['edge1.example.com']);
  assert.deepEqual(entryAddressesOf(jsonServer('xray-wireguard.json', 'jw')), ['wg.example.com']);
  assert.deepEqual(entryAddressesOf(VLESS_WS_TLS), ['a.example.com']);
  assert.deepEqual(entryAddressesOf(WG_BAD_MASK), ['d.example.com']);
  // raw: the whole config runs, so every proxy outbound in it that dials by itself
  const bal = Object.assign(jsonServer('xray-balancer.json', 'jb'), { jsonMode: 'raw' });
  assert.deepEqual(entryAddressesOf(bal), ['edge1.example.com']);
  assert.deepEqual(entryAddressesOf(bal, true), ['edge1.example.com', 'edge2.example.com']);
});

test('entryHosts: the names a connect resolves for a JSON server are its entries’ — hop.example.com, never exit.example.com', () => {
  const ch = jsonServer('xray-chain.json', 'jc');
  const fr = jsonServer('xray-fragment.json', 'jf');
  assert.deepEqual(entryHosts(single(ch)), ['hop.example.com']);
  assert.deepEqual(entryHosts(single(fr)), ['edge1.example.com']);
  assert.deepEqual(entryHosts({ mode: 'chain', chain: [ch, TROJAN_TCP_TLS] }), ['hop.example.com']);
  assert.deepEqual(entryHosts({ mode: 'chain', chain: [TROJAN_TCP_TLS, ch] }), ['b.example.com'], 'a later hop is entered through the hop before it');
  assert.deepEqual(entryHosts(advancedPlan({ serversById: { jc: ch, jf: fr }, rules: [{ type: 'domain', value: 'a.com', target: 'jc' }], def: 'jf' })), ['hop.example.com', 'edge1.example.com']);
  // names are resolved under TUN only, where a raw server runs its full form (rawApplies)
  const bal = Object.assign(jsonServer('xray-balancer.json', 'jb'), { jsonMode: 'raw' });
  assert.deepEqual(entryHosts(single(bal)), ['edge1.example.com']);
  assert.deepEqual(entryHosts(single(Object.assign({}, bal, { jsonMode: 'full' }))), ['edge1.example.com']);
});

test('pinEntryHosts answers a JSON server’s entries from the config: the hop behind a fragment dialer is pinned, the exit behind the hop is not', () => {
  const pins = { entryHostIps: { 'hop.example.com': ['203.0.113.30'], 'exit.example.com': ['203.0.113.31'], 'edge1.example.com': ['203.0.113.32'] } };
  const c = buildConfig(single(jsonServer('xray-chain.json', 'jc')), settings(pins));
  assert.deepEqual(c.dns.hosts, { 'hop.example.com': ['203.0.113.30'] });
  assert.deepEqual(sockoptOf(c, 'proxy~hop1'), { dialerProxy: 'proxy~frag', domainStrategy: 'UseIPv4' });
  assert.deepEqual(sockoptOf(c, 'proxy'), { dialerProxy: 'proxy~hop1' });
  assert.equal(outboundTagged(c, 'proxy~frag').settings.domainStrategy, 'UseIPv4', 'the dialer carries the strategy, as a dpi dialer does');
  const f = buildConfig(single(jsonServer('xray-fragment.json', 'jf')), settings(pins));
  assert.deepEqual(f.dns.hosts, { 'edge1.example.com': ['203.0.113.32'] });
  assert.deepEqual(sockoptOf(f, 'proxy'), { dialerProxy: 'proxy~fragment', domainStrategy: 'UseIPv4' });
  assert.equal(outboundTagged(f, 'proxy~fragment').settings.domainStrategy, 'UseIPv4');
  // without pins nothing of it is there
  const plain = buildConfig(single(jsonServer('xray-chain.json', 'jc')), settings());
  assert.equal(plain.dns.hosts, undefined);
  assert.deepEqual(sockoptOf(plain, 'proxy~hop1'), { dialerProxy: 'proxy~frag' });
  assert.equal(outboundTagged(plain, 'proxy~frag').settings.domainStrategy, undefined);
});

/* ------------------- raw mode runs in proxy mode on the desktop only ------------------- */
// Under TUN — and always on the router — the app's DNS (the LAN's port-53
// answer, the entry names answered from the config) and its tunnel rules are
// what keep names resolving: a raw server runs its full form there.

test('rawApplies: a raw JSON server runs as written in proxy mode on the desktop; under TUN and on the router its full form runs', () => {
  const { rawApplies, rawServerOf } = require('../src/main/configBuilder');
  const raw = Object.assign(jsonServer('xray-fragment.json', 'jr'), { jsonMode: 'raw', name: 'R' });
  const full = jsonServer('xray-fragment.json', 'jf');
  assert.equal(rawApplies(raw, { tunMode: false }), true, 'desktop, proxy mode');
  assert.equal(rawApplies(raw, { tunMode: true }), false, 'desktop, TUN');
  assert.equal(rawApplies(raw, { tunMode: false }, { openwrt: true }), false, 'the router, always');
  assert.equal(rawApplies(raw, { tunMode: true }, { openwrt: true }), false);
  assert.equal(rawApplies(full, { tunMode: false }), false, 'full mode is full mode');
  assert.equal(rawApplies(VLESS_WS_TLS, { tunMode: false }), false);
  assert.equal(rawServerOf(single(raw), { tunMode: false }), raw);
  assert.equal(rawServerOf(single(raw), { tunMode: true }), null);
  assert.equal(rawServerOf(single(raw), { tunMode: false }, { openwrt: true }), null);
});

test('rawModeNotes says once why a raw server runs its full form under TUN or on the router', () => {
  const { rawModeNotes } = require('../src/main/configBuilder');
  const raw = Object.assign(jsonServer('xray-fragment.json', 'jr'), { jsonMode: 'raw', name: 'R' });
  const running = [{ line: 'Running "R" exactly as written (raw JSON) — the app\'s DNS management, leak guard and routing mode do not apply', level: 'info' }];
  const full = [{ line: '"R" is set to run raw — under TUN (and on the router) its full form runs, so the app\'s DNS and tunnel rules apply', level: 'warn' }];
  assert.deepEqual(rawModeNotes(single(raw), { tunMode: false }), running);
  assert.deepEqual(rawModeNotes(single(raw), { tunMode: true }), full);
  assert.deepEqual(rawModeNotes(single(raw), { tunMode: false }, { openwrt: true }), full);
  assert.deepEqual(rawModeNotes({ mode: 'chain', chain: [VLESS_WS_TLS, raw] }, { tunMode: true }),
    [{ line: '"R" is set to run raw, but a chain/routing target uses its full form', level: 'warn' }]);
  assert.deepEqual(rawModeNotes(single(jsonServer('xray-chain.json', 'jc')), { tunMode: true }), []);
});

test('dialerTagsOf names the outbounds a running config dials through — a raw config’s helpers, whose bytes its main outbound already counted', () => {
  const { buildRawConfig, dialerTagsOf } = require('../src/main/configBuilder');
  assert.deepEqual([...dialerTagsOf(buildRawConfig(jsonServer('xray-chain.json', 'jc'), settings()))].sort(), ['frag', 'hop1']);
  assert.deepEqual([...dialerTagsOf(buildRawConfig(jsonServer('xray-fragment.json', 'jf'), settings()))], ['fragment']);
  assert.deepEqual([...dialerTagsOf(buildRawConfig(jsonServer('xray-balancer.json', 'jb'), settings()))], [], 'both balancer members carry their own traffic');
  assert.deepEqual([...dialerTagsOf(null)], []);
});

/* ------------------------- routing profiles: "via a base" ------------------------- */
// docs/superpowers/specs/2026-10-09-routing-profiles-design.md §2. A base is one
// outbound group (`base-<id>`, a chain's hops `base-chain-<cid>-h<i>`), shared
// by every target through it; a target through a base is its own outbound
// (`out-<id>@<baseKey>`, a chain `out-chain-<cid>@<baseKey>` with `…-h<i>`)
// whose self-dialing outbound dials the base. Without a via: today's tags.

const { MUX: MUX_OBJ } = require('../src/main/mux');
const { planServers } = require('../src/main/engineChoice');
/** A profile's plan: today's advanced plan plus the profile's own fields. */
const viaPlan = (over) => advancedPlan(Object.assign({ profileId: 'p1', defVia: 'inherit', base: null }, over));
const dialer = (c, tag) => {
  const o = outboundTagged(c, tag);
  assert.ok(o, `${tag} is in the config`);
  return (o.streamSettings && o.streamSettings.sockopt && o.streamSettings.sockopt.dialerProxy) || null;
};
const V2 = vlessWithMarkers('sv-v2', {});
const V3 = vlessWithMarkers('sv-v3', {});

test('via: two rules to different servers through one server base — one base-<id>, and out-<id>@<base> for each, dialing it', () => {
  const c = buildConfig(viaPlan({
    serversById: { 'sv-vless': VLESS_WS_TLS, 'sv-trojan': TROJAN_TCP_TLS, 'sv-ss': SS_TCP },
    base: 'sv-vless',
    rules: [{ type: 'domain', value: 'a.com', target: 'sv-trojan' }, { type: 'domain', value: 'c.com', target: 'sv-ss', via: 'inherit' }]
  }), settings({ blockAds: false }));
  assert.deepEqual(tagsOf(c), ['base-sv-vless', 'out-sv-trojan@sv-vless', 'out-sv-ss@sv-vless', 'direct', 'block']);
  assert.equal(dialer(c, 'out-sv-trojan@sv-vless'), 'base-sv-vless');
  assert.equal(dialer(c, 'out-sv-ss@sv-vless'), 'base-sv-vless');
  assert.equal(dialer(c, 'base-sv-vless'), null, 'the base dials by itself');
  const own = outboundTagged(buildConfig(advancedPlan({ def: 'sv-vless' }), settings()), 'out-sv-vless');
  assert.deepEqual(Object.assign({}, outboundTagged(c, 'base-sv-vless'), { tag: 'out-sv-vless' }), own, 'the base is the server’s own outbound');
  assert.deepEqual(outboundTagged(c, 'out-sv-trojan@sv-vless').settings, TROJAN_TCP_TLS.outbound.settings);
  assert.deepEqual(ruleTags(c), ['out-sv-trojan@sv-vless', 'out-sv-ss@sv-vless', 'direct', 'direct']);
});

test('via: a chain target through a base — its first hop dials the base, the rest dial the hop before', () => {
  const c = buildConfig(viaPlan({
    serversById: { 'sv-vless': VLESS_WS_TLS, 'sv-trojan': TROJAN_TCP_TLS, 'sv-ss': SS_TCP },
    rules: [{ type: 'ip', value: '10.0.0.0/8', target: 'chain:c1', via: 'sv-ss' }]
  }), settings({ blockAds: false }));
  assert.deepEqual(tagsOf(c), ['base-sv-ss', 'out-chain-c1@sv-ss-h0', 'out-chain-c1@sv-ss', 'direct', 'block']);
  assert.equal(dialer(c, 'out-chain-c1@sv-ss-h0'), 'base-sv-ss');
  assert.equal(dialer(c, 'out-chain-c1@sv-ss'), 'out-chain-c1@sv-ss-h0');
  assert.equal(c.routing.rules.find((r) => r.ip && r.ip[0] === '10.0.0.0/8').outboundTag, 'out-chain-c1@sv-ss');
});

test('via: a chain base — hops base-chain-<cid>-h<i>, exit base-chain-<cid>; a target through it is out-<id>@chain-<cid>', () => {
  const c = buildConfig(viaPlan({
    serversById: { 'sv-vless': VLESS_WS_TLS, 'sv-trojan': TROJAN_TCP_TLS, 'sv-ss': SS_TCP },
    base: 'chain:c1',
    rules: [{ type: 'domain', value: 'a.com', target: 'sv-ss' }]
  }), settings({ blockAds: false }));
  assert.deepEqual(tagsOf(c), ['base-chain-c1-h0', 'base-chain-c1', 'out-sv-ss@chain-c1', 'direct', 'block']);
  assert.equal(dialer(c, 'base-chain-c1-h0'), null);
  assert.equal(dialer(c, 'base-chain-c1'), 'base-chain-c1-h0');
  assert.equal(dialer(c, 'out-sv-ss@chain-c1'), 'base-chain-c1');
  // a chain through a chain base
  const cc = buildConfig(viaPlan({ chainsById: { c1: [VLESS_WS_TLS, TROJAN_TCP_TLS], c2: [SS_TCP, TROJAN_TCP_TLS] }, base: 'chain:c1', def: 'chain:c2' }), settings({ blockAds: false }));
  assert.deepEqual(tagsOf(cc), ['base-chain-c1-h0', 'base-chain-c1', 'out-chain-c2@chain-c1-h0', 'out-chain-c2@chain-c1', 'direct', 'block']);
  assert.equal(dialer(cc, 'out-chain-c2@chain-c1-h0'), 'base-chain-c1');
  assert.equal(ruleTags(cc).at(-1), 'out-chain-c2@chain-c1');
});

test('via: the default through the profile’s base; a default with via none is today’s out-<id>', () => {
  const plan = viaPlan({ base: 'sv-vless', def: 'sv-trojan' });
  const c = buildConfig(plan, settings({ blockAds: false }));
  assert.deepEqual(tagsOf(c), ['base-sv-vless', 'out-sv-trojan@sv-vless', 'direct', 'block']);
  assert.equal(ruleTags(c).at(-1), 'out-sv-trojan@sv-vless');
  const none = buildConfig(Object.assign({}, plan, { defVia: 'none' }), settings({ blockAds: false }));
  assert.deepEqual(tagsOf(none), ['out-sv-trojan', 'direct', 'block']);
  const explicit = buildConfig(Object.assign({}, plan, { base: null, defVia: 'chain:c1' }), settings({ blockAds: false }));
  assert.deepEqual(tagsOf(explicit), ['base-chain-c1-h0', 'base-chain-c1', 'out-sv-trojan@chain-c1', 'direct', 'block']);
  // the base as the default itself goes direct to it: a target is never its own base
  const self = buildConfig(Object.assign({}, plan, { def: 'sv-vless' }), settings({ blockAds: false }));
  assert.deepEqual(tagsOf(self), ['out-sv-vless', 'direct', 'block']);
});

test('via: a JSON server through a base dials the base — its own fragment helper left out', () => {
  const jf = jsonServer('xray-fragment.json', 'jf');
  const c = buildConfig(viaPlan({ serversById: { 'sv-vless': VLESS_WS_TLS, jf }, base: 'sv-vless', def: 'jf' }), settings({ blockAds: false }));
  assert.deepEqual(tagsOf(c), ['base-sv-vless', 'out-jf@sv-vless', 'direct', 'block']);
  assert.deepEqual(outboundTagged(c, 'out-jf@sv-vless').streamSettings.sockopt, { dialerProxy: 'base-sv-vless' });
  assert.equal(tagsOf(c).some((t) => t.includes('~')), false, 'no ~fragment helper');
  // a JSON server AS the base dials through its helpers, as any outbound that dials by itself
  const b = buildConfig(viaPlan({ serversById: { 'sv-vless': VLESS_WS_TLS, jf }, base: 'jf', def: 'sv-vless' }), settings({ blockAds: false }));
  assert.deepEqual(tagsOf(b), ['base-jf', 'base-jf~fragment', 'out-sv-vless@jf', 'direct', 'block']);
  assert.equal(dialer(b, 'base-jf'), 'base-jf~fragment');
  assert.equal(dialer(b, 'out-sv-vless@jf'), 'base-jf');
  // a JSON chain's own hop (proxySettings) is dropped with its helpers
  const jc = jsonServer('xray-chain.json', 'jc');
  const ch = buildConfig(viaPlan({ serversById: { 'sv-vless': VLESS_WS_TLS, jc }, base: 'sv-vless', def: 'jc' }), settings({ blockAds: false }));
  assert.deepEqual(tagsOf(ch), ['base-sv-vless', 'out-jc@sv-vless', 'direct', 'block']);
  assert.equal(outboundTagged(ch, 'out-jc@sv-vless').proxySettings, undefined);
  assert.equal(dialer(ch, 'out-jc@sv-vless'), 'base-sv-vless');
});

test('via: the same server with and without a via — out-<id> and out-<id>@<base> side by side', () => {
  const c = buildConfig(viaPlan({
    base: 'sv-vless',
    rules: [{ type: 'domain', value: 'a.com', target: 'sv-trojan', via: 'none' }, { type: 'domain', value: 'b.com', target: 'sv-trojan' }]
  }), settings({ blockAds: false }));
  assert.deepEqual(tagsOf(c), ['out-sv-trojan', 'base-sv-vless', 'out-sv-trojan@sv-vless', 'direct', 'block']);
  assert.equal(dialer(c, 'out-sv-trojan'), null);
  assert.equal(dialer(c, 'out-sv-trojan@sv-vless'), 'base-sv-vless');
  assert.deepEqual(ruleTags(c).slice(0, 2), ['out-sv-trojan', 'out-sv-trojan@sv-vless']);
});

test('via: a base that no longer exists refuses the connect in plain words (fa / en), like a missing default', () => {
  for (const over of [
    { base: 'sv-gone', rules: [{ type: 'domain', value: 'a.com', target: 'sv-trojan' }] },
    { base: 'chain:emptied', def: 'sv-trojan' },
    { rules: [{ type: 'domain', value: 'a.com', target: 'sv-trojan', via: 'chain:missing' }] },
    { def: 'sv-trojan', defVia: 'sv-gone' }
  ]) {
    const plan = viaPlan(Object.assign({ chainsById: { c1: [VLESS_WS_TLS, TROJAN_TCP_TLS], emptied: [] } }, over));
    assert.throws(() => buildConfig(plan, settings({ lang: 'en' })), /base .*no longer exists/i, JSON.stringify(over));
    assert.throws(() => buildConfig(plan, settings({ lang: 'fa' })), /پایه/, JSON.stringify(over) + ' (fa)');
  }
  // a base nothing goes through, and a rule whose own target is gone, stop nothing
  assert.doesNotThrow(() => buildConfig(viaPlan({ base: 'sv-gone', def: 'sv-trojan', defVia: 'none' }), settings()));
  assert.doesNotThrow(() => buildConfig(viaPlan({ rules: [{ type: 'domain', value: 'a.com', target: 'sv-also-gone', via: 'sv-gone' }] }), settings()));
});

test('via: mux only on a direct server target — never on a base, nor on anything through one', () => {
  const c = buildConfig(viaPlan({
    serversById: { 'sv-vless': VLESS_WS_TLS, 'sv-v2': V2, 'sv-v3': V3 },
    chainsById: { cv: [V2, V3] },
    base: 'sv-vless',
    rules: [{ type: 'domain', value: 'a.com', target: 'sv-v2' }, { type: 'domain', value: 'b.com', target: 'chain:cv' }],
    def: 'sv-v3', defVia: 'none'
  }), settings({ blockAds: false, muxServerIds: ['sv-vless', 'sv-v2', 'sv-v3'] }));
  const muxed = c.outbounds.filter((o) => o.mux).map((o) => o.tag);
  assert.deepEqual(muxed, ['out-sv-v3']);
  assert.deepEqual(outboundTagged(c, 'out-sv-v3').mux, MUX_OBJ);
  for (const t of tagsOf(c)) if (t.includes('@') || t.startsWith('base-')) assert.equal(outboundTagged(c, t).mux, undefined, t);
});

test('via: the entry hosts are the base’s, never a target behind it; only the base is pinned', () => {
  const plan = viaPlan({
    serversById: { 'sv-vless': VLESS_WS_TLS, 'sv-trojan': TROJAN_TCP_TLS, 'sv-ss': SS_TCP },
    base: 'sv-vless',
    rules: [{ type: 'domain', value: 'a.com', target: 'sv-trojan' }],
    def: 'sv-ss', defVia: 'none'
  });
  assert.deepEqual(entryHosts(plan), ['a.example.com', 'c.example.com']);
  const pins = { 'a.example.com': ['203.0.113.1'], 'b.example.com': ['203.0.113.2'], 'c.example.com': ['203.0.113.3'] };
  const c = buildConfig(plan, settings({ blockAds: false, entryHostIps: pins }));
  assert.deepEqual(c.dns.hosts, { 'a.example.com': ['203.0.113.1'], 'c.example.com': ['203.0.113.3'] });
  assert.deepEqual(outboundTagged(c, 'out-sv-trojan@sv-vless').streamSettings.sockopt, { dialerProxy: 'base-sv-vless' }, 'its name travels through the base');
  assert.equal(outboundTagged(c, 'base-sv-vless').streamSettings.sockopt.domainStrategy, 'UseIPv4');
  // …and under TUN only the base is bound to the NIC
  const tun = buildConfig(plan, settings({ blockAds: false, directInterface: 'Wi-Fi' }));
  assert.equal(outboundTagged(tun, 'base-sv-vless').streamSettings.sockopt.interface, 'Wi-Fi');
  assert.equal(outboundTagged(tun, 'out-sv-trojan@sv-vless').streamSettings.sockopt.interface, undefined);
  // a link server's anti-DPI dialer is a chained hop's: dropped behind a base
  const frag = vlessWithMarkers('sv-frag', { _fragment: 'tlshello,100-200,10-20' });
  const f = buildConfig(viaPlan({ serversById: { 'sv-vless': VLESS_WS_TLS, 'sv-frag': frag }, base: 'sv-vless', def: 'sv-frag' }), settings({ blockAds: false }));
  assert.equal(tagsOf(f).some((t) => t.startsWith('dpi-')), false);
  assert.equal(dialer(f, 'out-sv-frag@sv-vless'), 'base-sv-vless');
});

test('via: planServers includes the bases — a PattN base runs the whole plan on PattN', () => {
  const pattn = Object.assign({}, SS_TCP, { engine: 'xray-pattn' });
  const plan = viaPlan({ serversById: { 'sv-vless': VLESS_WS_TLS, 'sv-ss': pattn }, base: 'sv-ss', def: 'sv-vless' });
  assert.deepEqual(planServers(plan).map((s) => s.id), ['sv-vless', 'sv-ss']);
  assert.equal(require('../src/main/engineChoice').chooseEngine(plan, 'xray'), 'xray-pattn');
  const chainBase = viaPlan({ base: 'chain:c1', def: 'sv-wg' });
  assert.deepEqual(planServers(chainBase).map((s) => s.id), ['sv-wg', 'sv-vless', 'sv-trojan']);
});

test('via: a corporate WireGuard through a base carries its resolver through that outbound', () => {
  const c = buildConfig(viaPlan({
    serversById: { 'sv-vless': VLESS_WS_TLS, 'sv-wgcorp': WG_CORP },
    base: 'sv-vless',
    rules: [{ type: 'ip', value: '192.168.0.0/16', target: 'sv-wgcorp' }],
    def: 'sv-vless', defVia: 'none'
  }), settings({ blockAds: false, dnsManaged: true, dnsRemote: ['https://1.1.1.1/dns-query'], dnsDirect: [] }));
  assert.equal(dialer(c, 'out-sv-wgcorp@sv-vless'), 'base-sv-vless');
  const corp = c.routing.rules.find((r) => Array.isArray(r.ip) && r.ip.includes('192.168.60.1') && r.inboundTag);
  assert.ok(corp, 'the corporate resolver is routed');
  assert.equal(corp.outboundTag, 'out-sv-wgcorp@sv-vless');
});

test('via: a profile’s own useMode decides the country bypass under its rules', () => {
  const plan = viaPlan({ def: 'sv-vless' });
  const on = buildConfig(Object.assign({}, plan, { useMode: true }), settings({ blockAds: false, routingMode: 'bypass-ir', advancedUseMode: false }));
  assert.ok(on.routing.rules.some((r) => r.ip && r.ip[0] === 'geoip:ir'), 'the profile asks for it');
  const off = buildConfig(Object.assign({}, plan, { useMode: false }), settings({ blockAds: false, routingMode: 'bypass-ir', advancedUseMode: true }));
  assert.equal(off.routing.rules.some((r) => r.ip && r.ip[0] === 'geoip:ir'), false, 'the profile does not');
});

test('via: a migrated profile (no vias, no base) builds exactly today’s advanced config', () => {
  const { profileFromSettings } = require('../src/main/routingProfiles');
  const rules = [
    { type: 'domain', value: 'geosite:category-ir', target: 'direct' },
    { type: 'ip', value: '10.20.0.0/16', target: 'chain:c1' },
    { type: 'domain', value: 'a.com', target: 'sv-trojan' },
    { type: 'port', value: '5060', target: 'sv-wg' }
  ];
  for (const def of ['sv-vless', 'chain:c1', 'direct', 'block']) {
    for (const advancedUseMode of [false, true]) {
      const s = { routeRules: rules, routeDefault: def, advancedUseMode };
      const p = profileFromSettings(s);
      const today = advancedPlan({ rules, def });
      const profile = advancedPlan({ profileId: p.id, rules: p.rules, def: p.def, defVia: p.defVia, base: p.base, useMode: p.useMode });
      for (const over of [{}, { routingMode: 'bypass-ir', dnsManaged: true, dnsRemote: ['https://1.1.1.1/dns-query'], dnsDirect: ['178.22.122.100'] }, { directInterface: 'eth0', entryHostIps: { 'a.example.com': ['203.0.113.1'] }, muxServerIds: ['sv-vless'] }]) {
        const set = settings(Object.assign({ advancedUseMode }, over));
        assert.equal(JSON.stringify(buildConfig(profile, set)), JSON.stringify(buildConfig(today, set)), `${def} ${advancedUseMode} ${JSON.stringify(over)}`);
      }
      assert.deepEqual(entryHosts(profile), entryHosts(today));
      assert.deepEqual(planServers(profile), planServers(today));
    }
  }
});
