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

const { buildConfig, buildTestConfig, buildRoutingRules, buildChainOutbounds, resolverBypassIps, wgResolvers } = require('../src/main/configBuilder');
const {
  settings, ruleTags, outboundTagged, vlessWithMarkers,
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

test('advanced: a one-member chain collapses to a single outbound', () => {
  const c = buildConfig(advancedPlan({
    chainsById: { solo: [VLESS_WS_TLS] },
    rules: [{ type: 'domain', value: 'x.com', target: 'chain:solo' }]
  }), settings({ blockAds: false }));
  assert.deepEqual(c.outbounds.map(o => o.tag), ['out-chain-solo', 'direct', 'block']);
});

test('advanced: unknown / empty targets fall back to direct', () => {
  const c = buildConfig(advancedPlan({
    rules: [
      { type: 'domain', value: 'x.com', target: 'no-such-server' },
      { type: 'domain', value: 'y.com', target: 'chain:missing' },
      { type: 'domain', value: 'z.com', target: 'block' }
    ],
    def: 'also-missing'
  }), settings({ blockAds: false }));

  assert.deepEqual(ruleTags(c), ['direct', 'direct', 'block', 'direct', 'direct']);
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

test('wireguard dialed through a chain disables the dialer buffer', () => {
  // Xray-core #2850: without bufferSize 0 the tunnel silently passes no data.
  const chained = buildConfig({ mode: 'chain', chain: [VLESS_WS_TLS, WG_BAD_MASK] }, settings());
  assert.equal(chained.policy.levels['0'].bufferSize, 0);

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
});

test('buildTestConfig: a chain target is measured end to end', () => {
  const c = buildTestConfig([VLESS_WS_TLS, TROJAN_TCP_TLS], 47124);
  assert.deepEqual(c.outbounds.map(o => o.tag), ['proxy-h0', 'proxy', 'direct']);
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
  assert.deepEqual(c.routing.rules[0], { type: 'field', inboundTag: ['dns-internal'], ip: ['178.22.122.100'], outboundTag: 'direct' });
  assert.deepEqual(c.routing.rules[1], { type: 'field', inboundTag: ['dns-internal'], outboundTag: 'proxy' });
  assert.equal(c.routing.rules[2].outboundTag, 'dns-out');
  assert.equal(c.dns.servers[0].address, '178.22.122.100');
  assert.deepEqual(c.dns.servers[0].expectedIPs, ['geoip:ir']);
});

test('managed bypass-ir without geo files carries no geo token at all', () => {
  const c = buildConfig(single(), settings(Object.assign({ routingMode: 'bypass-ir', geoAssets: false }, MANAGED)));
  assert.equal(JSON.stringify(c).includes('geosite:'), false);
  assert.equal(JSON.stringify(c).includes('geoip:'), false);
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
const CORP_SERVER = { address: '192.168.60.1', domains: ['domain:tes.systems'], expectedIPs: ['192.168.0.0/16', '10.0.0.0/8'] };
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
