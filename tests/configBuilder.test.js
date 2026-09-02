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

const { buildConfig, buildTestConfig, buildRoutingRules, buildChainOutbounds } = require('../src/main/configBuilder');
const {
  settings, ruleTags, outboundTagged, vlessWithMarkers,
  VLESS_WS_TLS, TROJAN_TCP_TLS, SS_TCP, WG_BAD_MASK
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

test('dns and log level come from settings', () => {
  const c = buildConfig(single(), settings({ dns: ['9.9.9.9'], logLevel: 'debug' }));
  assert.deepEqual(c.dns, { servers: ['9.9.9.9'], queryStrategy: 'UseIP' });
  assert.equal(c.log.loglevel, 'debug');
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

test('fakeSni prepends a real ClientHello record carrying the decoy name', () => {
  const s = vlessWithMarkers('sv-sni', { _fakesni: 'www.wikipedia.org' });
  const c = buildConfig(single(s), settings());

  const noises = outboundTagged(c, 'dpi-1').settings.noises;
  assert.equal(noises[0].type, 'base64');

  const rec = Buffer.from(noises[0].packet, 'base64');
  assert.deepEqual([...rec.subarray(0, 3)], [0x16, 0x03, 0x01], 'not a TLS handshake record');
  assert.equal(rec.readUInt16BE(3), rec.length - 5, 'record length header is wrong');
  assert.equal(rec[5], 0x01, 'not a ClientHello');
  assert.ok(rec.includes(Buffer.from('www.wikipedia.org')), 'decoy SNI missing from the record');
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
