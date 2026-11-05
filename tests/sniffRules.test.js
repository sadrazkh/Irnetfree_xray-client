'use strict';
/*
 * What a domain rule's text means to the core, which addresses sniffing leaves alone, and where the QUIC pair sits.
 * Android's SniffRulesTest.kt holds the same cases. What the core does with them, on real cores:
 * scripts/probe-domain-routing.js.
 */
const { test } = require('node:test');
const assert = require('node:assert');
const { normalizeDomain, normalizeDomains, sniffExcludedIps, isIpLiteral, namesDecide, quicFallbackRules } = require('../src/main/sniffRules');
const { buildConfig } = require('../src/main/configBuilder');
const { groupRecord } = require('../src/main/groups');
const F = require('./fixtures');

const CASES = [
  // a name and everything under it, never a substring of another name
  ['example.com', 'domain:example.com'],
  ['  Example.COM ', 'domain:example.com'],
  ['.example.com', 'domain:example.com'],
  ['*.example.com', 'domain:example.com'],
  ['*..example.com', 'domain:example.com'],
  ['example.com.', 'domain:example.com'],
  // an address pasted whole
  ['https://claude.ai/chat?x=1#y', 'domain:claude.ai'],
  ['HTTP://Claude.ai:8443/', 'domain:claude.ai'],
  ['claude.ai/new', 'domain:claude.ai'],
  // any other star is a wildcard over the whole name
  ['*anthropic.com', 'regexp:^.*anthropic\\.com$'],
  ['*.example.*', 'regexp:^.*\\.example\\..*$'],
  ['api.*.example.com', 'regexp:^api\\..*\\.example\\.com$'],
  ['*', 'regexp:^.*$'],
  // no dot: the core's own substring
  ['google', 'google'],
  ['localhost', 'localhost'],
  // what the core knows stays as written, its prefix in the case it reads
  ['domain:Example.com', 'domain:Example.com'],
  ['Domain:example.com', 'domain:example.com'],
  ['full:www.example.com', 'full:www.example.com'],
  ['keyword:acme', 'keyword:acme'],
  ['Regexp:^a\\.b$', 'regexp:^a\\.b$'],
  ['geosite:category-ir', 'geosite:category-ir'],
  ['ext:my.dat:tag', 'ext:my.dat:tag'],
  ['dotless:corp', 'dotless:corp'],
  // a name is sniffed in its ASCII form
  ['مثال.ir', 'domain:xn--mgbh0fb.ir'],
  // nothing there
  ['', null],
  ['   ', null],
  ['.', null],
  ['https://', null],
  [null, null]
];

for (const [value, want] of CASES) {
  test(`domain value ${JSON.stringify(value)} is ${JSON.stringify(want)}`, () => {
    assert.equal(normalizeDomain(value), want);
  });
}

test('the owner\'s list: each once, the same name written twice one entry', () => {
  assert.deepEqual(normalizeDomains(['anthropic.com', '*anthropic.com', 'claude.ai', '*.claude.ai', '.claude.ai', '', null]),
    ['domain:anthropic.com', 'regexp:^.*anthropic\\.com$', 'domain:claude.ai']);
});

test('sniffing leaves alone only what the core can read', () => {
  for (const v of ['10.1.2.3', '192.168.0.0/16', '::1', 'fc00::/7', '0.0.0.0/0', '::/0']) assert.ok(isIpLiteral(v), v);
  for (const v of ['geoip:ir', 'ext:x:y', '1.2.3.4-1.2.3.9', '1.2.3.4/33', '::1/129', '1.2.3.4/x', '1.2.3.4/8/8', 'example.com', '', null]) assert.equal(isIpLiteral(v), false, String(v));
  assert.deepEqual(sniffExcludedIps(['192.168.0.0/16', 'geoip:ir', ' 172.16.0.0/12 ', '192.168.0.0/16', 'nonsense', '::1/128']), ['192.168.0.0/16', '172.16.0.0/12', '::1/128']);
});

test('the poison addresses stay sniffed: a range around them is cut, and what is left covers the rest of it', () => {
  const inside = (ip, cidr) => {
    const n = (s) => s.split('.').reduce((a, x) => ((a * 256) + Number(x)) >>> 0, 0);
    const [addr, mask] = cidr.split('/');
    const shift = 32 - Number(mask);
    return shift === 32 || (n(ip) >>> shift) === (n(addr) >>> shift);
  };
  const cut = sniffExcludedIps(['10.0.0.0/8']);
  for (const poison of ['10.10.34.34', '10.10.34.35', '10.10.34.36']) assert.equal(cut.some((c) => inside(poison, c)), false, poison);
  for (const kept of ['10.0.0.1', '10.10.33.1', '10.10.34.31', '10.10.34.40', '10.10.35.1', '10.255.255.254', '10.128.0.1']) {
    assert.equal(cut.filter((c) => inside(kept, c)).length, 1, kept);
  }
  assert.equal(cut.length, 21);
  assert.deepEqual(sniffExcludedIps(['0.0.0.0/0', '::/0', '128.0.0.0/1', '8.0.0.0/7', '2000::/3']), [], 'the internet, not a host: names must still be read');
  assert.deepEqual(sniffExcludedIps(['8.0.0.0/8', 'fc00::/7']), ['8.0.0.0/8', 'fc00::/7'], 'as wide as may be');
  assert.deepEqual(sniffExcludedIps(['10.10.34.0/29']), ['10.10.34.0/29'], 'beside it');
  assert.deepEqual(sniffExcludedIps(['10.10.34.32/29', '10.10.34.34', '10.10.34.34/32']), ['10.10.34.32/29', '10.10.34.34', '10.10.34.34/32'], 'named by the user: as written');
  assert.deepEqual(sniffExcludedIps(['192.168.0.0/16']), ['192.168.0.0/16'], 'elsewhere');
});

const plan = (rules, def = 'sv-vless') => ({
  mode: 'advanced',
  serversById: { 'sv-vless': F.VLESS_WS_TLS, 'sv-trojan': F.TROJAN_TCP_TLS, 'sv-wg': F.WG_CORP },
  chainsById: {},
  chain: [],
  rules,
  def
});
const settings = (over) => F.settings(Object.assign({ blockAds: false }, over));

test('a rule not written says nothing: it must not stop a name being read', () => {
  const kept = (c) => c.inbounds.find((i) => i.tag === 'socks-in').sniffing.ipsExcluded;
  const gone = buildConfig(plan([{ type: 'ip', value: '203.0.113.0/24', target: 'no-such-server' }]), settings({}));
  assert.equal(kept(gone).includes('203.0.113.0/24'), false, 'its target is gone');
  const left = buildConfig(plan([{ type: 'domain', value: 'a.example', target: 'sv-trojan' }]), settings({ customRules: [{ outboundTag: 'direct', ip: '203.0.113.0/24' }] }));
  assert.equal(kept(left).includes('203.0.113.0/24'), false, 'a simple-mode rule under an advanced plan');
  assert.equal(left.routing.rules.some((r) => (r.ip || []).includes('203.0.113.0/24')), false, 'and it is not in the config');
});

test('a plan\'s sniffing leaves alone its IP rules\' addresses, the private ones and a split WireGuard\'s', () => {
  const c = buildConfig(plan([
    { type: 'ip', value: '203.0.113.0/24, geoip:de', target: 'sv-trojan' },
    { type: 'domain', value: 'a.example', target: 'sv-trojan' },
    { type: 'port', value: '8443', target: 'sv-trojan' }
  ]), settings({}));
  const kept = c.inbounds.find((i) => i.tag === 'socks-in').sniffing.ipsExcluded;
  assert.ok(kept.includes('203.0.113.0/24'));
  assert.ok(kept.includes('172.16.0.0/12') && kept.includes('fe80::/10'));
  assert.equal(kept.some((k) => k.startsWith('geoip')), false);
  assert.equal(new Set(kept).size, kept.length);

  const custom = buildConfig({ mode: 'single', server: F.VLESS_WS_TLS }, settings({ customRules: [{ outboundTag: 'direct', ip: '198.51.100.7' }] }));
  assert.ok(custom.inbounds.find((i) => i.tag === 'socks-in').sniffing.ipsExcluded.includes('198.51.100.7'));

  const split = JSON.parse(JSON.stringify(F.WG_CORP));
  split.outbound.settings.peers[0].allowedIPs = ['198.18.0.0/15'];
  const wg = buildConfig(Object.assign(plan([], 'sv-wg'), { serversById: { 'sv-wg': split } }), settings({}));
  assert.ok(wg.inbounds.find((i) => i.tag === 'socks-in').sniffing.ipsExcluded.includes('198.18.0.0/15'));
});

test('a domain rule with nothing readable in it is no rule: an empty field would make the core refuse the config', () => {
  const c = buildConfig(plan([{ type: 'domain', value: '., https://', target: 'sv-trojan' }]), settings({}));
  assert.equal(c.routing.rules.some((r) => r.domain && !r.domain.length), false);
  assert.equal(c.outbounds.some((o) => o.tag === 'out-sv-trojan'), false, 'and no outbound for it');
});

test('the QUIC pair: only when a name sends something away from the default, right before the catch-all', () => {
  assert.equal(namesDecide([{ domain: ['a'], outboundTag: 'x' }], 'x'), false);
  assert.equal(namesDecide([{ ip: ['1.1.1.1'], outboundTag: 'y' }], 'x'), false);
  assert.equal(namesDecide([{ domain: ['a'], outboundTag: 'y' }], 'x'), true);

  const pair = (c) => c.routing.rules.filter((r) => r.network === 'udp' && r.port === '443');
  const none = buildConfig(plan([{ type: 'ip', value: '203.0.113.0/24', target: 'sv-trojan' }]), settings({}));
  assert.equal(pair(none).length, 0, 'only addresses in the rules');
  const same = buildConfig(plan([{ type: 'domain', value: 'a.example', target: 'sv-vless' }]), settings({}));
  assert.equal(pair(same).length, 0, 'to the default anyway');

  const c = buildConfig(plan([{ type: 'domain', value: 'a.example', target: 'sv-trojan' }]), settings({}));
  assert.deepEqual(c.routing.rules.slice(-3), [...quicFallbackRules('out-sv-vless'), { type: 'field', port: '0-65535', outboundTag: 'out-sv-vless' }]);
  assert.deepEqual(pair(c)[1].outboundTag, 'block');
  const nameRule = c.routing.rules.findIndex((r) => (r.domain || []).includes('domain:a.example'));
  assert.ok(nameRule < c.routing.rules.indexOf(pair(c)[0]), 'a name in a rule is decided first');

  const mode = buildConfig(plan([{ type: 'domain', value: 'a.example', target: 'block' }]), settings({ advancedUseMode: true, routingMode: 'bypass-ir' }));
  const at = (pred) => mode.routing.rules.findIndex(pred);
  assert.ok(at((r) => (r.ip || []).includes('geoip:ir')) < at((r) => r.network === 'udp' && r.port === '443'), 'the country\'s own stays direct, read or not');

  const simple = buildConfig({ mode: 'single', server: F.VLESS_WS_TLS }, settings({ customRules: [{ outboundTag: 'direct', domain: 'a.example' }] }));
  assert.deepEqual(simple.routing.rules.slice(-3).map((r) => r.outboundTag), ['proxy', 'block', 'proxy']);
  const plain = buildConfig({ mode: 'single', server: F.VLESS_WS_TLS }, settings({}));
  assert.equal(pair(plain).length, 0, 'no rule by name: QUIC as before');
});

test('a group as the default: the QUIC pair goes where the catch-all goes', () => {
  const byId = { 'sv-vless': F.VLESS_WS_TLS, 'sv-trojan': F.TROJAN_TCP_TLS };
  const group = groupRecord({ id: 'grp-g', name: 'G', strategy: 'leastPing', members: ['sv-vless', 'sv-trojan'] }, byId);
  const c = buildConfig(Object.assign(plan([{ type: 'domain', value: 'a.example', target: 'sv-trojan' }], 'grp-g'), {
    serversById: Object.assign({}, byId, { 'grp-g': group })
  }), settings({}));
  const last = c.routing.rules.at(-1);
  const named = c.routing.rules.find((r) => r.network === 'udp' && r.domain);
  assert.equal(named.outboundTag, last.outboundTag);
  assert.equal(named.balancerTag, last.balancerTag);
});
