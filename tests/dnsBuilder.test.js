'use strict';
/**
 * Name resolution is where "bypass Iran does nothing" came from: the resolver
 * used plain UDP through the proxy, the server dropped it, and geoip:ir never
 * matched. These tests pin the resolver plan: DoH for the world, an in-country
 * UDP resolver pinned to domestic domains, and a hijack of every port-53 packet.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const {
  buildDnsPlan, adapterDnsServers, isDohUrl,
  DNS_DEFAULT_REMOTE, DNS_DEFAULT_DIRECT_IR, DNS_DEFAULT_DIRECT_CN
} = require('../src/main/dnsBuilder');

const base = (over) => Object.assign({
  dnsManaged: true,
  dnsRemote: ['https://1.1.1.1/dns-query', 'https://8.8.8.8/dns-query'],
  dnsDirect: ['178.22.122.100', '185.51.200.2'],
  ipv6: false,
  routingMode: 'global',
  advancedRouting: false,
  routeRules: []
}, over || {});
const opts = (over) => Object.assign({ geoAssets: true, exitTag: 'proxy' }, over || {});

/* ----------------------------- managed: global ----------------------------- */

test('global: remote DoH only, hijack on, queries routed to the exit', () => {
  const p = buildDnsPlan(base(), opts());
  assert.deepEqual(p.dns, {
    tag: 'dns-internal',
    queryStrategy: 'UseIPv4',
    servers: ['https://1.1.1.1/dns-query', 'https://8.8.8.8/dns-query']
  });
  assert.deepEqual(p.hijackOutbound, { tag: 'dns-out', protocol: 'dns' });
  assert.deepEqual(p.rules, [
    { type: 'field', inboundTag: ['dns-internal'], outboundTag: 'proxy' },
    { type: 'field', port: '53', network: 'tcp,udp', outboundTag: 'dns-out' }
  ]);
  assert.deepEqual(p.directResolverIps, []);
});

test('ipv6 on switches the query strategy', () => {
  assert.equal(buildDnsPlan(base({ ipv6: true }), opts()).dns.queryStrategy, 'UseIP');
});

test('the exit tag is whatever the caller routes its catch-all to', () => {
  const adv = buildDnsPlan(base(), opts({ exitTag: 'out-sv-a' }));
  assert.equal(adv.rules[0].outboundTag, 'out-sv-a');
  const direct = buildDnsPlan(base({ routingMode: 'direct' }), opts({ exitTag: 'direct' }));
  assert.equal(direct.rules[0].outboundTag, 'direct');
});

/* ----------------------------- managed: bypass ----------------------------- */

test('bypass-ir: the direct resolver is pinned to Iranian domains and answers', () => {
  const p = buildDnsPlan(base({ routingMode: 'bypass-ir' }), opts());
  assert.deepEqual(p.dns.servers, [
    { address: '178.22.122.100', domains: ['geosite:category-ir', 'regexp:.*\\.ir$'], expectedIPs: ['geoip:ir'], skipFallback: true },
    { address: '185.51.200.2', domains: ['geosite:category-ir', 'regexp:.*\\.ir$'], expectedIPs: ['geoip:ir'], skipFallback: true },
    'https://1.1.1.1/dns-query',
    'https://8.8.8.8/dns-query'
  ]);
  // the resolver's OWN queries to the in-country server must go direct, and
  // must be decided before the port-53 hijack or they would loop into dns-out
  assert.deepEqual(p.rules, [
    { type: 'field', inboundTag: ['dns-internal'], ip: ['178.22.122.100', '185.51.200.2'], outboundTag: 'direct' },
    { type: 'field', inboundTag: ['dns-internal'], outboundTag: 'proxy' },
    { type: 'field', port: '53', network: 'tcp,udp', outboundTag: 'dns-out' }
  ]);
  assert.deepEqual(p.directResolverIps, ['178.22.122.100', '185.51.200.2']);
});

test('bypass-ir without geo files: no geosite/geoip tokens anywhere', () => {
  const p = buildDnsPlan(base({ routingMode: 'bypass-ir' }), opts({ geoAssets: false }));
  const srv = p.dns.servers[0];
  assert.deepEqual(srv.domains, ['regexp:.*\\.ir$']);
  assert.equal('expectedIPs' in srv, false, 'geoip:ir needs geoip.dat');
  assert.equal(JSON.stringify(p).includes('geosite:'), false);
  assert.equal(JSON.stringify(p).includes('geoip:'), false);
});

test('bypass-cn uses the Chinese resolver and lists', () => {
  const p = buildDnsPlan(base({ routingMode: 'bypass-cn' }), opts());
  assert.deepEqual(p.dns.servers[0], { address: '223.5.5.5', domains: ['geosite:cn'], expectedIPs: ['geoip:cn'], skipFallback: true });
  assert.deepEqual(p.directResolverIps, ['223.5.5.5']);
});

test('an empty dnsDirect falls back to the built-in in-country resolver', () => {
  const p = buildDnsPlan(base({ routingMode: 'bypass-ir', dnsDirect: [] }), opts());
  assert.equal(p.dns.servers[0].address, DNS_DEFAULT_DIRECT_IR[0]);
});

/* ----------------------------- managed: advanced ----------------------------- */

test('advanced: a geosite:category-ir → direct rule brings the Iranian resolver along', () => {
  const p = buildDnsPlan(base({
    advancedRouting: true,
    routeRules: [{ type: 'domain', value: 'geosite:category-ir', target: 'direct' }]
  }), opts({ exitTag: 'out-sv-a' }));
  assert.equal(p.dns.servers[0].address, '178.22.122.100');
  assert.deepEqual(p.dns.servers[0].domains, ['geosite:category-ir', 'regexp:.*\\.ir$']);
});

test('advanced: geosite:cn → direct brings the Chinese resolver; other geosites bring nothing', () => {
  const cn = buildDnsPlan(base({ advancedRouting: true, routeRules: [{ type: 'domain', value: 'geosite:cn', target: 'direct' }] }), opts({ exitTag: 'x' }));
  assert.equal(cn.dns.servers[0].address, '223.5.5.5');
  const other = buildDnsPlan(base({ advancedRouting: true, routeRules: [{ type: 'domain', value: 'geosite:google', target: 'direct' }] }), opts({ exitTag: 'x' }));
  assert.equal(typeof other.dns.servers[0], 'string', 'no known expectedIPs for that list');
  const notDirect = buildDnsPlan(base({ advancedRouting: true, routeRules: [{ type: 'domain', value: 'geosite:category-ir', target: 'out-sv-a' }] }), opts({ exitTag: 'x' }));
  assert.equal(typeof notDirect.dns.servers[0], 'string', 'only direct targets need an in-country answer');
});

/* ----------------------------- resolver shapes ----------------------------- */

test('a DoH direct resolver is not routable by IP: no direct rule for it, no hijack loop', () => {
  const p = buildDnsPlan(base({ routingMode: 'bypass-ir', dnsDirect: ['https://free.shecan.ir/dns-query'] }), opts());
  assert.equal(p.dns.servers[0].address, 'https://free.shecan.ir/dns-query');
  assert.deepEqual(p.directResolverIps, []);
  assert.equal(p.rules[0].ip, undefined, 'first rule is the exit rule, not an ip rule');
  assert.equal(p.rules.length, 2);
});

test('a DoH URL with an IP host is routable by that IP', () => {
  const p = buildDnsPlan(base({ routingMode: 'bypass-ir', dnsDirect: ['https://178.22.122.100/dns-query'] }), opts());
  assert.deepEqual(p.directResolverIps, ['178.22.122.100']);
});

test('dropUdpDirect (strict guard): UDP direct resolvers are dropped, DoH ones kept', () => {
  const p = buildDnsPlan(base({ routingMode: 'bypass-ir', dnsDirect: ['178.22.122.100', 'https://free.shecan.ir/dns-query'] }), opts({ dropUdpDirect: true }));
  assert.equal(p.dns.servers.filter(s => typeof s === 'object').length, 1);
  assert.equal(p.dns.servers[0].address, 'https://free.shecan.ir/dns-query');
});

test('blank and duplicate entries are ignored; at least one remote server always remains', () => {
  const p = buildDnsPlan(base({ dnsRemote: [' ', '', 'https://1.1.1.1/dns-query', 'https://1.1.1.1/dns-query'] }), opts());
  assert.deepEqual(p.dns.servers, ['https://1.1.1.1/dns-query']);
  const none = buildDnsPlan(base({ dnsRemote: [] }), opts());
  assert.deepEqual(none.dns.servers, DNS_DEFAULT_REMOTE);
});

/* ----------------------------- unmanaged (legacy) ----------------------------- */

test('dnsManaged off: the user’s list verbatim, no hijack, no rules', () => {
  const p = buildDnsPlan(base({ dnsManaged: false, dnsRemote: ['9.9.9.9', 'https://8.8.8.8/dns-query'], routingMode: 'bypass-ir' }), opts());
  assert.deepEqual(p.dns, { queryStrategy: 'UseIPv4', servers: ['9.9.9.9', 'https://8.8.8.8/dns-query'] });
  assert.equal(p.hijackOutbound, null);
  assert.deepEqual(p.rules, []);
  assert.deepEqual(p.directResolverIps, []);
});

test('a legacy `dns` array still works as the remote list', () => {
  const p = buildDnsPlan({ dnsManaged: false, dns: ['9.9.9.9'] }, opts());
  assert.deepEqual(p.dns.servers, ['9.9.9.9']);
});

/* ----------------------------- TUN adapter DNS ----------------------------- */

test('adapterDnsServers: managed → the tunnel peer (so queries are hijacked), else the remote IPs', () => {
  assert.deepEqual(adapterDnsServers(base(), '10.255.0.1'), ['10.255.0.1']);
  assert.deepEqual(adapterDnsServers(base({ dnsManaged: false, dnsRemote: ['9.9.9.9', 'https://1.1.1.1/dns-query', '8.8.8.8'] }), '10.255.0.1'), ['9.9.9.9', '8.8.8.8']);
  assert.deepEqual(adapterDnsServers(base({ dnsManaged: false, dnsRemote: ['https://1.1.1.1/dns-query'] }), '10.255.0.1'), ['1.1.1.1', '8.8.8.8'], 'URLs cannot be adapter DNS — fall back');
});

test('isDohUrl', () => {
  assert.equal(isDohUrl('https://1.1.1.1/dns-query'), true);
  assert.equal(isDohUrl('https+local://dns.google/dns-query'), true);
  assert.equal(isDohUrl('1.1.1.1'), false);
  assert.equal(isDohUrl('tcp://1.1.1.1'), false);
});
