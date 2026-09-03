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
  // nonIPQuery is pinned: older cores default to "skip", which forwards
  // PTR/SRV/TXT queries to their original destination — under TUN that is the
  // tunnel peer, so the packet would loop straight back into the hijack.
  assert.deepEqual(p.hijackOutbound, { tag: 'dns-out', protocol: 'dns', settings: { nonIPQuery: 'reject' } });
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

test('a host:port entry becomes the {address, port} object the core accepts', () => {
  // 26.3.27 refuses "178.22.122.100:5353" as a server string ("first path
  // segment in URL cannot contain colon"); the object form is accepted.
  const p = buildDnsPlan(base({ routingMode: 'bypass-ir', dnsDirect: ['178.22.122.100:5353'], dnsRemote: ['1.1.1.1:5353', 'https://8.8.8.8/dns-query'] }), opts());
  assert.deepEqual(p.dns.servers[0], {
    address: '178.22.122.100', port: 5353,
    domains: ['geosite:category-ir', 'regexp:.*\\.ir$'], expectedIPs: ['geoip:ir'], skipFallback: true
  });
  assert.deepEqual(p.dns.servers[1], { address: '1.1.1.1', port: 5353 });
  assert.equal(p.dns.servers[2], 'https://8.8.8.8/dns-query');
  assert.deepEqual(p.directResolverIps, ['178.22.122.100']);
});

test('IPv6 entries: bracketed host:port is split, a bare address is left alone and gets its direct rule', () => {
  const p = buildDnsPlan(base({ routingMode: 'bypass-ir', ipv6: true, dnsDirect: ['2a00:1450::1'], dnsRemote: ['[2001:4860:4860::8888]:5353'] }), opts());
  assert.equal(p.dns.servers[0].address, '2a00:1450::1');
  assert.deepEqual(p.dns.servers[1], { address: '2001:4860:4860::8888', port: 5353 });
  assert.deepEqual(p.directResolverIps, ['2a00:1450::1']);
  assert.deepEqual(p.rules[0], { type: 'field', inboundTag: ['dns-internal'], ip: ['2a00:1450::1'], outboundTag: 'direct' });
});

test('a private-range remote resolver is dialled direct: a LAN resolver is not reachable through the proxy', () => {
  const p = buildDnsPlan(base({ dnsRemote: ['192.168.1.1', 'https://1.1.1.1/dns-query'] }), opts());
  assert.deepEqual(p.dns.servers, ['192.168.1.1', 'https://1.1.1.1/dns-query']);
  assert.deepEqual(p.rules[0], { type: 'field', inboundTag: ['dns-internal'], ip: ['192.168.1.1'], outboundTag: 'direct' });
  assert.deepEqual(p.directResolverIps, ['192.168.1.1']);
  // a public remote resolver is NOT in that list — it must ride the exit
  assert.deepEqual(buildDnsPlan(base(), opts()).directResolverIps, []);
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

/* ----------------------------- target resolvers ----------------------------- */

// A corporate WireGuard names a resolver only its tunnel can reach. The core
// must ask that resolver THROUGH the target outbound — and only for the names
// the public resolver cannot answer, so browsing history never leaves for the
// company and public names never crawl through the chain.
const CORP = { address: '192.168.60.1', outboundTag: 'out-chain-c1', expectedIPs: ['192.168.0.0/16', '10.0.0.0/8'], domains: ['domain:tes.systems'] };

test('target resolver: appended after the remote list, as a fallback the public NXDOMAIN falls through to', () => {
  const p = buildDnsPlan(base(), opts({ targetResolvers: [CORP] }));
  assert.deepEqual(p.dns.servers, [
    'https://1.1.1.1/dns-query',
    'https://8.8.8.8/dns-query',
    { address: '192.168.60.1', domains: ['domain:tes.systems'], expectedIPs: ['192.168.0.0/16', '10.0.0.0/8'] }
  ]);
  // No skipFallback: the in-country resolver gets it because it must never be
  // asked about the rest of the world; the corporate one is the other way
  // round — it must remain a fallback for every name the public resolver does
  // not know, or an internal name without a search domain is never resolved.
  assert.equal('skipFallback' in p.dns.servers[2], false);
});

test('target resolver: its query leaves through the target, after the direct rule and before the exit rule', () => {
  const p = buildDnsPlan(base({ routingMode: 'bypass-ir' }), opts({ targetResolvers: [CORP] }));
  assert.deepEqual(p.rules, [
    { type: 'field', inboundTag: ['dns-internal'], ip: ['178.22.122.100', '185.51.200.2'], outboundTag: 'direct' },
    { type: 'field', inboundTag: ['dns-internal'], ip: ['192.168.60.1'], outboundTag: 'out-chain-c1' },
    { type: 'field', inboundTag: ['dns-internal'], outboundTag: 'proxy' },
    { type: 'field', port: '53', network: 'tcp,udp', outboundTag: 'dns-out' }
  ]);
});

test('target resolver: empty expectedIPs / domains leave no keys behind', () => {
  const p = buildDnsPlan(base(), opts({ targetResolvers: [{ address: '192.168.60.1', outboundTag: 'out-sv-wg', expectedIPs: [], domains: [] }] }));
  assert.deepEqual(p.dns.servers.at(-1), { address: '192.168.60.1' });
  const bare = buildDnsPlan(base(), opts({ targetResolvers: [{ address: '192.168.60.1', outboundTag: 'out-sv-wg' }] }));
  assert.deepEqual(bare.dns.servers.at(-1), { address: '192.168.60.1' });
});

test('target resolver: never dialled direct, even though it is a private-range address', () => {
  // The private-range rule for the REMOTE list must not catch it: it is
  // reachable through the target, not off the tunnel.
  const p = buildDnsPlan(base(), opts({ targetResolvers: [CORP] }));
  assert.deepEqual(p.directResolverIps, []);
  assert.equal(p.rules.some(r => r.outboundTag === 'direct'), false);
  // and a LAN resolver in the remote list still goes direct on its own
  const both = buildDnsPlan(base({ dnsRemote: ['192.168.1.1', 'https://1.1.1.1/dns-query'] }), opts({ targetResolvers: [CORP] }));
  assert.deepEqual(both.directResolverIps, ['192.168.1.1']);
  assert.deepEqual(both.rules[0], { type: 'field', inboundTag: ['dns-internal'], ip: ['192.168.1.1'], outboundTag: 'direct' });
  assert.deepEqual(both.rules[1], { type: 'field', inboundTag: ['dns-internal'], ip: ['192.168.60.1'], outboundTag: 'out-chain-c1' });
});

test('target resolver: ip:port becomes the object form and the rule uses the bare ip; a hostname gets no rule', () => {
  const p = buildDnsPlan(base(), opts({ targetResolvers: [{ address: '192.168.60.1:5353', outboundTag: 'out-sv-wg', expectedIPs: ['10.0.0.0/8'] }] }));
  assert.deepEqual(p.dns.servers.at(-1), { address: '192.168.60.1', port: 5353, expectedIPs: ['10.0.0.0/8'] });
  assert.deepEqual(p.rules[0], { type: 'field', inboundTag: ['dns-internal'], ip: ['192.168.60.1'], outboundTag: 'out-sv-wg' });

  const host = buildDnsPlan(base(), opts({ targetResolvers: [{ address: 'https://dns.corp.example/dns-query', outboundTag: 'out-sv-wg' }] }));
  assert.deepEqual(host.dns.servers.at(-1), { address: 'https://dns.corp.example/dns-query' });
  // nothing to route by ip: the query rides the exit like any other
  assert.deepEqual(host.rules, [
    { type: 'field', inboundTag: ['dns-internal'], outboundTag: 'proxy' },
    { type: 'field', port: '53', network: 'tcp,udp', outboundTag: 'dns-out' }
  ]);
});

test('target resolver: two entries with one ip → one rule (first target wins), both servers kept', () => {
  // The servers may differ in domains / expectedIPs, so both stay; the routing
  // decision for that ip can only be one outbound.
  const p = buildDnsPlan(base(), opts({ targetResolvers: [
    { address: '192.168.60.1', outboundTag: 'out-chain-c1', domains: ['domain:tes.systems'] },
    { address: '192.168.60.1', outboundTag: 'out-sv-wg', domains: ['domain:hawk.local'] }
  ] }));
  assert.equal(p.dns.servers.length, 4);
  assert.deepEqual(p.rules.filter(r => r.ip), [
    { type: 'field', inboundTag: ['dns-internal'], ip: ['192.168.60.1'], outboundTag: 'out-chain-c1' }
  ]);
});

test('target resolver: ignored when DNS is unmanaged — the legacy path is the user’s list verbatim', () => {
  const p = buildDnsPlan(base({ dnsManaged: false, dnsRemote: ['9.9.9.9'] }), opts({ targetResolvers: [CORP] }));
  assert.deepEqual(p.dns, { queryStrategy: 'UseIPv4', servers: ['9.9.9.9'] });
  assert.deepEqual(p.rules, []);
});

/* ----------------------------- the TUN adapter ----------------------------- */

test('adapterDnsServers: the tunnel peer when the core hijacks, the plain list when it cannot', () => {
  assert.deepEqual(adapterDnsServers(base(), '10.255.0.1'), ['10.255.0.1']);
  // no hijack target (a sing-box-format config carries no dns-out): managed
  // or not, the adapter needs a resolver the proxy can actually reach
  assert.deepEqual(adapterDnsServers(base(), null), ['1.1.1.1', '8.8.8.8']);
  assert.deepEqual(adapterDnsServers(base({ dnsRemote: ['9.9.9.9', 'https://1.1.1.1/dns-query'] }), null), ['9.9.9.9']);
  assert.deepEqual(adapterDnsServers(base({ dnsManaged: false, dnsRemote: ['9.9.9.9'] }), '10.255.0.1'), ['9.9.9.9']);
});

test('adapterDnsServers: a host:port entry cannot be an adapter resolver and is skipped', () => {
  assert.deepEqual(adapterDnsServers(base({ dnsManaged: false, dnsRemote: ['1.1.1.1:5353', '9.9.9.9'] }), '10.255.0.1'), ['9.9.9.9']);
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
