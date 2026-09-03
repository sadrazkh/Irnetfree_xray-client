'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { buildSingboxConfig } = require('../src/main/singboxBuilder');
const { VLESS_WS_TLS } = require('./fixtures');

test('a DoH remote resolver becomes an https DNS server', () => {
  const c = buildSingboxConfig(VLESS_WS_TLS, { dnsRemote: ['https://1.1.1.1/dns-query'] });
  assert.deepEqual(c.dns.servers[0], { type: 'https', tag: 'dns-direct', server: '1.1.1.1', path: '/dns-query' });
  assert.equal(c.dns.final, 'dns-direct');
});

test('a plain IP stays udp; the legacy dns list still works; nothing → 1.1.1.1', () => {
  assert.deepEqual(buildSingboxConfig(VLESS_WS_TLS, { dnsRemote: ['9.9.9.9'] }).dns.servers[0], { type: 'udp', tag: 'dns-direct', server: '9.9.9.9' });
  assert.equal(buildSingboxConfig(VLESS_WS_TLS, { dns: ['8.8.8.8'] }).dns.servers[0].server, '8.8.8.8');
  assert.equal(buildSingboxConfig(VLESS_WS_TLS, {}).dns.servers[0].server, '1.1.1.1');
});
