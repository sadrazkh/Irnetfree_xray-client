'use strict';
/**
 * A resolver that does not believe the network. Both lookups are injected, so
 * nothing here touches DNS or the wire: the OS answer and the DoH answer are
 * scripted, and what is pinned is which one wins and why.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { resolveHost, isSuspect, DEFAULT_DOH } = require('../src/main/trustedDns');

const os = (answers) => async () => { if (answers instanceof Error) throw answers; return answers; };
const doh = (table) => async (url, host, type) => (table[`${host}/${type}`] || []);

test('isSuspect: the ranges no public server can be in, and nothing else', () => {
  for (const ip of ['198.18.175.48', '198.19.0.1', '192.168.10.1', '10.0.0.1', '172.16.5.5', '127.0.0.1', '0.0.0.0', '169.254.1.1', '100.64.0.1', '224.0.0.1', '192.0.2.1']) {
    assert.equal(isSuspect(ip), true, ip);
  }
  for (const ip of ['51.222.52.23', '3.11.139.9', '1.1.1.1', '198.17.255.255', '198.20.0.1', '8.8.8.8']) {
    assert.equal(isSuspect(ip), false, ip);
  }
  for (const ip of ['fc00::1a0:73dc:65f', 'fd12::1', 'fe80::1', '::1', '::', '2001:db8::1']) assert.equal(isSuspect(ip), true, ip);
  for (const ip of ['2606:4700::1111', '2a01:5ec0::1']) assert.equal(isSuspect(ip), false, ip);
  assert.equal(isSuspect('not-an-ip'), true);
  assert.equal(isSuspect(''), true);
});

test('a literal address is returned as it is, without any lookup', async () => {
  let asked = 0;
  const r = await resolveHost('51.222.52.23', { lookup: async () => { asked++; return []; }, query: async () => { asked++; return []; } });
  assert.deepEqual(r, { ips: ['51.222.52.23'], source: 'literal', suspect: [] });
  assert.equal(asked, 0);
});

test('a sane OS answer wins and DoH is never asked', async () => {
  let dohAsked = 0;
  const r = await resolveHost('cobra.tes.ca', { lookup: os(['51.222.52.23']), query: async () => { dohAsked++; return []; } });
  assert.deepEqual(r, { ips: ['51.222.52.23'], source: 'os', suspect: [] });
  assert.equal(dohAsked, 0);
});

test('the fake-IP network: the OS answer is 198.18.x, DoH says otherwise, DoH wins and the fake is reported', async () => {
  // Verbatim from the owner's laptop: every name answered from 198.18.0.0/15
  // with a fc00:: companion by a resolver calling itself irnetfree_help.lan.
  const r = await resolveHost('cobra.tes.ca', {
    lookup: os(['198.18.175.48']),
    query: doh({ 'cobra.tes.ca/A': ['51.222.52.23'] })
  });
  assert.deepEqual(r, { ips: ['51.222.52.23'], source: 'doh', suspect: ['198.18.175.48'] });
});

test('a private answer with no second opinion is kept, and marked: a corporate endpoint may really be on the LAN', async () => {
  const r = await resolveHost('wg.corp.lan', { lookup: os(['10.0.0.5']), query: doh({}) });
  assert.deepEqual(r, { ips: ['10.0.0.5'], source: 'os-suspect', suspect: ['10.0.0.5'] });
});

test('DoH answers that are themselves suspect do not replace the OS answer', async () => {
  const r = await resolveHost('x.example', { lookup: os(['192.168.10.1']), query: doh({ 'x.example/A': ['198.18.1.1'] }) });
  assert.deepEqual(r, { ips: ['192.168.10.1'], source: 'os-suspect', suspect: ['192.168.10.1'] });
});

test('an OS failure falls through to DoH; nothing anywhere is "none"', async () => {
  const r = await resolveHost('cobra.tes.ca', { lookup: os(new Error('ENOTFOUND')), query: doh({ 'cobra.tes.ca/A': ['51.222.52.23'] }) });
  assert.deepEqual(r, { ips: ['51.222.52.23'], source: 'doh', suspect: [] });
  const none = await resolveHost('nowhere.invalid', { lookup: os([]), query: doh({}) });
  assert.deepEqual(none, { ips: [], source: 'none', suspect: [] });
  assert.deepEqual(await resolveHost('', {}), { ips: [], source: 'none', suspect: [] });
});

test('DoH is tried per server in the order given; ipv6 adds AAAA; only https URLs with a literal host count', async () => {
  const asked = [];
  const query = async (url, host, type) => { asked.push(`${url} ${type}`); return url.includes('8.8.8.8') ? ['51.222.52.23'] : []; };
  const r = await resolveHost('cobra.tes.ca', {
    lookup: os(['198.18.175.48']), ipv6: true, query,
    doh: ['https://1.1.1.1/dns-query', 'tcp://1.0.0.1', 'https://8.8.8.8/dns-query']
  });
  assert.equal(r.source, 'doh');
  assert.deepEqual(asked, ['https://1.1.1.1/dns-query A', 'https://1.1.1.1/dns-query AAAA', 'https://8.8.8.8/dns-query A', 'https://8.8.8.8/dns-query AAAA']);
  assert.deepEqual(DEFAULT_DOH, ['https://1.1.1.1/dns-query', 'https://8.8.8.8/dns-query'], 'the defaults name literal addresses on purpose');
});

test('the real DoH query refuses a URL whose host is a name: resolving the resolver would need the resolver', async () => {
  const { dohQuery } = require('../src/main/trustedDns');
  assert.deepEqual(await dohQuery('https://dns.google/dns-query', 'a.example', 'A', 100), []);
  assert.deepEqual(await dohQuery('http://1.1.1.1/dns-query', 'a.example', 'A', 100), []);
  assert.deepEqual(await dohQuery('not a url', 'a.example', 'A', 100), []);
});
