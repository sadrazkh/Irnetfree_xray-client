'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { chooseEngine, planServers, testEngineFor } = require('../src/main/engineChoice');

const S = (id, engine) => Object.assign({ id, outbound: { protocol: 'vless' } }, engine ? { engine } : {});
const a = S('a'), b = S('b'), p = S('p', 'xray-pattn'), sb = S('sb', 'sing-box');
const byId = { a, b, p, sb };

test('single: the server’s own engine, else the default', () => {
  assert.equal(chooseEngine({ mode: 'single', server: p }), 'xray-pattn');
  assert.equal(chooseEngine({ mode: 'single', server: sb }), 'sing-box');
  assert.equal(chooseEngine({ mode: 'single', server: a }), 'xray');
  assert.equal(chooseEngine({ mode: 'single', server: a }, 'xray-pattn'), 'xray-pattn');
});

test('chain: PattN if any hop wants it, else the default', () => {
  assert.equal(chooseEngine({ mode: 'chain', chain: [a, b] }), 'xray');
  assert.equal(chooseEngine({ mode: 'chain', chain: [a, p] }), 'xray-pattn');
  assert.equal(chooseEngine({ mode: 'chain', chain: [a, sb] }), 'xray', 'sing-box is single-config only');
  assert.equal(chooseEngine({ mode: 'chain', chain: [a, b] }, 'xray-pattn'), 'xray-pattn');
});

test('pool / advanced: looks through targets, chain: targets and the default target', () => {
  const chainsById = { c1: [a, p], c2: [a, b] };
  assert.equal(chooseEngine({ mode: 'pool', entries: [{ target: 'a' }, { target: 'chain:c2' }], serversById: byId, chainsById }), 'xray');
  assert.equal(chooseEngine({ mode: 'pool', entries: [{ target: 'chain:c1' }], serversById: byId, chainsById }), 'xray-pattn');
  assert.equal(chooseEngine({ mode: 'advanced', rules: [{ target: 'direct' }, { target: 'a' }], def: 'p', serversById: byId, chainsById }), 'xray-pattn');
  assert.equal(chooseEngine({ mode: 'advanced', rules: [{ target: 'block' }], def: 'direct', serversById: byId, chainsById }), 'xray');
  assert.equal(chooseEngine({ mode: 'advanced', rules: [null, { target: 'chain' }], def: 'a', serversById: byId, chainsById, chain: [p, a] }), 'xray-pattn', 'legacy chain target');
});

test('planServers lists every server a plan can dial', () => {
  assert.deepEqual(planServers({ mode: 'advanced', rules: [{ target: 'a' }], def: 'chain:c1', serversById: byId, chainsById: { c1: [a, p] } }).map(s => s.id), ['a', 'a', 'p']);
});

test('latency tests never run on sing-box', () => {
  assert.equal(testEngineFor('sing-box'), 'xray');
  assert.equal(testEngineFor('xray-pattn'), 'xray-pattn');
  assert.equal(testEngineFor(undefined), 'xray');
});

/* --------- who has to be handed a WireGuard endpoint as an address --------- */

test('every core is handed a WireGuard endpoint as an address: the gate is gone', () => {
  // Until v1.7.3 only the patterniha fork got one; the official core was left to
  // resolve the name itself, and when that lookup failed — the exit down, DoH
  // unreachable, or the plan's corporate resolver asked for the endpoint of the
  // tunnel that reaches it — proxy/wireguard panicked and the whole core died.
  // The decision now lives in main.js/service.js (withWgEndpointIps, through
  // trustedDns); nothing here may bring the per-engine gate back.
  assert.equal('needsWgEndpointIp' in require('../src/main/engineChoice'), false);
});

test('a Hysteria2 that asked for insecure and names no certificate runs on sing-box, unless the record chose a core', () => {
  const { chooseEngine, needsInsecureCore } = require('../src/main/engineChoice');
  const { parseLink } = require('../src/main/parser');
  const hy = parseLink('hysteria2://pw@h.example.com:443?insecure=1');
  assert.equal(needsInsecureCore(hy), true);
  assert.equal(chooseEngine({ mode: 'single', server: hy }), 'sing-box');
  assert.equal(chooseEngine({ mode: 'single', server: Object.assign({}, hy, { engine: 'xray-pattn' }) }), 'xray-pattn');
  for (const ok of [
    parseLink('hysteria2://pw@h.example.com:443'),
    parseLink('hysteria2://pw@h.example.com:443?insecure=1&pinSHA256=' + 'ab'.repeat(32)),
    Object.assign(parseLink('hysteria2://pw@h.example.com:443?insecure=1'), { certPin: 'cd'.repeat(32) }),
    parseLink('trojan://pw@a.example.com:443?allowInsecure=1')
  ]) {
    assert.equal(needsInsecureCore(ok), false);
    assert.equal(chooseEngine({ mode: 'single', server: ok }), 'xray');
  }
  // a chain is Xray's whatever its members are
  assert.equal(chooseEngine({ mode: 'chain', chain: [hy, hy] }), 'xray');
});
