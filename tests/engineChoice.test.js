'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { chooseEngine, planServers, testEngineFor, needsWgEndpointIp } = require('../src/main/engineChoice');

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

test('only the patterniha fork needs the WireGuard endpoint pre-resolved', () => {
  // The official core resolves a peer endpoint NAME through its own (DoH)
  // resolver. Substituting an address there would replace a censorship-resistant
  // lookup with whatever the machine's own resolver says — the one thing this
  // app exists to avoid. The fork does not resolve it at all, so it gets one.
  assert.equal(needsWgEndpointIp('xray-pattn'), true);
  assert.equal(needsWgEndpointIp('xray'), false);
  assert.equal(needsWgEndpointIp('sing-box'), false);
  assert.equal(needsWgEndpointIp(undefined), false);
});
