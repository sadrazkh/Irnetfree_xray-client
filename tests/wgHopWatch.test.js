'use strict';
// A WireGuard dropped by the config it goes through: the core says only
// `proxy/wireguard: unexpected closed > io: read/write on closed pipe` (seen with
// a WARP through a config whose REALITY failed) — the app names both, once.
const test = require('node:test');
const assert = require('node:assert/strict');
const { wgRides, WgHopWatch } = require('../src/main/stats');

const rec = (id, name, protocol = 'vless') => ({ id, name, protocol });
const WARP = rec('w1', '☁ WARP', 'wireguard');
const CORP = rec('wg2', 'cobra', 'wireguard');
const UK = rec('s1', 'UK 2');
const NL = rec('s2', 'NL');
const GRP = rec('grp-a', 'Irancell UK', 'group');
const serversById = { w1: WARP, wg2: CORP, s1: UK, s2: NL, 'grp-a': GRP };
const CORE_LINE = '2026/10/20 00:04:20.918645 [Error] proxy/wireguard: unexpected closed > io: read/write on closed pipe';

test('wgRides: a rule’s WireGuard through its via, the base for inherit, nothing for none; a chain’s through the member before it', () => {
  const plan = {
    mode: 'advanced', serversById, base: 'grp-a',
    chainsById: { c1: [NL, WARP], c2: [WARP, UK] },
    rules: [
      { target: 'w1', via: 's1' },
      { target: 'wg2', via: 'inherit' },
      { target: 'wg2', via: 'none' },
      { target: 'chain:c1', via: 'none' },
      { target: 'chain:c2', via: 'none' },
      { target: 's2', via: 's1' }
    ],
    def: 'base', defVia: 'inherit'
  };
  assert.deepEqual(wgRides(plan), [
    { wg: '☁ WARP', hop: 'UK 2' },
    { wg: 'cobra', hop: 'Irancell UK' },
    { wg: '☁ WARP', hop: 'NL' }
  ], 'a WireGuard dialled straight (via none, a chain’s first) and a non-WireGuard are not there; each pair once');
  assert.deepEqual(wgRides({ mode: 'advanced', serversById, base: null, chainsById: {}, rules: [{ target: 'w1' }], def: 'direct' }), [], 'no base: dialled straight');
  assert.deepEqual(wgRides({ mode: 'chain', chain: [UK, WARP] }), [{ wg: '☁ WARP', hop: 'UK 2' }]);
  assert.deepEqual(wgRides({ mode: 'single', server: WARP }), []);
  assert.deepEqual(wgRides(null), []);
});

test('WgHopWatch: the core’s nameless line becomes one that names the WireGuard and its config — once a connection, nothing without a ride', () => {
  const w = new WgHopWatch();
  assert.equal(w.onLine(CORE_LINE, 'en'), null, 'before a connect: nothing to name');
  w.reset({ mode: 'advanced', serversById, base: null, chainsById: {}, rules: [{ target: 'w1', via: 's1' }], def: 'direct' });
  assert.equal(w.onLine('[Error] transport/internet/reality: REALITY: received real certificate', 'en'), null, 'other lines: nothing');
  const en = w.onLine(CORE_LINE, 'en');
  assert.equal(en.level, 'warn');
  assert.match(en.line, /^WireGuard “☁ WARP”: the config it goes through \(“UK 2”\) closed on it/);
  assert.equal(w.onLine(CORE_LINE, 'en'), null, 'once');
  w.reset({ mode: 'chain', chain: [UK, WARP] });
  assert.match(w.onLine(CORE_LINE, 'fa').line, /^وایرگارد «☁ WARP»: کانفیگی که از آن رد می‌شود \(«UK 2»\)/, 'again after a connect, in Persian');
  // two WireGuards that ride: both named, since the core does not say which
  w.reset({ mode: 'advanced', serversById, base: 'grp-a', chainsById: {}, rules: [{ target: 'w1', via: 's1' }, { target: 'wg2', via: 'inherit' }], def: 'base', defVia: 'inherit' });
  assert.match(w.onLine(CORE_LINE, 'en').line, /^A WireGuard lost the config it goes through \(“☁ WARP” through “UK 2”, “cobra” through “Irancell UK”\)/);
  // a plan whose WireGuard is dialled straight: the core's line is left as it is
  w.reset({ mode: 'single', server: WARP });
  assert.equal(w.onLine(CORE_LINE, 'en'), null);
});
