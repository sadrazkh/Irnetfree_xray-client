'use strict';
/**
 * The legacy tun2socks backend. Its start/stop paths shell out to route/netsh
 * and are exercised by hand; what is pinned here is the surface main.js and
 * service.js rely on when the two backends are swapped.
 */
const test = require('node:test');
const assert = require('node:assert/strict');

const { TunManager, TUN_GW } = require('../src/main/tunManager');
const { TunSingbox } = require('../src/main/tunSingbox');

test('excludeIps mirrors the bypass routes it laid, as a copy (the sing-box backend has the same name)', () => {
  const tun = new TunManager({ extraDirs: [], onLog: () => {} });
  assert.deepEqual(tun.excludeIps, []);
  // the array the backend keeps for cleanup is the source of truth …
  tun.bypassIps.push('1.2.3.4', '5.6.7.8');
  assert.deepEqual(tun.excludeIps, ['1.2.3.4', '5.6.7.8']);
  // … and a caller cannot reach into it through the getter
  tun.excludeIps.push('9.9.9.9');
  assert.deepEqual(tun.bypassIps, ['1.2.3.4', '5.6.7.8']);
  assert.deepEqual(tun.excludeIps, ['1.2.3.4', '5.6.7.8']);
});

test('the surface the connect path swaps against sing-box', () => {
  const tun = new TunManager({ extraDirs: [], onLog: () => {}, lang: 'en' });
  assert.equal(tun.active, false);
  assert.equal(tun.dnsPeer, undefined, 'no peer of its own: the caller falls back to TUN_GW');
  assert.equal(TUN_GW, '10.255.0.1');
  // doConnect() calls every one of these on whichever backend makeTun picked;
  // a missing one is a TUN-mode connect that throws instead of connecting
  // (physicalInterface was exactly that bug).
  for (const m of ['isAvailable', 'isElevated', 'start', 'stop', 'cleanupSync', 'physicalInterface']) {
    assert.equal(typeof tun[m], 'function', m);
  }
});

// The two backends are swapped by makeTun() behind one variable, so the connect
// path may only use what BOTH provide.
test('both backends answer everything the connect path asks of them', () => {
  const legacy = new TunManager({ extraDirs: [], onLog: () => {} });
  const singbox = new TunSingbox({ extraDirs: [], onLog: () => {} });
  for (const m of ['isAvailable', 'isElevated', 'start', 'stop', 'cleanupSync', 'physicalInterface']) {
    assert.equal(typeof legacy[m], 'function', 'tun2socks.' + m);
    assert.equal(typeof singbox[m], 'function', 'sing-box.' + m);
  }
  assert.deepEqual(legacy.excludeIps, []);
  assert.deepEqual(singbox.excludeIps, []);
});
