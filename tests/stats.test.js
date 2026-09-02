'use strict';
/**
 * The traffic meter reads Xray's /debug/vars. The pool and advanced plans have
 * no outbound called 'proxy' — they tag exits 'out-<serverId>' — which is why
 * the old fixed-name query reported 0 B/s in exactly those modes.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { sumOutbounds } = require('../src/main/stats');

const vars = (outbound) => ({ stats: { outbound } });

test('sums every proxying outbound, whatever its tag', () => {
  assert.deepEqual(sumOutbounds(vars({
    'out-sv-a': { uplink: 100, downlink: 900 },
    'out-chain-c1': { uplink: 5, downlink: 50 },
    'out-chain-c1-h0': { uplink: 7, downlink: 70 }
  })), { up: 112, down: 1020 });
});

test('single-server and chain plans still work (tag "proxy")', () => {
  assert.deepEqual(sumOutbounds(vars({ proxy: { uplink: 10, downlink: 20 } })), { up: 10, down: 20 });
});

test('direct, block, dns and the DPI dialers are not proxied traffic', () => {
  assert.deepEqual(sumOutbounds(vars({
    proxy: { uplink: 10, downlink: 20 },
    direct: { uplink: 1000, downlink: 2000 },
    block: { uplink: 1, downlink: 2 },
    'dns-out': { uplink: 3, downlink: 4 },
    'dpi-1': { uplink: 5, downlink: 6 }
  })), { up: 10, down: 20 });
});

test('missing or malformed payloads read as zero, never NaN', () => {
  for (const v of [null, undefined, {}, { stats: {} }, { stats: { outbound: null } }, 'nonsense']) {
    assert.deepEqual(sumOutbounds(v), { up: 0, down: 0 }, JSON.stringify(v));
  }
  assert.deepEqual(sumOutbounds(vars({ proxy: { uplink: 'x' } })), { up: 0, down: 0 });
});
