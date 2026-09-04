'use strict';
/**
 * The traffic meter reads Xray's /debug/vars. The pool and advanced plans have
 * no outbound called 'proxy' — they tag exits 'out-<serverId>' — which is why
 * the old fixed-name query reported 0 B/s in exactly those modes.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { sumOutbounds, SilenceWatch } = require('../src/main/stats');

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

/* ------------------- a tunnel that sends and is never answered ------------------- */

test('SilenceWatch names an outbound that has sent and heard nothing back', () => {
  // A WireGuard whose handshake never completes looks exactly like this: the
  // core keeps writing handshake initiations, and the downlink stays at zero.
  // Nothing else in the app can see it — the core only says so at debug level.
  const w = new SilenceWatch(['out-wg'], { minUp: 1000, ticks: 2 });
  assert.deepEqual(w.check(vars({ 'out-wg': { uplink: 200, downlink: 0 } })), [], 'too little sent to judge');
  assert.deepEqual(w.check(vars({ 'out-wg': { uplink: 2000, downlink: 0 } })), [], 'one tick is not enough');
  assert.deepEqual(w.check(vars({ 'out-wg': { uplink: 3000, downlink: 0 } })), ['out-wg']);
  assert.deepEqual(w.check(vars({ 'out-wg': { uplink: 4000, downlink: 0 } })), [], 'reported once, not every tick');
});

test('SilenceWatch stays quiet for a tunnel that answers', () => {
  const w = new SilenceWatch(['out-wg'], { minUp: 1000, ticks: 2 });
  for (let i = 0; i < 5; i++) {
    assert.deepEqual(w.check(vars({ 'out-wg': { uplink: 2000 * (i + 1), downlink: 1 } })), []);
  }
});

test('SilenceWatch forgets a run of silence as soon as one answer arrives', () => {
  const w = new SilenceWatch(['out-wg'], { minUp: 1000, ticks: 3 });
  w.check(vars({ 'out-wg': { uplink: 2000, downlink: 0 } }));
  w.check(vars({ 'out-wg': { uplink: 3000, downlink: 0 } }));
  assert.deepEqual(w.check(vars({ 'out-wg': { uplink: 4000, downlink: 12 } })), []);
  assert.deepEqual(w.check(vars({ 'out-wg': { uplink: 5000, downlink: 12 } })), [], 'the counter restarted');
});

test('SilenceWatch ignores outbounds it was not asked about, and a missing one', () => {
  const w = new SilenceWatch(['out-wg'], { minUp: 10, ticks: 1 });
  assert.deepEqual(w.check(vars({ 'out-other': { uplink: 9999, downlink: 0 } })), []);
  assert.deepEqual(w.check(vars({})), []);
  assert.deepEqual(new SilenceWatch([], {}).check(vars({ 'out-wg': { uplink: 9999, downlink: 0 } })), []);
});
