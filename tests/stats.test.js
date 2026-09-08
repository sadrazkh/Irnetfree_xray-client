'use strict';
/**
 * The traffic meter reads Xray's /debug/vars. The pool and advanced plans have
 * no outbound called 'proxy' — they tag exits 'out-<serverId>' — which is why
 * the old fixed-name query reported 0 B/s in exactly those modes.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { sumOutbounds, SilenceWatch, byOutbound, StatsPoller } = require('../src/main/stats');

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

/* ---------------- per-outbound figures (the home traffic path) ---------------- */

test('byOutbound keeps each proxying tag apart and drops the rest', () => {
  assert.deepEqual(byOutbound(vars({
    'out-sv-a': { uplink: 100, downlink: 900 },
    'out-chain-c1': { uplink: 5, downlink: 50 },
    direct: { uplink: 7, downlink: 70 },
    block: { uplink: 1, downlink: 0 },
    'dns-out': { uplink: 2, downlink: 3 },
    'dpi-1': { uplink: 4, downlink: 4 }
  })), {
    'out-sv-a': { up: 100, down: 900 },
    'out-chain-c1': { up: 5, down: 50 },
    // direct is not "the proxy", but the path diagram still has to show what
    // went past the tunnel — so it is reported, just not summed
    direct: { up: 7, down: 70 }
  });
});

test('byOutbound survives a body with no outbound section', () => {
  assert.deepEqual(byOutbound({}), {});
  assert.deepEqual(byOutbound(vars({})), {});
  assert.deepEqual(byOutbound(vars({ 'out-x': {} })), { 'out-x': { up: 0, down: 0 } });
});

/* --------------------------- cadence --------------------------- */

test('retime changes the cadence and keeps the baseline (no phantom speed spike)', async () => {
  // The window goes to the tray: polling drops to every five seconds. The
  // bytes that arrived meanwhile must read as a rate over the MEASURED gap,
  // never as a burst over a reset baseline.
  const seen = [];
  const p = new StatsPoller({ onStats: (s) => seen.push(s) });
  let up = 1000;
  p.query = async () => ({ up, down: 0, per: {} });
  p.start(10);
  await new Promise(r => setTimeout(r, 35));
  assert.ok(seen.length >= 1, 'polled at the fast cadence');
  up = 2000;
  p.retime(30);
  assert.equal(p.intervalMs, 30);
  const before = seen.length;
  await new Promise(r => setTimeout(r, 50));
  p.stop();
  assert.ok(seen.length > before, 'polled at the slow cadence');
  const last = seen[seen.length - 1];
  assert.equal(last.totalUp, 2000);
  // 1000 new bytes over at least the slow gap: far below what a reset baseline would report
  assert.ok(last.upSpeed > 0 && last.upSpeed <= 1000 / 0.03, 'speed against the kept baseline: ' + last.upSpeed);
  assert.equal(p.timer, null, 'stopped');
});

test('retime before start() only records the cadence; the same value is a no-op', () => {
  const p = new StatsPoller({});
  p.retime(5000);
  assert.equal(p.intervalMs, 5000);
  assert.equal(p.timer, null);
  p.retime(5000);
  p.retime(0);
  assert.equal(p.intervalMs, 5000);
});
