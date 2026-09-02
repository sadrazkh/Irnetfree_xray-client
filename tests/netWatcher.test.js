'use strict';
/**
 * The watcher must fire ONCE per settled network change. A flapping adapter that
 * changes three times in a second must not trigger three tunnel rebuilds — each
 * rebuild tears the tunnel down and back up.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { NetWatcher, fingerprint } = require('../src/main/netWatcher');

const wifi = { 'Wi-Fi': [{ family: 'IPv4', internal: false, address: '192.168.1.20' }] };
const wifi2 = { 'Wi-Fi': [{ family: 'IPv4', internal: false, address: '192.168.1.99' }] };
const eth = { Ethernet: [{ family: 'IPv4', internal: false, address: '10.0.0.5' }] };

/** A watcher whose clock is a queue of callbacks this test fires by hand. */
function harness(reads) {
  const fired = [];
  let tick = null;
  let i = 0;
  const w = new NetWatcher({
    read: () => reads[Math.min(i, reads.length - 1)],
    onChange: (why) => fired.push(why),
    debounceMs: 2500,
    intervalMs: 3000,
    setTimer: (fn) => { tick = fn; return 'timer'; },
    clearTimer: () => { tick = null; }
  });
  return {
    w, fired,
    advance: (n = 1) => { i = Math.min(i + n, reads.length - 1); },
    tick: () => tick && tick(),
    running: () => tick !== null
  };
}

test('fingerprint ignores interface order, internal and loopback addresses', () => {
  const a = { A: [{ family: 'IPv4', internal: false, address: '1.1.1.1' }], B: [{ family: 'IPv6', internal: false, address: 'fe80::1' }] };
  const b = { B: [{ family: 'IPv6', internal: false, address: 'fe80::1' }], A: [{ family: 'IPv4', internal: false, address: '1.1.1.1' }] };
  assert.equal(fingerprint(a), fingerprint(b), 'order must not matter');
  const withLoopback = Object.assign({ lo: [{ family: 'IPv4', internal: true, address: '127.0.0.1' }] }, a);
  assert.equal(fingerprint(withLoopback), fingerprint(a), 'internal addresses must not matter');
  assert.notEqual(fingerprint(a), fingerprint(eth));
  assert.equal(fingerprint(null), fingerprint({}), 'a missing read is just "no addresses"');
});

test('a settled change fires once, after the debounce', () => {
  const h = harness([wifi, eth]);
  h.w.start();
  h.tick();                       // first poll only records the baseline
  assert.deepEqual(h.fired, []);
  h.advance();                    // network switched
  h.tick();                       // change seen — debounce starts, nothing fired yet
  assert.deepEqual(h.fired, []);
  h.tick();                       // still the same fingerprint → debounce elapses
  assert.deepEqual(h.fired, ['interfaces']);
  h.tick();                       // nothing new
  assert.deepEqual(h.fired, ['interfaces']);
});

test('a flapping adapter fires once, not once per change', () => {
  const h = harness([wifi, eth, wifi2, eth]);
  h.w.start();
  h.tick();
  h.advance(); h.tick();          // change 1
  h.advance(); h.tick();          // change 2 — restarts the debounce
  h.advance(); h.tick();          // change 3 — restarts again
  assert.deepEqual(h.fired, [], 'must not fire while it is still moving');
  h.tick();                       // settled
  assert.deepEqual(h.fired, ['interfaces']);
});

test('poke() delivers an external signal immediately and only when running', () => {
  const h = harness([wifi]);
  h.w.poke('resume');
  assert.deepEqual(h.fired, [], 'a stopped watcher must stay silent');
  h.w.start();
  h.w.poke('resume');
  assert.deepEqual(h.fired, ['resume']);
});

test('a change during an in-flight recovery is suppressed, not queued up', async () => {
  let release;
  const fired = [];
  let tick = null, i = 0;
  const reads = [wifi, eth, wifi2];
  const w = new NetWatcher({
    read: () => reads[Math.min(i, reads.length - 1)],
    onChange: (why) => { fired.push(why); return new Promise((r) => { release = r; }); },
    debounceMs: 0, intervalMs: 3000,
    setTimer: (fn) => { tick = fn; return 't'; }, clearTimer: () => { tick = null; }
  });
  w.start();
  tick();
  i = 1; tick(); tick();
  assert.deepEqual(fired, ['interfaces']);
  assert.equal(w.busy, true);
  i = 2; tick(); tick();
  assert.deepEqual(fired, ['interfaces'], 'no second call while the first is running');
  release();
  await Promise.resolve(); await Promise.resolve();
  assert.equal(w.busy, false);
});

test('stop() clears the timer and start() is idempotent', () => {
  const h = harness([wifi]);
  h.w.start();
  h.w.start();
  assert.equal(h.running(), true);
  h.w.stop();
  assert.equal(h.running(), false);
  h.tick();                        // no-op, nothing should throw
  assert.deepEqual(h.fired, []);
});
