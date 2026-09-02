'use strict';
/**
 * The watcher must fire ONCE per settled network change. A flapping adapter that
 * changes three times in a second must not trigger three tunnel rebuilds — each
 * rebuild tears the tunnel down and back up.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { NetWatcher, fingerprint } = require('../src/main/netWatcher');
// The regression test below uses the REAL predicate the app injects, so a rename
// of the adapter in tunManager.js cannot silently reopen the recovery loop.
const { isOwnTunInterface } = require('../src/main/tunManager');

const wifi = { 'Wi-Fi': [{ family: 'IPv4', internal: false, address: '192.168.1.20' }] };
const wifi2 = { 'Wi-Fi': [{ family: 'IPv4', internal: false, address: '192.168.1.99' }] };
const eth = { Ethernet: [{ family: 'IPv4', internal: false, address: '10.0.0.5' }] };

/** A watcher whose clock is a queue of callbacks this test fires by hand. */
function harness(reads, opts = {}) {
  const fired = [];
  let tick = null;
  let i = 0;
  const w = new NetWatcher(Object.assign({
    read: () => reads[Math.min(i, reads.length - 1)],
    onChange: (why) => fired.push(why),
    debounceMs: 2500,
    intervalMs: 3000,
    setTimer: (fn) => { tick = fn; return 'timer'; },
    clearTimer: () => { tick = null; }
  }, opts));
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

/**
 * The scenario this whole feature exists for: the user switches Wi-Fi, recovery
 * starts, and mid-recovery the laptop lands on ethernet. The rebuild that is in
 * flight was built for the PREVIOUS network, so dropping the second trigger
 * leaves the tunnel dead forever — the watcher would never fire again because it
 * has already recorded the new fingerprint as its baseline.
 */
test('a change that lands mid-recovery is deferred, not dropped', async () => {
  const fired = [];
  const releases = [];
  let tick = null, i = 0;
  const reads = [wifi, eth, wifi2];
  const w = new NetWatcher({
    read: () => reads[Math.min(i, reads.length - 1)],
    onChange: (why) => { fired.push(why); return new Promise((r) => releases.push(r)); },
    debounceMs: 0, intervalMs: 3000,
    setTimer: (fn) => { tick = fn; return 't'; }, clearTimer: () => { tick = null; }
  });
  w.start();
  tick();
  i = 1; tick(); tick();                  // wifi → eth settles: recovery #1 starts
  assert.deepEqual(fired, ['interfaces']);
  assert.equal(w.busy, true);
  i = 2; tick(); tick();                  // eth → wifi2 while recovery #1 is still running
  assert.deepEqual(fired, ['interfaces'], 'no second call while the first is running');
  releases.shift()();                     // recovery #1 finishes
  await Promise.resolve(); await Promise.resolve();
  assert.deepEqual(fired, ['interfaces', 'interfaces'],
    'the change seen mid-recovery must be acted on once the first recovery settles');
  assert.equal(w.busy, true, 'the deferred recovery holds the lock in its turn');
  releases.shift()();
  await Promise.resolve(); await Promise.resolve();
  assert.equal(w.busy, false);
  assert.deepEqual(fired, ['interfaces', 'interfaces'], 'and only the one deferred trigger runs');
});

/**
 * The other half of the same promise, and the reason the watcher owns no
 * "adopt the network as it is now" call.
 *
 * A recovery does not end the moment the new tunnel carries traffic: on Windows
 * TUN the tail after tun.start() has read the gateway — waitForAdapter, four
 * netsh calls, two route adds, the LAN firewall rule, the kill-switch disarm —
 * runs for seconds. A genuine change that lands in THAT window has been seen
 * once and is still only `pending`: it is 3-6 s (one poll plus the debounce)
 * from settling. Treating "the recovery finished" as "so this is the network
 * now" would adopt it as the baseline and it would never fire again — the
 * tunnel stays built for the previous gateway, the UI still says connected, and
 * nothing is left to notice. It must survive the recovery and fire when it
 * settles, exactly as it would have with no recovery in flight at all.
 */
test('a genuine change seen in a recovery\'s tail still fires once it settles', async () => {
  const fired = [];
  const releases = [];
  let tick = null, i = 0;
  const reads = [wifi, eth, wifi2];
  const w = new NetWatcher({
    read: () => reads[Math.min(i, reads.length - 1)],
    onChange: (why) => { fired.push(why); return new Promise((r) => releases.push(r)); },
    debounceMs: 2500, intervalMs: 3000,
    setTimer: (fn) => { tick = fn; return 't'; }, clearTimer: () => { tick = null; }
  });
  w.start();
  tick();
  i = 1; tick(); tick();                  // wifi → eth settles: recovery #1 starts
  assert.deepEqual(fired, ['interfaces']);
  assert.equal(w.busy, true);

  i = 2; tick();                          // a REAL change lands in the recovery's tail
  assert.notEqual(w.pending, null, 'seen once — half-observed, the debounce is running');
  assert.deepEqual(fired, ['interfaces'], 'and rightly silent so far');

  releases.shift()();                     // recovery #1 finishes
  await Promise.resolve(); await Promise.resolve();
  assert.equal(w.busy, false, 'the lock is released');
  assert.deepEqual(fired, ['interfaces'], 'a half-observed change is still not a trigger');
  assert.notEqual(w.pending, null, 'and finishing a recovery must not forget it');

  tick();                                 // it holds still: the debounce elapses
  assert.deepEqual(fired, ['interfaces', 'interfaces'],
    'the change the recovery did not cover must still fire');
});

/**
 * An onChange that never settles must not deafen the watcher permanently: stop()
 * is the reset, so stop()/start() always revives it.
 */
test('stop() releases the recovery lock, so a stuck onChange cannot deafen the watcher', () => {
  const fired = [];
  let tick = null;
  const w = new NetWatcher({
    read: () => wifi,
    onChange: (why) => { fired.push(why); return new Promise(() => {}); },   // never settles
    setTimer: (fn) => { tick = fn; return 't'; }, clearTimer: () => { tick = null; }
  });
  w.start();
  w.poke('resume');
  assert.deepEqual(fired, ['resume']);
  assert.equal(w.busy, true);
  w.stop();
  assert.equal(w.busy, false, 'stop() must release the lock');
  w.start();
  w.poke('online');
  assert.deepEqual(fired, ['resume', 'online'], 'a restarted watcher must fire again');
});

/**
 * The other half of that reset: when the stuck recovery finally does settle, it
 * must not unlock a NEWER one. Two overlapping reapplyConnection() calls would
 * tear a tunnel down in the middle of rebuilding it.
 */
test('a recovery that settles after stop() cannot unlock a newer one', async () => {
  const fired = [];
  const releases = [];
  let tick = null;
  const w = new NetWatcher({
    read: () => wifi,
    onChange: (why) => { fired.push(why); return new Promise((r) => releases.push(r)); },
    setTimer: (fn) => { tick = fn; return 't'; }, clearTimer: () => { tick = null; }
  });
  w.start();
  w.poke('resume');           // recovery #1 — will settle late
  w.stop();
  w.start();
  w.poke('online');           // recovery #2 — the live one
  assert.equal(w.busy, true);
  releases.shift()();         // #1 settles at last
  await Promise.resolve(); await Promise.resolve();
  assert.equal(w.busy, true, 'the stale run must not release the live run\'s lock');
  releases.shift()();
  await Promise.resolve(); await Promise.resolve();
  assert.equal(w.busy, false);
  assert.deepEqual(fired, ['resume', 'online']);
});

/* --------------------- the app's own TUN adapter --------------------- */
// A TUN rebuild removes and recreates OUR adapter, which is non-internal and so
// used to land in the fingerprint. Every recovery therefore produced the change
// that triggered the next one: one Wi-Fi switch = a permanent rebuild loop.

const tun4 = { family: 'IPv4', internal: false, address: '10.255.0.2' };
const tunLl = { family: 'IPv6', internal: false, address: 'fe80::1a2b:3c4d:5e6f:7a8b%14' };
const tunLl2 = { family: 'IPv6', internal: false, address: 'fe80::9911:2233:4455:6677%21' };
const wifi4 = { family: 'IPv4', internal: false, address: '192.168.1.20' };
const eth4 = { family: 'IPv4', internal: false, address: '10.0.0.5' };

test('the names the app creates for TUN are recognised on every platform', () => {
  assert.equal(isOwnTunInterface('XrayTun'), true, 'Windows adapter');
  assert.equal(isOwnTunInterface('utun'), true, 'macOS, before the kernel picks a unit');
  assert.equal(isOwnTunInterface('utun4'), true, 'macOS');
  assert.equal(isOwnTunInterface('utun12'), true, 'macOS, two digits');
  assert.equal(isOwnTunInterface('tun0'), true, 'Linux');
  assert.equal(isOwnTunInterface('Wi-Fi'), false);
  assert.equal(isOwnTunInterface('Ethernet'), false);
  assert.equal(isOwnTunInterface('tun1'), false, 'someone else\'s tun device is real network news');
  assert.equal(isOwnTunInterface(''), false);
  assert.equal(isOwnTunInterface(undefined), false);
});

test('fingerprint ignores the interfaces the caller says to ignore', () => {
  const withTun = { 'Wi-Fi': [wifi4], XrayTun: [tun4] };
  assert.notEqual(fingerprint(withTun), fingerprint({ 'Wi-Fi': [wifi4] }),
    'without the predicate the TUN adapter still counts');
  assert.equal(fingerprint(withTun, isOwnTunInterface), fingerprint({ 'Wi-Fi': [wifi4] }, isOwnTunInterface));
  // default = ignore nothing, so the existing single-argument callers are unchanged
  assert.equal(fingerprint(withTun, () => false), fingerprint(withTun));
});

test('fingerprint drops IPv6 link-local addresses', () => {
  // fe80::/10 is regenerated whenever an adapter is recreated and never says
  // anything about routing, so it must not be part of the signature.
  const a = { 'Wi-Fi': [wifi4, tunLl] };
  const b = { 'Wi-Fi': [wifi4, tunLl2] };
  assert.equal(fingerprint(a), fingerprint(b), 'a new link-local is not a network change');
  assert.equal(fingerprint(a), fingerprint({ 'Wi-Fi': [wifi4] }));
  assert.equal(fingerprint({ A: [{ family: 'IPv6', internal: false, address: 'febf::1' }] }), '',
    'the whole fe80::/10 block, not just fe80::/16');
  // a routable IPv6 address is still real news
  assert.notEqual(fingerprint({ A: [{ family: 'IPv6', internal: false, address: '2001:db8::1' }] }), '');
});

/**
 * The regression: reapplyConnection() destroys and recreates the TUN adapter, and
 * the teardown window is longer than the debounce. Without the ignore predicate
 * the watcher reads "the TUN adapter vanished" as a network change, fires, and
 * the recovery it triggers vanishes the adapter again — forever. Only the genuine
 * Wi-Fi → Ethernet switch at the end may fire.
 */
test('a TUN rebuild is not a network change, but a real one still is', () => {
  const reads = [
    { 'Wi-Fi': [wifi4], XrayTun: [tun4, tunLl] },    // baseline: connected, TUN up
    { 'Wi-Fi': [wifi4] },                            // tun.stop(): the adapter is gone
    { 'Wi-Fi': [wifi4], XrayTun: [tun4, tunLl2] },   // back, fresh GUID → fresh link-local
    { 'Wi-Fi': [wifi4] },                            // and the next rebuild tears it down again
    { 'Wi-Fi': [wifi4], XrayTun: [tun4, tunLl] },    // …and back
    { Ethernet: [eth4], XrayTun: [tun4, tunLl] }     // GENUINE: Wi-Fi → Ethernet
  ];
  const h = harness(reads, { ignoreInterface: isOwnTunInterface });
  h.w.start();
  h.tick();
  for (let step = 1; step <= 4; step++) {
    h.advance();
    h.tick(); h.tick(); h.tick();                    // well past the debounce
    assert.deepEqual(h.fired, [], `the TUN adapter moving must not fire (step ${step})`);
  }
  h.advance();                                        // the cable goes in
  h.tick();                                           // seen — debounce starts
  assert.deepEqual(h.fired, []);
  h.tick();                                           // settled
  assert.deepEqual(h.fired, ['interfaces'], 'a real network change still fires exactly once');
  h.tick(); h.tick();
  assert.deepEqual(h.fired, ['interfaces'], 'and only once');
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
