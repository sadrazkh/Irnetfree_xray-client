'use strict';
/**
 * macOS network recovery runs every step on its own (audit 2026-09-24, M6).
 *
 * The launch recovery and the "Recover network" button were a row of awaits:
 * native service → sing-box journals → tun2socks journals → the leak guard's
 * DNS restore. The native step throws when the service is enabled but not
 * answering, and it ran first — so the journals were never recovered, the
 * guard never gave the services their DNS back (every one stayed on the tunnel
 * peer), and every Connect was refused until a reboot.
 *
 * Now each step runs whatever the one before it did, its failure is logged, and
 * the guard always runs. The native step's failure gates nothing: a Connect on
 * sing-box/tun2socks never talks to the daemon, and the native backend's own
 * start() stops a session the daemon still holds before it starts another.
 * Every backend here is a fake.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { recoverMacNetwork } = require('../src/main/macRecovery');
const { LIVE_TUNNEL } = require('../src/main/macSessionOwner');

function fakes(fail = {}) {
  const ran = [];
  const make = (name) => class {
    constructor(opts) { this.opts = opts; }
    async recoverMacSessions() {
      ran.push([name, this.opts && this.opts.userData]);
      const f = fail[name];
      if (f) throw (f instanceof Error ? f : new Error(f));
    }
  };
  const backends = { NativeMacTun: make('native'), TunSingbox: make('sing-box'), TunManager: make('tun2socks') };
  const guard = async () => { ran.push(['guard']); if (fail.guard) throw new Error(fail.guard); };
  return { ran, backends, guard };
}

test('every step runs in order and nothing gates when all succeed', async () => {
  const { ran, backends, guard } = fakes();
  const logs = [];
  const gate = await recoverMacNetwork({ userData: '/u', guard, backends, onLog: (l, v) => logs.push([v, l]) });
  assert.equal(gate, null);
  assert.deepEqual(ran, [['native', '/u'], ['sing-box', '/u'], ['tun2socks', '/u'], ['guard']]);
  assert.deepEqual(logs, []);
});

test('a native service that is enabled but not answering no longer stops the rest — and gates no Connect', async () => {
  const { ran, backends, guard } = fakes({ native: 'Native macOS service recovery status is unavailable.' });
  const logs = [];
  const gate = await recoverMacNetwork({ userData: '/u', guard, backends, onLog: (l, v) => logs.push([v, l]) });
  assert.deepEqual(ran.map(r => r[0]), ['native', 'sing-box', 'tun2socks', 'guard'], 'the DNS restore ran');
  assert.equal(gate, null, 'sing-box / tun2socks connects are not refused over the native daemon');
  assert.equal(logs.length, 1);
  assert.equal(logs[0][0], 'warn');
  assert.match(logs[0][1], /native macOS service.*status is unavailable/);
});

test('a backend journal that cannot be recovered still lets the guard run, and gates Connect', async () => {
  const { ran, backends, guard } = fakes({ 'sing-box': 'User canceled' });
  const logs = [];
  const gate = await recoverMacNetwork({ userData: '/u', guard, backends, onLog: (l, v) => logs.push([v, l]) });
  assert.deepEqual(ran.map(r => r[0]), ['native', 'sing-box', 'tun2socks', 'guard']);
  assert.ok(gate instanceof Error);
  assert.match(gate.message, /sing-box.*User canceled/);
  assert.equal(logs[0][0], 'error');
});

test('a guard that could not restore DNS gates Connect; several failures are all named', async () => {
  const { backends, guard } = fakes({ guard: 'Saved DNS recovery is incomplete', tun2socks: 'Invalid tunnel recovery path' });
  const gate = await recoverMacNetwork({ userData: '/u', guard, backends });
  assert.match(gate.message, /tun2socks.*Invalid tunnel recovery path/);
  assert.match(gate.message, /DNS.*Saved DNS recovery is incomplete/);
});

test('no guard step when none is given; a throwing logger cannot turn into a rejection', async () => {
  const { ran, backends } = fakes({ native: 'x', 'sing-box': 'y' });
  const gate = await recoverMacNetwork({ userData: '/u', backends, onLog: () => { throw new Error('window gone'); } });
  assert.deepEqual(ran.map(r => r[0]), ['native', 'sing-box', 'tun2socks']);
  assert.match(gate.message, /sing-box.*y/);
});

// Review fix: a step that refused because a LIVE tunnel owns the journal (a
// second instance started with `open -n`, a connect still in flight) must not
// be followed by the guard's DNS restore — that would put the live instance's
// services back on the ISP's resolver under its running tunnel.
test('a live tunnel owner stops the DNS step: logged, gated, the guard never runs', async () => {
  const live = Object.assign(new Error('Another application instance may own this tunnel; close it before recovery'), { code: LIVE_TUNNEL });
  for (const backend of ['sing-box', 'tun2socks']) {
    const { ran, backends, guard } = fakes({ [backend]: live });
    const logs = [];
    const gate = await recoverMacNetwork({ userData: '/u', guard, backends, onLog: (l, v) => logs.push([v, l]) });
    assert.deepEqual(ran.map(r => r[0]), ['native', 'sing-box', 'tun2socks'], `${backend}: the guard step did not run`);
    assert.ok(gate instanceof Error);
    assert.match(gate.message, /Another application instance/);
    assert.ok(logs.some(([v, l]) => v === 'warn' && /saved DNS.*left alone.*live tunnel/i.test(l)), `${backend}: says why`);
  }
});

test('the real backends mark every "a live tunnel owns this" refusal with the code the recovery checks', async () => {
  const fs2 = require('node:fs'), os = require('node:os');
  const { TunSingbox } = require('../src/main/tunSingbox');
  const lock = require('../src/main/macSessionLock');
  assert.ok(typeof LIVE_TUNNEL === 'string' && LIVE_TUNNEL, 'the code is exported');
  const userData = fs2.mkdtempSync(path.join(os.tmpdir(), 'irnf-live-'));
  try {
    const holder = new TunSingbox({ platform: 'darwin', userData });
    lock.set(path.resolve(userData), holder);
    const other = new TunSingbox({ platform: 'darwin', userData });
    await assert.rejects(other.recoverMacSessions(), (e) => e.code === LIVE_TUNNEL);
    lock.delete(path.resolve(userData));
    holder.active = true;
    await assert.rejects(holder.recoverMacSessions(), (e) => e.code === LIVE_TUNNEL);
  } finally { lock.delete(path.resolve(userData)); fs2.rmSync(userData, { recursive: true, force: true }); }
});

/* --------------------------- main.js / service.js --------------------------- */

// Both require their runtime at load, so the wiring is read as text.
const read = (...p) => fs.readFileSync(path.join(__dirname, '..', ...p), 'utf8').replace(/\r\n/g, '\n');
const MAIN = read('src', 'main', 'main.js');
const SERVICE = read('src', 'server', 'service.js');

function launchChain(source, label) {
  const start = source.lastIndexOf('macRepairPromise = ');   // not the `let … = Promise.resolve()` declaration
  assert.notEqual(start, -1, `${label}: the launch recovery is gone`);
  return source.slice(start, source.indexOf('} else {', start));
}

test('the launch recovery runs every step on its own and always the guard\'s DNS repair', () => {
  for (const [label, src] of [['main.js', MAIN], ['service.js', SERVICE]]) {
    const chain = launchChain(src, label);
    assert.match(chain, /recoverMacNetwork\(\{/, `${label}: steps are not independent`);
    assert.match(chain, /guard: async \(\) => \{\s*await leakGuard\.repairAtLaunch\(\);\s*if \(leakGuard\.readState\(\)\) throw new Error\('Saved DNS recovery is incomplete'\);/,
      `${label}: the guard's repair is not a step of its own`);
    assert.doesNotMatch(chain, /await new (NativeMacTun|TunSingbox|TunManager)\(/, `${label}: a bare await chain is back`);
    assert.match(chain, /macRepairError = /, `${label}: a gating failure no longer blocks Connect`);
  }
});

test('manual recovery: on macOS the guard release is the recovery\'s own last step (skipped under a live tunnel), elsewhere it runs as before', () => {
  for (const [label, src] of [['main.js', MAIN], ['service.js', SERVICE]]) {
    const start = src.indexOf('async function repairNetwork()');
    const body = src.slice(start, src.indexOf('finally { networkRepairing = false; }', start));
    assert.match(body, /if \(process\.platform === 'darwin'\) failed = await recoverMacNetwork\(\{[^\n]*guard: \(\) => releaseGuardChecked\(leakGuard\) \}\);\n\s*else await releaseGuardChecked\(leakGuard\);\n\s*if \(failed\) throw failed;/,
      `${label}: recover (guard as its step) → report; other platforms release directly`);
    assert.doesNotMatch(body, /await new (NativeMacTun|TunSingbox|TunManager)\(/);
  }
});
