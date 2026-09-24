'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { stopTrackedTunnels, releaseGuardChecked, releaseStrandedGuard } = require('../src/main/tunnelCleanup');
const { LeakGuard, STATE_FILE } = require('../src/main/leakGuard');

test('mac cleanup attempts every tunnel and keeps only failures for retry', async () => {
  let fail = true;
  const calls = [];
  const first = { stop: async () => { calls.push('first'); if (fail) throw new Error('permission cancelled'); } };
  const second = { stop: async () => { calls.push('second'); } };
  const started = new Set([first, second]);
  await assert.rejects(stopTrackedTunnels(started, first, 'darwin'), /cleanup incomplete/);
  assert.deepEqual(calls, ['first', 'second']);
  assert.deepEqual([...started], [first]);
  fail = false;
  await stopTrackedTunnels(started, first, 'darwin');
  assert.equal(started.size, 0);
});
test('Windows keeps best-effort cleanup semantics', async () => {
  const started = new Set([{ stop: async () => { throw new Error('old behavior'); } }]);
  await stopTrackedTunnels(started, null, 'win32');
  assert.equal(started.size, 0);
});
test('mac guard failures cannot become successful disconnects', async () => {
  const guard = { release: async () => ({ released: false, error: 'cancelled' }) };
  await assert.rejects(releaseGuardChecked(guard, 'darwin'), /DNS recovery incomplete/);
  assert.equal((await releaseGuardChecked(guard, 'win32')).released, false);
});

/* ------------- a guard held for a tunnel that is not coming back (final wave F1) ------------- */

/**
 * The real LeakGuard on a fake Windows: every PowerShell run is recorded and
 * answered by `answer`; nothing runs, no adapter is touched.
 */
function fakeGuard(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-strand-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const ps = [];
  const snap = JSON.stringify([{ alias: 'Wi-Fi', v4: ['192.168.8.1'], v6: [], dhcp4: true, dhcp6: true }]);
  const guard = new LeakGuard({
    userData: dir,
    platform: 'win32',
    onLog: () => {},
    run: async (cmd, args) => { ps.push(args.at(-1)); return /ConvertTo-Json/.test(args.at(-1)) ? snap : ''; },
    runScriptPrivileged: async () => { throw new Error('no privileged runs here'); },
    runSync: () => { throw new Error('no sync runs here'); }
  });
  return { guard, ps, statePath: path.join(dir, STATE_FILE) };
}

test('a guard a reapply held for the tunnel is given back by a connect that builds none', async (t) => {
  // TUN → proxy: reapplyConnection holds the adapters on loopback, stops the
  // tunnel, and the proxy connect never engaged or released anything — the
  // whole proxy session ran with no resolver at all.
  const h = fakeGuard(t);
  await h.guard.engage({ level: 'standard', peer4: '172.19.0.2', peer6: 'fdfe:dcba:9876::2', tunAlias: 'IRNetFree' });
  assert.equal((await h.guard.holdForReconnect({ excludes: ['203.0.113.10'] })).held, true);
  h.ps.length = 0;
  const r = await releaseStrandedGuard(h.guard);
  assert.equal(r.released, true);
  assert.equal(fs.existsSync(h.statePath), false, 'the session is over: nothing left to restore at the disconnect');
  assert.match(h.ps.join('\n'), /-InterfaceAlias 'Wi-Fi' -ResetServerAddresses/, 'the adapter gets its own resolver back');
});

test('with nothing held, and with only proxy mode’s own UDP block, nothing is released', async (t) => {
  const none = fakeGuard(t);
  assert.equal(await releaseStrandedGuard(none.guard), null);
  assert.deepEqual(none.ps, [], 'not even a snapshot');
  // a proxy → proxy switch: the UDP block names no resolver, and lifting it
  // would open the WebRTC leak for the whole switch — that connect renews it
  const udp = fakeGuard(t);
  await udp.guard.engageUdpBlock({ excludes: ['203.0.113.10'] });
  udp.ps.length = 0;
  assert.equal(await releaseStrandedGuard(udp.guard), null);
  assert.deepEqual(udp.ps, []);
  assert.equal(fs.existsSync(udp.statePath), true);
  assert.equal(await releaseStrandedGuard(null), null);
});

test('a release that fails keeps the record for the next launch and does not throw into the connect', async (t) => {
  const h = fakeGuard(t);
  await h.guard.engage({ level: 'standard', peer4: '172.19.0.2', tunAlias: 'IRNetFree' });
  h.guard.run = async () => { throw new Error('Access is denied.'); };
  const r = await releaseStrandedGuard(h.guard);
  assert.equal(r.released, false);
  assert.match(r.error, /Access is denied/);
  assert.equal(fs.existsSync(h.statePath), true);
});
