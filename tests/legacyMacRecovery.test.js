'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const cp = require('node:child_process');
// No test invokes a network command, privileged shell, or real VPN process.
cp.execFileSync = () => '';
const { TunManager } = require('../src/main/tunManager');
const realPlatform = os.platform;
os.platform = () => 'darwin';
test.after(() => { os.platform = realPlatform; });
function fixture(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-legacy-test-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  // No `ps` for the owner's start time, no signal to a real pid.
  const manager = new TunManager({ userData: dir, lang: 'en', probe: { signal: () => 'gone', identity: async () => null } });
  t.after(() => require('../src/main/macSessionLock').delete(path.resolve(dir)));
  manager.tun2socksPath = () => '/test/tun2socks';
  manager.getDefaultRouteMac = async () => ({ gateway: '192.0.2.1', device: 'en0' });
  manager.serviceForDeviceMac = async () => 'Wi-Fi';
  manager.getServiceDnsMac = async () => ['192.0.2.53'];
  manager.resolveServerIps = async () => ['198.51.100.1'];
  manager.startMacLogTail = () => {};
  return { manager, dir };
}
function finishSetup(manager) {
  const st = manager.macState;
  fs.writeFileSync(st.pidFile, '4242');
  fs.writeFileSync(st.identityFile, 'Wed Sep 9 12:00:00 2026');
  fs.writeFileSync(st.devFile, 'utun7');
  fs.writeFileSync(st.dnsFile, '');
}
test('legacy journals original DNS before mutation and survives failed setup/restart', async t => {
  const { manager, dir } = fixture(t);
  manager.runScriptPrivileged = async () => {
    const saved = JSON.parse(fs.readFileSync(path.join(manager.macState.work, 'session.json')));
    assert.deepEqual(saved.savedDns, ['192.0.2.53']);
    finishSetup(manager);
    throw new Error('route failed');
  };
  await assert.rejects(manager.start(1080, 'server', ['10.255.0.1']), /failed/);
  assert.equal(manager.hasPendingMacRecovery(), true);
  // Simulate a process restart: in-memory ownership disappears, disk survives.
  require('../src/main/macSessionLock').delete(path.resolve(dir));
  const recovery = new TunManager({ userData: dir });
  let script;
  recovery.runScriptPrivileged = async file => { script = fs.readFileSync(file, 'utf8'); };
  assert.equal(await recovery.recoverMacSessions(), 1);
  assert.match(script, /kill -KILL/);
  assert.match(script, /networksetup -setdnsservers 'Wi-Fi' '192.0.2.53'/);
  assert.doesNotMatch(script, /pkill|pgrep/);
  assert.equal(recovery.hasPendingMacRecovery(), false);
});
test('legacy disconnect waits for setup and failed cleanup remains retryable', async t => {
  const { manager } = fixture(t);
  let resume;
  let entered;
  const ready = new Promise(r => { entered = r; });
  manager.runScriptPrivileged = async file => {
    if (file.endsWith('setup.sh')) {
      entered(); await new Promise(r => { resume = r; }); finishSetup(manager);
    } else throw new Error('User canceled');
  };
  const start = manager.start(1080, 'server', ['10.255.0.1']);
  await ready;
  const stop = manager.stop();
  resume();
  await start;
  await assert.rejects(stop, /User canceled/);
  assert.equal(manager.active, true);
  assert.ok(fs.existsSync(path.join(manager.macState.work, 'session.json')));
  manager.runScriptPrivileged = async () => {};
  await manager.stop();
  assert.equal(manager.active, false);
  assert.equal(manager.macState, null);
});
test('legacy pre-launch cancellation discards its empty journal', async t => {
  const { manager } = fixture(t);
  manager.runScriptPrivileged = async () => { throw new Error('User canceled'); };
  await assert.rejects(manager.start(1080, 'server', []), /permission/);
  assert.equal(manager.hasPendingMacRecovery(), false);
});
test('legacy rejects recovery artifacts escaping the session directory', async t => {
  const { manager, dir } = fixture(t);
  manager.runScriptPrivileged = async () => { finishSetup(manager); throw new Error('failed'); };
  await assert.rejects(manager.start(1080, 'server', []));
  const file = path.join(manager.macState.work, 'session.json');
  const state = JSON.parse(fs.readFileSync(file));
  state.pidFile = path.join(dir, 'outside.pid');
  fs.writeFileSync(file, JSON.stringify(state));
  require('../src/main/macSessionLock').delete(path.resolve(dir));
  const recovery = new TunManager({ userData: dir });
  recovery.runScriptPrivileged = async () => { assert.fail('must not execute'); };
  await assert.rejects(recovery.recoverMacSessions(), /Invalid tunnel recovery path/);
  assert.ok(fs.existsSync(file));
});
