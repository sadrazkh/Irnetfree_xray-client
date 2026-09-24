'use strict';
/**
 * A macOS TUN setup that failed and rolled itself back leaves nothing to
 * recover (audit 2026-09-24, M5).
 *
 * sing-box dying at start — wrong architecture, a bad config, "Killed: 9" on an
 * unsigned binary — writes its pid, then the setup script's own rollback runs
 * the teardown and succeeds. The journal used to be kept anyway (a pid had been
 * written) and with it the in-process owner lock: the next Connect said
 * "Another tunnel operation is live; disconnect it first", quit and the next
 * launch asked for a password to recover nothing, and cancelling that prompt
 * blocked every Connect.
 *
 * Kept, as before: a setup whose rollback reported failure, a tunnel process
 * still alive, or a DNS change still marked. Every runner and probe is fake.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const cp = require('node:child_process');
cp.execFileSync = () => '';   // no xattr/codesign on the fake binary

const platform = require('../src/main/tunPlatform');
const macOwners = require('../src/main/macSessionLock');
const { TunSingbox } = require('../src/main/tunSingbox');
const { TunManager } = require('../src/main/tunManager');

const DIED = 'execution error: ERR: sing-box did not create a unique ready utun device\n'
  + 'FATAL[0000] start service: initialize inbound/tun[tun-in]: configure tun interface: operation not permitted (11)';
const ROLLBACK_FAILED = 'execution error: Owned tunnel process still running\nTunnel rollback failed; recovery required (11)';

const probe = (signal) => ({ signal: () => signal, identity: async () => null });

function userDir(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-failed-setup-'));
  t.after(() => { fs.rmSync(dir, { recursive: true, force: true }); macOwners.delete(path.resolve(dir)); });
  return dir;
}

/** The sing-box backend against a fake Mac whose privileged setup does `setup(work)` and fails with `message`. */
function singbox(t, { signal = 'gone', message = DIED, setup = () => {} } = {}) {
  const userData = userDir(t);
  fs.writeFileSync(path.join(userData, 'sing-box'), '');
  const tun = new TunSingbox({ platform: 'darwin', userData, lang: 'en', probe: probe(signal) });
  tun.dirs = () => [userData];
  const saved = {};
  for (const k of ['getDefaultRouteMac', 'serviceForDeviceMac', 'getServiceDnsMac', 'resolveServerIps', 'runScriptPrivileged']) saved[k] = platform[k];
  t.after(() => Object.assign(platform, saved));
  Object.assign(platform, {
    getDefaultRouteMac: async () => ({ gateway: '192.168.1.1', device: 'en0' }),
    serviceForDeviceMac: async () => 'Wi-Fi',
    getServiceDnsMac: async () => ['192.168.60.1'],
    resolveServerIps: async () => ['203.0.113.7'],
    runScriptPrivileged: async (p) => {
      if (path.basename(p) !== 'setup.sh') return '';
      const work = path.dirname(p);
      fs.writeFileSync(path.join(work, 'sing-box.pid'), '31337\n');
      setup(work);
      throw new Error(message);
    }
  });
  return { tun, userData };
}

test('sing-box: a setup that died and rolled back discards its journal and releases the lock', async (t) => {
  const { tun, userData } = singbox(t);
  await assert.rejects(tun.start(10808, ['203.0.113.7'], ['172.19.0.2'], {}), /TUN setup failed: .*operation not permitted/);
  assert.equal(tun.macState, null);
  assert.equal(tun.hasPendingMacRecovery(), false, 'nothing is left for the next launch to prompt about');
  assert.equal(macOwners.has(path.resolve(userData)), false, 'the owner lock is released');
  // The next Connect is a fresh attempt, not "another tunnel operation is live".
  const next = new TunSingbox({ platform: 'darwin', userData, lang: 'en', probe: probe('gone') });
  next.dirs = () => [userData];
  await assert.rejects(next.start(10808, ['203.0.113.7'], ['172.19.0.2'], {}), /TUN setup failed/);
});

test('sing-box: a rollback that reported failure keeps the journal for recovery', async (t) => {
  const { tun, userData } = singbox(t, { message: ROLLBACK_FAILED });
  await assert.rejects(tun.start(10808, ['203.0.113.7'], ['172.19.0.2'], {}), /TUN setup failed/);
  assert.equal(tun.hasPendingMacRecovery(), true);
  assert.equal(macOwners.get(path.resolve(userData)), tun, 'still ours until recovered');
});

test('sing-box: a tunnel process still alive (a root pid answers EPERM) keeps the journal', async (t) => {
  const { tun } = singbox(t, { signal: 'other' });
  await assert.rejects(tun.start(10808, ['203.0.113.7'], ['172.19.0.2'], {}), /TUN setup failed/);
  assert.equal(tun.hasPendingMacRecovery(), true);
});

test('sing-box: a DNS change still marked keeps the journal', async (t) => {
  const { tun } = singbox(t, { setup: (work) => fs.writeFileSync(path.join(work, 'dns-changed'), '') });
  await assert.rejects(tun.start(10808, ['203.0.113.7'], ['172.19.0.2'], {}), /TUN setup failed/);
  assert.equal(tun.hasPendingMacRecovery(), true);
});

/* ------------------------------ tun2socks ------------------------------ */

function legacy(t, { signal = 'gone', message = DIED, setup = () => {} } = {}) {
  const real = os.platform;
  os.platform = () => 'darwin';
  t.after(() => { os.platform = real; });
  const userData = userDir(t);
  const m = new TunManager({ userData, lang: 'en', probe: probe(signal) });
  m.tun2socksPath = () => '/test/tun2socks';
  m.getDefaultRouteMac = async () => ({ gateway: '192.168.1.1', device: 'en0' });
  m.serviceForDeviceMac = async () => 'Wi-Fi';
  m.getServiceDnsMac = async () => ['192.168.60.1'];
  m.resolveServerIps = async () => ['203.0.113.7'];
  m.startMacLogTail = () => {};
  m.runScriptPrivileged = async () => {
    fs.writeFileSync(m.macState.pidFile, '4242');
    setup(m.macState);
    throw new Error(message);
  };
  return { m, userData };
}

test('tun2socks: a setup that died and rolled back discards its journal and releases the lock', async (t) => {
  const { m, userData } = legacy(t);
  await assert.rejects(m.start(10808, 'server', ['10.255.0.1']), /TUN setup failed/);
  assert.equal(m.macState, null);
  assert.equal(m.hasPendingMacRecovery(), false);
  assert.equal(macOwners.has(path.resolve(userData)), false);
});

test('tun2socks: rollback failure, a live process or a marked DNS change keep the journal', async (t) => {
  for (const opts of [{ message: 'execution error: Tunnel rollback failed; recovery retained (13)' }, { signal: 'other' },
    { setup: (st) => fs.writeFileSync(st.dnsFile, '') }]) {
    const { m } = legacy(t, opts);
    await assert.rejects(m.start(10808, 'server', ['10.255.0.1']), /TUN setup failed/);
    assert.equal(m.hasPendingMacRecovery(), true, JSON.stringify(Object.keys(opts)));
  }
});
