'use strict';
/**
 * Who owns a macOS tunnel journal (audit 2026-09-24, M1).
 *
 * Each journal names the app process that started the tunnel, so a second
 * instance never tears down a tunnel a live one is using. The pid alone used
 * to be the whole identity: after a reboot (and "Start at login" makes that the
 * usual launch) the number belongs to some other process, `process.kill(pid, 0)`
 * succeeded — or failed with EPERM for a root process — and recovery threw
 * "Another application instance may own this tunnel". That throw came before
 * the DNS repair, so every service stayed on the tunnel peer and every Connect
 * was refused.
 *
 * Every probe is injected: nothing here signals, lists or tears down a real
 * process. The stale owner is `process.ppid` — a pid that really is alive and
 * ours to signal on every CI runner, which is exactly the reboot case.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const cp = require('node:child_process');
// No xattr/codesign on the fake binary: the backends destructure this at require time.
cp.execFileSync = () => '';

const platform = require('../src/main/tunPlatform');
const { TunSingbox } = require('../src/main/tunSingbox');
const { TunManager } = require('../src/main/tunManager');
const { ownerAlive, ownerRecord, pidAlive } = require('../src/main/macSessionOwner');

const LIVE_START = 'Wed Sep 23 08:00:00 2026';
const OLD_START = 'Mon Sep 21 09:15:02 2026';

/** A probe: `signal` answers for one pid, `identity` describes it. */
function probe({ signal = 'ours', start = LIVE_START, command = '/usr/libexec/some-daemon' } = {}) {
  const seen = [];
  return {
    seen,
    signal: (pid) => { seen.push(['signal', pid]); return signal; },
    identity: async (pid) => { seen.push(['identity', pid]); return start === null ? null : { start, command }; }
  };
}

test('ownerAlive: the pid AND its start time must match; EPERM is never an instance of this app', async () => {
  const pid = process.ppid;
  assert.equal(await ownerAlive({ ownerPid: pid, ownerStart: LIVE_START }, probe()), true, 'same pid, same start: live owner');
  assert.equal(await ownerAlive({ ownerPid: pid, ownerStart: OLD_START }, probe()), false, 'a reused pid is not the owner');
  assert.equal(await ownerAlive({ ownerPid: pid, ownerStart: LIVE_START }, probe({ signal: 'other' })), false, 'EPERM: a root process');
  assert.equal(await ownerAlive({ ownerPid: pid, ownerStart: LIVE_START }, probe({ signal: 'gone' })), false);
  assert.equal(await ownerAlive({ ownerPid: pid, ownerStart: LIVE_START }, probe({ start: null })), false, 'no identity readable: not provably the owner');
  assert.equal(await ownerAlive({ ownerPid: process.pid, ownerStart: LIVE_START }, probe()), false, 'this process is never "another instance"');
  assert.equal(await ownerAlive({ ownerPid: 1 }, probe()), false);
  assert.equal(await ownerAlive({}, probe()), false);
});

test('ownerAlive: a journal from before the identity was recorded is live only when the pid runs this app', async () => {
  const exe = '/Applications/IRNetFree.app/Contents/MacOS/IRNetFree';
  const pid = process.ppid;
  assert.equal(await ownerAlive({ ownerPid: pid }, probe({ command: exe }), exe), true);
  assert.equal(await ownerAlive({ ownerPid: pid }, probe({ command: exe + ' --hidden' }), exe), true);
  assert.equal(await ownerAlive({ ownerPid: pid }, probe({ command: '/usr/sbin/cfprefsd agent' }), exe), false);
  const helper = '/Applications/IRNetFree.app/Contents/Frameworks/IRNetFree Helper (Renderer).app/Contents/MacOS/IRNetFree Helper (Renderer) --type=renderer';
  assert.equal(await ownerAlive({ ownerPid: pid }, probe({ command: helper }), exe), false, 'a helper of the app is not the main process');
  assert.equal(await ownerAlive({ ownerPid: pid }, probe({ command: exe, signal: 'other' }), exe), false);
});

test('ownerRecord names this process by pid and start time; pidAlive counts a root process as alive', async () => {
  const p = probe({ start: LIVE_START });
  assert.deepEqual(await ownerRecord(p), { ownerPid: process.pid, ownerStart: LIVE_START });
  assert.deepEqual(p.seen, [['identity', process.pid]]);
  assert.deepEqual(await ownerRecord(probe({ start: null })), { ownerPid: process.pid, ownerStart: null });
  const failing = { signal: () => 'ours', identity: async () => { throw new Error('ps failed'); } };
  assert.deepEqual(await ownerRecord(failing), { ownerPid: process.pid, ownerStart: null });
  // sing-box / tun2socks run as root: EPERM means "running", ESRCH means gone.
  assert.equal(pidAlive(4242, probe({ signal: 'other' })), true);
  assert.equal(pidAlive(4242, probe({ signal: 'ours' })), true);
  assert.equal(pidAlive(4242, probe({ signal: 'gone' })), false);
  assert.equal(pidAlive(0, probe()), false);
  assert.equal(pidAlive(null, probe()), false);
});

/* ------------------------------ sing-box journals ------------------------------ */

function singboxJournal(t, extra) {
  const userData = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-owner-sb-'));
  t.after(() => fs.rmSync(userData, { recursive: true, force: true }));
  const writer = new TunSingbox({ platform: 'darwin', userData });
  const { work, cfgFile } = writer.writeConfig(10808, [], {}, null);
  const st = { work, cfgFile, bin: '/bin/sing-box', savedDns: ['9.9.9.9'], service: 'Wi-Fi', ...extra };
  for (const key of ['logFile', 'pidFile', 'devFile', 'identityFile', 'dnsFile']) st[key] = path.join(work, key);
  writer.macState = st; writer.saveMacSession(); writer.macState = null;
  return { userData, work };
}

function capturePrivileged(t) {
  const real = platform.runScriptPrivileged;
  const ran = [];
  platform.runScriptPrivileged = async (p) => { ran.push(fs.readFileSync(p, 'utf8')); return ''; };
  t.after(() => { platform.runScriptPrivileged = real; });
  return ran;
}

test('sing-box recovery: a journal whose ownerPid now belongs to another process is recovered', async (t) => {
  const ran = capturePrivileged(t);
  const { userData, work } = singboxJournal(t, { ownerPid: process.ppid, ownerStart: OLD_START });
  const tun = new TunSingbox({ platform: 'darwin', userData, probe: probe({ start: LIVE_START }) });
  assert.equal(await tun.recoverMacSessions(), 1);
  assert.equal(ran.length, 1, 'the teardown ran');
  assert.match(ran[0], /networksetup -setdnsservers 'Wi-Fi' '9\.9\.9\.9'/);
  assert.equal(fs.existsSync(work), false);
});

test('sing-box recovery: a root process on the old pid (EPERM) does not block recovery', async (t) => {
  capturePrivileged(t);
  const { userData } = singboxJournal(t, { ownerPid: process.ppid, ownerStart: OLD_START });
  const tun = new TunSingbox({ platform: 'darwin', userData, probe: probe({ signal: 'other', start: OLD_START }) });
  assert.equal(await tun.recoverMacSessions(), 1);
});

test('sing-box recovery: a live owner (same pid, same start) still refuses, and nothing runs', async (t) => {
  const ran = capturePrivileged(t);
  const { userData, work } = singboxJournal(t, { ownerPid: process.ppid, ownerStart: LIVE_START });
  const tun = new TunSingbox({ platform: 'darwin', userData, probe: probe({ start: LIVE_START }) });
  await assert.rejects(tun.recoverMacSessions(), /Another application instance/);
  assert.equal(ran.length, 0);
  assert.ok(fs.existsSync(path.join(work, 'session.json')));
});

test('sing-box recovery: an old journal without an owner start is ours unless the pid runs this app', async (t) => {
  capturePrivileged(t);
  const { userData } = singboxJournal(t, { ownerPid: process.ppid });
  const other = new TunSingbox({ platform: 'darwin', userData, probe: probe({ command: '/usr/sbin/distnoted agent' }) });
  assert.equal(await other.recoverMacSessions(), 1);
  const again = singboxJournal(t, { ownerPid: process.ppid });
  const app = new TunSingbox({ platform: 'darwin', userData: again.userData, probe: probe({ command: process.execPath }) });
  await assert.rejects(app.recoverMacSessions(), /Another application instance/);
});

test('sing-box start journals the owner start time next to the pid', async (t) => {
  const userData = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-owner-sb-start-'));
  t.after(() => { fs.rmSync(userData, { recursive: true, force: true }); require('../src/main/macSessionLock').delete(path.resolve(userData)); });
  const bin = path.join(userData, 'sing-box');
  fs.writeFileSync(bin, '');
  const tun = new TunSingbox({ platform: 'darwin', userData, lang: 'en', probe: probe({ start: LIVE_START }) });
  tun.dirs = () => [userData];
  const realRoute = platform.getDefaultRouteMac, realSvc = platform.serviceForDeviceMac, realDns = platform.getServiceDnsMac, realRes = platform.resolveServerIps;
  const realPriv = platform.runScriptPrivileged;
  t.after(() => Object.assign(platform, { getDefaultRouteMac: realRoute, serviceForDeviceMac: realSvc, getServiceDnsMac: realDns, resolveServerIps: realRes, runScriptPrivileged: realPriv }));
  let journal = null;
  Object.assign(platform, {
    getDefaultRouteMac: async () => ({ gateway: '192.168.1.1', device: 'en0' }),
    serviceForDeviceMac: async () => 'Wi-Fi',
    getServiceDnsMac: async () => [],
    resolveServerIps: async () => ['203.0.113.7'],
    runScriptPrivileged: async (p) => {
      journal = JSON.parse(fs.readFileSync(path.join(path.dirname(p), 'session.json'), 'utf8'));
      throw new Error('execution error: User canceled. (-128)');
    }
  });
  await assert.rejects(tun.start(10808, ['203.0.113.7'], ['172.19.0.2'], {}), /administrator password/);
  assert.equal(journal.ownerPid, process.pid);
  assert.equal(journal.ownerStart, LIVE_START);
});

/* ------------------------------ tun2socks journals ------------------------------ */

function legacyJournal(t, extra) {
  const userData = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-owner-t2s-'));
  t.after(() => fs.rmSync(userData, { recursive: true, force: true }));
  const base = path.join(userData, 'mac-legacy-tun-sessions');
  fs.mkdirSync(base, { recursive: true });
  const work = fs.mkdtempSync(path.join(base, 'irnf-tun-'));
  const st = {
    work, service: 'Wi-Fi', savedDns: ['9.9.9.9'], gateway: '192.168.1.1', bypassIps: ['203.0.113.7'],
    reqDev: 'utun', macPid: 4242, dev: 'utun7', identity: '', expectedCommand: '/bin/tun2socks -device utun', ...extra
  };
  for (const key of ['logFile', 'pidFile', 'devFile', 'identityFile', 'dnsFile', 'routesFile']) st[key] = path.join(work, key);
  fs.writeFileSync(path.join(work, 'session.json'), JSON.stringify(st));
  return { userData, work };
}

function darwin(t) {
  const real = os.platform;
  os.platform = () => 'darwin';
  t.after(() => { os.platform = real; });
}

test('tun2socks recovery: a reused ownerPid is recovered; a live owner still refuses', async (t) => {
  darwin(t);
  const stale = legacyJournal(t, { ownerPid: process.ppid, ownerStart: OLD_START });
  const recovery = new TunManager({ userData: stale.userData, probe: probe({ start: LIVE_START }) });
  const ran = [];
  recovery.runScriptPrivileged = async (p) => { ran.push(fs.readFileSync(p, 'utf8')); };
  assert.equal(await recovery.recoverMacSessions(), 1);
  assert.equal(ran.length, 1);
  assert.equal(fs.existsSync(stale.work), false);

  const live = legacyJournal(t, { ownerPid: process.ppid, ownerStart: LIVE_START });
  const blocked = new TunManager({ userData: live.userData, probe: probe({ start: LIVE_START }) });
  blocked.runScriptPrivileged = async () => assert.fail('must not tear down a live instance\'s tunnel');
  await assert.rejects(blocked.recoverMacSessions(), /Another application instance/);

  const root = legacyJournal(t, { ownerPid: process.ppid, ownerStart: LIVE_START });
  const eperm = new TunManager({ userData: root.userData, probe: probe({ signal: 'other', start: LIVE_START }) });
  eperm.runScriptPrivileged = async () => {};
  assert.equal(await eperm.recoverMacSessions(), 1);
});
