'use strict';
/**
 * A reconnect keeps the service's DNS on the tunnel (audit 2026-09-24, M3).
 *
 * A reconnect (network change, settings apply, server switch) holds the leak
 * guard — every service stays on the tunnel's resolver — and then stops the
 * tunnel. On macOS that stop ran the teardown script, which put the main
 * service's saved (ISP) DNS straight back: clear-text lookups to the ISP for
 * the whole rebuild, password prompt included, and if the rebuild gave up the
 * service stayed on the ISP's resolver while the log said nothing was leaking.
 *
 * `stop({ keepDns: true })` is the reconnect's stop: the teardown leaves DNS as
 * the guard set it. A plain stop — a real disconnect, a recovery — restores it
 * exactly as before. The next start of the same app then reads the tunnel's own
 * resolver off the service, so the stopping session hands its originals over.
 *
 * Nothing runs: the privileged runner and every platform query are fakes.
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
const { TunSingbox, buildMacTeardownScript, TUN_PEER4, TUN_PEER6 } = require('../src/main/tunSingbox');
const { TunManager } = require('../src/main/tunManager');
const { stopTrackedTunnels } = require('../src/main/tunnelCleanup');

const W = '/Users/owner/Library/Application Support/IRNetFree/mac-tun-sessions/irnf-sb-AbC123';
const ARGS = {
  bin: '/Applications/IRNetFree.app/Contents/Resources/bin/sing-box', cfgFile: W + '/sing-box.json',
  pidFile: W + '/sing-box.pid', identityFile: W + '/identity', dnsFile: W + '/dns-changed',
  service: 'Wi-Fi', savedDns: ['192.168.60.1'], pid: 31337
};
const RESTORE = [
  'if [ -f "$DNSFILE" ]; then',
  "  networksetup -setdnsservers 'Wi-Fi' '192.168.60.1' || exit 25",
  '  rm -f "$DNSFILE"',
  'fi'
].join('\n');

test('sing-box teardown: keepDns leaves the service\'s DNS alone; the default still restores it — nothing else differs', () => {
  const restore = buildMacTeardownScript(ARGS);
  const keep = buildMacTeardownScript({ ...ARGS, keepDns: true });
  assert.ok(restore.includes(RESTORE), 'a disconnect restores the saved DNS');
  assert.doesNotMatch(keep, /networksetup/);
  assert.equal(keep, restore.replace(RESTORE, 'true'), 'the process half of the teardown is byte-identical');
});

const probe = { signal: () => 'gone', identity: async () => null };

/**
 * A sing-box backend on a fake Mac; returns the scripts it ran, by name.
 * `ctl.fail` makes the next setup fail: 'cancel' (the password prompt, nothing
 * ran) or 'died' (sing-box wrote its pid, died, and the rollback succeeded).
 */
function fakeMac(t, userData, dnsOnService, ctl = {}) {
  const scripts = [];
  const saved = {};
  for (const k of ['getDefaultRouteMac', 'serviceForDeviceMac', 'getServiceDnsMac', 'resolveServerIps', 'runScriptPrivileged']) saved[k] = platform[k];
  t.after(() => Object.assign(platform, saved));
  Object.assign(platform, {
    getDefaultRouteMac: async () => ({ gateway: '192.168.1.1', device: 'en0' }),
    serviceForDeviceMac: async () => 'Wi-Fi',
    getServiceDnsMac: async () => dnsOnService.slice(),
    resolveServerIps: async () => ['203.0.113.7'],
    runScriptPrivileged: async (p) => {
      scripts.push([path.basename(p), fs.readFileSync(p, 'utf8')]);
      if (path.basename(p) === 'setup.sh') {
        const work = path.dirname(p);
        const fail = ctl.fail; ctl.fail = null;
        if (fail === 'cancel') throw new Error('execution error: User canceled. (-128)');
        fs.writeFileSync(path.join(work, 'sing-box.pid'), '31337\n');
        if (fail === 'died') throw new Error('execution error: ERR: sing-box did not create a unique ready utun device (11)');
        fs.writeFileSync(path.join(work, 'sing-box.dev'), 'utun9\n');
        fs.writeFileSync(path.join(work, 'dns-changed'), '');
      }
      return '';
    }
  });
  return scripts;
}

function singbox(userData) {
  fs.writeFileSync(path.join(userData, 'sing-box'), '');
  const tun = new TunSingbox({ platform: 'darwin', userData, lang: 'en', probe });
  tun.dirs = () => [userData];
  tun.startMacLogTail = () => {};
  tun.startMacHealthCheck = () => {};
  return tun;
}

function userDir(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-keepdns-'));
  t.after(() => { fs.rmSync(dir, { recursive: true, force: true }); macOwners.delete(path.resolve(dir)); });
  return dir;
}

test('sing-box: a reconnect stop keeps DNS, and the next session journals the ORIGINAL DNS, not the tunnel peer', async (t) => {
  const userData = userDir(t);
  const dns = ['192.168.60.1'];
  const scripts = fakeMac(t, userData, dns);
  const first = singbox(userData);
  await first.start(10808, ['203.0.113.7'], [TUN_PEER4], {});
  assert.deepEqual(first.macState.savedDns, ['192.168.60.1']);

  // The setup pointed Wi-Fi at the tunnel; a reconnect's stop leaves it there.
  dns.splice(0, dns.length, TUN_PEER4, TUN_PEER6);
  await first.stop({ keepDns: true });
  const [name, teardown] = scripts[scripts.length - 1];
  assert.equal(name, 'teardown.sh');
  assert.doesNotMatch(teardown, /networksetup/, 'the reconnect did not hand Wi-Fi back to the ISP');
  assert.equal(first.macState, null);

  const second = singbox(userData);
  await second.start(10808, ['203.0.113.7'], [TUN_PEER4], {});
  assert.deepEqual(second.macState.savedDns, ['192.168.60.1'], 'the originals carried over, not 172.19.0.2');
  const journal = JSON.parse(fs.readFileSync(path.join(second.macState.work, 'session.json'), 'utf8'));
  assert.deepEqual(journal.savedDns, ['192.168.60.1']);

  // A real disconnect restores them.
  await second.stop();
  assert.match(scripts[scripts.length - 1][1], /networksetup -setdnsservers 'Wi-Fi' '192\.168\.60\.1' \|\| exit 25/);
});

test('sing-box: DNS changed by hand during the gap wins over the handed-over originals', async (t) => {
  const userData = userDir(t);
  const dns = ['192.168.60.1'];
  fakeMac(t, userData, dns);
  const first = singbox(userData);
  await first.start(10808, ['203.0.113.7'], [TUN_PEER4], {});
  await first.stop({ keepDns: true });
  dns.splice(0, dns.length, '9.9.9.9');      // not what the tunnel set: the user's own choice
  const second = singbox(userData);
  await second.start(10808, ['203.0.113.7'], [TUN_PEER4], {});
  assert.deepEqual(second.macState.savedDns, ['9.9.9.9']);
  await second.stop();
});

// Review fix: the handover used to be consumed on read, BEFORE the new setup
// had succeeded. A rebuild that failed after the read (a cancelled prompt, a
// sing-box that died and rolled back) lost it, and the retry journalled the
// guard's peer as the "original" — a later restore then left Wi-Fi on a dead
// resolver with no record of the real one anywhere.
for (const fail of ['cancel', 'died']) {
  test(`sing-box: a rebuild that fails (${fail}) keeps the handed-over originals for the retry`, async (t) => {
    const userData = userDir(t);
    const dns = ['192.168.60.1'];
    const ctl = {};
    fakeMac(t, userData, dns, ctl);
    const first = singbox(userData);
    await first.start(10808, ['203.0.113.7'], [TUN_PEER4], {});
    dns.splice(0, dns.length, TUN_PEER4, TUN_PEER6);
    await first.stop({ keepDns: true });

    ctl.fail = fail;
    const failed = singbox(userData);
    await assert.rejects(failed.start(10808, ['203.0.113.7'], [TUN_PEER4], {}), fail === 'cancel' ? /administrator password/ : /TUN setup failed/);
    assert.equal(failed.macState, null, 'nothing journalled (the M5 discard)');

    const retry = singbox(userData);
    await retry.start(10808, ['203.0.113.7'], [TUN_PEER4], {});
    assert.deepEqual(retry.macState.savedDns, ['192.168.60.1'], 'the retry journals the originals, not 172.19.0.2');
    await retry.stop();
  });
}

test('sing-box: once a session has started with the handed-over originals, they are not handed over again', async (t) => {
  const userData = userDir(t);
  const dns = ['192.168.60.1'];
  fakeMac(t, userData, dns);
  const first = singbox(userData);
  await first.start(10808, ['203.0.113.7'], [TUN_PEER4], {});
  dns.splice(0, dns.length, TUN_PEER4, TUN_PEER6);
  await first.stop({ keepDns: true });
  const second = singbox(userData);
  await second.start(10808, ['203.0.113.7'], [TUN_PEER4], {});
  assert.deepEqual(second.macState.savedDns, ['192.168.60.1']);
  // A plain stop restores; what happens after is the machine's own business.
  await second.stop();
  dns.splice(0, dns.length, TUN_PEER4);           // e.g. a crash left the peer behind
  const third = singbox(userData);
  await third.start(10808, ['203.0.113.7'], [TUN_PEER4], {});
  assert.deepEqual(third.macState.savedDns, [TUN_PEER4], 'no stale handover from a session that already started');
  await third.stop();
});

test('stopTrackedTunnels hands the stop options to every tunnel', async () => {
  const seen = [];
  const a = { stop: async (o) => { seen.push(['a', o]); } };
  const b = { stop: async (o) => { seen.push(['b', o]); } };
  await stopTrackedTunnels(new Set([a]), b, 'darwin', { keepDns: true });
  assert.deepEqual(seen, [['a', { keepDns: true }], ['b', { keepDns: true }]]);
  seen.length = 0;
  await stopTrackedTunnels(new Set([a]), null, 'win32', { keepDns: true });
  assert.deepEqual(seen, [['a', { keepDns: true }]]);
});

/* ------------------------------ tun2socks ------------------------------ */

test('tun2socks teardown: keepDns leaves the service\'s DNS alone; the default restores it; the next session keeps the originals', async (t) => {
  const real = os.platform;
  os.platform = () => 'darwin';
  t.after(() => { os.platform = real; });
  const userData = userDir(t);
  let dns = ['192.168.60.1'];
  const scripts = [];
  const make = () => {
    const m = new TunManager({ userData, lang: 'en', probe });
    m.tun2socksPath = () => '/test/tun2socks';
    m.getDefaultRouteMac = async () => ({ gateway: '192.168.1.1', device: 'en0' });
    m.serviceForDeviceMac = async () => 'Wi-Fi';
    m.getServiceDnsMac = async () => dns.slice();
    m.resolveServerIps = async () => ['203.0.113.7'];
    m.startMacLogTail = () => {};
    m.runScriptPrivileged = async (p) => {
      scripts.push([path.basename(p), fs.readFileSync(p, 'utf8')]);
      if (path.basename(p) === 'setup.sh') {
        fs.writeFileSync(m.macState.pidFile, '4242');
        fs.writeFileSync(m.macState.identityFile, 'Wed Sep 9 12:00:00 2026');
        fs.writeFileSync(m.macState.devFile, 'utun7');
        fs.writeFileSync(m.macState.dnsFile, '');
      }
    };
    return m;
  };
  const first = make();
  await first.start(10808, 'server', ['10.255.0.1']);
  const restore = first.macTeardownScript();
  const keep = first.macTeardownScript({ keepDns: true });
  assert.match(restore, /networksetup -setdnsservers 'Wi-Fi' '192\.168\.60\.1' \|\| exit 25/);
  assert.doesNotMatch(keep, /networksetup/);
  assert.deepEqual(keep.split('\n'), restore.split('\n').filter(l => !/networksetup/.test(l)), 'only the DNS line differs');

  dns = ['10.255.0.1'];
  await first.stop({ keepDns: true });
  assert.doesNotMatch(scripts[scripts.length - 1][1], /networksetup/);
  const second = make();
  await second.start(10808, 'server', ['10.255.0.1']);
  assert.deepEqual(second.macState.savedDns, ['192.168.60.1']);
  await second.stop();
  assert.match(scripts[scripts.length - 1][1], /networksetup -setdnsservers 'Wi-Fi' '192\.168\.60\.1'/);
});

test('tun2socks: a rebuild whose prompt was cancelled keeps the handed-over originals for the retry', async (t) => {
  const real = os.platform;
  os.platform = () => 'darwin';
  t.after(() => { os.platform = real; });
  const userData = userDir(t);
  let dns = ['192.168.60.1'];
  let fail = false;
  const make = () => {
    const m = new TunManager({ userData, lang: 'en', probe });
    m.tun2socksPath = () => '/test/tun2socks';
    m.getDefaultRouteMac = async () => ({ gateway: '192.168.1.1', device: 'en0' });
    m.serviceForDeviceMac = async () => 'Wi-Fi';
    m.getServiceDnsMac = async () => dns.slice();
    m.resolveServerIps = async () => ['203.0.113.7'];
    m.startMacLogTail = () => {};
    m.runScriptPrivileged = async (p) => {
      if (path.basename(p) !== 'setup.sh') return;
      if (fail) { fail = false; throw new Error('execution error: User canceled. (-128)'); }
      fs.writeFileSync(m.macState.pidFile, '4242');
      fs.writeFileSync(m.macState.identityFile, 'Wed Sep 9 12:00:00 2026');
      fs.writeFileSync(m.macState.devFile, 'utun7');
      fs.writeFileSync(m.macState.dnsFile, '');
    };
    return m;
  };
  const first = make();
  await first.start(10808, 'server', ['10.255.0.1']);
  dns = ['10.255.0.1'];
  await first.stop({ keepDns: true });
  fail = true;
  await assert.rejects(make().start(10808, 'server', ['10.255.0.1']), /administrator password/);
  const retry = make();
  await retry.start(10808, 'server', ['10.255.0.1']);
  assert.deepEqual(retry.macState.savedDns, ['192.168.60.1']);
  await retry.stop();
});

/* ------------------------------ main.js wiring ------------------------------ */

// main.js requires Electron at load, so the wiring is read as text.
// A Windows checkout with core.autocrlf hands it back with CRLF.
const MAIN = fs.readFileSync(path.join(__dirname, '..', 'src', 'main', 'main.js'), 'utf8').replace(/\r\n/g, '\n');

function body(source, head) {
  const start = source.indexOf(head);
  assert.notEqual(start, -1, `${head} is gone`);
  const end = source.indexOf('\n}\n', start);
  return source.slice(start, end);
}

test('main.js: a reconnect stops the tunnel with keepDns exactly when the guard is holding DNS', () => {
  const reapply = body(MAIN, 'async function reapplyConnection(');
  assert.match(reapply, /\bhold = await leakGuard\.holdForReconnect\(/, 'the hold result is kept');
  assert.match(reapply, /await stopAllTuns\(\{ keepDns: !!\(hold && hold\.held\) \}\);/);
  const stopAll = body(MAIN, 'async function stopAllTuns(');
  assert.match(stopAll, /stopTrackedTunnels\(startedTuns, tun, process\.platform, opts\)/);
  // A server switch under TUN rebuilds the tunnel in doConnect with the guard held too.
  const connect = body(MAIN, 'async function connectOnce(');   // doConnect became a thin wrapper around connectOnce (the drop budget)
  assert.match(connect, /await myTun\.stop\(\{ keepDns: !!\(hold && hold\.held\) \}\)/);
  // A disconnect restores: every other stopAllTuns() call passes nothing.
  assert.equal([...MAIN.matchAll(/stopAllTuns\(\{ keepDns/g)].length, 1);
});

test('service.js mirrors it: the headless reconnect keeps the held DNS on the main service too', () => {
  const SERVICE = fs.readFileSync(path.join(__dirname, '..', 'src', 'server', 'service.js'), 'utf8').replace(/\r\n/g, '\n');
  // service.js's functions sit one level deeper (inside createService)
  const inner = (head) => {
    const start = SERVICE.indexOf(head);
    assert.notEqual(start, -1, `${head} is gone`);
    return SERVICE.slice(start, SERVICE.indexOf('\n  }\n', start));
  };
  const reapply = inner('async function reapplyConnection(');
  assert.match(reapply, /\bhold = await leakGuard\.holdForReconnect\(/, 'the hold result is kept');
  assert.match(reapply, /await stopAllTuns\(\{ keepDns: !!\(hold && hold\.held\) \}\);/);
  assert.match(inner('async function stopAllTuns('), /stopTrackedTunnels\(startedTuns, tun, process\.platform, opts\)/);
  assert.equal([...SERVICE.matchAll(/stopAllTuns\(\{ keepDns/g)].length, 1, 'a disconnect and a shutdown restore');
  // …and a server switch under TUN (headless macOS), which rebuilds the tunnel inside doConnect with the guard held
  // (to its own end: a block inside it sits at the function's indentation)
  const from = SERVICE.indexOf('async function doConnect(');
  const connect = SERVICE.slice(from, SERVICE.indexOf('\n    return { ok: true, tunError };\n  }', from));
  assert.match(connect, /\bhold = await leakGuard\.holdForReconnect\(/, 'the switch keeps the hold result too');
  assert.match(connect, /if \(process\.platform === 'darwin'\) await myTun\.stop\(\{ keepDns: !!\(hold && hold\.held\) \}\);/);
});
