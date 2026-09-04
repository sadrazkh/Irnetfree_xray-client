'use strict';
/**
 * The macOS matrix, run on every platform.
 *
 * Nobody on this project has a Mac, so every decision the code takes from
 * `platform === 'darwin'` that CAN be driven from a parameter is driven here:
 * the executable names, what counts as installed, the sing-box backend's
 * binary lookup and its first refusal, the utun recognition the network
 * watcher's fingerprint depends on, and the constants scripts/mac-selfcheck.sh
 * copies by hand. Nothing here spawns a process (the one `bash -n` is skipped
 * on Windows, where `bash` may be a WSL stub).
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const { ENGINES, engineExe } = require('../src/main/engines');
const { assetStatus } = require('../src/main/assets');
const { TunSingbox, TUN_PEER4, TUN_PEER6, buildMacSetupScript } = require('../src/main/tunSingbox');
const { isOwnTunInterface } = require('../src/main/tunPlatform');
const { fingerprint } = require('../src/main/netWatcher');
const { STATE_FILE } = require('../src/main/leakGuard');

const SELFCHECK = path.join(__dirname, '..', 'scripts', 'mac-selfcheck.sh');

function tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-darwin-')); }
function rm(d) { try { fs.rmSync(d, { recursive: true, force: true }); } catch {} }
function touch(dir, names) { for (const n of names) fs.writeFileSync(path.join(dir, n), ''); }

test('darwin: every engine runs under its bare name — no .exe anywhere', () => {
  for (const id of Object.keys(ENGINES)) {
    const exe = engineExe(id, 'darwin');
    assert.equal(exe, ENGINES[id].exe.default, id);
    assert.doesNotMatch(exe, /\.exe$/i, id);
  }
  assert.deepEqual(Object.keys(ENGINES).map(id => engineExe(id, 'darwin')), ['xray', 'xray-pattn', 'sing-box']);
});

test('darwin: a bin dir full of Windows files counts for nothing; the macOS names count for everything', () => {
  const d = tmp();
  try {
    touch(d, ['xray.exe', 'xray-pattn.exe', 'sing-box.exe', 'tun2socks.exe', 'wintun.dll']);
    let st = assetStatus([d], 'darwin');
    assert.equal(st.platform, 'darwin');
    for (const k of ['xray', 'xray-pattn', 'sing-box', 'tun2socks']) assert.equal(st[k], false, k + ' must not see the .exe');
    assert.equal(st.wintun, true, 'wintun is a Windows-only need');
    assert.equal(st.tunReady, false, 'no backend for this platform is installed');

    touch(d, ['xray', 'sing-box', 'geoip.dat', 'geosite.dat']);
    st = assetStatus([d], 'darwin');
    assert.equal(st.xray, true);
    assert.equal(st['sing-box'], true);
    assert.equal(st['xray-pattn'], false);
    assert.equal(st.tunReady, true, 'sing-box alone is a TUN backend off Windows');
    assert.equal(st.geoip && st.geosite, true);
  } finally { rm(d); }
});

test('darwin: the sing-box backend finds `sing-box`, ignores `sing-box.exe`, and wants no wintun', () => {
  const d = tmp();
  try {
    touch(d, ['sing-box.exe']);
    const win = new TunSingbox({ binDir: d, platform: 'win32' });
    const mac = new TunSingbox({ binDir: d, platform: 'darwin' });
    assert.equal(path.basename(win.singboxPath()), 'sing-box.exe');
    assert.equal(mac.singboxPath(), null, 'a Windows binary is not a macOS binary');
    assert.equal(mac.isAvailable(), false);

    touch(d, ['sing-box']);
    assert.equal(mac.singboxPath(), path.join(d, 'sing-box'));
    assert.equal(mac.isAvailable(), true, 'no wintun.dll asked for off Windows');
    assert.equal(win.isAvailable(), false, 'Windows still wants wintun next to it');
    assert.equal(mac.isElevated(), true, 'the osascript prompt stands in for admin rights');
  } finally { rm(d); }
});

test('darwin: start() without the binary refuses in English or Persian, names `sing-box`, and runs nothing', async () => {
  const d = tmp();
  try {
    const en = new TunSingbox({ binDir: d, platform: 'darwin', lang: 'en' });
    await assert.rejects(en.start(10808, ['1.2.3.4'], [TUN_PEER4], {}), /^Error: sing-box not found — put it in the bin folder/);
    assert.doesNotMatch(await en.start(10808, [], [], {}).catch(e => e.message), /\.exe/, 'the Windows name must not surface on a Mac');
    const fa = new TunSingbox({ binDir: d, platform: 'darwin' });
    await assert.rejects(fa.start(10808, [], [], {}), /sing-box پیدا نشد/);
    assert.equal(en.active, false);
    assert.equal(en.proc, null);
    assert.equal(en.macState, null, 'nothing privileged was even prepared');
  } finally { rm(d); }
});

test('darwin: whatever utun unit the kernel hands out is ours to ignore; the physical interfaces are not', () => {
  for (const n of ['utun0', 'utun3', 'utun12', 'utun', 'UTUN5']) assert.equal(isOwnTunInterface(n), true, n);
  for (const n of ['en0', 'en1', 'awdl0', 'llw0', 'bridge100', 'lo0', 'utun0x', 'xutun1', 'ap1']) assert.equal(isOwnTunInterface(n), false, n);
});

test('darwin: a tunnel rebuilt on the next utun unit is not a network change — a Wi-Fi move is', () => {
  const v4 = (address) => [{ address, family: 'IPv4', internal: false, netmask: '255.255.255.0' }];
  const base = { lo0: [{ address: '127.0.0.1', family: 'IPv4', internal: true }], en0: v4('192.168.1.20') };
  const before = Object.assign({}, base, { utun3: v4('172.19.0.1') });
  const after = Object.assign({}, base, { utun4: v4('172.19.0.1') });
  assert.equal(fingerprint(before, isOwnTunInterface), fingerprint(after, isOwnTunInterface));
  assert.notEqual(fingerprint(before), fingerprint(after), 'without the predicate the unit change would look like a move');
  const moved = Object.assign({}, after, { en0: v4('10.0.0.7') });
  assert.notEqual(fingerprint(after, isOwnTunInterface), fingerprint(moved, isOwnTunInterface));
});

test('darwin: the setup script quotes a service name with a space and writes both peers', () => {
  const s = buildMacSetupScript({
    bin: '/Applications/IRNetFree.app/Contents/Resources/bin/sing-box', cfgFile: '/tmp/x/c.json',
    logFile: '/tmp/x/l', pidFile: '/tmp/x/p', devFile: '/tmp/x/d',
    service: 'Thunderbolt Bridge', dnsServers: [TUN_PEER4, TUN_PEER6]
  });
  assert.ok(s.includes(`networksetup -setdnsservers 'Thunderbolt Bridge' ${TUN_PEER4} ${TUN_PEER6} 2>/dev/null || true`));
});

test('darwin: the self-check script carries the same peers and state file, in bash 3.2', () => {
  // a Windows checkout with core.autocrlf on hands the file back with CRLF
  const script = fs.readFileSync(SELFCHECK, 'utf8').replace(/\r\n/g, '\n');
  assert.equal((script.match(/^PEER4='([^']+)'/m) || [])[1], TUN_PEER4, 'PEER4 drifted from tunSingbox.TUN_PEER4');
  assert.equal((script.match(/^PEER6='([^']+)'/m) || [])[1], TUN_PEER6, 'PEER6 drifted from tunSingbox.TUN_PEER6');
  assert.ok(script.includes('/' + STATE_FILE), 'the leak guard state file it looks for is the one leakGuard.js writes');
  assert.ok(script.startsWith('#!/bin/bash\n'));
  // stock macOS ships bash 3.2: none of these may appear in CODE (the header
  // comment names them as the things to avoid, so comment lines are skipped)
  const code = script.split('\n').filter(l => !/^\s*#/.test(l)).join('\n');
  assert.doesNotMatch(code, /declare -A|mapfile|readarray|\$\{[A-Za-z_]+\^\^\}|\$\{[A-Za-z_]+,,\}/);
  if (process.platform !== 'win32') execFileSync('bash', ['-n', SELFCHECK], { stdio: 'ignore' });
});
