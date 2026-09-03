'use strict';
/**
 * The standard leak guard: the scripts it generates, what it parses back out of
 * them, and the state file that makes a crash repairable.
 *
 * Nothing here runs a command. `run`, `runScriptPrivileged` and `runSync` are
 * all injected, so no adapter on this machine is ever touched — the scripts are
 * pinned as text instead, which is the only review a PowerShell/networksetup
 * line gets before it runs as Administrator on someone's laptop.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const {
  LeakGuard, STATE_FILE,
  winSnapshotScript, parseWinSnapshot, winApplyScript, winRestoreScript,
  winOrphanKillScript, winRepairScript,
  macSnapshotScript, parseMacSnapshot, macApplyScript, macRestoreScript,
  macOrphanKillScript, macRepairScript
} = require('../src/main/leakGuard');

const PEER4 = '172.19.0.2';
const PEER6 = 'fdfe:dcba:9876::2';

/* ----------------------------- Windows: snapshot ----------------------------- */

test('winSnapshotScript skips our own adapters and the virtual ones, and prints JSON', () => {
  const lines = winSnapshotScript('IRNetFree').split('\n');
  assert.equal(lines[0], "$ErrorActionPreference = 'SilentlyContinue'");
  assert.equal(lines[1], '$out = @()');
  assert.equal(lines[2],
    'foreach ($a in @(Get-NetAdapter | Where-Object { $_.Status -eq \'Up\''
    + " -and $_.InterfaceAlias -ne 'IRNetFree'"
    + " -and $_.InterfaceAlias -ne 'XrayTun'"
    + " -and $_.InterfaceDescription -notmatch 'Wintun|TAP|Loopback|Hyper-V|VMware|VirtualBox|Bluetooth' })) {");
  assert.equal(lines[3],
    "$k4 = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\' + $a.InterfaceGuid");
  assert.equal(lines[4],
    "$k6 = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\Interfaces\\' + $a.InterfaceGuid");
  assert.equal(lines[5],
    '$out += [pscustomobject]@{ alias = $a.InterfaceAlias;'
    + ' v4 = @(Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses);'
    + ' v6 = @(Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv6 | Select-Object -ExpandProperty ServerAddresses);'
    + ' dhcp4 = [string]::IsNullOrWhiteSpace((Get-ItemProperty -Path $k4 -Name NameServer).NameServer);'
    + ' dhcp6 = [string]::IsNullOrWhiteSpace((Get-ItemProperty -Path $k6 -Name NameServer).NameServer) }');
  assert.equal(lines[6], '}');
  assert.equal(lines[7], 'ConvertTo-Json -InputObject @($out) -Depth 3 -Compress');
  assert.equal(lines.length, 8);
});

test('winSnapshotScript: both backends\' adapters are always excluded, a custom alias is added once', () => {
  // tun2socks is the live backend — its adapter is the passed one, and sing-box's
  // must be skipped too (the owner may have both installed).
  const t2s = winSnapshotScript('XrayTun');
  assert.equal((t2s.match(/-ne 'XrayTun'/g) || []).length, 1, 'no duplicated clause');
  assert.match(t2s, /-ne 'IRNetFree'/);
  const custom = winSnapshotScript("Bob's Wi-Fi");
  assert.match(custom, /-ne 'IRNetFree' -and \$_\.InterfaceAlias -ne 'XrayTun' -and \$_\.InterfaceAlias -ne 'Bob''s Wi-Fi'/);
  assert.match(winSnapshotScript(null), /-ne 'IRNetFree' -and \$_\.InterfaceAlias -ne 'XrayTun' -and \$_\.InterfaceDescription/);
});

test('parseWinSnapshot reads the adapter list ConvertTo-Json produces', () => {
  const json = JSON.stringify([
    { alias: 'Wi-Fi', v4: ['192.168.8.1'], v6: ['fe80::1'], dhcp4: true, dhcp6: true },
    { alias: 'Ethernet', v4: ['178.22.122.100', '185.51.200.2'], v6: [], dhcp4: false, dhcp6: true }
  ]);
  assert.deepEqual(parseWinSnapshot(json), [
    { alias: 'Wi-Fi', v4: ['192.168.8.1'], v6: ['fe80::1'], dhcp4: true, dhcp6: true },
    { alias: 'Ethernet', v4: ['178.22.122.100', '185.51.200.2'], v6: [], dhcp4: false, dhcp6: true }
  ]);
});

test('parseWinSnapshot survives what PowerShell does to a one-element array and an empty one', () => {
  // PowerShell 5.1 unwraps a single object out of ConvertTo-Json in some paths.
  assert.deepEqual(parseWinSnapshot('{"alias":"Wi-Fi","v4":"192.168.8.1","v6":null}'),
    [{ alias: 'Wi-Fi', v4: ['192.168.8.1'], v6: [] }], 'a bare object and a bare string address');
  assert.deepEqual(parseWinSnapshot(''), [], 'no adapters: no output at all');
  assert.deepEqual(parseWinSnapshot('null'), [], 'ConvertTo-Json of an empty array');
  assert.deepEqual(parseWinSnapshot('[]'), []);
  assert.deepEqual(parseWinSnapshot('Get-NetAdapter : Access denied'), [], 'an error instead of JSON is not a crash');
  assert.deepEqual(parseWinSnapshot(null), []);
  assert.deepEqual(parseWinSnapshot('[{"v4":["1.1.1.1"]},{"alias":"  "}]'), [], 'an entry with no alias is dropped');
  assert.deepEqual(parseWinSnapshot('[{"alias":"Wi-Fi","v4":["1.1.1.1",""," 8.8.8.8 "]}]'),
    [{ alias: 'Wi-Fi', v4: ['1.1.1.1', '8.8.8.8'], v6: [] }], 'blank addresses dropped, the rest trimmed');
});

/* ----------------------------- Windows: apply / restore ----------------------------- */

test('winApplyScript points every adapter at the tunnel peer in one script', () => {
  const adapters = [{ alias: 'Wi-Fi' }, { alias: "Bob's Ethernet" }];
  assert.equal(winApplyScript(adapters, PEER4, PEER6), [
    "$ErrorActionPreference = 'Stop'",
    "Set-DnsClientServerAddress -InterfaceAlias 'Wi-Fi' -ServerAddresses '172.19.0.2'",
    "Set-DnsClientServerAddress -InterfaceAlias 'Wi-Fi' -ServerAddresses 'fdfe:dcba:9876::2'",
    "Set-DnsClientServerAddress -InterfaceAlias 'Bob''s Ethernet' -ServerAddresses '172.19.0.2'",
    "Set-DnsClientServerAddress -InterfaceAlias 'Bob''s Ethernet' -ServerAddresses 'fdfe:dcba:9876::2'",
    'Clear-DnsClientCache'
  ].join('\n'));
});

test('winApplyScript leaves IPv6 alone when there is no v6 peer', () => {
  assert.equal(winApplyScript([{ alias: 'Wi-Fi' }], PEER4, null), [
    "$ErrorActionPreference = 'Stop'",
    "Set-DnsClientServerAddress -InterfaceAlias 'Wi-Fi' -ServerAddresses '172.19.0.2'",
    'Clear-DnsClientCache'
  ].join('\n'));
});

test('winRestoreScript resets to DHCP first, then puts back only what was static', () => {
  // Set-DnsClientServerAddress has no -AddressFamily: -ResetServerAddresses puts
  // BOTH families back on DHCP, so the statically configured lists are re-applied
  // after it. Without that, a machine with static v4 + automatic v6 would keep
  // our peer as its v6 resolver forever.
  const adapters = [
    { alias: 'Wi-Fi', v4: ['192.168.8.1'], v6: ['fe80::1'], dhcp4: true, dhcp6: true },
    { alias: 'Ethernet', v4: ['178.22.122.100', '185.51.200.2'], v6: ['2606:4700::1111'], dhcp4: false, dhcp6: false },
    { alias: 'Mixed', v4: ['9.9.9.9'], v6: ['fe80::2'], dhcp4: false, dhcp6: true }
  ];
  assert.equal(winRestoreScript(adapters), [
    "$ErrorActionPreference = 'Stop'",
    "if (Get-NetAdapter -InterfaceAlias 'Wi-Fi' -ErrorAction SilentlyContinue) {",
    "Set-DnsClientServerAddress -InterfaceAlias 'Wi-Fi' -ResetServerAddresses",
    '}',
    "if (Get-NetAdapter -InterfaceAlias 'Ethernet' -ErrorAction SilentlyContinue) {",
    "Set-DnsClientServerAddress -InterfaceAlias 'Ethernet' -ResetServerAddresses",
    "Set-DnsClientServerAddress -InterfaceAlias 'Ethernet' -ServerAddresses '178.22.122.100','185.51.200.2'",
    "Set-DnsClientServerAddress -InterfaceAlias 'Ethernet' -ServerAddresses '2606:4700::1111'",
    '}',
    "if (Get-NetAdapter -InterfaceAlias 'Mixed' -ErrorAction SilentlyContinue) {",
    "Set-DnsClientServerAddress -InterfaceAlias 'Mixed' -ResetServerAddresses",
    "Set-DnsClientServerAddress -InterfaceAlias 'Mixed' -ServerAddresses '9.9.9.9'",
    '}',
    'Clear-DnsClientCache'
  ].join('\n'));
});

test('winRestoreScript: no recorded servers at all is a plain reset', () => {
  assert.equal(winRestoreScript([{ alias: 'Wi-Fi', v4: [], v6: [] }]), [
    "$ErrorActionPreference = 'Stop'",
    "if (Get-NetAdapter -InterfaceAlias 'Wi-Fi' -ErrorAction SilentlyContinue) {",
    "Set-DnsClientServerAddress -InterfaceAlias 'Wi-Fi' -ResetServerAddresses",
    '}',
    'Clear-DnsClientCache'
  ].join('\n'));
  // No dhcp flags recorded (a hand-edited state file): "originals present" wins.
  assert.match(winRestoreScript([{ alias: 'Wi-Fi', v4: ['1.1.1.1'] }]),
    /-ResetServerAddresses\nSet-DnsClientServerAddress -InterfaceAlias 'Wi-Fi' -ServerAddresses '1\.1\.1\.1'/);
  assert.equal(winRestoreScript([]), ["$ErrorActionPreference = 'Stop'", 'Clear-DnsClientCache'].join('\n'));
});

/* ----------------------------- orphan tunnel process ----------------------------- */

test('winOrphanKillScript kills a stray tunnel by its argv and names each one', () => {
  assert.equal(winOrphanKillScript(), [
    "$ErrorActionPreference = 'SilentlyContinue'",
    "foreach ($p in @(Get-CimInstance Win32_Process -Filter 'Name=''sing-box.exe''' | Where-Object { $_.CommandLine -like '*irnf-sb-*' })) "
      + "{ Write-Output ('killed sing-box (pid ' + $p.ProcessId + ')'); Stop-Process -Id $p.ProcessId -Force }",
    "foreach ($p in @(Get-CimInstance Win32_Process -Filter 'Name=''tun2socks.exe''' | Where-Object { $_.CommandLine -like '*-device XrayTun*' })) "
      + "{ Write-Output ('killed tun2socks (pid ' + $p.ProcessId + ')'); Stop-Process -Id $p.ProcessId -Force }"
  ].join('\n'));
});

test('winRepairScript is the orphan kill followed by the restore, in one spawn', () => {
  const adapters = [{ alias: 'Wi-Fi', v4: ['192.168.8.1'], dhcp4: true }];
  assert.equal(winRepairScript(adapters), winOrphanKillScript() + '\n' + winRestoreScript(adapters));
});

test('macOrphanKillScript kills a stray tunnel by its argv', () => {
  assert.equal(macOrphanKillScript(), [
    '#!/bin/bash',
    'FAIL=0',
    'for p in $(pgrep -f \'sing-box run -c .*irnf-sb-\' 2>/dev/null); do echo "killed sing-box (pid $p)"; kill -TERM "$p" 2>/dev/null || true; done',
    'for p in $(pgrep -f \'[-]device utun\' 2>/dev/null); do echo "killed tun2socks (pid $p)"; kill -TERM "$p" 2>/dev/null || true; done',
    'exit $FAIL',
    ''
  ].join('\n'));
});

/* ----------------------------- macOS ----------------------------- */

test('macSnapshotScript walks every enabled service and prints "name<TAB>servers"', () => {
  assert.equal(macSnapshotScript(), [
    '#!/bin/bash',
    'FAIL=0',
    'networksetup -listallnetworkservices 2>/dev/null | tail -n +2 | while IFS= read -r svc; do',
    "  case \"$svc\" in ''|\\**) continue;; esac",
    '  dns="$(networksetup -getdnsservers "$svc" 2>/dev/null)"',
    '  case "$dns" in',
    "    *'any DNS Servers'*) printf '%s\\t\\n' \"$svc\";;",
    "    *) printf '%s\\t%s\\n' \"$svc\" \"$(printf '%s' \"$dns\" | tr '\\n' ' ')\";;",
    '  esac',
    'done',
    'exit $FAIL',
    ''
  ].join('\n'));
});

test('parseMacSnapshot splits on the tab and keeps services with no servers set', () => {
  const out = [
    'Wi-Fi\t192.168.8.1 2606:4700::1111 ',
    'Ethernet\t',
    'Thunderbolt Bridge\t178.22.122.100',
    '',
    'Broken line with no tab'
  ].join('\n');
  assert.deepEqual(parseMacSnapshot(out), [
    { name: 'Wi-Fi', dns: ['192.168.8.1', '2606:4700::1111'] },
    { name: 'Ethernet', dns: [] },
    { name: 'Thunderbolt Bridge', dns: ['178.22.122.100'] }
  ]);
  assert.deepEqual(parseMacSnapshot(''), []);
  assert.deepEqual(parseMacSnapshot(null), []);
});

test('macApplyScript sets every service to the peers and flushes the cache', () => {
  const services = [{ name: 'Wi-Fi', dns: ['192.168.8.1'] }, { name: "Bob's Net", dns: [] }];
  assert.equal(macApplyScript(services, PEER4, PEER6), [
    '#!/bin/bash',
    'FAIL=0',
    "networksetup -setdnsservers 'Wi-Fi' 172.19.0.2 fdfe:dcba:9876::2 || FAIL=1",
    "networksetup -setdnsservers 'Bob'\\''s Net' 172.19.0.2 fdfe:dcba:9876::2 || FAIL=1",
    'dscacheutil -flushcache 2>/dev/null || true',
    'killall -HUP mDNSResponder 2>/dev/null || true',
    'exit $FAIL',
    ''
  ].join('\n'));
  assert.match(macApplyScript([{ name: 'Wi-Fi' }], PEER4, null),
    /networksetup -setdnsservers 'Wi-Fi' 172\.19\.0\.2 \|\| FAIL=1/);
});

test('macRestoreScript puts the recorded servers back, "Empty" where there were none', () => {
  const services = [
    { name: 'Wi-Fi', dns: ['192.168.8.1', '2606:4700::1111'] },
    { name: 'Ethernet', dns: [] }
  ];
  assert.equal(macRestoreScript(services), [
    '#!/bin/bash',
    'FAIL=0',
    "networksetup -setdnsservers 'Wi-Fi' 192.168.8.1 2606:4700::1111 || FAIL=1",
    "networksetup -setdnsservers 'Ethernet' Empty || FAIL=1",
    'dscacheutil -flushcache 2>/dev/null || true',
    'killall -HUP mDNSResponder 2>/dev/null || true',
    'exit $FAIL',
    ''
  ].join('\n'));
});

test('macRepairScript is one script: the orphan kill and then the restore (one password prompt)', () => {
  const services = [{ name: 'Wi-Fi', dns: [] }];
  const repair = macRepairScript(services).split('\n');
  const orphan = macOrphanKillScript().split('\n');
  const restore = macRestoreScript(services).split('\n');
  assert.deepEqual(repair, ['#!/bin/bash', 'FAIL=0', ...orphan.slice(2, -2), ...restore.slice(2, -2), 'exit $FAIL', '']);
});

/* ----------------------------- the class ----------------------------- */

const tmpDirs = [];
test.after(() => { for (const d of tmpDirs) { try { fs.rmSync(d, { recursive: true, force: true }); } catch {} } });

function harness(platform, answer) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-lg-test-'));
  tmpDirs.push(dir);
  const statePath = path.join(dir, STATE_FILE);
  const calls = [];
  const logs = [];
  const record = (cmd, args, script, sync) => {
    calls.push({ cmd, args, script, sync: !!sync, stateExists: fs.existsSync(statePath) });
  };
  const reply = (cmd, args) => {
    const out = answer ? answer(cmd, args) : '';
    if (out instanceof Error) throw out;
    return out == null ? '' : out;
  };
  const guard = new LeakGuard({
    userData: dir,
    platform,
    onLog: (line, level) => logs.push([line, level]),
    run: async (cmd, args) => { record(cmd, args, args[args.length - 1]); return reply(cmd, args); },
    runScriptPrivileged: async (p) => {
      record('privileged', [p], fs.readFileSync(p, 'utf8'));
      return reply('privileged', [p]);
    },
    runSync: (cmd, args) => { record(cmd, args, args[args.length - 1], true); return reply(cmd, args); }
  });
  return { guard, dir, statePath, calls, logs, state: () => JSON.parse(fs.readFileSync(statePath, 'utf8')) };
}

const WIN_SNAP = JSON.stringify([
  { alias: 'Wi-Fi', v4: ['192.168.8.1'], v6: [], dhcp4: true, dhcp6: true },
  { alias: 'Ethernet', v4: ['178.22.122.100'], v6: [], dhcp4: false, dhcp6: true }
]);

test('engage: level "off" changes nothing and leaves no state file', async () => {
  const h = harness('win32', () => WIN_SNAP);
  const r = await h.guard.engage({ level: 'off', peer4: PEER4, tunAlias: 'IRNetFree' });
  assert.equal(r.engaged, false);
  assert.equal(h.calls.length, 0, 'not even the snapshot runs');
  assert.equal(fs.existsSync(h.statePath), false);
});

test('engage (win32): snapshot, then the state file, THEN the apply', async () => {
  const h = harness('win32', (cmd, args) => (/ConvertTo-Json/.test(args[args.length - 1]) ? WIN_SNAP : ''));
  const r = await h.guard.engage({ level: 'standard', peer4: PEER4, peer6: PEER6, tunAlias: 'IRNetFree', backend: 'sing-box' });
  assert.equal(r.engaged, true);
  assert.equal(r.adapters, 2);
  assert.equal(h.calls.length, 2);
  assert.equal(h.calls[0].cmd, 'powershell');
  assert.deepEqual(h.calls[0].args.slice(0, 3), ['-NoProfile', '-NonInteractive', '-Command']);
  assert.equal(h.calls[0].script, winSnapshotScript('IRNetFree'));
  assert.equal(h.calls[0].stateExists, false, 'nothing is recorded before we know what to record');
  assert.equal(h.calls[1].script, winApplyScript([{ alias: 'Wi-Fi' }, { alias: 'Ethernet' }], PEER4, PEER6));
  assert.equal(h.calls[1].stateExists, true,
    'the originals are on disk BEFORE the first adapter is changed — a crash between the two must be repairable');

  const st = h.state();
  assert.equal(st.version, 1);
  assert.equal(st.backend, 'sing-box');
  assert.equal(st.peer4, PEER4);
  assert.equal(st.peer6, PEER6);
  assert.equal(st.tunAlias, 'IRNetFree');
  assert.match(st.at, /^\d{4}-\d{2}-\d{2}T/);
  assert.deepEqual(st.win.adapters, parseWinSnapshot(WIN_SNAP));
  assert.deepEqual(h.logs, [[`Leak guard: DNS of 2 adapters → ${PEER4} ${PEER6}`, 'info']]);
});

test('engage (win32): no physical adapter is nothing to guard — no state file, no apply', async () => {
  const h = harness('win32', () => '[]');
  const r = await h.guard.engage({ level: 'standard', peer4: PEER4, tunAlias: 'IRNetFree' });
  assert.equal(r.engaged, false);
  assert.equal(h.calls.length, 1, 'the snapshot only');
  assert.equal(fs.existsSync(h.statePath), false);
  assert.match(h.logs[0][0], /no physical adapter/i);
});

test('engage (win32): a failing apply keeps the state file so the next release can undo it', async () => {
  const h = harness('win32', (cmd, args) => (/ConvertTo-Json/.test(args[args.length - 1])
    ? WIN_SNAP
    : new Error('Access is denied.')));
  await assert.rejects(
    () => h.guard.engage({ level: 'standard', peer4: PEER4, tunAlias: 'IRNetFree' }),
    /Access is denied/);
  assert.equal(fs.existsSync(h.statePath), true, 'a half-applied override is exactly what the file exists for');
});

test('engage (darwin): one privileged run with the apply script, state file first', async () => {
  const h = harness('darwin', (cmd) => (cmd === '/bin/bash' ? 'Wi-Fi\t192.168.8.1\nEthernet\t' : ''));
  const r = await h.guard.engage({ level: 'standard', peer4: PEER4, peer6: null, tunAlias: 'utun4' });
  assert.equal(r.adapters, 2);
  assert.equal(h.calls.length, 2);
  assert.deepEqual(h.calls[0].args.slice(0, 1), ['-c'], 'the read-only snapshot needs no password');
  assert.equal(h.calls[0].cmd, '/bin/bash');
  assert.equal(h.calls[0].script, macSnapshotScript());
  assert.equal(h.calls[1].cmd, 'privileged');
  assert.equal(h.calls[1].stateExists, true);
  assert.equal(h.calls[1].script, macApplyScript(
    [{ name: 'Wi-Fi', dns: ['192.168.8.1'] }, { name: 'Ethernet', dns: [] }], PEER4, null));
  assert.deepEqual(h.state().mac.services, [
    { name: 'Wi-Fi', dns: ['192.168.8.1'] }, { name: 'Ethernet', dns: [] }
  ]);
});

test('engage (linux): says it cannot and touches nothing', async () => {
  const h = harness('linux', () => '');
  const r = await h.guard.engage({ level: 'standard', peer4: PEER4, tunAlias: 'IRNetFree' });
  assert.equal(r.engaged, false);
  assert.equal(h.calls.length, 0);
  assert.equal(fs.existsSync(h.statePath), false);
  assert.match(h.logs[0][0], /Linux/);
});

test('release: no state file is a no-op, and it can be called twice', async () => {
  const h = harness('win32', () => '');
  assert.deepEqual(await h.guard.release(), { released: false, adapters: 0 });
  assert.deepEqual(await h.guard.release(), { released: false, adapters: 0 });
  assert.equal(h.calls.length, 0);
  assert.deepEqual(h.logs, []);
});

test('release (win32): restores the recorded originals and deletes the state file', async () => {
  const h = harness('win32', (cmd, args) => (/ConvertTo-Json/.test(args[args.length - 1]) ? WIN_SNAP : ''));
  await h.guard.engage({ level: 'standard', peer4: PEER4, tunAlias: 'IRNetFree' });
  h.calls.length = 0; h.logs.length = 0;

  const r = await h.guard.release();
  assert.deepEqual(r, { released: true, adapters: 2 });
  assert.equal(h.calls.length, 1, 'one spawn, not one per adapter');
  assert.equal(h.calls[0].script, winRestoreScript(parseWinSnapshot(WIN_SNAP)),
    'no orphan kill on a normal disconnect — the tunnel is ours and still running');
  assert.equal(fs.existsSync(h.statePath), false);
  assert.deepEqual(h.logs, [['Leak guard released: DNS of 2 adapters restored', 'info']]);
});

test('release: a failing restore keeps the state file for the next launch', async () => {
  const h = harness('win32', (cmd, args) => (/ConvertTo-Json/.test(args[args.length - 1])
    ? WIN_SNAP
    : (/Set-DnsClientServerAddress/.test(args[args.length - 1]) && /ResetServerAddresses/.test(args[args.length - 1])
      ? new Error('Access is denied.') : '')));
  await h.guard.engage({ level: 'standard', peer4: PEER4, tunAlias: 'IRNetFree' });
  h.logs.length = 0;
  const r = await h.guard.release();
  assert.equal(r.released, false);
  assert.equal(fs.existsSync(h.statePath), true);
  assert.equal(h.logs[0][1], 'error');
  assert.match(h.logs[0][0], /Access is denied/);
});

test('repairAtLaunch: nothing to repair when the last session shut down cleanly', async () => {
  const h = harness('win32', () => '');
  assert.deepEqual(await h.guard.repairAtLaunch(), { repaired: false, adapters: 0 });
  assert.equal(h.calls.length, 0, 'no state file → no orphan hunt either');
  assert.deepEqual(h.logs, []);
});

test('repairAtLaunch (win32): kills the orphan tunnel, restores the DNS, clears the file', async () => {
  const h = harness('win32', (cmd, args) => (/ConvertTo-Json/.test(args[args.length - 1])
    ? WIN_SNAP
    : 'killed sing-box (pid 4242)\r\n'));
  await h.guard.engage({ level: 'standard', peer4: PEER4, tunAlias: 'IRNetFree' });
  h.calls.length = 0; h.logs.length = 0;

  const r = await h.guard.repairAtLaunch();
  assert.deepEqual(r, { repaired: true, adapters: 2 });
  assert.equal(h.calls.length, 1, 'the orphan kill and the restore are one script');
  assert.equal(h.calls[0].script, winRepairScript(parseWinSnapshot(WIN_SNAP)));
  assert.equal(fs.existsSync(h.statePath), false);
  assert.deepEqual(h.logs, [
    ['A previous session did not shut down cleanly — putting the network back', 'warn'],
    ['killed sing-box (pid 4242)', 'warn'],
    ['Restored DNS of 2 adapters left from a previous session', 'info']
  ]);
});

test('repairAtLaunch (darwin): one privileged script does both', async () => {
  const h = harness('darwin', (cmd) => (cmd === '/bin/bash' ? 'Wi-Fi\t192.168.8.1' : 'killed sing-box (pid 77)\n'));
  await h.guard.engage({ level: 'standard', peer4: PEER4, tunAlias: 'utun4' });
  h.calls.length = 0; h.logs.length = 0;

  await h.guard.repairAtLaunch();
  assert.equal(h.calls.length, 1);
  assert.equal(h.calls[0].cmd, 'privileged');
  assert.equal(h.calls[0].script, macRepairScript([{ name: 'Wi-Fi', dns: ['192.168.8.1'] }]));
  assert.equal(fs.existsSync(h.statePath), false);
  assert.ok(h.logs.some(([l]) => l === 'killed sing-box (pid 77)'));
});

test('releaseSync (win32): one bounded PowerShell restore, then the file is gone', async () => {
  const h = harness('win32', (cmd, args) => (/ConvertTo-Json/.test(args[args.length - 1]) ? WIN_SNAP : ''));
  await h.guard.engage({ level: 'standard', peer4: PEER4, tunAlias: 'IRNetFree' });
  h.calls.length = 0;

  assert.equal(h.guard.releaseSync(), true);
  assert.equal(h.calls.length, 1);
  assert.equal(h.calls[0].sync, true);
  assert.equal(h.calls[0].cmd, 'powershell');
  assert.equal(h.calls[0].script, winRestoreScript(parseWinSnapshot(WIN_SNAP)));
  assert.equal(fs.existsSync(h.statePath), false);
});

test('releaseSync never throws, and keeps the state file when the restore failed', async () => {
  const h = harness('win32', (cmd, args) => (/ConvertTo-Json/.test(args[args.length - 1])
    ? WIN_SNAP
    : new Error('powershell is not recognized')));
  await h.guard.engage({ level: 'standard', peer4: PEER4, tunAlias: 'IRNetFree' }).catch(() => {});
  assert.equal(h.guard.releaseSync(), false, 'process exit is no place for an exception');
  assert.equal(fs.existsSync(h.statePath), true, 'the next launch repairs it');
});

test('releaseSync (darwin) does nothing unless we are already root — it cannot prompt', async () => {
  const h = harness('darwin', (cmd) => (cmd === '/bin/bash' ? 'Wi-Fi\t192.168.8.1' : ''));
  await h.guard.engage({ level: 'standard', peer4: PEER4, tunAlias: 'utun4' });
  h.calls.length = 0;
  const root = !!(process.getuid && process.getuid() === 0);
  assert.equal(h.guard.releaseSync(), root);
  if (!root) {
    assert.equal(h.calls.length, 0);
    assert.equal(fs.existsSync(h.statePath), true, 'the graceful teardown (or the next launch) does it');
  }
});

test('operations are serialized: a repair in flight cannot delete the file a new engage just wrote', async () => {
  let release = null;
  const gate = new Promise((r) => { release = r; });
  let hang = false;
  const h = harness('win32', (cmd, args) => {
    if (/ConvertTo-Json/.test(args[args.length - 1])) return WIN_SNAP;
    if (hang) { hang = false; return gate; }   // the repair's restore hangs
    return '';
  });
  await h.guard.engage({ level: 'standard', peer4: PEER4, tunAlias: 'IRNetFree' });
  h.calls.length = 0;
  hang = true;

  const repairing = h.guard.repairAtLaunch();
  const engaging = h.guard.engage({ level: 'standard', peer4: PEER4, tunAlias: 'IRNetFree' });
  release('');
  await repairing;
  await engaging;
  assert.equal(fs.existsSync(h.statePath), true, 'the live session\'s originals survived the repair');
  assert.deepEqual(h.state().win.adapters, parseWinSnapshot(WIN_SNAP));
});
