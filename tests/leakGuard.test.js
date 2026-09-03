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
  LeakGuard, STATE_FILE, GUARD_EXCLUDES, rangeComplement, withoutPeers,
  winSnapshotScript, parseWinSnapshot, winApplyScript, winRestoreScript,
  winOrphanKillScript, winRepairScript, winReleaseScript,
  winStrictApplyScript, winGroupRemoveScript, winUdpBlockApplyScript,
  macSnapshotScript, parseMacSnapshot, macApplyScript, macRestoreScript,
  macOrphanKillScript, macRepairScript, macReleaseScript,
  macPfAnchorText, macPfApplyScript, macPfRemoveScript
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
    // quoted: the addresses came off the machine and this runs as root
    "networksetup -setdnsservers 'Wi-Fi' '192.168.8.1' '2606:4700::1111' || FAIL=1",
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

/* ============================ level: strict ============================ */
/*
 * Standard stops DNS from leaving through the physical adapters; strict stops
 * everything that is not the tunnel. The scripts below are the only review
 * these lines get before they run as Administrator — none of them is executed
 * here (the owner's own tunnel is live on this machine, and a wrong outbound
 * block would cut it).
 */

/** The complement of the default exclude set, worked out by hand once. */
const DEFAULT_RANGES = [
  '0.0.0.0-9.255.255.255',          // ends where 10/8 begins
  '11.0.0.0-100.63.255.255',        // ends where the CGNAT 100.64/10 begins
  '100.128.0.0-126.255.255.255',    // ends where 127/8 begins
  '128.0.0.0-169.253.255.255',      // ends where link-local 169.254/16 begins
  '169.255.0.0-172.15.255.255',     // ends where 172.16/12 begins (the TUN subnet is inside it)
  '172.32.0.0-192.167.255.255',     // ends where 192.168/16 begins
  '192.169.0.0-223.255.255.255',    // ends where multicast 224/4 begins
  // the reserved tail, stopping one short: 255.255.255.255 is the DHCP limited
  // broadcast, and a machine that cannot renew its lease loses its address
  '240.0.0.0-255.255.255.254'
];

const psRanges = (list) => list.map(r => `'${r}'`).join(',');

test('rangeComplement: nothing excluded is the whole address space', () => {
  assert.deepEqual(rangeComplement([]), ['0.0.0.0-255.255.255.255']);
  assert.deepEqual(rangeComplement(null), ['0.0.0.0-255.255.255.255']);
});

test('rangeComplement: one host splits the space in two', () => {
  assert.deepEqual(rangeComplement(['5.6.7.8']), ['0.0.0.0-5.6.7.7', '5.6.7.9-255.255.255.255']);
  assert.deepEqual(rangeComplement(['5.6.7.8/32']), ['0.0.0.0-5.6.7.7', '5.6.7.9-255.255.255.255']);
});

test('rangeComplement: an exclude at either edge shortens instead of splitting', () => {
  assert.deepEqual(rangeComplement(['0.0.0.0/8']), ['1.0.0.0-255.255.255.255']);
  assert.deepEqual(rangeComplement(['255.255.255.255']), ['0.0.0.0-255.255.255.254']);
  assert.deepEqual(rangeComplement(['0.0.0.0/0']), [], 'everything excluded is nothing to block');
});

test('rangeComplement: overlapping, adjacent and unsorted excludes merge into one hole', () => {
  // the two adjacent halves of 10/8, given in the wrong order, with an overlap inside them
  assert.deepEqual(rangeComplement(['10.128.0.0/9', '10.0.0.0/9', '10.1.2.3']),
    ['0.0.0.0-9.255.255.255', '11.0.0.0-255.255.255.255']);
  assert.deepEqual(rangeComplement(['1.0.0.0/8', '1.1.0.0/16']),
    ['0.0.0.0-0.255.255.255', '2.0.0.0-255.255.255.255'], 'a range inside another adds no hole');
  assert.deepEqual(rangeComplement(['1.2.3.4', '1.2.3.4']), ['0.0.0.0-1.2.3.3', '1.2.3.5-255.255.255.255']);
});

test('rangeComplement takes a host address with a prefix as its network', () => {
  assert.deepEqual(rangeComplement(['192.168.8.63/24']),
    ['0.0.0.0-192.168.7.255', '192.168.9.0-255.255.255.255']);
});

test('rangeComplement ignores what it cannot block instead of throwing', () => {
  // a v6 server address (strict_route blocks v6 off-TUN by itself), a hostname
  // we never resolved, junk from a hand-edited setting
  assert.deepEqual(rangeComplement(['2606:4700::1111', 'vpn.example.com', '', null, '999.1.1.1', '1.2.3.4/33', 5]),
    ['0.0.0.0-255.255.255.255']);
  assert.deepEqual(rangeComplement(['vpn.example.com', '9.9.9.9']),
    ['0.0.0.0-9.9.9.8', '9.9.9.10-255.255.255.255'], 'the addresses among them still count');
});

test('rangeComplement: the default guard set leaves exactly these eight ranges', () => {
  assert.deepEqual(GUARD_EXCLUDES, [
    '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16',
    '127.0.0.0/8', '224.0.0.0/4', '100.64.0.0/10', '172.19.0.0/30',
    '255.255.255.255/32'
  ]);
  assert.deepEqual(rangeComplement(GUARD_EXCLUDES), DEFAULT_RANGES);
  // the server's entry IP is the hole that keeps the tunnel reachable
  assert.deepEqual(rangeComplement(['5.6.7.8', ...GUARD_EXCLUDES]).slice(0, 2),
    ['0.0.0.0-5.6.7.7', '5.6.7.9-9.255.255.255']);
});

/* ----------------------------- Windows: the strict rules ----------------------------- */

test('winStrictApplyScript blocks both protocols on every adapter, everywhere but the excludes', () => {
  const rule = (proto, alias) =>
    `New-NetFirewallRule -Group 'IRNetFree' -DisplayName 'IRNetFree strict ${proto} ${alias}'`
    + ' -Direction Outbound -Action Block -Enabled True -Profile Any'
    + ` -InterfaceAlias '${alias}' -Protocol ${proto} -RemoteAddress @(${psRanges(DEFAULT_RANGES)}) | Out-Null`;
  assert.equal(winStrictApplyScript({ adapters: [{ alias: 'Wi-Fi' }, { alias: "Bob's Ethernet" }], ranges: DEFAULT_RANGES }), [
    "$ErrorActionPreference = 'Stop'",
    // re-engaging (a server switch under TUN) must not stack a second set of rules
    "Remove-NetFirewallRule -Group 'IRNetFree' -ErrorAction SilentlyContinue",
    rule('TCP', 'Wi-Fi'),
    rule('UDP', 'Wi-Fi'),
    rule('TCP', "Bob''s Ethernet"),
    rule('UDP', "Bob''s Ethernet")
  ].join('\n'));
});

test('winStrictApplyScript with nothing to block is only the removal', () => {
  const bare = ["$ErrorActionPreference = 'Stop'", "Remove-NetFirewallRule -Group 'IRNetFree' -ErrorAction SilentlyContinue"].join('\n');
  assert.equal(winStrictApplyScript({ adapters: [], ranges: DEFAULT_RANGES }), bare);
  // an EMPTY -RemoteAddress means "Any" to New-NetFirewallRule, which would
  // block the whole machine instead of nothing — no ranges, no rule.
  assert.equal(winStrictApplyScript({ adapters: [{ alias: 'Wi-Fi' }], ranges: [] }), bare);
  assert.equal(winStrictApplyScript({}), bare);
});

test('winGroupRemoveScript takes the group and never a rule name — the kill switch is not ours to touch', () => {
  assert.equal(winGroupRemoveScript(), "Remove-NetFirewallRule -Group 'IRNetFree' -ErrorAction SilentlyContinue");
  // main.js's kill switch is a netsh rule NAMED 'IRNetFree KillSwitch' with no
  // group, so -Group cannot reach it — and nothing we generate names it either.
  // Its own `netsh delete rule name=…` cannot reach ours for the same reason.
  const generated = [
    winGroupRemoveScript(),
    winStrictApplyScript({ adapters: [{ alias: 'Wi-Fi' }], ranges: DEFAULT_RANGES }),
    winUdpBlockApplyScript({ adapters: [{ alias: 'Wi-Fi' }], ranges: DEFAULT_RANGES }),
    winReleaseScript([], { firewall: true })
  ];
  for (const s of generated) {
    assert.equal(/KillSwitch/.test(s), false);
    assert.equal(/netsh/.test(s), false);
    assert.equal(/Remove-NetFirewallRule (?!-Group)/.test(s), false, 'removal is by group, only ever by group');
  }
});

test('winUdpBlockApplyScript blocks UDP to the internet except DNS, per adapter', () => {
  const rule = (alias) =>
    `New-NetFirewallRule -Group 'IRNetFree' -DisplayName 'IRNetFree udp ${alias}'`
    + ' -Direction Outbound -Action Block -Enabled True -Profile Any'
    + ` -InterfaceAlias '${alias}' -Protocol UDP -RemotePort @('1-52','54-65535')`
    + ` -RemoteAddress @(${psRanges(DEFAULT_RANGES)}) | Out-Null`;
  assert.equal(winUdpBlockApplyScript({ adapters: [{ alias: 'Wi-Fi' }, { alias: 'Ethernet' }], ranges: DEFAULT_RANGES }), [
    "$ErrorActionPreference = 'Stop'",
    "Remove-NetFirewallRule -Group 'IRNetFree' -ErrorAction SilentlyContinue",
    rule('Wi-Fi'),
    rule('Ethernet')
  ].join('\n'));
  // The LAN is outside the ranges on purpose: a rule that blocked every UDP
  // port but 53 would also kill the DHCP renewal (unicast to the router, port
  // 67) and take the machine's address with it hours into a session.
  assert.equal(/'192\.168\.|'10\.0\.0\.0/.test(winUdpBlockApplyScript({ adapters: [{ alias: 'Wi-Fi' }], ranges: DEFAULT_RANGES })), false);
  assert.equal(winUdpBlockApplyScript({ adapters: [{ alias: 'Wi-Fi' }], ranges: [] }),
    ["$ErrorActionPreference = 'Stop'", "Remove-NetFirewallRule -Group 'IRNetFree' -ErrorAction SilentlyContinue"].join('\n'));
});

test('winReleaseScript: the firewall group goes before the DNS restore, and only when we made rules', () => {
  const adapters = [{ alias: 'Wi-Fi', v4: ['192.168.8.1'], dhcp4: true }];
  assert.equal(winReleaseScript(adapters), winRestoreScript(adapters), 'a standard session made no rules');
  assert.equal(winReleaseScript(adapters, { firewall: true }),
    winGroupRemoveScript() + '\n' + winRestoreScript(adapters));
  assert.equal(winReleaseScript(adapters, { orphans: true, firewall: true }),
    winOrphanKillScript() + '\n' + winGroupRemoveScript() + '\n' + winRestoreScript(adapters));
  assert.equal(winReleaseScript(adapters, { orphans: true }), winRepairScript(adapters));
});

/* ----------------------------- macOS: the pf anchor ----------------------------- */

test('macPfAnchorText passes the tunnel and the excludes, then blocks both families', () => {
  assert.equal(macPfAnchorText({ tunDevice: 'utun4', excludes: ['5.6.7.8', '178.22.122.100', '5.6.7.8'] }), [
    '# IRNetFree strict guard — generated, loaded into anchor "irnetfree"',
    // `set skip on lo0` would be an OPTION, and pf takes options only in the
    // main ruleset — inside an anchor it is a parse error. A pass rule does the
    // same job for outbound traffic and is legal here.
    'pass out quick on lo0 all',
    'pass out quick on utun4 all',
    'pass out quick to { 5.6.7.8, 178.22.122.100, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 127.0.0.0/8, 224.0.0.0/4, 100.64.0.0/10, 172.19.0.0/30, 255.255.255.255/32 }',
    'block out quick inet all',
    'block out quick inet6 all',
    ''
  ].join('\n'));
});

test('macPfAnchorText refuses to generate a ruleset it cannot let the tunnel through', () => {
  assert.match(macPfAnchorText({ tunDevice: 'utun9' }), /pass out quick on utun9 all\npass out quick to \{ 10\.0\.0\.0\/8, /);
  // No device name means no pass rule for the tunnel, i.e. a machine with no
  // network at all. Generate nothing rather than something catastrophic.
  assert.equal(macPfAnchorText({ tunDevice: '', excludes: ['5.6.7.8'] }), null);
  assert.equal(macPfAnchorText({ tunDevice: 'IRNetFree' }), null, 'the Windows adapter name is not a utun device');
  assert.equal(macPfAnchorText({ tunDevice: 'utun4; rm -rf /' }), null);
  assert.equal(macPfAnchorText({}), null);
});

test('macPfApplyScript writes the anchor, loads it and reports whether pf was already on', () => {
  const anchor = macPfAnchorText({ tunDevice: 'utun4', excludes: [] });
  assert.equal(macPfApplyScript(anchor), [
    '#!/bin/bash',
    'FAIL=0',
    'umask 077',
    'mkdir -p /etc/pf.anchors',
    "cat > /etc/pf.anchors/irnetfree <<'IRNF_ANCHOR'",
    ...anchor.split('\n').slice(0, -1),
    'IRNF_ANCHOR',
    // the answer goes into the state file, so release() only turns pf off again
    // when it was off before us
    "if pfctl -s info 2>/dev/null | head -n 1 | grep -q 'Status: Enabled'; then",
    "  echo 'IRNF_PF_WAS=enabled'",
    'else',
    "  echo 'IRNF_PF_WAS=disabled'",
    '  pfctl -E >/dev/null 2>&1 || FAIL=1',
    'fi',
    // /etc/pf.conf is never edited: the anchor line is appended to a COPY, and
    // that copy lives in the root-owned anchors dir (a world-writable /tmp file
    // fed to pfctl as root is a local privilege escalation waiting to happen).
    'if ! pfctl -sr 2>/dev/null | grep -q \'anchor "irnetfree"\'; then',
    '  { cat /etc/pf.conf; echo \'anchor "irnetfree"\'; } > /etc/pf.anchors/irnetfree.conf || FAIL=1',
    '  pfctl -f /etc/pf.anchors/irnetfree.conf || FAIL=1',
    'fi',
    'pfctl -a irnetfree -f /etc/pf.anchors/irnetfree || FAIL=1',
    'exit $FAIL',
    ''
  ].join('\n'));
});

test('macPfRemoveScript flushes the anchor and only disables pf when we enabled it', () => {
  const lines = [
    'pfctl -a irnetfree -F all 2>/dev/null || true',
    'rm -f /etc/pf.anchors/irnetfree /etc/pf.anchors/irnetfree.conf'
  ];
  assert.equal(macPfRemoveScript(), ['#!/bin/bash', 'FAIL=0', ...lines, 'exit $FAIL', ''].join('\n'));
  assert.equal(macPfRemoveScript({ disable: true }),
    ['#!/bin/bash', 'FAIL=0', ...lines, 'pfctl -d 2>/dev/null || true', 'exit $FAIL', ''].join('\n'));
});

test('macReleaseScript: the pf anchor goes before the DNS restore, in one password prompt', () => {
  const services = [{ name: 'Wi-Fi', dns: [] }];
  const body = (s) => s.split('\n').slice(2, -2);
  assert.equal(macReleaseScript(services), macRestoreScript(services), 'a standard session loaded no anchor');
  assert.deepEqual(body(macReleaseScript(services, { firewall: true, disablePf: true })),
    [...body(macPfRemoveScript({ disable: true })), ...body(macRestoreScript(services))]);
  assert.deepEqual(body(macReleaseScript(services, { orphans: true, firewall: true })),
    [...body(macOrphanKillScript()), ...body(macPfRemoveScript()), ...body(macRestoreScript(services))]);
  assert.equal(macReleaseScript(services, { orphans: true }), macRepairScript(services));
});

/* ----------------------------- the class, at strict ----------------------------- */

test('engage (win32, strict): DNS first, then the firewall — and the state file before both', async () => {
  const h = harness('win32', (cmd, args) => (/ConvertTo-Json/.test(args[args.length - 1]) ? WIN_SNAP : ''));
  const r = await h.guard.engage({
    level: 'strict', peer4: PEER4, tunAlias: 'IRNetFree', backend: 'sing-box',
    excludes: ['5.6.7.8', '178.22.122.100']
  });
  assert.equal(r.engaged, true);
  assert.equal(r.adapters, 2);
  assert.equal(h.calls.length, 3);
  const adapters = parseWinSnapshot(WIN_SNAP);
  assert.equal(h.calls[0].script, winSnapshotScript('IRNetFree'));
  assert.equal(h.calls[1].script, winApplyScript(adapters, PEER4, null), 'the standard step still runs first');
  assert.equal(h.calls[2].script, winStrictApplyScript({
    adapters, ranges: rangeComplement(['5.6.7.8', '178.22.122.100', ...GUARD_EXCLUDES])
  }));
  assert.equal(h.calls[2].stateExists, true);
  assert.match(h.calls[2].script, /'0\.0\.0\.0-5\.6\.7\.7','5\.6\.7\.9-9\.255\.255\.255'/, 'the entry IP is a hole in the block');

  const st = h.state();
  assert.equal(st.strict, true);
  assert.equal(st.udpBlock, false);
  assert.deepEqual(st.win.adapters, adapters);
  assert.deepEqual(h.logs, [
    [`Leak guard: DNS of 2 adapters → ${PEER4}`, 'info'],
    ['Leak guard (strict): 2 adapters now block every outbound address but the tunnel\'s — traffic your rules send direct is blocked too', 'warn']
  ]);
});

test('engage (win32, standard): no firewall rule is even mentioned', async () => {
  const h = harness('win32', (cmd, args) => (/ConvertTo-Json/.test(args[args.length - 1]) ? WIN_SNAP : ''));
  await h.guard.engage({ level: 'standard', peer4: PEER4, tunAlias: 'IRNetFree', excludes: ['5.6.7.8'] });
  assert.equal(h.calls.length, 2);
  assert.equal(h.calls.some(c => /NetFirewallRule/.test(c.script)), false);
  assert.equal(h.state().strict, false);
});

test('engage (win32, strict): a failing firewall step keeps the state file — the DNS is already ours', async () => {
  const h = harness('win32', (cmd, args) => (/ConvertTo-Json/.test(args[args.length - 1])
    ? WIN_SNAP
    : (/NetFirewallRule/.test(args[args.length - 1]) ? new Error('Access is denied.') : '')));
  await assert.rejects(() => h.guard.engage({ level: 'strict', peer4: PEER4, tunAlias: 'IRNetFree' }), /Access is denied/);
  assert.equal(fs.existsSync(h.statePath), true);
  assert.equal(h.state().strict, true, 'release() must still remove whatever half of it was created');
});

test('release (win32, strict): the block is lifted BEFORE the resolvers go back', async () => {
  const h = harness('win32', (cmd, args) => (/ConvertTo-Json/.test(args[args.length - 1]) ? WIN_SNAP : ''));
  await h.guard.engage({ level: 'strict', peer4: PEER4, tunAlias: 'IRNetFree', excludes: ['5.6.7.8'] });
  h.calls.length = 0; h.logs.length = 0;

  const r = await h.guard.release();
  assert.deepEqual(r, { released: true, adapters: 2 });
  assert.equal(h.calls.length, 1, 'one spawn for both halves');
  assert.equal(h.calls[0].script, winReleaseScript(parseWinSnapshot(WIN_SNAP), { firewall: true }));
  assert.ok(h.calls[0].script.indexOf('Remove-NetFirewallRule') < h.calls[0].script.indexOf('Set-DnsClientServerAddress'));
  assert.equal(fs.existsSync(h.statePath), false);
  assert.deepEqual(h.logs, [['Leak guard released: DNS of 2 adapters restored, firewall rules removed', 'info']]);
});

test('repairAtLaunch (win32, strict): the orphan, the rules and the DNS in one script', async () => {
  const h = harness('win32', (cmd, args) => (/ConvertTo-Json/.test(args[args.length - 1]) ? WIN_SNAP : ''));
  await h.guard.engage({ level: 'strict', peer4: PEER4, tunAlias: 'IRNetFree' });
  h.calls.length = 0; h.logs.length = 0;

  await h.guard.repairAtLaunch();
  assert.equal(h.calls.length, 1);
  assert.equal(h.calls[0].script, winReleaseScript(parseWinSnapshot(WIN_SNAP), { orphans: true, firewall: true }));
  assert.equal(fs.existsSync(h.statePath), false);
  assert.equal(h.logs[1][0], 'Restored DNS of 2 adapters left from a previous session, and removed its firewall rules');
});

test('releaseSync (win32, strict): the exit hook takes the rules with it', async () => {
  const h = harness('win32', (cmd, args) => (/ConvertTo-Json/.test(args[args.length - 1]) ? WIN_SNAP : ''));
  await h.guard.engage({ level: 'strict', peer4: PEER4, tunAlias: 'IRNetFree' });
  h.calls.length = 0;
  assert.equal(h.guard.releaseSync(), true);
  assert.equal(h.calls[0].sync, true);
  assert.equal(h.calls[0].script, winReleaseScript(parseWinSnapshot(WIN_SNAP), { firewall: true }));
  assert.equal(fs.existsSync(h.statePath), false);
});

test('engage (darwin, strict): the anchor is loaded after the DNS, and pf is left as it was found', async () => {
  const h = harness('darwin', (cmd, args) => {
    if (cmd === '/bin/bash') return 'Wi-Fi\t192.168.8.1';
    return /pfctl/.test(fs.readFileSync(args[0], 'utf8')) ? 'IRNF_PF_WAS=enabled\n' : '';
  });
  const r = await h.guard.engage({ level: 'strict', peer4: PEER4, tunAlias: 'utun4', excludes: ['5.6.7.8'] });
  assert.equal(r.engaged, true);
  assert.equal(h.calls.length, 3);
  assert.equal(h.calls[1].script, macApplyScript([{ name: 'Wi-Fi', dns: ['192.168.8.1'] }], PEER4, null));
  assert.equal(h.calls[2].script, macPfApplyScript(macPfAnchorText({ tunDevice: 'utun4', excludes: ['5.6.7.8'] })));
  assert.equal(h.state().strict, true);
  assert.equal(h.state().pfEnabledByUs, false, 'pf was already on — release() must not turn it off');

  h.calls.length = 0;
  await h.guard.release();
  assert.equal(h.calls.length, 1, 'one password prompt for the whole teardown');
  assert.equal(h.calls[0].script, macReleaseScript([{ name: 'Wi-Fi', dns: ['192.168.8.1'] }], { firewall: true, disablePf: false }));
});

test('engage (darwin, strict): pf that WE enabled is recorded, and turned off again on release', async () => {
  const h = harness('darwin', (cmd) => (cmd === '/bin/bash' ? 'Wi-Fi\t' : 'IRNF_PF_WAS=disabled\n'));
  await h.guard.engage({ level: 'strict', peer4: PEER4, tunAlias: 'utun4' });
  assert.equal(h.state().pfEnabledByUs, true);
  h.calls.length = 0;
  await h.guard.release();
  assert.equal(h.calls[0].script, macReleaseScript([{ name: 'Wi-Fi', dns: [] }], { firewall: true, disablePf: true }));
  assert.match(h.calls[0].script, /pfctl -d/);
});

test('engage (darwin, strict): an unnamed tunnel device gets DNS only, never a block-everything ruleset', async () => {
  const h = harness('darwin', (cmd) => (cmd === '/bin/bash' ? 'Wi-Fi\t' : ''));
  const r = await h.guard.engage({ level: 'strict', peer4: PEER4, tunAlias: 'IRNetFree' });
  assert.equal(r.engaged, true);
  assert.equal(h.calls.length, 2, 'the snapshot and the DNS apply — no pfctl');
  assert.equal(h.state().strict, false);
  assert.match(h.logs[h.logs.length - 1][0], /could not name the tunnel device/i);
});

/* ----------------------------- the proxy-mode UDP block ----------------------------- */

test('engageUdpBlock (win32): one rule per adapter, and a state file that says so', async () => {
  const h = harness('win32', (cmd, args) => (/ConvertTo-Json/.test(args[args.length - 1]) ? WIN_SNAP : ''));
  const r = await h.guard.engageUdpBlock({ excludes: ['5.6.7.8', 'vpn.example.com'] });
  assert.deepEqual(r, { engaged: true, adapters: 2 });
  assert.equal(h.calls.length, 2);
  assert.equal(h.calls[0].script, winSnapshotScript(null), 'no tunnel of ours to skip in proxy mode');
  assert.equal(h.calls[1].script, winUdpBlockApplyScript({
    adapters: parseWinSnapshot(WIN_SNAP), ranges: rangeComplement(['5.6.7.8', 'vpn.example.com', ...GUARD_EXCLUDES])
  }));
  assert.equal(h.calls[1].stateExists, true);

  const st = h.state();
  assert.equal(st.udpBlock, true);
  assert.equal(st.strict, false);
  assert.deepEqual(st.win.adapters, [],
    'nothing here touched a resolver — recording the adapters would make release() reset DNS we never set');
  assert.deepEqual(h.logs, [['Blocked outbound UDP to the internet (except DNS) on 2 adapters — WebRTC cannot leak your address', 'info']]);
});

test('release after the UDP block: the group goes, no DNS is touched', async () => {
  const h = harness('win32', (cmd, args) => (/ConvertTo-Json/.test(args[args.length - 1]) ? WIN_SNAP : ''));
  await h.guard.engageUdpBlock({});
  h.calls.length = 0; h.logs.length = 0;

  const r = await h.guard.release();
  assert.equal(r.released, true);
  assert.equal(h.calls.length, 1);
  assert.equal(h.calls[0].script, winReleaseScript([], { firewall: true }));
  assert.equal(/Set-DnsClientServerAddress/.test(h.calls[0].script), false);
  assert.equal(fs.existsSync(h.statePath), false);
  assert.deepEqual(h.logs, [['Leak guard released: the UDP block removed', 'info']]);
});

test('engageUdpBlock keeps a live DNS override that a failed repair left behind', async () => {
  // The repair could not restore the adapters (no admin), so its record is the
  // only copy of the originals. A proxy-mode connect must add to it, not clobber it.
  const h = harness('win32', (cmd, args) => (/ConvertTo-Json/.test(args[args.length - 1]) ? WIN_SNAP : ''));
  await h.guard.engage({ level: 'standard', peer4: PEER4, tunAlias: 'IRNetFree' });
  await h.guard.engageUdpBlock({});
  const st = h.state();
  assert.deepEqual(st.win.adapters, parseWinSnapshot(WIN_SNAP));
  assert.equal(st.udpBlock, true);
  assert.equal(st.peer4, PEER4);
});

test('engageUdpBlock (darwin/linux): says it cannot, once, and touches nothing', async () => {
  for (const plat of ['darwin', 'linux']) {
    const h = harness(plat, () => '');
    assert.deepEqual(await h.guard.engageUdpBlock({}), { engaged: false, adapters: 0 });
    assert.deepEqual(await h.guard.engageUdpBlock({}), { engaged: false, adapters: 0 });
    assert.equal(h.calls.length, 0);
    assert.equal(fs.existsSync(h.statePath), false);
    assert.equal(h.logs.length, 1, 'the same warning twice in a session is noise');
    assert.match(h.logs[0][0], /not available/i);
  }
});

test('engageUdpBlock (win32): no physical adapter is nothing to block', async () => {
  const h = harness('win32', () => '[]');
  assert.deepEqual(await h.guard.engageUdpBlock({}), { engaged: false, adapters: 0 });
  assert.equal(h.calls.length, 1);
  assert.equal(fs.existsSync(h.statePath), false);
});

/* ------------------------- the branch review's findings ------------------------- */

// C1 (critical). engage() used to take a fresh snapshot every time. On a second
// engage — a server switch under TUN, which never releases in between — what it
// reads back is the peer the FIRST engage wrote. Restoring that pins every
// adapter to an address that routes nowhere once the tunnel stops, and the state
// file is deleted on a successful restore, so nothing is left to undo it.
test('engage twice keeps the first session’s originals instead of re-reading our own peer', async () => {
  let snaps = 0;
  const h = harness('win32', (cmd, args) => {
    if (!String(args[args.length - 1]).includes('ConvertTo-Json')) return '';
    snaps++;
    return snaps === 1 ? WIN_SNAP : JSON.stringify([{ alias: 'Wi-Fi', v4: [PEER4], v6: [], dhcp4: false, dhcp6: true }]);
  });
  const opts = { level: 'standard', peer4: PEER4, tunAlias: 'IRNetFree' };
  await h.guard.engage(opts);
  await h.guard.engage(opts);
  assert.equal(snaps, 1, 'the live session is snapshotted once, not once per connect');
  assert.deepEqual(h.state().win.adapters, JSON.parse(WIN_SNAP));
  assert.equal(h.guard.readState().win.adapters.some(a => a.v4.includes(PEER4)), false);
});

// The same protection from the other side, for the snapshot that has no earlier
// record to fall back on: on macOS the tunnel sets the service's DNS before the
// guard ever looks, so the peer is already there the first time.
test('the tunnel’s own resolvers are never recorded as an adapter’s originals', () => {
  assert.deepEqual(
    withoutPeers([{ alias: 'Wi-Fi', v4: [PEER4], v6: [PEER6], dhcp4: false, dhcp6: false },
                  { alias: 'Ethernet', v4: ['9.9.9.9', PEER4], v6: [], dhcp4: false, dhcp6: true }], [PEER4, PEER6]),
    [{ alias: 'Wi-Fi', v4: [], v6: [], dhcp4: false, dhcp6: false },
     { alias: 'Ethernet', v4: ['9.9.9.9'], v6: [], dhcp4: false, dhcp6: true }]);
  // a family left empty is restored by the reset, so the peer cannot be pinned
  const restore = winRestoreScript(withoutPeers([{ alias: 'Wi-Fi', v4: [PEER4], v6: [], dhcp4: false, dhcp6: true }], [PEER4]));
  assert.equal(restore.includes(PEER4), false, 'the peer never reaches a restore command');
  assert.match(restore, /-ResetServerAddresses/);
  // macOS records the same way, under its own key
  assert.deepEqual(withoutPeers([{ name: 'Wi-Fi', dns: [PEER4] }, { name: 'Bridge', dns: ['8.8.8.8', PEER4] }], [PEER4]),
    [{ name: 'Wi-Fi', dns: [] }, { name: 'Bridge', dns: ['8.8.8.8'] }]);
});

test('macOS: a service already carrying the peer is engaged as empty and restored to Empty', async () => {
  const h = harness('darwin', (cmd) => (cmd === 'privileged' ? '' : `Wi-Fi\t${PEER4}\nBridge\t8.8.8.8 ${PEER4}\n`));
  await h.guard.engage({ level: 'standard', peer4: PEER4, tunAlias: 'utun4' });
  assert.deepEqual(h.state().mac.services, [{ name: 'Wi-Fi', dns: [] }, { name: 'Bridge', dns: ['8.8.8.8'] }]);
  assert.match(macRestoreScript(h.state().mac.services), /-setdnsservers 'Wi-Fi' Empty/);
});

// M3. DHCP renewal is a unicast to the router, but the DISCOVER/REQUEST that
// follows a lease loss is broadcast to 255.255.255.255 — blocking it takes the
// machine's address with it, hours after anyone would connect the two.
test('the strict block leaves the DHCP limited broadcast alone', () => {
  assert.equal(rangeComplement(GUARD_EXCLUDES).some(r => r.endsWith('-255.255.255.255')), false);
  assert.ok(GUARD_EXCLUDES.includes('255.255.255.255/32'));
});

// L1. A recorded resolver is data read off the machine, and the restore script
// runs as root.
test('recorded resolvers are quoted before they reach a root shell', () => {
  const evil = "1.1.1.1'; touch /tmp/pwned; echo '";
  const script = macRestoreScript([{ name: 'Wi-Fi', dns: [evil] }]);
  // The address is data read off the machine and this script runs as root, so
  // it must arrive as ONE shell word: the quote it carries comes back escaped
  // (sh()), never raw, and the line still ends the way every other one does.
  assert.equal(script.includes(evil), false, 'the payload is never interpolated raw');
  assert.equal(script.split(String.fromCharCode(92) + "'").length - 1, 2, 'both quotes escaped');
  assert.match(script, /networksetup -setdnsservers 'Wi-Fi' .* \|\| FAIL=1/);
});
