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
  winSnapshotScript, parseWinSnapshot, parseNetshDnsServers, winApplyScript, winRestoreScript,
  winOrphanKillScript, winRepairScript, winReleaseScript,
  winStrictApplyScript, winGroupRemoveScript, winUdpBlockApplyScript,
  macSnapshotScript, parseMacSnapshot, macApplyScript, macRestoreScript,
  macOrphanKillScript, macRepairScript, macReleaseScript,
  macPfAnchorText, macPfApplyScript, macPfRemoveScript
} = require('../src/main/leakGuard');

const PEER4 = '172.19.0.2';
const PEER6 = 'fdfe:dcba:9876::2';
/** What the guard holds a Windows adapter on (WIN_HOLD4/6 in leakGuard.js). */
const HOLD4 = '127.0.0.2';
const HOLD6 = '::1';

/* ----------------------------- Windows: snapshot ----------------------------- */

test('winSnapshotScript skips our own adapters and the virtual ones, and prints JSON', () => {
  const lines = winSnapshotScript('IRNetFree').split('\n');
  assert.equal(lines[0], "$ErrorActionPreference = 'SilentlyContinue'");
  assert.equal(lines[1], '$out = @()');
  assert.equal(lines[2],
    'foreach ($a in @(Get-NetAdapter | Where-Object { $_.Status -eq \'Up\''
    + " -and $_.InterfaceAlias -ne 'IRNetFree'"
    + " -and $_.InterfaceAlias -ne 'XrayTun'"
    + " -and $_.InterfaceDescription -notmatch 'Wintun|TAP|Loopback|VMware Virtual Ethernet|VirtualBox Host-Only' })) {");
  assert.equal(lines[3], '$d4 = @(Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4)');
  assert.equal(lines[4], '$d6 = @(Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv6)');
  assert.equal(lines[5], 'if (-not $d4.Count -and -not $d6.Count) { continue }');
  assert.equal(lines[6],
    "$k4 = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\' + $a.InterfaceGuid");
  assert.equal(lines[7],
    "$k6 = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\Interfaces\\' + $a.InterfaceGuid");
  assert.equal(lines[8],
    '$out += [pscustomobject]@{ alias = $a.InterfaceAlias;'
    + ' v4 = @($d4 | Select-Object -ExpandProperty ServerAddresses);'
    + ' v6 = @($d6 | Select-Object -ExpandProperty ServerAddresses);'
    + ' has4 = [bool]$d4.Count; has6 = [bool]$d6.Count;'
    + ' dhcp4 = [string]::IsNullOrWhiteSpace((Get-ItemProperty -Path $k4 -Name NameServer).NameServer);'
    + ' dhcp6 = [string]::IsNullOrWhiteSpace((Get-ItemProperty -Path $k6 -Name NameServer).NameServer) }');
  assert.equal(lines[9], '}');
  assert.equal(lines[10], 'ConvertTo-Json -InputObject @($out) -Depth 3 -Compress');
  assert.equal(lines.length, 11);
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

test('winApplyScript holds every adapter on the given resolvers in one script, each line on its own', () => {
  const adapters = [{ alias: 'Wi-Fi' }, { alias: "Bob's Ethernet" }];
  assert.equal(winApplyScript(adapters, HOLD4, HOLD6), [
    "$ErrorActionPreference = 'Stop'",
    '$set = 0',
    "try { Set-DnsClientServerAddress -InterfaceAlias 'Wi-Fi' -ServerAddresses '127.0.0.2'; $set++ } catch { Write-Output ('IRNF_FAIL 0 v4 ' + $_.Exception.Message) }",
    "try { Set-DnsClientServerAddress -InterfaceAlias 'Wi-Fi' -ServerAddresses '::1'; $set++ } catch { Write-Output ('IRNF_FAIL 0 v6 ' + $_.Exception.Message) }",
    "try { Set-DnsClientServerAddress -InterfaceAlias 'Bob''s Ethernet' -ServerAddresses '127.0.0.2'; $set++ } catch { Write-Output ('IRNF_FAIL 1 v4 ' + $_.Exception.Message) }",
    "try { Set-DnsClientServerAddress -InterfaceAlias 'Bob''s Ethernet' -ServerAddresses '::1'; $set++ } catch { Write-Output ('IRNF_FAIL 1 v6 ' + $_.Exception.Message) }",
    'if ($set) { Clear-DnsClientCache }'
  ].join('\n'));
});

test('winApplyScript leaves a family alone when it is given no address for it', () => {
  assert.equal(winApplyScript([{ alias: 'Wi-Fi' }], HOLD4, null), [
    "$ErrorActionPreference = 'Stop'",
    '$set = 0',
    "try { Set-DnsClientServerAddress -InterfaceAlias 'Wi-Fi' -ServerAddresses '127.0.0.2'; $set++ } catch { Write-Output ('IRNF_FAIL 0 v4 ' + $_.Exception.Message) }",
    'if ($set) { Clear-DnsClientCache }'
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

test('macOS guard never kills processes without an owned backend session', () => {
  assert.doesNotMatch(macOrphanKillScript(), /pgrep|pkill|kill -/);
  assert.equal(macRepairScript([]), macRestoreScript([]));
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
    // quoted too (audit M7): the peers are read back from the state file for every refresh
    "networksetup -setdnsservers 'Wi-Fi' '172.19.0.2' 'fdfe:dcba:9876::2' || FAIL=1",
    "networksetup -setdnsservers 'Bob'\\''s Net' '172.19.0.2' 'fdfe:dcba:9876::2' || FAIL=1",
    'dscacheutil -flushcache 2>/dev/null || true',
    'killall -HUP mDNSResponder 2>/dev/null || true',
    'exit $FAIL',
    ''
  ].join('\n'));
  assert.match(macApplyScript([{ name: 'Wi-Fi' }], PEER4, null),
    /networksetup -setdnsservers 'Wi-Fi' '172\.19\.0\.2' \|\| FAIL=1/);
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

test('refresh repairs DHCP drift and journals a newly connected adapter before writing DNS', async () => {
  let snapshot = WIN_SNAP;
  const h = harness('win32', (cmd, args) => /ConvertTo-Json/.test(args.at(-1)) ? snapshot : '');
  const { token } = await h.guard.engage({ level: 'standard', peer4: PEER4, peer6: PEER6 });
  const original = h.state().win.adapters;
  snapshot = JSON.stringify([
    { alias: 'Wi-Fi', v4: ['192.168.8.254'], v6: ['fe80::2'], dhcp4: true, dhcp6: true },
    { alias: 'Ethernet', v4: [HOLD4], v6: [HOLD6], dhcp4: false, dhcp6: false },
    { alias: 'USB Ethernet', v4: ['192.168.20.1'], v6: [], dhcp4: true, dhcp6: true }
  ]);
  // the harness answers netsh with nothing, so the cheap check falls through
  const ps = () => h.calls.filter(c => c.cmd === 'powershell').length;
  const before = ps();
  assert.deepEqual(await h.guard.refresh({ token }), { refreshed: true, adapters: 2 });
  assert.equal(ps(), before + 2);
  assert.deepEqual(h.state().win.adapters.slice(0, 2), original);
  assert.deepEqual(h.state().win.adapters[2].v4, ['192.168.20.1']);
  assert.doesNotMatch(h.calls.at(-1).script, /Firewall|InterfaceAlias 'Ethernet'/);
  await h.guard.release({ token });
  assert.match(h.calls.at(-1).script, /InterfaceAlias 'USB Ethernet' -ResetServerAddresses/);
  const after = h.calls.length;
  assert.equal((await h.guard.refresh({ token })).skipped, true);
  assert.equal(h.calls.length, after);
});

test('an engage that fails after writing its state hands its receipt over on the error — its own release still works, a stranger’s does not', async () => {
  // An overtaken connect releases only with a receipt (a release without one is
  // unconditional and undid the newer connect's live guard). An engage whose
  // apply threw had written the state already: without the receipt on the
  // error that connect could not undo it at all.
  const h = harness('win32', (cmd, args) => (/ConvertTo-Json/.test(args.at(-1)) ? WIN_SNAP : new Error('Access is denied.')));
  const err = await h.guard.engage({ level: 'standard', peer4: PEER4, peer6: PEER6 }).then(() => null, (e) => e);
  assert.ok(err, 'the apply failed');
  assert.match(err.token, /^irnf-guard-\d+$/);
  assert.equal(fs.existsSync(h.statePath), true, 'its state was written before the apply');
  assert.equal((await h.guard.release({ token: 'irnf-guard-0' })).stale, true, 'another receipt is refused');
  const snap = h.calls.length;
  const r = await h.guard.release({ token: err.token });
  assert.ok(h.calls.length > snap, 'the release ran with the receipt');
  assert.equal(r.stale, undefined);
});

test('refresh without drift is read-only, and stale receipts do not even snapshot', async () => {
  let snapshot = WIN_SNAP;
  const h = harness('win32', (cmd, args) => /ConvertTo-Json/.test(args.at(-1)) ? snapshot : '');
  const { token } = await h.guard.engage({ level: 'strict', peer4: PEER4, peer6: PEER6 });
  snapshot = JSON.stringify([{ alias: 'Wi-Fi', v4: [HOLD4], v6: [HOLD6] }]);
  const ps = () => h.calls.filter(c => c.cmd === 'powershell').length;
  const before = ps();
  assert.deepEqual(await h.guard.refresh({ token }), { refreshed: false, adapters: 0 });
  assert.equal(ps(), before + 1);
  const all = h.calls.length;
  assert.equal((await h.guard.refresh({ token: 'old' })).skipped, true);
  assert.equal(h.calls.length, all, 'a stale receipt runs nothing, not even netsh');
});

/* ------------------------- refresh: the cheap half (netsh) ------------------------- */

const netshBlock = (alias, label, addrs) => [
  `Configuration for interface "${alias}"`,
  ...addrs.map((a, i) => (i ? ' '.repeat(42) : `    ${label}:`.padEnd(42)) + a),
  '    Register with which suffix:           Primary only',
  ''
].join('\r\n');
const NETSH_V4 = ['',
  netshBlock('IRNetFree', 'Statically Configured DNS Servers', [PEER4]),
  netshBlock('Wi-Fi', 'Statically Configured DNS Servers', [PEER4]),
  netshBlock('Ethernet', 'Statically Configured DNS Servers', [PEER4]),
  netshBlock('Bluetooth Network Connection', 'DNS servers configured through DHCP', ['None'])
].join('\r\n');
const NETSH_V6 = ['',
  netshBlock('Wi-Fi', 'Statically Configured DNS Servers', [PEER6]),
  netshBlock('Ethernet', 'Statically Configured DNS Servers', [PEER6]),
  netshBlock('Bluetooth Network Connection', 'DNS servers configured through DHCP', ['fec0:0:0:ffff::1%1', 'fec0:0:0:ffff::2%1'])
].join('\r\n');

/** The same machine under the guard: the TUN lists its peer, the guarded adapters the hold. */
const HELD_V4 = ['',
  netshBlock('IRNetFree', 'Statically Configured DNS Servers', [PEER4]),
  netshBlock('Wi-Fi', 'Statically Configured DNS Servers', [HOLD4]),
  netshBlock('Ethernet', 'Statically Configured DNS Servers', [HOLD4]),
  netshBlock('Bluetooth Network Connection', 'DNS servers configured through DHCP', ['None'])
].join('\r\n');
const HELD_V6 = ['',
  netshBlock('Wi-Fi', 'Statically Configured DNS Servers', [HOLD6]),
  netshBlock('Ethernet', 'Statically Configured DNS Servers', [HOLD6]),
  netshBlock('Bluetooth Network Connection', 'DNS servers configured through DHCP', ['fec0:0:0:ffff::1%1', 'fec0:0:0:ffff::2%1'])
].join('\r\n');

test('parseNetshDnsServers: one block per quoted alias, addresses only, scope ids dropped, headings never matched', () => {
  const v4 = parseNetshDnsServers(NETSH_V4);
  assert.deepEqual([...v4.keys()], ['irnetfree', 'wi-fi', 'ethernet', 'bluetooth network connection']);
  assert.deepEqual(v4.get('wi-fi'), [PEER4]);
  assert.deepEqual(v4.get('bluetooth network connection'), [], '"None" is not an address');
  const v6 = parseNetshDnsServers(NETSH_V6);
  assert.deepEqual(v6.get('ethernet'), [PEER6]);
  assert.deepEqual(v6.get('bluetooth network connection'), ['fec0:0:0:ffff::1', 'fec0:0:0:ffff::2'], 'continuation lines, %zone dropped');
  // a localized heading is still a heading: only the quotes are matched
  assert.deepEqual(parseNetshDnsServers('پیکربندی برای رابط "Wi-Fi"\r\n    سرورهای DNS:   10.255.0.1\r\n').get('wi-fi'), ['10.255.0.1']);
  assert.equal(parseNetshDnsServers('').size, 0);
  assert.equal(parseNetshDnsServers(null).size, 0);
  assert.equal(parseNetshDnsServers('    10.255.0.1\r\n').size, 0, 'an address before any block belongs to nobody');
});

test('refresh: a netsh listing that still names the holds costs no PowerShell; a drift, `full` or an unreadable listing takes the snapshot', async () => {
  let v4 = HELD_V4, v6 = HELD_V6, snapshot = WIN_SNAP;
  const h = harness('win32', (cmd, args) => {
    if (cmd === 'netsh') return args[1] === 'ipv6' ? v6 : v4;
    return /ConvertTo-Json/.test(args.at(-1)) ? snapshot : '';
  });
  const { token } = await h.guard.engage({ level: 'standard', peer4: PEER4, peer6: PEER6 });
  assert.deepEqual(h.state().win.adapters.map(a => a.alias), ['Wi-Fi', 'Ethernet']);
  const ps = () => h.calls.filter(c => c.cmd === 'powershell').length;
  const netsh = () => h.calls.filter(c => c.cmd === 'netsh').map(c => c.args.join(' '));

  let p = ps();
  const n = netsh().length;
  assert.deepEqual(await h.guard.refresh({ token }), { refreshed: false, adapters: 0, quick: true });
  assert.equal(ps(), p, 'no PowerShell at all');
  assert.deepEqual(netsh().slice(n), ['interface ipv4 show dnsservers', 'interface ipv6 show dnsservers']);

  // the v6 family of an owned adapter drifted back to the router → the full
  // path, which sees the same drift in the snapshot and repairs it
  v6 = HELD_V6.replace(`Statically Configured DNS Servers:    ${HOLD6}`, 'DNS servers configured through DHCP:  fe80::1%22');
  snapshot = JSON.stringify([
    { alias: 'Wi-Fi', v4: [HOLD4], v6: ['fe80::1'], dhcp4: true, dhcp6: true },
    { alias: 'Ethernet', v4: [HOLD4], v6: [HOLD6], dhcp4: false, dhcp6: false }
  ]);
  p = ps();
  assert.deepEqual(await h.guard.refresh({ token }), { refreshed: true, adapters: 1 });
  assert.equal(ps(), p + 2, 'snapshot + apply');
  assert.match(h.calls.at(-1).script, /InterfaceAlias 'Wi-Fi' -ServerAddresses '::1'/);
  assert.doesNotMatch(h.calls.at(-1).script, /InterfaceAlias 'Ethernet'/);

  // `full` skips the cheap half even when nothing drifted
  v6 = HELD_V6;
  snapshot = JSON.stringify([{ alias: 'Wi-Fi', v4: [HOLD4], v6: [HOLD6] }, { alias: 'Ethernet', v4: [HOLD4], v6: [HOLD6] }]);
  p = ps();
  const before = netsh().length;
  assert.deepEqual(await h.guard.refresh({ token, full: true }), { refreshed: false, adapters: 0 });
  assert.equal(ps(), p + 1);
  assert.equal(netsh().length, before);

  // an adapter netsh no longer lists is gone, not drifted
  v4 = HELD_V4.replace(netshBlock('Ethernet', 'Statically Configured DNS Servers', [HOLD4]), '');
  v6 = HELD_V6.replace(netshBlock('Ethernet', 'Statically Configured DNS Servers', [HOLD6]), '');
  p = ps();
  assert.deepEqual(await h.guard.refresh({ token }), { refreshed: false, adapters: 0, quick: true });
  assert.equal(ps(), p);

  // an empty (unreadable) listing is not trusted: the snapshot decides
  v4 = '';
  p = ps();
  assert.deepEqual(await h.guard.refresh({ token }), { refreshed: false, adapters: 0 });
  assert.equal(ps(), p + 1);

  // a v4 drift alone is enough
  v4 = HELD_V4.replace(`Statically Configured DNS Servers:    ${HOLD4}\r\n    Register with which suffix:           Primary only\r\n\r\nConfiguration for interface "Ethernet"`,
    `DNS servers configured through DHCP:  192.168.8.1\r\n    Register with which suffix:           Primary only\r\n\r\nConfiguration for interface "Ethernet"`);
  assert.deepEqual(parseNetshDnsServers(v4).get('wi-fi'), ['192.168.8.1']);
  snapshot = JSON.stringify([{ alias: 'Wi-Fi', v4: ['192.168.8.1'], v6: [HOLD6], dhcp4: true, dhcp6: true }]);
  p = ps();
  assert.deepEqual(await h.guard.refresh({ token }), { refreshed: true, adapters: 1 });
  assert.equal(ps(), p + 2);
});

/**
 * An adapter that comes up mid-session and that netWatcher does not treat as a
 * network change (a phone tethered over Bluetooth PAN is on its ignore list; so
 * is everything when auto-reconnect is off) used to wait for the tenth tick —
 * five minutes of every name going to its resolver. netsh lists it on the next
 * cheap tick; a resolver of its own on an alias nobody owns is what the
 * PowerShell snapshot exists to find.
 */
test('refresh (win32): an adapter nobody owns showing a resolver of its own takes the snapshot on the next cheap tick', async () => {
  let v4 = HELD_V4, v6 = HELD_V6, snapshot = WIN_SNAP;
  const h = harness('win32', (cmd, args) => {
    if (cmd === 'netsh') return args[1] === 'ipv6' ? v6 : v4;
    return /ConvertTo-Json/.test(args.at(-1)) ? snapshot : '';
  });
  const { token } = await h.guard.engage({ level: 'standard', peer4: PEER4, peer6: PEER6, tunAlias: 'IRNetFree' });
  const ps = () => h.calls.filter(c => c.cmd === 'powershell').length;
  assert.deepEqual(await h.guard.refresh({ token }), { refreshed: false, adapters: 0, quick: true },
    'our own TUN listing its peer, and an adapter with no resolver, are nothing new');

  const tether = netshBlock('Bluetooth Network Connection 2', 'DNS servers configured through DHCP', ['192.168.44.1']);
  v4 = HELD_V4 + '\r\n' + tether;
  snapshot = JSON.stringify([
    { alias: 'Wi-Fi', v4: [HOLD4], v6: [HOLD6], has4: true, has6: true },
    { alias: 'Ethernet', v4: [HOLD4], v6: [HOLD6], has4: true, has6: true },
    { alias: 'Bluetooth Network Connection 2', v4: ['192.168.44.1'], v6: [], has4: true, has6: false, dhcp4: true, dhcp6: true }
  ]);
  let p = ps();
  assert.deepEqual(await h.guard.refresh({ token }), { refreshed: true, adapters: 1 });
  assert.equal(ps(), p + 2, 'snapshot + apply, on a cheap tick');
  assert.deepEqual(h.state().win.adapters.at(-1).v4, ['192.168.44.1'], 'its own resolver recorded before it is touched');
  assert.deepEqual(written(h.calls.at(-1).script), [{ alias: 'Bluetooth Network Connection 2', addr: HOLD4 }]);

  // held now, and owned: the next tick is cheap again
  v4 = HELD_V4 + '\r\n' + netshBlock('Bluetooth Network Connection 2', 'Statically Configured DNS Servers', [HOLD4]);
  snapshot = JSON.stringify([
    { alias: 'Wi-Fi', v4: [HOLD4], v6: [HOLD6], has4: true, has6: true },
    { alias: 'Ethernet', v4: [HOLD4], v6: [HOLD6], has4: true, has6: true },
    { alias: 'Bluetooth Network Connection 2', v4: [HOLD4], v6: [], has4: true, has6: false }
  ]);
  p = ps();
  assert.deepEqual(await h.guard.refresh({ token }), { refreshed: false, adapters: 0, quick: true });
  assert.equal(ps(), p);

  // another VPN's tunnel: looked at once, left alone, never looked at again
  v4 += '\r\n' + netshBlock('OpenVPN TAP-Windows6', 'Statically Configured DNS Servers', ['10.8.0.1']);
  p = ps();
  assert.deepEqual(await h.guard.refresh({ token }), { refreshed: false, adapters: 0 });
  assert.equal(ps(), p + 1, 'one snapshot, which does not list it');
  p = ps();
  assert.deepEqual(await h.guard.refresh({ token }), { refreshed: false, adapters: 0, quick: true });
  assert.equal(ps(), p);

  // Windows' fec0:0:0:ffff::1-3 placeholders are "no resolver configured"
  v6 = HELD_V6 + '\r\n' + netshBlock('vEthernet (WSL)', 'DNS servers configured through DHCP', ['fec0:0:0:ffff::1%1', 'fec0:0:0:ffff::2%1']);
  p = ps();
  assert.deepEqual(await h.guard.refresh({ token }), { refreshed: false, adapters: 0, quick: true });
  assert.equal(ps(), p);
});

test('mac refresh preserves original DNS and changes only drifted services', async () => {
  let snapshot = 'Wi-Fi\t192.168.1.1\n';
  const h = harness('darwin', cmd => cmd === '/bin/bash' ? snapshot : '');
  const { token } = await h.guard.engage({ level: 'standard', peer4: PEER4, peer6: PEER6 });
  snapshot = `Wi-Fi\t${PEER4} ${PEER6}\nUSB LAN\t192.168.2.1\n`;
  assert.deepEqual(await h.guard.refresh({ token }), { refreshed: true, adapters: 1 });
  assert.deepEqual(h.state().mac.services, [{ name: 'Wi-Fi', dns: ['192.168.1.1'] }, { name: 'USB LAN', dns: ['192.168.2.1'] }]);
  assert.match(h.calls.at(-1).script, /-setdnsservers 'USB LAN'/);
  assert.doesNotMatch(h.calls.at(-1).script, /-setdnsservers 'Wi-Fi'/);
  snapshot = `Wi-Fi\t${PEER4} ${PEER6}\nUSB LAN\t${PEER4} ${PEER6}\n`;
  const before = h.calls.length;
  assert.equal((await h.guard.refresh({ token })).refreshed, false);
  assert.equal(h.calls.length, before + 1, 'unchanged DNS never opens an administrator prompt');
});

/**
 * The state file a session that never shut down cleanly leaves behind.
 *
 * The repair tests write it themselves rather than manufacturing one with
 * engage(): a guard that has engaged in THIS process owns the file, and
 * repairAtLaunch refuses to touch it (see 'repairAtLaunch never undoes a
 * session this process engaged'). Only a file that predates the process is a
 * previous session's, and that is what this makes.
 */
function crashedSession(h, extra = {}) {
  fs.writeFileSync(h.statePath, JSON.stringify(Object.assign({
    version: 1, at: new Date().toISOString(), backend: 'sing-box',
    peer4: PEER4, peer6: null, tunAlias: 'IRNetFree',
    level: 'standard', excludes: [], strict: false, udpBlock: false
  }, extra), null, 2));
}

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
  assert.equal(h.calls[1].script, winApplyScript(parseWinSnapshot(WIN_SNAP), HOLD4, HOLD6));
  assert.equal(h.calls[1].stateExists, true,
    'the originals are on disk BEFORE the first adapter is changed — a crash between the two must be repairable');

  const st = h.state();
  assert.equal(st.version, 1);
  assert.equal(st.backend, 'sing-box');
  assert.equal(st.peer4, PEER4);
  assert.equal(st.peer6, PEER6);
  assert.equal(st.hold4, HOLD4);
  assert.equal(st.hold6, HOLD6);
  assert.equal(st.tunAlias, 'IRNetFree');
  assert.match(st.at, /^\d{4}-\d{2}-\d{2}T/);
  assert.deepEqual(st.win.adapters, parseWinSnapshot(WIN_SNAP));
  assert.deepEqual(h.logs, [[`Leak guard: DNS of 2 adapters → ${HOLD4} ${HOLD6} (loopback: nothing asked there leaves the machine;`
    + ` the tunnel's resolver ${PEER4} ${PEER6} answers)`, 'info']]);
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
  crashedSession(h, { win: { adapters: parseWinSnapshot(WIN_SNAP) } });

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
  crashedSession(h, { tunAlias: 'utun4', mac: { services: [{ name: 'Wi-Fi', dns: ['192.168.8.1'] }] } });

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

/* ================= Windows: what a guarded adapter is pointed at ================= */
/*
 * The 2026-09-24 report: "the DNS still leaks, especially on Windows" (v1.13.5,
 * standard guard). The guard pointed every physical adapter at the TUNNEL PEER
 * (172.19.0.2 / fdfe:dcba:9876::2) on the theory that a query to the peer can
 * only enter the tunnel. It cannot be relied on to:
 *
 *  - The peer is on-link only on the TUN adapter. Whenever that adapter does not
 *    exist — every reconnect (the guard is HELD across it, the tunnel is torn
 *    down and rebuilt), a tunnel that crashed, an app that was killed, retries
 *    given up on with the guard still holding — the only route to 172.19.0.2 is
 *    the physical default route, and every name the machine looks up goes to the
 *    router and the ISP in cleartext. A network that answers every port-53
 *    packet (the owner has met one: the 198.18/15 fake-IP gateway) then RESOLVES
 *    it, and a leak test shows that network's resolver.
 *  - Windows sends each adapter's queries ON that adapter (smart multi-homed
 *    name resolution: Tailscale adds an NRPT "." rule because Windows 8.1+
 *    "issue parallel DNS requests to DNS servers associated with all network
 *    adapters"; Mullvad: "even if the tunnel is the default gateway, all other
 *    interfaces will also send out the same DNS query outside of the tunnel"),
 *    and fans a query out to every adapter when the preferred one answers
 *    REFUSED — which the hijack answers for every non-A/AAAA question.
 *
 * Loopback is the one destination no packet ever leaves the host for, on any
 * adapter, tunnel up or not. So every guarded adapter's resolvers become
 * loopback on both families, and the TUN adapter's own resolver (set by the
 * backend, never by the guard) is the one that answers.
 */

const isLoopback = (ip) => /^127\./.test(ip) || ip === '::1';
// (the reconnect-gap section below has its own copies of these two)
const snapAnswer = (snap) => (cmd, args) => (/ConvertTo-Json/.test(args.at(-1)) ? snap : '');
const psScripts = (h) => h.calls.filter(c => c.cmd === 'powershell').map(c => c.script);
/** Every address an apply script writes, per `-InterfaceAlias`. */
function written(script) {
  const out = [];
  for (const m of String(script).matchAll(/-InterfaceAlias '((?:[^']|'')*)' -ServerAddresses ((?:'[^']*',?)+)/g)) {
    for (const a of m[2].split(',')) out.push({ alias: m[1].replace(/''/g, "'"), addr: a.replace(/'/g, '') });
  }
  return out;
}

test('engage (win32): every guarded adapter is held on loopback, both families — never on an address that can leave the machine', async () => {
  // managed DNS (the tunnel peers), tun2socks whose v6 setup failed (no v6
  // peer), and managed DNS off / a sing-box-format core (the user's own public
  // resolvers): the physical adapters get the same answer in all three.
  for (const peers of [{ peer4: PEER4, peer6: PEER6 }, { peer4: '10.255.0.1', peer6: null }, { peer4: '1.1.1.1', peer6: null }]) {
    const h = harness('win32', snapAnswer(WIN_SNAP));
    const r = await h.guard.engage(Object.assign({ level: 'standard', tunAlias: 'IRNetFree' }, peers));
    assert.equal(r.engaged, true);
    const addrs = written(h.calls[1].script);
    assert.deepEqual(addrs.map(w => w.alias), ['Wi-Fi', 'Wi-Fi', 'Ethernet', 'Ethernet'], JSON.stringify(peers));
    assert.ok(addrs.every(w => isLoopback(w.addr)), `${JSON.stringify(peers)} wrote ${addrs.map(w => w.addr).join(' ')}`);
    assert.ok(addrs.some(w => w.addr.includes(':')), 'the v6 family is held too, peer6 or not — the router’s fe80:: resolver is on-link');
    // what the state says the adapters now hold is what refresh() compares against
    const st = h.state();
    assert.ok(isLoopback(st.hold4) && isLoopback(st.hold6));
    assert.equal(st.peer4, peers.peer4, 'the tunnel’s own resolver is still recorded, for the log');
  }
});

test('holdForReconnect (win32): what the adapters are held on during the gap cannot leave the machine', async () => {
  const h = harness('win32', snapAnswer(WIN_SNAP));
  const s = await h.guard.engage({ level: 'standard', peer4: PEER4, peer6: PEER6, tunAlias: 'IRNetFree' });
  await h.guard.holdForReconnect({ excludes: ['198.51.100.7'], token: s.token });
  // — the TUN adapter is gone here: 172.19.0.2 would route via the ISP —
  const addrs = psScripts(h).flatMap(written);
  assert.ok(addrs.length && addrs.every(w => isLoopback(w.addr)), addrs.map(w => w.addr).join(' '));
  assert.equal(addrs.some(w => w.addr === PEER4 || w.addr === PEER6), false);
});

test('winApplyScript: one adapter that cannot be set does not leave the next one on the ISP\'s resolver', () => {
  // `$ErrorActionPreference = 'Stop'` made the first failing line end the
  // script: every adapter after it kept its own resolvers, engage() threw, and
  // the drift watch was never started for the session. A NIC bound to a
  // Hyper-V external switch or a bridge is Up with no IP interface at all, so
  // it fails — and the adapter that carries the machine's address comes later.
  const adapters = [{ alias: 'Wi-Fi' }, { alias: "Bob's Ethernet", has6: false }, { alias: 'Bridge member', has4: false, has6: false }];
  assert.equal(winApplyScript(adapters, '127.0.0.2', '::1'), [
    "$ErrorActionPreference = 'Stop'",
    '$set = 0',
    "try { Set-DnsClientServerAddress -InterfaceAlias 'Wi-Fi' -ServerAddresses '127.0.0.2'; $set++ } catch { Write-Output ('IRNF_FAIL 0 v4 ' + $_.Exception.Message) }",
    "try { Set-DnsClientServerAddress -InterfaceAlias 'Wi-Fi' -ServerAddresses '::1'; $set++ } catch { Write-Output ('IRNF_FAIL 0 v6 ' + $_.Exception.Message) }",
    "try { Set-DnsClientServerAddress -InterfaceAlias 'Bob''s Ethernet' -ServerAddresses '127.0.0.2'; $set++ } catch { Write-Output ('IRNF_FAIL 1 v4 ' + $_.Exception.Message) }",
    'if ($set) { Clear-DnsClientCache }'
  ].join('\n'), 'a family the adapter does not have is never attempted');
});

test('engage (win32): an adapter that refuses is a warning naming it, not a session with no guard', async () => {
  const h = harness('win32', (cmd, args) => (/ConvertTo-Json/.test(args.at(-1))
    ? WIN_SNAP
    : "IRNF_FAIL 1 v6 No MSFT_DNSClientServerAddress objects found with property 'InterfaceAlias' equal to 'Ethernet'.\r\n"));
  const r = await h.guard.engage({ level: 'standard', peer4: PEER4, peer6: PEER6, tunAlias: 'IRNetFree' });
  assert.equal(r.engaged, true, 'the other adapters ARE guarded — the caller must start the drift watch');
  assert.ok(r.token);
  const warn = h.logs.find(([, level]) => level === 'warn');
  assert.ok(warn, JSON.stringify(h.logs));
  assert.match(warn[0], /Ethernet \(IPv6\): No MSFT_DNSClientServerAddress/);

  // nothing could be set at all: that is a failed guard, and the state file stays
  const all = harness('win32', (cmd, args) => (/ConvertTo-Json/.test(args.at(-1))
    ? WIN_SNAP
    : ['IRNF_FAIL 0 v4 Access is denied.', 'IRNF_FAIL 0 v6 Access is denied.',
      'IRNF_FAIL 1 v4 Access is denied.', 'IRNF_FAIL 1 v6 Access is denied.'].join('\r\n')));
  await assert.rejects(() => all.guard.engage({ level: 'standard', peer4: PEER4, tunAlias: 'IRNetFree' }), /Access is denied/);
  assert.equal(fs.existsSync(all.statePath), true);
});

test('winSnapshotScript: a NIC whose description says Hyper-V or Bluetooth carries real resolvers and is guarded', () => {
  // Excluded before, although Windows asks their resolvers like any other:
  // the only NIC of a Windows VM on Hyper-V (Windows Sandbox, Azure, a test
  // VM), the host's vEthernet on an EXTERNAL switch (the machine's real
  // address lives there — netWatcher.js already counts it), and a phone
  // tethered over Bluetooth PAN.
  const m = winSnapshotScript('IRNetFree').match(/-notmatch '([^']*)'/);
  assert.ok(m);
  const re = new RegExp(m[1], 'i');   // PowerShell's -notmatch is case-insensitive
  for (const d of ['Microsoft Hyper-V Network Adapter', 'Hyper-V Virtual Ethernet Adapter #2',
    'Bluetooth Device (Personal Area Network)', 'Intel(R) Wi-Fi 6 AX201 160MHz', 'Remote NDIS based Internet Sharing Device',
    'Intel(R) PRO/1000 MT Desktop Adapter', 'vmxnet3 Ethernet Adapter']) {
    assert.equal(re.test(d), false, `${d} must be guarded`);
  }
  // another VPN's tunnel, loopback and the host-only side of a hypervisor are not ours to touch
  for (const d of ['Wintun Userspace Tunnel', 'TAP-Windows Adapter V9', 'Microsoft KM-TEST Loopback Adapter',
    'VMware Virtual Ethernet Adapter for VMnet8', 'VirtualBox Host-Only Ethernet Adapter']) {
    assert.equal(re.test(d), true, `${d} stays excluded`);
  }
});

test('winSnapshotScript says which families an adapter has, and skips one with no IP interface at all', () => {
  const s = winSnapshotScript('IRNetFree');
  assert.match(s, /\$d4 = @\(Get-DnsClientServerAddress -InterfaceIndex \$a\.ifIndex -AddressFamily IPv4\)/);
  assert.match(s, /\$d6 = @\(Get-DnsClientServerAddress -InterfaceIndex \$a\.ifIndex -AddressFamily IPv6\)/);
  assert.match(s, /if \(-not \$d4\.Count -and -not \$d6\.Count\) \{ continue \}/);
  assert.match(s, /has4 = \[bool\]\$d4\.Count; has6 = \[bool\]\$d6\.Count;/);
  assert.deepEqual(parseWinSnapshot('[{"alias":"Wi-Fi","v4":["192.168.8.1"],"v6":[],"has4":true,"has6":false,"dhcp4":true,"dhcp6":true}]'),
    [{ alias: 'Wi-Fi', v4: ['192.168.8.1'], v6: [], has4: true, has6: false, dhcp4: true, dhcp6: true }]);
});

test('refresh (win32): drift is measured against the loopback hold, and a family the adapter lacks is never drift', async () => {
  let snapshot = JSON.stringify([
    { alias: 'Wi-Fi', v4: ['192.168.8.1'], v6: ['fe80::1'], has4: true, has6: true, dhcp4: true, dhcp6: true },
    { alias: 'Ethernet', v4: ['192.168.1.1'], v6: [], has4: true, has6: false, dhcp4: true, dhcp6: true }
  ]);
  let v4 = '', v6 = '';
  const h = harness('win32', (cmd, args) => {
    if (cmd === 'netsh') return args[1] === 'ipv6' ? v6 : v4;
    return /ConvertTo-Json/.test(args.at(-1)) ? snapshot : '';
  });
  // no v6 peer (tun2socks whose v6 setup failed): the v6 family is watched anyway
  const { token } = await h.guard.engage({ level: 'standard', peer4: '10.255.0.1', peer6: null, tunAlias: 'XrayTun' });
  const { hold4, hold6 } = h.state();
  const ps = () => h.calls.filter(c => c.cmd === 'powershell').length;

  v4 = ['', netshBlock('Wi-Fi', 'Statically Configured DNS Servers', [hold4]), netshBlock('Ethernet', 'Statically Configured DNS Servers', [hold4])].join('\r\n');
  v6 = ['', netshBlock('Wi-Fi', 'Statically Configured DNS Servers', [hold6])].join('\r\n');
  let p = ps();
  assert.deepEqual(await h.guard.refresh({ token }), { refreshed: false, adapters: 0, quick: true });
  assert.equal(ps(), p, 'the holds are what the adapters should list — no PowerShell');

  // the router's RA puts its v6 resolver back on Wi-Fi: seen although peer6 is null
  v6 = ['', netshBlock('Wi-Fi', 'DNS servers configured through DHCP', ['fe80::1%12'])].join('\r\n');
  snapshot = JSON.stringify([
    { alias: 'Wi-Fi', v4: [hold4], v6: ['fe80::1'], has4: true, has6: true },
    { alias: 'Ethernet', v4: [hold4], v6: [], has4: true, has6: false }
  ]);
  p = ps();
  assert.deepEqual(await h.guard.refresh({ token }), { refreshed: true, adapters: 1 });
  assert.equal(ps(), p + 2);
  assert.deepEqual(written(h.calls.at(-1).script), [{ alias: 'Wi-Fi', addr: hold6 }], 'only the family that drifted');

  // Ethernet has no IPv6 at all: its empty v6 list is not drift, on any tick
  snapshot = JSON.stringify([
    { alias: 'Wi-Fi', v4: [hold4], v6: [hold6], has4: true, has6: true },
    { alias: 'Ethernet', v4: [hold4], v6: [], has4: true, has6: false }
  ]);
  assert.deepEqual(await h.guard.refresh({ token, full: true }), { refreshed: false, adapters: 0 });
});

test('engage (win32): our own hold is stripped from a re-read snapshot, but a user\'s own loopback resolver is an original', async () => {
  // A local DNS proxy (dnscrypt-proxy, Acrylic…) is configured exactly like
  // this: 127.0.0.1 is never our hold, and ::1 beside it is the user's too.
  // It must come back on disconnect.
  const own = JSON.stringify([{ alias: 'Wi-Fi', v4: ['127.0.0.1'], v6: ['::1'], has4: true, has6: true, dhcp4: false, dhcp6: false }]);
  const h = harness('win32', snapAnswer(own));
  await h.guard.engage({ level: 'standard', peer4: PEER4, peer6: PEER6, tunAlias: 'IRNetFree' });
  assert.deepEqual(h.state().win.adapters[0].v6, ['::1']);
  assert.match(winRestoreScript(h.state().win.adapters), /-ServerAddresses '::1'/);

  // A re-engage reads our own hold back off an adapter it has not recorded
  // under that alias (renamed mid-session): that is ours, never an original.
  let snaps = 0;
  const g = harness('win32', (cmd, args) => {
    if (!/ConvertTo-Json/.test(args.at(-1))) return '';
    return ++snaps === 1 ? WIN_SNAP : JSON.stringify([{ alias: 'Wi-Fi 2', v4: ['127.0.0.2'], v6: ['::1'], has4: true, has6: true, dhcp4: false, dhcp6: false }]);
  });
  const opts = { level: 'standard', peer4: PEER4, peer6: PEER6, tunAlias: 'IRNetFree' };
  await g.guard.engage(opts);
  await g.guard.engage(opts);
  const renamed = g.state().win.adapters.find(a => a.alias === 'Wi-Fi 2');
  assert.deepEqual([renamed.v4, renamed.v6], [[], []]);
});

/**
 * Review I1. A USB NIC or an RNDIS tether unplugged before the disconnect is
 * skipped by the restore (it is not there) while the state file is cleared —
 * and Windows keeps its static 127.0.0.2 / ::1 for when it comes back. The next
 * FIRST engage then read our hold as the adapter's original (dhcp4:false) and
 * the release after it pinned 127.0.0.2 for good: no DNS on that adapter
 * outside the VPN, ever. 127.0.0.2 is ours by construction, with or without a
 * state file; ::1 is ours when it sits beside it.
 */
test('engage (win32): a hold left behind on an adapter that missed its restore is never recorded as the original', async () => {
  const h = harness('win32', snapAnswer(JSON.stringify([
    { alias: 'USB Ethernet', v4: ['127.0.0.2'], v6: ['::1'], has4: true, has6: true, dhcp4: false, dhcp6: false },
    { alias: 'Wi-Fi', v4: ['192.168.8.1'], v6: ['::1'], has4: true, has6: true, dhcp4: true, dhcp6: false }
  ])));
  assert.equal(fs.existsSync(h.statePath), false, 'no session of ours is live — the first engage');
  await h.guard.engage({ level: 'standard', peer4: PEER4, peer6: PEER6, tunAlias: 'IRNetFree' });
  const [usb, wifi] = h.state().win.adapters;
  assert.deepEqual([usb.v4, usb.v6], [[], []], 'recorded as "was DHCP" — the reset is the restore');
  assert.deepEqual(wifi.v6, ['::1'], '::1 without our 127.0.0.2 beside it is the user\'s own');
  const restore = winRestoreScript(h.state().win.adapters);
  assert.doesNotMatch(restore, /'127\.0\.0\.2'/);
  assert.match(restore, /if \(Get-NetAdapter -InterfaceAlias 'USB Ethernet'[^\n]*\n[^\n]*'USB Ethernet' -ResetServerAddresses\n\}/);
});

/**
 * Review M1. On Windows the tunnel's own resolvers are never written to an
 * adapter any more, so they are not ours to strip: with managed DNS off peer4
 * is the user's own public resolver, and a user who set 1.1.1.1 statically was
 * reset to DHCP at disconnect. Only a state file from before the hold (which
 * did write the peers) still gets them stripped.
 */
test('engage (win32): a static resolver that is also the tunnel\'s (managed DNS off) is an original', async () => {
  const h = harness('win32', snapAnswer(JSON.stringify([
    { alias: 'Wi-Fi', v4: ['1.1.1.1', '8.8.8.8'], v6: [], has4: true, has6: true, dhcp4: false, dhcp6: true }
  ])));
  await h.guard.engage({ level: 'standard', peer4: '1.1.1.1', peer6: null, tunAlias: 'IRNetFree' });
  assert.deepEqual(h.state().win.adapters[0].v4, ['1.1.1.1', '8.8.8.8']);
  assert.match(winRestoreScript(h.state().win.adapters), /-ServerAddresses '1\.1\.1\.1','8\.8\.8\.8'/);

  // a live state file written before the hold existed: it wrote the peers
  const g = harness('win32', snapAnswer(JSON.stringify([
    { alias: 'Wi-Fi', v4: [PEER4], v6: [PEER6], has4: true, has6: true },
    { alias: 'Ethernet', v4: [PEER4], v6: [PEER6], has4: true, has6: true, dhcp4: false, dhcp6: false }
  ])));
  fs.writeFileSync(g.statePath, JSON.stringify({
    version: 1, peer4: PEER4, peer6: PEER6, level: 'standard', strict: false,
    win: { adapters: [{ alias: 'Wi-Fi', v4: ['192.168.8.1'], v6: [], dhcp4: true, dhcp6: true }] }
  }));
  await g.guard.engage({ level: 'standard', peer4: PEER4, peer6: PEER6, tunAlias: 'IRNetFree' });
  const eth = g.state().win.adapters.find(a => a.alias === 'Ethernet');
  assert.deepEqual([eth.v4, eth.v6], [[], []]);
});

test('refresh (win32): an adapter first seen mid-session keeps a ::1 of its own', async () => {
  let snapshot = WIN_SNAP;
  const h = harness('win32', (cmd, args) => (/ConvertTo-Json/.test(args.at(-1)) ? snapshot : ''));
  const { token } = await h.guard.engage({ level: 'standard', peer4: PEER4, peer6: PEER6, tunAlias: 'IRNetFree' });
  snapshot = JSON.stringify([
    { alias: 'Wi-Fi', v4: [HOLD4], v6: [HOLD6], has4: true, has6: true },
    { alias: 'Ethernet', v4: [HOLD4], v6: [HOLD6], has4: true, has6: true },
    { alias: 'USB LAN', v4: ['192.168.20.1'], v6: ['::1'], has4: true, has6: true, dhcp4: true, dhcp6: false }
  ]);
  assert.deepEqual(await h.guard.refresh({ token, full: true }), { refreshed: true, adapters: 1 });
  assert.deepEqual(h.state().win.adapters.at(-1).v6, ['::1']);
});

/**
 * Review M2. An adapter family that refuses (the error is the adapter's, it
 * does not go away) was retried on every 30-s tick — a PowerShell snapshot
 * each time, a warning each time, and a Clear-DnsClientCache each time: the
 * whole machine's DNS cache flushed twice a minute for the session. It is
 * retried on the full ticks only (the first and every tenth), so a one-off
 * refusal — a race with an unplug — does not leave the family on its own
 * resolver for the whole session; and it is warned about once.
 */
test('refresh (win32): a family that refused is retried on full ticks only, warned about once, and the cache is flushed only after a Set that worked', async () => {
  let snapshot = WIN_SNAP, v4 = '', v6 = '';
  let applyOut = 'IRNF_FAIL 1 v6 The requested operation is not supported.\r\n';
  const h = harness('win32', (cmd, args) => {
    if (cmd === 'netsh') return args[1] === 'ipv6' ? v6 : v4;
    return /ConvertTo-Json/.test(args.at(-1)) ? snapshot : applyOut;
  });
  const { token } = await h.guard.engage({ level: 'standard', peer4: PEER4, peer6: PEER6, tunAlias: 'IRNetFree' });
  const warns = () => h.logs.filter(([l, level]) => level === 'warn' && /could not set the DNS/.test(l)).length;
  assert.equal(warns(), 1);
  applyOut = '';
  const ps = () => h.calls.filter(c => c.cmd === 'powershell').length;

  // Ethernet's v6 still lists the router: not drift, it is the family that refused
  v4 = HELD_V4;
  v6 = HELD_V6.replace(netshBlock('Ethernet', 'Statically Configured DNS Servers', [HOLD6]),
    netshBlock('Ethernet', 'DNS servers configured through DHCP', ['fe80::1%22']));
  let p = ps();
  assert.deepEqual(await h.guard.refresh({ token }), { refreshed: false, adapters: 0, quick: true });
  assert.equal(ps(), p, 'no PowerShell on the cheap tick');

  // a cheap tick that does take the snapshot (Ethernet's v4 drifted): the
  // family that works is repaired, the one that refused is not attempted
  v4 = HELD_V4.replace(netshBlock('Ethernet', 'Statically Configured DNS Servers', [HOLD4]),
    netshBlock('Ethernet', 'DNS servers configured through DHCP', ['192.168.1.1']));
  snapshot = JSON.stringify([
    { alias: 'Wi-Fi', v4: [HOLD4], v6: [HOLD6], has4: true, has6: true },
    { alias: 'Ethernet', v4: ['192.168.1.1'], v6: ['fe80::1'], has4: true, has6: true }
  ]);
  assert.deepEqual(await h.guard.refresh({ token }), { refreshed: true, adapters: 1 });
  assert.deepEqual(written(h.calls.at(-1).script), [{ alias: 'Ethernet', addr: HOLD4 }]);

  // a full tick tries it again; refusing again is neither an error nor a second warning
  v4 = HELD_V4;
  snapshot = JSON.stringify([
    { alias: 'Wi-Fi', v4: [HOLD4], v6: [HOLD6], has4: true, has6: true },
    { alias: 'Ethernet', v4: [HOLD4], v6: ['fe80::1'], has4: true, has6: true }
  ]);
  applyOut = 'IRNF_FAIL 0 v6 The requested operation is not supported.\r\n';
  assert.deepEqual(await h.guard.refresh({ token, full: true }), { refreshed: false, adapters: 0, refused: 1 });
  assert.deepEqual(written(h.calls.at(-1).script), [{ alias: 'Ethernet', addr: HOLD6 }]);
  assert.equal(warns(), 1, 'said once per connect');
  assert.equal(h.logs.some(([l]) => /repaired DNS drift/.test(l)), true, 'the v4 repair above');
  const repairs = h.logs.filter(([l]) => /repaired DNS drift/.test(l)).length;

  // … and between full ticks it is left alone again
  p = ps();
  assert.deepEqual(await h.guard.refresh({ token }), { refreshed: false, adapters: 0, quick: true });
  assert.equal(ps(), p);

  // the refusal was a one-off: the next full tick holds it
  applyOut = '';
  assert.deepEqual(await h.guard.refresh({ token, full: true }), { refreshed: true, adapters: 1 });
  assert.deepEqual(written(h.calls.at(-1).script), [{ alias: 'Ethernet', addr: HOLD6 }]);
  assert.equal(h.logs.filter(([l]) => /repaired DNS drift/.test(l)).length, repairs + 1);
});

/**
 * Review minor 2. The cheap tick looks at an alias nobody owns once — but
 * netsh also lists an adapter that is not up, with whatever resolver it last
 * had. Judged (and skipped: the snapshot lists only adapters that are Up)
 * while it was down, it must still be looked at again when it comes up on a
 * network that hands it a different resolver.
 */
test('refresh (win32): an alias judged once is looked at again when its resolvers change', async () => {
  let v4 = HELD_V4, snapshot = WIN_SNAP;
  const h = harness('win32', (cmd, args) => {
    if (cmd === 'netsh') return args[1] === 'ipv6' ? HELD_V6 : v4;
    return /ConvertTo-Json/.test(args.at(-1)) ? snapshot : '';
  });
  const { token } = await h.guard.engage({ level: 'standard', peer4: PEER4, peer6: PEER6, tunAlias: 'IRNetFree' });
  snapshot = JSON.stringify([
    { alias: 'Wi-Fi', v4: [HOLD4], v6: [HOLD6], has4: true, has6: true },
    { alias: 'Ethernet', v4: [HOLD4], v6: [HOLD6], has4: true, has6: true }
  ]);
  const ps = () => h.calls.filter(c => c.cmd === 'powershell').length;
  // down, listed with a stale resolver: one snapshot, which does not list it
  v4 = HELD_V4 + '\r\n' + netshBlock('USB LAN', 'DNS servers configured through DHCP', ['192.168.50.1']);
  let p = ps();
  assert.deepEqual(await h.guard.refresh({ token }), { refreshed: false, adapters: 0 });
  assert.equal(ps(), p + 1);
  p = ps();
  assert.deepEqual(await h.guard.refresh({ token }), { refreshed: false, adapters: 0, quick: true });
  assert.equal(ps(), p, 'the same alias with the same resolver is not looked at twice');
  // up, on another network: looked at again, and adopted
  v4 = HELD_V4 + '\r\n' + netshBlock('USB LAN', 'DNS servers configured through DHCP', ['10.20.0.1']);
  snapshot = JSON.stringify([
    { alias: 'Wi-Fi', v4: [HOLD4], v6: [HOLD6], has4: true, has6: true },
    { alias: 'Ethernet', v4: [HOLD4], v6: [HOLD6], has4: true, has6: true },
    { alias: 'USB LAN', v4: ['10.20.0.1'], v6: [], has4: true, has6: false, dhcp4: true, dhcp6: true }
  ]);
  assert.deepEqual(await h.guard.refresh({ token }), { refreshed: true, adapters: 1 });
  assert.deepEqual(written(h.calls.at(-1).script), [{ alias: 'USB LAN', addr: HOLD4 }]);
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
  assert.equal(h.calls[1].script, winApplyScript(adapters, HOLD4, HOLD6), 'the standard step still runs first');
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
    [`Leak guard: DNS of 2 adapters → ${HOLD4} ${HOLD6} (loopback: nothing asked there leaves the machine; the tunnel's resolver ${PEER4} answers)`, 'info'],
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
  crashedSession(h, { level: 'strict', strict: true, win: { adapters: parseWinSnapshot(WIN_SNAP) } });

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
  assert.equal(r.engaged, true);
  assert.equal(r.adapters, 2);
  assert.ok(r.token, 'this session has a receipt too — release() is the same call either way');
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
  // The second engage DOES look again — that is how an adapter which has come
  // up since gets the override too (see 'engage over a live session adopts an
  // adapter that has come up since'). What it must never do is let what it
  // reads back overwrite an original it already holds: every alias below still
  // carries the resolver the machine had before we touched anything.
  assert.equal(snaps, 2);
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

/* ========================= the reconnect gap ========================= */
/*
 * The owner's report: the VPN gets confused when the network changes, and a
 * reconnect must not leak anything in the gap between the old tunnel going down
 * and the new one coming up.
 *
 * What makes that gap leak is the ordering above the guard — release, tear the
 * tunnel down, rebuild, engage again — which puts every physical adapter back on
 * the ISP's resolver, and takes the strict firewall down with it, for the whole
 * length of a rebuild. The primitives below are what a leak-free ordering needs:
 * a session RECEIPT, so an overtaken connect cannot undo the guard of the one
 * that overtook it; a re-engage that MERGES rather than replaces; and a hold
 * that widens the firewall for the next server without ever letting go.
 */

const winPs = (h) => h.calls.filter(c => c.cmd === 'powershell').map(c => c.script);
const winAnswer = (snap) => (cmd, args) => (/ConvertTo-Json/.test(args[args.length - 1]) ? snap : '');

/**
 * The residual race the phase-3 review carried forward: "two OVERLAPPING
 * connects can drop the override on a live tunnel — leak, not breakage".
 *
 * doConnect() releases the guard unconditionally when it finds itself stale.
 * But by then the connect that overtook it may already have engaged the guard
 * for a tunnel that is up and carrying traffic — so the loser's release points
 * every adapter back at the ISP, removes the strict firewall, and deletes the
 * state file, while the UI says connected and the tunnel keeps running. The
 * receipt is what tells the two apart.
 */
test('release: a receipt from an overtaken connect cannot undo the live session', async () => {
  const h = harness('win32', winAnswer(WIN_SNAP));
  const opts = { level: 'standard', peer4: PEER4, tunAlias: 'IRNetFree' };
  const first = await h.guard.engage(opts);
  assert.ok(first.token, 'engage hands back a receipt for the session it created');
  const second = await h.guard.engage(opts);
  assert.notEqual(second.token, first.token, 'a second engage is a second session');
  h.calls.length = 0; h.logs.length = 0;

  const late = await h.guard.release({ token: first.token });
  assert.equal(late.released, false);
  assert.equal(late.stale, true);
  assert.equal(h.calls.length, 0, 'not one adapter is touched');
  assert.equal(fs.existsSync(h.statePath), true, 'and the live session keeps the only record of the originals');

  const own = await h.guard.release({ token: second.token });
  assert.equal(own.released, true, 'the session that owns the override can still release it');
  assert.equal(fs.existsSync(h.statePath), false);
});

/**
 * The same race with the receipt left in the caller's pocket — which is what
 * main.js does today, at the `if (stale())` cleanup in doConnect(). Recorded as
 * a test because the fix is only half in this file: the receipt exists now, but
 * it protects nothing until the caller presents it.
 */
test('WITHOUT a receipt the overlap still drops the override on a live tunnel', async () => {
  const h = harness('win32', winAnswer(WIN_SNAP));
  const opts = { level: 'standard', peer4: PEER4, tunAlias: 'IRNetFree' };
  await h.guard.engage(opts);                     // connect A engages
  const b = await h.guard.engage(opts);           // connect B overtakes it and re-engages
  await h.guard.release();                        // A notices it is stale and "cleans up"

  assert.equal(fs.existsSync(h.statePath), false,
    'B\'s tunnel is up and carrying traffic, and every adapter is back on the ISP\'s resolver');
  assert.deepEqual(await h.guard.release({ token: b.token }), { released: false, adapters: 0 },
    'with nothing left for B to put back when it finally does disconnect');
});

test('release with no receipt is still the unconditional teardown', async () => {
  // Disconnect, quit and the exit hook mean it whoever engaged: they are the
  // user's own intent, not one connect racing another.
  const h = harness('win32', winAnswer(WIN_SNAP));
  await h.guard.engage({ level: 'standard', peer4: PEER4, tunAlias: 'IRNetFree' });
  assert.equal((await h.guard.release()).released, true);
  assert.equal(fs.existsSync(h.statePath), false);
  // and a receipt for a session that is already gone is not an error either
  assert.deepEqual(await h.guard.release({ token: 'irnf-1' }), { released: false, adapters: 0 });
});

/**
 * A NIC that was down when the guard engaged never got the override. Today the
 * only thing that fixes it is the release + re-snapshot of a full reconnect — so
 * an ordering that holds the guard across the gap would leave the new adapter on
 * the ISP's resolver for the whole session. Plugging the ethernet cable in while
 * connected over Wi-Fi is exactly that case, and it is also a network change, so
 * the two land together.
 */
test('engage over a live session adopts an adapter that has come up since', async () => {
  const LATER = JSON.stringify([
    // Wi-Fi reads back OUR peer now — the first engage put it there.
    { alias: 'Wi-Fi', v4: [PEER4], v6: [], dhcp4: false, dhcp6: true },
    { alias: 'Ethernet', v4: [PEER4], v6: [], dhcp4: false, dhcp6: true },
    // and this one was plugged in after the tunnel came up: never overridden.
    { alias: 'Ethernet 2', v4: ['192.168.5.1'], v6: [], dhcp4: true, dhcp6: true }
  ]);
  let snaps = 0;
  const h = harness('win32', (cmd, args) => {
    if (!/ConvertTo-Json/.test(args[args.length - 1])) return '';
    return ++snaps === 1 ? WIN_SNAP : LATER;
  });
  const opts = { level: 'standard', peer4: PEER4, tunAlias: 'IRNetFree' };
  await h.guard.engage(opts);
  h.calls.length = 0;
  await h.guard.engage(opts);

  const adapters = h.state().win.adapters;
  assert.deepEqual(adapters.map(a => a.alias), ['Wi-Fi', 'Ethernet', 'Ethernet 2']);
  assert.deepEqual(adapters[0].v4, ['192.168.8.1'], 'the first session\'s originals are kept, not re-read');
  assert.deepEqual(adapters[1].v4, ['178.22.122.100']);
  assert.deepEqual(adapters[2], { alias: 'Ethernet 2', v4: ['192.168.5.1'], v6: [], dhcp4: true, dhcp6: true },
    'and the newcomer\'s own resolvers are recorded before it is touched');
  assert.match(winPs(h).join('\n'), /Set-DnsClientServerAddress -InterfaceAlias 'Ethernet 2'/,
    'the newcomer gets the override too — otherwise it hands every name to the ISP');
});

test('engage over a live session keeps an adapter that has gone away', async () => {
  // The USB NIC was unplugged mid-session. Its record must survive: if it comes
  // back before the release it is ours again, and the restore already skips an
  // adapter that no longer exists.
  let snaps = 0;
  const h = harness('win32', (cmd, args) => {
    if (!/ConvertTo-Json/.test(args[args.length - 1])) return '';
    return ++snaps === 1 ? WIN_SNAP : JSON.stringify([{ alias: 'Wi-Fi', v4: [PEER4], v6: [], dhcp4: false, dhcp6: true }]);
  });
  const opts = { level: 'standard', peer4: PEER4, tunAlias: 'IRNetFree' };
  await h.guard.engage(opts);
  await h.guard.engage(opts);
  assert.deepEqual(h.state().win.adapters.map(a => a.alias), ['Wi-Fi', 'Ethernet']);
  assert.deepEqual(h.state().win.adapters[1].v4, ['178.22.122.100']);
});

/**
 * Dropping from strict to standard without an intervening release leaves the
 * block rules on every physical adapter AND a state file that no longer mentions
 * them — so release() will not remove them either. Those rules block everything
 * that is not the tunnel, and the tunnel is what is about to go away: the machine
 * is left with no internet at all, and nothing in the app knows why.
 */
test('engage at standard over a live strict session takes the strict rules with it', async () => {
  const h = harness('win32', winAnswer(WIN_SNAP));
  await h.guard.engage({ level: 'strict', peer4: PEER4, tunAlias: 'IRNetFree', excludes: ['203.0.113.9'] });
  assert.equal(h.state().strict, true);
  h.calls.length = 0;

  await h.guard.engage({ level: 'standard', peer4: PEER4, tunAlias: 'IRNetFree' });
  assert.equal(h.state().strict, false);
  assert.match(winPs(h).join('\n'), /Remove-NetFirewallRule -Group 'IRNetFree'/,
    'the rules the state file no longer tracks must go now, while we still know they exist');
  assert.equal(/New-NetFirewallRule/.test(winPs(h).join('\n')), false, 'and none are put back');
});

test('engage (standard) over a live UDP block keeps the flag that gets the rules removed', async () => {
  const h = harness('win32', winAnswer(WIN_SNAP));
  await h.guard.engageUdpBlock({});
  await h.guard.engage({ level: 'standard', peer4: PEER4, tunAlias: 'IRNetFree' });
  assert.equal(h.state().udpBlock, true,
    'the DNS override does not touch the firewall, so the UDP rules are still out there');
  h.calls.length = 0;
  await h.guard.release();
  assert.match(winPs(h).join('\n'), /Remove-NetFirewallRule -Group 'IRNetFree'/);
});

test('engage (strict) over a live UDP block replaces those rules and says so', async () => {
  const h = harness('win32', winAnswer(WIN_SNAP));
  await h.guard.engageUdpBlock({});
  await h.guard.engage({ level: 'strict', peer4: PEER4, tunAlias: 'IRNetFree', excludes: [] });
  const st = h.state();
  assert.equal(st.strict, true);
  assert.equal(st.udpBlock, false, 'the strict apply removes the whole group first — those rules are gone');
});

/* --------------------------- holding across the gap --------------------------- */

test('holdForReconnect (win32, strict): the override stays, the firewall admits the next server too', async () => {
  const h = harness('win32', winAnswer(WIN_SNAP));
  await h.guard.engage({ level: 'strict', peer4: PEER4, tunAlias: 'IRNetFree', excludes: ['203.0.113.9'] });
  assert.deepEqual(h.state().excludes, ['203.0.113.9'], 'engage records what it cut the holes from');
  h.calls.length = 0; h.logs.length = 0;

  const r = await h.guard.holdForReconnect({ excludes: ['198.51.100.7'] });
  assert.equal(r.held, true);
  assert.equal(fs.existsSync(h.statePath), true, 'nothing is released — that is the entire point');
  assert.equal(h.calls.length, 1, 'one PowerShell run, and it is the firewall');
  assert.equal(h.calls[0].script, winStrictApplyScript({
    adapters: parseWinSnapshot(WIN_SNAP),
    ranges: rangeComplement(['203.0.113.9', '198.51.100.7', ...GUARD_EXCLUDES])
  }));
  assert.equal(/Set-DnsClientServerAddress/.test(h.calls[0].script), false,
    'the adapters keep pointing at the tunnel peer — during the gap that resolves nothing, which is the safe answer');
  assert.deepEqual(h.state().excludes, ['203.0.113.9', '198.51.100.7']);
  assert.deepEqual(h.state().win.adapters, parseWinSnapshot(WIN_SNAP), 'and the originals are untouched');
});

test('holdForReconnect (win32, standard): there is nothing to widen, and nothing is released', async () => {
  const h = harness('win32', winAnswer(WIN_SNAP));
  await h.guard.engage({ level: 'standard', peer4: PEER4, tunAlias: 'IRNetFree' });
  h.calls.length = 0;
  assert.equal((await h.guard.holdForReconnect({ excludes: ['198.51.100.7'] })).held, true);
  assert.equal(h.calls.length, 0, 'the DNS override is the whole guard at this level');
  assert.equal(fs.existsSync(h.statePath), true);
});

test('holdForReconnect with nothing engaged is a no-op', async () => {
  const h = harness('win32', winAnswer(WIN_SNAP));
  assert.deepEqual(await h.guard.holdForReconnect({ excludes: ['1.2.3.4'] }), { held: false, adapters: 0 });
  assert.equal(h.calls.length, 0);
  assert.equal(fs.existsSync(h.statePath), false);
});

test('holdForReconnect (darwin, strict): the anchor is reloaded with both servers in it', async () => {
  const h = harness('darwin', (cmd) => (cmd === 'privileged' ? 'IRNF_PF_WAS=enabled' : 'Wi-Fi\t192.168.8.1\n'));
  await h.guard.engage({ level: 'strict', peer4: PEER4, tunAlias: 'utun4', excludes: ['203.0.113.9'] });
  h.calls.length = 0;
  assert.equal((await h.guard.holdForReconnect({ excludes: ['198.51.100.7'] })).held, true);
  assert.equal(h.calls.length, 1);
  assert.equal(h.calls[0].script,
    macPfApplyScript(macPfAnchorText({ tunDevice: 'utun4', excludes: ['203.0.113.9', '198.51.100.7'] })));
  assert.equal(/setdnsservers/.test(h.calls[0].script), false);
});

test('the widened holes are narrowed again by the engage on the other side of the gap', async () => {
  // Holding is not a licence to keep the old server's hole open forever: the
  // re-engage rewrites the rules from the NEW tunnel's exclusions alone.
  const h = harness('win32', winAnswer(WIN_SNAP));
  await h.guard.engage({ level: 'strict', peer4: PEER4, tunAlias: 'IRNetFree', excludes: ['203.0.113.9'] });
  await h.guard.holdForReconnect({ excludes: ['198.51.100.7'] });
  h.calls.length = 0;
  await h.guard.engage({ level: 'strict', peer4: PEER4, tunAlias: 'IRNetFree', excludes: ['198.51.100.7'] });
  assert.deepEqual(h.state().excludes, ['198.51.100.7']);
  assert.match(winPs(h).join('\n'),
    new RegExp(rangeComplement(['198.51.100.7', ...GUARD_EXCLUDES]).map(r => `'${r}'`).join(',')));
});

/**
 * The whole point, end to end at this layer: a complete reconnect in which the
 * guard is never let go. Engage for the old tunnel, hold across the gap, engage
 * for the new one. If a single `-ResetServerAddresses` appears anywhere in the
 * scripts these three calls produce, some adapter went back to the ISP's
 * resolver while there was no tunnel — which is the leak the owner asked about.
 */
test('a reconnect with the guard held: no restore is ever run and the record survives', async () => {
  const h = harness('win32', winAnswer(WIN_SNAP));
  const s = await h.guard.engage({ level: 'strict', peer4: PEER4, tunAlias: 'IRNetFree', excludes: ['203.0.113.9'] });
  await h.guard.holdForReconnect({ excludes: ['198.51.100.7'], token: s.token });
  // — the old tunnel goes down and the new one comes up here —
  const again = await h.guard.engage({ level: 'strict', peer4: PEER4, tunAlias: 'IRNetFree', excludes: ['198.51.100.7'] });

  assert.equal(again.engaged, true);
  assert.equal(fs.existsSync(h.statePath), true, 'the file never went away, so nothing was ever unguarded');
  const scripts = winPs(h).join('\n');
  assert.equal(/-ResetServerAddresses/.test(scripts), false,
    'not one adapter was handed back to the ISP at any point in the reconnect');
  assert.deepEqual(h.state().win.adapters, parseWinSnapshot(WIN_SNAP), 'and the originals are still the originals');
  assert.deepEqual(h.state().excludes, ['198.51.100.7'], 'with the old server\'s hole closed again on the far side');
});

/**
 * M5, carried out of the phase-3 review: repairAtLaunch is fired and not awaited
 * (a macOS password prompt must not hold up the window), so it can still be
 * pending when the user presses Connect. The queue makes the two orderly, but
 * orderly is not enough — a repair that runs AFTER an engage would restore the
 * live session's adapters and delete the record of its originals. A state file
 * is only a previous session's while this process has engaged nothing.
 */
test('repairAtLaunch never undoes a session this process engaged', async () => {
  const h = harness('win32', winAnswer(WIN_SNAP));
  // what a crash left behind
  fs.writeFileSync(h.statePath, JSON.stringify({
    version: 1, peer4: PEER4, strict: false, win: { adapters: [{ alias: 'Wi-Fi', v4: ['192.168.8.1'], v6: [] }] }
  }));
  await h.guard.engage({ level: 'standard', peer4: PEER4, tunAlias: 'IRNetFree' });
  h.calls.length = 0; h.logs.length = 0;

  const r = await h.guard.repairAtLaunch();
  assert.equal(r.repaired, false);
  assert.equal(h.calls.length, 0, 'nothing is restored under a live tunnel');
  assert.equal(fs.existsSync(h.statePath), true);
  assert.deepEqual(h.logs, []);
});

test('repairAtLaunch still repairs when the app has engaged nothing yet', async () => {
  const h = harness('win32', winAnswer(WIN_SNAP));
  fs.writeFileSync(h.statePath, JSON.stringify({
    version: 1, peer4: PEER4, strict: false, win: { adapters: [{ alias: 'Wi-Fi', v4: ['192.168.8.1'], v6: [] }] }
  }));
  const r = await h.guard.repairAtLaunch();
  assert.equal(r.repaired, true);
  assert.equal(r.adapters, 1);
  assert.equal(fs.existsSync(h.statePath), false);
});

// L1. A recorded resolver is data read off the machine, and the restore script
// runs as root.
test('recorded resolvers are quoted before they reach a root shell', () => {
  const evil = "1.1.1.1'; touch /tmp/pwned; echo '";
  const script = macRestoreScript([{ name: 'Wi-Fi', dns: [evil, '9.9.9.9'] }]);
  // The address is data read off the machine and this script runs as root.
  // Every value is quoted (sh()); since audit M7 one that is not an IP literal
  // does not reach the script at all — the restore says less, never something else.
  assert.equal(script.includes(evil), false, 'the payload is never interpolated raw');
  assert.doesNotMatch(script, /pwned/);
  assert.match(script, /networksetup -setdnsservers 'Wi-Fi' '9\.9\.9\.9' \|\| FAIL=1/);
});

for (const dns of [['9.9.9.9', '149.112.112.112'], []]) {
  test('macOS restores pre-TUN DNS including DHCP: ' + JSON.stringify(dns), async () => {
    const h = harness('darwin', cmd => cmd === 'privileged' ? '' : 'Wi-Fi\t' + PEER4 + '\n');
    await h.guard.engage({level:'standard', peer4:PEER4, originalMacServices:[{name:'Wi-Fi',dns}]});
    assert.deepEqual(h.state().mac.services, [{name:'Wi-Fi',dns}]);
    await h.guard.release();
    assert.equal(h.calls.at(-1).script, macRestoreScript([{name:'Wi-Fi',dns}]));
  });
}
test('macOS retains previous-session originals ahead of a reconnect snapshot', async () => {
  const h = harness('darwin', cmd => cmd === 'privileged' ? '' : 'Wi-Fi\t' + PEER4 + '\n');
  const opts = {level:'standard', peer4:PEER4};
  await h.guard.engage({...opts, originalMacServices:[{name:'Wi-Fi',dns:['9.9.9.9']}]});
  await h.guard.engage({...opts, originalMacServices:[{name:'Wi-Fi',dns:[PEER4]}]});
  assert.deepEqual(h.state().mac.services, [{name:'Wi-Fi',dns:['9.9.9.9']}]);
});
test('macOS trusts a fresh uncontaminated service instead of stale setup DNS', async () => {
  const h = harness('darwin', cmd => cmd === 'privileged' ? '' : 'Wi-Fi\t8.8.4.4\nEthernet\t' + PEER4 + '\n');
  await h.guard.engage({level:'standard', peer4:PEER4, originalMacServices:[{name:'Wi-Fi',dns:['9.9.9.9']}]});
  assert.deepEqual(h.state().mac.services, [{name:'Wi-Fi',dns:['8.8.4.4']},{name:'Ethernet',dns:[]}]);
});
