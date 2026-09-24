'use strict';
/**
 * Every PowerShell we run reads its stdout back as UTF-8, and names adapters
 * without wildcard surprises.
 *
 * Windows PowerShell 5.1 writes REDIRECTED stdout in the console's OEM code
 * page. An adapter renamed "اترنت" (or any adapter on a Chinese or Russian
 * Windows) came back as "?????": xray was bound to an interface that does not
 * exist — TUN "connected", nothing passing — and `?` is a wildcard, so the leak
 * guard's `-InterfaceAlias '?????'` hit "Wi-Fi" as well.
 *
 * Proven by hand on the owner's machine (read-only): the same one-line script
 * printed "?????" plain and "اترنت" with the UTF-8 line in front; the escaped
 * bracket alias matched no adapter while the bare one matched "Wi-Fi".
 *
 * Nothing is spawned: execFile is stubbed before the modules load.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const os = require('node:os');

const cp = require('node:child_process');
const calls = [];
let answer = null;
// Never falls through to the real execFile: nothing here may run on the machine.
cp.execFile = (cmd, args, opts, cb) => {
  if (typeof opts === 'function') { cb = opts; opts = undefined; }
  if (!answer) throw new Error(`the test reached the real ${cmd}`);
  calls.push([cmd, args]);
  let out;
  try { out = answer(cmd, args); } catch (e) { return process.nextTick(() => cb(e, '', e.message)); }
  process.nextTick(() => cb(null, out, ''));
};

const P = require('../src/main/tunPlatform');
const procRouter = require('../src/main/procRouter');
const {
  LeakGuard, winApplyScript, winRestoreScript, winStrictApplyScript, winUdpBlockApplyScript
} = require('../src/main/leakGuard');

const UTF8_LINE = /^try \{ \[Console\]::OutputEncoding = \[System\.Text\.Encoding\]::UTF8 \} catch \{\};$/;

/** Every powershell call: flags, -Command, the UTF-8 line, then the script — untouched, last. */
function assertUtf8Call(args, scriptRe, label) {
  assert.deepEqual(args.slice(0, 3), ['-NoProfile', '-NonInteractive', '-Command'], `${label}: flags`);
  assert.match(args[3], UTF8_LINE, `${label}: the output encoding is not switched to UTF-8 first`);
  assert.equal(args.length, 5, `${label}: the script travels as ONE argument after it`);
  assert.match(args[4], scriptRe, `${label}: the script`);
}

test('psArgs: the UTF-8 line rides ahead of the script as its own argument', () => {
  const script = "$ErrorActionPreference = 'Stop'\nGet-NetAdapter";
  const args = P.psArgs(script);
  assertUtf8Call(args, /Get-NetAdapter/, 'psArgs');
  assert.equal(args[4], script, 'the script itself is not rewritten');
});

test('tunPlatform: every adapter / gateway query switches to UTF-8 and decodes the real name', async () => {
  const ETH = 'اترنت';
  answer = (cmd, args) => {
    const s = args[args.length - 1];
    // the gateway query answers JSON rows since the network-switch fix
    if (/Get-NetRoute/.test(s)) return JSON.stringify([{ nextHop: '192.168.1.1', ifIndex: 7, alias: ETH, routeMetric: 0, ifMetric: 25, state: 'Connected' }]) + '\r\n';
    if (/-InterfaceIndex 7/.test(s)) return ETH + '\r\n';
    if (/\.ifIndex/.test(s)) return '23\r\n';
    if (/\.Status/.test(s)) return 'Up\r\n';
    throw new Error('unexpected: ' + s);
  };
  calls.length = 0;
  try {
    assert.deepEqual(await P.physicalInterface('win32'), { name: ETH, ifIndex: '7', gateway: '192.168.1.1' },
      'the physical interface keeps its non-ASCII name — xray binds to exactly this string');
    assert.equal(await P.getTunIfIndex('IRNetFree'), '23');
    assert.equal(await P.waitForAdapter('IRNetFree', 1000), true);
    assert.ok(calls.length >= 4);
    for (const [cmd, args] of calls) {
      assert.equal(cmd, 'powershell');
      assertUtf8Call(args, /Get-Net(Route|Adapter)/, 'tunPlatform');
    }
  } finally { answer = null; }
});

test('procRouter: process names come back through the same UTF-8 PowerShell', async (t) => {
  const realPlatform = os.platform;
  os.platform = () => 'win32';
  t.after(() => { os.platform = realPlatform; answer = null; });
  answer = () => '微信|4242|203.0.113.9|微信.exe\r\n';
  calls.length = 0;
  const list = await procRouter.listProcesses();
  assert.equal(calls.length, 1);
  assertUtf8Call(calls[0][1], /Get-NetTCPConnection/, 'procRouter');
  assert.deepEqual(list.map(p => p.name), ['微信'], 'the process name a routing rule keys on survives');
});

test('leakGuard: every PowerShell it runs, async and at exit, switches to UTF-8 first', async () => {
  const fs = require('node:fs');
  const path = require('node:path');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-psenc-'));
  const seen = [];
  const snap = JSON.stringify([{ alias: 'اترنت', v4: ['192.168.1.1'], v6: [], dhcp4: true, dhcp6: true }]);
  const guard = new LeakGuard({
    userData: dir, platform: 'win32', onLog: () => {},
    run: async (cmd, args) => { seen.push([cmd, args]); return /ConvertTo-Json/.test(args[args.length - 1]) ? snap : ''; },
    runSync: (cmd, args) => { seen.push([cmd, args]); return ''; }
  });
  try {
    await guard.engage({ peer4: '172.19.0.2', peer6: null, level: 'standard', tunAlias: 'IRNetFree' });
    assert.equal(guard.readState().win.adapters[0].alias, 'اترنت', 'the journal names the adapter as Windows does');
    assert.equal(guard.releaseSync(), true);
    assert.ok(seen.length >= 3);
    for (const [cmd, args] of seen) {
      assert.equal(cmd, 'powershell');
      assertUtf8Call(args, /./, 'leakGuard');
    }
    // the adapter is held on loopback now, not on the tunnel peer
    assert.match(seen[1][1][4], /-InterfaceAlias 'اترنت' -ServerAddresses '127\.0\.0\.2'/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('an alias with brackets is escaped for -InterfaceAlias, which is a wildcard; plain names are untouched', () => {
  const odd = { alias: 'Ethernet [USB]', v4: ['9.9.9.9'], v6: [], dhcp4: false, dhcp6: true };
  const esc = "'Ethernet `[USB`]'";
  const apply = winApplyScript([odd, { alias: 'Wi-Fi' }], '172.19.0.2', null);
  assert.ok(apply.includes(`Set-DnsClientServerAddress -InterfaceAlias ${esc} -ServerAddresses '172.19.0.2'`), apply);
  assert.ok(apply.includes("Set-DnsClientServerAddress -InterfaceAlias 'Wi-Fi' -ServerAddresses '172.19.0.2'"), 'a plain name is byte-identical');
  const restore = winRestoreScript([odd]);
  assert.ok(restore.includes(`if (Get-NetAdapter -InterfaceAlias ${esc} -ErrorAction SilentlyContinue) {`), restore);
  assert.ok(restore.includes(`Set-DnsClientServerAddress -InterfaceAlias ${esc} -ResetServerAddresses`));
  assert.ok(restore.includes(`Set-DnsClientServerAddress -InterfaceAlias ${esc} -ServerAddresses '9.9.9.9'`));
  const strict = winStrictApplyScript({ adapters: [odd], ranges: ['1.0.0.0-9.255.255.255'] });
  assert.ok(strict.includes(`-DisplayName 'IRNetFree strict TCP Ethernet [USB]'`), 'the display name is just text');
  assert.ok(strict.includes(`-InterfaceAlias ${esc} -Protocol TCP`), strict);
  const udp = winUdpBlockApplyScript({ adapters: [odd], ranges: ['1.0.0.0-9.255.255.255'] });
  assert.ok(udp.includes(`-InterfaceAlias ${esc} -Protocol UDP`), udp);
  // a backtick — the wildcard escape itself — is escaped too; a quote still doubles
  assert.ok(winApplyScript([{ alias: "Bob's `lab`" }], '172.19.0.2', null).includes("-InterfaceAlias 'Bob''s ``lab``'"));
  // `?` cannot be in a Windows connection name: in a record it is an alias an
  // older build read garbled and APPLIED as a wildcard, and only the same
  // wildcard undoes it
  assert.ok(winRestoreScript([{ alias: '?????', v4: [], v6: [] }]).includes("-InterfaceAlias '?????' -ResetServerAddresses"));
});
