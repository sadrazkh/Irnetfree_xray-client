'use strict';
/**
 * The tun2socks backend's Windows start path with every shell command stubbed
 * (the tunSingbox.test.js pattern). What is pinned is the exact route / netsh
 * lines it issues — the IPv6 ones are new in v1.7.2, and nobody can run them
 * on a machine whose live tunnel must not be touched.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

// tunPlatform.js destructures child_process at require time: stubs first.
const cp = require('node:child_process');
const spawns = [];
const execs = [];
let table = [];
cp.spawn = (...args) => {
  spawns.push(args);
  const p = new EventEmitter();
  p.stdout = new EventEmitter();
  p.stderr = new EventEmitter();
  p.pid = 777;
  p.kill = () => {};
  return p;
};
cp.execFile = (cmd, args, opts, cb) => {
  if (typeof opts === 'function') { cb = opts; opts = undefined; }
  execs.push([cmd, args]);
  const line = [cmd, ...args].join(' ');
  let out = '';
  for (const [re, val] of table) if (re.test(line)) { out = val; break; }
  if (out instanceof Error) process.nextTick(() => cb(out, '', out.message));
  else process.nextTick(() => cb(null, out, ''));
  return new EventEmitter();
};
cp.execFileSync = (cmd, args) => { execs.push([cmd, args]); return ''; };

const { TunManager, TUN_GW, TUN_GW6 } = require('../src/main/tunManager');

const execLines = () => execs.map(([c, a]) => [c, ...a].join(' '));
const netshLines = () => execs.filter(([c]) => c === 'netsh').map(([, a]) => a.join(' '));

/** A ready-to-start backend over a temp bin dir, plus the canned answers a start needs. */
function harness(extraTable = []) {
  spawns.length = 0;
  execs.length = 0;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-t2s-test-'));
  for (const f of ['tun2socks.exe', 'wintun.dll']) fs.writeFileSync(path.join(dir, f), '');
  const logs = [];
  const tun = new TunManager({ extraDirs: [dir], onLog: (line, level) => logs.push([level, line]), lang: 'en' });
  tun.dirs = () => [dir];
  tun.tun2socksPath = () => path.join(dir, 'tun2socks.exe');
  tun.isElevated = () => true;
  table = [
    ...extraTable,
    [/Get-NetRoute -DestinationPrefix/, '192.168.8.1|22\r\n'],
    [/Get-NetAdapter -Name 'XrayTun'.*\.Status$/, 'Up\r\n'],
    [/Get-NetAdapter -Name 'XrayTun'.*\.ifIndex$/, '44\r\n']
  ];
  return { tun, dir, logs, done: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

const V6_LINES = [
  'interface ipv6 add address interface=XrayTun address=fdfe:dcba:9876::1/126 store=active',
  'interface ipv6 set dnsservers name=XrayTun static fdfe:dcba:9876::2 primary validate=no',
  'interface ipv6 add route prefix=::/1 interface=XrayTun nexthop=fdfe:dcba:9876::2 metric=1 store=active',
  'interface ipv6 add route prefix=8000::/1 interface=XrayTun nexthop=fdfe:dcba:9876::2 metric=1 store=active'
];

test('win32 start: v4 as before, then the adapter gets a v6 address, the peer as v6 resolver and ::/1 + 8000::/1', async () => {
  const h = harness();
  try {
    await h.tun.startWindows(10808, '1.2.3.4', ['10.255.0.1']);
    assert.equal(h.tun.active, true);
    assert.equal(h.tun.dnsPeer6, TUN_GW6, 'the leak guard reads this as the v6 peer');
    assert.equal(TUN_GW6, 'fdfe:dcba:9876::2', 'the sing-box backend\'s peer: one v6 peer whichever backend is live');
    assert.equal(spawns[0][0], path.join(h.dir, 'tun2socks.exe'));
    assert.deepEqual(spawns[0][1], ['-device', 'XrayTun', '-proxy', 'socks5://127.0.0.1:10808', '-loglevel', 'warn']);

    const lines = execLines();
    assert.ok(lines.includes('route add 1.2.3.4 mask 255.255.255.255 192.168.8.1 metric 1 if 22'), 'server bypass route');
    assert.deepEqual(netshLines(), [
      'interface ip set address name=XrayTun static 10.255.0.2 255.255.255.0',
      'interface ip set interface interface=XrayTun metric=1',
      'interface ip set dnsservers name=XrayTun static 10.255.0.1 primary validate=no',
      ...V6_LINES
    ]);
    // the v4 split routes come AFTER the v6 setup, unchanged
    const routes = lines.filter(l => /^route add (0\.0\.0\.0|128\.0\.0\.0) /.test(l));
    assert.deepEqual(routes, [
      `route add 0.0.0.0 mask 128.0.0.0 ${TUN_GW} metric 1 if 44`,
      `route add 128.0.0.0 mask 128.0.0.0 ${TUN_GW} metric 1 if 44`
    ]);
    assert.ok(lines.indexOf(routes[0]) > lines.indexOf('netsh ' + V6_LINES[3]));
    assert.ok(h.logs.some(([, l]) => /IPv6 -> TUN too/.test(l)));

    // stop: v4 split routes, v6 split routes and the bypass route all go
    execs.length = 0;
    await h.tun.cleanupRoutesWindows();
    assert.deepEqual(execLines(), [
      `route delete 0.0.0.0 mask 128.0.0.0 ${TUN_GW}`,
      `route delete 128.0.0.0 mask 128.0.0.0 ${TUN_GW}`,
      'netsh interface ipv6 delete route prefix=::/1 interface=XrayTun nexthop=fdfe:dcba:9876::2',
      'netsh interface ipv6 delete route prefix=8000::/1 interface=XrayTun nexthop=fdfe:dcba:9876::2',
      'route delete 1.2.3.4'
    ]);
    assert.equal(h.tun.dnsPeer6, null, 'no v6 peer once the adapter is gone');
  } finally { h.done(); }
});

test('win32 start: a failing v6 step is logged, its routes withdrawn, dnsPeer6 stays null — and v4 comes up regardless', async () => {
  const h = harness([[/ipv6 add route prefix=8000::\/1/, new Error('Element not found.')]]);
  try {
    await h.tun.startWindows(10808, '1.2.3.4', ['10.255.0.1']);
    assert.equal(h.tun.active, true, 'v4 tunnel is up');
    assert.equal(h.tun.dnsPeer6, null, 'the guard will leave the v6 family alone, as before v1.7.2');
    const netsh = netshLines();
    assert.ok(netsh.includes(V6_LINES[3]), 'the failing line was attempted');
    assert.ok(netsh.includes('interface ipv6 delete route prefix=::/1 interface=XrayTun nexthop=fdfe:dcba:9876::2'), 'the route that did land is withdrawn');
    assert.ok(h.logs.some(([lvl, l]) => lvl === 'warn' && /IPv6 on the TUN adapter failed/.test(l) && /Element not found/.test(l)));
    assert.ok(execLines().some(l => /^route add 0\.0\.0\.0 mask 128\.0\.0\.0/.test(l)), 'the v4 split routes still follow');
  } finally { h.done(); }
});

/**
 * With managed DNS off the core hijacks nothing, so the tunnel's v6 gateway
 * answers no query — and since the leak guard holds the physical adapters on
 * loopback, the TUN adapter's resolvers are the only ones that answer: a dead
 * v6 one ahead of them pushed every lookup to Windows' "all servers" step
 * (~3 s). The v6 resolver is the peer only when the v4 one is (tunSingbox's
 * adapterDns rule); the v6 address and routes stay either way, so v6 traffic
 * still cannot go around the tunnel.
 */
test('win32 start: without the peer on v4 (managed DNS off) the adapter gets no dead v6 resolver — v6 still routes into the tunnel', async () => {
  const h = harness();
  try {
    await h.tun.startWindows(10808, '1.2.3.4', ['1.1.1.1', '8.8.8.8']);
    assert.equal(h.tun.active, true);
    const netsh = netshLines();
    assert.ok(netsh.includes('interface ip set dnsservers name=XrayTun static 1.1.1.1 primary validate=no'));
    assert.ok(netsh.includes('interface ip add dnsservers name=XrayTun 8.8.8.8 index=2 validate=no'));
    assert.equal(netsh.some(l => /ipv6 set dnsservers/.test(l)), false, 'no v6 resolver nothing answers on');
    assert.ok(netsh.includes(V6_LINES[0]) && netsh.includes(V6_LINES[2]) && netsh.includes(V6_LINES[3]), 'v6 address and both /1 routes');
    assert.equal(h.tun.dnsPeer6, null, 'the adapter has no v6 resolver of ours');
  } finally { h.done(); }
});

test('win32 start: the TUN adapter\'s own metric and resolvers failing is said, not swallowed', async () => {
  // The guard now holds every physical adapter on loopback: the TUN adapter's
  // resolvers are the only ones that answer, so losing them silently is a
  // machine with no DNS and nothing in the log.
  const h = harness([
    [/interface ip set interface interface=XrayTun metric=1/, new Error('The parameter is incorrect.')],
    [/interface ip set dnsservers name=XrayTun/, new Error('The object already exists.')],
    [/interface ip add dnsservers name=XrayTun/, new Error('Element not found.')]
  ]);
  try {
    await h.tun.startWindows(10808, '1.2.3.4', ['1.1.1.1', '8.8.8.8']);
    assert.equal(h.tun.active, true, 'still not fatal');
    const warn = h.logs.filter(([lvl]) => lvl === 'warn').map(([, l]) => l).join('\n');
    assert.match(warn, /metric.*The parameter is incorrect/);
    assert.match(warn, /1\.1\.1\.1.*The object already exists/);
    assert.match(warn, /8\.8\.8\.8.*Element not found/);
  } finally { h.done(); }
});

test('cleanupSync (Windows) withdraws the v6 split routes with the v4 ones', { skip: process.platform !== 'win32' }, () => {
  const h = harness();
  try {
    h.tun.bypassIps.push('9.9.9.9');
    execs.length = 0;
    h.tun.cleanupSync();
    assert.deepEqual(execLines(), [
      `route delete 0.0.0.0 mask 128.0.0.0 ${TUN_GW}`,
      `route delete 128.0.0.0 mask 128.0.0.0 ${TUN_GW}`,
      'netsh interface ipv6 delete route prefix=::/1 interface=XrayTun nexthop=fdfe:dcba:9876::2',
      'netsh interface ipv6 delete route prefix=8000::/1 interface=XrayTun nexthop=fdfe:dcba:9876::2',
      'route delete 9.9.9.9'
    ]);
  } finally { h.done(); }
});
