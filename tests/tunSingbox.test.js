'use strict';
/**
 * The sing-box TUN backend. Nothing here starts a TUN: the child process and
 * every shell command are stubbed (the xrayManager.test.js pattern), so the
 * tests pin the config sing-box is handed, the argv it is spawned with, the
 * netsh/networksetup lines around it, and the macOS scripts nobody can run
 * on this machine.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { EventEmitter } = require('node:events');

// Both modules destructure child_process at require time, so the stubs go in
// first. `fakeSpawn` stands in for sing-box / taskkill; `answer` for every
// execFile-based helper (powershell, netsh, route, networksetup).
const cp = require('node:child_process');
const realSpawn = cp.spawn;
const realExecFile = cp.execFile;
let fakeSpawn = null;
const spawns = [];
cp.spawn = (...args) => { spawns.push(args); return fakeSpawn ? fakeSpawn(...args) : realSpawn(...args); };
const execs = [];
let answer = null;
cp.execFile = (cmd, args, opts, cb) => {
  if (typeof opts === 'function') { cb = opts; opts = undefined; }
  if (!answer) return realExecFile(cmd, args, opts, cb);
  execs.push([cmd, args]);
  let out;
  try { out = answer(cmd, args); } catch (e) { return process.nextTick(() => cb(e, '', e.message)); }
  process.nextTick(() => cb(null, out, ''));
};

const {
  TunSingbox, buildTunConfig, buildMacSetupScript, buildMacTeardownScript,
  TUN_IF, TUN_PEER4, TUN_PEER6
} = require('../src/main/tunSingbox');
const { isOwnTunInterface } = require('../src/main/tunPlatform');

function stubChild() {
  const p = new EventEmitter();
  p.stdout = new EventEmitter();
  p.stderr = new EventEmitter();
  p.pid = 4242;
  p.kill = () => {};
  return p;
}

/** A fake spawn: the first child is "sing-box"; a later `taskkill` spawn makes it exit. */
function killable() {
  let child = null;
  return (cmd) => {
    const c = stubChild();
    if (!child) child = c;
    else if (cmd === 'taskkill') process.nextTick(() => child.emit('exit', null, 'SIGKILL'));
    return c;
  };
}

function canned(table) {
  execs.length = 0;
  spawns.length = 0;
  answer = (cmd, args) => {
    const line = [cmd, ...args].join(' ');
    for (const [re, out] of table) if (re.test(line)) return out;
    return '';
  };
}
const execLines = () => execs.map(([c, a]) => [c, ...a].join(' '));

/** A fake bin dir with the given files, removed after the (async) body. */
async function withBin(files, platform, fn) {
  spawns.length = 0;
  execs.length = 0;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-sb-test-'));
  for (const f of files) fs.writeFileSync(path.join(dir, f), '');
  const logs = [];
  const tun = new TunSingbox({ extraDirs: [dir], onLog: (line, level) => logs.push([level, line]), platform, lang: 'en' });
  tun.dirs = () => [dir];
  try { return await fn(tun, dir, logs); }
  finally { fs.rmSync(dir, { recursive: true, force: true }); fakeSpawn = null; answer = null; }
}

/* ------------------------------ buildTunConfig ------------------------------ */

test('buildTunConfig: the shape that passed `sing-box check`, byte-stable', () => {
  const cfg = buildTunConfig({ socksPort: 10808 });
  assert.equal(JSON.stringify(cfg), JSON.stringify({
    log: { level: 'warn', timestamp: false },
    inbounds: [{
      type: 'tun', tag: 'tun-in', interface_name: 'IRNetFree',
      address: ['172.19.0.1/30', 'fdfe:dcba:9876::1/126'],
      mtu: 1500, auto_route: true, strict_route: false, stack: 'system',
      route_exclude_address: []
    }],
    outbounds: [{ type: 'socks', tag: 'socks-out', server: '127.0.0.1', server_port: 10808, version: '5' }],
    route: { final: 'socks-out', auto_detect_interface: true }
  }));
  assert.equal(TUN_IF, 'IRNetFree');
  assert.equal(TUN_PEER4, '172.19.0.2');
  assert.equal(TUN_PEER6, 'fdfe:dcba:9876::2');
});

test('buildTunConfig: strict_route follows `strict`; socks port lands on socks-out', () => {
  assert.equal(buildTunConfig({ socksPort: 1 }).inbounds[0].strict_route, false);
  assert.equal(buildTunConfig({ socksPort: 1, strict: true }).inbounds[0].strict_route, true);
  assert.equal(buildTunConfig({ socksPort: 61080 }).outbounds[0].server_port, 61080);
});

test('buildTunConfig: route_exclude_address gets /32 for v4, /128 for v6, CIDRs untouched', () => {
  const cfg = buildTunConfig({ socksPort: 1, excludeIps: ['1.2.3.4', '2001:db8::1', '5.6.7.0/24', ' 9.9.9.9 '] });
  assert.deepEqual(cfg.inbounds[0].route_exclude_address, ['1.2.3.4/32', '2001:db8::1/128', '5.6.7.0/24', '9.9.9.9/32']);
});

test('buildTunConfig: the v6 address stays even with ipv6:false — v6 must never bypass the TUN', () => {
  for (const ipv6 of [false, true]) {
    const inb = buildTunConfig({ socksPort: 1, ipv6 }).inbounds[0];
    assert.deepEqual(inb.address, ['172.19.0.1/30', 'fdfe:dcba:9876::1/126'], `ipv6:${ipv6}`);
  }
});

test('buildTunConfig: stack and mtu are tunable; the matrix ipv6 × strict × exclude is 8 distinct configs', () => {
  const inb = buildTunConfig({ socksPort: 1, stack: 'gvisor', mtu: 9000 }).inbounds[0];
  assert.equal(inb.stack, 'gvisor');
  assert.equal(inb.mtu, 9000);
  const seen = new Set();
  for (const ipv6 of [false, true]) for (const strict of [false, true]) for (const excludeIps of [[], ['1.2.3.4', '2001:db8::1']]) {
    seen.add(JSON.stringify(buildTunConfig({ socksPort: 10808, ipv6, strict, excludeIps })));
  }
  assert.equal(seen.size, 4, 'ipv6 changes nothing in the sing-box config (Xray answers no AAAA instead)');
});

test('buildTunConfig: without an interface name the key is omitted (darwin: sing-tun only accepts utunN)', () => {
  const inb = buildTunConfig({ socksPort: 1, interfaceName: null }).inbounds[0];
  assert.equal('interface_name' in inb, false);
  assert.deepEqual(Object.keys(inb), ['type', 'tag', 'address', 'mtu', 'auto_route', 'strict_route', 'stack', 'route_exclude_address']);
});

/* ------------------------------ buildTunConfig: apps (task 10a) ------------------------------ */

test('buildTunConfig: apps off — null, mode neither exclude/only, or no usable name — is byte-stable with today\'s output', () => {
  const base = JSON.stringify(buildTunConfig({ socksPort: 10808 }));
  assert.equal(JSON.stringify(buildTunConfig({ socksPort: 10808, apps: null })), base, 'apps: null');
  assert.equal(JSON.stringify(buildTunConfig({ socksPort: 10808, apps: { mode: 'exclude', names: [] } })), base, 'no names');
  assert.equal(JSON.stringify(buildTunConfig({ socksPort: 10808, apps: { mode: 'exclude', names: ['', '  '] } })), base, 'only blank names');
  assert.equal(JSON.stringify(buildTunConfig({ socksPort: 10808, apps: { mode: 'off', names: ['x.exe'] } })), base, 'unknown mode');
});

test('buildTunConfig: apps exclude — trims/dedupes names keeping first occurrence and order, DNS rule ahead of it', () => {
  const cfg = buildTunConfig({ socksPort: 10808, apps: { mode: 'exclude', names: ['Telegram.exe', ' steam.exe ', 'Telegram.exe'] } });
  assert.deepEqual(cfg.route.rules, [
    { port: 53, outbound: 'socks-out' },
    { process_name: ['Telegram.exe', 'steam.exe'], outbound: 'direct' }
  ]);
  assert.equal(cfg.route.final, 'socks-out');
  assert.deepEqual(cfg.outbounds.map(o => o.tag), ['socks-out', 'direct']);
});

test('buildTunConfig: a name that is not a string is dropped, never stringified into the rule', () => {
  // '[object Object]' / '42' would be a rule matching nothing while the log says
  // per-app routing is on — the builder drops them instead of coercing them.
  const cfg = buildTunConfig({ socksPort: 10808, apps: { mode: 'exclude', names: [{}, 42, 'chrome.exe'] } });
  assert.deepEqual(cfg.route.rules[1].process_name, ['chrome.exe']);
});

test('buildTunConfig: apps only — the named apps are the only ones sent into the tunnel', () => {
  const cfg = buildTunConfig({ socksPort: 10808, apps: { mode: 'only', names: ['chrome.exe'] } });
  assert.deepEqual(cfg.route.rules, [
    { port: 53, outbound: 'socks-out' },
    { process_name: ['chrome.exe'], outbound: 'socks-out' }
  ]);
  assert.equal(cfg.route.final, 'direct');
  assert.deepEqual(cfg.outbounds.map(o => o.tag), ['socks-out', 'direct']);
});

test('buildTunConfig: with apps active, route key order is final, auto_detect_interface, rules', () => {
  const cfg = buildTunConfig({ socksPort: 10808, apps: { mode: 'exclude', names: ['chrome.exe'] } });
  assert.deepEqual(Object.keys(cfg.route), ['final', 'auto_detect_interface', 'rules']);
});

test('writeConfig: opts.apps rides into buildTunConfig — rules present when set, absent when not', () => {
  const tun = new TunSingbox({ extraDirs: [], onLog: () => {} });
  const { cfgFile: withAppsFile } = tun.writeConfig(10808, [], { apps: { mode: 'exclude', names: ['chrome.exe'] } }, 'IRNetFree');
  const withApps = JSON.parse(fs.readFileSync(withAppsFile, 'utf8'));
  assert.deepEqual(withApps.route.rules, [
    { port: 53, outbound: 'socks-out' },
    { process_name: ['chrome.exe'], outbound: 'direct' }
  ]);
  tun.removeWork();

  const { cfgFile: noAppsFile } = tun.writeConfig(10808, [], {}, 'IRNetFree');
  const noApps = JSON.parse(fs.readFileSync(noAppsFile, 'utf8'));
  assert.equal('rules' in noApps.route, false, 'no apps opt → no rules');
  tun.removeWork();
});

/* ------------------------------ surface ------------------------------ */

test('the surface task 2 wires in', () => {
  const tun = new TunSingbox({ extraDirs: [], onLog: () => {}, lang: 'fa' });
  assert.equal(tun.backendId, 'sing-box');
  assert.equal(tun.interfaceName, 'IRNetFree');
  assert.equal(tun.dnsPeer, '172.19.0.2');
  assert.equal(tun.dnsPeer6, 'fdfe:dcba:9876::2');
  assert.equal(tun.active, false);
  assert.deepEqual(tun.excludeIps, [], 'the resolved bypass list, for the firewall excludes (task 3b)');
  assert.equal(tun.msg('فا', 'en'), 'فا');
  tun.lang = 'en';
  assert.equal(tun.msg('فا', 'en'), 'en');
  for (const m of ['dirs', 'isAvailable', 'isElevated', 'start', 'stop', 'cleanupSync', 'physicalInterface']) {
    assert.equal(typeof tun[m], 'function', m);
  }
});

test('isAvailable: win32 needs sing-box.exe and a wintun.dll it can put beside it; darwin only the binary', async () => {
  await withBin(['sing-box.exe'], 'win32', (tun) => assert.equal(tun.isAvailable(), false, 'no wintun anywhere'));
  await withBin(['sing-box.exe', 'wintun.dll'], 'win32', (tun) => assert.equal(tun.isAvailable(), true));
  await withBin(['sing-box', 'wintun.dll'], 'win32', (tun) => assert.equal(tun.isAvailable(), false, 'win32 wants the .exe'));
  await withBin(['sing-box'], 'darwin', (tun) => assert.equal(tun.isAvailable(), true));
  await withBin(['sing-box.exe'], 'darwin', (tun) => assert.equal(tun.isAvailable(), false));
  await withBin([], 'linux', (tun) => assert.equal(tun.isAvailable(), false));
  // wintun in ANOTHER known dir counts: start() copies it beside sing-box. That
  // is the layout every install with a downloaded sing-box (userData/bin) and
  // the bundled wintun (resources/bin, beside tun2socks) has — v1.7.1 and
  // earlier read it as "sing-box not installed" and ran tun2socks instead,
  // whatever the setting said.
  const other = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-sb-other-'));
  fs.writeFileSync(path.join(other, 'wintun.dll'), 'dll');
  try {
    await withBin(['sing-box.exe'], 'win32', (tun, dir, logs) => {
      tun.dirs = () => [dir, other];
      assert.equal(tun.isAvailable(), true);
      assert.equal(tun.wintunSource(), path.join(other, 'wintun.dll'));
      assert.equal(fs.existsSync(path.join(dir, 'wintun.dll')), false, 'isAvailable() only looks');
      assert.equal(tun.ensureWintun(), path.join(dir, 'wintun.dll'));
      assert.equal(fs.readFileSync(path.join(dir, 'wintun.dll'), 'utf8'), 'dll', 'copied beside the binary');
      assert.equal(tun.wintunSource(), path.join(dir, 'wintun.dll'), 'beside wins from now on');
      assert.ok(logs.some(([, l]) => /wintun\.dll copied beside sing-box/.test(l)));
    });
  } finally { fs.rmSync(other, { recursive: true, force: true }); }
});

test('ensureWintun: a no-op beside the binary, nothing to do off Windows, a clear error with no wintun anywhere', async () => {
  await withBin(['sing-box.exe', 'wintun.dll'], 'win32', (tun, dir, logs) => {
    assert.equal(tun.ensureWintun(), path.join(dir, 'wintun.dll'));
    assert.equal(logs.length, 0, 'nothing copied, nothing logged');
  });
  await withBin(['sing-box'], 'darwin', (tun) => assert.equal(tun.ensureWintun(), null));
  await withBin(['sing-box.exe'], 'win32', (tun) => assert.throws(() => tun.ensureWintun(), /wintun\.dll is not next to sing-box\.exe/));
});

test('win32 start: a wintun.dll from another known dir is copied beside sing-box before the spawn', async () => {
  const other = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-sb-other-'));
  fs.writeFileSync(path.join(other, 'wintun.dll'), 'dll');
  try {
    await withBin(['sing-box.exe'], 'win32', async (tun, dir) => {
      tun.dirs = () => [dir, other];
      tun.isElevated = () => true;
      fakeSpawn = () => stubChild();
      canned([[/Get-NetAdapter -Name 'IRNetFree'.*Status/, 'Up\r\n']]);
      await tun.start(10808, [], ['172.19.0.2'], {});
      assert.equal(tun.active, true);
      assert.equal(fs.readFileSync(path.join(dir, 'wintun.dll'), 'utf8'), 'dll');
      assert.equal(spawns[0][0], path.join(dir, 'sing-box.exe'));
      assert.deepEqual(spawns[0][2], { cwd: dir, windowsHide: true });
    });
  } finally { fs.rmSync(other, { recursive: true, force: true }); }
});

test('isOwnTunInterface recognises the sing-box adapter', () => {
  assert.equal(isOwnTunInterface('IRNetFree'), true);
});

test('physicalInterface delegates to the shared helper for the instance platform', async () => {
  canned([[/Get-NetRoute -DestinationPrefix/, '10.0.0.1|7\r\n'], [/Get-NetAdapter -InterfaceIndex 7/, 'Ethernet 2\r\n']]);
  const tun = new TunSingbox({ extraDirs: [], platform: 'win32' });
  assert.deepEqual(await tun.physicalInterface(), { name: 'Ethernet 2', ifIndex: '7', gateway: '10.0.0.1' });
  answer = null;
});

/* ------------------------------ Windows ------------------------------ */

test('win32 start: spawns `sing-box run -c <cfg>` from its own dir, waits for the adapter, sets adapter DNS', async () => {
  await withBin(['sing-box.exe', 'wintun.dll'], 'win32', async (tun, dir, logs) => {
    tun.isElevated = () => true;
    let child = null;
    fakeSpawn = () => { const c = stubChild(); if (!child) child = c; return c; };
    canned([[/Get-NetAdapter -Name 'IRNetFree'.*Status/, 'Up\r\n']]);

    await tun.start(10808, ['1.2.3.4', '2001:db8::1', '1.2.3.4'], ['172.19.0.2'], { ipv6: true, strict: true });

    assert.equal(tun.active, true);
    const [bin, args, opts] = spawns[0];
    assert.equal(bin, path.join(dir, 'sing-box.exe'));
    assert.deepEqual(args.slice(0, 2), ['run', '-c']);
    assert.deepEqual(opts, { cwd: dir, windowsHide: true });
    const cfgFile = args[2];
    assert.equal(path.basename(cfgFile), 'sing-box.json');
    assert.match(path.basename(path.dirname(cfgFile)), /^irnf-sb-/);
    assert.deepEqual(JSON.parse(fs.readFileSync(cfgFile, 'utf8')),
      buildTunConfig({ socksPort: 10808, excludeIps: ['1.2.3.4', '2001:db8::1'], ipv6: true, strict: true }),
      'the config on disk is buildTunConfig of the resolved, de-duplicated bypass list');
    assert.deepEqual(tun.excludeIps, ['1.2.3.4', '2001:db8::1'], 'exposed for the firewall excludes');

    const lines = execLines();
    assert.ok(lines.some(l => /^powershell .*Get-NetAdapter -Name 'IRNetFree' -ErrorAction SilentlyContinue\)\.Status$/.test(l)), 'waited for the adapter');
    const netsh = execs.filter(([c]) => c === 'netsh').map(([, a]) => a);
    assert.deepEqual(netsh, [
      ['interface', 'ip', 'set', 'dnsservers', 'name=IRNetFree', 'static', '172.19.0.2', 'primary', 'validate=no'],
      ['interface', 'ipv6', 'set', 'dnsservers', 'name=IRNetFree', 'static', 'fdfe:dcba:9876::2', 'primary', 'validate=no']
    ]);
    assert.ok(!lines.some(l => /^route /.test(l)), 'no route commands — sing-box lays the routes');
    assert.ok(logs.some(([, l]) => /TUN mode active/.test(l)));

    // stop: taskkill /t /f, wait for the exit, config dir removed
    const stopping = tun.stop();
    const tk = spawns.find(([c]) => c === 'taskkill');
    assert.ok(tk, 'taskkill issued');
    assert.deepEqual(tk[1], ['/pid', '4242', '/t', '/f']);
    assert.deepEqual(tk[2], { windowsHide: true });
    child.emit('exit', null, 'SIGKILL');
    await stopping;
    assert.equal(tun.active, false);
    assert.equal(tun.proc, null);
    assert.deepEqual(tun.excludeIps, [], 'cleared on stop');
    assert.equal(fs.existsSync(path.dirname(cfgFile)), false, 'temp config dir removed on stop');
    assert.ok(!logs.some(([lvl, l]) => lvl === 'error' && /exited/.test(l)), 'an exit WE asked for is not an error');
  });
});

test('win32 start: two v4 servers → set + add index=2; no v6 line without ipv6', async () => {
  await withBin(['sing-box.exe', 'wintun.dll'], 'win32', async (tun) => {
    tun.isElevated = () => true;
    fakeSpawn = killable();
    canned([[/Get-NetAdapter -Name 'IRNetFree'.*Status/, 'Up\r\n']]);
    await tun.start(10808, ['1.2.3.4'], ['1.1.1.1', '8.8.8.8'], { ipv6: false });
    const netsh = execs.filter(([c]) => c === 'netsh').map(([, a]) => a);
    assert.deepEqual(netsh, [
      ['interface', 'ip', 'set', 'dnsservers', 'name=IRNetFree', 'static', '1.1.1.1', 'primary', 'validate=no'],
      ['interface', 'ip', 'add', 'dnsservers', 'name=IRNetFree', '8.8.8.8', 'index=2', 'validate=no']
    ]);
    assert.equal(JSON.parse(fs.readFileSync(spawns[0][1][2], 'utf8')).inbounds[0].strict_route, false);
    await tun.stop();
    assert.equal(tun.proc, null);
  });
});

/**
 * The v6 half of the "smart multi-homed name resolution" leak.
 *
 * buildTunConfig keeps the v6 address (and therefore the v6 default route) even
 * with ipv6:false — the comment there says why: so v6 can never bypass the TUN.
 * But the adapter was then left with NO v6 resolver, which leaves the machine's
 * only IPv6 resolvers on the physical adapters: the ISP's. Windows asks every
 * adapter's resolvers in parallel, and an ISP resolver reached over a link-local
 * v6 address is on-link — it never meets the tunnel's default route at all.
 *
 * The peer answers on either family: scripts/probe-dns-leak.js shows the
 * port-53 hijack taking `[udp:[::1]:53]` and `[tcp:[::1]:53]` and answering
 * both, so pointing the adapter's v6 side at the peer costs nothing and closes
 * the family the leak guard's `peer6` does not cover while ipv6 is off.
 */
test('win32 start: the tunnel peer is the adapter resolver on BOTH families, ipv6 setting or not', async () => {
  for (const ipv6 of [false, true]) {
    await withBin(['sing-box.exe', 'wintun.dll'], 'win32', async (tun) => {
      tun.isElevated = () => true;
      fakeSpawn = killable();
      canned([[/Get-NetAdapter -Name 'IRNetFree'.*Status/, 'Up\r\n']]);
      await tun.start(10808, ['1.2.3.4'], [TUN_PEER4], { ipv6 });
      const netsh = execs.filter(([c]) => c === 'netsh').map(([, a]) => a);
      assert.deepEqual(netsh, [
        ['interface', 'ip', 'set', 'dnsservers', 'name=IRNetFree', 'static', TUN_PEER4, 'primary', 'validate=no'],
        ['interface', 'ipv6', 'set', 'dnsservers', 'name=IRNetFree', 'static', TUN_PEER6, 'primary', 'validate=no']
      ], `ipv6:${ipv6}`);
      await tun.stop();
    });
  }
});

/**
 * The other way round: a config whose core has no port-53 hijack (the sing-box
 * format) gets plain public resolvers instead of the peer — and then the peer is
 * an address nothing answers on. Handing it out as the v6 resolver would be a
 * v6 black hole, so it is only ever offered next to its own v4 half.
 */
test('win32 start: without the tunnel peer on v4 there is no invented v6 peer, even with ipv6 on', async () => {
  await withBin(['sing-box.exe', 'wintun.dll'], 'win32', async (tun) => {
    tun.isElevated = () => true;
    fakeSpawn = killable();
    canned([[/Get-NetAdapter -Name 'IRNetFree'.*Status/, 'Up\r\n']]);
    await tun.start(10808, ['1.2.3.4'], ['1.1.1.1', '8.8.8.8'], { ipv6: true });
    const netsh = execs.filter(([c]) => c === 'netsh').map(([, a]) => a);
    assert.deepEqual(netsh, [
      ['interface', 'ip', 'set', 'dnsservers', 'name=IRNetFree', 'static', '1.1.1.1', 'primary', 'validate=no'],
      ['interface', 'ip', 'add', 'dnsservers', 'name=IRNetFree', '8.8.8.8', 'index=2', 'validate=no']
    ]);
    await tun.stop();
  });
});

test('win32 start: no servers given → the tunnel peer; a v6 server given → used instead of the peer', async () => {
  await withBin(['sing-box.exe', 'wintun.dll'], 'win32', async (tun) => {
    tun.isElevated = () => true;
    fakeSpawn = killable();
    canned([[/Get-NetAdapter -Name 'IRNetFree'.*Status/, 'Up\r\n']]);
    await tun.start(10808, ['1.2.3.4'], ['2606:4700::1111'], { ipv6: true });
    const netsh = execs.filter(([c]) => c === 'netsh').map(([, a]) => a);
    assert.deepEqual(netsh, [
      ['interface', 'ip', 'set', 'dnsservers', 'name=IRNetFree', 'static', '172.19.0.2', 'primary', 'validate=no'],
      ['interface', 'ipv6', 'set', 'dnsservers', 'name=IRNetFree', 'static', '2606:4700::1111', 'primary', 'validate=no']
    ]);
    await tun.stop();
  });
});

test('win32 start: a process that dies inside the fail-fast window throws its last lines, active stays false', async () => {
  await withBin(['sing-box.exe', 'wintun.dll'], 'win32', async (tun, dir, logs) => {
    tun.isElevated = () => true;
    fakeSpawn = () => {
      const c = stubChild();
      setTimeout(() => {
        c.stderr.emit('data', Buffer.from('FATAL[0000] start service: initialize inbound/tun[tun-in]: configure tun interface: Access is denied.\n'));
        c.emit('exit', 1, null);
      }, 30);
      return c;
    };
    canned([]);
    let cfgDir = null;
    await assert.rejects(async () => {
      const p = tun.start(10808, ['1.2.3.4'], ['172.19.0.2'], {});
      await new Promise(r => setTimeout(r, 5));
      cfgDir = path.dirname(spawns[0][1][2]);
      await p;
    }, (e) => /sing-box exited immediately/.test(e.message) && /Access is denied/.test(e.message));
    assert.equal(tun.active, false);
    assert.equal(tun.proc, null);
    assert.equal(fs.existsSync(cfgDir), false, 'temp config dir removed on failure');
    assert.ok(!execs.some(([c]) => c === 'netsh'), 'no DNS written for a dead tunnel');
    assert.ok(logs.some(([lvl, l]) => lvl === 'warn' && /\[tun\] FATAL/.test(l)), 'stderr reaches the app log');
  });
});

test('win32 start: adapter never comes Up → stop + throw', async () => {
  await withBin(['sing-box.exe', 'wintun.dll'], 'win32', async (tun) => {
    tun.isElevated = () => true;
    fakeSpawn = killable();
    canned([[/Get-NetAdapter -Name 'IRNetFree'.*Status/, 'Disconnected\r\n']]);
    const platform = require('../src/main/tunPlatform');
    const realWait = platform.waitForAdapter;
    platform.waitForAdapter = async (name, timeout) => { assert.equal(name, 'IRNetFree'); assert.equal(timeout, 12000); return false; };
    try {
      await assert.rejects(() => tun.start(10808, ['1.2.3.4'], ['172.19.0.2'], {}), /did not become ready/);
    } finally { platform.waitForAdapter = realWait; }
    assert.equal(tun.active, false);
    assert.ok(spawns.some(([c]) => c === 'taskkill'), 'the half-started process is killed');
    assert.ok(!execs.some(([c]) => c === 'netsh'));
  });
});

test('win32 start: refuses without a wintun.dll anywhere, and without elevation', async () => {
  await withBin(['sing-box.exe'], 'win32', async (tun) => {
    tun.isElevated = () => true;
    await assert.rejects(() => tun.start(1, [], [], {}), /wintun\.dll/);
    assert.equal(spawns.length, 0);
  });
  await withBin(['sing-box.exe', 'wintun.dll'], 'win32', async (tun) => {
    tun.isElevated = () => false;
    await assert.rejects(() => tun.start(1, [], [], {}), /Administrator/);
    assert.equal(spawns.length, 0);
  });
  await withBin([], 'win32', async (tun) => {
    await assert.rejects(() => tun.start(1, [], [], {}), /sing-box\.exe not found/);
  });
});

test('win32: the process dying while active marks the tunnel dead and logs at error', async () => {
  await withBin(['sing-box.exe', 'wintun.dll'], 'win32', async (tun, dir, logs) => {
    tun.isElevated = () => true;
    const child = stubChild();
    fakeSpawn = () => child;
    canned([[/Get-NetAdapter -Name 'IRNetFree'.*Status/, 'Up\r\n']]);
    await tun.start(10808, ['1.2.3.4'], ['172.19.0.2'], {});
    assert.equal(tun.active, true);
    child.emit('exit', 2, null);
    assert.equal(tun.active, false);
    assert.equal(tun.proc, null);
    assert.ok(logs.some(([lvl, l]) => lvl === 'error' && /sing-box exited \(code=2/.test(l)));
    await tun.stop();   // no process left: nothing to kill, no throw
    assert.ok(!spawns.some(([c]) => c === 'taskkill'));
  });
});

test('stop / cleanupSync are no-ops when nothing runs', async () => {
  await withBin([], 'win32', async (tun) => {
    canned([]);
    fakeSpawn = () => stubChild();
    await tun.stop();
    tun.cleanupSync();
    assert.equal(spawns.length, 0);
    assert.equal(execs.length, 0);
  });
});

/* ------------------------------ macOS (blind) ------------------------------ */

const macArgs = {
  bin: '/Users/a b/Library/Application Support/IRNetFree/bin/sing-box',
  cfgFile: '/tmp/irnf-sb-XyZ/sing-box.json',
  logFile: '/tmp/irnf-sb-XyZ/sing-box.log',
  pidFile: '/tmp/irnf-sb-XyZ/sing-box.pid',
  devFile: '/tmp/irnf-sb-XyZ/sing-box.dev',
  service: 'Wi-Fi',
  dnsServers: ['172.19.0.2', 'fdfe:dcba:9876::2']
};

test('macOS setup rolls back failures and identifies a new addressed utun before DNS', () => {
  const s = buildMacSetupScript(macArgs);
  assert.match(s, /trap rollback EXIT/);
  assert.match(s, /ps -ww -p "\$SBPID" -o lstart=/);
  assert.match(s, /count.*-eq 1/);
  assert.ok(s.includes('inet 172\\.19\\.0\\.1'));
  assert.match(s, /tail -c 4096/);
  assert.match(s, /networksetup -setdnsservers 'Wi-Fi' '172.19.0.2' 'fdfe:dcba:9876::2' \|\| exit 14/);
  assert.ok(!s.includes('nohup'));
  assert.ok(!/^\s*(route|ifconfig "\$ACTUAL")/m.test(s));
});

test('macOS setup script: no service → `true` instead of a DNS line; quotes in paths are escaped', () => {
  const s = buildMacSetupScript(Object.assign({}, macArgs, { service: null, bin: "/Users/o'brien/sing-box" }));
  assert.ok(!s.includes('networksetup'));
  assert.ok(s.split('\n').includes('true'));
  assert.ok(s.includes("BIN='/Users/o'\\''brien/sing-box'"));
});

test('macOS teardown verifies identity, escalates TERM to KILL, and fails when cleanup fails', () => {
  const s = buildMacTeardownScript({ ...macArgs, pid: 4242, savedDns: ['9.9.9.9'] });
  assert.match(s, /-o command=/);
  assert.match(s, /-o lstart=/);
  assert.match(s, /kill -TERM/);
  assert.match(s, /kill -KILL/);
  assert.match(s, /exit 23/);
  assert.match(s, /networksetup -setdnsservers 'Wi-Fi' '9.9.9.9' \|\| exit 25/);
  assert.ok(!s.includes('pkill'));
});

test('darwin start: config without interface_name, scripts through one privileged run, state and DNS restored on stop', async () => {
  await withBin(['sing-box'], 'darwin', async (tun, dir, logs) => {
    const scripts = [];
    const platform = require('../src/main/tunPlatform');
    const realPriv = platform.runScriptPrivileged;
    platform.runScriptPrivileged = async (p) => {
      const text = fs.readFileSync(p, 'utf8');
      scripts.push([path.basename(p), text]);
      if (path.basename(p) === 'setup.sh') {
        const work = path.dirname(p);
        fs.writeFileSync(path.join(work, 'sing-box.pid'), '31337\n');
        fs.writeFileSync(path.join(work, 'sing-box.dev'), 'utun9\n');
      }
      return '';
    };
    canned([
      [/^route -n get default$/, '   route to: default\n    gateway: 192.168.1.1\n  interface: en0\n'],
      [/networksetup -listnetworkserviceorder/, '(1) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n'],
      [/networksetup -getdnsservers Wi-Fi/, '9.9.9.9\n']
    ]);
    try {
      await tun.start(10808, ['1.2.3.4'], ['172.19.0.2'], { ipv6: false });
      assert.equal(tun.active, true);
      assert.equal(spawns.length, 0, 'nothing spawned directly — the script launches sing-box as root');
      const [setupName, setup] = scripts[0];
      assert.equal(setupName, 'setup.sh');
      const cfgFile = setup.match(/^CFG='(.*)'$/m)[1];
      const cfg = JSON.parse(fs.readFileSync(cfgFile, 'utf8'));
      assert.equal('interface_name' in cfg.inbounds[0], false, 'darwin: sing-box names the utun');
      assert.deepEqual(cfg.inbounds[0].route_exclude_address, ['1.2.3.4/32']);
      assert.deepEqual(tun.excludeIps, ['1.2.3.4']);
      assert.ok(setup.includes(`BIN='${path.join(dir, 'sing-box')}'`));
      // Both families, ipv6:false and all: macOS resolves per network service,
      // so a service left with only a v4 tunnel resolver keeps asking its v6
      // ones — see adapterDns.
      assert.ok(setup.includes(`networksetup -setdnsservers 'Wi-Fi' '${TUN_PEER4}' '${TUN_PEER6}' || exit 14`));
      assert.equal(tun.macState.macPid, 31337);
      assert.equal(tun.macState.dev, 'utun9');
      assert.deepEqual(tun.macState.savedDns, ['9.9.9.9']);
      assert.ok(logs.some(([, l]) => /TUN device: utun9/.test(l)));

      const savedState = { ...tun.macState };
      await tun.stop();
      assert.equal(tun.active, false);
      assert.equal(tun.macState, null);
      assert.deepEqual(tun.excludeIps, []);
      const [downName, down] = scripts[1];
      assert.equal(downName, 'teardown.sh');
      assert.equal(down, buildMacTeardownScript({ ...savedState, pid: 31337 }));
      assert.equal(fs.existsSync(path.dirname(cfgFile)), false, 'work dir removed');
    } finally { platform.runScriptPrivileged = realPriv; }
  });
});

test('darwin start: a cancelled password prompt is its own message; a failed script prints the sing-box log tail', async () => {
  await withBin(['sing-box'], 'darwin', async (tun, dir, logs) => {
    const platform = require('../src/main/tunPlatform');
    const realPriv = platform.runScriptPrivileged;
    canned([
      [/^route -n get default$/, '    gateway: 192.168.1.1\n  interface: en0\n'],
      [/networksetup -listnetworkserviceorder/, '(1) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n'],
      [/networksetup -getdnsservers/, "There aren't any DNS Servers set on Wi-Fi.\n"]
    ]);
    try {
      platform.runScriptPrivileged = async () => { throw new Error('execution error: User canceled. (-128)'); };
      await assert.rejects(() => tun.start(10808, ['1.2.3.4'], ['172.19.0.2'], {}), /administrator password/);
      assert.equal(tun.active, false);

      platform.runScriptPrivileged = async (p) => {
        fs.writeFileSync(path.join(path.dirname(p), 'sing-box.log'), 'INFO[0000] starting\nFATAL[0000] start service: operation not permitted\n');
        throw new Error('ERR: sing-box did not create a utun device (11)');
      };
      await assert.rejects(() => tun.start(10808, ['1.2.3.4'], ['172.19.0.2'], {}), /TUN setup failed: .*operation not permitted/);
      assert.ok(logs.some(([lvl, l]) => lvl === 'error' && /\[tun\] FATAL\[0000\] start service/.test(l)), 'log tail surfaced');
    } finally { platform.runScriptPrivileged = realPriv; }
  });
});

test('darwin start: no default route → a clear error before anything privileged runs', async () => {
  await withBin(['sing-box'], 'darwin', async (tun) => {
    const platform = require('../src/main/tunPlatform');
    const realPriv = platform.runScriptPrivileged;
    let ran = false;
    platform.runScriptPrivileged = async () => { ran = true; };
    canned([[/^route -n get default$/, '']]);
    try {
      await assert.rejects(() => tun.start(10808, ['1.2.3.4'], ['172.19.0.2'], {}), /gateway\/interface not found/);
    } finally { platform.runScriptPrivileged = realPriv; }
    assert.equal(ran, false);
  });
});

/* --------------------------- phase 3 review fixes --------------------------- */

// scripts/mac-selfcheck.sh carries a copy of this config so the owner can check
// it on a Mac with sing-box alone. A copy drifts; this is what notices.
test('the macOS self-check script checks the config this module actually builds', () => {
  const fs = require('node:fs');
  const path = require('node:path');
  const script = fs.readFileSync(path.join(__dirname, '..', 'scripts', 'mac-selfcheck.sh'), 'utf8');
  const m = script.match(/cat > "\$CFG" <<'JSON'\n([\s\S]*?)\nJSON\n/);
  assert.ok(m, 'the heredoc that holds the config is gone — update this test with it');
  const embedded = JSON.parse(m[1]);
  // darwin gets no interface_name (sing-tun only accepts utun<N>, so the kernel
  // picks the unit) — the script says so in a comment, and buildTunConfig takes
  // null for exactly that case.
  const built = buildTunConfig({ socksPort: embedded.outbounds[0].server_port, interfaceName: null });
  assert.deepEqual(embedded, built);
});


test('macOS stop failure retains active state and journal; retry clears it only on success', async () => {
  const platform = require('../src/main/tunPlatform');
  const realPriv = platform.runScriptPrivileged;
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-sb-retry-'));
  const logs = [];
  const tun = new TunSingbox({ platform: 'darwin', onLog: m => logs.push(m) });
  tun.work = work;
  tun.macState = { work, bin: '/bin/sing-box', cfgFile: path.join(work, 'config'), savedDns: ['9.9.9.9'] };
  tun.saveMacSession(); tun.active = true; tun.excludeIps = ['1.2.3.4'];
  try {
    platform.runScriptPrivileged = async () => { throw new Error('User canceled'); };
    await assert.rejects(tun.stop(), /User canceled/);
    assert.equal(tun.active, true);
    assert.ok(tun.macState);
    assert.ok(fs.existsSync(path.join(work, 'session.json')));
    assert.deepEqual(tun.excludeIps, ['1.2.3.4']);
    assert.ok(!logs.some(l => /mode stopped/.test(l)));
    platform.runScriptPrivileged = async () => {};
    await tun.stop();
    assert.equal(tun.macState, null); assert.equal(tun.active, false);
    assert.equal(fs.existsSync(work), false);
  } finally { platform.runScriptPrivileged = realPriv; fs.rmSync(work, { recursive: true, force: true }); }
});

test('macOS log reads stay bounded on a large file and tolerate truncation', () => {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-sb-log-'));
  const log = path.join(work, 'log'); const tun = new TunSingbox({ platform: 'darwin' });
  try {
    fs.writeFileSync(log, 'a'.repeat(1024 * 1024));
    const chunk = tun.readMacLogChunk(log);
    assert.equal(chunk.text.length, 32768); assert.equal(chunk.pos, 1024 * 1024);
    fs.writeFileSync(log, 'new'); assert.equal(tun.readMacLogChunk(log, chunk.pos).text, 'new');
  } finally { fs.rmSync(work, { recursive: true, force: true }); }
});

test('macOS recovery loads durable original DNS and removes only verified session', async () => {
  const platform = require('../src/main/tunPlatform'); const realPriv = platform.runScriptPrivileged;
  const userData = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-sb-recovery-'));
  const tun = new TunSingbox({ platform: 'darwin', userData });
  const { work, cfgFile } = tun.writeConfig(10808, [], {}, null);
  const st = { work, cfgFile, bin: '/bin/sing-box', savedDns: ['9.9.9.9'], service: 'Wi-Fi' };
  for (const key of ['logFile', 'pidFile', 'devFile', 'identityFile', 'dnsFile']) st[key] = path.join(work, key);
  tun.macState = st; tun.saveMacSession(); tun.macState = null;
  try {
    assert.equal(tun.hasPendingMacRecovery(), true);
    platform.runScriptPrivileged = async p => { assert.match(fs.readFileSync(p, 'utf8'), /'9.9.9.9'/); };
    assert.equal(await tun.recoverMacSessions(), 1);
    assert.equal(tun.hasPendingMacRecovery(), false);
  } finally { platform.runScriptPrivileged = realPriv; fs.rmSync(userData, { recursive: true, force: true }); }
});

test('macOS health loss notifies once and retains state for DNS recovery', async () => {
  const platform = require('../src/main/tunPlatform'); const realRun = platform.run;
  let calls = 0;
  const tun = new TunSingbox({ platform: 'darwin', onUnexpectedExit: () => calls++ });
  tun.macState = { macPid: 4242, bin: '/bin/sing-box', cfgFile: '/tmp/config' }; tun.active = true;
  try {
    platform.run = async () => { throw new Error('No process'); };
    await tun.checkMacHealth(); await Promise.resolve();
    await tun.checkMacHealth();
    assert.equal(calls, 1); assert.equal(tun.active, false); assert.ok(tun.macState);
  } finally { platform.run = realRun; }
});
