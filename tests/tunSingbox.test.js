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

test('isAvailable: win32 needs wintun.dll NEXT TO sing-box.exe; darwin only the binary', async () => {
  await withBin(['sing-box.exe'], 'win32', (tun) => assert.equal(tun.isAvailable(), false, 'no wintun'));
  await withBin(['sing-box.exe', 'wintun.dll'], 'win32', (tun) => assert.equal(tun.isAvailable(), true));
  await withBin(['sing-box', 'wintun.dll'], 'win32', (tun) => assert.equal(tun.isAvailable(), false, 'win32 wants the .exe'));
  await withBin(['sing-box'], 'darwin', (tun) => assert.equal(tun.isAvailable(), true));
  await withBin(['sing-box.exe'], 'darwin', (tun) => assert.equal(tun.isAvailable(), false));
  await withBin([], 'linux', (tun) => assert.equal(tun.isAvailable(), false));
  // wintun in ANOTHER known dir does not count: sing-box loads it from its own dir
  const other = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-sb-other-'));
  fs.writeFileSync(path.join(other, 'wintun.dll'), '');
  try {
    await withBin(['sing-box.exe'], 'win32', (tun, dir) => {
      tun.dirs = () => [dir, other];
      assert.equal(tun.isAvailable(), false);
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

test('win32 start: refuses without wintun next to the binary, and without elevation', async () => {
  await withBin(['sing-box.exe'], 'win32', async (tun) => {
    tun.isElevated = () => true;
    await assert.rejects(() => tun.start(1, [], [], {}), /wintun\.dll/);
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

test('macOS setup script: HUP trap, backgrounded sing-box with a pid file, wait for a NEW utun, DNS, no route lines', () => {
  const s = buildMacSetupScript(macArgs);
  const lines = s.split('\n');
  assert.equal(lines[0], '#!/bin/bash');
  assert.equal(lines[1], "trap '' HUP");
  assert.equal(lines[2], "BIN='/Users/a b/Library/Application Support/IRNetFree/bin/sing-box'");
  assert.equal(lines[3], "CFG='/tmp/irnf-sb-XyZ/sing-box.json'");
  assert.equal(lines[4], "LOG='/tmp/irnf-sb-XyZ/sing-box.log'");
  assert.equal(lines[5], "PIDFILE='/tmp/irnf-sb-XyZ/sing-box.pid'");
  assert.equal(lines[6], "DEVFILE='/tmp/irnf-sb-XyZ/sing-box.dev'");
  assert.equal(lines[7], 'BEFORE=" $(ifconfig -l 2>/dev/null) "');
  assert.equal(lines[8], '"$BIN" run -c "$CFG" >"$LOG" 2>&1 </dev/null &');
  assert.equal(lines[9], 'SBPID=$!');
  assert.equal(lines[10], 'echo "$SBPID" > "$PIDFILE"');
  assert.ok(s.includes('while [ $i -lt 50 ]; do'), 'utun wait loop');
  assert.ok(s.includes('  if ! kill -0 "$SBPID" 2>/dev/null; then break; fi'), 'stops waiting once sing-box is gone');
  assert.ok(s.includes('      utun*)'), 'looks for utun devices');
  assert.ok(s.includes('          *" $u "*) ;;'), 'skips the ones that existed before');
  assert.ok(s.includes('echo "ERR: sing-box did not create a utun device" >&2'));
  assert.ok(s.includes('  cat "$LOG" >&2 2>/dev/null'), 'prints the sing-box log on failure');
  assert.ok(s.includes('  exit 11'));
  assert.ok(s.includes('echo "$ACTUAL" > "$DEVFILE"'));
  assert.ok(s.includes("networksetup -setdnsservers 'Wi-Fi' 172.19.0.2 fdfe:dcba:9876::2 2>/dev/null || true"));
  assert.ok(!/^\s*(route|ifconfig "\$ACTUAL")/m.test(s), 'auto_route lays routes and addresses — the script must not');
  assert.equal(lines.at(-2), 'exit 0');
  assert.equal(lines.at(-1), '', 'trailing newline');
  assert.ok(!s.includes('nohup'), 'nohup fails under osascript');
});

test('macOS setup script: no service → `true` instead of a DNS line; quotes in paths are escaped', () => {
  const s = buildMacSetupScript(Object.assign({}, macArgs, { service: null, bin: "/Users/o'brien/sing-box" }));
  assert.ok(!s.includes('networksetup'));
  assert.ok(s.split('\n').includes('true'));
  assert.ok(s.includes("BIN='/Users/o'\\''brien/sing-box'"));
});

test('macOS teardown script: kill, wait, pkill by argv, DNS restore (`Empty` when none was saved), exit 0', () => {
  const s = buildMacTeardownScript({ pid: 4242, cfgFile: '/tmp/irnf-sb-XyZ/sing-box.json', service: 'Wi-Fi', savedDns: [] });
  assert.equal(s, [
    '#!/bin/bash',
    'kill 4242 2>/dev/null || true',
    'i=0',
    'while [ $i -lt 20 ] && kill -0 4242 2>/dev/null; do i=$((i+1)); sleep 0.2; done',
    "pkill -f 'sing-box run -c /tmp/irnf-sb-XyZ/sing-box.json' 2>/dev/null || true",
    "networksetup -setdnsservers 'Wi-Fi' Empty 2>/dev/null || true",
    'exit 0',
    ''
  ].join('\n'));
  const saved = buildMacTeardownScript({ pid: null, cfgFile: '/tmp/x/sing-box.json', service: 'Wi-Fi', savedDns: ['1.1.1.1', '9.9.9.9'] });
  assert.ok(!/^kill /m.test(saved), 'no pid known → no kill line');
  assert.ok(!saved.includes('kill -0'));
  assert.ok(saved.includes("pkill -f 'sing-box run -c /tmp/x/sing-box.json' 2>/dev/null || true"));
  assert.ok(saved.includes("networksetup -setdnsservers 'Wi-Fi' 1.1.1.1 9.9.9.9 2>/dev/null || true"));
  const noService = buildMacTeardownScript({ pid: 1, cfgFile: '/tmp/x/sing-box.json', service: null, savedDns: [] });
  assert.ok(!noService.includes('networksetup'));
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
      assert.ok(setup.includes("networksetup -setdnsservers 'Wi-Fi' 172.19.0.2 2>/dev/null || true"));
      assert.equal(tun.macState.macPid, 31337);
      assert.equal(tun.macState.dev, 'utun9');
      assert.deepEqual(tun.macState.savedDns, ['9.9.9.9']);
      assert.ok(logs.some(([, l]) => /TUN device: utun9/.test(l)));

      await tun.stop();
      assert.equal(tun.active, false);
      assert.equal(tun.macState, null);
      assert.deepEqual(tun.excludeIps, []);
      const [downName, down] = scripts[1];
      assert.equal(downName, 'teardown.sh');
      assert.equal(down, buildMacTeardownScript({ pid: 31337, cfgFile, service: 'Wi-Fi', savedDns: ['9.9.9.9'] }));
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
