'use strict';
/**
 * A LAN → Wi-Fi switch under the tun2socks backend (what a fresh Windows
 * install runs: the release bundles tun2socks + wintun, sing-box comes later
 * from "Required files"), played against a model of the Windows IPv4 route
 * table. Nothing here touches a real route: every command the backend runs is
 * answered by FakeWindows, and a command it does not model fails the test.
 *
 * What the model holds to, and where it comes from:
 *  - The table keeps routes of a DISCONNECTED interface. Measured on the dev
 *    machine: `netsh interface ipv4 show route` lists 224.0.0.0/4 and
 *    255.255.255.255/32 on its disconnected Ethernet, while `route print` shows
 *    none of them — route.exe only ever looks at connected interfaces. A cable
 *    pulled out therefore leaves our manual /32 on the LAN interface in place.
 *  - DHCP takes back the gateway it gave when the link goes; a STATIC gateway is
 *    configuration and stays in the persistent store, which `Get-NetRoute`
 *    without `-PolicyStore` lists beside the active one.
 *  - Windows routes by the lowest route metric + interface metric among the
 *    CONNECTED interfaces; RouteMetric alone ties at 0 for every DHCP gateway.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const MASKS = { '255.255.255.255': 32, '128.0.0.0': 1, '0.0.0.0': 0 };

class FakeWindows {
  constructor() {
    this.ifs = new Map();       // idx → { idx, alias, metric, state }
    this.routes = [];           // { prefix, nextHop, ifIndex, routeMetric, store, origin }
    this.cmds = [];
    this.unfaked = [];
    this.tunProc = null;
    this.nextTunIdx = 44;
    this.denyDelete = null;     // a Set of prefixes whose delete is refused (not elevated, say)
  }

  addIf(idx, alias, metric, state = 'Connected') { this.ifs.set(idx, { idx, alias, metric, state }); }
  addRoute(r) { this.routes.push(Object.assign({ routeMetric: 0, store: 'active', origin: 'manual' }, r)); }
  connected(idx) { const i = this.ifs.get(Number(idx)); return !!i && i.state === 'Connected'; }
  byAlias(alias) { return [...this.ifs.values()].find(i => i.alias === alias) || null; }

  /** The cable comes out: DHCP takes its gateway back, everything else stays in the table. */
  unplug(idx) {
    this.ifs.get(idx).state = 'Disconnected';
    this.routes = this.routes.filter(r => !(r.ifIndex === idx && r.origin === 'dhcp'));
  }

  /** An interface associates and DHCP hands it a default gateway. */
  join(idx, gw) {
    this.ifs.get(idx).state = 'Connected';
    this.addRoute({ prefix: '0.0.0.0/0', nextHop: gw, ifIndex: idx, origin: 'dhcp' });
  }

  /**
   * The app is killed (Task Manager, a crash): no stop(), no exit hook, nobody
   * left to hear tun2socks go. Its adapter and the routes ON it go with it; the
   * routes it laid on the physical interface are active routes and stay.
   */
  crash() {
    const tun = this.byAlias('XrayTun');
    if (tun) {
      this.ifs.delete(tun.idx);
      this.routes = this.routes.filter(r => r.ifIndex !== tun.idx);
    }
    this.tunProc = null;
  }

  /** The active /32 routes to `ip`, as "nextHop@ifIndex". */
  hostRoutes(ip) {
    return this.routes.filter(r => r.store === 'active' && r.prefix === `${ip}/32`).map(r => `${r.nextHop}@${r.ifIndex}`).sort();
  }

  exec(cmd, args) {
    this.cmds.push([cmd, ...args].join(' '));
    if (cmd === 'powershell') return this.powershell(args[args.length - 1]);
    if (cmd === 'route') return this.routeExe(args);
    if (cmd === 'netsh') return this.netsh(args);
    return this.unknown(cmd, args);
  }

  unknown(cmd, args) {
    const line = [cmd, ...args].join(' ');
    this.unfaked.push(line);
    throw new Error('unfaked command: ' + line);
  }

  powershell(script) {
    if (/Get-NetRoute/.test(script) && /0\.0\.0\.0\/0/.test(script)) {
      const onlyActive = /-PolicyStore\s+ActiveStore/.test(script);
      const rows = this.routes.filter(r => r.prefix === '0.0.0.0/0' && (!onlyActive || r.store === 'active'));
      if (/ConvertTo-Json/.test(script) && /Get-NetIPInterface/.test(script)) {
        return JSON.stringify(rows.map((r) => {
          const i = this.ifs.get(r.ifIndex);
          return { nextHop: r.nextHop, ifIndex: r.ifIndex, alias: i ? i.alias : '', routeMetric: r.routeMetric,
            ifMetric: i ? i.metric : null, state: i ? i.state : '' };
        })) + '\r\n';
      }
      if (/Sort-Object RouteMetric/.test(script)) {
        // The v1.13.5 one-liner: on-link routes out, sort by RouteMetric, take the first.
        const best = rows.filter(r => r.nextHop !== '0.0.0.0').sort((a, b) => a.routeMetric - b.routeMetric)[0];
        return best ? `${best.nextHop}|${best.ifIndex}\r\n` : '|\r\n';
      }
    }
    let m = script.match(/^\(Get-NetAdapter -InterfaceIndex (\d+) -ErrorAction SilentlyContinue\)\.Name$/);
    if (m) { const i = this.ifs.get(Number(m[1])); return i ? i.alias + '\r\n' : '\r\n'; }
    m = script.match(/^\(Get-NetAdapter -Name '([^']+)' -ErrorAction SilentlyContinue\)\.(Status|ifIndex)$/);
    if (m) {
      const i = this.byAlias(m[1]);
      if (!i) return '\r\n';
      return (m[2] === 'Status' ? 'Up' : String(i.idx)) + '\r\n';
    }
    return this.unknown('powershell', ['-Command', script]);
  }

  routeExe(args) {
    const [verb, dest, ...rest] = args;
    if (verb === 'add') {
      const [, mask, gw, , metric, , idx] = rest;   // mask M G metric X if I
      if (rest[0] !== 'mask' || rest[3] !== 'metric' || rest[5] !== 'if') return this.unknown('route', args);
      const r = { prefix: `${dest}/${MASKS[mask]}`, nextHop: gw, ifIndex: Number(idx), routeMetric: Number(metric) };
      if (this.routes.some(x => x.store === 'active' && x.prefix === r.prefix && x.nextHop === r.nextHop && x.ifIndex === r.ifIndex)) {
        throw new Error('The route addition failed: The object already exists.');
      }
      this.addRoute(r);
      return ' OK!\r\n';
    }
    if (verb === 'delete') {
      // route.exe works on its own view of the table: connected interfaces only.
      const prefix = rest[0] === 'mask' ? `${dest}/${MASKS[rest[1]]}` : null;
      const gw = rest[0] === 'mask' ? rest[2] : null;
      const hit = (r) => r.store === 'active' && this.connected(r.ifIndex)
        && (prefix ? r.prefix === prefix : r.prefix.split('/')[0] === dest)
        && (!gw || r.nextHop === gw);
      const before = this.routes.length;
      this.routes = this.routes.filter(r => !hit(r));
      if (this.routes.length === before) throw new Error('The route deletion failed: Element not found.');
      return ' OK!\r\n';
    }
    return this.unknown('route', args);
  }

  netsh(args) {
    const line = args.join(' ');
    const kv = Object.fromEntries(args.filter(a => a.includes('=')).map(a => [a.slice(0, a.indexOf('=')), a.slice(a.indexOf('=') + 1)]));
    if (/^interface ipv4 delete route /.test(line)) {
      if (this.denyDelete && this.denyDelete.has(kv.prefix)) throw new Error('The requested operation requires elevation (Run as administrator).');
      const idx = Number(kv.interface);
      const hit = (r) => (!kv.store || r.store === kv.store) && r.prefix === kv.prefix && r.ifIndex === idx && r.nextHop === kv.nexthop;
      const before = this.routes.length;
      this.routes = this.routes.filter(r => !hit(r));
      if (this.routes.length === before) throw new Error('Element not found.');
      return 'Ok.\r\n';
    }
    // The adapter setup and the v6 side all name our own adapter: accepted, not modelled.
    if (/^interface (ip|ipv4|ipv6) (set|add|delete) /.test(line) && /(name|interface)=XrayTun\b/.test(line)) return 'Ok.\r\n';
    return this.unknown('netsh', args);
  }

  spawn(cmd, args) {
    this.cmds.push([cmd, ...args].join(' '));
    const p = new EventEmitter();
    p.stdout = new EventEmitter();
    p.stderr = new EventEmitter();
    p.kill = () => {};
    if (/tun2socks\.exe$/.test(cmd)) {
      const idx = this.nextTunIdx++;
      this.addIf(idx, 'XrayTun', 5);
      p.pid = 7000 + idx;
      this.tunProc = p;
      return p;
    }
    if (cmd === 'taskkill') {
      // wintun's adapter goes with the process, and every route on it
      const tun = this.byAlias('XrayTun');
      if (tun) {
        this.ifs.delete(tun.idx);
        this.routes = this.routes.filter(r => r.ifIndex !== tun.idx);
      }
      const dying = this.tunProc;
      this.tunProc = null;
      if (dying) process.nextTick(() => dying.emit('exit', 1));
      p.pid = 1;
      return p;
    }
    this.unknown(cmd, args);
    return p;
  }
}

let fake = new FakeWindows();

// tunPlatform and tunManager destructure child_process at require time, and
// both ask os.platform() at call time: every stub goes in before the require.
const cp = require('node:child_process');
cp.execFile = (cmd, args, opts, cb) => {
  if (typeof opts === 'function') { cb = opts; opts = undefined; }
  let out;
  try { out = fake.exec(cmd, args); } catch (e) { process.nextTick(() => cb(e, '', e.message)); return new EventEmitter(); }
  process.nextTick(() => cb(null, out, ''));
  return new EventEmitter();
};
cp.execFileSync = (cmd, args) => fake.exec(cmd, args);
cp.spawn = (cmd, args) => fake.spawn(cmd, args);
os.platform = () => 'win32';
// The machine's uptime, when a test needs a reboot between two sessions.
const realUptime = os.uptime;
let uptimeNow = null;
os.uptime = () => (uptimeNow == null ? realUptime() : uptimeNow);

const TM_PATH = require.resolve('../src/main/tunManager');
const tunPlatform = require('../src/main/tunPlatform');

/** A fresh copy of the module: what the next launch of the app loads. */
function freshTunManager() {
  delete require.cache[TM_PATH];
  return require(TM_PATH).TunManager;
}

function setup() {
  fake = new FakeWindows();
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-netswitch-'));
  const binDir = path.join(root, 'bin');
  const userData = path.join(root, 'userData');
  fs.mkdirSync(binDir);
  fs.mkdirSync(userData);
  for (const f of ['tun2socks.exe', 'wintun.dll']) fs.writeFileSync(path.join(binDir, f), '');
  const logs = [];
  const make = (TunManager) => {
    const tun = new TunManager({ extraDirs: [binDir], userData, onLog: (line, level) => logs.push([level, line]), lang: 'en' });
    tun.dirs = () => [binDir];
    tun.tun2socksPath = () => path.join(binDir, 'tun2socks.exe');
    tun.isElevated = () => true;
    return tun;
  };
  return { make, userData, logs, done: () => fs.rmSync(root, { recursive: true, force: true }) };
}

/** A laptop on its LAN (static gateway, the way an office desk is set up) with Wi-Fi in range. */
function officeLaptop() {
  fake.addIf(5, 'Ethernet', 25);
  fake.addIf(23, 'Wi-Fi', 55, 'Disconnected');
  fake.addRoute({ prefix: '0.0.0.0/0', nextHop: '192.168.1.1', ifIndex: 5, origin: 'static' });
  fake.addRoute({ prefix: '0.0.0.0/0', nextHop: '192.168.1.1', ifIndex: 5, origin: 'static', store: 'persistent' });
}

const SERVER = '1.2.3.4';

test('LAN → Wi-Fi under tun2socks: the rebuild binds to Wi-Fi and routes the server via the Wi-Fi gateway; nothing of ours stays on the LAN', async () => {
  const h = setup();
  try {
    const TunManager = freshTunManager();
    officeLaptop();

    // connect on the LAN: what doConnect asks, then the tunnel
    const first = h.make(TunManager);
    assert.equal((await first.physicalInterface()).name, 'Ethernet');
    await first.start(10808, [SERVER], ['10.255.0.1']);
    assert.equal(first.active, true);
    assert.deepEqual(fake.hostRoutes(SERVER), ['192.168.1.1@5']);

    // the cable comes out, Wi-Fi takes over (a different network, a different gateway)
    fake.unplug(5);
    fake.join(23, '192.168.10.1');

    // the network-change recovery: stop everything, build it again (reapplyConnection → doConnect)
    await first.stop();
    const second = h.make(TunManager);
    const phys = await second.physicalInterface();
    assert.equal(phys.name, 'Wi-Fi', 'Xray\'s direct dials must be bound to the NIC that is still there');
    await second.start(10808, [SERVER], ['10.255.0.1']);
    assert.equal(second.active, true);
    assert.deepEqual(fake.hostRoutes(SERVER), ['192.168.10.1@23'],
      'the server is routed via the Wi-Fi gateway only — the /32 pinned to the LAN is gone, not waiting for the cable to come back');
    assert.ok(h.logs.some(([, l]) => /Default gateway: 192\.168\.10\.1 \(if 23\)/.test(l)));

    // a clean disconnect leaves nothing of ours in the table
    await second.stop();
    assert.deepEqual(fake.hostRoutes(SERVER), []);
    assert.deepEqual(fake.unfaked, []);
  } finally { h.done(); }
});

test('the bypass route is removed by exact match: the user\'s own route to the same address survives a disconnect', async () => {
  const h = setup();
  try {
    const TunManager = freshTunManager();
    fake.addIf(5, 'Ethernet', 25);
    fake.addIf(30, 'Corp VPN', 5);
    fake.addRoute({ prefix: '0.0.0.0/0', nextHop: '192.168.1.1', ifIndex: 5, origin: 'dhcp' });
    fake.addRoute({ prefix: `${SERVER}/32`, nextHop: '10.8.0.1', ifIndex: 30, origin: 'user' });

    const tun = h.make(TunManager);
    await tun.start(10808, [SERVER], ['10.255.0.1']);
    assert.deepEqual(fake.hostRoutes(SERVER), ['10.8.0.1@30', '192.168.1.1@5']);
    await tun.stop();
    assert.deepEqual(fake.hostRoutes(SERVER), ['10.8.0.1@30'], 'only the route we added goes');
    assert.deepEqual(fake.unfaked, []);
  } finally { h.done(); }
});

test('a session that died without its teardown: its bypass routes are journaled, and the next launch removes exactly those', async () => {
  const h = setup();
  try {
    let TunManager = freshTunManager();
    fake.addIf(5, 'Ethernet', 25);
    fake.addIf(30, 'Corp VPN', 5);
    fake.addRoute({ prefix: '0.0.0.0/0', nextHop: '192.168.1.1', ifIndex: 5, origin: 'dhcp' });
    fake.addRoute({ prefix: `${SERVER}/32`, nextHop: '10.8.0.1', ifIndex: 30, origin: 'user' });

    const tun = h.make(TunManager);
    await tun.start(10808, [SERVER, '5.6.7.8'], ['10.255.0.1']);
    assert.deepEqual(fake.hostRoutes('5.6.7.8'), ['192.168.1.1@5']);

    // the app is killed: tun2socks dies with its adapter; the /32s on the
    // physical interface are active routes and stay until a reboot.
    fake.crash();
    assert.deepEqual(fake.hostRoutes(SERVER), ['10.8.0.1@30', '192.168.1.1@5']);

    // the next launch
    TunManager = freshTunManager();
    const removed = await h.make(TunManager).recoverRoutesWindows();
    assert.equal(removed, 2);
    assert.deepEqual(fake.hostRoutes(SERVER), ['10.8.0.1@30'], 'the user\'s route is not ours to remove');
    assert.deepEqual(fake.hostRoutes('5.6.7.8'), []);
    assert.equal(fs.readdirSync(h.userData).filter(n => /route/i.test(n)).length, 0, 'the journal goes with the routes');
    assert.ok(h.logs.some(([lvl, l]) => lvl === 'warn' && /2 bypass routes/.test(l)));

    // once per launch: a second ask runs nothing
    const before = fake.cmds.length;
    assert.equal(await h.make(TunManager).recoverRoutesWindows(), 2);
    assert.equal(fake.cmds.length, before);
    assert.deepEqual(fake.unfaked, []);
  } finally { h.done(); }
});

test('the first connect after such a crash clears the leftovers before it lays its own (no launch hook needed)', async () => {
  const h = setup();
  try {
    let TunManager = freshTunManager();
    officeLaptop();
    await h.make(TunManager).start(10808, [SERVER], ['10.255.0.1']);
    fake.crash();                                                   // killed on the LAN
    fake.unplug(5);
    fake.join(23, '192.168.10.1');                                  // launched again on Wi-Fi

    TunManager = freshTunManager();
    const tun = h.make(TunManager);
    await tun.start(10808, [SERVER], ['10.255.0.1']);
    assert.deepEqual(fake.hostRoutes(SERVER), ['192.168.10.1@23']);
    await tun.stop();
    assert.deepEqual(fake.hostRoutes(SERVER), []);
    assert.deepEqual(fake.unfaked, []);
  } finally { h.done(); }
});

/* The route journal across reboots, refusals and a user who is not an administrator. */

const journalRoutes = (userData) => {
  const f = path.join(userData, 'tun2socks-routes.json');
  return fs.existsSync(f) ? JSON.parse(fs.readFileSync(f, 'utf8')).routes.map(r => r.ip).sort() : [];
};
const deletes = (from) => fake.cmds.slice(from).filter(c => /^netsh interface ipv4 delete route /.test(c));

test('a journal an earlier boot left is dropped without netsh: its routes died with that boot, and an identical one laid since is someone else’s', async () => {
  const h = setup();
  try {
    let TunManager = freshTunManager();
    fake.addIf(5, 'Ethernet', 25);
    fake.addRoute({ prefix: '0.0.0.0/0', nextHop: '192.168.1.1', ifIndex: 5, origin: 'dhcp' });
    uptimeNow = 50000;                                              // hours into this boot
    await h.make(TunManager).start(10808, [SERVER], ['10.255.0.1']);
    fake.crash();
    // the machine reboots: every active route goes with it…
    fake.routes = fake.routes.filter(r => r.store !== 'active' || r.origin === 'dhcp');
    uptimeNow = 120;
    // …and since, the user (or another VPN) laid the very same /32
    fake.addRoute({ prefix: `${SERVER}/32`, nextHop: '192.168.1.1', ifIndex: 5, origin: 'user' });
    TunManager = freshTunManager();
    const from = fake.cmds.length;
    assert.equal(await h.make(TunManager).recoverRoutesWindows(), 0);
    assert.deepEqual(deletes(from), [], 'nothing run for a route of another boot');
    assert.deepEqual(fake.hostRoutes(SERVER), ['192.168.1.1@5'], 'theirs stays');
    assert.deepEqual(journalRoutes(h.userData), [], 'the stale record is gone');
    assert.deepEqual(fake.unfaked, []);
  } finally { uptimeNow = null; h.done(); }
});

test('a sweep whose delete fails keeps that record — the route may still be there — and the next launch retries it', async () => {
  const h = setup();
  try {
    let TunManager = freshTunManager();
    officeLaptop();
    await h.make(TunManager).start(10808, [SERVER, '5.6.7.8'], ['10.255.0.1']);
    fake.crash();
    fake.denyDelete = new Set(['5.6.7.8/32']);
    TunManager = freshTunManager();
    assert.equal(await h.make(TunManager).recoverRoutesWindows(), 1);
    assert.deepEqual(fake.hostRoutes('5.6.7.8'), ['192.168.1.1@5']);
    assert.deepEqual(journalRoutes(h.userData), ['5.6.7.8'], 'still ours, still recorded');
    fake.denyDelete = null;
    TunManager = freshTunManager();                                 // the next launch
    assert.equal(await h.make(TunManager).recoverRoutesWindows(), 1);
    assert.deepEqual(fake.hostRoutes('5.6.7.8'), []);
    assert.deepEqual(journalRoutes(h.userData), []);
  } finally { h.done(); }
});

test('not elevated: the launch sweep runs nothing and forgets nothing — an elevated launch does it', async () => {
  const h = setup();
  try {
    let TunManager = freshTunManager();
    officeLaptop();
    await h.make(TunManager).start(10808, [SERVER, '5.6.7.8'], ['10.255.0.1']);
    fake.crash();
    TunManager = freshTunManager();
    const plain = h.make(TunManager);
    plain.isElevated = () => false;
    const from = fake.cmds.length;
    assert.equal(await plain.recoverRoutesWindows(), 0);
    assert.deepEqual(deletes(from), []);
    assert.deepEqual(journalRoutes(h.userData), ['1.2.3.4', '5.6.7.8']);
    assert.equal(await h.make(TunManager).recoverRoutesWindows(), 2, 'the same process, elevated after all (the TUN connect)');
    assert.deepEqual(journalRoutes(h.userData), []);
  } finally { h.done(); }
});

test('a teardown whose delete fails keeps the record for the next launch (the exit hook’s too)', async () => {
  const h = setup();
  try {
    let TunManager = freshTunManager();
    officeLaptop();
    const tun = h.make(TunManager);
    await tun.start(10808, [SERVER, '5.6.7.8'], ['10.255.0.1']);
    fake.denyDelete = new Set([`${SERVER}/32`]);
    await tun.stop();
    assert.deepEqual(journalRoutes(h.userData), ['1.2.3.4']);
    const again = h.make(TunManager);
    await again.start(10808, ['5.6.7.8'], ['10.255.0.1']);
    fake.denyDelete = new Set(['5.6.7.8/32']);
    again.cleanupSync();
    assert.deepEqual(journalRoutes(h.userData), ['1.2.3.4', '5.6.7.8']);
    fake.denyDelete = null;
    TunManager = freshTunManager();
    assert.equal(await h.make(TunManager).recoverRoutesWindows(), 2);
    assert.deepEqual(fake.hostRoutes(SERVER), []);
    assert.deepEqual(journalRoutes(h.userData), []);
  } finally { h.done(); }
});

test('physicalInterface (both backends share it) names the NIC Windows routes by on a machine with two live gateways', async () => {
  fake = new FakeWindows();
  // DHCP gives both a RouteMetric of 0; the Wi-Fi is listed first, the LAN wins on its interface metric.
  fake.addIf(23, 'Wi-Fi', 55);
  fake.addIf(5, 'Ethernet', 25);
  fake.addRoute({ prefix: '0.0.0.0/0', nextHop: '192.168.10.1', ifIndex: 23, origin: 'dhcp' });
  fake.addRoute({ prefix: '0.0.0.0/0', nextHop: '192.168.1.1', ifIndex: 5, origin: 'dhcp' });
  assert.deepEqual(await tunPlatform.physicalInterface('win32'), { name: 'Ethernet', ifIndex: '5', gateway: '192.168.1.1' });
  assert.deepEqual(fake.unfaked, []);
});
