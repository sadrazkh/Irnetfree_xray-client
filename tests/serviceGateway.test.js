'use strict';
/**
 * The headless service as a router's gateway, driven through its real connect,
 * recovery and boot paths — with the cores faked (tests/gatewayFakes.js): the
 * real TunOpenwrt runs over a fake sing-box and a fake `ip`/`nft`, the core
 * manager spawns nothing, the system proxy is never touched. What is pinned is
 * what keeps a router online with nobody there to press a button:
 *
 *   R1  the gateway comes back after a restart (a stale activeServerId used to
 *       make the boot connect believe it was already connected);
 *   R3  a core that dies — sing-box or xray — is rebuilt, and on a router the
 *       rebuild keeps trying for as long as it takes;
 *   R4  a gateway that did not come up is a FAILED connect, never "connected,
 *       proxy only" (on a router that is the whole LAN going direct);
 *   R7  the exit hook stops the core too; a killed run's orphans are ended
 *       before the first connect;
 *   R9  a config on the sing-box core runs on Xray (the port-53 hijack);
 *   R13 warnings, errors and state changes reach syslog, marked irnetfree.
 */
process.env.IRNETFREE_PLATFORM = 'openwrt';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { createService } = require('../src/server/service');
const { makeProxyServer } = require('../src/main/parser');
const fakes = require('./gatewayFakes');

process.setMaxListeners(40);   // every service registers its own exit hook

const SERVER = Object.assign(makeProxyServer({ type: 'socks', address: '192.0.2.10', port: 1080, name: 'ci-upstream' }), { id: 'srv-1' });
// ports nothing listens on here: the stats poller dials apiPort, and the owner's own app holds the defaults
const PORTS = { socksPort: 47808, httpPort: 47809, apiPort: 47885 };
const BASE = Object.assign({ autoUpdateSubs: false, autoUpdateAssets: 'off', autoConnect: false, tunMode: true, lang: 'en', routingMode: 'global', blockAds: false }, PORTS);

const dirs = [];
test.after(() => { for (const d of dirs) { try { fs.rmSync(d, { recursive: true, force: true }); } catch {} } });

/** A service on a fresh data dir with this store; events and syslog lines recorded. */
function start(store = {}, extraDeps = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-svc-gw-'));
  dirs.push(dir);
  const content = Object.assign({ servers: [SERVER], routerDefaultsApplied: true }, store);
  content.settings = Object.assign({}, BASE, store.settings || {});
  fs.writeFileSync(path.join(dir, 'store.json'), JSON.stringify(content));
  const state = fakes.makeState();
  const syslog = [];
  const service = createService({ dataDir: dir, deps: fakes.deps(state, Object.assign({ syslog: (level, text) => syslog.push([level, text]) }, extraDeps)) });
  const statuses = [];
  const logs = [];
  service.onEvent((ch, p) => {
    if (ch === 'status') statuses.push(p);
    if (ch === 'log') logs.push(p);
  });
  return { service, state, statuses, logs, syslog, dir };
}

/** Poll until `pred()` is true (or fail with `what`). */
async function until(pred, what, ms = 4000) {
  const deadline = Date.now() + ms;
  while (!pred()) {
    if (Date.now() > deadline) throw new Error('timed out waiting for: ' + what);
    await new Promise((r) => setTimeout(r, 5));
  }
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const connectedCount = (s) => s.statuses.filter(x => x.state === 'connected').length;

/* ----------------------------- R1: back after a restart ----------------------------- */

test('R1: a stale activeServerId from the last run is cleared, and the boot connect resumes that connection', async (t) => {
  const s = start({ activeServerId: SERVER.id, lastServerId: SERVER.id, settings: { autoConnect: true } });
  t.after(() => s.service.shutdown());
  // a new process has no live connection, whatever the store remembers
  assert.equal((await s.service.invoke('app:init')).activeServerId, null);
  await until(() => connectedCount(s) === 1, 'the boot connect');
  assert.equal(s.state.xray.starts.length, 1, 'the connect attempt was reached');
  assert.equal((await s.service.invoke('app:init')).activeServerId, SERVER.id);
  assert.equal(s.statuses.find(x => x.state === 'connected').tun, true, 'with the gateway up');
});

test('R1: the boot connect resumes advanced routing (and any non-server target), not only a single server', async (t) => {
  const s = start({ activeServerId: '__advanced__', lastServerId: '__advanced__', settings: { autoConnect: true, advancedRouting: true, routeDefault: SERVER.id, routeRules: [] } });
  t.after(() => s.service.shutdown());
  await until(() => connectedCount(s) === 1, 'the boot connect of __advanced__');
  assert.equal(s.statuses.find(x => x.state === 'connected').serverId, '__advanced__');
});

test('R1: a boot connect to something that no longer exists says so instead of doing nothing silently', async (t) => {
  const s = start({ lastServerId: 'gone-after-a-refresh', settings: { autoConnect: true } });
  t.after(() => s.service.shutdown());
  await until(() => s.logs.some(l => /Auto-connect/.test(l.line)), 'a log line');
  assert.equal(s.state.xray.starts.length, 0, 'nothing was started');
});

test('R1: on a router the boot connect keeps retrying — and a disconnect by hand ends the retries', async (t) => {
  const s = start({ lastServerId: SERVER.id, settings: { autoConnect: true } });
  t.after(() => s.service.shutdown());
  s.state.gatewayFails = true;
  await until(() => s.state.events.filter(e => e === 'gateway:start').length >= 4, 'four boot attempts');
  await s.service.invoke('disconnect');
  const n = s.state.events.filter(e => e === 'gateway:start').length;
  await sleep(150);
  assert.equal(s.state.events.filter(e => e === 'gateway:start').length, n, 'no attempt after the disconnect');
  assert.equal(connectedCount(s), 0);
});

test('R1: a connect by hand during the boot retries ends them too', async (t) => {
  const s = start({ lastServerId: SERVER.id, settings: { autoConnect: true } });
  t.after(() => s.service.shutdown());
  s.state.gatewayFails = true;
  await until(() => s.state.events.filter(e => e === 'gateway:start').length >= 2, 'two boot attempts');
  s.state.gatewayFails = false;
  await s.service.invoke('connect', SERVER.id);
  const n = s.state.events.filter(e => e === 'xray:start').length;
  await sleep(150);
  assert.equal(s.state.events.filter(e => e === 'xray:start').length, n, 'the boot loop did not start another core');
  assert.equal(connectedCount(s), 1);
});

/* ----------------------------- R4: a failed gateway is a failed connect ----------------------------- */

test('R4: a gateway that does not come up fails the connect — the core is stopped, nothing says connected', async (t) => {
  const s = start();
  t.after(() => s.service.shutdown());
  s.state.gatewayFails = true;
  await assert.rejects(s.service.invoke('connect', SERVER.id), /Gateway did not come up \(sing-box\)/);
  assert.equal(s.state.xray.running, false, 'the core this connect started is stopped again');
  assert.equal(connectedCount(s), 0, 'no "connected, proxy only"');
  assert.equal((await s.service.invoke('app:init')).activeServerId, null);
  await sleep(30);
  assert.ok(!s.logs.some(l => /core exited/i.test(l.line)), 'stopping it is not mistaken for a crash');
});

test('R4: no sing-box on the router is a failed connect before any core starts', async (t) => {
  const s = start();
  t.after(() => s.service.shutdown());
  s.state.singboxMissing = true;
  await assert.rejects(s.service.invoke('connect', SERVER.id), /sing-box/);
  assert.equal(s.state.xray.starts.length, 0);
});

test('R4: TUN turned off on a router is still a plain proxy connect (the user’s choice, not a failure)', async (t) => {
  const s = start({ settings: { tunMode: false } });
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  assert.equal(connectedCount(s), 1);
  assert.equal(s.statuses.find(x => x.state === 'connected').tun, false);
});

/* ----------------------------- R3: dead cores are rebuilt ----------------------------- */

test('R3: sing-box dying under a live gateway is rebuilt', async (t) => {
  const s = start();
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  const live = s.state.inners.find(i => i.active);
  live.crash();
  await until(() => connectedCount(s) === 2, 'the rebuilt gateway');
  assert.ok(s.state.inners.filter(i => i.active).length === 1, 'one live sing-box again');
  assert.notEqual(s.state.inners.find(i => i.active), live);
  assert.ok(s.statuses.some(x => x.state === 'reconnecting' && x.reason === 'tunnel-exited'));
});

test('R3: xray dying under a live gateway is rebuilt (sing-box would route into a dead SOCKS port)', async (t) => {
  const s = start();
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  s.state.xray.crash();
  await until(() => connectedCount(s) === 2, 'the rebuilt connection');
  assert.equal(s.state.xray.starts.length, 2);
  assert.equal(s.state.xray.running, true);
  assert.ok(s.statuses.some(x => x.state === 'reconnecting' && x.reason === 'core-exited'));
});

test('R3: a stop we asked for (disconnect) is never taken for a crash', async (t) => {
  const s = start();
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  await s.service.invoke('disconnect');
  await sleep(50);
  assert.ok(!s.statuses.some(x => x.state === 'reconnecting'));
  assert.equal(s.state.xray.starts.length, 1);
});

test('R3: on a router the recovery keeps retrying past the desktop’s three tries, until a disconnect', async (t) => {
  const s = start();
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  s.state.gatewayFails = true;
  s.state.inners.find(i => i.active).crash();
  await until(() => s.statuses.filter(x => x.state === 'reconnecting').length >= 7, 'seven recovery attempts');
  assert.ok(!s.statuses.some(x => x.state === 'reconnect-failed'), 'a router never gives up');
  await s.service.invoke('disconnect');
  const n = s.statuses.filter(x => x.state === 'reconnecting').length;
  await sleep(100);
  assert.equal(s.statuses.filter(x => x.state === 'reconnecting').length, n, 'the disconnect ended them');
  // and when the gateway can come up again, the retries bring it back
  const s2 = start();
  t.after(() => s2.service.shutdown());
  await s2.service.invoke('connect', SERVER.id);
  s2.state.gatewayFails = true;
  s2.state.inners.find(i => i.active).crash();
  await until(() => s2.statuses.filter(x => x.state === 'reconnecting').length >= 5, 'five failed attempts');
  s2.state.gatewayFails = false;
  await until(() => connectedCount(s2) === 2, 'back once it can be');
});

test('R3/R4: a rebuild by hand (apply settings) whose gateway fails is handed to the recovery, which brings it back', async (t) => {
  const s = start();
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  s.state.gatewayFails = true;
  const r = await s.service.invoke('settings:apply');
  assert.equal(r.ok, false);
  await until(() => s.statuses.some(x => x.state === 'reconnecting' && x.reason === 'gateway-failed'), 'the recovery taking over');
  s.state.gatewayFails = false;
  await until(() => connectedCount(s) === 2, 'the gateway back without another click');
});

/* ----------------------------- R7: orphans and the exit hook ----------------------------- */

test('R7: the cores a killed run left behind are ended before the first connect, and its rules and table cleared', async (t) => {
  const killed = [];
  const alive = new Set([9001, 9002]);
  const s = start({}, {
    orphans: () => [{ pid: 9001, argv: ['/usr/bin/xray', 'run', '-c', '/etc/irnetfree/config.json'] }, { pid: 9002, argv: ['/usr/bin/sing-box', 'run', '-c', '/tmp/irnf-sb-x/sing-box.json'] }],
    kill: (pid, sig) => {
      if (sig === 0) { if (!alive.has(pid)) throw Object.assign(new Error('ESRCH'), { code: 'ESRCH' }); return true; }
      killed.push([pid, sig]);
      if (sig === 'SIGTERM' && pid === 9001) alive.delete(pid);    // xray goes on SIGTERM…
      if (sig === 'SIGKILL') alive.delete(pid);                     // …sing-box needs the SIGKILL
      return true;
    }
  });
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  assert.deepEqual(killed, [[9001, 'SIGTERM'], [9002, 'SIGTERM'], [9002, 'SIGKILL']]);
  const ev = s.state.events;
  assert.ok(ev.indexOf('gateway:clear-table') >= 0 && ev.indexOf('gateway:clear-table') < ev.indexOf('xray:start'), ev.join(', '));
  // said at start, before any client listens — so it is the syslog copy that carries it
  assert.ok(s.syslog.some(([lvl, l]) => lvl === 'err' && /irnetfree: \[warn\] Ending 2 core process\(es\) a previous run left behind: 9001 xray, 9002 sing-box/.test(l)), JSON.stringify(s.syslog));
});

test('R7: the exit hook stops the core as well as the gateway (a crash no longer leaves xray holding the SOCKS port)', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-svc-exit-'));
  dirs.push(dir);
  fs.writeFileSync(path.join(dir, 'store.json'), JSON.stringify({ servers: [SERVER], routerDefaultsApplied: true, settings: BASE }));
  const child = `
    process.env.IRNETFREE_PLATFORM = 'openwrt';
    const { createService } = require(${JSON.stringify(path.join(__dirname, '..', 'src', 'server', 'service.js'))});
    const fakes = require(${JSON.stringify(path.join(__dirname, 'gatewayFakes.js'))});
    const state = fakes.makeState();
    const svc = createService({ dataDir: ${JSON.stringify(dir)}, deps: fakes.deps(state) });
    svc.invoke('connect', 'srv-1').then(() => {
      process.on('exit', () => { console.log('EVENTS ' + state.events.join(',')); });
      setImmediate(() => { throw new Error('boom: an uncaught exception in the service'); });
    }, (e) => { console.log('CONNECT FAILED ' + e.message); process.exit(3); });
  `;
  const r = spawnSync(process.execPath, ['-e', child], { encoding: 'utf8', timeout: 30000, windowsHide: true });
  assert.notEqual(r.status, 0, 'the child died of the exception');
  const line = (r.stdout.match(/^EVENTS (.*)$/m) || [])[1];
  assert.ok(line, r.stdout + r.stderr);
  assert.match(line, /xray:start/);
  assert.match(line, /xray:kill/, 'the exit hook killed the core: ' + line);
});

/* ----------------------------- R9: the port-53 hijack ----------------------------- */

test('R9: on a router a config on the sing-box core runs on Xray — sing-box has no port-53 hijack', async (t) => {
  const sb = Object.assign({}, SERVER, { id: 'srv-sb', engine: 'sing-box' });
  const s = start({ servers: [sb] });
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', 'srv-sb');
  const v = s.state.xray.validated[0];
  assert.equal(v.engine, 'xray');
  assert.ok(Array.isArray(v.config.outbounds) && v.config.outbounds.some(o => o.protocol), 'an Xray-format config');
  assert.ok(s.logs.some(l => l.level === 'warn' && /no port-53 hijack/i.test(l.line) && /Xray/.test(l.line)), JSON.stringify(s.logs.map(l => l.line)));
  assert.equal(s.statuses.find(x => x.state === 'connected').engine, 'xray');
});

/* ----------------------------- R13: syslog ----------------------------- */

test('R13: warnings, errors and the connection’s state reach syslog marked irnetfree; info lines do not', async (t) => {
  const s = start();
  t.after(() => s.service.shutdown());
  s.state.gatewayFails = true;
  await assert.rejects(s.service.invoke('connect', SERVER.id));
  s.state.gatewayFails = false;
  await s.service.invoke('connect', SERVER.id);
  await s.service.invoke('disconnect');
  const text = s.syslog.map(([lvl, l]) => `${lvl} ${l}`).join('\n');
  assert.match(text, /^err irnetfree: \[error\] .*Gateway did not come up/m);
  assert.match(text, /^info irnetfree: connected — ci-upstream, gateway up$/m);
  assert.match(text, /^info irnetfree: disconnected$/m);
  assert.doesNotMatch(text, /Gateway up on br-lan/, 'an info log line stays out of syslog');
  for (const [, l] of s.syslog) assert.ok(!l.includes('\n'), 'one line per entry');
});
