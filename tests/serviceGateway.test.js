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

/** A service on a fresh data dir with this store; events and syslog lines recorded. `prime(state)`: see startIn. */
function start(store = {}, extraDeps = {}, prime = null) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-svc-gw-'));
  dirs.push(dir);
  const content = Object.assign({ servers: [SERVER], routerDefaultsApplied: true }, store);
  content.settings = Object.assign({}, BASE, store.settings || {});
  fs.writeFileSync(path.join(dir, 'store.json'), JSON.stringify(content));
  return startIn(dir, extraDeps, prime);
}

/** A service on an existing data dir — "the next boot". `prime(state)` runs before it is created. */
function startIn(dir, extraDeps = {}, prime = null) {
  const state = fakes.makeState();
  if (prime) prime(state);
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
// Boot retries run on timers, each behind a whole failing connect: on a loaded
// CI runner (Windows, with every test file running beside this one) four of
// them once took longer than the 4 s default. These waits are for the attempts,
// not a race against the clock — a generous deadline only costs time when the
// test fails anyway.
const RETRIES_MS = 30000;
const gatewayStarts = (s) => s.state.events.filter(e => e === 'gateway:start').length;
/** The count once it has stopped moving: an attempt already past its last gate may still land. */
async function settledStarts(s, quietMs = 200) {
  let n = gatewayStarts(s);
  for (;;) {
    await sleep(quietMs);
    const m = gatewayStarts(s);
    if (m === n) return n;
    n = m;
  }
}

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
  const s = start({ connectIntent: '__advanced__', lastServerId: '__advanced__', settings: { autoConnect: true, advancedRouting: true, routeDefault: SERVER.id, routeRules: [] } });
  t.after(() => s.service.shutdown());
  await until(() => connectedCount(s) === 1, 'the boot connect of __advanced__');
  assert.equal(s.statuses.find(x => x.state === 'connected').serverId, '__advanced__');
});

test('R1: a boot connect to something that no longer exists says so instead of doing nothing silently', async (t) => {
  const s = start({ connectIntent: 'gone-after-a-refresh', settings: { autoConnect: true } });
  t.after(() => s.service.shutdown());
  await until(() => s.logs.some(l => /Auto-connect/.test(l.line)), 'a log line');
  assert.equal(s.state.xray.starts.length, 0, 'nothing was started');
});

test('R1: on a router the boot connect keeps retrying — and a disconnect by hand ends the retries', async (t) => {
  const s = start({ connectIntent: SERVER.id, lastServerId: SERVER.id, settings: { autoConnect: true } });
  t.after(() => s.service.shutdown());
  s.state.gatewayFails = true;
  await until(() => gatewayStarts(s) >= 4, 'four boot attempts', RETRIES_MS);
  await s.service.invoke('disconnect');
  const n = await settledStarts(s);
  await sleep(300);   // well past bootEveryMs (20 ms): a retry still scheduled would have run
  assert.equal(gatewayStarts(s), n, 'no attempt after the disconnect');
  assert.equal(connectedCount(s), 0);
});

/* The owner's rule: on a router the connection stays the way the user left it. */

test('R1: a disconnect by hand survives a reboot — the router stays disconnected (no fallback to the last server)', async (t) => {
  const s = start({ settings: { autoConnect: true } });
  await s.service.invoke('connect', SERVER.id);
  await s.service.invoke('disconnect');
  await s.service.shutdown();
  const again = startIn(s.dir);
  t.after(() => again.service.shutdown());
  await sleep(150);
  assert.equal(again.state.xray.starts.length, 0, 'nothing was connected at boot');
  assert.equal(connectedCount(again), 0);
  // a store with only a last server (a disconnected router upgraded from an older version) stays disconnected too
  const old = start({ lastServerId: SERVER.id, settings: { autoConnect: true } });
  t.after(() => old.service.shutdown());
  await sleep(150);
  assert.equal(old.state.xray.starts.length, 0);
});

test('R1: two power cuts before a boot retry succeeds still resume — only a disconnect by hand clears the intent', async (t) => {
  const s = start({ settings: { autoConnect: true } });
  await s.service.invoke('connect', SERVER.id);
  await s.service.shutdown();                                        // power cut 1 (shutdown does not clear it either)
  const second = startIn(s.dir, {}, (st) => { st.gatewayFails = true; });
  await until(() => second.state.events.filter(e => e === 'gateway:start').length >= 3, 'failing boot attempts', RETRIES_MS);
  await second.service.shutdown();                                   // power cut 2, before any retry succeeded
  const third = startIn(s.dir);
  t.after(() => third.service.shutdown());
  await until(() => connectedCount(third) === 1, 'resumed after the second cut');
  assert.equal(third.statuses.find(x => x.state === 'connected').serverId, SERVER.id);
});

test('R1: upgrading a router that was connected (activeServerId, no intent yet) resumes it once', async (t) => {
  const s = start({ activeServerId: SERVER.id, lastServerId: SERVER.id, settings: { autoConnect: true } });
  t.after(() => s.service.shutdown());
  await until(() => connectedCount(s) === 1, 'the boot connect');
  assert.equal(JSON.parse(fs.readFileSync(path.join(s.dir, 'store.json'), 'utf8')).connectIntent, SERVER.id);
});

test('R1: a connect by hand during the boot retries ends them too', async (t) => {
  const s = start({ connectIntent: SERVER.id, lastServerId: SERVER.id, settings: { autoConnect: true } });
  t.after(() => s.service.shutdown());
  s.state.gatewayFails = true;
  await until(() => gatewayStarts(s) >= 2, 'two boot attempts', RETRIES_MS);
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
  await assert.rejects(s.service.invoke('connect', SERVER.id), /The whole-network tunnel did not come up \(sing-box\)/);
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

// v1.16.1 (field report fix 5): TUN is forced on a router — "proxy only" there
// was the whole LAN going direct behind a panel that said connected, and a LAN
// with no internet under an armed kill switch. A stored "off" still connects,
// with the gateway (routerFieldFixes.test.js pins the settings side).
test('R4: TUN turned off in a router’s store is overridden — the connect builds the gateway', async (t) => {
  const s = start({ settings: { tunMode: false } });
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  assert.equal(connectedCount(s), 1);
  assert.equal(s.statuses.find(x => x.state === 'connected').tun, true);
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
  await until(() => s.statuses.filter(x => x.state === 'reconnecting').length >= 7, 'seven recovery attempts', RETRIES_MS);
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
  await until(() => s2.statuses.filter(x => x.state === 'reconnecting').length >= 5, 'five failed attempts', RETRIES_MS);
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

/* ----------------------------- review fixes ----------------------------- */

test('crash loop: a core that dies again soon after every rebuild is rebuilt with growing waits, and a stable spell resets them', async (t) => {
  const waits = [150, 400, 800];
  const s = start({}, { timing: Object.assign({}, fakes.deps(fakes.makeState()).timing, { routerBackoffMs: waits, crashWindowMs: 1500 }) });
  t.after(() => s.service.shutdown());
  const at = [];
  s.service.onEvent((ch, p) => { if (ch === 'status' && p.state === 'connected') at.push(Date.now()); });
  await s.service.invoke('connect', SERVER.id);
  const gaps = [];
  for (let i = 0; i < 3; i++) {
    const n = at.length;
    const crashed = Date.now();
    s.state.xray.crash();
    await until(() => at.length > n, `rebuild ${i + 1}`, 5000);
    gaps.push(at[n] - crashed);
  }
  assert.ok(gaps[0] < waits[0], `the first drop is rebuilt at once: ${gaps}`);
  assert.ok(gaps[1] >= waits[0] - 20, `the second waits ${waits[0]}ms: ${gaps}`);
  assert.ok(gaps[2] >= waits[1] - 20, `the third waits ${waits[1]}ms: ${gaps}`);
  // (v1.16: the backoff says "reconnecting" with the wait before the attempt starts, so an attempt may be said twice)
  assert.deepEqual([...new Set(s.statuses.filter(x => x.state === 'reconnecting').map(x => x.attempt))], [1, 2, 3], 'the attempt count carries over');
  assert.ok(s.logs.some(l => /dropped again \d+s after it was rebuilt \(core-exited\) — waiting 0\.4s before the next rebuild/.test(l.line)), JSON.stringify(s.logs.map(l => l.line)));
  // a spell longer than the window: the next drop is a first drop again
  const quietStart = Date.now();
  await sleep(1600);
  const n = at.length;
  s.state.xray.crash();
  await until(() => at.length > n, 'the rebuild after a stable spell');
  assert.ok(at[n] - quietStart - 1600 < waits[0], 'rebuilt at once again');
  assert.equal(s.statuses.filter(x => x.state === 'reconnecting').at(-1).attempt, 1);
});

test('a failed switch A→B on a router ends disconnected — and says so to every client and to syslog', async (t) => {
  const b = Object.assign({}, SERVER, { id: 'srv-2', name: 'second' });
  const s = start({ servers: [SERVER, b] });
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  s.state.gatewayFails = true;
  await assert.rejects(s.service.invoke('connect', 'srv-2'));
  assert.equal(s.statuses.at(-1).state, 'disconnected', JSON.stringify(s.statuses.map(x => x.state)));
  assert.equal(s.syslog.at(-1)[1], 'irnetfree: disconnected');
  assert.equal((await s.service.invoke('app:init')).activeServerId, null);
});

test('an endless recovery does not rewrite store.json on every attempt', async (t) => {
  const s = start();
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  const file = path.join(s.dir, 'store.json');
  s.state.gatewayFails = true;
  s.state.inners.find(i => i.active).crash();
  await until(() => s.statuses.filter(x => x.state === 'reconnecting').length >= 2, 'two attempts', RETRIES_MS);
  const before = fs.readFileSync(file, 'utf8');
  const mtime = fs.statSync(file).mtimeMs;
  await until(() => s.statuses.filter(x => x.state === 'reconnecting').length >= 6, 'four more attempts', RETRIES_MS);
  assert.equal(fs.statSync(file).mtimeMs, mtime, 'no write — nothing in it changed');
  assert.equal(fs.readFileSync(file, 'utf8'), before);
});

test('a connect overtaken while it is undoing a failed gateway gives way: no store write, no status, no throw', async (t) => {
  const s = start();
  t.after(() => s.service.shutdown());
  s.state.gatewayFails = true;
  s.state.stopDelayMs = 150;            // the core is slow to exit: the undo is still awaiting it
  const first = s.service.invoke('connect', SERVER.id);
  await until(() => s.state.events.includes('gateway:start'), 'the failed gateway');
  s.state.gatewayFails = false;
  const second = s.service.invoke('connect', SERVER.id);
  const r1 = await first;
  assert.deepEqual(r1, { ok: false, stale: true }, 'abandoned, not an error');
  await second;
  assert.equal(s.statuses.at(-1).state, 'connected', JSON.stringify(s.statuses.map(x => x.state)));
  assert.ok(!s.statuses.some(x => x.state === 'disconnected'), 'the overtaken call said nothing');
  assert.equal((await s.service.invoke('app:init')).activeServerId, SERVER.id);
});

test('on a router a dead core is rebuilt even with "reconnect on network change" off', async (t) => {
  const s = start({ settings: { autoReconnectOnNetworkChange: false } });
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  s.state.xray.crash();
  await until(() => connectedCount(s) === 2, 'the rebuild');
  s.state.inners.find(i => i.active).crash();
  await until(() => connectedCount(s) === 3, 'the rebuild after sing-box died');
});

test('a gateway that fails AFTER it came up is stopped before the core — never left routing into a dead SOCKS port', async (t) => {
  let st = null;   // the fake's shared event list, once the service exists
  const s = start({}, {
    gateway: () => ({
      backendId: 'openwrt', managesDns: true, active: false, interfaceName: 'IRNetFree', dnsPeer: '172.19.0.2', excludeIps: [],
      isAvailable: () => true, isElevated: () => true, physicalInterface: async () => ({ name: 'eth0' }),
      async start() { this.active = true; st.events.push('gw:up'); throw new Error('failed after coming up'); },
      async stop() { if (this.active) st.events.push('gw:stop'); this.active = false; },
      cleanupSync() {}
    })
  });
  st = s.state;
  t.after(() => s.service.shutdown());
  await assert.rejects(s.service.invoke('connect', SERVER.id), /failed after coming up/);
  assert.equal(s.state.xray.running, false);
  const ev = s.state.events;
  assert.ok(ev.includes('gw:stop'), ev.join(', '));
  assert.ok(ev.indexOf('gw:stop') < ev.lastIndexOf('xray:stop'), 'the gateway goes first: ' + ev.join(', '));
  assert.ok(!s.logs.some(l => /core exited/i.test(l.line)), 'stopping the core here is not a crash');
});

test('sing-box\'s own [tun] lines reach syslog at most once per 10s per kind; the service\'s own lines are never held back', async (t) => {
  const s = start();
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  const gw = s.state.gateways.find(g => g.active);
  s.syslog.length = 0;
  for (let i = 0; i < 50; i++) gw.onLog(`[tun] ERROR inbound/tun[tun-in]: connection ${i} from 192.168.1.${i}:5${i} reset by peer`, 'warn');
  gw.onLog('[tun] WARN router: a different kind of line', 'warn');
  gw.onLog('Gateway down: sing-box exited on its own (code=- signal=SIGKILL)', 'error');
  gw.onLog('Gateway down: sing-box exited on its own (code=- signal=SIGKILL)', 'error');
  const lines = s.syslog.map(([, l]) => l);
  assert.equal(lines.filter(l => /connection \d+ from/.test(l)).length, 1, lines.join('\n'));
  assert.equal(lines.filter(l => /a different kind/.test(l)).length, 1);
  assert.equal(lines.filter(l => /Gateway down/.test(l)).length, 2, 'our own lines are not rate-limited');
});

/* ----------------------------- post-merge ----------------------------- */

test('a settings apply keeps the system proxy through the rebuild; a rebuild that fails puts it back', async (t) => {
  const proxy = [];
  const s = start({ settings: { systemProxy: true } }, { setSystemProxy: async (on) => { proxy.push(on); } });
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  assert.deepEqual(proxy, [true]);
  await s.service.invoke('settings:apply');
  assert.deepEqual(proxy, [true, true], 'set again by the connect, never switched off in between');
  s.state.gatewayFails = true;
  const r = await s.service.invoke('settings:apply');
  assert.equal(r.ok, false);
  assert.equal(proxy.at(-1), false, 'not left aimed at a core that did not come back');
  await s.service.invoke('disconnect');
  // the proxy switched off in the settings: restored before the rebuild
  const off = start({ settings: { systemProxy: true } }, { setSystemProxy: async (on) => { off.proxy.push(on); } });
  off.proxy = [];
  t.after(() => off.service.shutdown());
  await off.service.invoke('connect', SERVER.id);
  await off.service.invoke('settings:set', { systemProxy: false });
  await off.service.invoke('settings:apply');
  assert.deepEqual(off.proxy, [true, false]);
});

test('a failing boot attempt says nothing about a disconnect — there was no connection to lose', async (t) => {
  const s = start({ connectIntent: SERVER.id, lastServerId: SERVER.id, settings: { autoConnect: true } });
  t.after(() => s.service.shutdown());
  s.state.gatewayFails = true;
  await until(() => s.state.events.filter(e => e === 'gateway:start').length >= 3, 'three failed boot attempts', RETRIES_MS);
  assert.ok(!s.statuses.some(x => x.state === 'disconnected'), JSON.stringify(s.statuses.map(x => x.state)));
  assert.ok(!s.syslog.some(([, l]) => l === 'irnetfree: disconnected'), 'syslog is not told of a disconnect every 15 s');
  assert.ok(!s.syslog.some(([, l]) => /^irnetfree: error — /.test(l)), 'nor of an error status: each attempt’s reason is in it already');
});

test('a first connect by hand whose gateway fails ends every open panel on the error — not on "Connecting…"', async (t) => {
  // No connection before it, so no "disconnected" (see the boot test above) —
  // but it said "connecting" to every client, and the one that asked is the
  // only one that hears the throw.
  const s = start();
  t.after(() => s.service.shutdown());
  s.state.gatewayFails = true;
  await assert.rejects(s.service.invoke('connect', SERVER.id), /The whole-network tunnel did not come up/);
  const last = s.statuses.at(-1);
  assert.equal(last.state, 'error', JSON.stringify(s.statuses.map(x => x.state)));
  assert.match(last.message, /The whole-network tunnel did not come up \(sing-box\)/);
  assert.ok(!s.syslog.some(([, l]) => /^irnetfree: error — /.test(l)), 'syslog has the reason once, from the log line');
  assert.ok(s.syslog.some(([, l]) => /\[error\] .*The whole-network tunnel did not come up/.test(l)));
});

const withTiming = (over) => ({ timing: Object.assign({}, fakes.deps(fakes.makeState()).timing, over) });

test('a drop queued behind a recovery is replayed through the crash window, not rebuilt at once', async (t) => {
  // the core's SOCKS port takes a moment to come up: the rebuild is still going when the next drop lands
  const slowPort = { waitForLocalPort: () => new Promise((r) => setTimeout(() => r(true), 100)) };
  const s = start({}, Object.assign(withTiming({ routerBackoffMs: [300, 300, 300], crashWindowMs: 10000 }), slowPort));
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  // the core dies again while the recovery for its first death is still rebuilding
  let again = false;
  s.service.onEvent((ch, p) => { if (ch === 'status' && p.state === 'reconnecting' && !again) { again = true; s.state.xray.crash(); } });
  s.state.xray.crash();
  await until(() => connectedCount(s) === 3, 'the rebuild, then the queued drop’s', 5000);
  assert.ok(s.logs.findIndex(l => /dropped again/.test(l.line)) > s.logs.findIndex(l => /Connection restored/.test(l.line)), 'replayed after the rebuild');
  assert.deepEqual([...new Set(s.statuses.filter(x => x.state === 'reconnecting').map(x => x.attempt))], [1, 2], 'it continued that rebuild’s backoff');
  assert.ok(s.logs.some(l => /dropped again \d+s after it was rebuilt \(core-exited\)/.test(l.line)), JSON.stringify(s.logs.map(l => l.line)));
});

test('a core that dies while its connect waits for the SOCKS port fails that connect — no gateway into the dead port, none beside it', async (t) => {
  // The core binds its SOCKS port while the connect waits (waitPort): a kill -9
  // there used to start the recovery's connect at once, beside the first — a
  // second TunOpenwrt built while the first was inside start(), and the loser's
  // undo deleted the shared nft table by name: a gateway "up" with no
  // exclusions and no QUIC rule. v1.16.0 then built the first connect's
  // gateway anyway, into the dead port, and rebuilt after it. Now (field
  // report fix 20) a connect by hand fails, with the core's own last lines,
  // and nothing is rebuilt behind the user's back.
  const slowPort = { waitForLocalPort: () => new Promise((r) => setTimeout(() => r(true), 150)) };
  const s = start({}, slowPort);
  t.after(() => s.service.shutdown());
  const first = s.service.invoke('connect', SERVER.id);
  await until(() => s.state.events.includes('xray:start'), 'the connect’s core');
  s.state.xray.crash(['panic: the core went']);
  await assert.rejects(first, /The core exited \(code=- signal=SIGKILL\) before it opened 127\.0\.0\.1:\d+ — the whole-network tunnel was not started\. Its last lines: panic: the core went/);
  await sleep(100);
  assert.equal(s.state.events.includes('gateway:start'), false, 'no gateway at all');
  assert.equal(s.state.xray.starts.length, 1, 'no rebuild of a connect by hand that failed');
  assert.equal(connectedCount(s), 0);
});

test('…at boot the same death is retried by the boot loop: one gateway, once a core lives', async (t) => {
  let calls = 0;
  let s = null;
  const dying = { waitForLocalPort: async () => { if (++calls === 1) s.state.xray.crash(['panic: the core went']); return true; } };
  s = start({ connectIntent: SERVER.id, lastServerId: SERVER.id, settings: { autoConnect: true } }, dying);
  t.after(() => s.service.shutdown());
  await until(() => connectedCount(s) === 1, 'the boot connect’s second attempt');
  assert.equal(s.state.xray.starts.length, 2);
  assert.equal(s.state.inners.filter(i => i.starts > 0).length, 1, 'one gateway — none was built for the dead core');
  const ev = s.state.events.filter(e => e === 'gateway:start' || e === 'xray:start');
  assert.deepEqual(ev, ['xray:start', 'xray:start', 'gateway:start'], ev.join(', '));
  assert.ok(!s.logs.some(l => /starting the gateway anyway/.test(l.line)));
});

/**
 * deps.waitForLocalPort for a core that dies while the connect waits for its
 * SOCKS port — whenever `dying()` says so; it returns as the real one does,
 * once `opts.stop()` sees the core gone.
 */
function portOfDyingCore(get, dying, lines = ['panic: out of memory']) {
  return async (port, ms, opts) => {
    if (!dying()) return true;
    get().state.xray.crash(lines);
    const deadline = Date.now() + Math.min(ms, 2000);
    while (Date.now() < deadline && !(opts && typeof opts.stop === 'function' && opts.stop())) await sleep(5);
    return false;
  };
}

test('a recovery whose core dies before its SOCKS port opens, attempt after attempt, keeps the backoff — never a restart at once', async (t) => {
  // v1.16.1 review (critical): each attempt's connect fails with the core's own
  // words (fix 20) — and the same death, a drop queued behind that recovery,
  // was replayed through recoverFromDrop as a FIRST drop (no successful
  // rebuild to count from), which ran attempt 0 again at once and cancelled
  // the backoff timer: 127 core starts in 1.5 s, forever, on the A7.
  let s = null;
  let dying = false;
  s = start({}, Object.assign(withTiming({ routerBackoffMs: [1000, 1000, 1000], crashWindowMs: 120000 }), { waitForLocalPort: portOfDyingCore(() => s, () => dying) }));
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  dying = true;
  const n0 = s.state.xray.starts.length;
  s.state.xray.crash();   // the drop: its rebuild's core dies before its port opens, and so does every retry's
  await sleep(1500);
  const n = s.state.xray.starts.length - n0;
  assert.ok(n >= 1 && n <= 2, `at most two core starts in 1.5 s with a 1 s backoff, got ${n}: ${s.logs.map(l => l.line).slice(-8).join(' / ')}`);
  assert.ok(s.statuses.some(x => x.state === 'reconnecting' && x.retryInMs === 1000), 'the retry waits its turn');
  // …and once a core lives again, the next retry brings the connection back
  dying = false;
  await until(() => connectedCount(s) === 2, 'back once the core lives', 5000);
});

test('…and a Connect by hand on a pending edit whose core dies the same way is handed to the recovery AFTER the first wait', async (t) => {
  // The hand Connect on the live server (item 18) keeps the intent when it
  // fails (abortGateway): it used to be taken up by the drop at once — a
  // second start right behind the first — and then looped like the above.
  let s = null;
  let dying = false;
  s = start({}, Object.assign(withTiming({ routerBackoffMs: [1000, 1000, 1000], crashWindowMs: 120000 }), { waitForLocalPort: portOfDyingCore(() => s, () => dying) }));
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  await s.service.invoke('servers:update', { id: SERVER.id, fields: { address: '192.0.2.10', port: 1081 } });
  dying = true;
  const n0 = s.state.xray.starts.length;
  await assert.rejects(s.service.invoke('connect', SERVER.id), /before it opened 127\.0\.0\.1:47808/);
  await sleep(1500);
  const n = s.state.xray.starts.length - n0;
  assert.ok(n >= 1 && n <= 2, `the Connect and at most one retry after the 1 s wait, got ${n}: ${s.logs.map(l => l.line).slice(-8).join(' / ')}`);
  assert.ok(s.statuses.some(x => x.state === 'reconnecting' && x.retryInMs === 1000), 'the hand-over says when it retries');
  dying = false;
  await until(() => connectedCount(s) === 2, 'back without another click', 5000);
  assert.equal(s.state.xray.starts.at(-1).config.outbounds.find(o => o.tag === 'proxy').settings.servers[0].port, 1081, 'with the edit');
});

test('…but a Connect on the live connection refused before anything was torn down (a bad edit) leaves the running connection alone', async (t) => {
  const s = start({}, withTiming({ routerBackoffMs: [20, 20, 20], crashWindowMs: 120000 }));
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  await s.service.invoke('servers:update', { id: SERVER.id, fields: { port: 1082 } });
  s.state.check = { ok: false, error: 'infra/conf: something the core refuses' };
  await assert.rejects(s.service.invoke('connect', SERVER.id), /Config error: infra\/conf: something the core refuses/);
  await sleep(100);
  assert.equal(s.state.xray.starts.length, 1, 'no retry tears down what still works');
  assert.ok(!s.statuses.some(x => x.state === 'reconnecting'), JSON.stringify(s.statuses.map(x => x.state)));
  assert.equal(s.state.xray.running, true);
  assert.ok(s.state.inners.some(i => i.active), 'the gateway is still up');
});

test('a connect by hand whose core dies before its port opens: no "rebuilding" for a rebuild that never comes; the error names the signal and the panic, not its stack', async (t) => {
  const stack = [
    '2026/10/02 10:00:00 [Warning] core: Xray 26.3.27 started',
    'panic: runtime error: invalid memory address or nil pointer dereference',
    '[signal SIGSEGV: segmentation violation code=0x1 addr=0x0 pc=0x5c1a2c]',
    'goroutine 1 [running]:',
    'github.com/xtls/xray-core/app/dns.(*Server).Start(0x0)',
    '\t/build/app/dns/server.go:123 +0x1c',
    'main.main()',
    '\t/build/main/main.go:45 +0x2a8'
  ];
  let s = null;
  s = start({ settings: { killSwitch: true } }, { waitForLocalPort: portOfDyingCore(() => s, () => true, stack) });
  t.after(() => s.service.shutdown());
  await assert.rejects(s.service.invoke('connect', SERVER.id), (e) => {
    assert.match(e.message, /^The core exited \(code=- signal=SIGKILL\) before it opened 127\.0\.0\.1:47808 — the whole-network tunnel was not started\. Its last lines: panic: runtime error: invalid memory address or nil pointer dereference( mem:.*)?$/);
    return true;
  });
  await sleep(50);
  const text = s.logs.map(l => `[${l.level}] ${l.line}`);
  assert.ok(!text.some(l => /rebuilding the connection/.test(l)), text.join('\n'));
  assert.ok(text.some(l => /^\[error\] The core exited on its own \(code=- signal=SIGKILL\) while connecting/.test(l)), text.join('\n'));
  // the kill switch stays armed (the intent is the user's), and says what that means now
  assert.ok(text.some(l => /^\[warn\] Kill switch: the connect failed and nothing retries it — LAN internet stays blocked until a connect succeeds or you press Disconnect/.test(l)), text.join('\n'));
  assert.equal(s.state.xray.starts.length, 1);
});

test('a drop that lands inside a connect which then comes up whole is not rebuilt', async (t) => {
  // a sing-box that died while the connect was still building the gateway, which that connect then rebuilt
  const slowPort = { waitForLocalPort: () => new Promise((r) => setTimeout(() => r(true), 100)) };
  const s = start({}, slowPort);
  t.after(() => s.service.shutdown());
  const first = s.service.invoke('connect', SERVER.id);
  await until(() => s.state.events.includes('xray:start'), 'the connect’s core');
  const own = s.state.xray.proc;
  s.state.xray.crash();
  // …a stale "stopped" of a core already replaced: the connect’s own is up (the
  // real XrayManager never clears `proc` for a late exit of an old one)
  s.state.xray.running = true;
  s.state.xray.proc = own;
  await first;
  await sleep(100);
  assert.equal(connectedCount(s), 1);
  assert.ok(!s.statuses.some(x => x.state === 'reconnecting'), JSON.stringify(s.statuses.map(x => x.state)));
});

test('a connect by hand starts with no crash history — its first drop is rebuilt at once', async (t) => {
  const s = start({}, withTiming({ routerBackoffMs: [1500, 1500, 1500], crashWindowMs: 60000 }));
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  s.state.xray.crash();
  await until(() => connectedCount(s) === 2, 'the rebuild');
  await s.service.invoke('connect', SERVER.id);   // the user, by hand
  const n = connectedCount(s);
  const crashed = Date.now();
  s.state.xray.crash();
  await until(() => connectedCount(s) === n + 1, 'the rebuild after the connect by hand');
  assert.ok(Date.now() - crashed < 1500, 'no wait: the history before the connect by hand is gone');
  assert.ok(!s.logs.some(l => /dropped again/.test(l.line)));
});

test('a Reconnect by hand that fails while the drop’s own recovery brings the connection back leaves no retry behind — the next crash is still rebuilt', async (t) => {
  // v1.16.1 re-review: the hand-over armed its retry while that recovery was
  // running; the timer fired into it (only queued there), its handle stayed,
  // and recoverFromDrop took the dead handle for a retry still to come — every
  // later core or sing-box death ignored, every WAN change "not judged".
  let s = null;
  let mode = 'ok';
  const port = async () => {
    // the Reconnect's core binds and dies 5 ms later: a drop, not that connect's own failure
    if (mode === 'die-after-bind') { mode = 'slow'; setTimeout(() => s.state.xray.crash(), 5); return true; }
    if (mode === 'slow') { mode = 'ok'; await sleep(1500); return true; }   // the recovery's core, slow to bind (the A7)
    return true;
  };
  s = start({}, Object.assign(withTiming({ routerBackoffMs: [1000, 1000, 1000], crashWindowMs: 120000 }), { waitForLocalPort: port }));
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  let open = null;
  s.state.gatewayGate = new Promise((r) => { open = r; });
  mode = 'die-after-bind';
  const reconnect = s.service.invoke('vpn:reconnect');
  await until(() => gatewayStarts(s) === 2, 'the Reconnect’s gateway start, held');
  await until(() => s.logs.some(l => /^The core exited on its own .* while connecting/.test(l.line)), 'its core’s death');
  s.state.gatewayFails = true;   // …and then that gateway fails too
  s.state.gatewayGate = null;
  open();
  assert.equal((await reconnect).ok, false);
  s.state.gatewayFails = false;  // the recovery's core is still waiting for its port
  await until(() => connectedCount(s) === 2, 'the drop’s recovery bringing it back', 5000);
  await sleep(1300);             // past the hand-over's 1 s: nothing rebuilds what is up
  const lines = () => s.logs.map(l => l.line).slice(-10).join(' / ');
  assert.equal(connectedCount(s), 2, 'the restored connection is not rebuilt again: ' + lines());
  assert.ok(!s.logs.some(l => /Reconnect failed — retrying/.test(l.line)), 'one chain, the recovery’s: ' + lines());
  const n = s.state.xray.starts.length;
  s.state.xray.crash();
  await until(() => connectedCount(s) === 3, 'the next crash rebuilt', 5000);
  assert.ok(s.state.xray.starts.length > n);
});

test('a Connect by hand whose core dies while a recovery’s gateway start is held is retried once that recovery gives way', async (t) => {
  // v1.16.1 re-review: the Connect overtakes the recovery, which then goes
  // stale and retries nothing; the hand-over's timer fired into it and was
  // only queued, and its dead handle stopped every retry after it — the
  // status stuck at "Reconnecting… (attempt 2)", the LAN blocked for good.
  let s = null;
  let dying = false;
  const once = () => { const d = dying; dying = false; return d; };
  s = start({}, Object.assign(withTiming({ routerBackoffMs: [300, 300, 300], crashWindowMs: 120000 }), { waitForLocalPort: portOfDyingCore(() => s, once) }));
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  let open = null;
  s.state.gatewayGate = new Promise((r) => { open = r; });
  s.state.xray.crash();          // the drop: its recovery's gateway start is held (a slow A7)
  await until(() => gatewayStarts(s) === 2, 'the recovery’s gateway start, held');
  dying = true;                  // the Connect's own core dies before its port opens
  await assert.rejects(s.service.invoke('connect', SERVER.id), /before it opened 127\.0\.0\.1:47808/);
  await sleep(600);              // past the 300 ms wait, the recovery still held
  const n = s.state.xray.starts.length;
  s.state.gatewayGate = null;
  open();                        // the overtaken recovery gives way
  await until(() => s.state.xray.starts.length > n, 'another core start', 3000);
  await until(() => connectedCount(s) === 2, 'connected again', 5000);
});

test('every recovery timer lets go of its handle as it fires — a handle left behind reads as a retry still to come', () => {
  // recoverFromDrop, judgeWanChange's busy() and alreadyUp() all read
  // `recoverTimer`; a call that fired into an early return (queued behind a
  // recovery, an intent gone, auto-reconnect turned off mid-backoff) must not
  // leave it set. Pinned as text: every arm, present and future.
  const src = fs.readFileSync(path.join(__dirname, '..', 'src', 'server', 'service.js'), 'utf8');
  const arms = src.match(/recoverTimer = setTimeout\(\(\) => \{?\s*[^\n]*/g) || [];
  assert.ok(arms.length >= 3, arms.join('\n'));
  for (const a of arms) assert.match(a, /^recoverTimer = setTimeout\(\(\) => \{\s*recoverTimer = null;/, a);
});

// what xrayManager.validateWithFallback answers for a finalmask server on a feed core (24.12.31) with no Xray-PattN
const PATTN_REFUSAL = {
  ok: false, engine: 'xray', pattnNeeded: true, finalmaskIgnored: true, coreVersion: '24.12.31',
  error: 'xray 24.12.31 does not know finalmask (26.3.27 and newer do) — it would run this server without its mask'
};

test('a boot connect the core refuses (a finalmask server, no Xray-PattN) is an error that says why — not "waiting for internet" every 15 s', async (t) => {
  const s = start({ connectIntent: SERVER.id, lastServerId: SERVER.id, settings: { autoConnect: true, killSwitch: true } },
    withTiming({ refusedRetryMs: 700 }), (st) => { st.check = PATTN_REFUSAL; });
  t.after(() => s.service.shutdown());
  await until(() => s.statuses.some(x => x.state === 'error'), 'the refusal said');
  const err = s.statuses.find(x => x.state === 'error');
  assert.match(err.message, /^This server needs Xray-PattN — install it under Settings → Required files \(the official core 24\.12\.31 does not know finalmask/);
  assert.equal(err.cause, 'boot');
  await sleep(300);              // bootEveryMs is 20 ms: a retry as for a missing WAN would have run a dozen times
  assert.equal(s.state.xray.validated.length, 1, 'refused once, not retried at the boot loop’s pace');
  assert.ok(!s.statuses.some(x => x.state === 'waiting'), JSON.stringify(s.statuses.map(x => x.state)));
  const snap = s.service.connSnapshot();
  assert.equal(snap.state, 'error');
  assert.match(snap.reason, /needs Xray-PattN/);
  assert.ok(s.syslog.some(([, l]) => /^irnetfree: error — This server needs Xray-PattN/.test(l)), JSON.stringify(s.syslog));
  assert.ok(s.logs.some(l => l.level === 'warn' && /^Kill switch: the core refuses this connection — LAN internet stays blocked/.test(l.line)), JSON.stringify(s.logs.map(l => l.line)));
  // tried again rarely: once the fork is there, it connects with nobody pressing a button
  delete s.state.check;
  await until(() => connectedCount(s) === 1, 'the rare retry', 3000);
});

// …and for an ECH server on a feed core older than 25.8.3 (25.1.30) with no Xray-PattN (v1.18)
const ECH_REFUSAL = {
  ok: false, engine: 'xray', echUnsupported: true, coreVersion: '25.1.30', plaintextRejected: false,
  error: 'xray 25.1.30 does not know ECH (25.8.3 and newer do) — it would connect without it'
};

test('a boot connect of an ECH server on a core too old for ECH is refused like the Xray-PattN case: said once, not retried at the boot loop’s pace', async (t) => {
  const s = start({ connectIntent: SERVER.id, lastServerId: SERVER.id, settings: { autoConnect: true } },
    withTiming({ refusedRetryMs: 60000 }), (st) => { st.check = ECH_REFUSAL; });
  t.after(() => s.service.shutdown());
  await until(() => s.statuses.some(x => x.state === 'error'), 'the refusal said');
  const err = s.statuses.find(x => x.state === 'error');
  assert.equal(err.message, 'This server uses ECH, which Xray 25.1.30 does not know (it would connect without it) — update Xray under Settings → Required files');
  await sleep(300);              // bootEveryMs is 20 ms: a retry as for a missing WAN would have run a dozen times
  assert.equal(s.state.xray.validated.length, 1, 'refused once, not retried at the boot loop’s pace');
  assert.equal(s.state.xray.starts.length, 0, 'never started without its ECH');
  assert.equal(s.service.connSnapshot().state, 'error');
  assert.ok(s.logs.some(l => l.level === 'error' && l.line === 'Config rejected by xray: ' + ECH_REFUSAL.error), 'the core’s own words stay in the log');
});

test('a rebuild the core refuses (the store changed under the live connection) stops the quick retries and says why; the rare retry brings it back', async (t) => {
  const s = start({}, withTiming({ refusedRetryMs: 700 }));
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  s.state.check = PATTN_REFUSAL;
  const v0 = s.state.xray.validated.length;
  s.state.xray.crash();
  await until(() => s.statuses.some(x => x.state === 'error'), 'the refusal said');
  await sleep(300);              // routerBackoffMs is 5 ms: quick retries would have run dozens of times
  assert.equal(s.state.xray.validated.length - v0, 1, 'one refused attempt');
  assert.equal(s.statuses.at(-1).state, 'error');
  assert.match(s.statuses.at(-1).message, /needs Xray-PattN/);
  assert.equal(s.service.connSnapshot().state, 'error');
  delete s.state.check;
  await until(() => connectedCount(s) === 2, 'the rare retry', 3000);
});

test('…but a binary that is gone for a while (sing-box or the core: an opkg upgrade, a file held) is no refusal — the recovery keeps its quick backoff and comes back by itself', async (t) => {
  // the QEMU smoke holds /usr/bin/sing-box during a recovery and gives it back: run 37080745024 waited out
  // the 10-minute refusal retry on 23.05.5 when a missing sing-box was taken for one
  const s = start({}, withTiming({ refusedRetryMs: 60000 }));
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  s.state.singboxMissing = true;
  s.state.inners.find(i => i.active).crash();
  await until(() => s.statuses.filter(x => x.state === 'reconnecting').length >= 4, 'retries at the backoff’s pace', RETRIES_MS);
  assert.ok(!s.statuses.some(x => x.state === 'error'), JSON.stringify(s.statuses.map(x => x.state)));
  s.state.singboxMissing = false;
  await until(() => connectedCount(s) === 2, 'back once sing-box is', 5000);
  // the core's file, the same way: what its check says when there is none, or when the spawn finds it gone or busy
  for (const error of ['core binary not found', 'spawn /usr/bin/xray ENOENT', 'spawn /usr/bin/xray ETXTBSY']) {
    s.state.check = { ok: false, error };
    const n = s.statuses.filter(x => x.state === 'reconnecting').length;
    s.state.xray.crash();
    await until(() => s.statuses.filter(x => x.state === 'reconnecting').length >= n + 3, `retries for "${error}"`, RETRIES_MS);
    assert.ok(!s.statuses.some(x => x.state === 'error'), error + ': ' + JSON.stringify(s.statuses.map(x => x.state)));
    delete s.state.check;
    const c = connectedCount(s);
    await until(() => connectedCount(s) === c + 1, `back after "${error}"`, 5000);
  }
});

// What xrayManager.validate answers for a -test that never gave a verdict: killed by a signal after its banner (the
// kernel's OOM killer on the 512 MB AC-1304), or ended by Go's runtime out of memory. The first carries the banner's
// last line as its text, as the manager used to answer it: the flag is what says so, never the words.
const KILLED_CHECKS = [
  { ok: false, killed: true, error: '[Info] infra/conf/serial: Reading config: &{Name:/etc/irnetfree/test-cfg-1.json Format:json}' },
  { ok: false, killed: true, error: 'xray -test was killed (SIGKILL) — the config was not checked' },
  { ok: false, killed: true, error: 'xray -test ran out of memory (fatal error: runtime: out of memory) — the config was not checked' }
];

test('…nor is a config check that was killed or ran out of memory — the recovery keeps its quick backoff, no "error", and comes back by itself', async (t) => {
  // v1.16.1 re-review: the banner's last line was taken for the core's verdict, and a 512 MB router waited 10 minutes
  const s = start({}, withTiming({ refusedRetryMs: 60000 }));
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  for (const check of KILLED_CHECKS) {
    s.state.check = check;
    const n = s.statuses.filter(x => x.state === 'reconnecting').length;
    s.state.xray.crash();
    await until(() => s.statuses.filter(x => x.state === 'reconnecting').length >= n + 3, `retries for "${check.error}"`, RETRIES_MS);
    assert.ok(!s.statuses.some(x => x.state === 'error'), check.error + ': ' + JSON.stringify(s.statuses.map(x => x.state)));
    assert.notEqual(s.service.connSnapshot().state, 'error');
    delete s.state.check;
    const c = connectedCount(s);
    await until(() => connectedCount(s) === c + 1, `back after "${check.error}"`, 5000);
  }
});

test('…and at boot (the cache is empty there): a killed config check is "waiting", retried at the boot loop\'s pace', async (t) => {
  const s = start({ connectIntent: SERVER.id, lastServerId: SERVER.id, settings: { autoConnect: true, killSwitch: true } },
    withTiming({ refusedRetryMs: 60000 }), (st) => { st.check = KILLED_CHECKS[1]; });
  t.after(() => s.service.shutdown());
  await until(() => s.state.xray.validated.length >= 3, 'the boot loop’s retries', RETRIES_MS);
  assert.ok(!s.statuses.some(x => x.state === 'error'), JSON.stringify(s.statuses.map(x => x.state)));
  assert.ok(s.statuses.some(x => x.state === 'waiting'), JSON.stringify(s.statuses.map(x => x.state)));
  assert.ok(!s.logs.some(l => /Config rejected by xray|refuses this connection/.test(l.line)), JSON.stringify(s.logs.map(l => l.line)));
  delete s.state.check;
  await until(() => connectedCount(s) === 1, 'connected once the check finishes', 5000);
});

test('…and a Reconnect by hand the core refuses is not handed to the quick retries either', async (t) => {
  const s = start({}, withTiming({ refusedRetryMs: 60000 }));
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  s.state.check = PATTN_REFUSAL;
  const v0 = s.state.xray.validated.length;
  const r = await s.service.invoke('vpn:reconnect');
  assert.equal(r.ok, false);
  assert.match(r.error, /needs Xray-PattN/);
  await sleep(300);
  assert.equal(s.state.xray.validated.length - v0, 1);
  assert.ok(!s.statuses.some(x => x.state === 'reconnecting'), JSON.stringify(s.statuses.map(x => x.state)));
  assert.equal(s.service.connSnapshot().state, 'error');
  // a Connect by hand still tries at once
  delete s.state.check;
  await s.service.invoke('connect', SERVER.id);
  assert.equal(connectedCount(s), 2);
});

test('the give-up of a crash loop says whether the proxy is still up', () => {
  // Reached only on the desktop (a router never gives up) and only after 2+5+15 s of
  // waits, so pinned as text: a tunnel that keeps dying over a live core leaves the proxy up.
  const src = fs.readFileSync(path.join(__dirname, '..', 'src', 'server', 'service.js'), 'utf8');
  const body = src.slice(src.indexOf('function recoverFromDrop(reason, seq = null) {'), src.indexOf('async function recoverFromNetworkChange('));
  assert.match(body, /send\('status', \{ state: 'reconnect-failed', reason, proxyUp: !!\(xray && xray\.running\), tunError: null \}\);/);
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
  assert.match(text, /^err irnetfree: \[error\] .*The whole-network tunnel did not come up/m);
  assert.match(text, /^info irnetfree: connected — ci-upstream, gateway up$/m);
  assert.match(text, /^info irnetfree: disconnected$/m);
  assert.doesNotMatch(text, /Whole-network tunnel \(gateway\) up on br-lan/, 'an info log line stays out of syslog');
  for (const [, l] of s.syslog) assert.ok(!l.includes('\n'), 'one line per entry');
});

/* ------------- the connect path: pinned entry names, loud chains, the live NIC ------------- */

/** An upstream addressed by NAME (.invalid: were anything to ask a real resolver, it asks for nothing real). */
const NAMED = Object.assign(makeProxyServer({ type: 'socks', address: 'upstream.invalid', port: 1080, name: 'named-upstream' }), { id: 'srv-named' });

/** deps.resolveHost: answers `answer()` for every name, remembers each question. */
function fakeResolver(answer) {
  const asked = [];
  const fn = async (host) => {
    asked.push(host);
    const ips = answer(host) || [];
    return { ips, source: ips.length ? 'os' : 'none', suspect: [] };
  };
  fn.asked = asked;
  return fn;
}
const configAt = (s, i) => s.state.xray.starts[i].config;
const outboundOf = (cfg, tag) => cfg.outbounds.find(o => o.tag === tag);

test('A1: an upstream named by hostname is answered from the config, resolved before the gateway comes up', async (t) => {
  const resolveHost = fakeResolver(() => ['198.51.100.7']);
  const s = start({ servers: [NAMED] }, { resolveHost });
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', NAMED.id);
  const cfg = configAt(s, 0);
  assert.deepEqual(cfg.dns.hosts, { 'upstream.invalid': ['198.51.100.7'] });
  const proxy = outboundOf(cfg, 'proxy');
  assert.equal(proxy.streamSettings.sockopt.domainStrategy, 'UseIPv4', 'the dialer asks the core’s DNS, never dnsmasq');
  assert.equal(proxy.streamSettings.sockopt.interface, 'eth0');
  assert.equal(proxy.settings.servers[0].address, 'upstream.invalid', 'the name stays in the outbound');
  assert.deepEqual(resolveHost.asked, ['upstream.invalid']);
  const gw = s.state.inners.find(i => i.active);
  assert.ok(gw.bypass.includes('198.51.100.7'), `the gateway keeps the pinned address off the tunnel: ${gw.bypass}`);
});

test('A1: a rebuild where nothing resolves keeps the address of the last connect — the name is never handed back to the OS', async (t) => {
  let answer = ['198.51.100.7'];
  const s = start({ servers: [NAMED] }, { resolveHost: fakeResolver(() => answer) });
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', NAMED.id);
  answer = [];   // a recovery under the gateway: dnsmasq's upstream is the tunnel that is down
  // a rebuild of the live connection (v1.16: a Connect on the connection that is already up is a no-op, S2)
  await s.service.invoke('vpn:reconnect');
  assert.deepEqual(configAt(s, 1).dns.hosts, { 'upstream.invalid': ['198.51.100.7'] });
  assert.ok(s.logs.some(l => l.level === 'warn' && /upstream\.invalid does not resolve right now — using 198\.51\.100\.7/.test(l.line)), JSON.stringify(s.logs.map(l => l.line)));
  answer = ['198.51.100.8'];   // a fresh answer always wins
  await s.service.invoke('vpn:reconnect');
  assert.deepEqual(configAt(s, 2).dns.hosts, { 'upstream.invalid': ['198.51.100.8'] });
});

test('A1: a name nothing ever resolved is left to the core, and said so; a router’s stored "TUN off" still pins it', async (t) => {
  const none = fakeResolver(() => []);
  const s = start({ servers: [NAMED] }, { resolveHost: none });
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', NAMED.id);
  assert.equal('hosts' in configAt(s, 0).dns, false);
  assert.equal('domainStrategy' in outboundOf(configAt(s, 0), 'proxy').streamSettings.sockopt, false);
  assert.ok(s.logs.some(l => l.level === 'warn' && /Could not resolve the server upstream\.invalid/.test(l.line)));

  // A proxy-only connect resolves nothing (`if (!settings.tunMode) return
  // settings;`, pinned in both mirrors by connectPath.test.js) — but a router
  // has no proxy-only connect any more (field report fix 5): a stored "off"
  // is still a tunnel, so the name is pinned like under any other gateway.
  const asked = fakeResolver(() => ['198.51.100.7']);
  const p = start({ servers: [NAMED], settings: { tunMode: false } }, { resolveHost: asked });
  t.after(() => p.service.shutdown());
  await p.service.invoke('connect', NAMED.id);
  assert.deepEqual(asked.asked, ['upstream.invalid']);
  assert.deepEqual(configAt(p, 0).dns.hosts, { 'upstream.invalid': ['198.51.100.7'] });
});

test('A2: a chain that lost a member refuses to connect, by name, instead of becoming a shorter chain', async (t) => {
  const b = Object.assign({}, SERVER, { id: 'srv-2', name: 'second' });
  const tes = { id: 'tes', name: 'Tes Chain', members: ['srv-gone', SERVER.id, 'srv-2'] };
  const s = start({ servers: [SERVER, b], chains: [tes] });
  t.after(() => s.service.shutdown());
  // [gone → A → B] would have connected as [A → B]
  await assert.rejects(s.service.invoke('connect', 'tes'), /The chain “Tes Chain” lost a server/);
  const pair = start({ servers: [SERVER], chains: [{ id: 'tes', name: 'Tes Chain', members: ['srv-gone', SERVER.id] }] });
  t.after(() => pair.service.shutdown());
  await assert.rejects(pair.service.invoke('connect', 'tes'), /The chain “Tes Chain” lost a server/, 'not “needs at least 2 servers”');
  assert.equal(s.state.xray.starts.length + pair.state.xray.starts.length, 0, 'nothing was started');
});

test('A2: advanced routing to a chain that lost its first hop refuses — the corporate range never dials the company from the ISP', async (t) => {
  const tes = { id: 'tes', name: 'Tes Chain', members: ['srv-xhttp-replaced', SERVER.id] };
  const rules = [{ type: 'ip', value: '192.168.0.0/16, 10.0.0.0/8, 192.168.45.0/24', target: 'chain:tes' }];
  const s = start({ servers: [SERVER], chains: [tes], settings: { advancedRouting: true, routeDefault: SERVER.id, routeRules: rules } });
  t.after(() => s.service.shutdown());
  await assert.rejects(s.service.invoke('connect', '__advanced__'), /The chain “Tes Chain” lost a server/);
  assert.equal(s.state.xray.starts.length, 0);
  // the default may name it too
  const d = start({ servers: [SERVER], chains: [tes], settings: { advancedRouting: true, routeDefault: 'chain:tes', routeRules: [] } });
  t.after(() => d.service.shutdown());
  await assert.rejects(d.service.invoke('connect', '__advanced__'), /Tes Chain/);
  // a broken chain nothing routes to stops nothing
  const u = start({ servers: [SERVER], chains: [tes], settings: { advancedRouting: true, routeDefault: SERVER.id, routeRules: [] } });
  t.after(() => u.service.shutdown());
  await u.service.invoke('connect', '__advanced__');
  assert.equal(u.state.xray.starts.length, 1);
});

test('A2: a pool entry on a chain that lost a member refuses as well', async (t) => {
  const tes = { id: 'tes', name: 'Tes Chain', members: ['srv-gone', SERVER.id] };
  const pool = [{ id: 'p1', name: 'corp', target: 'chain:tes', socksPort: 47811, enabled: true }];
  const s = start({ servers: [SERVER], chains: [tes], pool });
  t.after(() => s.service.shutdown());
  await assert.rejects(s.service.invoke('connect', '__pool__'), /The chain “Tes Chain” lost a server/);
});

test('A3: a connect over a live gateway reads the NIC again instead of keeping the one the tunnel was built with', async (t) => {
  const b = Object.assign({}, SERVER, { id: 'srv-2', name: 'second' });
  const s = start({ servers: [SERVER, b] });
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  assert.equal(outboundOf(configAt(s, 0), 'direct').streamSettings.sockopt.interface, 'eth0');
  // the WAN moved while connected; the switch to B rebuilds the gateway for it
  s.state.inners.find(i => i.active).physicalInterface = async () => ({ name: 'wan2', ifIndex: null, gateway: '10.0.0.1' });
  await s.service.invoke('connect', 'srv-2');
  assert.equal(outboundOf(configAt(s, 1), 'direct').streamSettings.sockopt.interface, 'wan2');
  // a read that names nothing usable (the tunnel's own device, a failed
  // lookup) keeps the name the live tunnel was built with
  s.state.inners.find(i => i.active).physicalInterface = async () => ({ name: 'IRNetFree', ifIndex: null, gateway: null });
  await s.service.invoke('connect', SERVER.id);
  assert.equal(outboundOf(configAt(s, 2), 'direct').streamSettings.sockopt.interface, 'wan2');
  s.state.inners.find(i => i.active).physicalInterface = async () => { throw new Error('ip: not found'); };
  await s.service.invoke('connect', 'srv-2');
  assert.equal(outboundOf(configAt(s, 3), 'direct').streamSettings.sockopt.interface, 'wan2');
});
