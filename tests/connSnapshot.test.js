'use strict';
/**
 * The connection as ONE fact the service can be asked for — connSnapshot() —
 * on every page load (app:init.conn) and as the first event of every /events
 * stream (v1.16, S1): a phone reloading a background tab used to see
 * "disconnected" while the tunnel was up, and its Connect was a full rebuild.
 * Also S2 (a Connect on the connection that is already up is a no-op), S4
 * (a drop shows "reconnecting" through the backoff, boot retries "waiting"),
 * B1 (the boot connect follows connectIntent) and S6/S7 (the ring, the
 * diagnostics bundle, every transition logged with its cause).
 *
 * The real service over the gateway fakes (tests/gatewayFakes.js): nothing is
 * spawned or bound, the machine's network is never touched.
 */
process.env.IRNETFREE_PLATFORM = 'openwrt';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const H = require('./serviceHarness');
const child = require('./serverChild');

process.setMaxListeners(60);   // every service registers its own exit hook
test.after(() => H.cleanupDirs());

const { SERVER, SERVER_B, until, sleep, connectedCount } = H;

/* ----------------------------- S1: the snapshot ----------------------------- */

test('S1: after a connect app:init carries conn {state connected, serverId, since}; after a disconnect it says so', async (t) => {
  const s = H.start();
  t.after(() => s.service.shutdown());
  const before = Date.now();
  const fresh = (await s.service.invoke('app:init')).conn;
  assert.equal(fresh.state, 'disconnected');
  assert.equal(fresh.since, null);
  assert.deepEqual(fresh.killSwitch, { enabled: false, armed: false, blocking: false });

  await s.service.invoke('connect', SERVER.id);
  const conn = (await s.service.invoke('app:init')).conn;
  assert.equal(conn.state, 'connected');
  assert.equal(conn.serverId, SERVER.id);
  assert.equal(conn.label, 'ci-upstream');
  assert.equal(conn.engine, 'xray');
  assert.equal(conn.tun, true);
  assert.equal(conn.cause, 'user');
  assert.equal(conn.reason, null);
  assert.equal(conn.attempt, 0);
  assert.equal(conn.retryInMs, null);
  assert.ok(typeof conn.since === 'number' && conn.since >= before && conn.since <= Date.now(), 'since is the epoch ms the tunnel came up');
  // the same thing, as the method the facade (luciApi) calls
  assert.deepEqual(s.service.connSnapshot(), conn);

  await s.service.invoke('disconnect');
  const off = (await s.service.invoke('app:init')).conn;
  assert.equal(off.state, 'disconnected');
  assert.equal(off.since, null);
  assert.equal(off.serverId, null);
  assert.equal(off.cause, 'user');
});

test('S1: a connect by hand that fails leaves the snapshot on error with the reason — never stuck on connecting', async (t) => {
  const s = H.start();
  t.after(() => s.service.shutdown());
  s.state.gatewayFails = true;
  await assert.rejects(s.service.invoke('connect', SERVER.id), /Gateway did not come up/);
  const conn = s.service.connSnapshot();
  assert.equal(conn.state, 'error');
  assert.match(conn.reason, /Gateway did not come up/);
  assert.equal(conn.since, null);
});

test('S1: the headless server sends the snapshot as the first event of every /events response', async (t) => {
  const dir = child.tempDir();
  const srv = await child.startServer(dir, ['--token', 'tok-0123456789abcdef']);
  t.after(() => child.stop(srv, dir));
  const [first] = await child.sseLines(srv.port, '/events?token=tok-0123456789abcdef', 1);
  const msg = JSON.parse(first);
  assert.equal(msg.channel, 'conn:snapshot');
  assert.equal(msg.payload.state, 'disconnected');
  assert.ok('since' in msg.payload && 'killSwitch' in msg.payload && 'serverId' in msg.payload, JSON.stringify(msg.payload));
  // …and again on the next connection (a browser reconnecting its EventSource)
  const [again] = await child.sseLines(srv.port, '/events?token=tok-0123456789abcdef', 1);
  assert.equal(JSON.parse(again).channel, 'conn:snapshot');
});

test('S1: the web bridge exposes the snapshot channel and the renderer applies it on load and on every reconnect', () => {
  const R = (...p) => fs.readFileSync(path.join(__dirname, '..', 'src', ...p), 'utf8').replace(/\r\n/g, '\n');
  assert.match(R('server', 'web-api.js'), /onConnSnapshot: \(cb\) => on\('conn:snapshot', cb\)/);
  const APP = R('renderer', 'app.js');
  assert.match(APP, /if \(data\.conn\) applyConnSnapshot\(data\.conn\);/, 'init() seeds the UI from app:init.conn');
  assert.match(APP, /if \(window\.api\.onConnSnapshot\) window\.api\.onConnSnapshot\(applyConnSnapshot\);/, 'every events (re)connect re-syncs');
  // main.js (the desktop) answers app:init with the same fact, so a renderer reload there shows the real state too
  const MAIN = R('main', 'main.js');
  assert.match(MAIN, /ipcMain\.handle\('app:init', \(\) => \(\{[\s\S]*?conn: connSnapshot\(\)\n/);
  assert.match(MAIN, /^function connSnapshot\(\) \{/m);
});

/* ----------------------------- S2: a stale page cannot tear down a live gateway ----------------------------- */

test('S2: Connect on the connection that is already up is a no-op ({ already: true }), a connect to another server still switches', async (t) => {
  const s = H.start();
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  const gw = s.state.inners.find(i => i.active);
  const starts = s.state.xray.starts.length;
  const stops = s.state.xray.stops;

  const r = await s.service.invoke('connect', SERVER.id);
  assert.deepEqual(r, { ok: true, already: true });
  assert.equal(s.state.xray.starts.length, starts, 'no core restart');
  assert.equal(s.state.xray.stops, stops, 'no core stop');
  assert.equal(s.state.inners.find(i => i.active), gw, 'the same gateway, untouched');
  assert.equal(gw.starts, 1);
  assert.ok(s.logs.some(l => /already connected/.test(l.line)), JSON.stringify(s.logs.map(l => l.line)));
  assert.equal(connectedCount(s), 1, 'no second "connected"');

  const sw = await s.service.invoke('connect', SERVER_B.id);
  assert.equal(sw.ok, true);
  assert.equal(sw.already, undefined);
  assert.equal((await s.service.invoke('app:init')).activeServerId, SERVER_B.id);
  assert.equal(s.service.connSnapshot().serverId, SERVER_B.id);
  assert.equal(s.service.connSnapshot().cause, 'switch');
});

test('S2: with the gateway down (a drop being rebuilt) a Connect is not a no-op', async (t) => {
  const s = H.start({}, { timing: Object.assign({}, H.fakes.deps(H.fakes.makeState()).timing, { routerBackoffMs: [2000, 2000, 2000], crashWindowMs: 60000 }) });
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  s.state.gatewayFails = true;
  s.state.inners.find(i => i.active).crash();
  await until(() => s.statuses.some(x => x.state === 'reconnecting'), 'the recovery');
  s.state.gatewayFails = false;
  const r = await s.service.invoke('connect', SERVER.id);
  assert.equal(r.already, undefined, 'a real connect: the gateway was down');
  assert.equal(s.service.connSnapshot().state, 'connected');
});

/* ----------------------------- S4 / B3: a drop reads "reconnecting", a boot retry "waiting" ----------------------------- */

const timing = (over) => ({ timing: Object.assign({}, H.fakes.deps(H.fakes.makeState()).timing, over) });

test('S4: the core dying under a live connection: the very next status is reconnecting (attempt 1, retryInMs 0), the stop event says rebuilding, and the backoff keeps saying reconnecting with the wait', async (t) => {
  const s = H.start({}, timing({ routerBackoffMs: [400, 400, 400], crashWindowMs: 60000 }));
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  const n = s.statuses.length;
  const stops = s.events.filter(([ch]) => ch === 'xray-status').length;
  s.state.xray.crash();
  await until(() => s.statuses.length > n, 'a status after the drop');
  assert.deepEqual([s.statuses[n].state, s.statuses[n].attempt, s.statuses[n].retryInMs, s.statuses[n].cause], ['reconnecting', 1, 0, 'recovery'], JSON.stringify(s.statuses[n]));
  const stop = s.events.filter(([ch]) => ch === 'xray-status')[stops][1];
  assert.equal(stop.state, 'stopped');
  assert.equal(stop.rebuilding, true, 'the window keeps "connected" until the recovery speaks');
  await until(() => connectedCount(s) === 2, 'the rebuild');
  assert.equal(s.service.connSnapshot().state, 'connected');

  // a second drop soon after: the backoff — said at once, with the wait, and the snapshot says so through it
  const m = s.statuses.length;
  s.state.xray.crash();
  await until(() => s.statuses.length > m, 'the backoff status');
  const waiting = s.statuses[m];
  assert.equal(waiting.state, 'reconnecting');
  assert.equal(waiting.attempt, 2);
  assert.equal(waiting.retryInMs, 400);
  const snap = s.service.connSnapshot();
  assert.equal(snap.state, 'reconnecting');
  assert.equal(snap.attempt, 2);
  assert.ok(snap.retryInMs > 0 && snap.retryInMs <= 400, 'until the next attempt: ' + snap.retryInMs);
  assert.equal(snap.reason, 'core-exited');
  assert.ok(!s.statuses.slice(n).some(x => x.state === 'disconnected' || x.state === 'error'), 'never a bare disconnected: ' + s.statuses.slice(n).map(x => x.state).join(','));
  await until(() => connectedCount(s) === 3, 'the rebuild after the wait', 5000);
  assert.equal(s.service.connSnapshot().retryInMs, null);
  // a final stop (the user's disconnect) is not a rebuild
  await s.service.invoke('disconnect');
  const last = s.events.filter(([ch]) => ch === 'xray-status').at(-1)[1];
  assert.equal(last.state, 'stopped');
  assert.equal(!!last.rebuilding, false);
});

test('S4: a rebuild that fails keeps saying reconnecting with the next wait — the snapshot never shows error while the recovery goes on', async (t) => {
  const s = H.start({}, timing({ routerBackoffMs: [300, 300, 300], crashWindowMs: 0 }));
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  s.state.gatewayFails = true;
  s.state.inners.find(i => i.active).crash();
  await until(() => s.statuses.filter(x => x.state === 'reconnecting' && x.retryInMs > 0).length >= 1, 'the wait after a failed attempt', 5000);
  const w = s.statuses.filter(x => x.state === 'reconnecting' && x.retryInMs > 0)[0];
  assert.equal(w.attempt, 2, 'the attempt about to start');
  assert.equal(w.retryInMs, 300);
  assert.equal(s.service.connSnapshot().state, 'reconnecting');
  assert.ok(!s.statuses.some(x => x.state === 'error' || x.state === 'disconnected'), s.statuses.map(x => x.state).join(','));
  s.state.gatewayFails = false;
  await until(() => connectedCount(s) === 2, 'back', 5000);
});

test('B3: the boot connect with the WAN not there reads waiting (attempt n) between and during its retries, never error — and comes up when it can', async (t) => {
  const s = H.start({ connectIntent: SERVER.id, settings: { autoConnect: true } }, timing({ bootDelayMs: 5, bootEveryMs: 60, bootSlowAfter: 1000 }));
  t.after(() => s.service.shutdown());
  s.state.gatewayFails = true;
  await until(() => s.statuses.some(x => x.state === 'waiting' && x.attempt >= 3), 'the third attempt', 10000);
  const waits = s.statuses.filter(x => x.state === 'waiting');
  // said after each failure (with the wait) and again as the next attempt starts (its "connecting" reads waiting too)
  assert.deepEqual([...new Set(waits.map(x => x.attempt))].slice(0, 3), [1, 2, 3], 'the attempt increments: ' + waits.map(x => x.attempt).join(','));
  assert.ok(waits.every(x => x.cause === 'boot' && x.serverId === SERVER.id));
  assert.ok(waits.some(x => typeof x.retryInMs === 'number' && x.retryInMs > 0), 'the wait before the next attempt is said');
  assert.ok(!s.statuses.some(x => x.state === 'error' || x.state === 'disconnected'), 'no error between attempts: ' + s.statuses.map(x => x.state).join(','));
  assert.ok(!s.statuses.slice(1).some(x => x.state === 'connecting'), 'a retry reads waiting, not connecting: ' + s.statuses.map(x => x.state).join(','));
  const snap = s.service.connSnapshot();
  assert.equal(snap.state, 'waiting');
  assert.ok(snap.attempt >= 3);
  assert.equal(snap.cause, 'boot');
  assert.ok(snap.reason && /Gateway did not come up/.test(snap.reason), snap.reason);
  s.state.gatewayFails = false;
  await until(() => connectedCount(s) === 1, 'up once the WAN is there', 10000);
  assert.equal(s.service.connSnapshot().state, 'connected');
  assert.equal(s.service.connSnapshot().cause, 'boot');
  // …and a later connect by hand is a plain "connecting" again
  await s.service.invoke('disconnect');
  await s.service.invoke('connect', SERVER.id);
  assert.equal(s.statuses.at(-2).state, 'connecting');
  assert.equal(s.statuses.at(-1).state, 'connected');
});

test('B1: the boot connect follows connectIntent — set with autoConnect on it connects, cleared it does not', async (t) => {
  const on = H.start({ connectIntent: SERVER.id, settings: { autoConnect: true } });
  t.after(() => on.service.shutdown());
  await until(() => connectedCount(on) === 1, 'the boot connect');
  assert.equal(on.service.connSnapshot().cause, 'boot');
  const off = H.start({ connectIntent: null, lastServerId: SERVER.id, settings: { autoConnect: true } });
  t.after(() => off.service.shutdown());
  await sleep(150);
  assert.equal(off.state.xray.starts.length, 0, 'no intent: nothing connects');
  const noAuto = H.start({ connectIntent: SERVER.id, settings: { autoConnect: false } });
  t.after(() => noAuto.service.shutdown());
  await sleep(150);
  assert.equal(noAuto.state.xray.starts.length, 0, 'the setting off: nothing connects');
});
