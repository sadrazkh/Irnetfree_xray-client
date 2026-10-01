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
