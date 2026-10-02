'use strict';
/**
 * A headless service on a router, with every seam faked (gatewayFakes.js):
 * the helpers serviceGateway.test.js grew, for the test files of the v1.16
 * router round (connSnapshot, luciApi, killSwitch). Not a test file itself.
 *
 * The caller's file sets `process.env.IRNETFREE_PLATFORM = 'openwrt'` BEFORE
 * requiring the service (the flavour is read at load).
 */
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createService } = require('../src/server/service');
const { makeProxyServer } = require('../src/main/parser');
const fakes = require('./gatewayFakes');

const SERVER = Object.assign(makeProxyServer({ type: 'socks', address: '192.0.2.10', port: 1080, name: 'ci-upstream' }), { id: 'srv-1' });
const SERVER_B = Object.assign(makeProxyServer({ type: 'socks', address: '192.0.2.11', port: 1080, name: 'second' }), { id: 'srv-2' });
// ports nothing listens on here: the stats poller dials apiPort, and the owner's own app holds the defaults
const PORTS = { socksPort: 47808, httpPort: 47809, apiPort: 47885 };
const BASE = Object.assign({ autoUpdateSubs: false, autoUpdateAssets: 'off', autoConnect: false, tunMode: true, lang: 'en', routingMode: 'global', blockAds: false }, PORTS);

const dirs = [];
function cleanupDirs() { for (const d of dirs) { try { fs.rmSync(d, { recursive: true, force: true }); } catch {} } }

/** A service on a fresh data dir with this store; events and syslog lines recorded. */
function start(store = {}, extraDeps = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-svc-'));
  dirs.push(dir);
  const content = Object.assign({ servers: [SERVER, SERVER_B], routerDefaultsApplied: true }, store);
  content.settings = Object.assign({}, BASE, store.settings || {});
  fs.writeFileSync(path.join(dir, 'store.json'), JSON.stringify(content));
  return startIn(dir, extraDeps);
}

/** A service on an existing data dir — "the next boot". `prime(state)` runs before it is created. */
function startIn(dir, extraDeps = {}, prime = null) {
  const state = fakes.makeState();
  if (prime) prime(state);
  const syslog = [];
  const service = createService({ dataDir: dir, deps: fakes.deps(state, Object.assign({ syslog: (level, text) => syslog.push([level, text]) }, extraDeps)) });
  const statuses = [];
  const logs = [];
  const events = [];
  service.onEvent((ch, p) => {
    events.push([ch, p]);
    if (ch === 'status') statuses.push(p);
    if (ch === 'log') logs.push(p);
  });
  return { service, state, statuses, logs, events, syslog, dir };
}

/** Poll until `pred()` is true (or fail with `what`); the predicate may be async. */
async function until(pred, what, ms = 4000) {
  const deadline = Date.now() + ms;
  while (!(await pred())) {
    if (Date.now() > deadline) throw new Error('timed out waiting for: ' + what);
    await new Promise((r) => setTimeout(r, 5));
  }
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const connectedCount = (s) => s.statuses.filter(x => x.state === 'connected').length;

module.exports = { SERVER, SERVER_B, PORTS, BASE, start, startIn, until, sleep, connectedCount, cleanupDirs, fakes };
