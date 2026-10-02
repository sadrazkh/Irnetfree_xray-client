'use strict';
/**
 * The LuCI facade (v1.16 A9): POST /luci/<method> on the headless server —
 * loopback peers only, {token, arg} in the body, the token compared in
 * constant time — and the methods LuCI's pages call (spec §3.4). The rpcd
 * plugin (feat/router-luci) and the pages code against exactly this.
 *
 * Two layers: the methods over a service with the gateway fakes (in process),
 * and the route over the real server.js as a child (serverChild.js).
 */
process.env.IRNETFREE_PLATFORM = 'openwrt';
const test = require('node:test');
const assert = require('node:assert/strict');
const H = require('./serviceHarness');
const child = require('./serverChild');
const { createLuciApi, isLoopbackPeer } = require('../src/server/luciApi');

process.setMaxListeners(60);
test.after(() => H.cleanupDirs());
const { SERVER, SERVER_B, until } = H;

const METHODS = ['status', 'configs', 'connect', 'select', 'disconnect', 'reconnect', 'test', 'subs_update', 'settings_get', 'settings_set', 'devices', 'log', 'diagnostics', 'remote_get', 'remote_set', 'remote_status', 'cloudflared_install'];

test('the facade answers every method of the contract and refuses an unknown one with 404', async (t) => {
  const s = H.start();
  t.after(() => s.service.shutdown());
  const api = createLuciApi({ service: s.service, remoteApi: null });
  for (const m of METHODS) assert.ok(typeof api.handle === 'function', m);
  await assert.rejects(api.handle('nope', {}), (e) => e.code === 404);
  await assert.rejects(api.handle('', {}), (e) => e.code === 404);
  await assert.rejects(api.handle('__proto__', {}), (e) => e.code === 404);
});

test('status: the snapshot plus version, traffic, memAvailableKb and remote (null without the remote api)', async (t) => {
  const s = H.start();
  t.after(() => s.service.shutdown());
  const api = createLuciApi({ service: s.service });
  const st = await api.handle('status', {});
  assert.equal(st.state, 'disconnected');
  assert.equal(st.version, require('../package.json').version);
  assert.deepEqual(st.traffic, { up: 0, down: 0, upRate: 0, downRate: 0 });
  assert.ok('memAvailableKb' in st);
  assert.ok(!('remote' in st), 'no remote api: no remote key');
  assert.deepEqual(st.killSwitch, { enabled: false, armed: false, blocking: false });
  // a remote api whose status throws: {error}, never a failed status
  const broken = createLuciApi({ service: s.service, remoteApi: { remote_status: async () => { throw new Error('agent not started'); } } });
  assert.deepEqual((await broken.handle('status', {})).remote, { error: 'agent not started' });
});

test('connect {id} is accepted at once and the status follows; select, disconnect, reconnect and subs_update answer their shapes', async (t) => {
  const s = H.start();
  t.after(() => s.service.shutdown());
  const api = createLuciApi({ service: s.service });
  assert.deepEqual(await api.handle('connect', { id: SERVER.id }), { accepted: true });
  await until(async () => (await api.handle('status')).serverId === SERVER.id && (await api.handle('status')).state === 'connected', 'connected through the facade');
  assert.equal((await s.service.invoke('app:init')).selectedServerId, SERVER.id, 'connect selects too');
  assert.deepEqual(await api.handle('select', { id: SERVER_B.id }), { ok: true });
  assert.equal((await s.service.invoke('app:init')).selectedServerId, SERVER_B.id);
  assert.deepEqual(await api.handle('reconnect', {}), { accepted: true });
  await until(() => s.statuses.filter(x => x.state === 'connected').length >= 2, 'the rebuild');
  assert.deepEqual(await api.handle('subs_update', {}), { accepted: true });
  assert.deepEqual(await api.handle('disconnect', {}), { accepted: true });
  await until(async () => (await api.handle('status')).state === 'disconnected', 'disconnected through the facade');
  await assert.rejects(api.handle('connect', {}), (e) => e.code === 400 && /id/.test(e.message));
});

test('settings_set accepts only the four router keys, validated, applied live; settings_get answers them', async (t) => {
  const s = H.start();
  t.after(() => s.service.shutdown());
  const api = createLuciApi({ service: s.service });
  const r = await api.handle('settings_set', { killSwitch: true, other: 1, lanBypassMacs: ['AA:BB:CC:DD:EE:01', 'junk'], lanBlockQuic: '0', autoConnect: 'true' });
  assert.equal(r.ok, true);
  assert.deepEqual(r.settings, { autoConnect: true, killSwitch: true, lanBlockQuic: false, lanBypassMacs: ['aa:bb:cc:dd:ee:01'] });
  const got = await api.handle('settings_get', {});
  assert.deepEqual(got, { autoConnect: true, killSwitch: true, lanBlockQuic: false, lanBypassMacs: ['aa:bb:cc:dd:ee:01'] });
  assert.equal((await s.service.invoke('settings:get')).other, undefined, 'an unknown key never reaches the store');
  // a MAC list as text, as a form may send it
  const r2 = await api.handle('settings_set', { lanBypassMacs: 'aa:bb:cc:dd:ee:02, aa:bb:cc:dd:ee:03' });
  assert.deepEqual(r2.settings.lanBypassMacs, ['aa:bb:cc:dd:ee:02', 'aa:bb:cc:dd:ee:03']);
  await assert.rejects(api.handle('settings_set', 'not an object'), (e) => e.code === 400);
});

test('configs groups subscriptions by name, manual servers under manual, chains / pools / routing when they exist', async (t) => {
  const subbed = Object.assign({}, SERVER, { id: 'srv-sub', name: 'from the sub', subId: 'sub1' });
  const s = H.start({
    servers: [SERVER, SERVER_B, subbed],
    subscriptions: [{ id: 'sub1', name: 'My subscription', url: 'https://sub.invalid/x' }],
    chains: [{ id: 'ch1', name: 'Chain one', members: [SERVER.id, SERVER_B.id] }, { id: 'ch-short', name: 'short', members: [SERVER.id] }],
    pool: [{ id: 'p1', name: 'Pool entry', target: SERVER.id, socksPort: 60001, enabled: true }],
    selectedServerId: SERVER_B.id,
    settings: { advancedRouting: true, routeDefault: SERVER.id, routeRules: [] }
  });
  t.after(() => s.service.shutdown());
  const api = createLuciApi({ service: s.service });
  const c = await api.handle('configs', {});
  assert.equal(c.selectedId, SERVER_B.id);
  assert.equal(c.activeId, null);
  assert.deepEqual(c.groups.map(g => [g.id, g.kind, g.name]), [
    ['sub:sub1', 'subscription', 'My subscription'], ['manual', 'manual', 'Manual'], ['chains', 'chains', 'Chains'], ['pools', 'pools', 'Proxy pool'], ['routing', 'routing', 'Advanced routing']
  ]);
  assert.deepEqual(c.groups[0].items, [{ id: 'srv-sub', name: 'from the sub', proto: 'socks' }]);
  assert.deepEqual(c.groups[1].items.map(i => i.id), [SERVER.id, SERVER_B.id]);
  assert.deepEqual(c.groups[2].items, [{ id: 'ch1', name: 'Chain one', proto: 'chain' }], 'a chain with one member is not connectable');
  assert.deepEqual(c.groups[3].items, [{ id: '__pool__', name: 'Proxy pool (1)', proto: 'pool' }]);
  assert.deepEqual(c.groups[4].items, [{ id: '__advanced__', name: 'Advanced routing', proto: 'advanced' }]);
  await s.service.invoke('connect', SERVER.id);
  assert.equal((await api.handle('configs', {})).activeId, SERVER.id);
  // nothing but manual servers: one group
  const plain = H.start();
  t.after(() => plain.service.shutdown());
  assert.deepEqual((await createLuciApi({ service: plain.service }).handle('configs', {})).groups.map(g => g.kind), ['manual']);
});

test('devices, log and diagnostics answer their shapes; test without a connection says so', async (t) => {
  const s = H.start();
  t.after(() => s.service.shutdown());
  const api = createLuciApi({ service: s.service });
  assert.deepEqual(await api.handle('devices', {}), []);
  await s.service.invoke('settings:set', { lanBypassMacs: ['aa:bb:cc:dd:ee:09'] });
  assert.deepEqual(await api.handle('devices', {}), [{ mac: 'aa:bb:cc:dd:ee:09', ip: '', name: '', online: false, bypass: true }], 'an excluded device not on the LAN still shows');
  for (let i = 1; i <= 5; i++) s.service.log('ring line ' + i, 'info');
  const log = await api.handle('log', { lines: 2 });
  assert.equal(log.lines.length, 2);
  assert.match(log.lines[1], /\[info\] ring line 5$/);
  const mine = (lines) => lines.filter(l => /ring line \d$/.test(l)).length;
  const all = (await api.handle('log', {})).lines;
  assert.equal(mine(all), 5, 'the default is the last 300 — all five here');
  assert.ok(all.length < 300);
  assert.deepEqual((await api.handle('log', { lines: 9999 })).lines, all, 'capped at the ring');
  const d = await api.handle('diagnostics', {});
  assert.equal(typeof d.text, 'string');
  assert.match(d.text, /status: \{/);
  assert.deepEqual(await api.handle('test', {}), { ok: false, error: 'not connected' });
});

test('remote_* and cloudflared_install are the remote api when it is mounted, and say so when it is not', async (t) => {
  const s = H.start();
  t.after(() => s.service.shutdown());
  const none = createLuciApi({ service: s.service, remoteApi: null });
  for (const m of ['remote_get', 'remote_set', 'remote_status', 'cloudflared_install']) {
    assert.deepEqual(await none.handle(m, {}), { error: 'remote not available' }, m);
  }
  const calls = [];
  // feat/remote's shapes: get/set/install synchronous, status async, set throws an Error on invalid input
  const remoteApi = {
    remote_get: () => ({ relay: { enabled: false, relayUrl: '', name: '', tokenSet: false }, cloudflared: { installed: false, enabled: false, tokenSet: false } }),
    remote_set: (arg) => { if (arg && arg.relay && arg.relay.relayUrl === 'ftp://x') throw new Error('relayUrl must be https://'); calls.push(arg); return { ok: true }; },
    remote_status: async () => ({ relay: { state: 'off' }, cloudflared: { installed: false } }),
    cloudflared_install: () => ({ accepted: true })
  };
  const api = createLuciApi({ service: s.service, remoteApi });
  assert.equal((await api.handle('remote_get', {})).relay.tokenSet, false);
  assert.deepEqual(await api.handle('remote_set', { relay: { enabled: true } }), { ok: true });
  assert.deepEqual(calls, [{ relay: { enabled: true } }]);
  assert.deepEqual(await api.handle('remote_set', { relay: { relayUrl: 'ftp://x' } }), { error: 'relayUrl must be https://' }, 'a refused setting is the reply, not a 500');
  assert.deepEqual((await api.handle('status', {})).remote, { relay: { state: 'off' }, cloudflared: { installed: false } }, 'status carries the awaited remote_status');
  // the api may also be handed in as a getter (mounted after the facade was built)
  let late = null;
  const lazy = createLuciApi({ service: s.service, remoteApi: () => late });
  assert.deepEqual(await lazy.handle('remote_get', {}), { error: 'remote not available' });
  late = remoteApi;
  assert.deepEqual(await lazy.handle('cloudflared_install', {}), { accepted: true });
});

test('connect on the config that is already up answers {accepted, already: true} — the page can say so instead of nothing (L4)', async (t) => {
  const s = H.start();
  t.after(() => s.service.shutdown());
  const api = createLuciApi({ service: s.service });
  await s.service.actions.connect(SERVER.id);   // the whole connect, gateway up
  assert.equal(s.service.connSnapshot().state, 'connected');
  const starts = s.state.xray.starts.length;
  assert.deepEqual(await api.handle('connect', { id: SERVER.id }), { accepted: true, already: true });
  assert.equal(s.state.xray.starts.length, starts, 'nothing rebuilt');
  // another config is a real switch: accepted, and no "already"
  assert.deepEqual(await api.handle('connect', { id: SERVER_B.id }), { accepted: true });
  await until(async () => (await api.handle('status')).serverId === SERVER_B.id && (await api.handle('status')).state === 'connected', 'the switch');
  // a service whose connect never settles still answers at once
  const slow = createLuciApi({ service: { actions: { connect: () => new Promise(() => {}) }, log() {} } });
  assert.deepEqual(await slow.handle('connect', { id: 'x' }), { accepted: true });
});

test('a refused remote setting is logged at warn — "LuCI: <method> refused: <msg>" — so syslog has it, not only the page', async (t) => {
  const s = H.start();
  t.after(() => s.service.shutdown());
  const msg = 'enabling needs the relay URL and the device token';
  const api = createLuciApi({ service: s.service, remoteApi: { remote_set: () => { throw new Error(msg); } } });
  assert.deepEqual(await api.handle('remote_set', { relay: { enabled: true } }), { error: msg });
  assert.ok(s.logs.some((l) => l.level === 'warn' && l.line === 'LuCI: remote_set refused: ' + msg), JSON.stringify(s.logs));
  assert.ok(s.syslog.some(([, text]) => text.includes('LuCI: remote_set refused: ' + msg)), 'warn reaches syslog: ' + JSON.stringify(s.syslog));
});

test('isLoopbackPeer: 127.0.0.1, ::1 and the v4-mapped loopback are local; a LAN address is not', () => {
  for (const a of ['127.0.0.1', '::1', '::ffff:127.0.0.1', '127.0.0.53']) assert.equal(isLoopbackPeer(a), true, a);
  for (const a of ['192.168.1.10', '::ffff:192.168.1.10', '10.0.0.1', '', null, undefined, 'fe80::1']) assert.equal(isLoopbackPeer(a), false, String(a));
});

/* ----------------------------- the route, over the real server ----------------------------- */

const TOKEN = 'a1b2c3d4e5f60718293a4b5c6d7e8f90';

test('POST /luci/<method> from 127.0.0.1 with the token answers; wrong token 401, missing body 400, GET 405, unknown 404', async (t) => {
  const dir = child.tempDir();
  const srv = await child.startServer(dir, ['--token', TOKEN]);
  t.after(() => child.stop(srv, dir));
  const post = (p, body, headers = {}) => child.request(srv.port, { method: 'POST', path: p, body, headers: Object.assign({ 'Content-Type': 'text/plain' }, headers) });

  const ok = await post('/luci/status', JSON.stringify({ token: TOKEN, arg: {} }));
  assert.equal(ok.status, 200, ok.body);
  assert.equal(ok.json.state, 'disconnected');
  assert.equal(typeof ok.json.version, 'string');

  const wrong = await post('/luci/status', JSON.stringify({ token: TOKEN.replace(/0/g, '1'), arg: {} }));
  assert.equal(wrong.status, 401);
  const shorter = await post('/luci/status', JSON.stringify({ token: 'nope', arg: {} }));
  assert.equal(shorter.status, 401);
  const noToken = await post('/luci/status', JSON.stringify({ arg: {} }));
  assert.equal(noToken.status, 401);
  // the token in the query string or the header is the web UI's way, not this route's
  assert.equal((await post('/luci/status?token=' + TOKEN, JSON.stringify({ arg: {} }))).status, 401);

  assert.equal((await post('/luci/status', '')).status, 400);
  assert.equal((await post('/luci/status', '{not json')).status, 400);
  assert.equal((await post('/luci/status', '"a string"')).status, 400);
  assert.equal((await child.request(srv.port, { method: 'GET', path: '/luci/status?token=' + TOKEN })).status, 405);
  const nope = await post('/luci/nope', JSON.stringify({ token: TOKEN, arg: {} }));
  assert.equal(nope.status, 404);
  assert.equal(nope.json.error, 'unknown method');
  // a method's own refusal is a 200 {error}: uclient-fetch (the rpcd plugin) drops the body of every non-2xx reply
  const bad = await post('/luci/connect', JSON.stringify({ token: TOKEN, arg: {} }));
  assert.equal(bad.status, 200);
  assert.match(bad.json.error, /id/);
  const badSetting = await post('/luci/settings_set', JSON.stringify({ token: TOKEN, arg: { killSwitch: 'maybe' } }));
  assert.equal(badSetting.status, 200);
  assert.match(badSetting.json.error, /killSwitch must be a boolean/);
  const notObject = await post('/luci/settings_set', JSON.stringify({ token: TOKEN, arg: 'x' }));
  assert.equal(notObject.status, 200);
  assert.match(notObject.json.error, /object/);
  // the methods that take no argument accept a missing one
  const log = await post('/luci/log', JSON.stringify({ token: TOKEN }));
  assert.equal(log.status, 200);
  assert.ok(Array.isArray(log.json.lines));
  assert.equal(srv.child.exitCode, null, 'the process is still alive');
});

test('server.js: the route checks the peer before anything else and compares the token in constant time', () => {
  const src = require('node:fs').readFileSync(child.SERVER, 'utf8').replace(/\r\n/g, '\n');
  assert.match(src, /isLoopbackPeer\(req\.socket && req\.socket\.remoteAddress\)/);
  assert.match(src, /crypto\.timingSafeEqual/);
  assert.match(src, /createLuciApi\(\{ service, remoteApi/);
});

test('server.js mounts the remote api its start hook builds: remote_get answers the relay settings and status carries remote', async (t) => {
  // feat/remote's start() runs inside listen's callback and returns the api; the
  // facade reaches it through server.js's `remoteApi` getter — a start whose
  // result is dropped leaves every Remote access call "remote not available"
  const dir = child.tempDir();
  const srv = await child.startServer(dir, ['--token', TOKEN]);
  t.after(() => child.stop(srv, dir));
  const post = (p, body) => child.request(srv.port, { method: 'POST', path: p, body, headers: { 'Content-Type': 'text/plain' } });
  const rg = await post('/luci/remote_get', JSON.stringify({ token: TOKEN, arg: {} }));
  assert.equal(rg.status, 200, rg.body);
  assert.equal(rg.json.error, undefined, rg.body);
  assert.equal(typeof rg.json.relay, 'object', rg.body);
  assert.equal(rg.json.relay.tokenSet, false);
  const st = await post('/luci/status', JSON.stringify({ token: TOKEN, arg: {} }));
  assert.equal(st.status, 200, st.body);
  assert.ok(st.json.remote && typeof st.json.remote === 'object', st.body);
});
