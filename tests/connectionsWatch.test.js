'use strict';
/**
 * The tunnel's live connections by program (src/main/connectionsWatch.js):
 * grouped by app, with their bytes, rates, age and outbound; why there are
 * none to show; a connection closed; reads only when asked. Against a fake of
 * sing-box's clash API whose answers are copied from a real sing-box 1.14.4
 * (a request from node through a mixed inbound with route.find_process:
 * processPath "C:\Program Files\nodejs\node.exe", destinationPort a string,
 * start RFC 3339 with nanoseconds and the zone, DELETE → 204 for any id, a
 * wrong secret → 401) — and once against a loopback server, for the HTTP
 * itself (the header, the method, the path). Then the wiring: main.js and
 * service.js (read as text — Electron does not load here, the router's
 * service is run), and the two bridges.
 */
process.env.IRNETFREE_PLATFORM = 'openwrt';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const { createConnectionsWatch, fetchSnapshot, appOf, destOf, MIN_READ_MS, MAX_PER_APP } = require('../src/main/connectionsWatch');

const R = (...p) => fs.readFileSync(path.join(__dirname, '..', ...p), 'utf8').replace(/\r\n/g, '\n');
const SECRET = 'a'.repeat(32);
const T0 = Date.parse('2026-10-28T13:00:00Z');

/** A connection as sing-box 1.14.4 writes it. */
function conn(id, o = {}) {
  return {
    chains: o.chains || ['socks-out'], download: o.down || 0, upload: o.up || 0, id,
    metadata: {
      destinationIP: o.ip || '142.250.74.110', destinationPort: String(o.port || 443), dnsMode: 'normal', host: o.host == null ? 'www.google.com' : o.host,
      network: o.network || 'tcp', processPath: o.path == null ? 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe' : o.path,
      sourceIP: o.source || '172.19.0.1', sourcePort: '61046', type: 'tun/tun-in'
    },
    rule: o.rule || 'final', rulePayload: '',
    // sing-box's own clock, in its zone: a start 2 s before T0 written as +03:30
    start: new Date((o.start == null ? T0 - 2000 : o.start) + 3.5 * 3600000).toISOString().replace('Z', '1234+03:30')
  };
}

/** The fake API: what /connections answers now, what was asked; http.request's shape. */
function fakeApi() {
  const st = { conns: [], up: 0, down: 0, status: 200, asked: [], fail: null };
  const request = (o, cb) => {
    st.asked.push({ method: o.method, host: o.host, port: o.port, path: o.path, auth: o.headers.Authorization });
    const handlers = {};
    const req = { on(ev, fn) { if (ev === 'error') req.err = fn; return req; }, destroy(e) { if (req.err) req.err(e); }, end() {
      setImmediate(() => {
        if (st.fail) return req.err(new Error(st.fail));
        const del = o.method === 'DELETE';
        const res = { statusCode: del ? 204 : st.status, setEncoding() {}, on(ev, fn) { handlers[ev] = fn; } };
        cb(res);
        if (!del && st.status === 200) handlers.data && handlers.data(JSON.stringify({ connections: st.conns, downloadTotal: st.down, uploadTotal: st.up, memory: 4423680 }));
        else if (!del) handlers.data && handlers.data('Unauthorized');
        handlers.end && handlers.end();
      });
    } };
    return req;
  };
  return { st, request };
}

/** A watch over the fake: connected, a sing-box TUN with its API — each can be changed. */
function harness(over = {}) {
  const api = fakeApi();
  const s = { connected: true, tun: { active: true, backendId: 'sing-box', watch: { port: 24860, secret: SECRET } }, t: T0 };
  const w = createConnectionsWatch(Object.assign({ connected: () => s.connected, tun: () => s.tun, request: api.request, now: () => s.t }, over));
  return { api, s, w };
}

/* ------------------------------ the pieces ------------------------------ */

test('appOf: the program\'s file name from sing-box\'s processPath — Windows and Unix paths, the owner sing-box appends, a bare user id, nothing', () => {
  assert.equal(appOf('C:\\Program Files\\nodejs\\node.exe'), 'node.exe', 'what a real 1.14.4 said');
  assert.equal(appOf('C:\\Program Files (x86)\\Steam\\steam.exe'), 'steam.exe', 'the (x86) is part of the path');
  assert.equal(appOf('/usr/bin/curl (sadra)'), 'curl', 'the owner after a path is not part of its name');
  assert.equal(appOf('/opt/app/run (1000)'), 'run');
  assert.equal(appOf('/Applications/Telegram.app/Contents/MacOS/Telegram'), 'Telegram');
  assert.equal(appOf('1000'), '', 'a user id alone is no program');
  assert.equal(appOf(''), '');
  assert.equal(appOf(null), '');
  assert.equal(appOf('chrome.exe'), 'chrome.exe');
});

test('destOf: the name asked for, else the address — with its port, an IPv6 address in brackets', () => {
  assert.equal(destOf({ host: 'www.google.com', destinationIP: '142.250.74.110', destinationPort: '443' }), 'www.google.com:443');
  assert.equal(destOf({ host: '', destinationIP: '127.0.0.1', destinationPort: '24801' }), '127.0.0.1:24801', 'a real 1.14.4: host "" for a bare address');
  assert.equal(destOf({ host: '', destinationIP: '2001:db8::1', destinationPort: '53' }), '[2001:db8::1]:53');
  assert.equal(destOf({ host: 'example.com', destinationIP: '', destinationPort: '' }), 'example.com');
});

/* ------------------------------ a read ------------------------------ */

test('a read: the connections grouped by program, the busiest first and the unnamed last, newest first inside, each with where, how, how much, how long, which way', async () => {
  const { api, w } = harness();
  api.st.conns = [
    conn('c1', { up: 900, down: 40000, start: T0 - 65000 }),
    conn('c2', { host: '', ip: '2001:db8::5', port: 8443, network: 'udp', up: 100, down: 200, start: T0 - 1000, chains: ['direct'], rule: 'process_name=[chrome.exe] => route(direct)' }),
    conn('t1', { path: 'C:\\Users\\sadra\\AppData\\Roaming\\Telegram Desktop\\Telegram.exe', host: 'web.telegram.org', up: 5000000, down: 9000000 }),
    conn('u1', { path: '', host: '', ip: '8.8.8.8', port: 53, network: 'udp', source: '192.168.137.45', up: 60, down: 120 })
  ];
  api.st.up = 6000000; api.st.down = 9500000;
  const r = await w.read();
  assert.equal(r.available, true);
  assert.equal(r.processes, true);
  assert.equal(r.at, T0);
  assert.deepEqual(r.apps.map((g) => [g.app, g.count]), [['Telegram.exe', 1], ['chrome.exe', 2], ['', 1]], 'by bytes; the unnamed last whatever it carried');
  const chrome = r.apps[1];
  assert.deepEqual(chrome.paths, ['C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe']);
  assert.deepEqual([chrome.upload, chrome.download, chrome.up, chrome.down, chrome.more], [1000, 40200, 0, 0, 0], 'no rates on the first read');
  assert.deepEqual(chrome.connections.map((c) => c.id), ['c2', 'c1'], 'newest first');
  assert.deepEqual(chrome.connections[1], {
    id: 'c1', dest: 'www.google.com:443', ip: '142.250.74.110', network: 'tcp', source: '172.19.0.1',
    upload: 900, download: 40000, up: 0, down: 0, start: T0 - 65000, age: 65000,
    outbound: 'socks-out', chain: ['socks-out'], rule: 'final'
  });
  assert.deepEqual([chrome.connections[0].dest, chrome.connections[0].network, chrome.connections[0].outbound, chrome.connections[0].rule],
    ['[2001:db8::5]:8443', 'udp', 'direct', 'process_name=[chrome.exe] => route(direct)']);
  assert.equal(r.apps[2].connections[0].source, '192.168.137.45', 'a device on the hotspot: no program here, its address kept');
  assert.deepEqual(r.apps[2].paths, []);
  assert.deepEqual(r.totals, { count: 4, upload: 5001060, download: 9040320, up: 0, down: 0 });
  assert.deepEqual(api.st.asked, [{ method: 'GET', host: '127.0.0.1', port: 24860, path: '/connections', auth: 'Bearer ' + SECRET }], 'loopback, the secret in the header');
});

test('the rates: the bytes between two reads over the time between them — a connection seen before, one new since, and the totals sing-box keeps (the ended ones count there)', async () => {
  const { api, s, w } = harness();
  api.st.conns = [conn('c1', { up: 1000, down: 10000 })];
  api.st.up = 1000; api.st.down = 10000;
  await w.read();
  s.t = T0 + 2000;
  api.st.conns = [conn('c1', { up: 3000, down: 50000 }), conn('c3', { up: 400, down: 800, start: T0 + 500 })];
  api.st.up = 9000; api.st.down = 90000;   // c2 came and went in between: only the totals saw it
  const r = await w.read();
  const g = r.apps[0];
  const c1 = g.connections.find((c) => c.id === 'c1');
  const c3 = g.connections.find((c) => c.id === 'c3');
  assert.deepEqual([c1.up, c1.down], [1000, 20000], '(3000 − 1000) / 2 s, (50000 − 10000) / 2 s');
  assert.deepEqual([c3.up, c3.down], [200, 400], 'new since the read before: all its bytes over the interval');
  assert.deepEqual([g.up, g.down], [1200, 20400]);
  assert.deepEqual([r.totals.up, r.totals.down], [4000, 40000], 'sing-box\'s running totals');
  // a connection that was there before the first read and is only now seen gets no made-up rate
  s.t = T0 + 4000;
  api.st.conns = [conn('c1', { up: 3000, down: 50000 }), conn('old', { up: 99999, down: 99999, start: T0 - 60000 })];
  const r2 = await w.read();
  const old = r2.apps[0].connections.find((c) => c.id === 'old');
  assert.deepEqual([old.up, old.down], [0, 0]);
  assert.deepEqual([r2.apps[0].connections.find((c) => c.id === 'c1').up], [0], 'nothing moved');
});

test('reads closer together than MIN_READ_MS share one answer; two at once make one call', async () => {
  const { api, s, w } = harness();
  api.st.conns = [conn('c1', { up: 1, down: 2 })];
  const [a, b] = await Promise.all([w.read(), w.read()]);
  assert.equal(a, b);
  assert.equal(api.st.asked.length, 1);
  s.t = T0 + MIN_READ_MS - 1;
  assert.equal(await w.read(), a, 'within the window: the last answer');
  assert.equal(api.st.asked.length, 1);
  s.t = T0 + MIN_READ_MS;
  await w.read();
  assert.equal(api.st.asked.length, 2);
});

test('a program with very many connections: the newest MAX_PER_APP listed, the rest counted', async () => {
  const { api, w } = harness();
  api.st.conns = Array.from({ length: MAX_PER_APP + 7 }, (_, i) => conn('q' + i, { path: '/usr/bin/qbittorrent', start: T0 - 100000 + i, up: 1, down: 1 }));
  const r = await w.read();
  const g = r.apps[0];
  assert.equal(g.app, 'qbittorrent');
  assert.equal(g.count, MAX_PER_APP + 7);
  assert.equal(g.connections.length, MAX_PER_APP);
  assert.equal(g.more, 7);
  assert.equal(g.connections[0].id, 'q' + (MAX_PER_APP + 6), 'the newest kept');
  assert.equal(g.upload, MAX_PER_APP + 7, 'its bytes are all of them');
});

test('no process lookup (a sing-box that names none): every connection under the unnamed app, and the answer says so', async () => {
  const { api, w } = harness();
  api.st.conns = [conn('c1', { path: '' }), conn('c2', { path: '' })];
  const r = await w.read();
  assert.equal(r.processes, false);
  assert.deepEqual(r.apps.map((g) => [g.app, g.count]), [['', 2]]);
});

/* ------------------------------ nothing to show ------------------------------ */

test('why there is nothing to show — without asking the API: not connected, no TUN, tun2socks, the native macOS service, a router', async () => {
  const { api, s, w } = harness();
  s.connected = false;
  assert.deepEqual(await w.read(), { available: false, reason: 'off' });
  s.connected = true;
  s.tun = null;
  assert.deepEqual(await w.read(), { available: false, reason: 'noTun' });
  s.tun = { active: true, backendId: 'tun2socks' };
  assert.deepEqual(await w.read(), { available: false, reason: 'backend', backend: 'tun2socks' });
  s.tun = { active: true, backendId: 'sing-box', native: true };
  assert.deepEqual(await w.read(), { available: false, reason: 'backend', backend: 'native-macos' });
  assert.equal(api.st.asked.length, 0, 'none of these asks anything');
  const router = createConnectionsWatch({ router: true, connected: () => true, tun: () => ({ watch: { port: 1, secret: SECRET } }), request: api.request });
  assert.deepEqual(await router.read(), { available: false, reason: 'router' });
  assert.deepEqual(await router.close('abc'), { ok: false, error: 'router' });
  assert.equal(api.st.asked.length, 0);
});

test('an API that refuses or does not answer is said; the next read tries again, and a new tunnel starts its rates afresh', async () => {
  const { api, s, w } = harness();
  api.st.status = 401;
  assert.deepEqual(await w.read(), { available: false, reason: 'error', error: 'HTTP 401' });
  api.st.status = 200;
  api.st.fail = 'connect ECONNREFUSED 127.0.0.1:24860';
  s.t += 1000;
  assert.deepEqual(await w.read(), { available: false, reason: 'error', error: 'connect ECONNREFUSED 127.0.0.1:24860' });
  api.st.fail = null;
  api.st.conns = [conn('c1', { up: 1000, down: 1000 })];
  s.t += 1000;
  assert.equal((await w.read()).available, true);
  // a reconnect: a new sing-box, a new secret — the old ids and totals mean nothing to it
  s.tun = { active: true, backendId: 'sing-box', watch: { port: 24861, secret: 'b'.repeat(32) } };
  s.t += 2000;
  api.st.conns = [conn('c1', { up: 5000, down: 5000 })];
  const r = await w.read();
  assert.deepEqual([r.apps[0].up, r.totals.up], [0, 0], 'no rate across two tunnels');
  assert.equal(api.st.asked.at(-1).port, 24861);
  assert.equal(api.st.asked.at(-1).auth, 'Bearer ' + 'b'.repeat(32));
});

/* ------------------------------ closing one ------------------------------ */

test('close: DELETE /connections/<id> with the secret; the next read is fresh; a malformed id never leaves; nothing to close while there is no API', async () => {
  const { api, s, w } = harness();
  api.st.conns = [conn('ca3e1fae-1a27-427c-9680-bb0b0e2808d6')];
  await w.read();
  assert.deepEqual(await w.close('ca3e1fae-1a27-427c-9680-bb0b0e2808d6'), { ok: true });
  assert.deepEqual(api.st.asked.at(-1), { method: 'DELETE', host: '127.0.0.1', port: 24860, path: '/connections/ca3e1fae-1a27-427c-9680-bb0b0e2808d6', auth: 'Bearer ' + SECRET });
  api.st.conns = [];
  const after = await w.read();
  assert.equal(api.st.asked.at(-1).method, 'GET', 'within MIN_READ_MS, but a close spoils the last answer');
  assert.deepEqual(after.apps, []);
  const n = api.st.asked.length;
  for (const bad of ['../configs', 'a b', '', 'x'.repeat(65), 42, null]) assert.deepEqual(await w.close(bad), { ok: false, error: 'bad id' }, String(bad));
  assert.equal(api.st.asked.length, n, 'none of them was sent');
  api.st.fail = 'socket hang up';
  assert.deepEqual(await w.close('abc'), { ok: false, error: 'socket hang up' });
  s.tun = null;
  assert.deepEqual(await w.close('abc'), { ok: false, error: 'noTun' });
});

/* ------------------------------ the HTTP itself ------------------------------ */

test('fetchSnapshot and a close against a loopback server shaped like sing-box\'s API: the Bearer header, GET and DELETE, 401 without the secret', async (t) => {
  const seen = [];
  const srv = http.createServer((req, res) => {
    seen.push([req.method, req.url, req.headers.authorization]);
    if (req.headers.authorization !== 'Bearer ' + SECRET) { res.writeHead(401); return res.end('Unauthorized'); }
    if (req.method === 'DELETE') { res.writeHead(204); return res.end(); }
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ connections: [conn('c1', { path: 'C:\\Program Files\\nodejs\\node.exe', host: '', ip: '127.0.0.1', port: 24801, up: 77, down: 28885, chains: ['direct'] })], downloadTotal: 28885, memory: 4423680, uploadTotal: 77 }));
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  t.after(() => srv.close());
  const watch = { port: srv.address().port, secret: SECRET };
  const snap = await fetchSnapshot(watch);
  assert.deepEqual([snap.uploadTotal, snap.downloadTotal, snap.connections.length], [77, 28885, 1]);
  const w = createConnectionsWatch({ connected: () => true, tun: () => ({ active: true, backendId: 'sing-box', watch }) });
  const r = await w.read();
  assert.deepEqual([r.apps[0].app, r.apps[0].connections[0].dest, r.apps[0].connections[0].outbound], ['node.exe', '127.0.0.1:24801', 'direct']);
  assert.deepEqual(await w.close('c1'), { ok: true });
  await assert.rejects(fetchSnapshot({ port: watch.port, secret: 'b'.repeat(32) }), /HTTP 401/);
  assert.deepEqual(seen.map((x) => x.slice(0, 2)), [['GET', '/connections'], ['GET', '/connections'], ['DELETE', '/connections/c1'], ['GET', '/connections']]);
});

/* ------------------------------ the wiring ------------------------------ */

test('main.js: every sing-box TUN of ours gets the API (a free port, a fresh secret) — not tun2socks, not the native macOS service; conns:get / conns:close on one watch over the live tunnel', () => {
  const MAIN = R('src', 'main', 'main.js');
  assert.match(MAIN, /const tunWatch = myTun\.backendId === 'sing-box' && !myTun\.native\n\s*\? \{ port: \(await getFreePorts\(1\)\)\[0\], secret: require\('crypto'\)\.randomBytes\(16\)\.toString\('hex'\) \} : null;/);
  assert.match(MAIN, /apps: tunApps, watch: tunWatch,/, 'handed to the backend');
  assert.doesNotMatch(MAIN, /settings\.modules\.lanUsers\s*\n?\s*\? \{ port:/, 'no longer the users module\'s alone');
  assert.match(MAIN, /const connsWatch = createConnectionsWatch\(\{\n\s*connected: \(\) => !!\(xray && xray\.running\) && !!store\.get\('activeServerId', null\),\n\s*tun: \(\) => \(tun && tun\.active \? tun : null\)\n\s*\}\);/);
  assert.match(MAIN, /ipcMain\.handle\('conns:get', \(\) => connsWatch\.read\(\)\);/);
  assert.match(MAIN, /ipcMain\.handle\('conns:close', \(e, id\) => connsWatch\.close\(id\)\);/);
  // the hotspot check reads the same API, as before
  assert.match(MAIN, /watch: \(\) => \(tun && tun\.active && tun\.watch\) \|\| null,/);
});

test('service.js: a headless desktop\'s sing-box TUN gets the API, never the router\'s; the same two channels', () => {
  const SVC = R('src', 'server', 'service.js');
  assert.match(SVC, /const tunWatch = !OPENWRT && myTun\.backendId === 'sing-box' && !myTun\.native\n\s*\? \{ port: \(await getFreePorts\(1\)\)\[0\], secret: require\('crypto'\)\.randomBytes\(16\)\.toString\('hex'\) \} : null;/);
  assert.match(SVC, /lanUsersGw \? \{ lanUsers: lanUsersGw \} : \{\}, tunWatch \? \{ watch: tunWatch \} : \{\}\)\);/);
  assert.match(SVC, /const connsWatch = createConnectionsWatch\(\{\n\s*router: OPENWRT,/);
  assert.match(SVC, /'conns:get': \(\) => connsWatch\.read\(\),/);
  assert.match(SVC, /'conns:close': \(id\) => connsWatch\.close\(id\),/);
});

test('the router\'s service answers both channels: nothing to show there, nothing closed — connected or not', async (t) => {
  const H = require('./serviceHarness');
  t.after(() => H.cleanupDirs());
  const s = H.start();
  t.after(() => s.service.shutdown());
  assert.deepEqual(await s.service.invoke('conns:get'), { available: false, reason: 'router' });
  await s.service.invoke('connect', H.SERVER.id);
  assert.deepEqual(await s.service.invoke('conns:get'), { available: false, reason: 'router' });
  assert.deepEqual(await s.service.invoke('conns:close', 'ca3e1fae-1a27-427c-9680-bb0b0e2808d6'), { ok: false, error: 'router' });
});

test('the bridges: the two calls in the preload and in the router\'s web-api, on the channels main.js and service.js serve', () => {
  const preload = R('src', 'preload', 'preload.js');
  const web = R('src', 'server', 'web-api.js');
  assert.match(preload, /connsGet: \(\) => ipcRenderer\.invoke\('conns:get'\),/);
  assert.match(preload, /connsClose: \(id\) => ipcRenderer\.invoke\('conns:close', id\),/);
  assert.match(web, /\n {4}connsGet: \(\) => invoke\('conns:get'\),/);
  assert.match(web, /\n {4}connsClose: \(id\) => invoke\('conns:close', id\),/);
});
