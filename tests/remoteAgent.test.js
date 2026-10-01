'use strict';
/**
 * The router's agent (src/server/remote/agent.js): an outbound link to the
 * relay that executes the owner's requests against the router's own web UI
 * on 127.0.0.1 with the UI token injected, bypasses the tunnel on the way
 * out, and falls back to dialing through the tunnel's SOCKS inbound.
 *
 * Everything on loopback: the real relay (relay/), a fake router UI server
 * (checks the token and the Origin the way server.js does), a fake SOCKS5
 * server for the via-VPN path; DNS, the TLS layer and the timers are faked
 * so a test can see the servername the agent asked for, fail a dial at will,
 * and fire the backoff by hand.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const net = require('node:net');
const zlib = require('node:zlib');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createRelay } = require('../relay/server');
const { createRemoteAgent, BACKOFF_MS } = require('../src/server/remote/agent');

const PASSWORD = 'correct horse battery staple';
const UI_TOKEN = 'ui-token-0123456789abcdef';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const until = async (fn, ms = 5000, what = 'condition') => { const end = Date.now() + ms; while (!fn()) { if (Date.now() > end) throw new Error('timed out waiting for ' + what); await sleep(20); } };
const listen = (server, port = 0) => new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, '127.0.0.1', () => resolve(server.address().port)); });

/** One request to the relay with the owner's cookies; the body collected. */
function request(port, method, target, { headers = {}, body = null, jar = {} } = {}) {
  return new Promise((resolve, reject) => {
    const h = Object.assign({ Host: '127.0.0.1:' + port, Origin: 'http://127.0.0.1:' + port }, headers);
    const cookie = Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; ');
    if (cookie) h.Cookie = cookie;
    if (body != null) h['Content-Length'] = Buffer.byteLength(body);
    const req = http.request({ host: '127.0.0.1', port, method, path: target, headers: h }, (res) => {
      for (const sc of res.headers['set-cookie'] || []) { const [k, v] = sc.split(';')[0].split('='); jar[k.trim()] = v; }
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, raw: Buffer.concat(chunks), body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject);
    if (body != null) req.write(body);
    req.end();
  });
}
const form = (obj) => Object.entries(obj).map(([k, v]) => encodeURIComponent(k) + '=' + encodeURIComponent(v)).join('&');

/** The relay, logged in, one router paired and selected. */
async function startRelay(t, port = 0) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-agent-relay-'));
  const relay = createRelay({ password: PASSWORD, dataDir: dir, log: () => {} });
  await relay.listen(port, '127.0.0.1');
  t.after(async () => { await relay.close(); try { fs.rmSync(dir, { recursive: true, force: true }); } catch {} });
  const jar = {};
  const login = await request(relay.port, 'POST', '/_relay/login', { jar, headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: form({ password: PASSWORD }) });
  assert.equal(login.status, 302);
  const add = await request(relay.port, 'POST', '/_relay/routers', { jar, headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: form({ name: 'home' }) });
  const token = add.body.match(/data-token="([^"]+)"/)[1];
  const id = add.body.match(/data-router-id="([^"]+)"/)[1];
  await request(relay.port, 'POST', `/_relay/routers/${id}/open`, { jar });
  return { relay, jar, token, id, port: relay.port, dir };
}

/** A stand-in for server.js: token header or 401, Origin must match Host on /rpc and /events (guard.js), SSE on /events. */
async function startUi(t) {
  const seen = [];
  const sse = new Set();
  const srv = http.createServer((req, res) => {
    seen.push({ method: req.method, url: req.url, headers: req.headers });
    if (req.headers['x-irnetfree-token'] !== UI_TOKEN) { res.writeHead(401, { 'Content-Type': 'text/plain' }); return res.end('unauthorized'); }
    const origin = req.headers.origin || req.headers.referer;
    if ((req.url.startsWith('/rpc') || req.url.startsWith('/events')) && origin && new URL(origin).host !== req.headers.host) { res.writeHead(403); return res.end('cross-origin'); }
    if (req.url === '/events') {
      res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
      res.write('retry: 3000\n\n');
      sse.add(res);
      req.on('close', () => sse.delete(res));
      return;
    }
    if (req.url === '/rpc' && req.method === 'POST') {
      let b = ''; req.on('data', (c) => { b += c; });
      req.on('end', () => { const body = JSON.stringify({ result: { echo: JSON.parse(b || '{}') } }); res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(body) }); res.end(body); });
      return;
    }
    if (req.url.startsWith('/luci/')) { res.writeHead(200, { 'Content-Type': 'text/plain' }); return res.end('LUCI FACADE'); }
    if (req.url.startsWith('/app.js')) { const body = 'console.log("app");'.repeat(100); res.writeHead(200, { 'Content-Type': 'text/javascript; charset=utf-8', 'Cache-Control': 'no-cache' }); return res.end(body); }
    if (req.url === '/assets/icon.png') { res.writeHead(200, { 'Content-Type': 'image/png' }); return res.end(Buffer.alloc(300, 1)); }
    if (req.url === '/' || req.url.startsWith('/?')) { res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache' }); return res.end('<html><body>IRNetFree UI</body></html>'); }
    res.writeHead(404); res.end('not found');
  });
  const port = await listen(srv);
  t.after(() => { for (const r of sse) r.destroy(); srv.close(); });
  return { port, seen, emit: (obj) => { for (const r of sse) r.write('data: ' + JSON.stringify(obj) + '\n\n'); }, sse };
}

/** A SOCKS5 server (no auth) that CONNECTs everything to 127.0.0.1:<target>, ignoring the asked-for host. */
async function startSocks(t, targetPort) {
  const connects = [];
  const srv = net.createServer((client) => {
    let stage = 0;
    client.once('data', (greeting) => {
      assert.equal(greeting[0], 5);
      client.write(Buffer.from([5, 0]));
      client.once('data', (req) => {
        assert.equal(req[1], 1, 'CONNECT');
        const hostLen = req[4];
        const host = req.subarray(5, 5 + hostLen).toString();
        const port = req.readUInt16BE(5 + hostLen);
        connects.push({ host, port });
        const up = net.connect(targetPort, '127.0.0.1', () => {
          client.write(Buffer.from([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]));
          client.pipe(up); up.pipe(client);
          stage = 2;
        });
        up.on('error', () => client.destroy());
        client.on('error', () => up.destroy());
      });
    });
    client.on('error', () => {});
    void stage;
  });
  const port = await listen(srv);
  t.after(() => srv.close());
  return { port, connects };
}

/** The pieces an agent needs, all faked and observable. */
function makeDeps(t, { relayPort, uiPort, token, socksPort = 0, tunnelUp = () => false, lookup = null, resolve = null } = {}) {
  const logs = [];
  const events = [];      // the order of bypass calls and dials
  const timers = { queue: [], n: 0, setTimeout(fn, ms) { const id = ++this.n; this.queue.push({ id, fn, ms }); return id; }, clearTimeout(id) { this.queue = this.queue.filter((x) => x.id !== id); },
    fire(pred = () => true) { const i = this.queue.findIndex(pred); if (i < 0) return false; const [x] = this.queue.splice(i, 1); x.fn(); return true; },
    pending(pred = () => true) { return this.queue.filter(pred).map((x) => x.ms); } };
  const settings = { relayUrl: 'https://relay.test:' + relayPort, name: 'home', token, lastIps: [] };
  const saved = [];
  const bypass = [];
  const servernames = [];
  const dnsServers = [];
  const dials = [];
  let failDirect = 0;
  const service = {
    version: '1.16.0',
    getSettings: () => ({ socksPort }),
    setRemoteBypass: async (owner, list) => { bypass.push([owner, list]); events.push('bypass'); },
    directResolvers: () => ['178.22.122.100', '185.51.200.2'],
    connSnapshot: () => ({ state: tunnelUp() ? 'connected' : 'disconnected', tun: tunnelUp() })
  };
  const dns = {
    lookup: async (host) => { if (lookup) return lookup(host); return ['127.0.0.1']; },
    resolve: async (servers, host) => { dnsServers.push(servers); if (resolve) return resolve(servers, host); return ['127.0.0.1']; }
  };
  const netImpl = {
    connect: ({ host, port }) => new Promise((res, rej) => {
      dials.push({ host, port }); events.push('dial');
      if (failDirect > 0) { failDirect--; return rej(new Error('ECONNREFUSED (faked)')); }
      const s = net.connect(port, host, () => res(s)); s.once('error', rej);
    }),
    tls: async ({ socket, servername }) => { servernames.push(servername); return socket; },   // the fake TLS layer: a passthrough that remembers the SNI
    socks: ({ proxyPort, host, port }) => new Promise((res, rej) => {
      events.push('socks');
      const { socks5Connect } = require('../src/main/netutils');
      socks5Connect('127.0.0.1', proxyPort, host, port, 3000).then(res, rej);
    })
  };
  const agent = createRemoteAgent({
    getSettings: () => settings, saveLastIps: (ips) => { saved.push(ips); settings.lastIps = ips; },
    service, localPort: uiPort, uiToken: UI_TOKEN, log: (line, level) => logs.push(`${level || 'info'}: ${line}`),
    dns, netImpl, timers
  });
  t.after(() => agent.stop());
  return { agent, logs, settings, saved, bypass, servernames, dnsServers, dials, timers, events, failDirectTimes: (n) => { failDirect = n; } };
}

test('a page GET and an /rpc POST go browser → relay → agent → the router UI, with the UI token injected and Host/Origin kept', async (t) => {
  const r = await startRelay(t);
  const ui = await startUi(t);
  const d = makeDeps(t, { relayPort: r.port, uiPort: ui.port, token: r.token });
  d.agent.start();
  await until(() => d.agent.status().state === 'online', 5000, 'online');
  assert.equal(d.agent.status().path, 'direct');
  assert.equal(d.agent.status().relayHost, 'relay.test');

  const page = await request(r.port, 'GET', '/', { jar: r.jar });
  assert.equal(page.status, 200);
  assert.match(page.body, /IRNetFree UI/);
  const seen = ui.seen[0];
  assert.equal(seen.headers['x-irnetfree-token'], UI_TOKEN, 'the token was added on the router');
  assert.equal(seen.headers.host, '127.0.0.1:' + r.port, 'Host as the browser sent it');
  assert.equal(seen.headers.cookie, undefined, 'no relay cookie reached the router');

  const rpc = await request(r.port, 'POST', '/rpc', { jar: r.jar, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ channel: 'settings:get' }) });
  assert.equal(rpc.status, 200);
  assert.deepEqual(JSON.parse(rpc.body), { result: { echo: { channel: 'settings:get' } } });
  assert.equal(ui.seen[1].headers.origin, 'http://127.0.0.1:' + r.port, 'Origin kept so guard.js accepts it');
  // a token the browser tries to send itself is replaced, never trusted
  await request(r.port, 'GET', '/?forged=1', { jar: r.jar, headers: { 'x-irnetfree-token': 'forged' } });   // a new URL: the first / is in the relay's cache now
  assert.equal(ui.seen[2].headers['x-irnetfree-token'], UI_TOKEN);
});

test('/luci/* is refused by the agent with 403 and never reaches the router', async (t) => {
  const r = await startRelay(t);
  const ui = await startUi(t);
  const d = makeDeps(t, { relayPort: r.port, uiPort: ui.port, token: r.token });
  d.agent.start();
  await until(() => d.agent.status().state === 'online');
  for (const p of ['/luci/status', '/LUCI/status', '/luci/remote_get?x=1', '//luci/status']) {
    const res = await request(r.port, 'POST', p, { jar: r.jar, body: '{}' });
    assert.equal(res.status, 403, p);
    assert.doesNotMatch(res.body, /LUCI FACADE/, p);
  }
  assert.equal(ui.seen.length, 0, 'nothing reached the router');
});

test('SSE events stream through the link to the browser', async (t) => {
  const r = await startRelay(t);
  const ui = await startUi(t);
  const d = makeDeps(t, { relayPort: r.port, uiPort: ui.port, token: r.token });
  d.agent.start();
  await until(() => d.agent.status().state === 'online');
  const chunks = [];
  const req = http.request({ host: '127.0.0.1', port: r.port, method: 'GET', path: '/events', headers: { Cookie: `relay_session=${r.jar.relay_session}; relay_router=${r.jar.relay_router}`, Host: '127.0.0.1:' + r.port } }, (res) => {
    assert.equal(res.statusCode, 200);
    assert.equal(res.headers['content-type'], 'text/event-stream');
    res.on('data', (c) => chunks.push(c.toString()));
  });
  req.on('error', () => {});
  req.end();
  await until(() => ui.sse.size === 1, 5000, 'the SSE client at the router');
  ui.emit({ channel: 'status', payload: { state: 'connected' } });
  await until(() => chunks.join('').includes('"state":"connected"'), 5000, 'the first event');
  ui.emit({ channel: 'stats', payload: { up: 7 } });
  await until(() => chunks.join('').includes('"up":7'), 5000, 'the second event');
  req.destroy();
  await until(() => ui.sse.size === 0, 5000, 'the router side closed after the browser left');
});

test('compressible answers are gzipped when the browser accepts gzip; images and SSE are not; without Accept-Encoding nothing is', async (t) => {
  const r = await startRelay(t);
  const ui = await startUi(t);
  const d = makeDeps(t, { relayPort: r.port, uiPort: ui.port, token: r.token });
  d.agent.start();
  await until(() => d.agent.status().state === 'online');
  const gz = await request(r.port, 'GET', '/app.js', { jar: r.jar, headers: { 'Accept-Encoding': 'gzip, deflate, br' } });
  assert.equal(gz.status, 200);
  assert.equal(gz.headers['content-encoding'], 'gzip');
  assert.equal(gz.headers['content-length'], undefined, 'the original length no longer applies');
  assert.equal(zlib.gunzipSync(gz.raw).toString(), 'console.log("app");'.repeat(100));
  assert.ok(gz.raw.length < 200, 'smaller on the wire: ' + gz.raw.length);
  assert.equal(ui.seen[0].headers['accept-encoding'], undefined, 'the router is asked for plain bytes; the agent compresses');
  const png = await request(r.port, 'GET', '/assets/icon.png', { jar: r.jar, headers: { 'Accept-Encoding': 'gzip' } });
  assert.equal(png.headers['content-encoding'], undefined);
  assert.equal(png.raw.length, 300);
  const plain = await request(r.port, 'GET', '/app.js?plain=1', { jar: r.jar });
  assert.equal(plain.headers['content-encoding'], undefined);
  assert.equal(plain.body, 'console.log("app");'.repeat(100));
});

test('setRemoteBypass gets the host and the resolved IPs before the first dial; the direct resolvers are used while the tunnel is up, the system one when it is down', async (t) => {
  const r = await startRelay(t);
  const ui = await startUi(t);
  let up = true;
  const d = makeDeps(t, { relayPort: r.port, uiPort: ui.port, token: r.token, tunnelUp: () => up });
  d.agent.start();
  await until(() => d.agent.status().state === 'online');
  assert.deepEqual(d.bypass[0], ['relay', { hosts: ['relay.test'], cidrs: ['127.0.0.1/32'] }]);
  assert.deepEqual(d.events.slice(0, 2), ['bypass', 'dial'], 'the bypass is in place before the dial');
  assert.deepEqual(d.dnsServers[0], ['178.22.122.100', '185.51.200.2'], 'resolved through the config\'s direct resolvers');
  assert.deepEqual(d.saved[0], ['127.0.0.1'], 'the good IPs are remembered');
  assert.deepEqual(d.servernames, ['relay.test'], 'TLS with the host as SNI');
  // the tunnel goes down and the link drops: the next dial resolves through the system resolver
  up = false;
  d.dnsServers.length = 0;
  const lookups = [];
  d.agent.stop();
  await until(() => d.agent.status().state === 'off');
  const d2 = makeDeps(t, { relayPort: r.port, uiPort: ui.port, token: r.token, tunnelUp: () => false, lookup: async (h) => { lookups.push(h); return ['127.0.0.1']; } });
  d2.agent.start();
  await until(() => d2.agent.status().state === 'online');
  assert.deepEqual(lookups, ['relay.test']);
  assert.equal(d2.dnsServers.length, 0, 'no direct-resolver query with the tunnel down');
});

test('DNS failing: the remembered IP is dialed with SNI = the host', async (t) => {
  const r = await startRelay(t);
  const ui = await startUi(t);
  const d = makeDeps(t, { relayPort: r.port, uiPort: ui.port, token: r.token, lookup: async () => { throw new Error('EAI_AGAIN (faked)'); } });
  d.settings.lastIps = ['127.0.0.1'];
  d.agent.start();
  await until(() => d.agent.status().state === 'online');
  assert.deepEqual(d.dials[0], { host: '127.0.0.1', port: r.port });
  assert.deepEqual(d.servernames, ['relay.test']);
  assert.ok(d.logs.some((l) => /dns|resolve/i.test(l) && /remembered|last/i.test(l)), 'the log says the remembered address was used: ' + d.logs.join(' | '));
});

test('no DNS and nothing remembered: an error state, a retry scheduled, the token in no log line', async (t) => {
  const r = await startRelay(t);
  const ui = await startUi(t);
  const d = makeDeps(t, { relayPort: r.port, uiPort: ui.port, token: r.token, lookup: async () => { throw new Error('EAI_AGAIN (faked)'); } });
  d.agent.start();
  await until(() => d.agent.status().state === 'connecting' && d.agent.status().lastError, 5000, 'a failed attempt');
  assert.match(d.agent.status().lastError, /EAI_AGAIN|resolve/i);
  assert.equal(d.dials.length, 0, 'nothing to dial');
  assert.ok(d.timers.pending(() => true).length >= 1, 'a retry is scheduled');
  assert.ok(!d.logs.some((l) => l.includes(r.token)), 'the token is in no log line');
});

test('the relay going away: connecting with growing backoff (2/5/10/30/60 s + jitter), then online again when it is back', async (t) => {
  const r = await startRelay(t);
  const ui = await startUi(t);
  const d = makeDeps(t, { relayPort: r.port, uiPort: ui.port, token: r.token });
  d.agent.start();
  await until(() => d.agent.status().state === 'online');
  const port = r.port;
  await r.relay.close();
  await until(() => d.agent.status().state === 'connecting', 5000, 'connecting after the relay closed');
  const waits = [];
  for (let i = 0; i < 5; i++) {
    await until(() => d.timers.pending(() => true).length === 1, 5000, 'a retry timer');
    const ms = d.timers.pending(() => true)[0];
    waits.push(ms);
    d.timers.fire(() => true);
    await until(() => d.timers.pending(() => true).length === 1 || d.agent.status().state === 'online', 5000, 'the attempt to settle');
  }
  for (let i = 0; i < waits.length; i++) {
    const base = BACKOFF_MS[Math.min(i, BACKOFF_MS.length - 1)];
    assert.ok(waits[i] >= base && waits[i] <= base * 1.5, `wait ${i}: ${waits[i]} ms is ${base} ms + jitter`);
  }
  assert.equal(d.agent.status().state, 'connecting');
  assert.ok(/ECONNREFUSED|refused|connect/i.test(d.agent.status().lastError || ''), d.agent.status().lastError);
  // the relay comes back on the same port: the next attempt is online
  const dir2 = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-agent-relay2-'));
  fs.copyFileSync(path.join(r.dir, 'relay.json'), path.join(dir2, 'relay.json'));
  fs.copyFileSync(path.join(r.dir, 'secret.key'), path.join(dir2, 'secret.key'));
  const relay2 = createRelay({ password: PASSWORD, dataDir: dir2, log: () => {} });
  await relay2.listen(port, '127.0.0.1');
  t.after(async () => { await relay2.close(); try { fs.rmSync(dir2, { recursive: true, force: true }); } catch {} });
  d.timers.fire(() => true);
  await until(() => d.agent.status().state === 'online', 5000, 'online again');
  assert.equal(d.agent.status().lastError, null, 'the error is cleared');
  assert.equal((await request(port, 'GET', '/', { jar: r.jar })).status, 200);
});

test('three direct failures while the tunnel is up: the link goes through the local SOCKS inbound with path vpn; direct is tried again after 10 minutes', async (t) => {
  const r = await startRelay(t);
  const ui = await startUi(t);
  const socks = await startSocks(t, r.port);
  let now = 1000000;
  const d = makeDeps(t, { relayPort: r.port, uiPort: ui.port, token: r.token, socksPort: socks.port, tunnelUp: () => true });
  d.agent.setClock(() => now);
  d.failDirectTimes(3);
  d.agent.start();
  // the three failures: each schedules a retry that the test fires at once
  for (let i = 0; i < 3; i++) {
    await until(() => d.timers.pending(() => true).length === 1, 5000, 'retry ' + i);
    d.timers.fire(() => true);
  }
  await until(() => d.agent.status().state === 'online', 5000, 'online through the tunnel');
  assert.equal(d.agent.status().path, 'vpn');
  assert.equal(d.dials.length, 3, 'three direct dials failed');
  assert.deepEqual(socks.connects, [{ host: 'relay.test', port: r.port }], 'SOCKS5 CONNECT to the relay host, TLS done after');
  assert.deepEqual(d.servernames.slice(-1), ['relay.test']);
  assert.ok(d.logs.some((l) => /through the tunnel|via VPN|vpn/i.test(l)), d.logs.join(' | '));
  const dash = await request(r.port, 'GET', '/_relay/', { jar: r.jar });
  assert.match(dash.body, /via VPN/, 'the relay shows the path');
  assert.equal((await request(r.port, 'GET', '/', { jar: r.jar })).body, '<html><body>IRNetFree UI</body></html>');
  // ten minutes later the link drops: direct is tried first again, and works
  now += 10 * 60 * 1000 + 1;
  d.agent.link().close(1001, 'test: drop');
  await until(() => d.agent.status().state === 'connecting', 5000, 'reconnecting');
  d.timers.fire(() => true);
  await until(() => d.agent.status().state === 'online', 5000, 'online again');
  assert.equal(d.agent.status().path, 'direct');
  assert.equal(d.dials.length, 4);
});

test('a direct failure while the tunnel is DOWN does not count towards the fallback (SOCKS is not usable then)', async (t) => {
  const r = await startRelay(t);
  const ui = await startUi(t);
  const socks = await startSocks(t, r.port);
  const d = makeDeps(t, { relayPort: r.port, uiPort: ui.port, token: r.token, socksPort: socks.port, tunnelUp: () => false });
  d.failDirectTimes(4);
  d.agent.start();
  for (let i = 0; i < 4; i++) {
    await until(() => d.timers.pending(() => true).length === 1, 5000, 'retry ' + i);
    d.timers.fire(() => true);
  }
  await until(() => d.agent.status().state === 'online');
  assert.equal(d.agent.status().path, 'direct');
  assert.equal(socks.connects.length, 0);
  assert.equal(d.dials.length, 5);
});

test('stop() closes the link (the relay shows it offline) and the state is off; start() after it works; reconfigure() restarts', async (t) => {
  const r = await startRelay(t);
  const ui = await startUi(t);
  const d = makeDeps(t, { relayPort: r.port, uiPort: ui.port, token: r.token });
  d.agent.start();
  await until(() => d.agent.status().state === 'online');
  d.agent.stop();
  assert.equal(d.agent.status().state, 'off');
  await sleep(100);
  assert.match((await request(r.port, 'GET', '/_relay/', { jar: r.jar })).body, /Offline/);
  d.agent.start();
  await until(() => d.agent.status().state === 'online');
  const since = d.agent.status().since;
  await sleep(10);
  d.agent.reconfigure();
  await until(() => d.agent.status().state === 'online' && d.agent.status().since !== since, 5000, 'a new link');
  assert.ok(!d.logs.some((l) => l.includes(r.token)), 'no log line carries the token');
});

test('a missing token or relay URL: the agent reports error and does not dial', async (t) => {
  const ui = await startUi(t);
  const d = makeDeps(t, { relayPort: 1, uiPort: ui.port, token: '' });
  d.agent.start();
  await sleep(50);
  assert.equal(d.agent.status().state, 'error');
  assert.match(d.agent.status().lastError, /token|configured/i);
  assert.equal(d.dials.length, 0);
});

test('a revoked token (401 from the relay) is an error the status names, with a retry scheduled and the token in no log line', async (t) => {
  const r = await startRelay(t);
  const ui = await startUi(t);
  await request(r.port, 'POST', `/_relay/routers/${r.id}/revoke`, { jar: r.jar });
  const d = makeDeps(t, { relayPort: r.port, uiPort: ui.port, token: r.token });
  d.agent.start();
  await until(() => !!d.agent.status().lastError, 5000, 'the refusal');
  assert.match(d.agent.status().lastError, /401|token/i);
  assert.equal(d.agent.status().state, 'connecting');
  assert.ok(!d.logs.some((l) => l.includes(r.token)));
  assert.ok(!JSON.stringify(d.agent.status()).includes(r.token));
});
