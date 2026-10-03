'use strict';
/**
 * The self-hosted relay (relay/): the owner logs in, pairs a router with a
 * device token, and every request outside /_relay/ is carried to that router
 * over its outbound WebSocket link as a stream of frames. Everything here runs
 * on 127.0.0.1 — a browser is an http.request with cookies, an agent is a
 * wsConnect with the token — in a temp data dir, with a fake clock for the
 * rate limiter.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createRelay } = require('../relay/server');
const { wsConnect } = require('../src/server/remote/ws');
const { T, encode, decode } = require('../src/server/remote/frames');

const PASSWORD = 'correct horse battery staple';

/** One request; the body collected; `cookies` kept as a jar the caller owns. */
function request(port, method, target, { headers = {}, body = null, jar = {}, onHead = null } = {}) {
  return new Promise((resolve, reject) => {
    const h = Object.assign({ Host: '127.0.0.1:' + port }, headers);
    const cookie = Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; ');
    if (cookie) h.Cookie = cookie;
    if (body != null) h['Content-Length'] = Buffer.byteLength(body);
    const req = http.request({ host: '127.0.0.1', port, method, path: target, headers: h }, (res) => {
      for (const sc of res.headers['set-cookie'] || []) {
        const [kv, ...attrs] = sc.split(';');
        const [k, v] = kv.split('=');
        if (attrs.some((a) => /max-age=0/i.test(a))) delete jar[k.trim()]; else jar[k.trim()] = v;
      }
      if (onHead) onHead(res);
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8'), raw: Buffer.concat(chunks) }));
    });
    req.on('error', reject);
    if (body != null) req.write(body);
    req.end();
  });
}
const form = (obj) => Object.entries(obj).map(([k, v]) => encodeURIComponent(k) + '=' + encodeURIComponent(v)).join('&');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const once = (em, ev) => new Promise((resolve) => em.once(ev, (...a) => resolve(a)));

async function startRelay(t, opts = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-relay-'));
  const clock = { now: Date.now() };
  const relay = createRelay(Object.assign({ password: PASSWORD, dataDir: dir, now: () => clock.now, log: () => {} }, opts));
  await relay.listen(0, '127.0.0.1');
  t.after(async () => { await relay.close(); try { fs.rmSync(dir, { recursive: true, force: true }); } catch {} });
  const origin = 'http://127.0.0.1:' + relay.port;
  const login = async (jar = {}) => {
    const r = await request(relay.port, 'POST', '/_relay/login', { jar, headers: { Origin: origin, 'Content-Type': 'application/x-www-form-urlencoded' }, body: form({ password: PASSWORD }) });
    assert.equal(r.status, 302, 'login: ' + r.body.slice(0, 200));
    return jar;
  };
  /** Add router through the dashboard form; returns { id, token } from the page. */
  const addRouter = async (jar, name) => {
    const r = await request(relay.port, 'POST', '/_relay/routers', { jar, headers: { Origin: origin, 'Content-Type': 'application/x-www-form-urlencoded' }, body: form({ name }) });
    assert.equal(r.status, 200, r.body.slice(0, 300));
    const token = (r.body.match(/data-token="([^"]+)"/) || [])[1];
    const id = (r.body.match(/data-router-id="([^"]+)"/) || [])[1];
    assert.ok(token, 'the token is on the page once');
    assert.ok(id, 'the router id is on the page');
    return { id, token };
  };
  const connectAgent = async (token, hello = { name: 'home', version: '1.16.0', path: 'direct' }) => {
    const conn = await wsConnect(`ws://127.0.0.1:${relay.port}/_relay/agent`, { headers: { Authorization: 'Bearer ' + token } });
    if (hello) conn.send(encode(T.HELLO, 0, hello));
    return conn;
  };
  const open = async (jar, id) => {
    const r = await request(relay.port, 'POST', `/_relay/routers/${id}/open`, { jar, headers: { Origin: origin } });
    assert.equal(r.status, 302);
    assert.equal(r.headers.location, '/');
    assert.equal(jar.relay_router, id);
  };
  return { relay, dir, clock, origin, login, addRouter, connectAgent, open, port: relay.port };
}

/** A fake router behind the agent link: answers REQ_HEAD frames with the handler's reply. */
function serveAgent(conn, handler) {
  const seen = [];
  conn.on('message', (buf) => {
    const f = decode(buf);
    if (f.type === T.REQ_HEAD) {
      const head = f.json();
      const rec = { head, body: [], stream: f.stream, ended: false };
      seen.push(rec);
      handler(rec, {
        head: (status, headers) => conn.send(encode(T.RES_HEAD, f.stream, { status, headers })),
        body: (chunk) => conn.send(encode(T.RES_BODY, f.stream, chunk)),
        end: () => conn.send(encode(T.RES_END, f.stream))
      });
    } else if (f.type === T.REQ_BODY) {
      const rec = seen.find((r) => r.stream === f.stream); if (rec) rec.body.push(f.payload);
    } else if (f.type === T.REQ_END) {
      const rec = seen.find((r) => r.stream === f.stream); if (rec) { rec.ended = true; if (rec.onEnd) rec.onEnd(); }
    } else if (f.type === T.CANCEL) {
      const rec = seen.find((r) => r.stream === f.stream); if (rec) rec.cancelled = true;
    }
  });
  return seen;
}

test('refuses to start with a password shorter than 12 characters', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-relay-'));
  assert.throws(() => createRelay({ password: 'short12345', dataDir: dir }), /RELAY_PASSWORD/);
  assert.throws(() => createRelay({ password: '', dataDir: dir }), /RELAY_PASSWORD/);
  assert.doesNotThrow(() => createRelay({ password: 'twelve chars', dataDir: dir, log: () => {} }));
  fs.rmSync(dir, { recursive: true, force: true });
});

test('health answers 200 without a session; / without a session is a redirect to the login page (< 500 for the health gate)', async (t) => {
  const { port } = await startRelay(t);
  const h = await request(port, 'GET', '/_relay/health');
  assert.equal(h.status, 200);
  assert.equal(h.body, 'ok');
  const root = await request(port, 'GET', '/');
  assert.equal(root.status, 302);
  assert.equal(root.headers.location, '/_relay/login');
  const page = await request(port, 'GET', '/_relay/login');
  assert.equal(page.status, 200);
  assert.match(page.headers['content-type'], /text\/html/);
  assert.match(page.body, /password/i);
  assert.match(page.body, /رمز/, 'the Persian label is there too');
});

test('login: the session cookie is HttpOnly, Secure, SameSite=Strict; a tampered cookie is refused', async (t) => {
  const { port, origin } = await startRelay(t);
  let setCookie = null;
  const r = await request(port, 'POST', '/_relay/login', {
    headers: { Origin: origin, 'Content-Type': 'application/x-www-form-urlencoded' }, body: form({ password: PASSWORD }),
    onHead: (res) => { setCookie = (res.headers['set-cookie'] || []).find((c) => c.startsWith('relay_session=')); }
  });
  assert.equal(r.status, 302);
  assert.equal(r.headers.location, '/_relay/');
  assert.ok(setCookie, 'a session cookie is set');
  assert.match(setCookie, /;\s*HttpOnly/i);
  assert.match(setCookie, /;\s*Secure/i);
  assert.match(setCookie, /;\s*SameSite=Strict/i);
  assert.match(setCookie, /;\s*Path=\//i);
  const value = setCookie.split(';')[0].split('=')[1];
  const dash = await request(port, 'GET', '/_relay/', { jar: { relay_session: value } });
  assert.equal(dash.status, 200);
  // flip one character of the signature — the one before the last, chosen by what IS there: chosen by the last
  // character, a signature whose one before the last already was the replacement came back untouched (1 run in 64)
  const at = value.length - 2;
  const tampered = value.slice(0, at) + (value[at] === 'a' ? 'b' : 'a') + value.slice(at + 1);
  assert.notEqual(tampered, value);
  const bad = await request(port, 'GET', '/_relay/', { jar: { relay_session: tampered } });
  assert.equal(bad.status, 302);
  assert.equal(bad.headers.location, '/_relay/login');
  // and a made-up one
  const fake = await request(port, 'GET', '/_relay/', { jar: { relay_session: 'abc.def' } });
  assert.equal(fake.status, 302);
  // a wrong password is a 401 on the login page, with no cookie
  const wrong = await request(port, 'POST', '/_relay/login', { headers: { Origin: origin, 'Content-Type': 'application/x-www-form-urlencoded' }, body: form({ password: 'not it, not it' }) });
  assert.equal(wrong.status, 401);
  assert.equal(wrong.headers['set-cookie'], undefined);
});

test('rate limit: five wrong passwords, then the sixth is 429 even with the right one; after the window it works', async (t) => {
  const { port, origin, clock } = await startRelay(t);
  const attempt = (password) => request(port, 'POST', '/_relay/login', { headers: { Origin: origin, 'Content-Type': 'application/x-www-form-urlencoded' }, body: form({ password }) });
  for (let i = 0; i < 5; i++) assert.equal((await attempt('wrong password ' + i)).status, 401);
  const blocked = await attempt(PASSWORD);
  assert.equal(blocked.status, 429);
  assert.ok(Number(blocked.headers['retry-after']) > 0, 'Retry-After is set');
  clock.now += 15 * 60 * 1000 + 1000;
  const ok = await attempt(PASSWORD);
  assert.equal(ok.status, 302);
});

test('a POST under /_relay/ with a foreign Origin is 403, one with no Origin and no Referer too', async (t) => {
  const { port, login } = await startRelay(t);
  const jar = await login();
  const foreign = await request(port, 'POST', '/_relay/routers', { jar, headers: { Origin: 'https://evil.example', 'Content-Type': 'application/x-www-form-urlencoded' }, body: form({ name: 'x' }) });
  assert.equal(foreign.status, 403);
  const none = await request(port, 'POST', '/_relay/routers', { jar, headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: form({ name: 'x' }) });
  assert.equal(none.status, 403);
  const login403 = await request(port, 'POST', '/_relay/login', { headers: { Origin: 'https://evil.example', 'Content-Type': 'application/x-www-form-urlencoded' }, body: form({ password: PASSWORD }) });
  assert.equal(login403.status, 403);
  // behind the reverse proxy (a private peer) the public origin is what X-Forwarded-* says
  const fwd = await request(port, 'POST', '/_relay/routers', { jar, headers: { Origin: 'https://relay.example', 'X-Forwarded-Proto': 'https', 'X-Forwarded-Host': 'relay.example', 'Content-Type': 'application/x-www-form-urlencoded' }, body: form({ name: 'behind traefik' }) });
  assert.equal(fwd.status, 200);
});

test('Add router mints a token shown once; the store keeps only its SHA-256; the dashboard lists the router offline', async (t) => {
  const { port, login, addRouter, dir } = await startRelay(t);
  const jar = await login();
  const { id, token } = await addRouter(jar, 'Home router');
  assert.match(token, /^[A-Za-z0-9_-]{43}$/, '32 random bytes as base64url');
  const stored = JSON.parse(fs.readFileSync(path.join(dir, 'relay.json'), 'utf8'));
  const router = stored.routers[id];
  assert.ok(router, 'the router is in the store');
  assert.equal(router.name, 'Home router');
  assert.equal(router.tokenHash, crypto.createHash('sha256').update(token).digest('hex'));
  assert.ok(!JSON.stringify(stored).includes(token), 'the token itself is nowhere in the store');
  const dash = await request(port, 'GET', '/_relay/', { jar });
  assert.equal(dash.status, 200);
  assert.match(dash.body, /Home router/);
  assert.ok(!dash.body.includes(token), 'the token is not shown again');
  assert.match(dash.body, /Offline|آفلاین/);
});

test('an agent with the token connects; a browser GET reaches it as REQ_HEAD with Host kept and no relay cookies; the answer streams back', async (t) => {
  const { port, login, addRouter, connectAgent, open } = await startRelay(t);
  const jar = await login();
  const { id, token } = await addRouter(jar, 'home');
  const agent = await connectAgent(token);
  t.after(() => agent.socket.destroy());
  const seen = serveAgent(agent, (rec, reply) => {
    rec.onEnd = () => {
      reply.head(200, { 'content-type': 'text/plain; charset=utf-8', 'x-from': 'router' });
      reply.body('hello ');
      reply.body('from the router');
      reply.end();
    };
  });
  await open(jar, id);
  await sleep(50);
  const dash = await request(port, 'GET', '/_relay/', { jar });
  assert.match(dash.body, /Online|آنلاین/, 'the dashboard shows it online');
  assert.match(dash.body, /1\.16\.0/, 'with its app version');

  const r = await request(port, 'GET', '/x?y=1', { jar: Object.assign({ other: 'kept' }, jar), headers: { Origin: 'http://127.0.0.1:' + port, 'X-Custom': 'yes' } });
  assert.equal(r.status, 200);
  assert.equal(r.body, 'hello from the router');
  assert.equal(r.headers['x-from'], 'router');
  assert.equal(seen.length, 1);
  const head = seen[0].head;
  assert.equal(head.method, 'GET');
  assert.equal(head.path, '/x?y=1');
  assert.equal(head.headers.host, '127.0.0.1:' + port, 'Host as the browser sent it (the router checks Origin against it)');
  assert.equal(head.headers.origin, 'http://127.0.0.1:' + port);
  assert.equal(head.headers['x-custom'], 'yes');
  assert.equal(head.headers.cookie, 'other=kept', 'the relay\'s own cookies are stripped, others kept');
  assert.ok(!JSON.stringify(head).includes(jar.relay_session), 'the session cookie never reaches the router');
  assert.equal(head.headers.connection, undefined, 'hop-by-hop headers are dropped');
  assert.ok(seen[0].ended, 'REQ_END arrived');
});

test('a POST body reaches the agent as REQ_BODY, in order, then REQ_END; a body over 8 MB is refused with 413', async (t) => {
  const { port, login, addRouter, connectAgent, open } = await startRelay(t);
  const jar = await login();
  const { id, token } = await addRouter(jar, 'home');
  const agent = await connectAgent(token);
  t.after(() => agent.socket.destroy());
  const seen = serveAgent(agent, (rec, reply) => {
    rec.onEnd = () => { reply.head(200, { 'content-type': 'application/json' }); reply.body(JSON.stringify({ got: Buffer.concat(rec.body).length })); reply.end(); };
  });
  await open(jar, id);
  const body = JSON.stringify({ channel: 'connect', arg: 'id-1' });
  const r = await request(port, 'POST', '/rpc', { jar, headers: { Origin: 'http://127.0.0.1:' + port, 'Content-Type': 'application/json' }, body });
  assert.equal(r.status, 200);
  assert.deepEqual(JSON.parse(r.body), { got: body.length });
  assert.equal(Buffer.concat(seen[0].body).toString(), body);
  assert.equal(seen[0].head.method, 'POST');
  const big = Buffer.alloc(8 * 1024 * 1024 + 1, 65);
  const r2 = await request(port, 'POST', '/rpc', { jar, headers: { Origin: 'http://127.0.0.1:' + port, 'Content-Type': 'text/plain' }, body: big });
  assert.equal(r2.status, 413);
});

test('an SSE response streams: two events reach the browser before the stream ends', async (t) => {
  const { port, login, addRouter, connectAgent, open } = await startRelay(t);
  const jar = await login();
  const { id, token } = await addRouter(jar, 'home');
  const agent = await connectAgent(token);
  t.after(() => agent.socket.destroy());
  let reply;
  serveAgent(agent, (rec, rep) => { reply = rep; rep.head(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' }); rep.body('retry: 3000\n\n'); });
  await open(jar, id);
  const chunks = [];
  let resolveTwo;
  const twoEvents = new Promise((r) => { resolveTwo = r; });
  const done = new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method: 'GET', path: '/events', headers: { Cookie: `relay_session=${jar.relay_session}; relay_router=${jar.relay_router}`, Accept: 'text/event-stream' } }, (res) => {
      assert.equal(res.statusCode, 200);
      assert.equal(res.headers['content-type'], 'text/event-stream');
      res.on('data', (c) => { chunks.push(c.toString()); if (chunks.join('').split('\n\n').filter(Boolean).length >= 3) resolveTwo(); });
      res.on('end', () => resolve(chunks.join('')));
    });
    req.on('error', reject);
    req.end();
  });
  await sleep(100);
  reply.body('data: {"channel":"status","payload":{"state":"connected"}}\n\n');
  await sleep(50);
  reply.body('data: {"channel":"stats","payload":{"up":1}}\n\n');
  await twoEvents;
  assert.match(chunks.join(''), /"state":"connected"/);
  assert.match(chunks.join(''), /"up":1/);
  reply.end();
  const all = await done;
  assert.equal(all.split('\n\n').filter(Boolean).length, 3);
});

test('the browser going away cancels the stream at the agent', async (t) => {
  const { port, login, addRouter, connectAgent, open } = await startRelay(t);
  const jar = await login();
  const { id, token } = await addRouter(jar, 'home');
  const agent = await connectAgent(token);
  t.after(() => agent.socket.destroy());
  const seen = serveAgent(agent, (rec, rep) => { rep.head(200, { 'content-type': 'text/event-stream' }); rep.body(': ping\n\n'); });
  await open(jar, id);
  const req = http.request({ host: '127.0.0.1', port, method: 'GET', path: '/events', headers: { Cookie: `relay_session=${jar.relay_session}; relay_router=${jar.relay_router}` } }, (res) => { res.on('data', () => {}); });
  req.on('error', () => {});
  req.end();
  await sleep(150);
  assert.equal(seen.length, 1);
  req.destroy();
  await sleep(150);
  assert.equal(seen[0].cancelled, true, 'CANCEL reached the agent');
});

test('agent gone: the offline page with the last-seen time; /rpc gets JSON; a reconnect brings it back', async (t) => {
  const { port, login, addRouter, connectAgent, open, clock } = await startRelay(t);
  const jar = await login();
  const { id, token } = await addRouter(jar, 'home');
  await open(jar, id);
  const before = await request(port, 'GET', '/', { jar });
  assert.equal(before.status, 503);
  assert.match(before.body, /offline|آفلاین/i);
  assert.match(before.body, /never|هرگز/, 'never seen yet');
  const agent = await connectAgent(token);
  serveAgent(agent, (rec, rep) => { rep.head(200, { 'content-type': 'text/plain' }); rep.body('up'); rep.end(); });
  await sleep(50);
  assert.equal((await request(port, 'GET', '/', { jar })).body, 'up');
  clock.now += 61 * 1000;
  const closed = once(agent, 'close');
  agent.close(1000, 'going down');
  await closed;
  await sleep(50);
  const r = await request(port, 'GET', '/', { jar });
  assert.equal(r.status, 503);
  assert.match(r.body, /offline|آفلاین/i);
  assert.match(r.body, /last seen|آخرین/i);
  assert.doesNotMatch(r.body, /never/, 'it was seen once');
  const rpc = await request(port, 'POST', '/rpc', { jar, headers: { Origin: 'http://127.0.0.1:' + port, 'Content-Type': 'application/json' }, body: '{}' });
  assert.equal(rpc.status, 503);
  assert.match(rpc.headers['content-type'], /application\/json/);
  assert.match(JSON.parse(rpc.body).error, /offline/);
  const again = await connectAgent(token);
  t.after(() => again.socket.destroy());
  serveAgent(again, (rec, rep) => { rep.head(200, { 'content-type': 'text/plain' }); rep.body('back'); rep.end(); });
  await sleep(50);
  // the same app version came back: the static GET is still the cached page (by design), a POST proves the new link
  const cached = await request(port, 'GET', '/', { jar });
  assert.equal(cached.body, 'up');
  assert.equal(cached.headers['x-relay-cache'], 'hit');
  const live = await request(port, 'POST', '/rpc', { jar, headers: { Origin: 'http://127.0.0.1:' + port, 'Content-Type': 'application/json' }, body: '{}' });
  assert.equal(live.body, 'back');
});

test('a revoked token cannot connect, a wrong token neither; revoking closes the live link', async (t) => {
  const { port, login, addRouter, connectAgent, origin } = await startRelay(t);
  const jar = await login();
  const { id, token } = await addRouter(jar, 'home');
  const agent = await connectAgent(token);
  const closed = once(agent, 'close');
  const r = await request(port, 'POST', `/_relay/routers/${id}/revoke`, { jar, headers: { Origin: origin } });
  assert.equal(r.status, 302);
  await closed;
  await assert.rejects(connectAgent(token), (e) => e.status === 401);
  await assert.rejects(connectAgent('A'.repeat(43)), (e) => e.status === 401);
  await assert.rejects(wsConnect(`ws://127.0.0.1:${port}/_relay/agent`), (e) => e.status === 401);
  const dash = await request(port, 'GET', '/_relay/', { jar });
  assert.doesNotMatch(dash.body, /data-router-id="/, 'no router left');
});

test('a second link for the same router replaces the first', async (t) => {
  const { port, login, addRouter, connectAgent, open } = await startRelay(t);
  const jar = await login();
  const { id, token } = await addRouter(jar, 'home');
  const first = await connectAgent(token);
  const firstClosed = once(first, 'close');
  serveAgent(first, (rec, rep) => { rep.head(200, { 'content-type': 'text/plain' }); rep.body('first'); rep.end(); });
  await open(jar, id);
  await sleep(30);
  const second = await connectAgent(token);
  t.after(() => second.socket.destroy());
  serveAgent(second, (rec, rep) => { rep.head(200, { 'content-type': 'text/plain' }); rep.body('second'); rep.end(); });
  const [code] = await firstClosed;
  assert.equal(code, 1000, 'the old link is closed cleanly');
  await sleep(30);
  assert.equal((await request(port, 'GET', '/', { jar })).body, 'second');
});

test('a cached static GET is served without a second REQ_HEAD while the version is unchanged; /rpc and /events are never cached; a new version drops the cache', async (t) => {
  const { port, login, addRouter, connectAgent, open } = await startRelay(t);
  const jar = await login();
  const { id, token } = await addRouter(jar, 'home');
  const agent = await connectAgent(token);
  const seen = serveAgent(agent, (rec, rep) => {
    rec.onEnd = () => { rep.head(200, { 'content-type': 'text/javascript', 'cache-control': 'no-cache' }); rep.body('console.log(1)'); rep.end(); };
  });
  await open(jar, id);
  const a = await request(port, 'GET', '/app.js', { jar });
  assert.equal(a.status, 200);
  assert.equal(a.body, 'console.log(1)');
  const b = await request(port, 'GET', '/app.js', { jar });
  assert.equal(b.body, 'console.log(1)');
  assert.equal(b.headers['x-relay-cache'], 'hit');
  assert.equal(seen.length, 1, 'one REQ_HEAD for two GETs');
  await request(port, 'GET', '/app.js?v=2', { jar });
  assert.equal(seen.length, 2, 'a different query is a different entry');
  await request(port, 'POST', '/rpc', { jar, headers: { Origin: 'http://127.0.0.1:' + port }, body: '{}' });
  await request(port, 'POST', '/rpc', { jar, headers: { Origin: 'http://127.0.0.1:' + port }, body: '{}' });
  assert.equal(seen.length, 4, 'POST /rpc is never cached');
  await request(port, 'GET', '/events', { jar });
  await request(port, 'GET', '/events', { jar });
  assert.equal(seen.length, 6, 'GET /events is never cached');
  // the router comes back with a newer app: the cache for it is gone
  agent.socket.destroy();
  await sleep(50);
  const agent2 = await connectAgent(token, { name: 'home', version: '1.17.0', path: 'direct' });
  t.after(() => agent2.socket.destroy());
  const seen2 = serveAgent(agent2, (rec, rep) => { rec.onEnd = () => { rep.head(200, { 'content-type': 'text/javascript' }); rep.body('console.log(2)'); rep.end(); }; });
  await sleep(30);
  const c = await request(port, 'GET', '/app.js', { jar });
  assert.equal(c.body, 'console.log(2)');
  assert.equal(seen2.length, 1);
});

test('no session: /rpc and /events answer 401 JSON (a stale tab), pages redirect; no router selected goes to the dashboard', async (t) => {
  const { port, login } = await startRelay(t);
  const rpc = await request(port, 'POST', '/rpc', { headers: { Origin: 'http://127.0.0.1:' + port }, body: '{}' });
  assert.equal(rpc.status, 401);
  assert.match(rpc.headers['content-type'], /json/);
  const ev = await request(port, 'GET', '/events');
  assert.equal(ev.status, 401);
  const jar = await login();
  const r = await request(port, 'GET', '/', { jar });
  assert.equal(r.status, 302);
  assert.equal(r.headers.location, '/_relay/');
});

test('logout ends the session for good; the agent endpoint without an upgrade is 426', async (t) => {
  const { port, login, origin } = await startRelay(t);
  const jar = await login();
  const session = jar.relay_session;
  const out = await request(port, 'POST', '/_relay/logout', { jar, headers: { Origin: origin } });
  assert.equal(out.status, 302);
  const after = await request(port, 'GET', '/_relay/', { jar: { relay_session: session } });
  assert.equal(after.status, 302, 'the old cookie value is dead on the server too');
  const plain = await request(port, 'GET', '/_relay/agent');
  assert.equal(plain.status, 426);
});

test('a request that never gets its answer times out with 504 and a CANCEL; the link stays', async (t) => {
  const { port, login, addRouter, connectAgent, open } = await startRelay(t, { requestTimeoutMs: 300 });
  const jar = await login();
  const { id, token } = await addRouter(jar, 'home');
  const agent = await connectAgent(token);
  t.after(() => agent.socket.destroy());
  const seen = serveAgent(agent, () => { /* never answers */ });
  await open(jar, id);
  const r = await request(port, 'GET', '/slow', { jar });
  assert.equal(r.status, 504);
  await sleep(30);
  assert.equal(seen[0].cancelled, true);
  assert.equal(agent.readyState, 'open');
});

test('a slow-body request is cut by the HTTP request timeout, while an SSE response longer than it still streams (review I2)', async (t) => {
  const { port, login, addRouter, connectAgent, open } = await startRelay(t, { httpRequestTimeoutMs: 600, connectionsCheckingIntervalMs: 100 });
  const jar = await login();
  const { id, token } = await addRouter(jar, 'home');
  const agent = await connectAgent(token);
  t.after(() => agent.socket.destroy());
  let reply;
  serveAgent(agent, (rec, rep) => { reply = rep; rep.head(200, { 'content-type': 'text/event-stream' }); rep.body(': hi\n\n'); });
  await open(jar, id);
  // (a) the SSE response outlives requestTimeout: six chunks over 1.5 s all arrive
  const chunks = [];
  const streamed = new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method: 'GET', path: '/events', headers: { Cookie: `relay_session=${jar.relay_session}; relay_router=${jar.relay_router}` } }, (res) => {
      res.on('data', (c) => chunks.push(c.toString()));
      res.on('end', () => resolve());
      res.on('error', reject);
    });
    req.on('error', reject);
    req.end();
  });
  await sleep(100);
  for (let i = 0; i < 6; i++) { reply.body(`data: ${i}\n\n`); await sleep(250); }
  reply.end();
  await streamed;
  assert.equal(chunks.join('').split('\n\n').filter((s) => s.startsWith('data:')).length, 6, chunks.join(''));
  // (b) a request whose body trickles in is cut (408 or a closed socket) within a couple of seconds
  const net = require('node:net');
  const outcome = await new Promise((resolve) => {
    let buf = '';
    const started = Date.now();
    const s = net.connect(port, '127.0.0.1', () => s.write(`POST /_relay/login HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nOrigin: http://127.0.0.1:${port}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 100\r\n\r\np`));
    s.setEncoding('utf8');
    s.on('data', (d) => { buf += d; });
    s.on('close', () => resolve({ buf, ms: Date.now() - started }));
    s.on('error', () => {});
    setTimeout(() => { s.destroy(); resolve({ buf, ms: Infinity }); }, 4000);
  });
  assert.ok(outcome.ms < 3000, 'the trickling request was cut: ' + outcome.ms + ' ms');
  assert.ok(/408|^$/.test(outcome.buf.split('\r\n')[0] || ''), 'a 408 or a plain close, got: ' + outcome.buf.slice(0, 60));
});

test('the store: every write uses its own tmp name (two containers share one volume and both are PID 1 — review I3)', async (t) => {
  const { relay } = await startRelay(t);
  const seen = [];
  const orig = fs.openSync;
  fs.openSync = (p, ...a) => { if (/relay\.json\..*\.tmp$/.test(String(p))) seen.push(String(p)); return orig(p, ...a); };
  try {
    relay.store.update((d) => { d.routers.a = { name: 'a' }; });
    relay.store.update((d) => { d.routers.b = { name: 'b' }; });
  } finally { fs.openSync = orig; }
  assert.equal(seen.length, 2);
  assert.notEqual(seen[0], seen[1], 'a new tmp name per write');
  assert.ok(seen.every((p) => p.includes('.' + process.pid + '.')), 'the pid is in it too');
  assert.deepEqual(Object.keys(relay.store.get().routers).sort(), ['a', 'b']);
  assert.ok(!fs.readdirSync(path.dirname(relay.store.file)).some((n) => n.endsWith('.tmp')), 'no tmp file left behind');
});

test('a store write that fails while an agent says hello is a log line, not a crash of the relay (review I3)', async (t) => {
  const { port, relay, login, addRouter, connectAgent, open } = await startRelay(t);
  const jar = await login();
  const { id, token } = await addRouter(jar, 'home');
  await open(jar, id);
  const realUpdate = relay.store.update;
  relay.store.update = () => { throw new Error('ENOSPC: no space left on device (faked)'); };
  t.after(() => { relay.store.update = realUpdate; });
  const agent = await connectAgent(token);
  t.after(() => agent.socket.destroy());
  serveAgent(agent, (rec, rep) => { rep.head(200, { 'content-type': 'text/plain' }); rep.body('alive'); rep.end(); });
  await sleep(100);
  assert.equal(agent.readyState, 'open', 'the link stays up');
  const r = await request(port, 'GET', '/', { jar });
  assert.equal(r.status, 200);
  assert.equal(r.body, 'alive');
  relay.store.update = realUpdate;
  assert.equal((await request(port, 'GET', '/_relay/', { jar })).status, 200, 'the relay still answers');
});

test('behind the proxy the login limiter keys on the hop Traefik appended — the last X-Forwarded-For entry (review M1)', async (t) => {
  const { port, origin } = await startRelay(t);
  const attempt = (xff, password) => request(port, 'POST', '/_relay/login', { headers: { Origin: origin, 'X-Forwarded-For': xff, 'Content-Type': 'application/x-www-form-urlencoded' }, body: form({ password }) });
  // five failures with a different first hop each time, the same last hop: the sixth is blocked
  for (let i = 0; i < 5; i++) assert.equal((await attempt(`203.0.113.${i + 1}, 198.51.100.9`, 'wrong one ' + i)).status, 401);
  assert.equal((await attempt('203.0.113.77, 198.51.100.9', PASSWORD)).status, 429);
  // another last hop is not
  assert.equal((await attempt('203.0.113.1, 198.51.100.10', PASSWORD)).status, 302);
});

test('sessions do not survive a RELAY_PASSWORD change; they do survive a restart with the same one (review M2)', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-relay-pw-'));
  t.after(() => { try { fs.rmSync(dir, { recursive: true, force: true }); } catch {} });
  const start = async (password) => { const r = createRelay({ password, dataDir: dir, log: () => {} }); await r.listen(0, '127.0.0.1'); return r; };
  const a = await start(PASSWORD);
  const jar = {};
  const login = await request(a.port, 'POST', '/_relay/login', { jar, headers: { Origin: 'http://127.0.0.1:' + a.port, 'Content-Type': 'application/x-www-form-urlencoded' }, body: form({ password: PASSWORD }) });
  assert.equal(login.status, 302);
  await a.close();
  const same = await start(PASSWORD);
  assert.equal((await request(same.port, 'GET', '/_relay/', { jar })).status, 200, 'the same password: the session lives on');
  await same.close();
  const rotated = await start('a brand new password for the relay');
  assert.equal((await request(rotated.port, 'GET', '/_relay/', { jar })).status, 302, 'a new password: everyone is logged out');
  await rotated.close();
});

test('the Persian pages: ?lang=fa switches the dashboard and the login page to Persian with a cookie', async (t) => {
  const { port, login } = await startRelay(t);
  const jar = await login();
  const fa = await request(port, 'GET', '/_relay/?lang=fa', { jar });
  assert.equal(fa.status, 200);
  assert.match(fa.body, /dir="rtl"/);
  assert.match(fa.body, /روترها/);
  assert.equal(jar.relay_lang, 'fa');
  const again = await request(port, 'GET', '/_relay/', { jar });
  assert.match(again.body, /dir="rtl"/, 'remembered');
  const en = await request(port, 'GET', '/_relay/?lang=en', { jar });
  assert.match(en.body, /dir="ltr"/);
});
