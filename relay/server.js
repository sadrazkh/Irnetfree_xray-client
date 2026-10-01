#!/usr/bin/env node
'use strict';
/**
 * The IRNetFree relay — the owner's own door to a router that has no static
 * IP and sits behind any NAT. One process, no npm dependencies, Node ≥ 20.
 *
 *   RELAY_PASSWORD   the owner's password (12 characters at least; refused otherwise)
 *   RELAY_DATA       the data dir (default /app/data — a volume; atomic JSON, no lock)
 *   PORT             the listen port (default 8080)
 *
 * The router keeps an outbound WebSocket to /_relay/agent (Authorization:
 * Bearer <device token>); the logged-in owner opens / and every request
 * outside /_relay/ is carried to the selected router over that link and
 * answered by the router's own IRNetFree web UI. Pages of the relay itself
 * live under /_relay/ (login, routers, offline). Behind Traefik (Harbora) the
 * X-Forwarded-* headers are trusted from private peers only.
 *
 * What the relay sees is plaintext — it is the owner's server; the router's
 * UI token never travels here (the agent adds it on the router), relay cookies
 * never reach the router, no secret is logged.
 */
const http = require('http');
const path = require('path');
const crypto = require('crypto');
const { openStore, loadSecret } = require('./lib/store');
const { createAuth, safeEqual } = require('./lib/auth');
const pages = require('./lib/pages');
const { Link, createCache, acceptsGzip, isCacheablePath } = require('./lib/proxy');
const { wsAccept } = require('../src/server/remote/ws');
const { T, decode } = require('../src/server/remote/frames');
const { mintToken, isToken, hashToken } = require('../src/server/remote/token');

const FORM_LIMIT = 64 * 1024;
const HELLO_WAIT_MS = 10000;

/** 10/8, 172.16/12, 192.168/16, 127/8, ::1, fc00::/7 — the only peers whose X-Forwarded-* mean anything. */
function isPrivatePeer(addr) {
  const a = String(addr || '').replace(/^::ffff:/i, '').toLowerCase();
  if (a === '::1' || a.startsWith('127.') || a.startsWith('10.') || a.startsWith('192.168.')) return true;
  const m = /^172\.(\d+)\./.exec(a);
  if (m && Number(m[1]) >= 16 && Number(m[1]) <= 31) return true;
  return /^f[cd][0-9a-f]{2}:/.test(a);
}

function parseCookies(header) {
  const out = {};
  for (const part of String(header || '').split(';')) {
    const i = part.indexOf('=');
    if (i <= 0) continue;
    out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

const cookie = (name, value, { maxAge = null, httpOnly = true } = {}) =>
  `${name}=${value}; Path=/; ${httpOnly ? 'HttpOnly; ' : ''}Secure; SameSite=Strict${maxAge != null ? `; Max-Age=${maxAge}` : ''}`;
const clearCookie = (name) => cookie(name, '', { maxAge: 0 });

function readForm(req, limit = FORM_LIMIT) {
  return new Promise((resolve) => {
    let body = '';
    let over = false;
    req.on('data', (c) => { body += c; if (body.length > limit) { over = true; req.destroy(); } });
    req.on('end', () => resolve(over ? null : Object.fromEntries(new URLSearchParams(body))));
    req.on('error', () => resolve(null));
  });
}

function createRelay({ password, dataDir, now = Date.now, log = console.log, requestTimeoutMs = 60000, maxBodyBytes = 8 << 20 } = {}) {
  if (!dataDir) throw new Error('a data dir is required');
  const store = openStore(dataDir);
  // said at start, not at the first login: a volume the `node` user cannot write
  // (one made by hand as root) would otherwise fail the first session silently
  try { require('fs').accessSync(dataDir, require('fs').constants.W_OK); } catch { throw new Error(`the data dir ${dataDir} is not writable by this user (uid ${typeof process.getuid === 'function' ? process.getuid() : '?'})`); }
  const secret = loadSecret(dataDir);
  const auth = createAuth({ password, secret, store, now });
  const cache = createCache();
  const links = new Map();   // routerId → Link
  const SESSION_DAYS = 30;
  let closing = false;

  /* ----------------------------- helpers ----------------------------- */
  const send = (res, status, type, body, extra = {}) => {
    const buf = Buffer.isBuffer(body) ? body : Buffer.from(String(body), 'utf8');
    res.writeHead(status, Object.assign({ 'Content-Type': type, 'Content-Length': buf.length, 'Cache-Control': 'no-store' }, extra));
    res.end(buf);
  };
  const html = (res, status, body, extra) => send(res, status, 'text/html; charset=utf-8', body, extra);
  const json = (res, status, obj, extra) => send(res, status, 'application/json; charset=utf-8', JSON.stringify(obj), extra);
  const redirect = (res, to, extra = {}) => { res.writeHead(302, Object.assign({ Location: to, 'Cache-Control': 'no-store' }, extra)); res.end(); };

  /** Where the request really came from: the public scheme/host behind the reverse proxy, the client IP. */
  function context(req) {
    const peer = req.socket.remoteAddress || '';
    const trusted = isPrivatePeer(peer);
    const h = req.headers;
    const first = (v) => String(v || '').split(',')[0].trim();
    const proto = (trusted && first(h['x-forwarded-proto'])) || (req.socket.encrypted ? 'https' : 'http');
    const host = (trusted && first(h['x-forwarded-host'])) || String(h.host || '');
    const ip = (trusted && first(h['x-forwarded-for'])) || peer;
    return { proto, host, ip };
  }

  /** Origin (or the Referer's origin) must be this relay's own public origin. */
  function originAllowed(req, ctx) {
    let raw = req.headers.origin;
    if (!raw && req.headers.referer) { try { raw = new URL(req.headers.referer).origin; } catch { raw = null; } }
    if (!raw) return false;
    let o;
    try { o = new URL(String(raw)); } catch { return false; }
    return o.protocol === ctx.proto + ':' && o.host.toLowerCase() === ctx.host.toLowerCase();
  }

  function routerList(selectedId) {
    const routers = store.get().routers;
    return Object.entries(routers).map(([id, r]) => {
      const link = links.get(id);
      return { id, name: r.name, online: !!link, path: link ? link.hello.path : r.path, version: link ? link.hello.version : r.version, lastSeen: link ? now() : r.lastSeen, selected: id === selectedId };
    }).sort((a, b) => (a.name || '').localeCompare(b.name || ''));
  }

  /* ----------------------------- the agent link ----------------------------- */
  function routerForToken(token) {
    if (!isToken(token)) return null;
    const hash = hashToken(token);
    let found = null;
    for (const [id, r] of Object.entries(store.get().routers)) {
      if (r && typeof r.tokenHash === 'string' && safeEqual(r.tokenHash, hash)) found = Object.assign({ id }, r);
    }
    return found;
  }

  function attach(routerId, conn, hello) {
    const old = links.get(routerId);
    if (old) { links.delete(routerId); old.close(1000, 'replaced by a newer link'); }
    const link = new Link({
      routerId, conn, hello, now, log,
      onClose: (self) => {
        if (links.get(routerId) === self) links.delete(routerId);
        // a write that fails (the volume full, say) is a log line, never an exception out of a socket event
        if (!closing) { try { store.update((d) => { const r = d.routers[routerId]; if (r) r.lastSeen = now(); }); } catch (e) { log('relay: store write failed: ' + e.message); } }
        log(`relay: router ${routerId} (${self.hello.name || '?'}) link closed`);
      }
    });
    links.set(routerId, link);
    if (cache.version(routerId) !== link.hello.version) cache.drop(routerId);
    store.update((d) => {
      const r = d.routers[routerId];
      if (r) { r.lastSeen = now(); r.version = link.hello.version; r.path = link.hello.path; }
    });
    log(`relay: router ${routerId} (${link.hello.name || '?'}) online, app ${link.hello.version || '?'}, path ${link.hello.path || '?'}`);
  }

  function onUpgrade(req, socket, head) {
    const refuse = (status, text) => {
      try { socket.write(`HTTP/1.1 ${status} ${text}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`); } catch { /* gone */ }
      socket.destroy();
    };
    let url;
    try { url = new URL(req.url, 'http://relay'); } catch { return refuse(400, 'Bad Request'); }
    if (url.pathname !== '/_relay/agent') return refuse(404, 'Not Found');
    const m = /^Bearer\s+(\S+)$/i.exec(String(req.headers.authorization || ''));
    const router = m ? routerForToken(m[1]) : null;
    if (!router) return refuse(401, 'Unauthorized');
    let conn;
    try { conn = wsAccept(req, socket, head); } catch { return; }
    const timer = setTimeout(() => conn.close(1002, 'no hello'), HELLO_WAIT_MS);
    conn.once('message', (buf) => {
      clearTimeout(timer);
      let f;
      try { f = decode(buf); } catch { conn.close(1002, 'bad frame'); return; }
      if (f.type !== T.HELLO) { conn.close(1002, 'hello first'); return; }
      let hello = {};
      try { hello = f.json() || {}; } catch { /* an empty hello */ }
      if (!store.get().routers[router.id]) { conn.close(1008, 'revoked'); return; }
      attach(router.id, conn, { name: String(hello.name || '').slice(0, 40), version: String(hello.version || '').slice(0, 20), path: hello.path === 'vpn' ? 'vpn' : 'direct' });
    });
  }

  /* ----------------------------- the relay's own pages ----------------------------- */
  async function relayPage(req, res, url, ctx, cookies, lang, langCookie) {
    const p = url.pathname;
    const extra = langCookie ? { 'Set-Cookie': [langCookie] } : {};
    if (req.method === 'POST' && !originAllowed(req, ctx)) return html(res, 403, pages.errorPage({ lang, key: 'forbidden', status: 403 }));

    if (p === '/_relay/login') {
      if (req.method === 'GET') return html(res, 200, pages.loginPage({ lang }), extra);
      if (req.method !== 'POST') return html(res, 405, pages.errorPage({ lang, key: 'notFound', status: 405 }));
      const wait = auth.loginWait(ctx.ip);
      if (wait != null) {
        return html(res, 429, pages.loginPage({ lang, error: 'tooMany', retryMin: Math.ceil(wait / 60000) }), { 'Retry-After': String(Math.ceil(wait / 1000)) });
      }
      const form = await readForm(req);
      if (form && auth.checkPassword(form.password)) {
        auth.loginSucceeded(ctx.ip);
        const value = auth.createSession(ctx.ip);
        log('relay: owner signed in');
        return redirect(res, '/_relay/', { 'Set-Cookie': [cookie('relay_session', value, { maxAge: SESSION_DAYS * 86400 })] });
      }
      auth.loginFailed(ctx.ip);
      return html(res, 401, pages.loginPage({ lang, error: 'wrong' }));
    }

    if (p === '/_relay/agent') return send(res, 426, 'text/plain', 'upgrade required', { Upgrade: 'websocket' });

    const session = auth.verifySession(cookies.relay_session);
    if (!session) return redirect(res, '/_relay/login');

    if (p === '/_relay/logout' && req.method === 'POST') {
      auth.destroySession(session.id);
      return redirect(res, '/_relay/login', { 'Set-Cookie': [clearCookie('relay_session'), clearCookie('relay_router')] });
    }
    if (p === '/_relay/' || p === '/_relay') {
      if (req.method !== 'GET') return html(res, 405, pages.errorPage({ lang, key: 'notFound', status: 405 }));
      return html(res, 200, pages.dashboardPage({ lang, now: now(), routers: routerList(cookies.relay_router) }), extra);
    }
    if (p === '/_relay/routers' && req.method === 'POST') {
      const form = await readForm(req);
      const name = String((form && form.name) || '').replace(/[^\p{L}\p{N}\p{P}\p{Zs}]/gu, '').trim().slice(0, 40) || 'router';
      const token = mintToken();
      const id = crypto.randomBytes(6).toString('hex');
      store.update((d) => { d.routers[id] = { name, tokenHash: hashToken(token), createdAt: now(), lastSeen: null, version: null, path: null }; });
      log(`relay: router ${id} (${name}) added`);
      return html(res, 200, pages.dashboardPage({ lang, now: now(), routers: routerList(cookies.relay_router), newToken: { id, name, token } }));
    }
    const rm = /^\/_relay\/routers\/([a-f0-9]{12})\/(open|revoke)$/.exec(p);
    if (rm && req.method === 'POST') {
      const [, id, action] = rm;
      if (!store.get().routers[id]) return redirect(res, '/_relay/');
      if (action === 'open') return redirect(res, '/', { 'Set-Cookie': [cookie('relay_router', id, { maxAge: 365 * 86400 })] });
      const link = links.get(id);
      if (link) { links.delete(id); link.close(1008, 'revoked'); }
      cache.drop(id);
      store.update((d) => { delete d.routers[id]; });
      log(`relay: router ${id} revoked`);
      return redirect(res, '/_relay/', cookies.relay_router === id ? { 'Set-Cookie': [clearCookie('relay_router')] } : {});
    }
    return html(res, 404, pages.errorPage({ lang, key: 'notFound', status: 404 }));
  }

  /* ----------------------------- proxying ----------------------------- */
  function proxied(req, res, url, cookies, lang) {
    const isApi = url.pathname === '/rpc' || url.pathname === '/events';
    const session = auth.verifySession(cookies.relay_session);
    if (!session) return isApi ? json(res, 401, { error: 'not signed in to the relay' }) : redirect(res, '/_relay/login');
    const routerId = cookies.relay_router;
    const router = routerId ? store.get().routers[routerId] : null;
    if (!router) return isApi ? json(res, 400, { error: 'no router selected on the relay' }) : redirect(res, '/_relay/', routerId ? { 'Set-Cookie': [clearCookie('relay_router')] } : {});
    const link = links.get(routerId);
    if (!link || !link.open) {
      const seen = pages.ago(lang, router.lastSeen, now());
      if (isApi) return json(res, 503, { error: `router offline (${pages.t(lang, 'lastSeen')}: ${seen})` });
      return html(res, 503, pages.offlinePage({ lang, name: router.name, lastSeen: router.lastSeen, now: now() }));
    }
    const cacheable = req.method === 'GET' && isCacheablePath(url.pathname);
    if (cacheable) {
      const hit = cache.get(routerId, link.hello.version, req.url, acceptsGzip(req));
      if (hit) {
        const headers = Object.assign({}, hit.headers, { 'x-relay-cache': 'hit' });
        delete headers['content-length'];
        res.writeHead(hit.status, Object.assign(headers, { 'content-length': hit.body.length }));
        return res.end(hit.body);
      }
    }
    link.request(req, res, {
      cacheable, cache, requestTimeoutMs, maxBodyBytes,
      onError: (kind) => {
        const status = kind === 'timeout' ? 504 : kind === 'tooLarge' ? 413 : 502;
        if (isApi) return json(res, status, { error: pages.t('en', kind) });
        html(res, status, pages.errorPage({ lang, key: kind, status }));
      }
    });
  }

  /* ----------------------------- the server ----------------------------- */
  async function handle(req, res) {
    let url;
    try { url = new URL(req.url, 'http://relay'); } catch { return send(res, 400, 'text/plain', 'bad request'); }
    const p = url.pathname;
    if (p === '/_relay/health') return send(res, 200, 'text/plain', 'ok');
    const ctx = context(req);
    const cookies = parseCookies(req.headers.cookie);
    const wanted = url.searchParams.get('lang');
    const lang = pages.normLang(wanted || cookies.relay_lang || 'en');
    const langCookie = wanted && (wanted === 'fa' || wanted === 'en') ? cookie('relay_lang', lang, { maxAge: 365 * 86400, httpOnly: false }) : null;
    if (p === '/_relay' || p.startsWith('/_relay/')) return relayPage(req, res, url, ctx, cookies, lang, langCookie);
    return proxied(req, res, url, cookies, lang);
  }

  const server = http.createServer((req, res) => {
    handle(req, res).catch((e) => {
      log('relay: request failed: ' + ((e && e.message) || e));
      try { if (!res.headersSent) res.writeHead(500, { 'Content-Type': 'text/plain' }); res.end(); } catch { /* gone */ }
    });
  });
  server.on('upgrade', onUpgrade);
  server.keepAliveTimeout = 65000;
  server.headersTimeout = 70000;
  server.requestTimeout = 0;       // an SSE stream through the relay lives as long as the browser keeps it

  const api = {
    server, store, links, cache,
    get port() { const a = server.address(); return a ? a.port : null; },
    listen(port, host) {
      return new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(port, host, () => { server.removeListener('error', reject); resolve(api.port); });
      });
    },
    async close() {
      closing = true;
      const gone = [...links.values()].map((link) => new Promise((resolve) => {
        if (link.closed) return resolve();
        link.conn.once('close', resolve);
        link.close(1001, 'relay shutting down');
      }));
      links.clear();
      await Promise.race([Promise.all(gone), new Promise((r) => setTimeout(r, 1000).unref())]);
      await new Promise((resolve) => { server.close(() => resolve()); if (server.closeAllConnections) server.closeAllConnections(); });
    }
  };
  return api;
}

if (require.main === module) {
  const password = process.env.RELAY_PASSWORD || '';
  const dataDir = process.env.RELAY_DATA || '/app/data';
  const port = Number(process.env.PORT) || 8080;
  let relay;
  try { relay = createRelay({ password, dataDir }); }
  catch (e) { console.error('relay: ' + e.message); process.exit(1); }
  relay.listen(port, '0.0.0.0').then(() => {
    console.log(`relay: listening on :${port}, data in ${path.resolve(dataDir)}`);
  }).catch((e) => { console.error('relay: cannot listen: ' + e.message); process.exit(1); });
  const stop = (sig) => { console.log(`relay: ${sig}, shutting down`); relay.close().then(() => process.exit(0)); setTimeout(() => process.exit(0), 3000).unref(); };
  process.on('SIGTERM', () => stop('SIGTERM'));
  process.on('SIGINT', () => stop('SIGINT'));
}

module.exports = { createRelay, isPrivatePeer, parseCookies };
