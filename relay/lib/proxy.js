'use strict';
/**
 * A router's link and the requests carried over it.
 *
 * `Link` wraps one agent WebSocket: a browser request becomes a stream —
 * REQ_HEAD (method, path+query, headers minus hop-by-hop and minus the
 * relay's own cookies, Host kept so the router's Origin check passes), the
 * body as REQ_BODY frames, REQ_END — and the router's RES_HEAD / RES_BODY /
 * RES_END are written to the browser as they come (an SSE response streams
 * for as long as it lives; everything else has a deadline). A browser that
 * goes away sends CANCEL; a link that dies fails every open stream. The
 * link pings every 25 s and is dropped after 75 s of silence.
 *
 * `createCache`: static GETs (not /rpc, not /events) kept per router and app
 * version, so a phone reload does not pull the ~0.65 MB UI through the home
 * uplink again. A new version from the router's HELLO drops its entries.
 */
const { T, encode, decode } = require('../../src/server/remote/frames');

const HOP_BY_HOP = new Set(['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'proxy-connection', 'te', 'trailer', 'transfer-encoding', 'upgrade']);
const OWN_COOKIES = new Set(['relay_session', 'relay_router', 'relay_lang']);
const PING_MS = 25000;
const SILENT_MS = 75000;
const HIGH_WATER = 1 << 20;

/** The Cookie header without the relay's own cookies; null when nothing is left. */
function stripOwnCookies(header) {
  if (!header) return null;
  const kept = String(header).split(';').map((s) => s.trim()).filter((s) => s && !OWN_COOKIES.has(s.split('=')[0].trim()));
  return kept.length ? kept.join('; ') : null;
}

/** The request headers the router gets: lower-case, hop-by-hop and the proxy's own gone, cookies filtered, Host as it came. */
function requestHeaders(req) {
  const out = {};
  for (const [k, v] of Object.entries(req.headers)) {
    const key = k.toLowerCase();
    if (HOP_BY_HOP.has(key) || key.startsWith('x-forwarded-') || key === 'x-real-ip' || key === 'forwarded') continue;
    if (key === 'cookie') { const c = stripOwnCookies(v); if (c) out.cookie = c; continue; }
    out[key] = Array.isArray(v) ? v.join(', ') : v;
  }
  return out;
}

/** The response headers the browser gets. */
function responseHeaders(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers || {})) {
    const key = String(k).toLowerCase();
    if (HOP_BY_HOP.has(key)) continue;
    if (v == null) continue;
    out[key] = v;
  }
  return out;
}

const acceptsGzip = (req) => /(^|,)\s*gzip\s*(;|,|$)/i.test(String(req.headers['accept-encoding'] || ''));
const isCacheablePath = (pathname) => pathname !== '/rpc' && pathname !== '/events' && !pathname.startsWith('/_relay/');

function createCache({ maxEntryBytes = 2 << 20, maxRouterBytes = 12 << 20 } = {}) {
  const byRouter = new Map();   // routerId → { version, entries: Map(key → entry), bytes }
  const bucket = (routerId, version) => {
    let b = byRouter.get(routerId);
    if (!b || b.version !== version) { b = { version, entries: new Map(), bytes: 0 }; byRouter.set(routerId, b); }
    return b;
  };
  return {
    maxEntryBytes,
    /** The entry for this URL that the request can take (gzipped only when it accepts gzip), or null. */
    get(routerId, version, url, gzipOk) {
      const b = byRouter.get(routerId);
      if (!b || b.version !== version) return null;
      if (gzipOk) { const e = b.entries.get(url + '|gz'); if (e) return e; }
      return b.entries.get(url) || null;
    },
    put(routerId, version, url, entry) {
      if (entry.body.length > maxEntryBytes) return;
      const b = bucket(routerId, version);
      const key = url + (entry.gzipped ? '|gz' : '');
      const old = b.entries.get(key);
      if (old) { b.bytes -= old.body.length; b.entries.delete(key); }
      b.entries.set(key, entry);
      b.bytes += entry.body.length;
      for (const [k, e] of b.entries) {           // oldest first
        if (b.bytes <= maxRouterBytes) break;
        b.entries.delete(k); b.bytes -= e.body.length;
      }
    },
    drop(routerId) { byRouter.delete(routerId); },
    version(routerId) { const b = byRouter.get(routerId); return b ? b.version : null; }
  };
}

class Link {
  /**
   * @param {{ routerId: string, conn: import('../../src/server/remote/ws').WsConn, hello: object, now: () => number, log: Function, onClose: Function }} p
   */
  constructor({ routerId, conn, hello, now, log, onClose }) {
    this.routerId = routerId;
    this.conn = conn;
    this.hello = Object.assign({ name: '', version: '', path: 'direct' }, hello || {});
    this.now = now;
    this.log = log || (() => {});
    this.since = now();
    this.lastSeen = now();
    this.streams = new Map();
    this.nextStream = 1;
    this.paused = new Set();
    this.closed = false;
    this.onClose = onClose || (() => {});
    conn.on('message', (buf) => this._onMessage(buf));
    conn.on('pong', () => { this.lastSeen = this.now(); });
    conn.on('drain', () => { for (const req of this.paused) { try { req.resume(); } catch { /* gone */ } } this.paused.clear(); });
    conn.on('close', (code, reason) => this._onClose(code, reason));
    this.timer = setInterval(() => {
      if (this.now() - this.lastSeen > SILENT_MS) { this.log(`relay: router ${routerId} silent for ${SILENT_MS / 1000}s — dropping its link`); this.close(1001, 'silent'); return; }
      this.conn.ping();
    }, PING_MS);
    if (this.timer.unref) this.timer.unref();
  }

  get open() { return !this.closed && this.conn.readyState === 'open'; }

  close(code = 1000, reason = '') {
    if (this.closed) return;
    this.conn.close(code, reason);
  }

  _onClose(code, reason) {
    if (this.closed) return;
    this.closed = true;
    clearInterval(this.timer);
    for (const [id, s] of this.streams) { this.streams.delete(id); this._fail(s, 'gone'); }
    this.onClose(this, code, reason);
  }

  _onMessage(buf) {
    this.lastSeen = this.now();
    let f;
    try { f = decode(buf); } catch { this.close(1002, 'bad frame'); return; }
    const s = this.streams.get(f.stream);
    if (!s) return;                             // a stream the browser already left
    if (f.type === T.RES_HEAD) {
      if (s.headersSent) return;
      let head;
      try { head = f.json(); } catch { this._fail(s, 'gone'); return; }
      const status = Number(head && head.status) || 502;
      const headers = responseHeaders(head && head.headers);
      s.sse = /^text\/event-stream/i.test(String(headers['content-type'] || ''));
      if (s.sse && s.timer) { clearTimeout(s.timer); s.timer = null; }
      s.headersSent = true;
      s.status = status;
      if (s.cacheable && status === 200 && !s.sse) { s.collect = []; s.collected = 0; s.cacheHeaders = headers; }
      try { s.res.writeHead(status, headers); if (s.sse) s.res.flushHeaders(); } catch { this._drop(s); }
      return;
    }
    if (f.type === T.RES_BODY) {
      if (!s.headersSent) return;
      if (s.collect) {
        s.collected += f.payload.length;
        if (s.collected > s.cache.maxEntryBytes) s.collect = null; else s.collect.push(f.payload);
      }
      // the browser side has no flow control back to the router: a slow phone
      // buffers here, bounded in practice by the UI's own sizes
      try { s.res.write(f.payload); } catch { this._drop(s); }
      return;
    }
    if (f.type === T.RES_END) {
      if (!s.headersSent) { this._fail(s, 'gone'); return; }
      this.streams.delete(s.id);
      if (s.timer) clearTimeout(s.timer);
      if (s.collect) {
        const body = Buffer.concat(s.collect);
        s.cache.put(this.routerId, this.hello.version, s.url, { status: s.status, headers: s.cacheHeaders, body, gzipped: /gzip/i.test(String(s.cacheHeaders['content-encoding'] || '')) });
      }
      try { s.res.end(); } catch { /* gone */ }
      return;
    }
    if (f.type === T.CANCEL) { this._fail(s, 'gone'); }
  }

  /** Carry `req` to the router; `res` gets whatever comes back. */
  request(req, res, { cacheable = false, cache, requestTimeoutMs = 60000, maxBodyBytes = 8 << 20, onError }) {
    const id = this.nextStream;
    this.nextStream = this.nextStream >= 0xffffffff ? 1 : this.nextStream + 1;
    const s = { id, req, res, url: req.url, cacheable: cacheable && !!cache, cache, headersSent: false, sse: false, timer: null, onError, done: false };
    this.streams.set(id, s);
    this.conn.send(encode(T.REQ_HEAD, id, { method: req.method, path: req.url, headers: requestHeaders(req) }));
    let size = 0;
    req.on('data', (chunk) => {
      if (!this.streams.has(id)) return;
      size += chunk.length;
      if (size > maxBodyBytes) { this._fail(s, 'tooLarge'); return; }
      this.conn.send(encode(T.REQ_BODY, id, chunk));
      if (this.conn.bufferedAmount > HIGH_WATER) { req.pause(); this.paused.add(req); }
    });
    req.on('end', () => { if (this.streams.has(id)) this.conn.send(encode(T.REQ_END, id)); });
    req.on('error', () => this._drop(s));
    res.on('close', () => { if (this.streams.has(id)) this._drop(s); });
    s.timer = setTimeout(() => { if (this.streams.has(id) && !s.sse) this._fail(s, 'timeout'); }, requestTimeoutMs);
  }

  /** The browser left or the response is cut: tell the router, forget the stream. */
  _drop(s) {
    if (!this.streams.has(s.id)) return;
    this.streams.delete(s.id);
    if (s.timer) clearTimeout(s.timer);
    this.paused.delete(s.req);
    if (this.open) this.conn.send(encode(T.CANCEL, s.id));
    if (!s.res.writableEnded) { try { s.res.destroy(); } catch { /* gone */ } }
  }

  /** The router cannot answer this stream: an error page when nothing was sent yet, else cut. */
  _fail(s, kind) {
    if (!this.streams.has(s.id) && kind !== 'gone') return;
    this.streams.delete(s.id);
    if (s.timer) clearTimeout(s.timer);
    this.paused.delete(s.req);
    if (this.open && kind !== 'gone') this.conn.send(encode(T.CANCEL, s.id));
    if (s.headersSent || s.res.headersSent) { try { s.res.destroy(); } catch { /* gone */ } return; }
    try { s.onError(kind); } catch { try { s.res.destroy(); } catch { /* gone */ } }
  }
}

module.exports = { Link, createCache, acceptsGzip, isCacheablePath, requestHeaders, responseHeaders, stripOwnCookies, HOP_BY_HOP, OWN_COOKIES, PING_MS, SILENT_MS };
