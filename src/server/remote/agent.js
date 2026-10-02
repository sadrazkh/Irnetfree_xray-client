'use strict';
/**
 * The router's end of the relay link (spec §3.5 R4, R7–R9).
 *
 * An outbound WebSocket to wss://<relay>/_relay/agent with the device token
 * as a Bearer, opened with HELLO {name, version, path}; every REQ_* stream the
 * relay sends is executed against the router's OWN web UI on
 * http://127.0.0.1:<localPort> with the UI token injected (the token never
 * leaves the router), /_relay/* and /luci/* refused (403); compressible
 * answers gzipped when the browser accepted gzip; CANCEL aborts the local
 * request; the link pings every 25 s and is redialed after 75 s of silence;
 * reconnects with backoff 2/5/10/30/60 s + jitter.
 *
 * The control path never rides the tunnel: while the gateway is up the relay
 * host is resolved through the config's direct, route-excluded in-country
 * resolvers (`service.directResolvers()`), the resolved addresses are handed
 * to `service.setRemoteBypass('relay', {hosts, cidrs})` BEFORE the dial, and
 * the last good addresses are remembered (`saveLastIps`) so the relay is
 * reachable with SNI = host even when DNS fails. Three direct failures in a
 * row while the tunnel is up → dial through the local SOCKS inbound instead
 * (path 'vpn'), trying direct again every 10 minutes. Both service hooks are
 * called only when the service has them (another branch adds them).
 *
 * Nothing here logs the device token.
 */
const http = require('http');
const net = require('net');
const tls = require('tls');
const dns = require('dns');
const zlib = require('zlib');
const { wsConnect } = require('./ws');
const { T, encode, decode } = require('./frames');

const BACKOFF_MS = [2000, 5000, 10000, 30000, 60000];
const DIRECT_FAILURES_BEFORE_VPN = 3;
const DIRECT_RETRY_MS = 10 * 60 * 1000;
const PING_MS = 25000;
const SILENT_MS = 75000;
const DIAL_TIMEOUT_MS = 15000;
const HIGH_WATER = 1 << 20;
const HOP_BY_HOP = new Set(['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'proxy-connection', 'te', 'trailer', 'transfer-encoding', 'upgrade', 'expect']);
const COMPRESSIBLE = /^(text\/|application\/(javascript|x-javascript|json|xml|manifest\+json)|image\/svg\+xml)/i;

/**
 * The request target as the router's server routes it: `new URL(target,
 * 'http://localhost')` — the same parser, so dot-segments (`/./`, `/../`, their
 * percent-encoded forms) fold the same way on both sides — or null when it is
 * no path of the router's own UI: unparseable, or an absolute-form target for
 * another origin (the agent only ever talks to its own UI). Review I1: judging
 * the raw string let `/./luci/status` through to the facade.
 */
function normaliseTarget(target) {
  let u;
  try { u = new URL(String(target || ''), 'http://localhost'); } catch { return null; }
  if (u.origin !== 'http://localhost' || u.username || u.password) return null;
  return u;
}

/** /_relay/* and /luci/* (any case, any number of leading slashes, after normalisation) never reach the router; nor does a target that is not a path of its UI. */
function forbiddenPath(target) {
  const u = normaliseTarget(target);
  if (!u) return true;
  return /^\/+(_relay|luci)(\/|$)/i.test(u.pathname);
}

const cidrOf = (ip) => (ip.includes(':') ? ip + '/128' : ip + '/32');
const unique = (list) => [...new Set(list)];
const sameList = (a, b) => Array.isArray(a) && Array.isArray(b) && a.length === b.length && a.every((x, i) => x === b[i]);

function describeError(e) {
  if (e && e.status === 401) return 'the relay refused the device token (401) — revoked, or not this relay\'s token';
  if (e && e.status === 403) return 'the relay refused the link (403)';
  if (e && e.status) return `unexpected answer ${e.status} from the relay`;
  if (!e) return 'unknown error';
  const msg = String(e.message || e);
  return e.code && !msg.includes(e.code) ? `${e.code}: ${msg}` : msg;
}

/* ----------------------------- defaults ----------------------------- */
const defaultDns = {
  lookup: (host) => new Promise((resolve, reject) => {
    dns.lookup(host, { all: true }, (e, list) => (e ? reject(e) : resolve((list || []).map((a) => a.address))));
  }),
  resolve: async (servers, host) => {
    const r = new dns.Resolver({ timeout: 4000, tries: 2 });
    r.setServers(servers);
    const ask = (fn) => new Promise((resolve) => fn.call(r, host, (e, a) => resolve(e ? [] : a || [])));
    const v4 = await ask(r.resolve4);
    const v6 = await ask(r.resolve6);
    if (!v4.length && !v6.length) throw new Error('no answer from ' + servers.join(', '));
    return [...v4, ...v6];
  }
};

const defaultNet = {
  connect: ({ host, port }) => new Promise((resolve, reject) => {
    const s = net.connect({ host, port });
    const onErr = (e) => { clearTimeout(to); reject(e); };
    const to = setTimeout(() => s.destroy(new Error('connect timeout')), DIAL_TIMEOUT_MS);
    s.once('error', onErr);
    s.once('connect', () => { clearTimeout(to); s.removeListener('error', onErr); resolve(s); });
  }),
  tls: ({ socket, servername }) => new Promise((resolve, reject) => {
    const s = tls.connect({ socket, servername, rejectUnauthorized: true });
    const onErr = (e) => { clearTimeout(to); reject(e); };
    const to = setTimeout(() => s.destroy(new Error('tls timeout')), DIAL_TIMEOUT_MS);
    s.once('error', onErr);
    s.once('secureConnect', () => { clearTimeout(to); s.removeListener('error', onErr); resolve(s); });
  }),
  socks: ({ proxyPort, host, port }) => require('../../main/netutils').socks5Connect('127.0.0.1', proxyPort, host, port, DIAL_TIMEOUT_MS)
};

/**
 * @param {object} o
 * @param {() => {relayUrl, name, token, lastIps?}} o.getSettings   the remote.relay settings (+ the remembered IPs)
 * @param {(ips: string[]) => void} [o.saveLastIps]
 * @param {object} o.service   version, getSettings() (socksPort); optional setRemoteBypass, directResolvers, connSnapshot
 * @param {number} o.localPort   the web UI's port on 127.0.0.1
 * @param {string} o.uiToken     the web UI's token (injected into every proxied request)
 * @param {(line: string, level?: string) => void} [o.log]
 * @param {() => boolean} [o.tunnelUp]   default: service.connSnapshot() says connected with the gateway up
 * @param {() => number} [o.now]
 * @param {{lookup, resolve}} [o.dns]
 * @param {{connect, tls, socks}} [o.netImpl]
 * @param {{setTimeout, clearTimeout}} [o.timers]   the reconnect backoff only (tests fire it by hand)
 */
function createRemoteAgent(o) {
  const getSettings = o.getSettings || (() => ({}));
  const saveLastIps = o.saveLastIps || (() => {});
  const service = o.service || {};
  const log = o.log || (() => {});
  const dnsImpl = o.dns || defaultDns;
  const netImpl = o.netImpl || defaultNet;
  const timers = o.timers || { setTimeout, clearTimeout };
  const connectWs = o.wsConnect || wsConnect;
  const localPort = o.localPort;
  const uiToken = o.uiToken || '';
  let now = o.now || Date.now;
  const tunnelUp = o.tunnelUp || (() => {
    try {
      if (typeof service.connSnapshot === 'function') { const s = service.connSnapshot(); return !!(s && s.state === 'connected' && s.tun); }
    } catch { /* no opinion */ }
    return false;
  });
  const localAgent = new http.Agent({ keepAlive: true, maxSockets: 8 });

  let running = false;
  let gen = 0;                 // bumped by stop(): an attempt from before it is stale
  let conn = null;
  let keepalive = null;
  let lastSeen = 0;
  let retryTimer = null;
  let failures = 0;            // in a row, since the last online
  let directFailures = 0;      // in a row, while the tunnel was up
  let vpnMode = false;
  let lastDirectTry = 0;
  let state = 'off';
  let path = 'direct';
  let since = null;
  let lastError = null;
  let relayHost = null;
  const streams = new Map();   // stream id → { req, res, source, paused, headSent }

  /* ----------------------------- the link ----------------------------- */
  async function resolveHost(host, up, lastIps) {
    if (net.isIP(host)) return [host];
    let ips = [];
    let err = null;
    const servers = up && typeof service.directResolvers === 'function' ? (service.directResolvers() || []).filter((s) => net.isIP(s)) : [];
    if (servers.length) {
      try { ips = await dnsImpl.resolve(servers, host); }
      catch (e) { err = e; log(`remote: the direct resolvers could not resolve ${host} (${e.message}) — asking the system resolver`, 'warn'); }
    }
    if (!ips.length) {
      try { ips = await dnsImpl.lookup(host); } catch (e) { err = e; }
    }
    ips = unique((ips || []).filter((ip) => net.isIP(ip)));
    if (ips.length) return ips;
    const remembered = unique((lastIps || []).filter((ip) => net.isIP(ip)));
    if (remembered.length) {
      log(`remote: could not resolve ${host}${err ? ' (' + err.message + ')' : ''} — using the remembered address ${remembered.join(', ')}`, 'warn');
      return remembered;
    }
    throw new Error(`could not resolve ${host}: ${err ? err.message : 'no address'}`);
  }

  async function bypass(host, ips) {
    if (typeof service.setRemoteBypass !== 'function') return;
    try { await service.setRemoteBypass('relay', { hosts: [host], cidrs: ips.map(cidrOf) }); }
    catch (e) { log('remote: the bypass for the relay was not applied: ' + e.message, 'warn'); }
  }

  function clearBypass() {
    if (typeof service.setRemoteBypass !== 'function') return;
    try { Promise.resolve(service.setRemoteBypass('relay', { hosts: [], cidrs: [] })).catch(() => {}); } catch { /* best effort */ }
  }

  async function attempt(myGen) {
    const cfg = getSettings() || {};
    const token = String(cfg.token || '');
    let url = null;
    try { url = new URL(String(cfg.relayUrl || '')); } catch { url = null; }
    if (!url || url.protocol !== 'https:' || !url.hostname || !token) {
      running = false;
      state = 'error';
      lastError = 'the relay URL or the device token is not configured';
      log('remote: not started — ' + lastError, 'warn');
      return;
    }
    const host = url.hostname;
    const port = Number(url.port) || 443;
    relayHost = host;
    const up = tunnelUp();
    if (vpnMode && (!up || now() - lastDirectTry >= DIRECT_RETRY_MS)) vpnMode = false;   // direct again, every 10 min
    const useVpn = vpnMode && up;
    state = 'connecting';
    path = useVpn ? 'vpn' : 'direct';
    let ips = [];
    try {
      let socket;
      if (useVpn) {
        const socksPort = Number(typeof service.getSettings === 'function' && service.getSettings().socksPort) || 10808;
        log(`remote: dialing ${host}:${port} through the tunnel (SOCKS 127.0.0.1:${socksPort})`);
        socket = await netImpl.socks({ proxyPort: socksPort, host, port });
      } else {
        ips = await resolveHost(host, up, cfg.lastIps);
        if (myGen !== gen) return;
        await bypass(host, ips);
        if (myGen !== gen) return;
        const ip = ips[failures % ips.length];
        log(`remote: dialing ${host} (${ip}:${port}) direct${up ? ', past the tunnel' : ''}`);
        lastDirectTry = now();
        socket = await netImpl.connect({ host: ip, port });
      }
      if (myGen !== gen) { socket.destroy(); return; }
      const secure = await netImpl.tls({ socket, servername: host });
      if (myGen !== gen) { secure.destroy(); return; }
      const c = await connectWs(`wss://${host}${port === 443 ? '' : ':' + port}/_relay/agent`, { socket: secure, headers: { Authorization: 'Bearer ' + token }, timeoutMs: DIAL_TIMEOUT_MS });
      if (myGen !== gen) { c.close(1000, 'stale'); return; }
      online(c, useVpn ? 'vpn' : 'direct', host, ips, cfg);
    } catch (e) {
      if (myGen !== gen) return;
      const msg = `${useVpn ? 'the dial through the tunnel' : 'the direct dial'} to ${host} failed: ${describeError(e)}`;
      if (!useVpn && up) {
        directFailures++;
        if (directFailures >= DIRECT_FAILURES_BEFORE_VPN && !vpnMode) {
          vpnMode = true;
          log(`remote: ${directFailures} direct dials failed while the tunnel is up — the next one goes through the tunnel (via VPN); direct is tried again in ${DIRECT_RETRY_MS / 60000} min`, 'warn');
        }
      }
      if (e && (e.status === 401 || e.status === 403)) failures = Math.max(failures, BACKOFF_MS.length - 1);   // a dead token: no point hurrying
      scheduleRetry(msg);
    }
  }

  function online(c, p, host, ips, cfg) {
    conn = c;
    path = p;
    state = 'online';
    since = now();
    lastError = null;
    failures = 0;
    lastSeen = now();
    if (p === 'direct') {
      directFailures = 0;
      vpnMode = false;
      if (ips.length && !sameList(ips, cfg.lastIps)) { try { saveLastIps(ips); } catch { /* best effort */ } }
    }
    c.send(encode(T.HELLO, 0, { name: String(cfg.name || 'router').slice(0, 40), version: String(service.version || ''), path: p }));
    c.on('message', (buf) => { lastSeen = now(); onFrame(c, buf); });
    c.on('pong', () => { lastSeen = now(); });
    c.on('drain', () => { for (const s of streams.values()) if (s.paused) { const src = s.paused; s.paused = null; try { src.resume(); } catch { /* gone */ } } });
    c.on('close', (code, reason) => {
      if (conn !== c) return;
      conn = null;
      if (keepalive) { clearInterval(keepalive); keepalive = null; }
      for (const [id, s] of streams) { streams.delete(id); try { s.req.destroy(); } catch { /* gone */ } }
      if (!running) { state = 'off'; return; }
      scheduleRetry(`the link to ${host} closed (${code}${reason ? ', ' + reason : ''})`);
    });
    keepalive = setInterval(() => {
      if (conn !== c) return;
      if (now() - lastSeen > SILENT_MS) { log(`remote: the relay has been silent for ${SILENT_MS / 1000} s — redialing`, 'warn'); c.close(1001, 'silent'); return; }
      c.ping();
    }, PING_MS);
    if (keepalive.unref) keepalive.unref();
    log(`remote: online via ${p === 'vpn' ? 'the tunnel (VPN)' : 'direct'} — ${host}`);
  }

  function scheduleRetry(reason) {
    if (!running) return;
    state = 'connecting';
    lastError = reason;
    const base = BACKOFF_MS[Math.min(failures, BACKOFF_MS.length - 1)];
    failures++;
    const wait = Math.round(base * (1 + Math.random() * 0.3));
    log(`remote: ${reason} — next try in ${Math.round(wait / 1000)} s`, 'warn');   // one line per failed attempt, into syslog
    if (retryTimer) timers.clearTimeout(retryTimer);
    const myGen = gen;
    retryTimer = timers.setTimeout(() => { retryTimer = null; if (running && myGen === gen) attempt(myGen); }, wait);
    if (retryTimer && retryTimer.unref) retryTimer.unref();
  }

  /* ----------------------------- the streams ----------------------------- */
  function reply(c, id, status, text) {
    const body = Buffer.from(text, 'utf8');
    c.send(encode(T.RES_HEAD, id, { status, headers: { 'content-type': 'text/plain; charset=utf-8', 'content-length': String(body.length), 'cache-control': 'no-store' } }));
    c.send(encode(T.RES_BODY, id, body));
    c.send(encode(T.RES_END, id));
  }

  function onFrame(c, buf) {
    let f;
    try { f = decode(buf); } catch { return; }
    const s = streams.get(f.stream);
    switch (f.type) {
      case T.REQ_HEAD: {
        let head;
        try { head = f.json(); } catch { return; }
        if (!s) openStream(c, f.stream, head || {});
        return;
      }
      case T.REQ_BODY: if (s) { try { s.req.write(f.payload); } catch { /* ended */ } } return;
      case T.REQ_END: if (s) { try { s.req.end(); } catch { /* ended */ } } return;
      case T.CANCEL: if (s) { streams.delete(f.stream); try { s.req.destroy(); } catch { /* gone */ } } return;
      default: return;
    }
  }

  function openStream(c, id, head) {
    const method = String(head.method || 'GET').toUpperCase();
    const asked = String(head.path || '/');
    const u = normaliseTarget(asked);
    if (!u || forbiddenPath(asked)) { log(`remote: refused ${method} ${asked.slice(0, 80)} (not the web UI)`, 'warn'); reply(c, id, 403, 'forbidden'); return; }
    const target = u.pathname + u.search;   // the normalised form — what was judged is what is sent
    const inHeaders = head.headers && typeof head.headers === 'object' ? head.headers : {};
    const wantsGzip = /(^|,)\s*gzip\s*(;|,|$)/i.test(String(inHeaders['accept-encoding'] || ''));
    const headers = {};
    for (const [k, v] of Object.entries(inHeaders)) {
      const key = String(k).toLowerCase();
      if (HOP_BY_HOP.has(key) || key === 'x-irnetfree-token' || key === 'accept-encoding') continue;
      if (typeof v !== 'string') continue;
      headers[key] = v;
    }
    headers['x-irnetfree-token'] = uiToken;
    const s = { req: null, res: null, source: null, paused: null, headSent: false };
    const end = (sendEnd) => {
      if (!streams.has(id)) return;
      streams.delete(id);
      if (sendEnd && s.headSent) c.send(encode(T.RES_END, id));
    };
    let req;
    try { req = http.request({ host: '127.0.0.1', port: localPort, method, path: target, headers, agent: localAgent }); }
    catch (e) { reply(c, id, 502, 'bad request: ' + e.message); return; }
    s.req = req;
    streams.set(id, s);
    req.on('response', (res) => {
      if (!streams.has(id)) { res.destroy(); return; }
      s.res = res;
      const status = res.statusCode;
      const out = {};
      for (const [k, v] of Object.entries(res.headers)) if (!HOP_BY_HOP.has(k)) out[k] = v;
      const type = String(out['content-type'] || '');
      const sse = /^text\/event-stream/i.test(type);
      let source = res;
      if (wantsGzip && !sse && status === 200 && method !== 'HEAD' && !out['content-encoding'] && COMPRESSIBLE.test(type)) {
        delete out['content-length'];
        out['content-encoding'] = 'gzip';
        out.vary = out.vary ? out.vary + ', Accept-Encoding' : 'Accept-Encoding';
        source = res.pipe(zlib.createGzip({ level: 6 }));
      }
      s.source = source;
      s.headSent = true;
      c.send(encode(T.RES_HEAD, id, { status, headers: out }));
      source.on('data', (chunk) => {
        if (!streams.has(id)) return;
        c.send(encode(T.RES_BODY, id, chunk));
        if (c.bufferedAmount > HIGH_WATER && !s.paused) { s.paused = source; source.pause(); }
      });
      source.on('end', () => end(true));
      source.on('error', () => end(true));
      res.on('aborted', () => end(true));
    });
    req.on('error', (e) => {
      if (!streams.has(id)) return;
      if (!s.headSent) { streams.delete(id); reply(c, id, 502, 'the web UI did not answer: ' + e.message); return; }
      end(true);
    });
  }

  /* ----------------------------- control ----------------------------- */
  function start() {
    if (running) return;
    running = true;
    failures = 0;
    const myGen = ++gen;
    attempt(myGen);
  }

  function stop() {
    running = false;
    gen++;
    if (retryTimer) { timers.clearTimeout(retryTimer); retryTimer = null; }
    if (keepalive) { clearInterval(keepalive); keepalive = null; }
    for (const [id, s] of streams) { streams.delete(id); try { s.req.destroy(); } catch { /* gone */ } }
    if (conn) { const c = conn; conn = null; c.close(1000, 'stopped'); }
    state = 'off';
    lastError = null;
    since = null;
    vpnMode = false;
    directFailures = 0;
    clearBypass();
  }

  function reconfigure() { stop(); start(); }

  function status() {
    return {
      state,
      path: state === 'online' ? path : (vpnMode && tunnelUp() ? 'vpn' : 'direct'),
      since,
      lastError,
      relayHost,
      attempt: failures
    };
  }

  return { start, stop, reconfigure, status, link: () => conn, setClock: (fn) => { now = fn; } };
}

module.exports = { createRemoteAgent, BACKOFF_MS, forbiddenPath, normaliseTarget, describeError, DIRECT_RETRY_MS };
