'use strict';
/**
 * The tunnel's live connections, by app — the Logs page's «اتصال‌ها» /
 * "Connections" tab (src/renderer/connections.js): which program is connected
 * where right now, how much it sent and received, and which way it went.
 *
 * A desktop's sing-box TUN runs with its loopback API (tunSingbox.js `watch`:
 * `experimental.clash_api` on 127.0.0.1 with a secret) and with
 * `route.find_process`, so every connection it tracks names the program that
 * opened it. GET /connections lists them; DELETE /connections/{id} closes one.
 * What a real sing-box 1.14.4 answers (a request from node through a mixed
 * inbound, read back): `metadata.processPath` "C:\Program Files\nodejs\node.exe",
 * `metadata.host` (the name asked, '' for a bare address), `destinationIP`,
 * `destinationPort` (a string), `network`, `upload` / `download` (bytes so far),
 * `start` (RFC 3339 with nanoseconds and the zone), `chains` (the outbound tags
 * it took, the last one dialled), `rule` ("final", or the rule that sent it);
 * beside the list `uploadTotal` / `downloadTotal`, every byte since the start.
 * A DELETE answers 204 — for an id that is gone too. A wrong secret is a 401.
 *
 * Nothing here runs by itself: each read is one call from the page, which asks
 * every ~1.5 s while the tab is open and the tunnel is up — so nothing reads
 * when nobody looks. Rates are the bytes between two reads over the time
 * between them; a second reader within MIN_READ_MS (the router's page open in
 * two tabs) is handed the last answer instead of a rate over a sliver of time.
 *
 * Desktop (main.js) and the headless service (service.js) alike: no Electron,
 * no store; the caller says whether it is connected and which tunnel runs.
 */
const http = require('http');

const API_TIMEOUT_MS = 2500;
/** Reads closer together than this share one answer. */
const MIN_READ_MS = 700;
/** The connections listed per app, newest first; the rest are counted (`more`). */
const MAX_PER_APP = 200;
/** A tracker's id as sing-box makes it (a UUID) — anything else is never sent on. */
const ID_RE = /^[A-Za-z0-9-]{1,64}$/;

const num = (v) => { const n = Number(v); return Number.isFinite(n) && n > 0 ? n : 0; };

/**
 * One call to the tunnel's API → { status, body }. `request` is http.request's
 * shape (a test's fake); the secret goes in the header, never the URL.
 */
function apiCall(watch, method, path, request) {
  return new Promise((resolve, reject) => {
    const req = (request || http.request)({ host: '127.0.0.1', port: watch.port, path, method, headers: { Authorization: 'Bearer ' + watch.secret }, timeout: API_TIMEOUT_MS }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (d) => { body += d; if (body.length > 16 * 1024 * 1024) req.destroy(new Error('too big')); });
      res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    req.on('timeout', () => req.destroy(new Error('timed out')));
    req.on('error', reject);
    req.end();
  });
}

/** GET /connections → the whole answer ({ connections, uploadTotal, downloadTotal }); throws on no answer or not 200. */
async function fetchSnapshot(watch, request) {
  const r = await apiCall(watch, 'GET', '/connections', request);
  if (r.status !== 200) throw new Error('HTTP ' + r.status);
  const j = JSON.parse(r.body);
  return { connections: Array.isArray(j && j.connections) ? j.connections : [], uploadTotal: num(j && j.uploadTotal), downloadTotal: num(j && j.downloadTotal) };
}

/**
 * The program's file name from sing-box's processPath: 'chrome.exe',
 * 'firefox'; '' when it named none. sing-box adds the owner after the path
 * where it knows one — "/usr/bin/curl (sadra)", "… (1000)" — and a bare user
 * id when it found no path; neither is a program.
 */
function appOf(processPath) {
  let p = String(processPath == null ? '' : processPath).trim();
  if (/[\\/]/.test(p)) p = p.replace(/ \([^()\\/]*\)$/, '');
  else if (/^\d+$/.test(p)) return '';
  return p.split(/[\\/]/).pop() || '';
}

/** Where a connection goes, as people read it: the name it asked for, else the address — with the port. */
function destOf(m) {
  const port = m.destinationPort ? String(m.destinationPort) : '';
  const host = typeof m.host === 'string' && m.host ? m.host : String(m.destinationIP || '');
  if (!port) return host;
  return (host.includes(':') ? `[${host}]` : host) + ':' + port;
}

/**
 * Why there is nothing to show, in the order a person fixes it: not connected,
 * connected without the TUN, a TUN that cannot say (tun2socks has no API; the
 * native macOS backend's config is the daemon's, not ours), a router (its
 * tunnel carries the LAN's devices, not programs of its own).
 */
function unavailable(o) {
  if (o.router) return { available: false, reason: 'router' };
  if (!o.connected()) return { available: false, reason: 'off' };
  const tun = o.tun();
  if (!tun) return { available: false, reason: 'noTun' };
  if (!tun.watch) return { available: false, reason: 'backend', backend: tun.native ? 'native-macos' : String(tun.backendId || '') };
  return null;
}

/**
 * @param {object} o
 *   connected()  is a connection up (the core running, a target chosen)
 *   tun()        the live tunnel (its backend: `watch`, `backendId`, `native`), or null
 *   router       the router's service: never anything to show
 *   request      http.request's shape (a test's fake)
 *   now()
 * → { read() → Promise<payload>, close(id) → Promise<{ ok, error? }> }
 *
 * payload: { available: false, reason: 'router'|'off'|'noTun'|'backend'|'error', backend?, error? }
 *   or { available: true, at, processes, apps: [{ app, paths, count, more, upload, download, up, down,
 *        connections: [{ id, dest, ip, network, source, upload, download, up, down, start, age, outbound, chain, rule }] }],
 *        totals: { count, upload, download, up, down } }
 * — `up` / `down` are bytes per second since the read before (0 on the first), `processes` says whether
 * any connection named its program (false: grouped under '' — the page says why).
 */
function createConnectionsWatch(o) {
  const opts = Object.assign({ connected: () => false, tun: () => null, router: false }, o || {});
  const now = typeof opts.now === 'function' ? opts.now : () => Date.now();
  let secret = '';
  let last = null;       // { at, bytes: Map(id → { up, down }), up, down } of the read before
  let answer = null;     // the last payload, for a reader within MIN_READ_MS
  let busy = null;       // a read on its way: a second caller waits for it

  function reset() { last = null; answer = null; }

  function build(snap, t) {
    const dt = last ? (t - last.at) / 1000 : 0;
    const rate = (nowBytes, before) => (dt > 0 && nowBytes >= before ? (nowBytes - before) / dt : 0);
    const bytes = new Map();
    const byApp = new Map();
    let processes = false;
    for (const c of snap.connections) {
      if (!c || typeof c.id !== 'string' || !c.id) continue;
      const m = c.metadata && typeof c.metadata === 'object' ? c.metadata : {};
      const upload = num(c.upload), download = num(c.download);
      const start = Date.parse(c.start) || 0;
      // seen at the read before: what it moved since; new since then: all of it moved since
      const prev = last && last.bytes.get(c.id);
      const fresh = !prev && last && start >= last.at;
      const up = prev ? rate(upload, prev.up) : fresh ? rate(upload, 0) : 0;
      const down = prev ? rate(download, prev.down) : fresh ? rate(download, 0) : 0;
      bytes.set(c.id, { up: upload, down: download });
      const app = appOf(m.processPath);
      if (app) processes = true;
      const chain = Array.isArray(c.chains) ? c.chains.filter((x) => typeof x === 'string') : [];
      const conn = {
        id: c.id, dest: destOf(m), ip: String(m.destinationIP || ''), network: String(m.network || ''), source: String(m.sourceIP || ''),
        upload, download, up, down, start, age: start ? Math.max(0, t - start) : 0,
        outbound: chain.length ? chain[chain.length - 1] : '', chain, rule: typeof c.rule === 'string' ? c.rule : ''
      };
      let g = byApp.get(app);
      if (!g) byApp.set(app, (g = { app, paths: [], count: 0, more: 0, upload: 0, download: 0, up: 0, down: 0, connections: [] }));
      const p = String(m.processPath || '');
      if (app && p && g.paths.length < 3 && !g.paths.includes(p)) g.paths.push(p);
      g.count++;
      g.upload += upload; g.download += download; g.up += up; g.down += down;
      g.connections.push(conn);
    }
    const apps = [...byApp.values()];
    for (const g of apps) {
      g.connections.sort((x, y) => y.start - x.start || (x.id < y.id ? -1 : 1));
      if (g.connections.length > MAX_PER_APP) { g.more = g.connections.length - MAX_PER_APP; g.connections.length = MAX_PER_APP; }
    }
    // the busiest first, by what their open connections carried; the unnamed last
    apps.sort((x, y) => (x.app === '') - (y.app === '') || (y.upload + y.download) - (x.upload + x.download) || x.app.localeCompare(y.app, 'en'));
    // the totals' rates count the connections that ended in between too (sing-box's own running totals)
    const totals = {
      count: apps.reduce((s, g) => s + g.count, 0),
      upload: apps.reduce((s, g) => s + g.upload, 0),
      download: apps.reduce((s, g) => s + g.download, 0),
      up: last ? rate(snap.uploadTotal, last.up) : 0,
      down: last ? rate(snap.downloadTotal, last.down) : 0
    };
    last = { at: t, bytes, up: snap.uploadTotal, down: snap.downloadTotal };
    return { available: true, at: t, processes, apps, totals };
  }

  async function readNow() {
    const why = unavailable(opts);
    if (why) { reset(); secret = ''; return why; }
    const watch = opts.tun().watch;
    // a new tunnel's API: its ids, its totals are its own
    if (watch.secret !== secret) { reset(); secret = watch.secret; }
    const t = now();
    if (answer && t - answer.at < MIN_READ_MS) return answer;
    try {
      answer = build(await fetchSnapshot(watch, opts.request), t);
      return answer;
    } catch (e) {
      reset();
      return { available: false, reason: 'error', error: (e && e.message) || 'no answer' };
    }
  }

  function read() {
    if (busy) return busy;
    busy = readNow().finally(() => { busy = null; });
    return busy;
  }

  /** DELETE /connections/{id}: the program sees its connection reset. → { ok } or { ok: false, error } */
  async function close(id) {
    const why = unavailable(opts);
    if (why) return { ok: false, error: why.reason };
    if (typeof id !== 'string' || !ID_RE.test(id)) return { ok: false, error: 'bad id' };
    try {
      const r = await apiCall(opts.tun().watch, 'DELETE', '/connections/' + encodeURIComponent(id), opts.request);
      if (r.status !== 204 && r.status !== 200) return { ok: false, error: 'HTTP ' + r.status };
      answer = null;   // the next read shows it gone
      return { ok: true };
    } catch (e) {
      return { ok: false, error: (e && e.message) || 'no answer' };
    }
  }

  return { read, close };
}

module.exports = { createConnectionsWatch, fetchSnapshot, appOf, destOf, MIN_READ_MS, MAX_PER_APP };
