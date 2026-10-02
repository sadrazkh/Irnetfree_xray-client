#!/usr/bin/env node
'use strict';
/**
 * IRNetFree headless server. Serves the EXACT same web UI as the desktop app over
 * a local HTTP port and bridges it to the core service (../server/service.js)
 * with a small RPC + Server-Sent-Events layer — no Electron, no extra npm deps.
 *
 * Usage:
 *   node src/server/server.js [--port 6969] [--host 127.0.0.1] [--token SECRET]
 *                             [--token-file /path] [--data-dir /path] [--open]
 *
 * Security: binds to 127.0.0.1 by default (reach it via `ssh -L`). If you bind to
 * 0.0.0.0 a token is required (auto-generated + printed when you don't pass one).
 * `--token-file` reads it from a file (made there, root-only, when missing) and
 * never prints it — the router's init script uses that, because procd hands
 * this process's output to syslog.
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { createService } = require('./service');
const { hostAllowed, originAllowed } = require('./guard');
const { createLuciApi, isLoopbackPeer } = require('./luciApi');

// Every line this process writes starts with `irnetfree:` (v1.16 S5): under
// procd the lines are syslog, and `logread -e irnetfree` must find the
// banner, the shutdown, a stray rejection and a fatal error too — not only
// the service's own tagged lines. Blank lines (a terminal's cosmetics) are
// dropped; a chunk without its newline is continued by the next write.
function prefixed(stream) {
  const write = stream.write.bind(stream);
  let midLine = false;
  stream.write = function (chunk, encoding, cb) {
    if (typeof encoding === 'function') { cb = encoding; encoding = undefined; }
    const text = Buffer.isBuffer(chunk) ? chunk.toString('utf8') : String(chunk);
    const parts = text.split('\n');
    let out = '';
    for (let i = 0; i < parts.length; i++) {
      const last = i === parts.length - 1;
      const line = parts[i];
      if (last && line === '') break;              // the chunk ended with its newline
      if (!midLine && line === '') continue;       // a blank line
      out += (midLine || line.startsWith('irnetfree:') ? line : 'irnetfree: ' + line) + (last ? '' : '\n');
      midLine = last;
    }
    if (!out) { if (cb) process.nextTick(cb); return true; }
    return write(out, encoding, cb);
  };
}
for (const s of [process.stdout, process.stderr]) prefixed(s);

// A stray rejection anywhere in the service must not end the process: on a
// router this process IS the gateway, and Node ≥ 15 exits on an unhandled one
// (the exit hook then tears the tunnel down). Logged, and the service goes on.
process.on('unhandledRejection', (e) => {
  console.error('  ! unhandled rejection (the service keeps running): ' + ((e && e.stack) || e));
});
// Under procd stdout/stderr are pipes into syslog, and the service writes its
// warnings there: a pipe that breaks must not become an uncaught 'error'.
for (const s of [process.stdout, process.stderr]) s.on('error', () => {});

/* ----------------------------- CLI args ----------------------------- */
function parseArgs(argv) {
  const a = { port: 6969, host: '127.0.0.1', token: null, tokenFile: null, dataDir: null, noAuth: false };
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i];
    const val = () => argv[++i];
    // 0 is a real answer: an ephemeral port (the tests use it)
    if (k === '--port' || k === '-p') { const n = parseInt(val(), 10); if (Number.isInteger(n) && n >= 0) a.port = n; }
    else if (k === '--host' || k === '-h') a.host = val();
    else if (k === '--token' || k === '-t') a.token = val();
    else if (k === '--token-file') a.tokenFile = val();
    else if (k === '--data-dir' || k === '-d') a.dataDir = val();
    else if (k === '--no-auth') a.noAuth = true;
  }
  return a;
}

/** The token in `file`, or a new one written there (0600) when it is missing or empty. */
function tokenFromFile(file) {
  let t = '';
  try { t = fs.readFileSync(file, 'utf8').trim(); } catch { /* made below */ }
  if (t) return t;
  t = crypto.randomBytes(16).toString('hex');
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, t + '\n', { mode: 0o600 });
  return t;
}

const args = parseArgs(process.argv.slice(2));
const isLoopback = args.host === '127.0.0.1' || args.host === '::1' || args.host === 'localhost';
if (args.tokenFile && !args.token) {
  try { args.token = tokenFromFile(args.tokenFile); }
  catch (e) { console.error('\n  Cannot read or create the token file ' + args.tokenFile + ': ' + e.message + '\n'); process.exit(1); }
}
// Non-loopback bind must be authenticated; make a token if the user didn't set one.
if (!isLoopback && !args.token && !args.noAuth) {
  args.token = crypto.randomBytes(16).toString('hex');
}
const TOKEN = args.token;

/* ----------------------------- paths / mime ----------------------------- */
const RENDERER = path.join(__dirname, '..', 'renderer');
const ASSETS = path.join(__dirname, '..', '..', 'assets');
const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon', '.woff2': 'font/woff2', '.woff': 'font/woff'
};
const mimeFor = (p) => MIME[path.extname(p).toLowerCase()] || 'application/octet-stream';

// index.html with the web-api bridge injected before the app scripts.
function indexHtml() {
  let html = fs.readFileSync(path.join(RENDERER, 'index.html'), 'utf8');
  html = html.replace('<script src="i18n.js"></script>', '<script src="web-api.js"></script>\n  <script src="i18n.js"></script>');
  return html;
}

/* ----------------------------- service ----------------------------- */
const service = createService({ dataDir: args.dataDir });
// An uncaught exception used to be the end: node died, the exit hook tore the
// tunnel down, and after five such deaths in an hour procd gave up on the
// service — a router with no gateway until someone restarted it by hand (S5).
// Now it is said with the prefix, the gateway goes down in order (capped at
// 10 s), the process exits 1, and procd (respawn 3600 5 0: never giving up)
// brings the service back — which reconnects by itself.
process.on('uncaughtException', (e) => {
  console.error('irnetfree: [fatal] ' + ((e && e.stack) || e) + ' — shutting down for procd to restart the service');
  const cap = setTimeout(() => process.exit(1), 10000);
  cap.unref();
  Promise.resolve().then(() => service.shutdown()).catch(() => {}).then(() => process.exit(1));
});
const sseClients = new Set();
service.onEvent((channel, payload) => {
  const line = 'data: ' + JSON.stringify({ channel, payload }) + '\n\n';
  for (const res of sseClients) { try { res.write(line); } catch {} }
});

// The LuCI facade: POST /luci/<method>, loopback only, token in the body
// (see luciApi.js). feat/remote mounts its api here from its start hook —
// a getter, so a mount after this line still reaches the facade.
let remoteApi = null;
const luci = createLuciApi({ service, remoteApi: () => remoteApi });

/* ----------------------------- auth ----------------------------- */
/** `a` equals the token, in constant time (a string of another length is simply wrong). */
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const x = Buffer.from(a, 'utf8');
  const y = Buffer.from(b, 'utf8');
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
function authed(req, url) {
  if (!TOKEN) return true;
  const q = url.searchParams.get('token');
  const h = req.headers['x-irnetfree-token'];
  return safeEqual(q, TOKEN) || safeEqual(h, TOKEN);
}

/* ----------------------------- helpers ----------------------------- */
function sendJson(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(body) });
  res.end(body);
}
function sendFile(res, file) {
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404); res.end('not found'); return; }
    res.writeHead(200, { 'Content-Type': mimeFor(file), 'Cache-Control': 'no-cache' });
    res.end(data);
  });
}
function readBody(req) {
  return new Promise((resolve) => {
    let b = ''; req.on('data', c => { b += c; if (b.length > 5e6) req.destroy(); });
    req.on('end', () => resolve(b));
  });
}

/* ----------------------------- request router ----------------------------- */
async function handle(req, res) {
  // DNS-rebinding guard: without a token only loopback Host values are served.
  // --no-auth waives the token, not this guard: on a loopback bind the Host set
  // is enforced anyway (see guard.js), so pass the bind's loopback-ness in.
  if (!hostAllowed(req.headers.host, { token: TOKEN, noAuth: args.noAuth, loopbackBind: isLoopback })) {
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    return res.end('forbidden host');
  }
  // A request target that is not a path (`//x:99999/`, `//[`, `http://[`)
  // makes URL throw — and this runs before the token check, so it was the way
  // any host on the LAN could stop the service. A 400, not a crash.
  let url;
  try { url = new URL(req.url, 'http://localhost'); }
  catch {
    res.writeHead(400, { 'Content-Type': 'text/plain' });
    return res.end('bad request');
  }
  const pathname = url.pathname;

  // RPC: POST /rpc {channel, arg}
  if (pathname === '/rpc' && req.method === 'POST') {
    if (!authed(req, url)) return sendJson(res, 401, { error: 'unauthorized' });
    if (!originAllowed(req.headers)) return sendJson(res, 403, { error: 'cross-origin request refused' });
    try {
      const { channel, arg } = JSON.parse(await readBody(req) || '{}');
      const result = await service.invoke(channel, arg);
      return sendJson(res, 200, { result: result === undefined ? null : result });
    } catch (e) { return sendJson(res, 200, { error: e.message || String(e) }); }
  }

  // Server-Sent Events: GET /events
  if (pathname === '/events') {
    if (!authed(req, url)) return sendJson(res, 401, { error: 'unauthorized' });
    if (!originAllowed(req.headers)) return sendJson(res, 403, { error: 'cross-origin request refused' });
    res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
    res.write('retry: 3000\n\n');
    // The connection as it IS, first — on every (re)connect of the stream: a
    // browser whose EventSource dropped and came back (a phone's background
    // tab) missed whatever happened meanwhile, and nothing else would replay it.
    res.write('data: ' + JSON.stringify({ channel: 'conn:snapshot', payload: service.connSnapshot() }) + '\n\n');
    sseClients.add(res);
    const ping = setInterval(() => { try { res.write(': ping\n\n'); } catch {} }, 25000);
    req.on('close', () => { clearInterval(ping); sseClients.delete(res); });
    return;
  }

  // The LuCI facade: POST /luci/<method> {token, arg} — from this machine
  // only (the rpcd plugin), the token in the body, never in the URL.
  if (pathname.startsWith('/luci/')) {
    if (!isLoopbackPeer(req.socket && req.socket.remoteAddress)) return sendJson(res, 403, { error: 'loopback only' });
    if (req.method !== 'POST') return sendJson(res, 405, { error: 'POST only' });
    let body;
    try { body = JSON.parse(await readBody(req)); } catch { body = null; }
    if (!body || typeof body !== 'object' || Array.isArray(body)) return sendJson(res, 400, { error: 'a JSON object {token, arg} is required' });
    if (TOKEN && !safeEqual(body.token, TOKEN)) return sendJson(res, 401, { error: 'unauthorized' });
    try {
      const result = await luci.handle(pathname.slice('/luci/'.length), body.arg);
      return sendJson(res, 200, result === undefined ? {} : result);
    } catch (e) {
      // Only an unknown method is an HTTP error. Whatever a method itself
      // refuses or throws (a setting it will not take, remote_set's Error)
      // travels as 200 {error}: uclient-fetch — what the rpcd plugin fetches
      // with — drops the body of every non-2xx reply, and LuCI would see
      // nothing but "HTTP 400".
      if (e && e.code === 404) return sendJson(res, 404, { error: e.message || 'unknown method' });
      return sendJson(res, 200, { error: (e && e.message) || String(e) });
    }
  }

  // Static: only GET
  if (req.method !== 'GET') { res.writeHead(405); return res.end('method not allowed'); }
  // The page itself is gated too (so a token is needed to even load the UI).
  if ((pathname === '/' || pathname === '/index.html')) {
    if (!authed(req, url)) { res.writeHead(401, { 'Content-Type': 'text/plain' }); return res.end('unauthorized — open with ?token=...'); }
    const html = indexHtml();
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache' });
    return res.end(html);
  }
  if (pathname === '/web-api.js') return sendFile(res, path.join(__dirname, 'web-api.js'));

  // /assets/* -> project assets dir
  if (pathname.startsWith('/assets/')) {
    const rel = pathname.slice('/assets/'.length);
    const file = path.join(ASSETS, rel);
    if (!file.startsWith(ASSETS)) { res.writeHead(403); return res.end('forbidden'); }
    return sendFile(res, file);
  }

  // otherwise a renderer file (app.js, i18n.js, styles.css, …)
  const safe = path.normalize(pathname).replace(/^(\.\.[/\\])+/, '');
  const file = path.join(RENDERER, safe);
  if (!file.startsWith(RENDERER)) { res.writeHead(403); return res.end('forbidden'); }
  return sendFile(res, file);
}

// The handler is async: whatever it throws becomes a rejection, and one nobody
// catches ends the process. Every request goes through this one catch — a 500
// while nothing has been sent, otherwise the response is simply ended. (The
// URL is not logged: it can carry the token.)
const server = http.createServer((req, res) => {
  handle(req, res).catch((e) => {
    console.error('  ! request failed: ' + ((e && e.message) || e));
    try {
      if (!res.headersSent) res.writeHead(500, { 'Content-Type': 'text/plain' });
      res.end();
    } catch { /* the socket is gone */ }
  });
});

server.on('error', (e) => {
  if (e.code === 'EADDRINUSE') {
    console.error('\n  Port ' + args.port + ' is already in use. Pick another with --port <n>.\n');
  } else {
    console.error('\n  Server error: ' + (e.message || e) + '\n');
  }
  process.exit(1);
});

server.listen(args.port, args.host, () => {
  const shown = isLoopback ? '127.0.0.1' : args.host;
  const port = server.address().port;   // the real one when --port 0 asked for any
  // remote access (spec §3.5): the relay link and Cloudflare Tunnel, started from <data_dir>/remote.json; never throws
  require('./remote/api').start({ service, localPort: port, uiToken: TOKEN });
  // A token that lives in a file is never printed: on a router this output is
  // syslog (procd), and the file is where LuCI and the installer read it from.
  const q = TOKEN && !args.tokenFile ? ('?token=' + TOKEN) : '';
  console.log('');
  console.log('  IRNetFree server (headless) — v' + service.version);
  console.log('  Data dir : ' + service.dataDir);
  console.log('  Listening: http://' + shown + ':' + port + '/' + q);
  if (TOKEN && args.tokenFile) {
    console.log('  Token    : ' + args.tokenFile + '  (open http://<this host>:' + port + '/?token=<the token in that file>)');
  }
  if (isLoopback) {
    console.log('');
    console.log('  This is bound to localhost. From your machine, forward the port:');
    console.log('    ssh -N -L ' + port + ':127.0.0.1:' + port + ' user@SERVER');
    console.log('  then open  http://127.0.0.1:' + port + '/  in your browser.');
  } else if (TOKEN) {
    console.log('  Bound to a public interface — a token is required' + (args.tokenFile ? ' (in the file above).' : ' (in the URL above).'));
  }
  console.log('');
  // a test's way to make the service throw from a timer (tests/serverRequest.test.js): the fatal path above must end the process
  if (process.env.IRNETFREE_TEST_THROW_MS) {
    setTimeout(() => { throw new Error('IRNETFREE_TEST_THROW_MS: a test-made uncaught exception'); }, Number(process.env.IRNETFREE_TEST_THROW_MS) || 100);
  }
});

/* ----------------------------- lifecycle ----------------------------- */
async function stop(sig) {
  console.log('\nShutting down (' + sig + ')…');
  try { await service.shutdown(); } catch {}
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 3000);
}
process.on('SIGINT', () => stop('SIGINT'));
process.on('SIGTERM', () => stop('SIGTERM'));
