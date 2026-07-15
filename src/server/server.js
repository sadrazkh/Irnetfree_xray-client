#!/usr/bin/env node
'use strict';
/**
 * IRNetFree headless server. Serves the EXACT same web UI as the desktop app over
 * a local HTTP port and bridges it to the core service (../server/service.js)
 * with a small RPC + Server-Sent-Events layer — no Electron, no extra npm deps.
 *
 * Usage:
 *   node src/server/server.js [--port 6969] [--host 127.0.0.1] [--token SECRET]
 *                             [--data-dir /path] [--open]
 *
 * Security: binds to 127.0.0.1 by default (reach it via `ssh -L`). If you bind to
 * 0.0.0.0 a token is required (auto-generated + printed when you don't pass one).
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { createService } = require('./service');

/* ----------------------------- CLI args ----------------------------- */
function parseArgs(argv) {
  const a = { port: 6969, host: '127.0.0.1', token: null, dataDir: null, noAuth: false };
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i];
    const val = () => argv[++i];
    if (k === '--port' || k === '-p') a.port = parseInt(val(), 10) || a.port;
    else if (k === '--host' || k === '-h') a.host = val();
    else if (k === '--token' || k === '-t') a.token = val();
    else if (k === '--data-dir' || k === '-d') a.dataDir = val();
    else if (k === '--no-auth') a.noAuth = true;
  }
  return a;
}
const args = parseArgs(process.argv.slice(2));
const isLoopback = args.host === '127.0.0.1' || args.host === '::1' || args.host === 'localhost';
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
const sseClients = new Set();
service.onEvent((channel, payload) => {
  const line = 'data: ' + JSON.stringify({ channel, payload }) + '\n\n';
  for (const res of sseClients) { try { res.write(line); } catch {} }
});

/* ----------------------------- auth ----------------------------- */
function authed(req, url) {
  if (!TOKEN) return true;
  const q = url.searchParams.get('token');
  const h = req.headers['x-irnetfree-token'];
  return q === TOKEN || h === TOKEN;
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
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const pathname = url.pathname;

  // RPC: POST /rpc {channel, arg}
  if (pathname === '/rpc' && req.method === 'POST') {
    if (!authed(req, url)) return sendJson(res, 401, { error: 'unauthorized' });
    try {
      const { channel, arg } = JSON.parse(await readBody(req) || '{}');
      const result = await service.invoke(channel, arg);
      return sendJson(res, 200, { result: result === undefined ? null : result });
    } catch (e) { return sendJson(res, 200, { error: e.message || String(e) }); }
  }

  // Server-Sent Events: GET /events
  if (pathname === '/events') {
    if (!authed(req, url)) return sendJson(res, 401, { error: 'unauthorized' });
    res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
    res.write('retry: 3000\n\n');
    sseClients.add(res);
    const ping = setInterval(() => { try { res.write(': ping\n\n'); } catch {} }, 25000);
    req.on('close', () => { clearInterval(ping); sseClients.delete(res); });
    return;
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
  const q = TOKEN ? ('?token=' + TOKEN) : '';
  console.log('');
  console.log('  IRNetFree server (headless) — v' + service.version);
  console.log('  Data dir : ' + service.dataDir);
  console.log('  Listening: http://' + shown + ':' + args.port + '/' + q);
  if (isLoopback) {
    console.log('');
    console.log('  This is bound to localhost. From your machine, forward the port:');
    console.log('    ssh -N -L ' + args.port + ':127.0.0.1:' + args.port + ' user@SERVER');
    console.log('  then open  http://127.0.0.1:' + args.port + '/  in your browser.');
  } else if (TOKEN) {
    console.log('  Bound to a public interface — a token is required (in the URL above).');
  }
  console.log('');
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
