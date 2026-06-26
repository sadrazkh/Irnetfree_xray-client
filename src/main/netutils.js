'use strict';
/**
 * Network utilities:
 *  - tcpPing(host, port)            -> TCP handshake latency (ms)
 *  - httpThroughProxy(socksPort)    -> real delay measured through a running proxy
 *  - ipInfo(socksPort?)             -> current egress IP + country (direct or via proxy)
 */

const net = require('net');
const http = require('http');
const { SocksClient } = requireOptional('socks');

function requireOptional(name) {
  try { return require(name); } catch { return {}; }
}

/**
 * Measure raw TCP connect time to host:port.
 */
function tcpPing(host, port, timeout = 4000) {
  return new Promise((resolve) => {
    const start = Date.now();
    const socket = new net.Socket();
    let done = false;

    const finish = (result) => {
      if (done) return;
      done = true;
      try { socket.destroy(); } catch {}
      resolve(result);
    };

    socket.setTimeout(timeout);
    socket.once('connect', () => finish({ ok: true, ms: Date.now() - start }));
    socket.once('timeout', () => finish({ ok: false, ms: -1, error: 'timeout' }));
    socket.once('error', (e) => finish({ ok: false, ms: -1, error: e.code || e.message }));

    socket.connect(port, host);
  });
}

/**
 * Make an HTTP request through a local SOCKS5 proxy and time it.
 * Uses the `socks` package if available; otherwise does a manual SOCKS5 CONNECT.
 * Target is a small, fast endpoint that returns 204.
 */
function httpThroughProxy(socksPort, opts = {}) {
  const targetHost = opts.host || 'cp.cloudflare.com';
  const targetPort = opts.port || 80;
  const targetPath = opts.path || '/';
  const timeout = opts.timeout || 8000;

  return new Promise(async (resolve) => {
    const start = Date.now();
    let socket;
    try {
      socket = await socks5Connect('127.0.0.1', socksPort, targetHost, targetPort, timeout);
    } catch (e) {
      return resolve({ ok: false, ms: -1, error: e.message });
    }

    let done = false;
    const finish = (r) => { if (done) return; done = true; try { socket.destroy(); } catch {} resolve(r); };
    const to = setTimeout(() => finish({ ok: false, ms: -1, error: 'timeout' }), timeout);

    socket.write(
      `GET ${targetPath} HTTP/1.1\r\nHost: ${targetHost}\r\nUser-Agent: XrayClient\r\nConnection: close\r\n\r\n`
    );
    let buf = '';
    socket.on('data', (d) => {
      buf += d.toString('utf8');
      if (buf.includes('\r\n')) {
        clearTimeout(to);
        const statusLine = buf.split('\r\n')[0];
        const m = statusLine.match(/HTTP\/\d\.\d\s+(\d+)/);
        const code = m ? parseInt(m[1], 10) : 0;
        finish({ ok: code > 0 && code < 500, ms: Date.now() - start, status: code });
      }
    });
    socket.on('error', (e) => { clearTimeout(to); finish({ ok: false, ms: -1, error: e.code || e.message }); });
    socket.on('close', () => { clearTimeout(to); finish({ ok: false, ms: -1, error: 'closed' }); });
  });
}

/**
 * Minimal SOCKS5 CONNECT handshake (no auth). Resolves with a connected socket
 * already tunnelled to target host:port.
 */
function socks5Connect(proxyHost, proxyPort, destHost, destPort, timeout = 8000) {
  return new Promise((resolve, reject) => {
    const socket = new net.Socket();
    let stage = 0;
    socket.setTimeout(timeout);

    socket.once('timeout', () => { socket.destroy(); reject(new Error('socks timeout')); });
    socket.once('error', (e) => reject(e));

    socket.connect(proxyPort, proxyHost, () => {
      // greeting: VER=5, NMETHODS=1, METHOD=0 (no auth)
      socket.write(Buffer.from([0x05, 0x01, 0x00]));
    });

    socket.on('data', (data) => {
      if (stage === 0) {
        if (data[0] !== 0x05 || data[1] !== 0x00) {
          socket.destroy(); return reject(new Error('socks auth rejected'));
        }
        stage = 1;
        // CONNECT request, ATYP=3 (domain)
        const hostBuf = Buffer.from(destHost, 'utf8');
        const req = Buffer.concat([
          Buffer.from([0x05, 0x01, 0x00, 0x03, hostBuf.length]),
          hostBuf,
          Buffer.from([(destPort >> 8) & 0xff, destPort & 0xff])
        ]);
        socket.write(req);
      } else if (stage === 1) {
        if (data[1] !== 0x00) {
          socket.destroy(); return reject(new Error('socks connect failed code ' + data[1]));
        }
        stage = 2;
        socket.setTimeout(0);
        socket.removeAllListeners('data');
        resolve(socket);
      }
    });
  });
}

/**
 * Multiple geo-IP providers (HTTP, so they work through a raw SOCKS tunnel).
 * Each maps its JSON shape to our normalized result. We try them in order so a
 * single flaky/rate-limited/blocked endpoint doesn't break the whole IP check.
 */
const IP_SERVICES = [
  {
    host: 'ip-api.com',
    path: '/json/?fields=status,country,countryCode,city,isp,query',
    map: (j) => ({ ok: j.status === 'success', ip: j.query, country: j.country, countryCode: j.countryCode, city: j.city, isp: j.isp })
  },
  {
    host: 'ipwho.is',
    path: '/?fields=success,ip,country,country_code,city,connection',
    map: (j) => ({ ok: j.success !== false && !!j.ip, ip: j.ip, country: j.country, countryCode: j.country_code, city: j.city, isp: j.connection && j.connection.isp })
  },
  {
    host: 'ipinfo.io',
    path: '/json',
    map: (j) => ({ ok: !!j.ip, ip: j.ip, country: j.country, countryCode: j.country, city: j.city, isp: j.org })
  }
];

/**
 * Get current egress IP + geo. If socksPort is provided, queries through the
 * proxy. Tries several providers and tolerates chunked / partial responses.
 */
async function ipInfo(socksPort) {
  let lastErr = 'no response';
  for (const svc of IP_SERVICES) {
    try {
      const body = socksPort
        ? await httpGetViaSocks(socksPort, svc.host, svc.path, 9000)
        : await httpGetDirect(svc.host, svc.path, 9000);
      const json = parseJsonLoose(body);
      if (!json) { lastErr = 'parse'; continue; }
      const res = svc.map(json);
      if (res && res.ok && res.ip) return res;
      lastErr = (res && res.error) || 'no ip';
    } catch (e) {
      lastErr = e.code || e.message || String(e);
    }
  }
  return { ok: false, error: lastErr };
}

/** Direct HTTP GET returning the response body string. */
function httpGetDirect(host, path, timeout) {
  return new Promise((resolve, reject) => {
    const req = http.get({ host, path, timeout, headers: { 'User-Agent': 'Mozilla/5.0 XrayClient', 'Accept': 'application/json' } }, (res) => {
      let body = '';
      res.on('data', (c) => (body += c));
      res.on('end', () => resolve(body));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
  });
}

/** HTTP GET over a raw SOCKS5 tunnel; reads the full response then returns body. */
async function httpGetViaSocks(socksPort, host, path, timeout) {
  const socket = await socks5Connect('127.0.0.1', socksPort, host, 80, timeout);
  const raw = await new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    let done = false;
    const finish = (fn) => { if (done) return; done = true; try { socket.destroy(); } catch {} fn(); };
    const to = setTimeout(() => finish(() => reject(new Error('timeout'))), timeout);
    socket.write(`GET ${path} HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: Mozilla/5.0 XrayClient\r\nAccept: application/json\r\nConnection: close\r\n\r\n`);
    socket.on('data', (d) => { buf = Buffer.concat([buf, d]); });
    socket.on('end', () => { clearTimeout(to); finish(() => resolve(buf)); });
    socket.on('close', () => { clearTimeout(to); finish(() => resolve(buf)); });
    socket.on('error', (e) => { clearTimeout(to); finish(() => reject(e)); });
  });
  return httpBody(raw);
}

/** Split an HTTP/1.1 response, returning the (de-chunked) body as a string. */
function httpBody(raw) {
  const s = raw.toString('utf8');
  const i = s.indexOf('\r\n\r\n');
  if (i === -1) return s;
  const headers = s.slice(0, i).toLowerCase();
  let body = s.slice(i + 4);
  if (/transfer-encoding:\s*chunked/.test(headers)) body = dechunk(body);
  return body;
}

function dechunk(s) {
  let out = '';
  let idx = 0;
  while (idx < s.length) {
    const nl = s.indexOf('\r\n', idx);
    if (nl === -1) break;
    const len = parseInt(s.slice(idx, nl).trim(), 16);
    if (isNaN(len) || len === 0) break;
    out += s.slice(nl + 2, nl + 2 + len);
    idx = nl + 2 + len + 2;
  }
  return out;
}

/** Parse JSON tolerant of leading/trailing junk (locate the outermost braces). */
function parseJsonLoose(body) {
  if (!body) return null;
  try { return JSON.parse(body); } catch {}
  const start = body.indexOf('{');
  const end = body.lastIndexOf('}');
  if (start === -1 || end === -1 || end < start) return null;
  try { return JSON.parse(body.slice(start, end + 1)); } catch { return null; }
}

module.exports = { tcpPing, httpThroughProxy, ipInfo, socks5Connect };
