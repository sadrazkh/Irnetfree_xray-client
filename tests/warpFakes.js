'use strict';
/**
 * A fake Cloudflare WARP API for tests/warp*.test.js — never the real one
 * (api.cloudflareclient.com is not dialled by any test; noNetwork.preload.js
 * refuses a TLS connection to it). Not a test file itself.
 *
 *   fakeApi(opts)        the API as a function of one request: { method, path, headers, body } → { status, body };
 *                        `calls` records every request (the body parsed)
 *   serveHttps(api)      the same API behind a real HTTPS server on 127.0.0.1, its certificate made here
 *   socksServer()        a SOCKS5 server on 127.0.0.1 that dials 127.0.0.1 for whatever name it is asked for
 *   selfSigned(host)     a P-256 certificate for `host`, self-signed, valid from an hour ago for a day
 */
const crypto = require('node:crypto');
const https = require('node:https');
const net = require('node:net');

const TOKEN = 'tok-3f9a1c0e-SECRET-5b7d2e48a1';
const DEVICE = 'dev-0a1b2c3d';
const LICENSE = 'A1b2C3d4-E5f6G7h8-I9j0K1l2';
/** The MASQUE edge's key, as Cloudflare hands it out: base64 SPKI DER (a key made here). */
const EDGE_PUB = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ type: 'spki', format: 'der' }).toString('base64');

/** A device record as the API answers it (usque's AccountData shape); `over` replaces parts. */
function device(over = {}) {
  return Object.assign({
    id: DEVICE, type: 'a', model: 'PC', name: '', key: '', key_type: 'secp256r1', tunnel_type: 'masque',
    account: { id: 'acc-77', account_type: 'free', warp_plus: false, premium_data: 0, quota: 0, license: 'xyz' },
    config: {
      client_id: 'AAAA',
      peers: [{ public_key: EDGE_PUB, endpoint: { v4: '162.159.198.1:0', v6: '[2606:4700:103::1]:0', host: 'engage.cloudflareclient.com:2408' } }],
      interface: { addresses: { v4: '172.16.0.2', v6: '2606:4700:110:8a36:9c1:2b3:4d5:6e7f' } },
      services: { http_proxy: '172.16.0.1:2480' }
    },
    warp_enabled: true, waitlist_enabled: false, enabled: true, locale: 'en_US'
  }, over);
}

/**
 * The API, step by step as Cloudflare answers it. opts:
 *   enrolled     the PATCH key answer (default: device() with warp_enabled false — a fresh device)
 *   activated    the PATCH warp_enabled answer (default: device())
 *   fetched      the GET /reg/{id} answer (default: device())
 *   license      the PUT …/account answer (default: a WARP+ account)
 *   status       { 'POST /reg': 429, … } — a status (and `errorBody`) instead of the answer
 */
function fakeApi(opts = {}) {
  const calls = [];
  const v = '/v0a5641';
  const answer = (status, obj) => ({ status, body: typeof obj === 'string' ? obj : JSON.stringify(obj) });
  const api = async (req) => {
    let body = null;
    if (req.body != null && req.body !== '') { try { body = JSON.parse(req.body); } catch { body = req.body; } }
    calls.push({ method: req.method, path: req.path, headers: Object.assign({}, req.headers), body });
    const route = `${req.method} ${req.path.replace(v, '').replace(DEVICE, '{id}')}`;
    if (opts.status && opts.status[route]) return answer(opts.status[route], opts.errorBody || { success: false, errors: [{ code: 1000, message: 'Refused by the fake' }] });
    const auth = (req.headers.Authorization || req.headers.authorization || '');
    const authed = auth === 'Bearer ' + TOKEN;
    switch (route) {
      case 'POST /reg':
        return answer(200, device({ token: TOKEN, key_type: 'curve25519', tunnel_type: 'wireguard', warp_enabled: false,
          config: Object.assign({}, device().config, { peers: [{ public_key: 'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=', endpoint: { v4: '162.159.192.1:0', v6: '[2606:4700:d0::a29f:c001]:0' } }] }) }));
      case 'PATCH /reg/{id}':
        if (!authed) return answer(401, { success: false, errors: [{ code: 10000, message: 'Authentication error' }] });
        if (body && body.warp_enabled === true) return answer(200, opts.activated || device());
        return answer(200, opts.enrolled || device({ warp_enabled: false }));
      case 'GET /reg/{id}':
        if (!authed) return answer(401, { success: false, errors: [{ code: 10000, message: 'Authentication error' }] });
        return answer(200, opts.fetched || device());
      case 'PUT /reg/{id}/account':
        if (!authed) return answer(401, { success: false, errors: [{ code: 10000, message: 'Authentication error' }] });
        return answer(200, opts.license || { id: 'acc-77', account_type: 'unlimited', warp_plus: true, premium_data: 1, license: body && body.license });
      default:
        return answer(404, { success: false, errors: [{ code: 404, message: 'no route ' + route }] });
    }
  };
  api.calls = calls;
  return api;
}

/* ------------------------- a certificate, made here ------------------------- */
function derLen(n) {
  if (n < 0x80) return Buffer.from([n]);
  const b = [];
  while (n) { b.unshift(n & 0xff); n >>= 8; }
  return Buffer.from([0x80 | b.length, ...b]);
}
const der = (tag, ...parts) => { const body = Buffer.concat(parts); return Buffer.concat([Buffer.from([tag]), derLen(body.length), body]); };
const SEQ = (...p) => der(0x30, ...p);
const SET = (...p) => der(0x31, ...p);
function OID(s) {
  const a = s.split('.').map(Number);
  const out = [40 * a[0] + a[1]];
  for (const v of a.slice(2)) {
    const enc = [v & 0x7f];
    let x = v >> 7;
    while (x) { enc.unshift(0x80 | (x & 0x7f)); x >>= 7; }
    out.push(...enc);
  }
  return der(0x06, Buffer.from(out));
}
const utc = (d) => der(0x17, Buffer.from(d.toISOString().replace(/[-:T]/g, '').slice(2, 14) + 'Z'));
const pem = (buf, label) => `-----BEGIN ${label}-----\n${buf.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END ${label}-----\n`;

function selfSigned(host = 'localhost') {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const serial = crypto.randomBytes(8); serial[0] &= 0x7f;
  const sigAlg = SEQ(OID('1.2.840.10045.4.3.2'));                          // ecdsa-with-SHA256
  const name = SEQ(SET(SEQ(OID('2.5.4.3'), der(0x0c, Buffer.from(host)))));
  const now = Date.now();
  const san = SEQ(OID('2.5.29.17'), der(0x04, SEQ(der(0x82, Buffer.from(host)))));
  const tbs = SEQ(der(0xa0, der(0x02, Buffer.from([2]))), der(0x02, serial), sigAlg, name,
    SEQ(utc(new Date(now - 3600e3)), utc(new Date(now + 86400e3))), name,
    publicKey.export({ type: 'spki', format: 'der' }), der(0xa3, SEQ(san)));
  const cert = SEQ(tbs, sigAlg, der(0x03, Buffer.from([0]), crypto.sign('sha256', tbs, privateKey)));
  return { cert: pem(cert, 'CERTIFICATE'), key: privateKey.export({ type: 'pkcs8', format: 'pem' }) };
}

/**
 * `api` behind HTTPS on 127.0.0.1 (a certificate for `localhost`). `seen` records
 * what each connection negotiated and the Host header: { tls, alpn, host }.
 */
async function serveHttps(api, opts = {}) {
  const { cert, key } = selfSigned('localhost');
  const seen = [];
  const srv = https.createServer(Object.assign({ cert, key, ALPNProtocols: ['http/1.1'] }, opts.tls || {}), (req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', async () => {
      seen.push({ tls: req.socket.getProtocol(), alpn: req.socket.alpnProtocol, host: req.headers.host, headers: req.headers });
      if (opts.hang) return;   // never answers: the client's timeout has to end it
      const out = await api({ method: req.method, path: req.url, headers: req.headers, body: Buffer.concat(chunks).toString('utf8') });
      res.writeHead(out.status, { 'Content-Type': 'application/json' });
      res.end(out.body);
    });
  });
  srv.on('tlsClientError', () => {});
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  return { port: srv.address().port, ca: cert, seen, close: () => new Promise((r) => { srv.closeAllConnections && srv.closeAllConnections(); srv.close(r); }) };
}

/** A SOCKS5 server (no auth) on 127.0.0.1: every CONNECT dials 127.0.0.1 at the asked port. `asked` records host:port. */
async function socksServer(opts = {}) {
  const asked = [];
  const socks = new Set();
  const srv = net.createServer((c) => {
    socks.add(c);
    c.on('error', () => {});
    c.once('data', (greet) => {
      if (greet[0] !== 5) return c.destroy();
      c.write(Buffer.from([5, 0]));
      c.once('data', (req) => {
        const atyp = req[3];
        let host; let at;
        if (atyp === 3) { const n = req[4]; host = req.slice(5, 5 + n).toString(); at = 5 + n; }
        else if (atyp === 1) { host = [...req.slice(4, 8)].join('.'); at = 8; }
        else return c.destroy();
        const port = req.readUInt16BE(at);
        asked.push(`${host}:${port}`);
        if (opts.refuse) { c.end(Buffer.from([5, 5, 0, 1, 0, 0, 0, 0, 0, 0])); return; }   // 5 = connection refused
        const up = net.connect(port, '127.0.0.1', () => {
          c.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 0]));
          c.pipe(up); up.pipe(c);
        });
        socks.add(up);
        up.on('error', () => c.destroy());
      });
    });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  return { port: srv.address().port, asked, close: () => new Promise((r) => { for (const s of socks) s.destroy(); srv.close(r); }) };
}

/** A loopback port nothing listens on (bound, then released). */
async function deadPort() {
  const srv = net.createServer();
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const { port } = srv.address();
  await new Promise((r) => srv.close(r));
  return port;
}

module.exports = { TOKEN, DEVICE, LICENSE, EDGE_PUB, device, fakeApi, selfSigned, serveHttps, socksServer, deadPort };
