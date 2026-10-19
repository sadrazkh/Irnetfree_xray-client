'use strict';
/**
 * WARP on MASQUE (src/main/warp.js): a device registered with Cloudflare's API
 * — always a FAKE of it here (warpFakes.js), injected or behind a local HTTPS
 * server; the real api.cloudflareclient.com is never dialled — or brought in
 * from usque / a pasted Xray outbound, and the editor's fields for one server
 * per HTTP version. .superpowers/sdd/masque/design.md §5.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const tls = require('node:tls');
const W = require('../src/main/warp');
const F = require('./warpFakes');

const NOW = Date.UTC(2026, 9, 14, 9, 30, 15, 123);
const now = () => NOW;

/** registerWarp over the fake API; `log` lines collected. */
async function register(apiOpts = {}, args = {}) {
  const api = F.fakeApi(apiOpts);
  const lines = [];
  const reg = await W.registerWarp(Object.assign({ request: api, now, log: (l) => lines.push(l) }, args));
  return { reg, api, lines };
}
const spkiOfPrivate = (pemText) => crypto.createPublicKey(crypto.createPrivateKey(pemText)).export({ type: 'spki', format: 'der' }).toString('base64');
const spkiOfPublic = (pemText) => crypto.createPublicKey(pemText).export({ type: 'spki', format: 'der' }).toString('base64');

/* -------------------------------- the requests -------------------------------- */
test('registerWarp: POST /reg with usque’s body — a throwaway X25519 key, tos = now, a 16-hex serial — and wgcf 2.3.0’s headers, no token', async () => {
  const { api } = await register();
  const post = api.calls[0];
  assert.equal(post.method, 'POST');
  assert.equal(post.path, '/v0a5641/reg');
  assert.equal(post.headers['User-Agent'], '1.1.1.1/6.38.9-5641 (Android 16.0.0)');
  assert.equal(post.headers['CF-Client-Version'], 'a-6.38.9-5641');
  assert.equal(post.headers['Content-Type'], 'application/json; charset=UTF-8');
  assert.equal('Authorization' in post.headers, false);
  assert.deepEqual(Object.keys(post.body).sort(), ['fcm_token', 'install_id', 'key', 'key_type', 'locale', 'model', 'os_version', 'serial_number', 'tos', 'tunnel_type']);
  assert.equal(post.body.tos, '2026-10-14T09:30:15.123Z');
  assert.equal(post.body.key_type, 'curve25519');
  assert.equal(post.body.tunnel_type, 'wireguard');
  assert.equal(post.body.model, 'PC');
  assert.equal(post.body.locale, 'en_US');
  assert.equal(post.body.install_id, '');
  assert.equal(post.body.fcm_token, '');
  assert.equal(post.body.os_version, '');
  assert.match(post.body.serial_number, /^[0-9a-f]{16}$/);
  // a real X25519 public key: 32 bytes that make a key object
  const raw = Buffer.from(post.body.key, 'base64');
  assert.equal(raw.length, 32);
  const x = crypto.createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'), raw]), format: 'der', type: 'spki' });
  assert.equal(x.asymmetricKeyType, 'x25519');
});

test('registerWarp: PATCH /reg/{id} with the Bearer token and exactly { key: base64 SPKI of OUR P-256 key, key_type secp256r1, tunnel_type masque }', async () => {
  const { reg, api } = await register();
  const patch = api.calls[1];
  assert.equal(patch.method, 'PATCH');
  assert.equal(patch.path, '/v0a5641/reg/' + F.DEVICE);
  assert.equal(patch.headers.Authorization, 'Bearer ' + F.TOKEN);
  assert.equal(patch.headers['CF-Client-Version'], 'a-6.38.9-5641');
  assert.deepEqual(Object.keys(patch.body).sort(), ['key', 'key_type', 'tunnel_type']);
  assert.equal(patch.body.key_type, 'secp256r1');
  assert.equal(patch.body.tunnel_type, 'masque');
  // the key enrolled is the public half of the private key handed back
  assert.equal(patch.body.key, spkiOfPrivate(reg.privateKey));
  const k = crypto.createPrivateKey(reg.privateKey);
  assert.equal(k.asymmetricKeyDetails.namedCurve, 'prime256v1');
  assert.match(reg.privateKey, /^-----BEGIN PRIVATE KEY-----\n[\s\S]+\n-----END PRIVATE KEY-----\n?$/, 'PKCS#8 PEM');
});

test('registerWarp: warp_enabled — switched on with its own PATCH only when the answer says it is not; checked; a device that stays off is a warning, not a failure', async () => {
  // a fresh device answers warp_enabled:false → PATCH { warp_enabled: true }
  let { api, reg } = await register();
  // then the account and its devices read back (accountStep), every time
  assert.deepEqual(api.calls.map((c) => c.method + ' ' + c.path.replace('/v0a5641', '')), ['POST /reg', `PATCH /reg/${F.DEVICE}`, `PATCH /reg/${F.DEVICE}`, `GET /reg/${F.DEVICE}/account`, `GET /reg/${F.DEVICE}/account/devices`]);
  assert.deepEqual(api.calls[2].body, { warp_enabled: true });
  assert.equal(api.calls[2].headers.Authorization, 'Bearer ' + F.TOKEN);
  assert.deepEqual(reg.warnings, []);
  // already on → no second PATCH
  ({ api, reg } = await register({ enrolled: F.device({ warp_enabled: true }) }));
  assert.equal(api.calls.filter((c) => c.method === 'PATCH').length, 1);
  assert.deepEqual(reg.warnings, []);
  // still off after the PATCH → said, and the servers are still made from the record
  ({ api, reg } = await register({ activated: F.device({ warp_enabled: false }) }));
  assert.equal(api.calls.filter((c) => c.method === 'PATCH').length, 2);
  assert.deepEqual(reg.warnings.map((w) => w.code), ['warpNotEnabled']);
  assert.equal(reg.address.length, 2);
});

test('registerWarp: a WARP+ license — PUT /reg/{id}/account { license } after the key; the account read from its answer; none without one', async () => {
  let { api, reg } = await register({}, { license: '  ' + F.LICENSE + ' ' });
  const put = api.calls.find((c) => c.method === 'PUT');
  // the key, then the account read back
  assert.deepEqual(api.calls.slice(-3).map((c) => c.method + ' ' + c.path.replace('/v0a5641/reg/' + F.DEVICE, '')), ['PUT /account', 'GET /account', 'GET /account/devices']);
  assert.equal(put.method, 'PUT');
  assert.equal(put.path, `/v0a5641/reg/${F.DEVICE}/account`);
  assert.equal(put.headers.Authorization, 'Bearer ' + F.TOKEN);
  assert.deepEqual(put.body, { license: F.LICENSE });
  assert.deepEqual(reg.account, { id: F.DEVICE, type: 'unlimited', warpPlus: true });
  ({ api, reg } = await register());
  assert.equal(api.calls.some((c) => c.method === 'PUT'), false);
  assert.deepEqual(reg.account, { id: F.DEVICE, type: 'free', warpPlus: false });
});

test('registerWarp: a license that is not one is refused before anything is sent; one Cloudflare refuses leaves a free account and a warning', async () => {
  const api = F.fakeApi();
  await assert.rejects(W.registerWarp({ request: api, now, license: 'not-a-license' }), (e) => e.code === 'badLicense');
  assert.equal(api.calls.length, 0, 'no device was registered for nothing');
  const { reg } = await register({ status: { 'PUT /reg/{id}/account': 403 }, errorBody: { success: false, errors: [{ code: 1300, message: 'Too many connected devices.' }] } }, { license: F.LICENSE });
  assert.deepEqual(reg.warnings.map((w) => w.code), ['licenseFailed']);
  assert.match(reg.warnings[0].message, /Too many connected devices/);
  assert.equal(reg.account.warpPlus, false);
  assert.ok(reg.privateKey && reg.publicKey);
});

/* ------------------------------ the answer, mapped ------------------------------ */
test('registerWarp: the record mapped — the edge key as PEM, v4 /32 + v6 /128, H3 endpoints from peers[0] without ":0", H2 the fixed .2 pair', async () => {
  const { reg } = await register();
  assert.match(reg.publicKey, /^-----BEGIN PUBLIC KEY-----\n/);
  assert.equal(spkiOfPublic(reg.publicKey), F.EDGE_PUB);
  assert.deepEqual(reg.address, ['172.16.0.2/32', '2606:4700:110:8a36:9c1:2b3:4d5:6e7f/128']);
  assert.deepEqual(reg.endpoints, { h3v4: '162.159.198.1', h3v6: '2606:4700:103::1', h2v4: '162.159.198.2', h2v6: '2606:4700:103::2' });
  assert.deepEqual(Object.keys(reg).sort(), ['account', 'address', 'endpoints', 'info', 'privateKey', 'publicKey', 'warnings']);
});

test('registerWarp: endpoints fall back to Cloudflare’s defaults; an endpoint with another port loses it; addresses already with a prefix kept', async () => {
  const cfg = (peer, addresses) => F.device({ warp_enabled: true, config: { peers: [Object.assign({ public_key: F.EDGE_PUB }, peer)], interface: { addresses } } });
  let { reg } = await register({ enrolled: cfg({ endpoint: {} }, { v4: '172.16.0.2/32', v6: '2606:4700:110::2/128' }) });
  assert.deepEqual(reg.endpoints, { h3v4: '162.159.198.1', h3v6: '2606:4700:103::1', h2v4: '162.159.198.2', h2v6: '2606:4700:103::2' });
  assert.deepEqual(reg.address, ['172.16.0.2/32', '2606:4700:110::2/128']);
  ({ reg } = await register({ enrolled: cfg({ endpoint: { v4: '162.159.199.1:443', v6: '2606:4700:104::1' } }, { v4: '172.16.0.9' }) }));
  assert.equal(reg.endpoints.h3v4, '162.159.199.1');
  assert.equal(reg.endpoints.h3v6, '2606:4700:104::1');
  assert.deepEqual(reg.address, ['172.16.0.9/32'], 'no v6 given, none made up');
  // garbage in an endpoint → the default, not a broken address
  ({ reg } = await register({ enrolled: cfg({ endpoint: { v4: 'not an ip:0', v6: '[]:0' } }, { v4: '172.16.0.2' }) }));
  assert.equal(reg.endpoints.h3v4, '162.159.198.1');
  assert.equal(reg.endpoints.h3v6, '2606:4700:103::1');
});

test('registerWarp: an enroll answer without peers is no failure — the record is read back with GET /reg/{id}', async () => {
  const bare = F.device({ warp_enabled: true, config: { peers: [], interface: { addresses: {} } } });
  const { reg, api } = await register({ enrolled: bare });
  assert.deepEqual(api.calls.map((c) => c.method), ['POST', 'PATCH', 'GET', 'GET', 'GET']);
  assert.equal(api.calls[2].path, '/v0a5641/reg/' + F.DEVICE);
  assert.equal(api.calls[2].headers.Authorization, 'Bearer ' + F.TOKEN);
  assert.equal(api.calls[2].body, null);
  assert.equal(spkiOfPublic(reg.publicKey), F.EDGE_PUB);
  // and with no peers even then: said, as an answer that cannot be used
  await assert.rejects(register({ enrolled: bare, fetched: bare }), (e) => e.code === 'badAnswer');
});

/* ----------------------------------- errors ----------------------------------- */
test('registerWarp: 429 → rateLimited; another 4xx → rejected with Cloudflare’s own message; 5xx → rejected; an unreadable answer → badAnswer', async () => {
  await assert.rejects(register({ status: { 'POST /reg': 429 } }), (e) => e.code === 'rateLimited' && /429/.test(e.message));
  await assert.rejects(register({ status: { 'POST /reg': 400 }, errorBody: { success: false, errors: [{ code: 1002, message: 'Invalid public key' }] } }),
    (e) => e.code === 'rejected' && /400/.test(e.message) && /Invalid public key/.test(e.message) && e.detail === 'Invalid public key');
  await assert.rejects(register({ status: { 'PATCH /reg/{id}': 403 } }), (e) => e.code === 'rejected' && /Refused by the fake/.test(e.message));
  await assert.rejects(register({ status: { 'POST /reg': 503 }, errorBody: '<html>upstream</html>' }), (e) => e.code === 'rejected' && /503/.test(e.message));
  const notJson = async () => ({ status: 200, body: '<html>a captive portal</html>' });
  await assert.rejects(W.registerWarp({ request: notJson, now }), (e) => e.code === 'badAnswer');
  const noToken = async () => ({ status: 200, body: JSON.stringify({ id: 'x' }) });
  await assert.rejects(W.registerWarp({ request: noToken, now }), (e) => e.code === 'badAnswer');
  // a transport that fails says why in its own code; anything else is "blocked"
  const down = async () => { throw Object.assign(new Error('read ECONNRESET'), { code: 'ECONNRESET' }); };
  await assert.rejects(W.registerWarp({ request: down, now }), (e) => e.code === 'blocked' && /ECONNRESET/.test(e.message));
});

test('the token and the private key are never logged, nor in an error — not even when Cloudflare repeats them', async () => {
  const lines = [];
  const echo = F.fakeApi({ status: { 'PUT /reg/{id}/account': 400 }, errorBody: { success: false, errors: [{ code: 1, message: `bad token ${F.TOKEN}` }] } });
  const reg = await W.registerWarp({ request: echo, now, license: F.LICENSE, log: (l) => lines.push(l) });
  const keyBody = reg.privateKey.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  const secrets = [F.TOKEN, keyBody, keyBody.slice(0, 40), keyBody.slice(-40)];
  const text = lines.join('\n') + '\n' + reg.warnings.map((w) => w.message).join('\n');
  assert.ok(lines.length >= 3, 'the steps are logged');
  for (const s of secrets) assert.equal(text.includes(s), false, 'a secret reached the log');
  assert.match(reg.warnings[0].message, /bad token …/);
  // a refusal that repeats the token, thrown
  const thrown = F.fakeApi({ status: { 'PATCH /reg/{id}': 400 }, errorBody: { errors: [{ message: 'token ' + F.TOKEN + ' unknown' }] } });
  const lines2 = [];
  await assert.rejects(W.registerWarp({ request: thrown, now, log: (l) => lines2.push(l) }), (e) => {
    assert.equal(e.message.includes(F.TOKEN), false);
    assert.equal(String(e.detail).includes(F.TOKEN), false);
    assert.equal(String(e.stack).includes(F.TOKEN), false);
    return e.code === 'rejected';
  });
  assert.equal(lines2.join('\n').includes(F.TOKEN), false);
});

/* ------------------------- the real transport, on loopback ------------------------- */
test('makeRequest: HTTPS with TLS 1.2 and ALPN http/1.1 (the ClientHello that avoided 429s), Host the API’s name, the headers on the wire', async () => {
  const api = F.fakeApi();
  const srv = await F.serveHttps(api);
  try {
    const request = W.makeRequest({ host: 'localhost', connectHost: '127.0.0.1', port: srv.port, ca: srv.ca });
    const reg = await W.registerWarp({ request, now });
    assert.equal(reg.endpoints.h3v4, '162.159.198.1');
    assert.ok(srv.seen.length >= 3);
    for (const s of srv.seen) {
      assert.equal(s.tls, 'TLSv1.2');
      assert.equal(s.alpn, 'http/1.1');
      assert.equal(s.host, 'localhost');
      assert.equal(s.headers['user-agent'], '1.1.1.1/6.38.9-5641 (Android 16.0.0)');
      assert.equal(s.headers['cf-client-version'], 'a-6.38.9-5641');
      assert.equal(s.headers['accept-encoding'], 'identity');
    }
    assert.equal(srv.seen[1].headers.authorization, 'Bearer ' + F.TOKEN);
    assert.equal(api.calls[0].body.key_type, 'curve25519');
  } finally { await srv.close(); }
});

test('makeRequest through the app’s own SOCKS port: the name goes to the proxy (no local lookup), TLS inside; not connected → notConnected', async () => {
  const api = F.fakeApi();
  const srv = await F.serveHttps(api);
  const socks = await F.socksServer();
  try {
    const request = W.makeRequest({ via: 'proxy', socksPort: socks.port, host: 'localhost', port: srv.port, ca: srv.ca });
    const reg = await W.registerWarp({ request, now });
    assert.ok(reg.privateKey);
    assert.ok(socks.asked.length >= 3);
    assert.ok(socks.asked.every((a) => a === `localhost:${srv.port}`));
    assert.ok(srv.seen.every((s) => s.tls === 'TLSv1.2' && s.alpn === 'http/1.1'));
    // the proxy port answers nothing: the app is not connected
    const dead = await F.deadPort();
    const off = W.makeRequest({ via: 'proxy', socksPort: dead, host: 'localhost', port: srv.port, ca: srv.ca });
    await assert.rejects(W.registerWarp({ request: off, now }), (e) => e.code === 'notConnected');
    await assert.rejects(W.registerWarp({ request: W.makeRequest({ via: 'proxy', host: 'localhost', port: srv.port }), now }), (e) => e.code === 'notConnected');
  } finally { await socks.close(); await srv.close(); }
});

test('makeRequest: what a block looks like — nothing listening, a proxy that cannot reach the API, a certificate that is not the API’s, no answer in time — all "blocked"', async () => {
  const dead = await F.deadPort();
  const direct = W.makeRequest({ host: 'localhost', connectHost: '127.0.0.1', port: dead });
  await assert.rejects(W.registerWarp({ request: direct, now }), (e) => e.code === 'blocked');
  const refusing = await F.socksServer({ refuse: true });
  try {
    await assert.rejects(W.registerWarp({ request: W.makeRequest({ via: 'proxy', socksPort: refusing.port, host: 'localhost', port: 443 }), now }), (e) => e.code === 'blocked');
  } finally { await refusing.close(); }
  const api = F.fakeApi();
  const srv = await F.serveHttps(api);
  try {
    // no `ca`: the self-signed certificate is not trusted — a man in the middle looks exactly like this
    await assert.rejects(W.registerWarp({ request: W.makeRequest({ host: 'localhost', connectHost: '127.0.0.1', port: srv.port }), now }), (e) => e.code === 'blocked');
    assert.equal(api.calls.length, 0, 'nothing was sent over an unverified connection');
  } finally { await srv.close(); }
  const hang = await F.serveHttps(F.fakeApi(), { hang: true });
  try {
    const t0 = Date.now();
    await assert.rejects(W.registerWarp({ request: W.makeRequest({ host: 'localhost', connectHost: '127.0.0.1', port: hang.port, ca: hang.ca, timeoutMs: 300 }), now }),
      (e) => e.code === 'blocked' && /timed out/.test(e.message));
    assert.ok(Date.now() - t0 < 5000);
  } finally { await hang.close(); }
  // a black hole: the TCP connection is taken, the TLS handshake never answered — closed by the timeout, not left open
  const net = require('node:net');
  let closed;
  const hole = net.createServer((c) => { c.on('error', () => {}); c.resume(); closed = new Promise((r) => c.on('close', r)); });
  await new Promise((r) => hole.listen(0, '127.0.0.1', r));
  try {
    await assert.rejects(W.registerWarp({ request: W.makeRequest({ host: 'localhost', connectHost: '127.0.0.1', port: hole.address().port, timeoutMs: 300 }), now }),
      (e) => e.code === 'blocked' && /timed out/.test(e.message));
    await closed;
  } finally { await new Promise((r) => hole.close(r)); }
});

// only under the guard: without it these lines WOULD dial Cloudflare
test('the default request goes to api.cloudflareclient.com:443 — and npm test refuses to dial it (noNetwork.preload.js)', { skip: tls.connect.irnfGuard !== true && 'run through npm test (the noNetwork preload)' }, async () => {
  assert.equal(W.API.host, 'api.cloudflareclient.com');
  assert.equal(W.API.port, 443);
  assert.equal(W.API.version, 'v0a5641');
  assert.throws(() => tls.connect({ host: 'api.cloudflareclient.com', port: 443, servername: 'api.cloudflareclient.com' }), (e) => e.code === 'EIRNF_GUARD');
  assert.throws(() => tls.connect(443, 'api.cloudflareclient.com'), (e) => e.code === 'EIRNF_GUARD');
  // the app's own transport, unconfigured, is refused the same way — nothing leaves the machine
  const request = W.makeRequest();
  await assert.rejects(request({ method: 'POST', path: '/v0a5641/reg', headers: {}, body: '{}' }), (e) => e.code === 'blocked' && /EIRNF_GUARD/.test(e.message));
});

/* ----------------------------------- the fields ----------------------------------- */
const REG = {
  privateKey: '-----BEGIN PRIVATE KEY-----\nMIGHAgEA\n-----END PRIVATE KEY-----\n',
  publicKey: '-----BEGIN PUBLIC KEY-----\nMFkwEwYH\n-----END PUBLIC KEY-----\n',
  address: ['172.16.0.2/32', '2606:4700:110::2/128'],
  endpoints: { h3v4: '162.159.198.1', h3v6: '2606:4700:103::1', h2v4: '162.159.198.2', h2v6: '2606:4700:103::2' },
  account: { id: 'd', type: 'free', warpPlus: false }
};

test('warpServers: both by default — «☁ WARP · H3» then «☁ WARP · H2» on their own endpoints, port 443, the WARP fields, the WARP SNI, anti-DPI per HTTP version', () => {
  const out = W.warpServers(REG, {});
  assert.deepEqual(out, [
    { protocol: 'masque', name: '☁ WARP · H3', address: '162.159.198.1', port: 443, masqueHttp: 'h3',
      warpPrivateKey: REG.privateKey, warpPublicKey: REG.publicKey, warpAddress: '172.16.0.2/32, 2606:4700:110::2/128',
      sni: 'consumer-masque.cloudflareclient.com', noise: 'random' },
    { protocol: 'masque', name: '☁ WARP · H2', address: '162.159.198.2', port: 443, masqueHttp: 'h2',
      warpPrivateKey: REG.privateKey, warpPublicKey: REG.publicKey, warpAddress: '172.16.0.2/32, 2606:4700:110::2/128',
      sni: 'consumer-masque.cloudflareclient.com', fragment: 'tlshello,100-200,10-20' }
  ]);
  assert.deepEqual(W.warpServers(REG, { http: 'both', endpoint: 'auto', antiDpi: true }), out);
  // the input is not touched
  assert.deepEqual(REG.address, ['172.16.0.2/32', '2606:4700:110::2/128']);
});

test('warpServers: one HTTP version; IPv6 endpoints; my own clean IP (port 443 unless given) for every server; a name of my own', () => {
  let out = W.warpServers(REG, { http: 'h3' });
  assert.deepEqual(out.map((f) => [f.name, f.address, f.masqueHttp]), [['☁ WARP · H3', '162.159.198.1', 'h3']]);
  out = W.warpServers(REG, { http: 'h2', endpoint: 'v6' });
  assert.deepEqual(out.map((f) => [f.address, f.port, f.masqueHttp]), [['2606:4700:103::2', 443, 'h2']]);
  out = W.warpServers(REG, { endpoint: 'v6' });
  assert.deepEqual(out.map((f) => f.address), ['2606:4700:103::1', '2606:4700:103::2']);
  out = W.warpServers(REG, { endpoint: 'custom', address: ' 162.159.198.10 ', name: 'Home' });
  assert.deepEqual(out.map((f) => [f.name, f.address, f.port]), [['Home · H3', '162.159.198.10', 443], ['Home · H2', '162.159.198.10', 443]]);
  out = W.warpServers(REG, { endpoint: 'custom', address: '162.159.198.2:8443', http: 'h2' });
  assert.deepEqual(out.map((f) => [f.address, f.port]), [['162.159.198.2', 8443]]);
  out = W.warpServers(REG, { endpoint: 'custom', address: '[2606:4700:103::2]:4443', http: 'h2' });
  assert.deepEqual(out.map((f) => [f.address, f.port]), [['2606:4700:103::2', 4443]]);
  out = W.warpServers(REG, { endpoint: 'custom', address: '2606:4700:103::2', http: 'h2' });
  assert.deepEqual(out.map((f) => [f.address, f.port]), [['2606:4700:103::2', 443]]);
  out = W.warpServers(REG, { endpoint: 'custom', address: 'warp.example.net' });
  assert.deepEqual(out.map((f) => f.address), ['warp.example.net', 'warp.example.net']);
  for (const bad of ['', '   ', 'https://162.159.198.2/', '1.2.3.4:0', '1.2.3.4:70000', 'a b']) {
    assert.throws(() => W.warpServers(REG, { endpoint: 'custom', address: bad }), (e) => e.code === 'badAddress', JSON.stringify(bad));
  }
});

test('warpServers: a cover domain — serverName and verifyPeerCertByName both that name (the edge then serves its real certificate); anti-DPI off writes none', () => {
  const out = W.warpServers(REG, { cover: '  WWW.Example.COM ', antiDpi: false });
  for (const f of out) {
    assert.equal(f.sni, 'www.example.com');
    assert.equal(f.vcn, 'www.example.com');
    assert.equal('noise' in f, false);
    assert.equal('fragment' in f, false);
  }
  assert.equal(W.warpServers(REG, { cover: 'https://cdn.example.org/' })[0].sni, 'cdn.example.org');
  assert.equal('vcn' in W.warpServers(REG, {})[0], false, 'no cover: the WARP key pins the edge');
  for (const bad of ['1.2.3.4', 'localhost', 'a b.com', 'ex ample', '-x.com', 'x..com']) {
    assert.throws(() => W.warpServers(REG, { cover: bad }), (e) => e.code === 'badCover', bad);
  }
});

test('warpServers: a registration without its keys or addresses makes no server', () => {
  for (const k of ['privateKey', 'publicKey']) assert.throws(() => W.warpServers(Object.assign({}, REG, { [k]: '' }), {}), (e) => e.code === 'badAnswer');
  assert.throws(() => W.warpServers(Object.assign({}, REG, { address: [] }), {}), (e) => e.code === 'badAnswer');
});

/* ----------------------------------- importing ----------------------------------- */
function usqueConfig() {
  const k = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return {
    key: k,
    json: {
      private_key: k.privateKey.export({ type: 'sec1', format: 'der' }).toString('base64'),
      endpoint_v4: '162.159.198.1', endpoint_v6: '2606:4700:103::1',
      endpoint_h2_v4: '162.159.198.2', endpoint_h2_v6: '2606:4700:103::2',
      endpoint_pub_key: crypto.createPublicKey({ key: Buffer.from(F.EDGE_PUB, 'base64'), format: 'der', type: 'spki' }).export({ type: 'spki', format: 'pem' }),
      license: 'xyz', id: 'usque-dev-1', access_token: 'usque-SECRET-token', ipv4: '172.16.0.2', ipv6: '2606:4700:110:8a36::2'
    }
  };
}

test('importWarp: usque’s config.json — the SEC1 key as PKCS#8 PEM, its four endpoints, ipv4/ipv6 → /32 /128; its token is not carried', () => {
  const { key, json } = usqueConfig();
  const reg = W.importWarp(JSON.stringify(json, null, 2));
  assert.match(reg.privateKey, /^-----BEGIN PRIVATE KEY-----\n/);
  assert.equal(spkiOfPrivate(reg.privateKey), key.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'));
  assert.equal(spkiOfPublic(reg.publicKey), F.EDGE_PUB);
  assert.deepEqual(reg.address, ['172.16.0.2/32', '2606:4700:110:8a36::2/128']);
  assert.deepEqual(reg.endpoints, { h3v4: '162.159.198.1', h3v6: '2606:4700:103::1', h2v4: '162.159.198.2', h2v6: '2606:4700:103::2' });
  assert.deepEqual(reg.account, { id: 'usque-dev-1', type: '', warpPlus: false });
  assert.equal(JSON.stringify(reg).includes('usque-SECRET-token'), false);
  // the fields go straight to warpServers
  assert.equal(W.warpServers(reg, {}).length, 2);
  // the keys alone (the dialog's "or the keys"): endpoints default
  const bare = W.importWarp(JSON.stringify({ private_key: json.private_key, endpoint_pub_key: json.endpoint_pub_key, ipv4: '172.16.0.3/32' }));
  assert.deepEqual(bare.endpoints, { h3v4: '162.159.198.1', h3v6: '2606:4700:103::1', h2v4: '162.159.198.2', h2v6: '2606:4700:103::2' });
  assert.deepEqual(bare.address, ['172.16.0.3/32']);
});

test('importWarp: a pasted Xray WARP outbound, a whole config, an outbound list, or the warp object alone (base64 PKCS#8, SEC1 PEM)', () => {
  const k = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const warp = { privateKey: k.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'), publicKey: F.EDGE_PUB, address: ['172.16.0.2/32', '2606:4700:110::2'] };
  const h2 = { protocol: 'masque', settings: { address: '162.159.198.10', port: 443 }, tag: 'warp-masque',
    streamSettings: { method: 'masque', masqueSettings: { warp }, security: 'tls', tlsSettings: { serverName: 'consumer-masque.cloudflareclient.com', alpn: ['h2'] } } };
  const h3 = { protocol: 'masque', settings: { address: '2606:4700:103::7', port: 443 },
    streamSettings: { network: 'masque', masqueSettings: { warp }, security: 'tls', tlsSettings: {} } };
  const want = k.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  let reg = W.importWarp(JSON.stringify(h2));
  assert.equal(spkiOfPrivate(reg.privateKey), want);
  assert.equal(spkiOfPublic(reg.publicKey), F.EDGE_PUB);
  assert.deepEqual(reg.address, ['172.16.0.2/32', '2606:4700:110::2/128']);
  assert.deepEqual(reg.endpoints, { h3v4: '162.159.198.1', h3v6: '2606:4700:103::1', h2v4: '162.159.198.10', h2v6: '2606:4700:103::2' });
  reg = W.importWarp(JSON.stringify({ remarks: 'x', outbounds: [{ protocol: 'freedom', tag: 'direct' }, h2, h3] }));
  assert.equal(reg.endpoints.h2v4, '162.159.198.10');
  assert.equal(reg.endpoints.h3v6, '2606:4700:103::7');
  reg = W.importWarp(JSON.stringify([h3]));
  assert.equal(reg.endpoints.h3v6, '2606:4700:103::7');
  reg = W.importWarp(JSON.stringify({ warp: Object.assign({}, warp, { privateKey: k.privateKey.export({ type: 'sec1', format: 'pem' }) }) }));
  assert.equal(spkiOfPrivate(reg.privateKey), want);
  // 3x-ui's registration answer: { privateKey, publicKey, address, endpoint }
  reg = W.importWarp(JSON.stringify({ privateKey: k.privateKey.export({ type: 'pkcs8', format: 'pem' }), publicKey: F.EDGE_PUB, address: ['172.16.0.2/32'], endpoint: '162.159.198.1' }));
  assert.equal(reg.endpoints.h3v4, '162.159.198.1');
  assert.deepEqual(reg.account, { id: '', type: '', warpPlus: false });
});

test('importWarp: what is not a WARP account is said, without repeating the key', () => {
  const x = crypto.generateKeyPairSync('x25519').privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');
  const p384 = crypto.generateKeyPairSync('ec', { namedCurve: 'secp384r1' }).privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');
  const { json } = usqueConfig();
  const cases = [
    '', '   ', 'vless://x@y:443', '{"a":', '[]', '{"outbounds":[{"protocol":"vless"}]}',
    JSON.stringify({ protocol: 'masque', settings: { address: '1.2.3.4', port: 443 }, streamSettings: { masqueSettings: { user: 'u', pass: 'p' } } }),
    JSON.stringify(Object.assign({}, json, { private_key: x })),
    JSON.stringify(Object.assign({}, json, { private_key: p384 })),
    JSON.stringify(Object.assign({}, json, { private_key: 'bm90IGEga2V5' })),
    JSON.stringify(Object.assign({}, json, { endpoint_pub_key: '' })),
    JSON.stringify(Object.assign({}, json, { endpoint_pub_key: 'not-a-key' })),
    JSON.stringify(Object.assign({}, json, { ipv4: '', ipv6: '' })),
    JSON.stringify(Object.assign({}, json, { ipv4: '999.1.1.1' }))
  ];
  for (const c of cases) {
    assert.throws(() => W.importWarp(c), (e) => {
      assert.equal(e.code, 'badImport', c);
      assert.equal(e.message.includes(json.private_key.slice(8, 40)), false);
      assert.equal(e.message.includes(x.slice(8, 40)), false);
      return true;
    });
  }
});

/* --------------------------------- servers:addWarp --------------------------------- */
/** warpHandler over a fake store and a stub createServer (the parser learns masque in T1). */
function handler(over = {}) {
  const store = { servers: [{ id: 'old', name: 'old' }] };
  const made = [];
  const logs = [];
  const deps = Object.assign({
    createServer: (f) => { made.push(f); return { id: 'n' + made.length, name: f.name, protocol: f.protocol, fields: f }; },
    getServers: () => store.servers.slice(),
    setServers: (list) => { store.servers = list; },
    connected: () => false,
    socksPort: () => 47808,
    now,
    log: (line, level) => logs.push([level, line])
  }, over);
  return { add: W.warpHandler(deps), store, made, logs, deps };
}

test('servers:addWarp: a new account → registered, one server per HTTP version made by createServer and saved after the old ones; the full list back, the new ones and the account', async () => {
  const api = F.fakeApi();
  const h = handler({ request: api });
  const res = await h.add({ mode: 'new', via: 'direct', license: '', http: 'both', endpoint: 'auto', cover: '', antiDpi: true });
  assert.equal(res.ok, true, res.error);
  assert.deepEqual(res.added.map((s) => s.name), ['☁ WARP · H3', '☁ WARP · H2']);
  assert.deepEqual(res.servers.map((s) => s.id), ['old', 'n1', 'n2']);
  assert.deepEqual(h.store.servers.map((s) => s.id), ['old', 'n1', 'n2']);
  assert.deepEqual(res.account, { id: F.DEVICE, type: 'free', warpPlus: false });
  assert.deepEqual(res.warnings, []);
  assert.equal(h.made[0].masqueHttp, 'h3');
  assert.equal(h.made[1].fragment, 'tlshello,100-200,10-20');
  const text = JSON.stringify(h.logs);
  assert.match(text, /WARP/);
  assert.equal(text.includes(F.TOKEN), false);
  assert.equal(text.includes(h.made[0].warpPrivateKey.replace(/-----[^-]+-----/g, '').trim().slice(0, 40)), false);
});

test('servers:addWarp: through the connection only when connected — otherwise notConnected and nothing is sent; the port asked is the live SOCKS port', async () => {
  const api = F.fakeApi();
  const h = handler({ request: api });
  let res = await h.add({ mode: 'new', via: 'proxy' });
  assert.deepEqual([res.ok, res.code], [false, 'notConnected']);
  assert.equal(api.calls.length, 0);
  assert.deepEqual(h.store.servers.map((s) => s.id), ['old']);
  // connected, no request injected: the real transport is built for the app's SOCKS port — dead here, so "notConnected" from the dial
  const dead = await F.deadPort();
  const h2 = handler({ connected: () => true, socksPort: () => dead });
  res = await h2.add({ mode: 'new', via: 'proxy' });
  assert.deepEqual([res.ok, res.code], [false, 'notConnected']);
});

test('servers:addWarp: import needs no network; bad options are refused BEFORE a device is registered; a second call while one runs is "busy"; createServer refusing is said', async () => {
  const { json } = usqueConfig();
  const api = F.fakeApi();
  let h = handler({ request: api });
  let res = await h.add({ mode: 'import', importText: JSON.stringify(json), http: 'h2', cover: 'www.example.com' });
  assert.equal(res.ok, true, res.error);
  assert.deepEqual(res.added.map((s) => s.name), ['☁ WARP · H2']);
  assert.equal(h.made[0].vcn, 'www.example.com');
  assert.equal(api.calls.length, 0);
  res = await h.add({ mode: 'import', importText: '{}' });
  assert.deepEqual([res.ok, res.code], [false, 'badImport']);
  for (const [args, code] of [[{ cover: '1.2.3.4' }, 'badCover'], [{ endpoint: 'custom', address: '' }, 'badAddress'], [{ license: 'nope' }, 'badLicense']]) {
    res = await h.add(Object.assign({ mode: 'new', via: 'direct' }, args));
    assert.deepEqual([res.ok, res.code], [false, code]);
  }
  assert.equal(api.calls.length, 0, 'no device was registered for a typo');
  // busy: the first sign-up waits on the API; a second click meanwhile registers nothing
  let release;
  const gate = new Promise((r) => { release = r; });
  h = handler({ request: async (req) => { await gate; return api(req); } });
  const first = h.add({ mode: 'new' });
  await new Promise((r) => setImmediate(r));
  res = await h.add({ mode: 'new' });
  assert.deepEqual([res.ok, res.code], [false, 'busy']);
  release();
  assert.equal((await first).ok, true);
  assert.equal(api.calls.filter((c) => c.method === 'POST').length, 1, 'one device, not two');
  res = await h.add({ mode: 'import', importText: JSON.stringify(json) });
  assert.equal(res.ok, true, 'free again once the first one finished');
  // createServer refuses (the parser before T1: "Unknown protocol: masque")
  h = handler({ request: F.fakeApi(), createServer: () => { throw new Error('Unknown protocol: masque'); } });
  res = await h.add({ mode: 'new' });
  assert.deepEqual([res.ok, res.code], [false, 'createFailed']);
  assert.match(res.error, /Unknown protocol/);
  assert.equal(res.detail, 'Unknown protocol: masque', 'the window puts the detail in its own sentence');
  assert.deepEqual(h.store.servers.map((s) => s.id), ['old'], 'nothing half-saved');
});

test('servers:addWarp: every refusal carries a detail for the window’s {msg} — Cloudflare’s words, the network error, the reason', async () => {
  const cases = [
    [{ request: F.fakeApi({ status: { 'POST /reg': 400 }, errorBody: { errors: [{ message: 'Invalid locale' }] } }) }, 'rejected', 'Invalid locale'],
    [{ request: async () => { throw Object.assign(new Error('x'), { code: 'ECONNRESET' }); } }, 'blocked', 'ECONNRESET'],
    [{ request: F.fakeApi({ status: { 'POST /reg': 429 } }) }, 'rateLimited', /429/]
  ];
  for (const [over, code, detail] of cases) {
    const res = await handler(over).add({ mode: 'new' });
    assert.equal(res.code, code);
    if (detail instanceof RegExp) assert.match(res.detail, detail); else assert.equal(res.detail, detail);
  }
  const res = await handler({}).add({ mode: 'import', importText: '[]' });
  assert.equal(res.code, 'badImport');
  assert.match(res.detail, /No WARP account/);
});
