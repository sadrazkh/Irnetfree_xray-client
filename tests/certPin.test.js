'use strict';
/**
 * Certificate pinning on first use (the replacement for allowInsecure).
 *
 * The fixture is `bin/xray.exe tls cert -domain localhost -expire 240h` output
 * (EC P-256, self-signed, SAN localhost); its key header is relabelled
 * "EC PRIVATE KEY" because Node's OpenSSL will not decode an EC key under the
 * "RSA PRIVATE KEY" label xray writes. Expiry does not matter here: the probe
 * verifies nothing on purpose, and the core skips validity once a pin is set.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const tls = require('node:tls');
const net = require('node:net');
const fs = require('node:fs');
const path = require('node:path');
const { X509Certificate } = require('node:crypto');

const { fetchLeafPin, pinOf, normalizePin, directServers, pinTargets, staleCertPins, PinWatch, PIN_MISMATCH } = require('../src/main/certPin');

const FIXTURE = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', 'selfsigned.json'), 'utf8'));
const CERT = FIXTURE.certificate.join('\n');
const KEY = FIXTURE.key.join('\n');
const DER = Buffer.from(CERT.replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''), 'base64');
/** SHA-256 of the fixture's DER — the value the core wants in pinnedPeerCertSha256. */
const FIXTURE_PIN = 'ab11bf7ac877baa539294f5a3c864b8ed43e6fe3a9a8230fc2db7fff85c27fde';

/** A TLS server on a random loopback port; `fn` gets the port and resolves when done. */
async function withTlsServer(opts, fn) {
  const srv = tls.createServer(Object.assign({ cert: CERT, key: KEY }, opts), (s) => { s.on('error', () => {}); });
  await new Promise(r => srv.listen(0, '127.0.0.1', r));
  try { return await fn(srv.address().port, srv); }
  finally { await new Promise(r => srv.close(r)); }
}

/* ----------------------------- hashes ----------------------------- */

test('pinOf is the SHA-256 of the DER — the certificate’s standard fingerprint', () => {
  assert.equal(pinOf(DER), FIXTURE_PIN);
  assert.equal(pinOf(DER), new X509Certificate(CERT).fingerprint256.replace(/:/g, '').toLowerCase());
});

test('normalizePin: the core’s tolerant forms collapse to lowercase hex; junk is empty', () => {
  const colons = FIXTURE_PIN.toUpperCase().match(/../g).join(':');
  assert.equal(normalizePin(colons), FIXTURE_PIN);
  assert.equal(normalizePin(' ' + FIXTURE_PIN.toUpperCase() + '\n'), FIXTURE_PIN);
  assert.equal(normalizePin(FIXTURE_PIN), FIXTURE_PIN);
  assert.equal(normalizePin(FIXTURE_PIN.slice(1)), '', '63 hex chars is not a SHA-256');
  assert.equal(normalizePin(FIXTURE_PIN + '0'), '');
  assert.equal(normalizePin('not a pin'), '');
  assert.equal(normalizePin(''), '');
  assert.equal(normalizePin(null), '');
  assert.equal(normalizePin(undefined), '');
  assert.equal(normalizePin(42), '');
});

/* ----------------------------- the probe ----------------------------- */

test('fetchLeafPin reads the certificate a self-signed server presents and hangs up', async () => {
  await withTlsServer({}, async (port, srv) => {
    let opened = 0, closed = 0;
    srv.on('connection', (raw) => { opened++; raw.on('close', () => { closed++; }); });
    const pin = await fetchLeafPin({ host: '127.0.0.1', port, servername: 'localhost', timeoutMs: 3000 });
    assert.equal(pin, FIXTURE_PIN);
    // the socket is destroyed as soon as the certificate is in hand
    await new Promise(r => setTimeout(r, 100));
    assert.equal(opened, 1);
    assert.equal(closed, 1);
  });
});

test('fetchLeafPin sends SNI for a host name and none for an IP (RFC 6066; Node warns otherwise)', async () => {
  const seen = [];
  const SNICallback = (name, cb) => { seen.push(name); cb(null, tls.createSecureContext({ cert: CERT, key: KEY })); };
  await withTlsServer({ SNICallback }, async (port) => {
    await fetchLeafPin({ host: '127.0.0.1', port, servername: 'cdn.example.com', timeoutMs: 3000 });
    await fetchLeafPin({ host: '127.0.0.1', port, servername: '127.0.0.1', timeoutMs: 3000 });
    await fetchLeafPin({ host: '127.0.0.1', port, timeoutMs: 3000 });
  });
  assert.deepEqual(seen, ['cdn.example.com']);
});

test('fetchLeafPin rejects when nothing listens', async () => {
  const port = await new Promise((resolve) => {
    const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
  });
  await assert.rejects(fetchLeafPin({ host: '127.0.0.1', port, timeoutMs: 3000 }), /ECONNREFUSED/);
});

test('fetchLeafPin times out against a server that never speaks TLS', async () => {
  // accepts, reads the ClientHello (an unread socket never emits 'end') and says nothing
  const srv = net.createServer((s) => { s.on('error', () => {}); s.resume(); });
  await new Promise(r => srv.listen(0, '127.0.0.1', r));
  try {
    await assert.rejects(
      fetchLeafPin({ host: '127.0.0.1', port: srv.address().port, servername: 'localhost', timeoutMs: 150 }),
      /150 ms/);
  } finally { await new Promise(r => srv.close(r)); }
});

/* ----------------------------- which servers are dialled directly ----------------------------- */

const tlsServer = (id, over) => Object.assign({
  id, name: id, address: id + '.example', port: 443,
  outbound: { protocol: 'vless', streamSettings: { network: 'ws', security: 'tls', tlsSettings: { serverName: id + '.example', allowInsecure: true } } }
}, over);
const A = tlsServer('a'), B = tlsServer('b'), C = tlsServer('c');
const PINNED = tlsServer('p', { certPin: FIXTURE_PIN });
const SAFE = tlsServer('safe'); SAFE.outbound.streamSettings.tlsSettings.allowInsecure = false;
const REALITY = tlsServer('re'); REALITY.outbound.streamSettings = { network: 'tcp', security: 'reality', realitySettings: {} };
const byId = { a: A, b: B, c: C, p: PINNED, safe: SAFE, re: REALITY };

test('directServers: single → the server, chain → its first hop', () => {
  assert.deepEqual(directServers({ mode: 'single', server: A }), [A]);
  assert.deepEqual(directServers({ mode: 'chain', chain: [B, A, C] }), [B]);
  assert.deepEqual(directServers({ mode: 'chain', chain: [null, { id: 'x' }, A, C] }), [A], 'members without an outbound are skipped, as configBuilder does');
  assert.deepEqual(directServers({ mode: 'single' }), []);
  assert.deepEqual(directServers(null), []);
});

test('directServers: advanced and pool look at every target — the server itself or a chain’s first hop', () => {
  const chainsById = { c1: [B, A], c2: [C] };
  const adv = { mode: 'advanced', serversById: byId, chainsById, chain: [PINNED, A],
    rules: [{ target: 'a' }, { target: 'direct' }, { target: 'block' }, null, { target: 'chain:c1' }, { target: 'chain' }, { target: 'nope' }, { target: 'chain:c2' }],
    def: 'safe' };
  assert.deepEqual(directServers(adv).map(s => s.id), ['a', 'b', 'p', 'c', 'safe']);
  const pool = { mode: 'pool', serversById: byId, chainsById, entries: [{ target: 'chain:c1' }, { target: 'a' }, null, { target: 'chain:missing' }], primary: 'chain:c1' };
  assert.deepEqual(directServers(pool).map(s => s.id), ['b', 'a']);
});

test('pinTargets: probe = directly dialled, asked for allowInsecure, no pin yet; behind = the same but only reachable through a hop', () => {
  assert.deepEqual(pinTargets({ mode: 'single', server: A }), { probe: [A], behind: [] });
  assert.deepEqual(pinTargets({ mode: 'single', server: PINNED }), { probe: [], behind: [] }, 'already pinned');
  assert.deepEqual(pinTargets({ mode: 'single', server: SAFE }), { probe: [], behind: [] }, 'verifies normally');
  assert.deepEqual(pinTargets({ mode: 'single', server: REALITY }), { probe: [], behind: [] }, 'REALITY has its own verification');
  assert.deepEqual(pinTargets({ mode: 'chain', chain: [A, B, PINNED] }), { probe: [A], behind: [B] });
  // a server that is both an exit behind a hop and a direct target elsewhere is probed, not reported
  const adv = { mode: 'advanced', serversById: byId, chainsById: { c1: [A, B] }, rules: [{ target: 'chain:c1' }], def: 'b' };
  assert.deepEqual(pinTargets(adv), { probe: [A, B], behind: [] });
  // duplicates collapse: the same server behind two chains is reported once
  const twice = { mode: 'advanced', serversById: byId, chainsById: { c1: [A, C], c2: [B, C] }, rules: [{ target: 'chain:c1' }], def: 'chain:c2' };
  assert.deepEqual(pinTargets(twice), { probe: [A, B], behind: [C] });
});

/* ----------------------------- the core’s mismatch line ----------------------------- */

// Captured from Xray 26.3.27 and PattN 26.9.1 dialling the fixture server with a wrong
// pin (log level info — at warning the core says nothing at all).
const MISMATCH = '2026/09/03 19:08:23.723507 [Info] [2474940142] app/proxyman/outbound: app/proxyman/outbound: failed to process outbound traffic > proxy/trojan: failed to find an available destination > common/retry: [transport/internet/tls: peer cert is unrecognized (against pinnedPeerCertSha256)] > common/retry: all retry attempts failed';
const DIAL = (id, host, port) => `2026/09/03 19:08:17.724176 [Info] [${id}] transport/internet/tcp: dialing TCP to tcp:${host}:${port}`;
const withId = (id) => MISMATCH.replace('[2474940142]', `[${id}]`);

test('PIN_MISMATCH matches the core’s runtime line and not its config-load rejection of allowInsecure', () => {
  assert.match(MISMATCH, PIN_MISMATCH);
  assert.doesNotMatch('Failed to build TLS config. > The feature "allowInsecure" has been removed and migrated to "pinnedPeerCertSha256"', PIN_MISMATCH);
});

test('PinWatch: with one pinned server live, the mismatch line names it — once', () => {
  const w = new PinWatch();
  assert.equal(w.onLine(MISMATCH), null, 'nothing live');
  w.setLive([A, PINNED]);
  assert.deepEqual(w.live, [PINNED], 'only pinned servers can mismatch');
  assert.equal(w.onLine(DIAL(1, 'p.example', 443)), null);
  assert.deepEqual(w.onLine(MISMATCH), [PINNED]);
  assert.equal(w.onLine(MISMATCH), null, 'the core repeats the line on every retry; the pin is already cleared');
  assert.deepEqual(w.live, []);
});

test('PinWatch: several live — the session id of the dial line says which server', () => {
  const P2 = tlsServer('q', { certPin: FIXTURE_PIN });
  const w = new PinWatch();
  w.setLive([PINNED, P2]);
  w.onLine(DIAL(77, 'q.example', 443));
  w.onLine(DIAL(78, 'p.example', 443));
  w.onLine('2026/09/03 19:08:17 [Info] [77] app/dispatcher: default route for tcp:example.com:80');
  assert.deepEqual(w.onLine(withId(77)), [P2]);
  assert.deepEqual(w.live, [PINNED]);
  assert.deepEqual(w.onLine(withId(78)), [PINNED]);
  assert.deepEqual(w.live, []);
});

test('PinWatch: an uncorrelated line with several candidates clears them all rather than none', () => {
  const P2 = tlsServer('q', { certPin: FIXTURE_PIN });
  const w = new PinWatch();
  w.setLive([PINNED, P2]);
  assert.deepEqual(w.onLine(withId(5)), [PINNED, P2]);
  assert.deepEqual(w.live, []);
  w.clear();
  assert.equal(w.onLine(MISMATCH), null);
});

/* ------------------------- the branch review's findings ------------------------- */

// H4. The core names a pin mismatch only at log level `info`, and the app runs
// at `warning` — PinWatch alone can therefore never fire, and a server whose
// certificate rotated would stop connecting for ever with nothing said. Asking
// the servers before the dial works at any log level.
test('staleCertPins names the pinned servers that now present something else', async () => {
  const srv = (id, port, certPin) => ({
    id, name: id.toUpperCase(), address: 'h', port, certPin,
    outbound: { streamSettings: { security: 'tls', tlsSettings: {} } }
  });
  const A = 'a'.repeat(64), B = 'b'.repeat(64), C = 'c'.repeat(64), Z = 'z0'.repeat(32).replace(/z/g, 'e');
  const same = srv('a', 1, A);
  const rotated = srv('b', 2, B);
  const unreachable = srv('c', 3, C);
  const probe = async ({ port }) => {
    if (port === 1) return A;
    if (port === 2) return Z;          // the server presents another certificate
    throw new Error('connect ECONNREFUSED');
  };
  assert.deepEqual(await staleCertPins([same, rotated, unreachable], probe), [rotated],
    'only a certificate we actually saw, and that differs — unreachable is not changed');
  assert.deepEqual(await staleCertPins([], probe), []);
  assert.deepEqual(await staleCertPins([{ id: 'd', address: 'h', port: 4 }], probe), [], 'no pin, nothing to check');
});

test('staleCertPins compares pins the way the core does: hex, case- and separator-insensitive', async () => {
  const s = {
    id: 'a', name: 'A', address: 'h', port: 1,
    certPin: 'AB:11:BF:7A:C8:77:BA:A5:39:29:4F:5A:3C:86:4B:8E:D4:3E:6F:E3:A9:A8:23:0F:C2:DB:7F:FF:85:C2:7F:DE',
    outbound: { streamSettings: { security: 'tls', tlsSettings: {} } }
  };
  const lower = 'ab11bf7ac877baa539294f5a3c864b8ed43e6fe3a9a8230fc2db7fff85c27fde';
  assert.deepEqual(await staleCertPins([s], async () => lower), [], 'the same certificate, written differently');
});

test('staleCertPins asks with the SNI the config uses, not just the address', async () => {
  const asked = [];
  const s = {
    id: 'a', name: 'A', address: '1.2.3.4', port: 443, certPin: 'a'.repeat(64),
    outbound: { streamSettings: { security: 'tls', tlsSettings: { serverName: 'front.example.com' } } }
  };
  await staleCertPins([s], async (o) => { asked.push(o); return 'a'.repeat(64); });
  assert.deepEqual(asked, [{ host: '1.2.3.4', port: 443, servername: 'front.example.com' }]);
});
