'use strict';
/**
 * MASQUE (IETF CONNECT-IP, RFC 9484) end to end, against a REAL MASQUE server —
 * both ends Xray, all on loopback, nothing on the machine's network touched.
 *
 *   socks ─▶ client core ── masque out ══ HTTP/3 (QUIC) ══╗
 *   (tcp + udp)            (its own gVisor)  or HTTP/2 (TLS) ║
 *                                                           ▼
 *                              server core, masque in (one port, both versions)
 *                              gVisor ─▶ routing ├─ tcp ─▶ freedom ─▶ the page
 *                                                └─ udp ─▶ freedom ─▶ the echo
 *
 * Xray 26.9.30 brought the MASQUE outbound and inbound (XTLS/Xray-core #6807,
 * #6810, #6844). Before the app writes the outbound, this shows that the cores
 * it suggests carry a tunnel at all — both ways the outbound speaks: HTTP/3
 * (alpn unset) and HTTP/2 (alpn ["h2"]), against one server port serving both.
 *
 * Every check answers: the page on every round, the same over IPv6, 2 MB in one
 * piece, UDP datagrams echoed through SOCKS5 UDP ASSOCIATE — and a wrong
 * password fetches nothing, on either version, with the server logging that it
 * refused the credentials. Latencies are printed, not gated.
 *
 * The page is asked for at 192.0.2.1 / 2001:db8::1 (documentation ranges), not
 * 127.0.0.1: the target is an address INSIDE the tunnel, and the server's
 * freedom redirects every flow to the page anyway (finalRules allow, so no
 * default rule may block a private address). One line tries 127.0.0.1 as the
 * target for the record — it never gates. The certificate is made by the core
 * under test (`xray tls cert`); the client pins it (pinnedPeerCertSha256 — for
 * MASQUE, allowInsecure is a hard error at load).
 *
 *   IRNF_XRAY_EXE      the core under test, server and client (default bin/xray)
 *   IRNF_PROBE_PORT    base port, default 39950 (never 10808/10085: the app's own)
 *   IRNF_PROBE_ROUNDS  requests per line, default 10
 */
const fs = require('fs');
const os = require('os');
const net = require('net');
const path = require('path');
const http = require('http');
const dgram = require('dgram');
const crypto = require('crypto');
const { spawn, spawnSync } = require('child_process');

const BASE = Number(process.env.IRNF_PROBE_PORT || 39950);
const P = { masque: BASE, socks: BASE + 10, web: BASE + 20, echo: BASE + 21 };
const ROUNDS = Number(process.env.IRNF_PROBE_ROUNDS || 10);
/** The whole run, whatever hangs: CI must never wait out its own step timeout. */
const HARD_LIMIT_MS = 180000;
const TARGET4 = '192.0.2.1';
const TARGET6 = '2001:db8::1';
const UDP_DEST_PORT = 7;
const UDP_COUNT = 20;
const UDP_SIZE = 1000; // + 4 echo bytes + 28 headers: under the tunnel's MTU of 1280
const USER = 'ci';
const PASS = 'ci-pass';
const BIG = 2 * 1024 * 1024;
const BIG_BODY = crypto.randomBytes(BIG);
const BIG_SHA = crypto.createHash('sha256').update(BIG_BODY).digest('hex');
const exeName = (n) => (process.platform === 'win32' ? n + '.exe' : n);
const xray = process.env.IRNF_XRAY_EXE || path.join(__dirname, '..', 'bin', exeName('xray'));

/* ------------------------------ the far side ------------------------------ */

/** The page: a word, or 2 MB of random bytes at /big. */
function page() {
  const srv = http.createServer((req, res) => res.end(req.url === '/big' ? BIG_BODY : 'MASQUE-OK'));
  return new Promise((res) => srv.listen(P.web, '127.0.0.1', () => res(srv)));
}

/** A UDP echo that marks what it sends back, so a loop could not pass for it. */
function echo() {
  const s = dgram.createSocket('udp4');
  let heard = 0;
  s.on('message', (msg, ri) => { heard++; s.send(Buffer.concat([Buffer.from('ECHO'), msg]), ri.port, ri.address); });
  return new Promise((res) => s.bind(P.echo, '127.0.0.1', () => res({ close: () => s.close(), count: () => heard })));
}

/* --------------------------------- SOCKS5 --------------------------------- */

function ip6Bytes(s) {
  const [head, tail] = s.split('::');
  const h = head ? head.split(':') : [];
  const t = tail === undefined ? [] : (tail ? tail.split(':') : []);
  const groups = tail === undefined ? h : [...h, ...Array(8 - h.length - t.length).fill('0'), ...t];
  const b = Buffer.alloc(16);
  groups.forEach((g, i) => b.writeUInt16BE(parseInt(g, 16), i * 2));
  return b;
}

/** ATYP + address + port, as SOCKS5 writes a destination. */
function socksAddr(host, port) {
  let a;
  if (net.isIPv4(host)) a = Buffer.from([1, ...host.split('.').map(Number)]);
  else if (net.isIPv6(host)) a = Buffer.concat([Buffer.from([4]), ip6Bytes(host)]);
  else { const n = Buffer.from(host); a = Buffer.concat([Buffer.from([3, n.length]), n]); }
  const p = Buffer.alloc(2);
  p.writeUInt16BE(port);
  return Buffer.concat([a, p]);
}

/** The address at `off` (ATYP first): { host, port, end }, or null when cut short. */
function readSocksAddr(b, off) {
  const atyp = b[off];
  let host, at;
  if (atyp === 1) { if (b.length < off + 7) return null; host = [...b.slice(off + 1, off + 5)].join('.'); at = off + 5; }
  else if (atyp === 4) { if (b.length < off + 19) return null; host = b.slice(off + 1, off + 17).toString('hex').match(/.{4}/g).join(':'); at = off + 17; }
  else if (atyp === 3) { const n = b[off + 1]; if (b.length < off + 4 + n) return null; host = b.slice(off + 2, off + 2 + n).toString(); at = off + 2 + n; }
  else return null;
  return { host, port: b.readUInt16BE(at), end: at + 2 };
}

/** GET http://<host>/<pathname> through SOCKS5; resolves the body as a Buffer. */
function get(socksPort, host, pathname, timeoutMs = 20000) {
  return new Promise((resolve, reject) => {
    const s = net.connect(socksPort, '127.0.0.1');
    let settled = false;
    const fail = (e) => { if (settled) return; settled = true; s.destroy(); reject(e instanceof Error ? e : new Error(String(e))); };
    s.setTimeout(timeoutMs, () => fail(new Error('timed out')));
    s.on('error', fail);
    let stage = 0;
    const chunks = [];
    s.on('connect', () => s.write(Buffer.from([5, 1, 0])));
    s.on('data', (d) => {
      if (stage === 0) {
        stage = 1;
        return void s.write(Buffer.concat([Buffer.from([5, 1, 0]), socksAddr(host, 80)]));
      }
      if (stage === 1) {
        if (d[1] !== 0) return fail(new Error('socks connect refused (code ' + d[1] + ')'));
        stage = 2;
        const name = net.isIPv6(host) ? '[' + host + ']' : host;
        return void s.write('GET ' + pathname + ' HTTP/1.1\r\nHost: ' + name + '\r\nConnection: close\r\n\r\n');
      }
      chunks.push(d);
    });
    s.on('close', () => {
      if (settled) return;
      settled = true;
      const raw = Buffer.concat(chunks);
      const cut = raw.indexOf('\r\n\r\n');
      if (cut < 0) return reject(new Error(raw.length ? 'no HTTP response' : 'closed with nothing'));
      resolve(raw.slice(cut + 4));
    });
  });
}

/** SOCKS5 UDP ASSOCIATE on `ctl`: the relay to send datagrams to. */
function associate(ctl) {
  return new Promise((resolve, reject) => {
    let stage = 0;
    ctl.setTimeout(10000, () => reject(new Error('UDP ASSOCIATE timed out')));
    ctl.on('error', reject);
    ctl.on('close', () => reject(new Error('the SOCKS control connection closed')));
    ctl.on('connect', () => ctl.write(Buffer.from([5, 1, 0])));
    ctl.on('data', (d) => {
      if (stage === 0) { stage = 1; return void ctl.write(Buffer.from([5, 3, 0, 1, 0, 0, 0, 0, 0, 0])); }
      if (stage !== 1) return;
      stage = 2;
      if (d[1] !== 0) return reject(new Error('UDP ASSOCIATE refused (code ' + d[1] + ')'));
      ctl.setTimeout(0);
      const a = readSocksAddr(d, 3);
      if (!a) return reject(new Error('UDP ASSOCIATE answer cut short'));
      resolve({ host: !a.host || a.host === '0.0.0.0' ? '127.0.0.1' : a.host, port: a.port });
    });
  });
}

/**
 * UDP_COUNT datagrams to 192.0.2.1:7 through the SOCKS relay, one at a time,
 * each waited for (2 s) and resent at most twice. { got, resent }
 */
async function udpEcho(socksPort) {
  const ctl = net.connect(socksPort, '127.0.0.1');
  const sock = dgram.createSocket('udp4');
  sock.on('error', () => { /* a lost datagram is counted, not thrown */ });
  try {
    const relay = await associate(ctl);
    await new Promise((r) => sock.bind(0, '127.0.0.1', r));
    const inbox = [];
    let wake = null;
    sock.on('message', (m) => { inbox.push(m); if (wake) wake(); });
    const head = Buffer.concat([Buffer.from([0, 0, 0]), socksAddr(TARGET4, UDP_DEST_PORT)]);
    let got = 0, resent = 0;
    const rtt = [];
    for (let i = 0; i < UDP_COUNT; i++) {
      const payload = crypto.randomBytes(UDP_SIZE);
      const want = Buffer.concat([Buffer.from('ECHO'), payload]);
      let ok = false;
      const t0 = Date.now();
      for (let attempt = 0; attempt < 3 && !ok; attempt++) {
        if (attempt) resent++;
        sock.send(Buffer.concat([head, payload]), relay.port, relay.host);
        const until = Date.now() + 2000;
        while (!ok && Date.now() < until) {
          if (!inbox.length) {
            await new Promise((r) => { wake = r; setTimeout(r, Math.max(1, until - Date.now())); });
            wake = null;
          }
          while (inbox.length) {
            const m = inbox.shift();
            const a = m.length > 3 ? readSocksAddr(m, 3) : null;
            if (a && m.slice(a.end).equals(want)) ok = true;
          }
        }
      }
      if (ok) { got++; rtt.push(Date.now() - t0); }
      else if (got === 0 && i >= 2) break; // nothing came back at all: do not wait out the rest
    }
    return { got, resent, rtt };
  } finally {
    ctl.destroy();
    try { sock.close(); } catch { /* never bound */ }
  }
}

/* ------------------------------- processes ------------------------------- */

const kids = [];
let work = null;
function run(name, exe, args) {
  const p = spawn(exe, args, { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  const log = [];
  p.stdout.on('data', (d) => log.push(String(d)));
  p.stderr.on('data', (d) => log.push(String(d)));
  const kid = { name, proc: p, text: () => log.join('') };
  kids.push(kid);
  return kid;
}
function stop(kid) {
  const i = kids.indexOf(kid);
  if (i >= 0) kids.splice(i, 1);
  try { kid.proc.kill(); } catch { /* already gone */ }
}
function killAll() { for (const k of kids.splice(0)) { try { k.proc.kill(); } catch { /* already gone */ } } }
function cleanup() {
  killAll();
  if (work) {
    try { fs.rmSync(work, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }); } catch { /* best effort */ }
    work = null;
  }
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitPort(port, ms = 8000) {
  const until = Date.now() + ms;
  while (Date.now() < until) {
    const ok = await new Promise((res) => {
      const s = net.connect(port, '127.0.0.1');
      s.once('connect', () => { s.destroy(); res(true); });
      s.once('error', () => res(false));
    });
    if (ok) return true;
    await sleep(150);
  }
  return false;
}
/** The last few lines of a core's log that say something failed. */
function whyNot(log) {
  const lines = String(log).split(/\r?\n/).filter((l) => /fail|error|refused|timeout|closed|denied|unauthori[sz]ed|40\d|50\d/i.test(l));
  return lines.slice(-6).map((l) => '\n      ' + l.replace(/^\S+ \S+ /, '').slice(0, 280)).join('') || '(nothing failed in its log)';
}
function lastLine(r) {
  return ((r.stdout || '') + (r.stderr || '') + (r.error ? r.error.message : '')).trim().split(/\r?\n/).slice(-1)[0] || '(no output)';
}

/* --------------------------------- configs --------------------------------- */

function serverConfig(cert) {
  return {
    log: { loglevel: 'info' },
    inbounds: [{
      tag: 'masque-in', listen: '127.0.0.1', port: P.masque, protocol: 'masque',
      settings: { users: [{ email: USER, pass: PASS }], address: ['10.77.0.1/24', 'fd77::1/64'] },
      streamSettings: {
        network: 'masque', security: 'tls', masqueSettings: {},
        // both on one port: HTTP/3 over UDP and HTTP/2 over TCP
        tlsSettings: { alpn: ['h3', 'h2'], certificates: [{ certificate: cert.certificate, key: cert.key }] }
      }
    }],
    outbounds: [
      { tag: 'web', protocol: 'freedom', settings: { redirect: '127.0.0.1:' + P.web, finalRules: [{ action: 'allow' }] } },
      { tag: 'echo', protocol: 'freedom', settings: { redirect: '127.0.0.1:' + P.echo, finalRules: [{ action: 'allow' }] } }
    ],
    routing: { rules: [{ network: 'udp', outboundTag: 'echo' }, { network: 'tcp', outboundTag: 'web' }] }
  };
}

/**
 * The client, WRITTEN BY HAND: src/main/configBuilder.js does not know MASQUE
 * yet. The app's builder writes it in a later task; this probe then switches
 * to buildConfig, as probe-wg-base.js does for WireGuard.
 */
function clientConfig(socksPort, pin, h2, pass) {
  const tlsSettings = { serverName: 'localhost', pinnedPeerCertSha256: pin };
  if (h2) tlsSettings.alpn = ['h2']; // HTTP/2 only when alpn has h2 and not h3; anything else is HTTP/3
  return {
    log: { loglevel: 'info' },
    inbounds: [{ tag: 'socks-in', listen: '127.0.0.1', port: socksPort, protocol: 'socks', settings: { auth: 'noauth', udp: true, ip: '127.0.0.1' } }],
    outbounds: [{
      tag: 'out-masque', protocol: 'masque',
      settings: { address: '127.0.0.1', port: P.masque },
      streamSettings: { network: 'masque', security: 'tls', masqueSettings: { user: USER, pass }, tlsSettings }
    }]
  };
}

/* --------------------------------- the run --------------------------------- */

let failed = 0;
function report(ok, label, note, details) {
  if (ok === false) failed++;
  const mark = ok === null ? '·' : ok ? '✓' : '✗';
  console.log(`${mark} ${label}${note ? ' — ' + note : ''}`);
  for (const d of details || []) console.log('    ' + d);
}

/** Start a client; null (reported) when the core refused it or it never listened. */
async function startClient(id, label, socksPort, pin, h2, pass) {
  const file = path.join(work, id + '-client.json');
  fs.writeFileSync(file, JSON.stringify(clientConfig(socksPort, pin, h2, pass), null, 2));
  const test = spawnSync(xray, ['run', '-test', '-c', file], { encoding: 'utf8', timeout: 20000, windowsHide: true });
  if (test.status !== 0) { report(false, label, 'the core refused the client config — ' + lastLine(test)); return null; }
  const client = run(id, xray, ['run', '-c', file]);
  if (!await waitPort(socksPort)) {
    report(false, label, 'the client never opened its SOCKS port', [client.text().slice(-400)]);
    stop(client);
    return null;
  }
  return client;
}

const median = (a) => (a.length ? [...a].sort((x, y) => x - y)[a.length >> 1] : NaN);

/** One version with the right password: every check must answer. */
async function tunnel(label, socksPort, pin, h2, server) {
  const client = await startClient(h2 ? 'h2' : 'h3', label, socksPort, pin, h2, PASS);
  if (!client) return;
  const failedBefore = failed;
  let ok = 0, rounds = 0;
  const errors = new Map();
  const miss = (k) => errors.set(k, (errors.get(k) || 0) + 1);
  const took = [];
  for (let r = 0; r < ROUNDS; r++) {
    rounds++;
    const t0 = Date.now();
    try {
      const b = await get(socksPort, TARGET4, '/');
      if (b.toString() === 'MASQUE-OK') { ok++; took.push(Date.now() - t0); }
      else miss('body ' + JSON.stringify(b.toString('latin1').slice(0, 20)));
    } catch (e) { miss(e.message); }
    if (rounds === 3 && ok === 0) break; // nothing through the tunnel: the rest would only wait out the same timeouts
  }
  const detail = [...errors].map(([k, n]) => `${n}× ${k}`);
  if (!ok) {
    report(false, `${label} · page through ${TARGET4}`, `nothing answered in ${rounds} rounds — the rest skipped`, detail.concat('client log: ' + whyNot(client.text())));
    stop(client);
    return;
  }
  // the first request also builds the tunnel; the rest show what one connection through it costs
  report(ok === ROUNDS, `${label} · page through ${TARGET4}`,
    `${ok}/${ROUNDS} · first ${took[0]} ms (builds the tunnel), then median ${median(took.slice(1))} ms, max ${Math.max(...took.slice(1))} ms`,
    ok === ROUNDS ? [] : detail);

  try {
    const b = await get(socksPort, TARGET6, '/');
    report(b.toString() === 'MASQUE-OK', `${label} · page through ${TARGET6} (IPv6 in the tunnel)`, b.toString() === 'MASQUE-OK' ? 'answered' : 'body ' + JSON.stringify(b.toString('latin1').slice(0, 20)));
  } catch (e) { report(false, `${label} · page through ${TARGET6} (IPv6 in the tunnel)`, e.message); }

  const t0 = Date.now();
  try {
    const b = await get(socksPort, TARGET4, '/big', 60000);
    const s = (Date.now() - t0) / 1000;
    const same = b.length === BIG && crypto.createHash('sha256').update(b).digest('hex') === BIG_SHA;
    report(same, `${label} · 2 MB in one piece`, same ? `${s.toFixed(2)} s, ${(BIG / 1048576 / s).toFixed(1)} MB/s` : `${b.length} bytes, ${b.length === BIG ? 'other bytes' : 'cut short'}`);
  } catch (e) { report(false, `${label} · 2 MB in one piece`, e.message + ' after ' + ((Date.now() - t0) / 1000).toFixed(1) + ' s'); }

  try {
    const u = await udpEcho(socksPort);
    report(u.got === UDP_COUNT, `${label} · UDP through the tunnel (SOCKS5 UDP ASSOCIATE → echo)`,
      `${u.got}/${UDP_COUNT} echoed, ${u.resent} resent` + (u.rtt.length ? `, first ${u.rtt[0]} ms, then median ${median(u.rtt.slice(1))} ms` : ''));
  } catch (e) { report(false, `${label} · UDP through the tunnel (SOCKS5 UDP ASSOCIATE → echo)`, e.message); }

  // For the record, once (the client's netstack is the same for both versions):
  // does a loopback target travel the tunnel? Why the checks use 192.0.2.1.
  if (!h2) {
    const before = server.text().length;
    let what;
    try {
      const b = await get(socksPort, '127.0.0.1', '/', 8000);
      what = b.toString() === 'MASQUE-OK' ? 'answered' : 'answered something else';
    } catch (e) { what = 'no answer: ' + e.message; }
    const seen = /127\.0\.0\.1:80(?!\d)/.test(server.text().slice(before));
    report(null, `${label} · target 127.0.0.1 inside the tunnel`, `${what}; the server ${seen ? 'saw' : 'never saw'} that flow (not gated)`);
  }

  if (failed > failedBefore) console.log('    client log: ' + whyNot(client.text()));
  stop(client);
}

/** One version with a wrong password: nothing may come through. */
async function refused(label, socksPort, pin, h2, server) {
  const client = await startClient(h2 ? 'h2-wrong' : 'h3-wrong', label, socksPort, pin, h2, PASS + '-wrong');
  if (!client) return;
  const before = server.text().length;
  let through = 0;
  const why = [];
  for (let i = 0; i < 2; i++) {
    try {
      const b = await get(socksPort, TARGET4, '/', 15000);
      if (b.toString() === 'MASQUE-OK') through++;
      else why.push('body ' + JSON.stringify(b.toString('latin1').slice(0, 20)));
    } catch (e) { why.push(e.message); }
  }
  await sleep(300);
  // the server's own word that it was the credentials (a failed build is cached for 1 s: one line for both)
  const said = (server.text().slice(before).match(/authentication failed/gi) || []).length;
  report(through === 0 && said > 0, `${label} · refused`,
    `${through}/2 fetched (${[...new Set(why)].join(', ') || '-'}); the server logged "authentication failed" ×${said}`);
  stop(client);
}

async function main() {
  if (!fs.existsSync(xray)) { console.error(`no core at ${xray}`); process.exit(2); }
  work = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-masque-'));
  const version = (spawnSync(xray, ['version'], { encoding: 'utf8', windowsHide: true }).stdout || '').split(/\r?\n/)[0];

  // the certificate, made by the core itself; the pin is the SHA-256 of its DER, as hex
  const made = spawnSync(xray, ['tls', 'cert', '--domain=localhost', '--json'], { encoding: 'utf8', timeout: 20000, windowsHide: true });
  let cert;
  try { cert = JSON.parse(made.stdout); } catch { /* reported below */ }
  if (!cert || !Array.isArray(cert.certificate) || !Array.isArray(cert.key)) {
    console.error('`xray tls cert` gave no certificate: ' + lastLine(made));
    process.exit(1);
  }
  const pem = cert.certificate.join('\n') + '\n';
  const pin = new crypto.X509Certificate(pem).fingerprint256.replace(/:/g, '').toLowerCase();
  fs.writeFileSync(path.join(work, 'cert.pem'), pem);
  const hashed = spawnSync(xray, ['tls', 'hash', '--cert', path.join(work, 'cert.pem')], { encoding: 'utf8', timeout: 20000, windowsHide: true });
  const leaf = /Leaf SHA256:\s*([0-9a-f]{64})/i.exec(hashed.stdout || '');
  const pinNote = leaf ? (leaf[1].toLowerCase() === pin ? 'pin = `xray tls hash`' : 'pin ≠ `xray tls hash` ' + leaf[1]) : 'no `xray tls hash` to compare';
  console.log(`${version} · ${pinNote} · ${work}`);

  const sFile = path.join(work, 'server.json');
  fs.writeFileSync(sFile, JSON.stringify(serverConfig(cert), null, 2));
  const test = spawnSync(xray, ['run', '-test', '-c', sFile], { encoding: 'utf8', timeout: 20000, windowsHide: true });
  if (test.status !== 0) {
    const why = lastLine(test);
    if (/masque/i.test(why)) {
      console.error(`this core has no MASQUE (first in Xray 26.9.30): ${why}`);
      process.exit(2);
    }
    console.error('the core refused the server config: ' + why);
    process.exit(1);
  }

  const web = await page();
  const udp = await echo();
  const server = run('server', xray, ['run', '-c', sFile]);
  if (!await waitPort(P.masque)) {
    console.error('the MASQUE server never opened its port:\n' + server.text().slice(-800));
    process.exit(1);
  }

  const lines = [
    () => tunnel('HTTP/3', P.socks, pin, false, server),
    () => tunnel('HTTP/2', P.socks + 1, pin, true, server),
    () => refused('HTTP/3, wrong password', P.socks + 2, pin, false, server),
    () => refused('HTTP/2, wrong password', P.socks + 3, pin, true, server)
  ];
  for (const line of lines) {
    if (server.proc.exitCode !== null) { report(false, 'the MASQUE server', 'stopped', [server.text().slice(-800)]); break; }
    await line();
  }
  if (failed) console.log('server log: ' + whyNot(server.text()));
  console.log(`echo heard ${udp.count()} datagrams`);
  web.close(); udp.close();
  cleanup();
  console.log(failed ? `\n${failed} check(s) failed` : '\nMASQUE carries TCP and UDP over HTTP/3 and HTTP/2, and refuses a wrong password');
  process.exit(failed ? 1 : 0);
}

if (require.main === module) {
  process.on('exit', cleanup);
  process.on('SIGINT', () => { cleanup(); process.exit(130); });
  process.on('SIGTERM', () => { cleanup(); process.exit(143); });
  setTimeout(() => {
    console.log(`✗ the probe ran out of time (${HARD_LIMIT_MS / 1000} s) — stopped`);
    for (const k of kids) console.log(`  ${k.name} log: ` + whyNot(k.text()));
    process.exit(1);
  }, HARD_LIMIT_MS).unref();
  main().catch((e) => { cleanup(); console.error(e); process.exit(1); });
}
