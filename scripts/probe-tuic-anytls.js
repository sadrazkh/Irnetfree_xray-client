'use strict';
/**
 * TUIC and AnyTLS end to end, against REAL servers — both ends sing-box, all
 * on loopback, nothing on the machine's network touched.
 *
 *   socks ─▶ client sing-box ══ TUIC (QUIC) ══▶ server sing-box, tuic in   ─▶ direct ─▶ the page
 *   (tcp + udp)  (the app's   ══ AnyTLS (TLS) ═▶ server sing-box, anytls in ─▶ direct ─▶ the UDP echo
 *                 own config)
 *
 * Only sing-box has these two (engineChoice.isSingboxOnly). The client config
 * is the APP'S OWN: a server parsed from a share link, as an import parses one
 * (parser.parseLink), and the config singboxBuilder.buildSingboxConfig writes
 * for it — the one a connect runs. The servers take a certificate sing-box
 * made itself (`sing-box generate tls-keypair`); the clients ask for
 * allow_insecure / insecure, as such links do, which is sing-box's `insecure`
 * (no pin is learnt for these two: certPin.wantsPin).
 *
 * Every check answers: the page on every round, 1 MB in one piece, UDP
 * datagrams echoed through SOCKS5 UDP ASSOCIATE (TUIC in both relay modes,
 * native and quic, the first with no ALPN in its link — the builder's h3 —
 * the second with 0-RTT; AnyTLS over its TCP stream) — and a wrong password
 * fetches nothing, on either. Latencies are printed, not gated.
 *
 *   IRNF_SINGBOX_EXE   sing-box (default bin/sing-box); none there: skipped, exit 0
 *   IRNF_PROBE_PORT    base port, default 24100 (never 10808/10085: the app's own)
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
const { parseLink } = require('../src/main/parser');
const { buildSingboxConfig } = require('../src/main/singboxBuilder');

const BASE = Number(process.env.IRNF_PROBE_PORT || 24100);
const P = { tuic: BASE, anytls: BASE + 1, socks: BASE + 10, web: BASE + 20, echo: BASE + 21 };
const ROUNDS = Number(process.env.IRNF_PROBE_ROUNDS || 10);
/** The whole run, whatever hangs: CI must never wait out its own step timeout. */
const HARD_LIMIT_MS = 150000;
const SNI = 'irnf.test';
const UUID = crypto.randomUUID();
const PASS = 'ci-' + crypto.randomBytes(6).toString('hex');
const UDP_COUNT = 20;
const UDP_SIZE = 1000;
const BIG = 1024 * 1024;
const BIG_BODY = crypto.randomBytes(BIG);
const BIG_SHA = crypto.createHash('sha256').update(BIG_BODY).digest('hex');
const exeName = (n) => (process.platform === 'win32' ? n + '.exe' : n);
const singbox = process.env.IRNF_SINGBOX_EXE || path.join(__dirname, '..', 'bin', exeName('sing-box'));

/* ------------------------------ the far side ------------------------------ */

/** The page: a word, or 1 MB of random bytes at /big. */
function page() {
  const srv = http.createServer((req, res) => res.end(req.url === '/big' ? BIG_BODY : 'TUIC-ANYTLS-OK'));
  return new Promise((res) => srv.listen(P.web, '127.0.0.1', () => res(srv)));
}

/** A UDP echo that marks what it sends back, so a loop could not pass for it. */
function echo() {
  const s = dgram.createSocket('udp4');
  s.on('message', (msg, ri) => s.send(Buffer.concat([Buffer.from('ECHO'), msg]), ri.port, ri.address));
  return new Promise((res) => s.bind(P.echo, '127.0.0.1', () => res(s)));
}

/* --------------------------------- SOCKS5 --------------------------------- */

/** ATYP + an IPv4 address + port, as SOCKS5 writes a destination. */
function socksAddr4(host, port) {
  const p = Buffer.alloc(2);
  p.writeUInt16BE(port);
  return Buffer.concat([Buffer.from([1, ...host.split('.').map(Number)]), p]);
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

/** GET http://127.0.0.1:<web><pathname> through SOCKS5; done when Content-Length bytes are in: { body, ms }. */
function get(socksPort, pathname, timeoutMs = 15000) {
  return new Promise((resolve, reject) => {
    const t0 = Date.now();
    const s = net.connect(socksPort, '127.0.0.1');
    let settled = false;
    const fail = (e) => { if (settled) return; settled = true; s.destroy(); reject(e instanceof Error ? e : new Error(String(e))); };
    s.setTimeout(timeoutMs, () => fail(new Error('timed out')));
    s.on('error', fail);
    let stage = 0, total = 0, headEnd = -1, want = -1;
    const chunks = [];
    const finish = () => {
      if (settled) return;
      settled = true;
      const raw = Buffer.concat(chunks);
      s.destroy();
      resolve({ body: raw.slice(headEnd + 4, want >= 0 ? headEnd + 4 + want : undefined), ms: Date.now() - t0 });
    };
    s.on('connect', () => s.write(Buffer.from([5, 1, 0])));
    s.on('data', (d) => {
      if (stage === 0) {
        stage = 1;
        return void s.write(Buffer.concat([Buffer.from([5, 1, 0]), socksAddr4('127.0.0.1', P.web)]));
      }
      if (stage === 1) {
        if (d[1] !== 0) return fail(new Error('socks connect refused (code ' + d[1] + ')'));
        stage = 2;
        return void s.write('GET ' + pathname + ' HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n');
      }
      chunks.push(d);
      total += d.length;
      if (headEnd < 0) {
        const raw = Buffer.concat(chunks.splice(0));
        chunks.push(raw);
        headEnd = raw.indexOf('\r\n\r\n');
        if (headEnd >= 0) {
          const m = /\r\ncontent-length:\s*(\d+)/i.exec(raw.slice(0, headEnd).toString('latin1'));
          want = m ? Number(m[1]) : -1;
        }
      }
      if (headEnd >= 0 && want >= 0 && total - headEnd - 4 >= want) finish();
    });
    s.on('close', () => {
      if (settled) return;
      if (headEnd < 0) return fail(new Error(total ? 'no HTTP response' : 'closed with nothing'));
      finish();
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

/** UDP_COUNT datagrams to the echo through the SOCKS relay, one at a time, each waited for (2 s) and resent at most twice. */
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
    const head = Buffer.concat([Buffer.from([0, 0, 0]), socksAddr4('127.0.0.1', P.echo)]);
    let got = 0, resent = 0;
    for (let i = 0; i < UDP_COUNT; i++) {
      const payload = crypto.randomBytes(UDP_SIZE);
      const want = Buffer.concat([Buffer.from('ECHO'), payload]);
      let ok = false;
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
      if (ok) got++;
      else if (got === 0 && i >= 2) break; // nothing came back at all: do not wait out the rest
    }
    return { got, resent };
  } finally {
    ctl.destroy();
    try { sock.close(); } catch { /* never bound */ }
  }
}

/* ------------------------------- processes ------------------------------- */

const kids = [];
let work = null;
function run(name, args) {
  const p = spawn(singbox, args, { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
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
function cleanup() {
  for (const k of kids.splice(0)) { try { k.proc.kill(); } catch { /* already gone */ } }
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
  const lines = String(log).split(/\r?\n/).filter((l) => /fail|error|refused|timeout|closed|denied|unauthori[sz]ed|auth/i.test(l));
  return lines.slice(-6).map((l) => '\n      ' + l.slice(0, 280)).join('') || '(nothing failed in its log)';
}
function lastLine(r) {
  return ((r.stdout || '') + (r.stderr || '') + (r.error ? r.error.message : '')).trim().split(/\r?\n/).slice(-1)[0] || '(no output)';
}

/* --------------------------------- configs --------------------------------- */

/** The servers: TUIC (its users' uuid + password) and AnyTLS (a password), both on the certificate sing-box made. */
function serverConfig(certPath, keyPath) {
  const tls = { enabled: true, server_name: SNI, certificate_path: certPath, key_path: keyPath };
  return {
    log: { level: 'info', timestamp: false },
    inbounds: [
      { type: 'tuic', tag: 'tuic-in', listen: '127.0.0.1', listen_port: P.tuic, users: [{ name: 'ci', uuid: UUID, password: PASS }],
        congestion_control: 'bbr', tls: Object.assign({ alpn: ['h3'] }, tls) },
      { type: 'anytls', tag: 'anytls-in', listen: '127.0.0.1', listen_port: P.anytls, users: [{ name: 'ci', password: PASS }], tls }
    ],
    outbounds: [{ type: 'direct', tag: 'direct' }],
    route: { final: 'direct' }
  };
}

/** The links an import would read — the client's server is what parseLink makes of them. */
const enc = encodeURIComponent;
const LINKS = {
  // no ALPN in the link: the builder's h3 must be what a TUIC server takes
  'tuic-native': (pass) => `tuic://${UUID}:${enc(pass)}@127.0.0.1:${P.tuic}?sni=${SNI}&congestion_control=bbr&udp_relay_mode=native&allow_insecure=1#probe-tuic-native`,
  'tuic-quic': (pass) => `tuic://${UUID}:${enc(pass)}@127.0.0.1:${P.tuic}?sni=${SNI}&alpn=h3&congestion_control=cubic&udp_relay_mode=quic&reduce_rtt=1&heartbeat=5s&allow_insecure=1#probe-tuic-quic`,
  anytls: (pass) => `anytls://${enc(pass)}@127.0.0.1:${P.anytls}?sni=${SNI}&fp=chrome&insecure=1#probe-anytls`
};

/** The app's own config for the server a link makes; its resolver on loopback, so nothing could leave the machine. */
function clientConfig(kind, pass, socksPort) {
  const server = parseLink(LINKS[kind](pass));
  return buildSingboxConfig(server, { socksPort, httpPort: 0, dnsRemote: ['127.0.0.1'], logLevel: 'info' });
}

/* --------------------------------- the run --------------------------------- */

let failed = 0;
function report(ok, label, note, details) {
  if (ok === false) failed++;
  const mark = ok === null ? '·' : ok ? '✓' : '✗';
  console.log(`${mark} ${label}${note ? ' — ' + note : ''}`);
  for (const d of details || []) console.log('    ' + d);
}

/** Start a client; null (reported) when sing-box refused it or it never listened. */
async function startClient(id, label, config, socksPort) {
  const file = path.join(work, id + '-client.json');
  fs.writeFileSync(file, JSON.stringify(config, null, 2));
  const check = spawnSync(singbox, ['check', '-c', file], { encoding: 'utf8', timeout: 20000, windowsHide: true });
  if (check.status !== 0) { report(false, label, 'sing-box refused the client config — ' + lastLine(check)); return null; }
  const client = run(id, ['run', '-c', file]);
  if (!await waitPort(socksPort)) {
    report(false, label, 'the client never opened its SOCKS port', [client.text().slice(-400)]);
    stop(client);
    return null;
  }
  return client;
}

const median = (a) => (a.length ? [...a].sort((x, y) => x - y)[a.length >> 1] : NaN);

/** One kind with the right password: every check must answer. */
async function tunnel(kind, socksPort, server) {
  const label = kind;
  const client = await startClient(kind, label, clientConfig(kind, PASS, socksPort), socksPort);
  if (!client) return;
  let ok = 0, rounds = 0;
  const errors = new Map();
  const took = [];
  for (let r = 0; r < ROUNDS; r++) {
    rounds++;
    try {
      const { body, ms } = await get(socksPort, '/');
      if (body.toString() === 'TUIC-ANYTLS-OK') { ok++; took.push(ms); }
      else errors.set('body', (errors.get('body') || 0) + 1);
    } catch (e) { errors.set(e.message, (errors.get(e.message) || 0) + 1); }
    if (rounds === 3 && ok === 0) break; // nothing through the tunnel: the rest would only wait out the same timeouts
  }
  const detail = [...errors].map(([k, n]) => `${n}× ${k}`);
  if (!ok) {
    report(false, `${label} · the page`, `nothing answered in ${rounds} rounds — the rest skipped`,
      detail.concat('client log: ' + whyNot(client.text()), 'server log: ' + whyNot(server.text())));
    stop(client);
    return;
  }
  report(ok === ROUNDS, `${label} · the page`,
    `${ok}/${ROUNDS} · first ${took[0]} ms (builds the tunnel), then median ${median(took.slice(1))} ms`, ok === ROUNDS ? [] : detail);

  try {
    const { body, ms } = await get(socksPort, '/big', 60000);
    const sha = crypto.createHash('sha256').update(body).digest('hex');
    report(sha === BIG_SHA, `${label} · 1 MB in one piece`, sha === BIG_SHA ? `${ms} ms` : `${body.length} bytes, not the page's`);
  } catch (e) { report(false, `${label} · 1 MB in one piece`, e.message); }

  try {
    const u = await udpEcho(socksPort);
    report(u.got === UDP_COUNT, `${label} · UDP echoed (SOCKS5 UDP ASSOCIATE)`, `${u.got}/${UDP_COUNT}${u.resent ? `, ${u.resent} resent` : ''}`,
      u.got === UDP_COUNT ? [] : ['client log: ' + whyNot(client.text())]);
  } catch (e) { report(false, `${label} · UDP echoed (SOCKS5 UDP ASSOCIATE)`, e.message); }
  stop(client);
}

/** The same kind with a wrong password: nothing may come through. */
async function refused(kind, socksPort) {
  const label = `${kind} · a wrong password`;
  const client = await startClient(kind + '-wrong', label, clientConfig(kind, PASS + '-wrong', socksPort), socksPort);
  if (!client) return;
  let through = 0;
  for (let r = 0; r < 3; r++) {
    try { const { body } = await get(socksPort, '/', 6000); if (body.toString() === 'TUIC-ANYTLS-OK') through++; } catch { /* refused, as it should be */ }
  }
  report(through === 0, label, through ? `${through}/3 pages came through` : 'fetched nothing');
  stop(client);
}

async function main() {
  if (!fs.existsSync(singbox)) {
    console.log(`· skipped: no sing-box at ${singbox} (IRNF_SINGBOX_EXE)`);
    return 0;
  }
  const v = spawnSync(singbox, ['version'], { encoding: 'utf8', timeout: 15000, windowsHide: true });
  console.log(`${path.basename(singbox)} ${((/(\d+\.\d+\.\d+\S*)/.exec(String(v.stdout || '')) || [])[1]) || '?'} · ports ${BASE}..${BASE + 21}`);
  work = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-tuic-anytls-'));

  // the certificate, made by sing-box: the private key's PEM, then the certificate's
  const pair = spawnSync(singbox, ['generate', 'tls-keypair', SNI], { encoding: 'utf8', timeout: 20000, windowsHide: true });
  const out = String(pair.stdout || '');
  const at = out.indexOf('-----BEGIN CERTIFICATE-----');
  if (pair.status !== 0 || at < 0) { report(false, 'a certificate', 'sing-box generate tls-keypair: ' + lastLine(pair)); return 1; }
  const keyPath = path.join(work, 'key.pem');
  const certPath = path.join(work, 'cert.pem');
  fs.writeFileSync(keyPath, out.slice(0, at).trim() + '\n');
  fs.writeFileSync(certPath, out.slice(at).trim() + '\n');

  const web = await page();
  const udp = await echo();
  try {
    const file = path.join(work, 'server.json');
    fs.writeFileSync(file, JSON.stringify(serverConfig(certPath, keyPath), null, 2));
    const check = spawnSync(singbox, ['check', '-c', file], { encoding: 'utf8', timeout: 20000, windowsHide: true });
    if (check.status !== 0) { report(false, 'the servers', 'sing-box refused their config — ' + lastLine(check)); return 1; }
    const server = run('server', ['run', '-c', file]);
    if (!await waitPort(P.anytls)) { report(false, 'the servers', 'the AnyTLS server never listened', [server.text().slice(-400)]); return 1; }
    await sleep(300);   // TUIC's UDP socket has no port to knock on: a moment for it
    await tunnel('tuic-native', P.socks, server);
    await tunnel('tuic-quic', P.socks + 1, server);
    await tunnel('anytls', P.socks + 2, server);
    await refused('tuic-native', P.socks + 3);
    await refused('anytls', P.socks + 4);
  } finally {
    web.close();
    udp.close();
  }
  console.log(failed ? `\n${failed} check(s) failed` : '\nevery check answered');
  return failed ? 1 : 0;
}

const limit = setTimeout(() => { console.log(`✗ the probe ran past ${HARD_LIMIT_MS / 1000} s — stopped`); cleanup(); process.exit(1); }, HARD_LIMIT_MS);
main().then((code) => { clearTimeout(limit); cleanup(); process.exit(code); },
  (e) => { clearTimeout(limit); console.log('✗ ' + (e && e.stack || e)); cleanup(); process.exit(1); });
