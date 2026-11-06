#!/usr/bin/env node
'use strict';
/*
 * SNI spoof on the wire (src/main/sniSpoof.js): does sing-box, running the app's
 * own config (singboxBuilder.buildSingboxConfig with tls.spoof), really send a
 * forged ClientHello that carries the fake name — in a TCP segment the server
 * must drop — BEFORE the real one, and does the connection still work?
 *
 * Two network namespaces joined by a veth (the runner's network is not touched):
 *
 *   client namespace                      server namespace
 *   sing-box, the app's config  --veth-->  sing-box: a VLESS inbound over TLS (its own certificate),
 *   its SOCKS on 127.0.0.1                 a plain HTTP page beside it, and tcpdump on the link
 *
 * A page is fetched through the client's SOCKS; the capture on the server's end
 * of the link is read here (a pcap parser of this file's own: Ethernet, IPv4,
 * TCP, the TLS record and its server_name extension) and must show, per method:
 *
 *   control (spoof off)   exactly one ClientHello, with the real name — so the parser sees hellos at all;
 *   wrong-sequence        two: the fake name first, its sequence number LEFT of the window (seq + len ≤ ISN + 1,
 *                         ISN the client's SYN), then the real one at ISN + 1 — and the page answered, so the
 *                         server dropped the fake (had it taken the fake, the TLS handshake could not pass);
 *   wrong-checksum        two: the fake first with an INVALID TCP checksum, then the real one; the page answered.
 *
 * Needs root (sing-box's raw socket, the namespaces), Linux, IRNF_SPOOF_PROBE=1
 * and a sing-box of 1.14 or newer (IRNF_SINGBOX_EXE); tcpdump on the PATH. It
 * stops itself after 3 minutes and removes its namespaces whatever happened.
 *   IRNF_PROBE_PORT  the base port (the SOCKS port inside the client namespace; +1 the page's)
 */
const { spawn, spawnSync } = require('child_process');
const fs = require('fs');
const http = require('http');
const net = require('net');
const os = require('os');
const path = require('path');
const { buildSingboxConfig } = require('../src/main/singboxBuilder');
const { parseLink } = require('../src/main/parser');
const { singboxSpoofs } = require('../src/main/sniSpoof');

const BASE = Number(process.env.IRNF_PROBE_PORT || 25100);
const PORTS = { socks: BASE, page: BASE + 1 };
const TLS_PORT = 443;   // inside the server namespace: the port a real server would have
const NS_C = 'irnfspf-c', NS_S = 'irnfspf-s';
const IF_C = 'spf-c', IF_S = 'spf-s';
const IP_S = '10.201.0.1', IP_C = '10.201.0.2';
const SNI = 'own.example.test';
const FAKE = 'www.example.com';
const UUID = '11111111-1111-1111-1111-111111111111';
const SINGBOX = process.env.IRNF_SINGBOX_EXE || '';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/* ------------------------------ the child modes (run inside a namespace) ------------------------------ */

/** The page inside the server namespace: every GET answers one line. */
function pageMode() {
  const port = Number(process.argv[3]);
  http.createServer((req, res) => { res.setHeader('Connection', 'close'); res.end('spoof-probe-page\n'); }).listen(port, IP_S, () => console.log('listening'));
}

/** Inside the client namespace: GET http://<host>:<port>/ through the local SOCKS5 port, the body as one JSON line. */
function socksGetMode() {
  const [socksPort, host, port] = process.argv.slice(3);
  const s = net.connect(Number(socksPort), '127.0.0.1');
  const done = (o) => { clearTimeout(timer); console.log(JSON.stringify(o)); s.destroy(); process.exit(0); };
  const timer = setTimeout(() => done({ error: 'timeout' }), 12000);
  let stage = 0, buf = Buffer.alloc(0), body = '';
  s.on('connect', () => s.write(Buffer.from([5, 1, 0])));
  s.on('data', (d) => {
    if (stage === 2) { body += d; if (body.includes('spoof-probe-page')) done({ body: body.trim().split('\n').pop() }); return; }
    buf = Buffer.concat([buf, d]);
    if (stage === 0 && buf.length >= 2) {
      buf = buf.subarray(2); stage = 1;
      const p = Number(port);
      s.write(Buffer.from([5, 1, 0, 1, ...host.split('.').map(Number), p >> 8, p & 255]));
    }
    if (stage === 1 && buf.length >= 10) {
      if (buf[1] !== 0) return done({ error: 'socks refused ' + buf[1] });
      buf = buf.subarray(10); stage = 2;
      s.write(`GET / HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`);
    }
  });
  s.on('close', () => done({ error: 'closed', got: body.trim() }));
  s.on('error', (e) => done({ error: e.message }));
}

/* ------------------------------ the capture, read ------------------------------ */

/** The TCP checksum of a segment as the wire would compute it (IPv4 pseudo-header + the segment); 0 when right. */
function tcpChecksumLeft(ipSrc, ipDst, seg) {
  const pseudo = Buffer.alloc(12);
  ipSrc.copy(pseudo, 0); ipDst.copy(pseudo, 4);
  pseudo[9] = 6; pseudo.writeUInt16BE(seg.length, 10);
  const all = Buffer.concat([pseudo, seg, seg.length % 2 ? Buffer.alloc(1) : Buffer.alloc(0)]);
  let sum = 0;
  for (let i = 0; i < all.length; i += 2) sum += all.readUInt16BE(i);
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return (~sum) & 0xffff;
}

/** The server_name of a TLS ClientHello record, or null when `p` is no whole ClientHello. */
function clientHelloName(p) {
  if (p.length < 9 || p[0] !== 0x16 || p[1] !== 0x03 || p[5] !== 0x01) return null;
  let at = 9 + 2 + 32;                              // handshake header, version, random
  if (at >= p.length) return null;
  at += 1 + p[at];                                  // session id
  if (at + 2 > p.length) return null;
  at += 2 + p.readUInt16BE(at);                     // cipher suites
  if (at + 1 > p.length) return null;
  at += 1 + p[at];                                  // compression methods
  if (at + 2 > p.length) return null;
  const extEnd = Math.min(p.length, at + 2 + p.readUInt16BE(at));
  at += 2;
  while (at + 4 <= extEnd) {
    const type = p.readUInt16BE(at), len = p.readUInt16BE(at + 2);
    if (type === 0 && at + 4 + len <= extEnd) {
      const nameLen = p.readUInt16BE(at + 7);
      return p.subarray(at + 9, at + 9 + nameLen).toString();
    }
    at += 4 + len;
  }
  return '';
}

/**
 * The capture (libpcap, Ethernet) as the TCP segments to the TLS port, in order:
 * { syn, seq, len, name, checksumOk, flags } — `name` the ClientHello's server_name
 * (null for anything that is no hello), `syn` the client's SYN.
 */
function readCapture(file) {
  const b = fs.readFileSync(file);
  if (b.length < 24) return [];
  const magic = b.readUInt32LE(0);
  const le = magic === 0xa1b2c3d4 || magic === 0xa1b23c4d;
  const be = magic === 0xd4c3b2a1 || magic === 0x4d3cb2a1;
  if (!le && !be) throw new Error('not a pcap: magic ' + magic.toString(16));
  const u32 = (o) => (le ? b.readUInt32LE(o) : b.readUInt32BE(o));
  const link = u32(20);
  const out = [];
  let at = 24;
  while (at + 16 <= b.length) {
    const incl = u32(at + 8);
    const pkt = b.subarray(at + 16, at + 16 + incl);
    at += 16 + incl;
    let ip;
    if (link === 1) { if (pkt.length < 14 || pkt.readUInt16BE(12) !== 0x0800) continue; ip = pkt.subarray(14); }   // Ethernet
    else if (link === 101) ip = pkt;                                                                                // raw IP
    else if (link === 113) { if (pkt.length < 16 || pkt.readUInt16BE(14) !== 0x0800) continue; ip = pkt.subarray(16); }   // Linux cooked
    else continue;
    if (ip.length < 20 || (ip[0] >> 4) !== 4 || ip[9] !== 6) continue;
    const ihl = (ip[0] & 15) * 4, total = ip.readUInt16BE(2);
    const seg = ip.subarray(ihl, Math.min(ip.length, total));
    if (seg.length < 20) continue;
    const dst = seg.readUInt16BE(2);
    if (dst !== TLS_PORT) continue;
    const dataOff = (seg[12] >> 4) * 4, flags = seg[13];
    const payload = seg.subarray(dataOff);
    out.push({
      syn: !!(flags & 0x02) && !(flags & 0x10), seq: seg.readUInt32BE(4), len: payload.length, flags,
      name: payload.length ? clientHelloName(payload) : null,
      checksumOk: tcpChecksumLeft(ip.subarray(12, 16), ip.subarray(16, 20), seg) === 0
    });
  }
  return out;
}

/** (a - b) mod 2^32, as TCP sequence numbers are compared. */
const seqDiff = (a, b) => (a - b + 0x100000000) % 0x100000000;

/* ------------------------------ the probe ------------------------------ */

let failed = 0;
function gate(ok, name, detail) {
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}${detail ? ' — ' + detail : ''}`);
  if (!ok) failed++;
}
const run = (cmd, args, opts = {}) => {
  const r = spawnSync(cmd, args, Object.assign({ encoding: 'utf8', timeout: 20000 }, opts));
  if (r.status !== 0 && !opts.mayFail) throw new Error(`${cmd} ${args.join(' ')}: ${(r.stderr || r.stdout || r.error || '').toString().trim()}`);
  return r;
};
const inNs = (ns, args, opts) => run('ip', ['netns', 'exec', ns, ...args], opts);

function preconditions() {
  if (process.env.IRNF_SPOOF_PROBE !== '1' || process.platform !== 'linux' || !process.getuid || process.getuid() !== 0) {
    console.error('probe-sni-spoof: CI only — Linux, root and IRNF_SPOOF_PROBE=1 (it makes two network namespaces and a raw socket)');
    process.exit(2);
  }
  if (!SINGBOX || !fs.existsSync(SINGBOX)) { console.error('probe-sni-spoof: IRNF_SINGBOX_EXE is not a file'); process.exit(2); }
  const v = String(spawnSync(SINGBOX, ['version'], { encoding: 'utf8', timeout: 15000 }).stdout || '');
  const version = (/(\d+\.\d+\.\d+\S*)/.exec(v) || [])[1] || '';
  SB_VERSION = version;
  if (!singboxSpoofs(version)) { console.error(`probe-sni-spoof: sing-box ${version || '?'} has no tls.spoof (1.14+)`); process.exit(2); }
  if (spawnSync('tcpdump', ['--version'], { encoding: 'utf8' }).error) { console.error('probe-sni-spoof: tcpdump is not on the PATH'); process.exit(2); }
  console.log(`sing-box ${version} · ports ${BASE}..${BASE + 1} · tls ${TLS_PORT} in the server namespace`);
}

function netnsUp() {
  netnsDown();
  for (const ns of [NS_C, NS_S]) run('ip', ['netns', 'add', ns]);
  run('ip', ['link', 'add', IF_C, 'type', 'veth', 'peer', 'name', IF_S]);
  run('ip', ['link', 'set', IF_C, 'netns', NS_C]);
  run('ip', ['link', 'set', IF_S, 'netns', NS_S]);
  for (const [ns, ifc, ip] of [[NS_C, IF_C, IP_C], [NS_S, IF_S, IP_S]]) {
    inNs(ns, ['ip', 'link', 'set', 'lo', 'up']);
    inNs(ns, ['ip', 'addr', 'add', ip + '/24', 'dev', ifc]);
    inNs(ns, ['ip', 'link', 'set', ifc, 'up']);
  }
  inNs(NS_C, ['ip', 'route', 'add', 'default', 'via', IP_S]);
  // checksums on the wire, not left to an offload the capture would show as wrong (ethtool may be absent: then as it is)
  inNs(NS_C, ['ethtool', '-K', IF_C, 'tx', 'off'], { mayFail: true });
  inNs(NS_S, ['ethtool', '-K', IF_S, 'tx', 'off'], { mayFail: true });
}
function netnsDown() {
  for (const ns of [NS_C, NS_S]) run('ip', ['netns', 'del', ns], { mayFail: true });
}

const children = new Set();
function spawnInNs(ns, exe, args, label) {
  const p = spawn('ip', ['netns', 'exec', ns, exe, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '';
  p.stdout.on('data', (d) => { out += d; });
  p.stderr.on('data', (d) => { out += d; });
  p.text = () => out;
  p.tail = () => out.split('\n').slice(-25).map((l) => `      [${label}] ${l}`).join('\n');
  p.on('exit', () => children.delete(p));
  children.add(p);
  return p;
}
async function stop(p, signal = 'SIGTERM') {
  if (!p || p.exitCode != null) return;
  p.kill(signal);
  await Promise.race([new Promise((r) => p.once('exit', r)), sleep(4000)]);
  if (p.exitCode == null) p.kill('SIGKILL');
}
function listeningInNs(ns, ip, port) {
  const r = inNs(ns, ['ss', '-Hltn', `sport = :${port}`], { mayFail: true });
  return String(r.stdout || '').includes(`${ip}:${port}`) || String(r.stdout || '').includes(`:${port} `);
}
async function waitFor(fn, ms = 8000) {
  for (let t = 0; t < ms; t += 100) { if (fn()) return true; await sleep(100); }
  return false;
}

/** The server: sing-box with a VLESS inbound over TLS on the certificate it made, dialling the page directly. */
function serverConfig(certPath, keyPath) {
  return {
    log: { level: 'info', timestamp: false },
    inbounds: [{ type: 'vless', tag: 'vless-in', listen: IP_S, listen_port: TLS_PORT, users: [{ name: 'ci', uuid: UUID }],
      tls: { enabled: true, server_name: SNI, certificate_path: certPath, key_path: keyPath } }],
    outbounds: [{ type: 'direct', tag: 'direct' }]
  };
}

/** The client: the app's own config for a VLESS over TCP + TLS to the server, SNI spoof as the record asks. */
let SB_VERSION = '';   // the binary's, for the builder's record_fragment gate
function clientConfig(spoof, method, cutHello) {
  const server = parseLink(`vless://${UUID}@${IP_S}:${TLS_PORT}?type=tcp&security=tls&sni=${SNI}&fp=chrome&allowInsecure=1#spoof-probe`);
  if (spoof) Object.assign(server, { sniSpoof: true, sniSpoofNames: [FAKE], sniSpoofMethod: method });
  return buildSingboxConfig(server, { socksPort: PORTS.socks, httpPort: 0, dnsRemote: [IP_S], logLevel: 'info', modules: { sniSpoof: spoof }, cutHello: !!cutHello, singboxVersion: SB_VERSION });
}

/** One round: the client up with `cfg`, tcpdump on the server's end, one page fetch, the capture read. */
async function round(name, cfg, work) {
  const cfgFile = path.join(work, `client-${name}.json`);
  fs.writeFileSync(cfgFile, JSON.stringify(cfg, null, 2));
  const pcap = path.join(work, `${name}.pcap`);
  const dump = spawnInNs(NS_S, 'tcpdump', ['-i', IF_S, '-U', '-s', '0', '-w', pcap, 'tcp', 'port', String(TLS_PORT)], 'tcpdump');
  await waitFor(() => /listening on/.test(dump.text()), 6000);
  await sleep(300);
  const client = spawnInNs(NS_C, SINGBOX, ['run', '-c', cfgFile], 'client');
  const up = await waitFor(() => client.exitCode != null || listeningInNs(NS_C, '127.0.0.1', PORTS.socks), 10000);
  let fetched = { error: 'the client never listened' };
  if (up && client.exitCode == null) {
    const r = inNs(NS_C, [process.execPath, __filename, '--socks-get', String(PORTS.socks), IP_S, String(PORTS.page)], { mayFail: true, timeout: 20000 });
    try { fetched = JSON.parse(String(r.stdout || '').trim().split('\n').pop() || '{}'); } catch { fetched = { error: 'no answer: ' + String(r.stdout || r.stderr || '').trim() }; }
  }
  await sleep(500);
  await stop(client);
  await stop(dump, 'SIGINT');
  let segments = [];
  try { segments = readCapture(pcap); } catch (e) { fetched = Object.assign({}, fetched, { capture: e.message }); }
  const hellos = segments.filter((s) => s.name !== null);
  const syn = segments.find((s) => s.syn);
  return { fetched, segments, hellos, syn, clientLog: client.tail() };
}

async function main() {
  preconditions();
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-sni-spoof-'));
  const killer = setTimeout(() => { console.log('FAIL the probe ran past 3 minutes'); process.exit(1); }, 180000);
  killer.unref();
  let server = null, page = null;
  try {
    netnsUp();
    // the certificate, made by sing-box: the private key's PEM, then the certificate's (as probe-tuic-anytls)
    const pair = spawnSync(SINGBOX, ['generate', 'tls-keypair', SNI], { encoding: 'utf8', timeout: 20000 });
    const out = String(pair.stdout || '');
    const at = out.indexOf('-----BEGIN CERTIFICATE-----');
    if (pair.status !== 0 || at < 0) throw new Error('sing-box generate tls-keypair: ' + String(pair.stderr || pair.stdout || '').trim().split('\n').pop());
    const keyPath = path.join(work, 'key.pem'), certPath = path.join(work, 'cert.pem');
    fs.writeFileSync(keyPath, out.slice(0, at).trim() + '\n');
    fs.writeFileSync(certPath, out.slice(at).trim() + '\n');

    page = spawnInNs(NS_S, process.execPath, [__filename, '--page', String(PORTS.page)], 'page');
    const serverFile = path.join(work, 'server.json');
    fs.writeFileSync(serverFile, JSON.stringify(serverConfig(certPath, keyPath), null, 2));
    server = spawnInNs(NS_S, SINGBOX, ['run', '-c', serverFile], 'server');
    if (!await waitFor(() => listeningInNs(NS_S, IP_S, TLS_PORT), 10000)) throw new Error('the VLESS server never listened\n' + server.tail());
    if (!await waitFor(() => /listening/.test(page.text()), 8000)) throw new Error('the page never listened\n' + page.tail());

    // 1. control: no spoof — one hello, the real name, and the page
    const ctl = await round('control', clientConfig(false), work);
    gate(ctl.fetched.body === 'spoof-probe-page', 'control: the page answers through the tunnel', ctl.fetched.error && (ctl.fetched.error + '\n' + ctl.clientLog));
    gate(ctl.hellos.length === 1 && ctl.hellos[0].name === SNI, 'control: exactly one ClientHello, with the real name', `${ctl.hellos.length} hello(s): ${ctl.hellos.map((h) => h.name).join(', ')}`);
    gate(!!ctl.syn, 'control: the client’s SYN is in the capture');

    // 2. wrong-sequence: the fake first, left of the window; the real at ISN + 1; the page
    const ws = await round('wrong-sequence', clientConfig(true, 'wrong-sequence'), work);
    gate(ws.fetched.body === 'spoof-probe-page', 'wrong-sequence: the page answers — the server dropped the forged hello', ws.fetched.error && (ws.fetched.error + '\n' + ws.clientLog));
    gate(ws.hellos.length === 2, 'wrong-sequence: two ClientHellos on the wire', `${ws.hellos.length}: ${ws.hellos.map((h) => h.name).join(', ')}`);
    if (ws.hellos.length === 2 && ws.syn) {
      const [fake, real] = ws.hellos;
      const isn1 = (ws.syn.seq + 1) % 0x100000000;
      gate(fake.name === FAKE && real.name === SNI, 'wrong-sequence: the fake name goes first, the real one second', `${fake.name}, ${real.name}`);
      // patterniha's segment is ISN + 1 - len: wholly before the window. Left of it at all is the gate (a
      // segment the server took in part would have broken the handshake, and the page gate above with it)
      const behind = seqDiff(isn1, fake.seq);
      gate(behind > 0 && behind < 0x80000000, 'wrong-sequence: the forged segment’s sequence number lies left of the window (seq < ISN + 1)',
        `fake seq = ISN + 1 − ${behind}, len ${fake.len}${behind >= fake.len ? ' (wholly before the window)' : ''}; real seq = ISN + ${seqDiff(real.seq, ws.syn.seq)}`);
      gate(real.seq === isn1, 'wrong-sequence: the real hello starts at ISN + 1', `ISN+${seqDiff(real.seq, ws.syn.seq)}`);
      gate(fake.checksumOk, 'wrong-sequence: the forged segment’s checksum is right (only its sequence number is off)', fake.checksumOk ? '' : 'checksum wrong (an offload left on?)');
    } else gate(false, 'wrong-sequence: the capture has the SYN and both hellos', ws.syn ? '' : 'no SYN');

    // 3. wrong-checksum: the fake first with a bad checksum; the real one; the page
    const wc = await round('wrong-checksum', clientConfig(true, 'wrong-checksum'), work);
    gate(wc.fetched.body === 'spoof-probe-page', 'wrong-checksum: the page answers — the server dropped the forged hello', wc.fetched.error && (wc.fetched.error + '\n' + wc.clientLog));
    gate(wc.hellos.length === 2, 'wrong-checksum: two ClientHellos on the wire', `${wc.hellos.length}: ${wc.hellos.map((h) => h.name).join(', ')}`);
    if (wc.hellos.length === 2 && wc.syn) {
      const [fake, real] = wc.hellos;
      gate(fake.name === FAKE && real.name === SNI, 'wrong-checksum: the fake name goes first, the real one second', `${fake.name}, ${real.name}`);
      gate(!fake.checksumOk, 'wrong-checksum: the forged segment’s TCP checksum is invalid');
      gate(real.checksumOk, 'wrong-checksum: the real hello’s checksum is right', real.checksumOk ? '' : 'wrong (an offload left on? ethtool missing)');
      gate(real.seq === (wc.syn.seq + 1) % 0x100000000, 'wrong-checksum: the real hello starts at ISN + 1');
    } else gate(false, 'wrong-checksum: the capture has the SYN and both hellos', wc.syn ? '' : 'no SYN');
    // 4. the spoof beside the cut hello (helloCut.js: record_fragment when the path reads names): the fake still first
    const cutCfg = clientConfig(true, 'wrong-sequence', true);
    gate(!!(cutCfg.outbounds || []).find((o) => o.tls && o.tls.record_fragment && o.tls.spoof), 'spoof + cut hello: the config carries both record_fragment and spoof');
    const wr = await round('wrong-sequence-cut', cutCfg, work);
    gate(wr.fetched.body === 'spoof-probe-page', 'spoof + cut hello: the page answers', wr.fetched.error && (wr.fetched.error + '\n' + wr.clientLog));
    gate(wr.hellos.length >= 1 && wr.hellos[0].name === FAKE, 'spoof + cut hello: the forged hello with the allowed name goes first', `${wr.hellos.length}: ${wr.hellos.map((h) => h.name).join(', ')}`);
  } catch (e) {
    gate(false, 'the probe ran', e && e.message);
  } finally {
    await stop(server);
    await stop(page);
    for (const p of [...children]) await stop(p, 'SIGKILL');
    netnsDown();
    clearTimeout(killer);
  }
  console.log(failed ? `# ${failed} gate(s) FAILED` : '# all gates passed');
  process.exit(failed ? 1 : 0);
}

if (process.argv[2] === '--page') pageMode();
else if (process.argv[2] === '--socks-get') socksGetMode();
else main().catch((e) => { console.error(e); process.exit(1); });
