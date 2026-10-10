'use strict';
/**
 * A WireGuard base that is also "exit at the base", end to end, against a REAL
 * WireGuard peer — all on loopback, nothing on the machine's network touched.
 *
 *   socks ─▶ client core ── rule 192.168/16 ─▶ exit at the base ───────┐
 *                        └─ rule via.test ──▶ hop, through the base ─┐ │
 *                                                                    ▼ ▼
 *                                              the base (WireGuard) ──udp──▶ wg peer (sing-box)
 *                                                                              ├─▶ corp DNS + intranet page
 *                                                                              └─▶ the hop (xray) ─▶ its page
 *
 * Until v1.23.0 the builder wrote the WireGuard twice — once as the base the
 * hop rides on, once as the exit — two sessions on one key. The peer keeps only
 * the newest, so each handshake cut the other line off: about half of every
 * request on either line failed. Now the exit is a freedom dialling through the
 * base's own outbound: one session. Run twice — the base a server, then a chain
 * ending in the WireGuard (a corporate tunnel behind a hop, like the owner's).
 *
 * Every check answers: the intranet page fetched by a name the corporate DNS
 * resolved inside the tunnel, the hop's page, 2 MB each way at once on both
 * lines, the exit's own traffic figure — and exactly one WireGuard outbound.
 *
 *   IRNF_XRAY_EXE      the core under test (default bin/xray)
 *   IRNF_SINGBOX_EXE   the WireGuard peer (default bin/sing-box)
 *   IRNF_PROBE_PORT    base port, default 39800
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
const { buildConfig } = require('../src/main/configBuilder');

const BASE = Number(process.env.IRNF_PROBE_PORT || 39800);
const P = { hop: BASE + 1, wg: BASE + 2, front: BASE + 3, socks: BASE + 10, dns: BASE + 20, web: BASE + 21, web2: BASE + 22 };
const ROUNDS = Number(process.env.IRNF_PROBE_ROUNDS || 10);
const CORP_IP = '192.168.45.7';
// inside the WireGuard's AllowedIPs (10.0.0.0/8), outside the peer's own subnet (10.99.0.1/24)
const HOP_ADDR = '10.88.0.5';
const HOP_PORT = 8443;
const BIG = 2 * 1024 * 1024;
const UUID = '2c0f0d9a-6b3a-4f0e-9a1f-8c2b4d6e7a10';
const CRLF = String.fromCharCode(13, 10);
const exeName = (n) => (process.platform === 'win32' ? n + '.exe' : n);
const xray = process.env.IRNF_XRAY_EXE || path.join(__dirname, '..', 'bin', exeName('xray'));
const singbox = process.env.IRNF_SINGBOX_EXE || path.join(__dirname, '..', 'bin', exeName('sing-box'));

/* ------------------------------ the far side ------------------------------ */

/** A DNS that knows only *.corp.test, reachable only through the tunnel. */
function corpDns() {
  const s = dgram.createSocket('udp4');
  let asked = 0;
  s.on('message', (msg, ri) => {
    let i = 12; const parts = [];
    while (msg[i]) { parts.push(msg.slice(i + 1, i + 1 + msg[i]).toString()); i += msg[i] + 1; }
    const qend = i + 1;
    if (qend + 4 > msg.length) return;
    asked++;
    const hit = msg.readUInt16BE(qend) === 1 && /\.corp\.test$/.test(parts.join('.'));
    const head = Buffer.from(msg.slice(0, qend + 4));
    head.writeUInt16BE(0x8180, 2);
    head.writeUInt16BE(1, 4);
    head.writeUInt16BE(hit ? 1 : 0, 6);
    if (!hit) return void s.send(head, ri.port, ri.address);
    const ans = Buffer.concat([Buffer.from([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]), Buffer.from(CORP_IP.split('.').map(Number))]);
    s.send(Buffer.concat([head, ans]), ri.port, ri.address);
  });
  return new Promise((res) => s.bind(P.dns, '127.0.0.1', () => res({ close: () => s.close(), count: () => asked })));
}

/** A page: `word`, or 2 MB at /big. */
function page(port, word) {
  const srv = http.createServer((req, res) => res.end(req.url === '/big' ? Buffer.alloc(BIG, 120) : word));
  return new Promise((res) => srv.listen(port, '127.0.0.1', () => res(srv)));
}

/** GET http://<host><pathname> through SOCKS5, sending the NAME (the core resolves it). */
function get(host, pathname, timeoutMs = 20000) {
  return new Promise((resolve, reject) => {
    const s = net.connect(P.socks, '127.0.0.1');
    const fail = (e) => { s.destroy(); reject(e instanceof Error ? e : new Error(String(e))); };
    s.setTimeout(timeoutMs, () => fail(new Error('timed out')));
    s.on('error', fail);
    let stage = 0;
    const chunks = [];
    s.on('connect', () => s.write(Buffer.from([5, 1, 0])));
    s.on('data', (d) => {
      if (stage === 0) {
        stage = 1;
        const name = Buffer.from(host);
        return void s.write(Buffer.concat([Buffer.from([5, 1, 0, 3, name.length]), name, Buffer.from([0, 80])]));
      }
      if (stage === 1) {
        if (d[1] !== 0) return fail(new Error('socks connect refused (code ' + d[1] + ')'));
        stage = 2;
        return void s.write('GET ' + pathname + ' HTTP/1.1' + CRLF + 'Host: ' + host + CRLF + 'Connection: close' + CRLF + CRLF);
      }
      chunks.push(d);
    });
    s.on('close', () => {
      const raw = Buffer.concat(chunks).toString('latin1');
      const cut = raw.indexOf(CRLF + CRLF);
      if (cut < 0) return reject(new Error('no response'));
      resolve(raw.slice(cut + 4));
    });
  });
}

/* ------------------------------- processes ------------------------------- */

const kids = [];
function run(exe, args, cwd) {
  const p = spawn(exe, args, { cwd, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  const log = [];
  p.stdout.on('data', (d) => log.push(String(d)));
  p.stderr.on('data', (d) => log.push(String(d)));
  kids.push(p);
  return { proc: p, text: () => log.join('') };
}
function killAll() { for (const p of kids.splice(0)) { try { p.kill(); } catch { /* already gone */ } } }
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
function keypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
  return {
    priv: privateKey.export({ type: 'pkcs8', format: 'der' }).slice(-32).toString('base64'),
    pub: publicKey.export({ type: 'spki', format: 'der' }).slice(-32).toString('base64')
  };
}
/** The last few lines of a core's log that say something failed. */
function whyNot(log) {
  const lines = String(log).split(/\r?\n/).filter((l) => /fail|error|refused|timeout|closed/i.test(l));
  return lines.slice(-6).map((l) => l.replace(/^\S+ \S+ /, '').slice(0, 300)).join(' | ') || '(nothing failed in its log)';
}

/** The core's own per-outbound counters (the metrics listener the app reads). */
function outboundStats(port) {
  return new Promise((resolve) => {
    http.get('http://127.0.0.1:' + port + '/debug/vars', (r) => {
      const c = [];
      r.on('data', (d) => c.push(d));
      r.on('end', () => { try { resolve((JSON.parse(Buffer.concat(c).toString()).stats || {}).outbound || {}); } catch { resolve({}); } });
    }).on('error', () => resolve({}));
  });
}

/* --------------------------------- the run --------------------------------- */

/**
 * The plan a connect makes of a profile whose base is the WireGuard (or a
 * chain ending in it): "exit at the base" resolved (routingProfiles.
 * resolveBaseTargets: the base itself, via none) and a hop through the base.
 */
function probePlan(wg, chained) {
  const vless = (id, address, port, wsPath) => ({
    id, name: id, protocol: 'vless', address, port,
    outbound: {
      protocol: 'vless',
      settings: { vnext: [{ address, port, users: [{ id: UUID, encryption: 'none' }] }] },
      streamSettings: { network: 'ws', security: 'none', wsSettings: { path: wsPath } }
    }
  });
  const front = vless('front', '127.0.0.1', P.front, '/f');
  const hop = vless('hop', HOP_ADDR, HOP_PORT, '/x');
  const base = chained ? 'chain:corp' : 'wg';
  return {
    mode: 'advanced', serversById: { wg, hop, front }, chainsById: { corp: [front, wg] }, chain: [], base,
    rules: [
      { type: 'ip', value: '192.168.0.0/16', target: base, via: 'none' },
      { type: 'domain', value: 'full:via.test', target: 'hop' }
    ],
    def: 'direct', defVia: 'inherit'
  };
}

async function scenario(work, chained, cli, srv, dnsSrv) {
  const wg = {
    id: 'wg', name: 'Corp WG', protocol: 'wireguard', address: '127.0.0.1', port: P.wg,
    dns: ['192.168.60.1'], dnsDomains: ['corp.test'],
    outbound: {
      protocol: 'wireguard',
      settings: {
        secretKey: cli.priv, address: ['10.10.10.42/32'], mtu: 1420,
        peers: [{ publicKey: srv.pub, endpoint: '127.0.0.1:' + P.wg, allowedIPs: ['192.168.0.0/16', '10.0.0.0/8'] }]
      },
      streamSettings: { sockopt: {} }
    }
  };
  const cfg = buildConfig(probePlan(wg, chained), {
    socksPort: P.socks, httpPort: P.socks + 1, apiPort: P.socks + 2,
    routingMode: 'global', blockAds: false, enableSniffing: true,
    dnsManaged: true, dnsRemote: ['https://1.1.1.1/dns-query'], dnsDirect: ['8.8.8.8'],
    ipv6: false, logLevel: 'info', geoAssets: false
  });
  const file = path.join(work, (chained ? 'chain' : 'server') + '-client.json');
  fs.writeFileSync(file, JSON.stringify(cfg, null, 2));
  const name = chained ? 'a chain [hop → WireGuard] as the base' : 'a WireGuard server as the base';
  const exitTag = chained ? 'out-chain-corp' : 'out-wg';
  const problems = [];
  const wgs = cfg.outbounds.filter((o) => o.protocol === 'wireguard').map((o) => o.tag);
  if (wgs.length !== 1) problems.push(`${wgs.length} WireGuard outbounds (${wgs.join(', ')}) — one key, two sessions`);

  const test = spawnSync(xray, ['run', '-test', '-c', file], { encoding: 'utf8', timeout: 20000, windowsHide: true });
  if (test.status !== 0) {
    const why = ((test.stdout || '') + (test.stderr || '')).trim().split(/\r?\n/).slice(-1)[0];
    return { name, problems: problems.concat('the core refused the config — ' + why) };
  }
  const client = run(xray, ['run', '-c', file], work);
  if (!await waitPort(P.socks)) {
    killAll();
    return { name, problems: problems.concat('the client never opened its SOCKS port\n  ' + client.text().slice(-400)) };
  }
  const asked = dnsSrv.count();
  const tally = { exit: 0, via: 0 };
  const errors = new Map();
  const miss = (what, e) => errors.set(what + ': ' + e.message, (errors.get(what + ': ' + e.message) || 0) + 1);
  let rounds = 0;
  for (let r = 0; r < ROUNDS; r++) {
    // a fresh corporate name each round: each is a DNS query through the exit too
    try { const b = await get(`r${r}.corp.test`, '/'); if (b === 'CORP-OK') tally.exit++; else miss('exit at the base', new Error('body ' + JSON.stringify(b.slice(0, 20)))); } catch (e) { miss('exit at the base', e); }
    try { const b = await get('via.test', '/'); if (b === 'HOP-OK') tally.via++; else miss('through the base', new Error('body ' + JSON.stringify(b.slice(0, 20)))); } catch (e) { miss('through the base', e); }
    rounds++;
    // nothing at all through the tunnel: the rest would only wait out the same timeouts
    if (rounds === 3 && tally.exit + tally.via === 0) break;
  }
  if (rounds < ROUNDS) {
    problems.push(`nothing answered on either line in ${rounds} rounds — stopped there`);
    problems.push('client log: ' + whyNot(client.text()));
  }
  const big = rounds < ROUNDS ? [] : await Promise.allSettled([get('big1.corp.test', '/big', 40000), get('via.test', '/big', 40000), get('big2.corp.test', '/big', 40000), get('via.test', '/big', 40000)]);
  const bigOk = big.filter((b) => b.status === 'fulfilled' && b.value.length === BIG).length;
  const stats = await outboundStats(P.socks + 2);
  try { client.proc.kill(); } catch { /* already gone */ }
  await sleep(400);

  if (tally.exit !== ROUNDS) problems.push(`exit at the base answered ${tally.exit}/${ROUNDS}`);
  if (tally.via !== ROUNDS) problems.push(`through the base answered ${tally.via}/${ROUNDS}`);
  if (bigOk !== 4) problems.push(`2 MB on both lines at once: ${bigOk}/4`);
  if (dnsSrv.count() <= asked) problems.push('the corporate DNS was never asked — the names were resolved somewhere else');
  const own = (stats[exitTag] || {}).downlink || 0;
  if (own < 2 * BIG) problems.push(`the exit's own figure (${exitTag}) is ${own} bytes, not its 4 MB`);
  for (const [k, n] of errors) problems.push(`${n}× ${k}`);
  if (problems.length && rounds === ROUNDS) problems.push('client log: ' + whyNot(client.text()));
  const mb = (v) => ((v || 0) / 1048576).toFixed(1);
  return {
    name, problems,
    note: `exit ${tally.exit}/${ROUNDS} · through ${tally.via}/${ROUNDS} · 2 MB ×4 at once ${bigOk}/4 · ` +
      `${exitTag} ↓${mb(own)} MB, ${wgs[0] || '?'} ↓${mb((stats[wgs[0]] || {}).downlink)} MB`
  };
}

async function main() {
  for (const [what, exe] of [['core', xray], ['WireGuard peer (sing-box)', singbox]]) {
    if (!fs.existsSync(exe)) { console.error(`no ${what} at ${exe}`); process.exit(2); }
  }
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-wgbase-'));
  const cli = keypair(), srv = keypair();
  fs.writeFileSync(path.join(work, 'peer.json'), JSON.stringify({
    log: { level: 'warn' },
    endpoints: [{
      type: 'wireguard', tag: 'wg-srv', system: false, mtu: 1420,
      address: ['10.99.0.1/24'], private_key: srv.priv, listen_port: P.wg,
      peers: [{ public_key: cli.pub, allowed_ips: ['10.10.10.42/32'] }]
    }],
    outbounds: [{ type: 'direct', tag: 'direct' }],
    route: {
      rules: [
        { inbound: ['wg-srv'], port: [53], action: 'route', outbound: 'direct', override_address: '127.0.0.1', override_port: P.dns },
        { inbound: ['wg-srv'], port: [HOP_PORT], action: 'route', outbound: 'direct', override_address: '127.0.0.1', override_port: P.hop },
        { inbound: ['wg-srv'], action: 'route', outbound: 'direct', override_address: '127.0.0.1', override_port: P.web }
      ]
    }
  }, null, 2));
  const relay = (port, wsPath, redirect) => JSON.stringify({
    log: { loglevel: 'warning' },
    inbounds: [{ tag: 'in', listen: '127.0.0.1', port, protocol: 'vless', settings: { clients: [{ id: UUID }], decryption: 'none' }, streamSettings: { network: 'ws', wsSettings: { path: wsPath } } }],
    outbounds: [{ protocol: 'freedom', tag: 'direct', settings: redirect ? { redirect } : {} }]
  }, null, 2);
  // the hop behind the base (its page is all it serves), and the chain's front hop
  fs.writeFileSync(path.join(work, 'hop.json'), relay(P.hop, '/x', '127.0.0.1:' + P.web2));
  fs.writeFileSync(path.join(work, 'front.json'), relay(P.front, '/f', null));

  // the peer has no TCP port to wait on: its config is checked first, its process after
  const check = spawnSync(singbox, ['check', '-c', path.join(work, 'peer.json')], { encoding: 'utf8', timeout: 20000, windowsHide: true });
  if (check.status !== 0) {
    console.error('the WireGuard peer refused its config:\n' + ((check.stdout || '') + (check.stderr || '')).trim());
    process.exit(1);
  }
  const dnsSrv = await corpDns();
  const corpPage = await page(P.web, 'CORP-OK');
  const hopPage = await page(P.web2, 'HOP-OK');
  const peer = run(singbox, ['run', '-c', path.join(work, 'peer.json')], work);
  const hop = run(xray, ['run', '-c', path.join(work, 'hop.json')], work);
  run(xray, ['run', '-c', path.join(work, 'front.json')], work);
  if (!await waitPort(P.hop) || !await waitPort(P.front)) {
    console.error('a hop never came up:\n' + hop.text() + peer.text());
    killAll(); process.exit(1);
  }
  await sleep(800);
  if (peer.proc.exitCode !== null) {
    console.error('the WireGuard peer stopped:\n' + peer.text());
    killAll(); process.exit(1);
  }

  const version = (spawnSync(xray, ['version'], { encoding: 'utf8', windowsHide: true }).stdout || '').split(/\r?\n/)[0];
  console.log(`${version} · peer ${(spawnSync(singbox, ['version'], { encoding: 'utf8', windowsHide: true }).stdout || '').split(/\r?\n/)[0]} · ${work}`);
  let failed = 0;
  for (const chained of [false, true]) {
    const r = await scenario(work, chained, cli, srv, dnsSrv);
    if (r.problems.length) failed++;
    console.log(`${r.problems.length ? '✗' : '✓'} ${r.name}${r.note ? ' — ' + r.note : ''}`);
    for (const p of r.problems) console.log('    ' + p);
  }
  if (failed) console.log('peer log: ' + (peer.text().split(/\r?\n/).filter(Boolean).slice(-8).join(' | ') || '(nothing)'));
  killAll();
  dnsSrv.close(); corpPage.close(); hopPage.close();
  console.log(failed ? `\n${failed}/2 failed` : '\nboth lines through one WireGuard session, both times');
  process.exit(failed ? 1 : 0);
}

module.exports = { probePlan };
if (require.main === module) {
  process.on('exit', killAll);
  process.on('SIGINT', () => { killAll(); process.exit(130); });
  main().catch((e) => { killAll(); console.error(e); process.exit(1); });
}
