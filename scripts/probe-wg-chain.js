'use strict';
/**
 * The corporate-WireGuard scenario, end to end, against a REAL peer.
 *
 * `npm run validate` proves the cores ACCEPT what configBuilder emits. This
 * proves the config actually WORKS: a company range routed through a chain
 * whose last hop is a split-tunnel WireGuard, an internal name resolved by the
 * corporate DNS *inside* that tunnel, and a page fetched from an intranet host.
 *
 * It exists because the cheaper probe that preceded it — counting handshake
 * packets arriving at a socket that never answered — could not tell "the
 * request left" from "the exchange completed", and a wrong root cause was
 * shipped on the strength of it. Everything here answers.
 *
 *   client core  ──vless──▶  hop (xray)  ──udp──▶  wg peer (sing-box endpoint)
 *        │                                              │
 *        └── socks 127.0.0.1:PORT                       └──▶ corp DNS + intranet site
 *
 * Needs: bin/xray(.exe) for the hop, sing-box for the peer. Every Xray-format
 * core it can find is put through the same run, so a fork that diverges shows
 * up here instead of in a user's report. Nothing touches the machine's routes,
 * adapters or firewall — it is all loopback.
 *
 *   IRNF_XRAY_EXE     extra core to test (e.g. the patterniha fork)
 *   IRNF_SINGBOX_EXE  the WireGuard peer (required)
 *   IRNF_PROBE_PORT   base port, default 39700
 */
const fs = require('fs');
const os = require('os');
const net = require('net');
const path = require('path');
const http = require('http');
const dgram = require('dgram');
const crypto = require('crypto');
const { spawn } = require('child_process');
const { buildConfig } = require('../src/main/configBuilder');

const BASE = Number(process.env.IRNF_PROBE_PORT || 39700);
const P = { hop: BASE + 1, wg: BASE + 2, socks: BASE + 10, dns: BASE + 20, web: BASE + 21 };
const CORP_IP = '192.168.45.7';
const CORP_NAME = 'gitlab.corp.test';
const UUID = '2c0f0d9a-6b3a-4f0e-9a1f-8c2b4d6e7a10';
const exeName = (n) => (process.platform === 'win32' ? n + '.exe' : n);

/* ------------------------------- the cores ------------------------------- */

const singbox = process.env.IRNF_SINGBOX_EXE || path.join(__dirname, '..', 'bin', exeName('sing-box'));
const localXray = path.join(__dirname, '..', 'bin', exeName('xray'));
if (!fs.existsSync(singbox)) {
  console.error('no sing-box at ' + singbox + ' — it plays the WireGuard peer. Set IRNF_SINGBOX_EXE.');
  process.exit(2);
}
if (!fs.existsSync(localXray)) {
  console.error('no core at ' + localXray + ' — run: npm run get-xray');
  process.exit(2);
}
const clients = [{ name: path.basename(localXray), exe: localXray }];
if (process.env.IRNF_XRAY_EXE && process.env.IRNF_XRAY_EXE !== localXray) {
  if (fs.existsSync(process.env.IRNF_XRAY_EXE)) {
    clients.push({ name: path.basename(process.env.IRNF_XRAY_EXE), exe: process.env.IRNF_XRAY_EXE });
  } else {
    console.error('IRNF_XRAY_EXE points at nothing: ' + process.env.IRNF_XRAY_EXE);
    process.exit(2);
  }
}

/* ------------------------------ the company ------------------------------ */

/** A DNS that only knows corporate names, reachable only through the tunnel. */
function corpDns() {
  const s = dgram.createSocket('udp4');
  let asked = 0;
  s.on('message', (msg, ri) => {
    let i = 12; const parts = [];
    while (msg[i]) { parts.push(msg.slice(i + 1, i + 1 + msg[i]).toString()); i += msg[i] + 1; }
    const qend = i + 1;
    if (qend + 4 > msg.length) return;
    const qtype = msg.readUInt16BE(qend);
    asked++;
    const head = Buffer.from(msg.slice(0, qend + 4));
    head.writeUInt16BE(0x8180, 2);                      // response, recursion available
    head.writeUInt16BE(1, 4);                           // QDCOUNT
    head.writeUInt16BE(qtype === 1 ? 1 : 0, 6);         // ANCOUNT — A records only
    if (qtype !== 1 || parts.join('.') !== CORP_NAME) return void s.send(head, ri.port, ri.address);
    const ans = Buffer.concat([
      Buffer.from([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]),
      Buffer.from(CORP_IP.split('.').map(Number))
    ]);
    s.send(Buffer.concat([head, ans]), ri.port, ri.address);
  });
  return new Promise((res) => s.bind(P.dns, '127.0.0.1', () => res({ close: () => s.close(), count: () => asked })));
}

/** The intranet site behind the tunnel: a short page and a 2 MB one. */
function corpWeb() {
  const srv = http.createServer((req, res) => {
    if (req.url === '/big') return void res.end(Buffer.alloc(2 * 1024 * 1024, 120));
    res.end('CORP-OK');
  });
  return new Promise((res) => srv.listen(P.web, '127.0.0.1', () => res({ close: () => srv.close() })));
}

/* ------------------------------- processes ------------------------------- */

const kids = [];
function run(exe, args, tag, cwd) {
  const p = spawn(exe, args, { cwd, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  const log = [];
  p.stdout.on('data', (d) => log.push(String(d)));
  p.stderr.on('data', (d) => log.push(String(d)));
  kids.push(p);
  return { proc: p, tag, text: () => log.join('') };
}
function killAll() {
  for (const p of kids.splice(0)) { try { p.kill(); } catch { /* already gone */ } }
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Wait until something is listening, instead of guessing with a sleep. */
async function waitPort(port, ms = 8000) {
  const until = Date.now() + ms;
  while (Date.now() < until) {
    const ok = await new Promise((res) => {
      const s = net.connect(port, '127.0.0.1');
      s.once('connect', () => { s.destroy(); res(true); });
      s.once('error', () => res(false));
      setTimeout(() => { s.destroy(); res(false); }, 300);
    });
    if (ok) return true;
    await sleep(150);
  }
  return false;
}

/* --------------------------- one request, via SOCKS5 --------------------------- */

/**
 * GET http://<host><pathname>/ through a SOCKS5 proxy, sending the NAME (so the
 * core resolves it, which is the whole point) and reading the whole body.
 */
function getThroughSocks(port, host, pathname, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    const s = net.connect(port, '127.0.0.1');
    const fail = (e) => { s.destroy(); reject(e instanceof Error ? e : new Error(String(e))); };
    s.setTimeout(timeoutMs, () => fail(new Error('timed out')));
    s.on('error', fail);
    let stage = 0;
    const chunks = [];
    s.on('connect', () => s.write(Buffer.from([0x05, 0x01, 0x00])));
    s.on('data', (d) => {
      if (stage === 0) {
        if (d[0] !== 0x05 || d[1] !== 0x00) return fail(new Error('socks greeting refused'));
        stage = 1;
        const name = Buffer.from(host, 'utf8');
        return void s.write(Buffer.concat([
          Buffer.from([0x05, 0x01, 0x00, 0x03, name.length]), name, Buffer.from([0x00, 0x50])
        ]));
      }
      if (stage === 1) {
        if (d[0] !== 0x05 || d[1] !== 0x00) return fail(new Error('socks connect refused (code ' + d[1] + ')'));
        stage = 2;
        return void s.write(`GET ${pathname} HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`);
      }
      chunks.push(d);
    });
    s.on('close', () => {
      const raw = Buffer.concat(chunks).toString('latin1');
      const cut = raw.indexOf('\r\n\r\n');
      if (cut < 0) return reject(new Error('no HTTP response through the tunnel'));
      resolve({ head: raw.slice(0, cut), body: raw.slice(cut + 4) });
    });
  });
}

/* --------------------------------- the run --------------------------------- */

function keypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
  return {
    priv: privateKey.export({ type: 'pkcs8', format: 'der' }).slice(-32).toString('base64'),
    pub: publicKey.export({ type: 'spki', format: 'der' }).slice(-32).toString('base64')
  };
}

async function main() {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-wgprobe-'));
  const cli = keypair(), srv = keypair();

  // The peer: a real WireGuard responder. Traffic that arrives through the
  // tunnel is sent to the local stand-ins for the company's DNS and intranet.
  fs.writeFileSync(path.join(work, 'peer.json'), JSON.stringify({
    log: { level: 'warn' },
    endpoints: [{
      type: 'wireguard', tag: 'wg-srv', system: false, mtu: 1420,
      address: ['192.168.45.1/24'], private_key: srv.priv, listen_port: P.wg,
      peers: [{ public_key: cli.pub, allowed_ips: ['10.10.10.42/32'] }]
    }],
    outbounds: [{ type: 'direct', tag: 'direct' }],
    route: {
      rules: [
        { inbound: ['wg-srv'], port: [53], action: 'route', outbound: 'direct', override_address: '127.0.0.1', override_port: P.dns },
        { inbound: ['wg-srv'], action: 'route', outbound: 'direct', override_address: '127.0.0.1', override_port: P.web }
      ]
    }
  }, null, 2));

  // The hop the WireGuard is dialled through.
  fs.writeFileSync(path.join(work, 'hop.json'), JSON.stringify({
    log: { loglevel: 'warning' },
    inbounds: [{
      tag: 'in', listen: '127.0.0.1', port: P.hop, protocol: 'vless',
      settings: { clients: [{ id: UUID }], decryption: 'none' },
      streamSettings: { network: 'ws', security: 'none', wsSettings: { path: '/x' } }
    }],
    outbounds: [{ protocol: 'freedom', tag: 'direct' }]
  }, null, 2));

  // The client config comes from the APP's builder, from records shaped like
  // the ones the store holds — the point is to test what users actually run.
  const hop = {
    id: 'hop', name: 'hop', protocol: 'vless', address: '127.0.0.1', port: P.hop,
    outbound: {
      protocol: 'vless',
      settings: { vnext: [{ address: '127.0.0.1', port: P.hop, users: [{ id: UUID, encryption: 'none' }] }] },
      streamSettings: { network: 'ws', security: 'none', wsSettings: { path: '/x' } }
    }
  };
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
  const plan = {
    mode: 'advanced', serversById: { hop, wg }, chainsById: { corp: [hop, wg] }, chain: [],
    rules: [{ type: 'ip', value: '192.168.0.0/16, 10.0.0.0/8, 192.168.45.0/24', target: 'chain:corp' }],
    def: 'hop'
  };
  const cfg = buildConfig(plan, {
    socksPort: P.socks, httpPort: P.socks + 1, apiPort: P.socks + 2,
    routingMode: 'bypass-ir', advancedUseMode: true, blockAds: false, enableSniffing: true,
    dnsManaged: true, dnsRemote: ['https://1.1.1.1/dns-query'], dnsDirect: ['8.8.8.8'],
    ipv6: false, logLevel: 'warning', geoAssets: false
  });
  fs.writeFileSync(path.join(work, 'client.json'), JSON.stringify(cfg, null, 2));

  const wgOut = (cfg.outbounds || []).find((o) => o.protocol === 'wireguard');
  console.log(`probe dir: ${work}`);
  console.log(`wireguard: ${wgOut.tag} via ${(wgOut.streamSettings.sockopt || {}).dialerProxy} ` +
    `→ ${wgOut.settings.peers[0].endpoint} allowedIPs=${JSON.stringify(wgOut.settings.peers[0].allowedIPs)}`);

  const dnsSrv = await corpDns();
  const webSrv = await corpWeb();
  const peer = run(singbox, ['run', '-c', path.join(work, 'peer.json')], 'peer', work);
  const hopProc = run(localXray, ['run', '-c', path.join(work, 'hop.json')], 'hop', work);
  if (!await waitPort(P.hop)) {
    console.error('the hop never came up:\n' + hopProc.text());
    killAll(); dnsSrv.close(); webSrv.close();
    process.exit(1);
  }
  await sleep(500);   // the peer's UDP listener has no TCP port to wait on

  let failed = 0;
  for (const c of clients) {
    const before = dnsSrv.count();
    const client = run(c.exe, ['run', '-c', path.join(work, 'client.json')], c.name, work);
    const up = await waitPort(P.socks);
    let note = '';
    try {
      if (!up) throw new Error('the client core never opened its SOCKS port');
      const small = await getThroughSocks(P.socks, CORP_NAME, '/');
      if (!/ 200 /.test(small.head)) throw new Error('intranet page: ' + small.head.split('\r\n')[0]);
      if (small.body !== 'CORP-OK') throw new Error('intranet page body was ' + JSON.stringify(small.body.slice(0, 40)));
      if (dnsSrv.count() <= before) throw new Error('the corporate DNS was never asked — the name was resolved somewhere else');
      const big = await getThroughSocks(P.socks, CORP_NAME, '/big');
      if (big.body.length !== 2 * 1024 * 1024) throw new Error(`2 MB transfer returned ${big.body.length} bytes`);
      note = `resolved ${CORP_NAME} through the tunnel, fetched the page and 2 MB`;
    } catch (e) {
      failed++;
      note = 'FAILED — ' + e.message;
      const tail = client.text().split('\n').filter(Boolean).slice(-6).join('\n  ');
      if (tail) note += '\n  ' + tail;
    }
    try { client.proc.kill(); } catch { /* already gone */ }
    await sleep(400);
    console.log(`${failed ? '✗' : '✓'} ${c.name}: ${note}`);
  }

  killAll();
  dnsSrv.close();
  webSrv.close();
  console.log(`\n${clients.length - failed}/${clients.length} cores carried the corporate WireGuard through the chain`);
  process.exit(failed ? 1 : 0);
}

process.on('exit', killAll);
process.on('SIGINT', () => { killAll(); process.exit(130); });
main().catch((e) => { killAll(); console.error(e); process.exit(1); });
