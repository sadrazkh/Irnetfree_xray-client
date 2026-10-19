#!/usr/bin/env node
'use strict';
/**
 * A WARP on WireGuard as the app writes it, ridden over a config the user
 * already has (v1.26.0, .superpowers/sdd/warp-wg/design.md §5-6) — proven on
 * loopback against a real WireGuard peer, nothing reaching Cloudflare:
 *
 *   SOCKS → [the client core: the app's own config] → VLESS hop (Xray) → WireGuard
 *   peer (sing-box, standing in for Cloudflare's edge) → a local web page
 *
 * The WARP server comes from warp.js wgServerFields — the fields + WARP makes
 * for a chained account: the peer's key, the device's, its v4/v6 addresses,
 * reserved [0,0,0], MTU 1280, everything through it — and parser.createServer,
 * with only its edge address and port moved to the local peer. Two rounds:
 *   1. the chain [hop → WARP] selected, as the window's new chain is;
 *   2. advanced routing: a rule sends 203.0.113.0/24 to that chain, the rest
 *      goes to the hop alone (where 203.0.113.10 leads nowhere).
 * Each round fetches a page and 2 MB through the WARP.
 *
 *   IRNF_XRAY_EXE     the client core (default bin/xray)
 *   IRNF_HOP_EXE      the core the hop runs (default: the client core)
 *   IRNF_SINGBOX_EXE  the WireGuard peer (default bin/sing-box)
 *   IRNF_PROBE_PORT   base port, default 40100
 */
const fs = require('fs');
const os = require('os');
const net = require('net');
const path = require('path');
const http = require('http');
const crypto = require('crypto');
const { spawn, spawnSync } = require('child_process');
const { buildConfig } = require('../src/main/configBuilder');
const { createServer } = require('../src/main/parser');
const W = require('../src/main/warp');

const BASE = Number(process.env.IRNF_PROBE_PORT || 40100);
const P = { hop: BASE + 1, wg: BASE + 2, socks: BASE + 10, web: BASE + 21 };
const UUID = '7d2f0c3b-1e4a-4b6d-9c8e-0a1b2c3d4e5f';
const TARGET = '203.0.113.10';
const BIG = 2 * 1024 * 1024;
const exeName = (n) => (process.platform === 'win32' ? n + '.exe' : n);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const xray = process.env.IRNF_XRAY_EXE || path.join(__dirname, '..', 'bin', exeName('xray'));
const hopXray = process.env.IRNF_HOP_EXE || xray;
const singbox = process.env.IRNF_SINGBOX_EXE || path.join(__dirname, '..', 'bin', exeName('sing-box'));
for (const [what, p] of [['client core', xray], ['hop core', hopXray], ['sing-box (the WireGuard peer)', singbox]]) {
  if (!fs.existsSync(p)) { console.error(`no ${what} at ${p}`); process.exit(2); }
}

const procs = [];
function run(exe, args, tag, cwd) {
  const proc = spawn(exe, args, { cwd, windowsHide: true });
  let out = '';
  proc.stdout.on('data', (d) => { out += d; });
  proc.stderr.on('data', (d) => { out += d; });
  procs.push(proc);
  return { proc, text: () => `[${tag}] ` + out.slice(-4000) };
}
function killAll() { for (const p of procs) { try { p.kill(); } catch { /* gone */ } } }

async function waitPort(port, ms = 8000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const ok = await new Promise((r) => {
      const s = net.connect(port, '127.0.0.1', () => { s.destroy(); r(true); });
      s.on('error', () => r(false));
    });
    if (ok) return true;
    await sleep(150);
  }
  return false;
}

/** The page behind the peer: «WARP-OK», or BIG bytes at /big. */
function web() {
  const big = Buffer.alloc(BIG, 0x57);
  const srv = http.createServer((req, res) => {
    if (req.url === '/big') { res.writeHead(200, { 'Content-Length': big.length }); return res.end(big); }
    res.writeHead(200, { 'Content-Type': 'text/plain', 'Content-Length': 7 });
    return res.end('WARP-OK');
  });
  return new Promise((r) => srv.listen(P.web, '127.0.0.1', () => r(srv)));
}

/** GET http://host/path through the SOCKS5 port: { head, body (Buffer) }. */
function getThroughSocks(port, host, pathname, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    const s = net.connect(port, '127.0.0.1');
    const timer = setTimeout(() => { s.destroy(); reject(new Error(`no answer in ${timeoutMs} ms`)); }, timeoutMs);
    let stage = 0;
    let buf = Buffer.alloc(0);
    s.on('error', (e) => { clearTimeout(timer); reject(e); });
    s.on('connect', () => s.write(Buffer.from([5, 1, 0])));
    s.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      if (stage === 0 && buf.length >= 2) {
        buf = buf.subarray(2);
        stage = 1;
        const ip = host.split('.').map(Number);
        s.write(Buffer.from([5, 1, 0, 1, ...ip, 0, 80]));
      }
      if (stage === 1 && buf.length >= 10) {
        if (buf[1] !== 0) { clearTimeout(timer); s.destroy(); return reject(new Error('SOCKS refused the connect: ' + buf[1])); }
        buf = buf.subarray(10);
        stage = 2;
        s.write(`GET ${pathname} HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`);
      }
    });
    s.on('end', () => {
      clearTimeout(timer);
      const i = buf.indexOf('\r\n\r\n');
      if (stage < 2 || i < 0) return reject(new Error('no HTTP answer'));
      resolve({ head: buf.subarray(0, i).toString('latin1'), body: buf.subarray(i + 4) });
    });
  });
}

function keypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
  return {
    priv: privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32).toString('base64'),
    pub: publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64')
  };
}

async function main() {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-warpchain-'));
  const device = keypair();
  const edge = keypair();

  // the stand-in for Cloudflare's edge: a WireGuard responder that hands every
  // connection to the local page
  fs.writeFileSync(path.join(work, 'peer.json'), JSON.stringify({
    log: { level: 'warn' },
    endpoints: [{
      type: 'wireguard', tag: 'wg-edge', system: false, mtu: 1280,
      address: ['172.16.0.1/24', 'fd01::1/64'], private_key: edge.priv, listen_port: P.wg,
      peers: [{ public_key: device.pub, allowed_ips: ['172.16.0.2/32', '2606:4700:110:8a36::2/128'] }]
    }],
    outbounds: [{ type: 'direct', tag: 'direct' }],
    route: { rules: [{ inbound: ['wg-edge'], action: 'route', outbound: 'direct', override_address: '127.0.0.1', override_port: P.web }] }
  }, null, 2));

  // the user's config: a VLESS server (ws) standing for the one abroad
  fs.writeFileSync(path.join(work, 'hop.json'), JSON.stringify({
    log: { loglevel: 'warning' },
    inbounds: [{ tag: 'in', listen: '127.0.0.1', port: P.hop, protocol: 'vless', settings: { clients: [{ id: UUID }], decryption: 'none' }, streamSettings: { network: 'ws', wsSettings: { path: '/w' } } }],
    outbounds: [{ protocol: 'freedom', tag: 'direct' }]
  }, null, 2));
  const hop = {
    id: 'hop', name: 'UK xhttp', protocol: 'vless', address: '127.0.0.1', port: P.hop,
    outbound: { protocol: 'vless', settings: { vnext: [{ address: '127.0.0.1', port: P.hop, users: [{ id: UUID, encryption: 'none' }] }] }, streamSettings: { network: 'ws', security: 'none', wsSettings: { path: '/w' } } }
  };

  // the WARP server exactly as + WARP makes a chained one; only its edge moves to the local peer
  const reg = { kind: 'wireguard', privateKey: device.priv, publicKey: edge.pub, address: ['172.16.0.2/32', '2606:4700:110:8a36::2/128'], endpoints: { v4: '127.0.0.1', v6: '::1' }, reserved: [0, 0, 0] };
  const fields = W.wgServerFields(reg, { use: 'chain' }, '☁ WARP');
  if (fields.mtu !== '1280' || fields.reserved !== '0,0,0' || 'noise' in fields) throw new Error('wgServerFields changed: ' + JSON.stringify(fields));
  const warp = Object.assign(createServer(Object.assign({}, fields, { port: P.wg })), { id: 'warp' });

  const settings = {
    socksPort: P.socks, httpPort: P.socks + 1, apiPort: P.socks + 2,
    routingMode: 'bypass-ir', advancedUseMode: true, blockAds: false, enableSniffing: true,
    dnsManaged: true, dnsRemote: ['https://1.1.1.1/dns-query'], dnsDirect: ['8.8.8.8'],
    ipv6: false, logLevel: 'warning', geoAssets: false
  };
  const rounds = [
    ['the chain [hop → WARP]', { mode: 'chain', chain: [hop, warp] }],
    ['advanced routing: 203.0.113.0/24 → the chain, the rest → the hop', {
      mode: 'advanced', serversById: { hop, warp }, chainsById: { 'chain-warp': [hop, warp] }, chain: [],
      rules: [{ type: 'ip', value: '203.0.113.0/24', target: 'chain:chain-warp' }], def: 'hop'
    }]
  ];

  const page = await web();
  const peer = run(singbox, ['run', '-c', path.join(work, 'peer.json')], 'peer', work);
  const hopProc = run(hopXray, ['run', '-c', path.join(work, 'hop.json')], 'hop', work);
  if (!await waitPort(P.hop)) { console.error('the hop never came up:\n' + hopProc.text()); killAll(); process.exit(1); }
  await sleep(500);   // the peer's UDP listener has no TCP port to wait on

  let failed = 0;
  for (const [label, plan] of rounds) {
    const cfg = buildConfig(plan, settings);
    const file = path.join(work, 'client.json');
    fs.writeFileSync(file, JSON.stringify(cfg, null, 2));
    const wg = (cfg.outbounds || []).find((o) => o.protocol === 'wireguard');
    const via = wg && wg.streamSettings && wg.streamSettings.sockopt && wg.streamSettings.sockopt.dialerProxy;
    const test = spawnSync(xray, ['run', '-test', '-c', file], { encoding: 'utf8', timeout: 20000, windowsHide: true });
    let note;
    if (test.status !== 0) {
      failed++;
      note = 'FAILED — the core refused the config: ' + ((test.stdout || '') + (test.stderr || '')).trim().split(/\r?\n/).slice(-1)[0];
    } else {
      const client = run(xray, ['run', '-c', file], 'client', work);
      try {
        if (!wg) throw new Error('no WireGuard outbound in the config');
        if (!via) throw new Error('the WireGuard dials from here, not through the hop');
        if (JSON.stringify(wg.settings.reserved) !== '[0,0,0]' || wg.settings.mtu !== 1280) throw new Error('reserved/MTU not as written: ' + JSON.stringify(wg.settings));
        if (!await waitPort(P.socks)) throw new Error('the client core never opened its SOCKS port');
        const small = await getThroughSocks(P.socks, TARGET, '/');
        if (!/ 200 /.test(small.head) || small.body.toString() !== 'WARP-OK') throw new Error('page: ' + small.head.split('\r\n')[0] + ' ' + JSON.stringify(small.body.toString().slice(0, 40)));
        const big = await getThroughSocks(P.socks, TARGET, '/big');
        if (big.body.length !== BIG) throw new Error(`2 MB returned ${big.body.length} bytes`);
        note = `the WARP (via ${via}) carried the page and 2 MB`;
      } catch (e) {
        failed++;
        note = 'FAILED — ' + e.message + '\n  ' + client.text().split('\n').filter(Boolean).slice(-6).join('\n  ') + '\n  ' + peer.text().split('\n').filter(Boolean).slice(-3).join('\n  ');
      }
      try { client.proc.kill(); } catch { /* gone */ }
      await sleep(500);
    }
    console.log(`${note.startsWith('FAILED') ? '✗' : '✓'} ${label}: ${note}`);
  }

  killAll();
  page.close();
  await sleep(300);
  try { fs.rmSync(work, { recursive: true, force: true }); } catch { /* a core still closing */ }
  console.log(`\n${rounds.length - failed}/${rounds.length} rounds passed (client ${path.basename(path.dirname(xray))}/${path.basename(xray)}, hop ${path.basename(path.dirname(hopXray))}/${path.basename(hopXray)})`);
  process.exit(failed ? 1 : 0);
}

process.on('exit', killAll);
process.on('SIGINT', () => { killAll(); process.exit(130); });
main().catch((e) => { killAll(); console.error(e); process.exit(1); });
