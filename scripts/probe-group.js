#!/usr/bin/env node
'use strict';
/**
 * Groups (v1.27.0, .superpowers/sdd/groups/design.md) on real cores, loopback
 * only: the app's own builder (groups.groupRecord → configBuilder) against
 * local VLESS servers, nothing reaching the internet. Two of the servers hand
 * every connection to a page that names them (S1, S2), a third to its own (S3);
 * one member points at a port nobody listens on. Four rounds, each nine
 * fetches through the client core's SOCKS port:
 *   1. the group selected — round-robin: both live members answer, the dead
 *      one is left out by the health check (no fetch fails);
 *   2. advanced routing — a rule sends 203.0.113.0/24 to the group;
 *   3. a chain [group → S3] — S3 is dialled through the group: always S3;
 *   4. a chain [H → group] — every member dials through H: S1 and S2 again;
 *   5. with sing-box at hand (IRNF_SINGBOX_EXE or bin/sing-box), a chain
 *      [group → WireGuard] against a real WireGuard peer — the WireGuard built
 *      once and dialling the group (one key, one session), as [group of CDN IPs
 *      → WARP] would be; the page and 2 MB through it.
 * Each round also reads the core's traffic counters as the app's meter does
 * (stats.sumOutbounds): a group's bytes must show — on its loopback, since the
 * members' `~` tags are left out of the total like a JSON server's helpers —
 * and the live view the window gets (a StatsPoller handed the config's
 * groupTags): every member's health as the core's check found it, the dead
 * member dead and the others alive.
 * The health check asks a local page here instead of cp.cloudflare.com (the
 * only change made to what the builder wrote), so it needs no internet. The
 * builder is handed a chain relay port, as every connect is: in rounds 3 and 4
 * a dial through a hop rides it (configBuilder.relayHopDials) — straight
 * through the ws hop the core cut a page short now and then, which is what
 * made those two rounds fail 3 fetches in 9 on CI (scripts/probe-chain-tail.js).
 *
 *   IRNF_XRAY_EXE     the client core (default bin/xray)
 *   IRNF_HOP_EXE      the core the servers run (default: the client core)
 *   IRNF_SINGBOX_EXE  the WireGuard peer for round 5 (default bin/sing-box; absent → round 5 is skipped)
 *   IRNF_PROBE_PORT   base port, default 22400
 */
const fs = require('fs');
const os = require('os');
const net = require('net');
const path = require('path');
const http = require('http');
const { spawn, spawnSync } = require('child_process');
const { buildConfig } = require('../src/main/configBuilder');
const { groupRecord } = require('../src/main/groups');
const { sumOutbounds, StatsPoller } = require('../src/main/stats');

const BASE = Number(process.env.IRNF_PROBE_PORT || 22400);
const P = { s1: BASE + 1, s2: BASE + 2, s3: BASE + 3, h: BASE + 4, s1b: BASE + 5, s2b: BASE + 6, wg: BASE + 7, dead: BASE + 9,
  page1: BASE + 11, page2: BASE + 12, page3: BASE + 13, probe: BASE + 14, pageWg: BASE + 15, socks: BASE + 20, relay: BASE + 23 };
const UUID = '7d2f0c3b-1e4a-4b6d-9c8e-0a1b2c3d4e5f';
const TARGET = '203.0.113.9';
const exeName = (n) => (process.platform === 'win32' ? n + '.exe' : n);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const xray = process.env.IRNF_XRAY_EXE || path.join(__dirname, '..', 'bin', exeName('xray'));
const singbox = process.env.IRNF_SINGBOX_EXE || path.join(__dirname, '..', 'bin', exeName('sing-box'));
const BIG = 2 * 1024 * 1024;
const hopXray = process.env.IRNF_HOP_EXE || xray;
for (const [what, p] of [['client core', xray], ['server core', hopXray]]) {
  if (!fs.existsSync(p)) { console.error(`no ${what} at ${p}`); process.exit(2); }
}

const procs = [];
function run(exe, file, tag) {
  const proc = spawn(exe, ['run', '-c', file], { windowsHide: true });
  let out = '';
  proc.stdout.on('data', (d) => { out += d; });
  proc.stderr.on('data', (d) => { out += d; });
  procs.push(proc);
  return { proc, text: () => `[${tag}] ` + out.slice(-3000) };
}
function killAll() { for (const p of procs) { try { p.kill(); } catch { /* gone */ } } }
async function waitPort(port, ms = 8000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const ok = await new Promise((r) => { const s = net.connect(port, '127.0.0.1', () => { s.destroy(); r(true); }); s.on('error', () => r(false)); });
    if (ok) return true;
    await sleep(150);
  }
  return false;
}
const page = (port, text) => new Promise((r) => {
  const s = http.createServer((q, res) => { res.writeHead(200, { 'Content-Length': text.length }); res.end(text); });
  s.listen(port, '127.0.0.1', () => r(s));
});

/** GET / of TARGET:80 through the SOCKS port → the body. */
function fetchOnce(pathname = '/') {
  return new Promise((resolve, reject) => {
    const s = net.connect(P.socks, '127.0.0.1');
    let st = 0;
    let buf = Buffer.alloc(0);
    const t = setTimeout(() => { s.destroy(); reject(new Error('timeout')); }, 10000);
    s.on('error', (e) => { clearTimeout(t); reject(e); });
    s.on('connect', () => s.write(Buffer.from([5, 1, 0])));
    s.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      if (st === 0 && buf.length >= 2) { buf = buf.subarray(2); st = 1; s.write(Buffer.from([5, 1, 0, 1, ...TARGET.split('.').map(Number), 0, 80])); }
      if (st === 1 && buf.length >= 10) {
        if (buf[1] !== 0) { clearTimeout(t); s.destroy(); return reject(new Error('SOCKS refused: ' + buf[1])); }
        buf = buf.subarray(10); st = 2; s.write(`GET ${pathname} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n`);
      }
    });
    s.on('end', () => { clearTimeout(t); const i = buf.indexOf('\r\n\r\n'); return i < 0 ? reject(new Error('no HTTP answer')) : resolve(pathname === '/' ? buf.subarray(i + 4).toString() : String(buf.length - i - 4)); });
  });
}

/**
 * Until the core's health check has judged every member of every group
 * (vars.observatory: `T~gm<i>` alive, or dead), each judged alive except the
 * one called `dead`: true; false once `ms` have passed.
 */
async function waitVerdicts(apiPort, map, ms) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const vars = await new Promise((resolve) => {
      http.get({ host: '127.0.0.1', port: apiPort, path: '/debug/vars' }, (res) => {
        let b = '';
        res.on('data', (d) => { b += d; });
        res.on('end', () => { try { resolve(JSON.parse(b)); } catch { resolve(null); } });
      }).on('error', () => resolve(null));
    });
    const obs = (vars && vars.observatory) || {};
    const ok = (map || []).every((g) => g.members.every((m, i) => {
      const o = obs[`${g.tag}~gm${i}`];
      return o && (m.id === 'dead' ? o.alive !== true : o.alive === true);
    }));
    if (ok) return true;
    await sleep(500);
  }
  return false;
}

/** A VLESS+ws server on 127.0.0.1:port; with `to`, every connection is handed to that local page. */
function serverConfig(port, to) {
  return {
    log: { loglevel: 'warning' },
    inbounds: [{ listen: '127.0.0.1', port, protocol: 'vless', settings: { clients: [{ id: UUID }], decryption: 'none' }, streamSettings: { network: 'ws', wsSettings: { path: '/w' } } }],
    outbounds: [{ protocol: 'freedom', settings: Object.assign({ finalRules: [{ action: 'allow' }] }, to ? { redirect: '127.0.0.1:' + to } : {}) }]
  };
}
/** The record the app keeps for such a server. */
const record = (id, port) => ({
  id, name: id, protocol: 'vless', address: '127.0.0.1', port,
  outbound: { protocol: 'vless', settings: { vnext: [{ address: '127.0.0.1', port, users: [{ id: UUID, encryption: 'none' }] }] }, streamSettings: { network: 'ws', security: 'none', wsSettings: { path: '/w' } } }
});

async function main() {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-groupprobe-'));
  const pages = [await page(P.page1, 'S1'), await page(P.page2, 'S2'), await page(P.page3, 'S3'), await page(P.probe, 'ok')];
  // round 5's page behind the WireGuard: «WG», or 2 MB at /big
  const bigBody = Buffer.alloc(BIG, 0x57);
  pages.push(await new Promise((r) => {
    const srv = http.createServer((q, res) => {
      const body = q.url === '/big' ? bigBody : Buffer.from('WG');
      res.writeHead(200, { 'Content-Length': body.length });
      res.end(body);
    });
    srv.listen(P.pageWg, '127.0.0.1', () => r(srv));
  }));
  const servers = { s1: P.page1, s2: P.page2, s3: P.page3, h: 0, s1b: 0, s2b: 0 };
  for (const [id, to] of Object.entries(servers)) {
    const f = path.join(work, id + '.json');
    fs.writeFileSync(f, JSON.stringify(serverConfig(P[id], to)));
    run(hopXray, f, id);
  }
  for (const id of Object.keys(servers)) if (!await waitPort(P[id])) { console.error('server ' + id + ' never came up'); killAll(); process.exit(1); }

  // round 5: a real WireGuard peer (sing-box) that hands everything to the «WG» page
  let wgRec = null;
  if (fs.existsSync(singbox)) {
    const crypto = require('crypto');
    const pair = () => { const k = crypto.generateKeyPairSync('x25519'); return { priv: k.privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32).toString('base64'), pub: k.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64') }; };
    const device = pair();
    const edge = pair();
    const f = path.join(work, 'peer.json');
    fs.writeFileSync(f, JSON.stringify({
      log: { level: 'warn' },
      endpoints: [{ type: 'wireguard', tag: 'wg-edge', system: false, mtu: 1280, address: ['172.16.0.1/24'], private_key: edge.priv, listen_port: P.wg,
        peers: [{ public_key: device.pub, allowed_ips: ['172.16.0.2/32'] }] }],
      outbounds: [{ type: 'direct', tag: 'direct' }],
      route: { rules: [{ inbound: ['wg-edge'], action: 'route', outbound: 'direct', override_address: '127.0.0.1', override_port: P.pageWg }] }
    }));
    run(singbox, f, 'peer');
    await sleep(500);   // a UDP listener has no TCP port to wait on
    wgRec = { id: 'wg', name: 'WARP-like', protocol: 'wireguard', address: '127.0.0.1', port: P.wg,
      outbound: { protocol: 'wireguard', settings: { secretKey: device.priv, address: ['172.16.0.2/32'], mtu: 1280, reserved: [0, 0, 0],
        peers: [{ publicKey: edge.pub, endpoint: '127.0.0.1:' + P.wg, allowedIPs: ['0.0.0.0/0', '::/0'] }] }, streamSettings: { sockopt: {} } } };
  }

  const byId = {};
  for (const id of [...Object.keys(servers), 'dead']) byId[id] = record(id, P[id]);
  const live = groupRecord({ id: 'grp-live', name: 'S1+S2', members: [{ id: 's1' }, { id: 's2' }, { id: 'dead' }] }, byId);
  const plainGroup = groupRecord({ id: 'grp-hop', name: 'S1b+S2b', members: [{ id: 's1b' }, { id: 's2b' }, { id: 'dead' }] }, byId);
  const settings = { socksPort: P.socks, httpPort: P.socks + 1, apiPort: P.socks + 2, routingMode: 'global', blockAds: false,
    geoAssets: false, dnsManaged: false, logLevel: 'warning', enableSniffing: false, chainRelayPort: P.relay };
  const rounds = [
    ['the group selected', { mode: 'single', server: live }, (seen) => seen.includes('S1') && seen.includes('S2') && seen.every((x) => x === 'S1' || x === 'S2')],
    ['advanced routing: 203.0.113.0/24 → the group', {
      mode: 'advanced', serversById: Object.assign({}, byId, { 'grp-live': live }), chainsById: {}, chain: [],
      rules: [{ type: 'ip', value: '203.0.113.0/24', target: 'grp-live' }], def: 's3'
    }, (seen) => seen.includes('S1') && seen.includes('S2') && seen.every((x) => x === 'S1' || x === 'S2')],
    ['a chain [group → S3]', { mode: 'chain', chain: [plainGroup, byId.s3] }, (seen) => seen.every((x) => x === 'S3')],
    ['a chain [H → group]', { mode: 'chain', chain: [byId.h, live] }, (seen) => seen.includes('S1') && seen.includes('S2') && seen.every((x) => x === 'S1' || x === 'S2')],
    ...(wgRec ? [['a chain [group → WireGuard]', { mode: 'chain', chain: [plainGroup, wgRec] }, (seen) => seen.every((x) => x === 'WG'), true]] : [])
  ];
  if (!wgRec) console.log('– no sing-box at ' + singbox + ': the [group → WireGuard] round is skipped');

  let failed = 0;
  for (const [label, plan, good, big] of rounds) {
    const cfg = buildConfig(plan, settings);
    if (big && cfg.outbounds.filter((o) => o.protocol === 'wireguard').length !== 1) throw new Error(label + ': the WireGuard is not built exactly once');
    if (!cfg.observatory) throw new Error(label + ': the builder wrote no health check');
    cfg.observatory.probeUrl = `http://127.0.0.1:${P.probe}/`;
    cfg.observatory.probeInterval = '2s';
    const file = path.join(work, 'client.json');
    fs.writeFileSync(file, JSON.stringify(cfg, null, 1));
    const t = spawnSync(xray, ['run', '-test', '-c', file], { encoding: 'utf8', timeout: 20000, windowsHide: true });
    if (t.status !== 0) {
      failed++;
      console.log(`✗ ${label}: the core refused the config — ${((t.stdout || '') + (t.stderr || '')).trim().split(/\r?\n/).slice(-1)[0]}`);
      continue;
    }
    const client = run(xray, file, 'client');
    let note;
    try {
      if (!await waitPort(P.socks)) throw new Error('the client never opened its SOCKS port');
      // the health check's first rounds: every member judged, the dead one dead — read from the core
      // itself rather than a fixed wait: through a hop (H) its probe takes longer to fail, and on a
      // slow CI runner 9 s was sometimes not yet the verdict, one fetch going to the dead member
      const verdicts = await waitVerdicts(settings.apiPort, cfg.groupTags, 30000);
      if (!verdicts) throw new Error('the health check gave no verdict on every member within 30 s');
      const seen = [];
      for (let i = 0; i < 9; i++) {
        try { seen.push(await fetchOnce()); } catch (e) { seen.push('ERR:' + e.message); }
      }
      if (!good(seen)) throw new Error('got ' + seen.join(' '));
      if (big) {
        const n = await fetchOnce('/big');
        if (n !== String(BIG)) throw new Error('2 MB through the WireGuard returned ' + n + ' bytes');
      }
      const vars = await new Promise((resolve, reject) => {
        http.get({ host: '127.0.0.1', port: settings.apiPort, path: '/debug/vars' }, (res) => {
          let b = '';
          res.on('data', (d) => { b += d; });
          res.on('end', () => { try { resolve(JSON.parse(b)); } catch (e) { reject(e); } });
        }).on('error', reject);
      });
      const total = sumOutbounds(vars);
      if (!(total.down > 0)) throw new Error('the traffic meter saw nothing: ' + JSON.stringify((vars.stats || {}).outbound || {}));
      note = seen.join(' ') + ` — the meter saw ${total.down} B down`;
      // the window's live view: the poller with this config's groups
      if (!cfg.groupTags) throw new Error('the builder gave no groupTags');
      const poller = new StatsPoller({ apiPort: settings.apiPort });
      poller.groupMap = cfg.groupTags;
      let live = null;
      poller.onStats = (st) => { live = st; };
      poller.last.t = Date.now() - 1000;
      await poller.tick();
      if (!live || !live.groups) throw new Error('the poller gave no groups');
      for (const g of live.groups) {
        for (const m of g.members) {
          if (m.alive !== (m.id !== 'dead')) throw new Error(`the health of ${m.id} in ${g.tag} reads ${m.alive}`);
        }
      }
      note += ' — health ' + live.groups.map((g) => g.members.map((m) => (m.alive ? '●' : '○')).join('')).join(' ');
    } catch (e) {
      failed++;
      note = 'FAILED — ' + e.message + '\n  ' + client.text().split('\n').filter(Boolean).slice(-6).join('\n  ');
    }
    try { client.proc.kill(); } catch { /* gone */ }
    await sleep(500);
    console.log(`${note.startsWith('FAILED') ? '✗' : '✓'} ${label}: ${note}`);
  }

  killAll();
  for (const p of pages) p.close();
  await sleep(300);
  try { fs.rmSync(work, { recursive: true, force: true }); } catch { /* a core still closing */ }
  console.log(`\n${rounds.length - failed}/${rounds.length} rounds passed (client ${path.basename(xray)}, servers ${path.basename(hopXray)})`);
  process.exit(failed ? 1 : 0);
}

process.on('exit', killAll);
process.on('SIGINT', () => { killAll(); process.exit(130); });
main().catch((e) => { killAll(); console.error(e); process.exit(1); });
