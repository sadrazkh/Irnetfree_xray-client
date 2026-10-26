#!/usr/bin/env node
'use strict';
/**
 * The end of a closed connection through a chain (configBuilder.relayHopDials),
 * on real cores, loopback only: the app's own builder against local VLESS+ws
 * servers whose pages are 256 KB and close the connection when sent — what a
 * download, or any server that says `Connection: close`, does. Straight
 * through a ws hop (dialerProxy) the core cut such a response short — 1–4 %
 * of small pages, about half the 256 KB ones on a 4-core runner, a group in
 * the chain or not: the hop's transport ends with an error (WebSocket's close
 * frame), the core interrupts the in-memory pipe to the next hop, and what
 * that hop had not read yet is dropped (Xray-core app/proxyman/outbound/
 * handler.go, transport/pipe/impl.go). With the relay every dial through a
 * hop rides a loopback socket instead. Three rounds, as the app builds them —
 * each must carry every page whole, through the relay (its inbound's counter):
 *   1. a chain [H → S1];
 *   2. a chain [H → group(S1, S2)] — every member dials through H;
 *   3. a chain [group(S1b, S2b) → S3] — S3 dialled through each member.
 * Then round 1 once more without the relay, for the record only: how many the
 * core still cuts short by itself (none would mean the core was fixed, and the
 * relay could go — it never fails the run).
 *
 *   IRNF_XRAY_EXE     the client core (default bin/xray)
 *   IRNF_HOP_EXE      the core the servers run (default: the client core)
 *   IRNF_PROBE_PORT   base port, default 22600
 *   IRNF_PROBE_N      pages per round, default 40
 */
const fs = require('fs');
const os = require('os');
const net = require('net');
const path = require('path');
const http = require('http');
const { spawn, spawnSync } = require('child_process');
const { buildConfig } = require('../src/main/configBuilder');
const { groupRecord } = require('../src/main/groups');
const { sumOutbounds } = require('../src/main/stats');

const BASE = Number(process.env.IRNF_PROBE_PORT || 22600);
const P = { s1: BASE + 1, s2: BASE + 2, s3: BASE + 3, h: BASE + 4, s1b: BASE + 5, s2b: BASE + 6,
  page1: BASE + 11, page2: BASE + 12, page3: BASE + 13, probe: BASE + 14, socks: BASE + 20, relay: BASE + 23 };
const N = Number(process.env.IRNF_PROBE_N || 40);
const SIZE = 256 * 1024;
const UUID = '7d2f0c3b-1e4a-4b6d-9c8e-0a1b2c3d4e5f';
const TARGET = '203.0.113.9';
const exeName = (n) => (process.platform === 'win32' ? n + '.exe' : n);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const xray = process.env.IRNF_XRAY_EXE || path.join(__dirname, '..', 'bin', exeName('xray'));
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
/** A page that names its server in its first two bytes, SIZE bytes in all, the connection closed once sent. */
const page = (port, name) => new Promise((r) => {
  const body = Buffer.concat([Buffer.from(name), Buffer.alloc(SIZE - name.length, 0x2e)]);
  const s = http.createServer((q, res) => { res.writeHead(200, { 'Content-Length': body.length, Connection: 'close' }); res.end(body); });
  s.listen(port, '127.0.0.1', () => r(s));
});
const probePage = (port) => new Promise((r) => {
  const s = http.createServer((q, res) => { res.writeHead(204); res.end(); });
  s.listen(port, '127.0.0.1', () => r(s));
});

/** GET / of TARGET:80 through the SOCKS port → the server's name, or what went wrong (`short <n>`: the body cut at n bytes). */
function fetchOnce() {
  return new Promise((resolve) => {
    const s = net.connect(P.socks, '127.0.0.1');
    let st = 0;
    let buf = Buffer.alloc(0);
    const t = setTimeout(() => { s.destroy(); resolve('timeout'); }, 15000);
    s.on('error', (e) => { clearTimeout(t); resolve(e.message); });
    s.on('connect', () => s.write(Buffer.from([5, 1, 0])));
    s.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      if (st === 0 && buf.length >= 2) { buf = buf.subarray(2); st = 1; s.write(Buffer.from([5, 1, 0, 1, ...TARGET.split('.').map(Number), 0, 80])); }
      if (st === 1 && buf.length >= 10) {
        if (buf[1] !== 0) { clearTimeout(t); s.destroy(); return resolve('SOCKS refused: ' + buf[1]); }
        buf = buf.subarray(10); st = 2; s.write('GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n');
      }
    });
    s.on('end', () => {
      clearTimeout(t);
      const i = buf.indexOf('\r\n\r\n');
      if (i < 0) return resolve('no HTTP answer');
      const body = buf.subarray(i + 4);
      resolve(body.length === SIZE ? body.subarray(0, 2).toString() : 'short ' + body.length);
    });
  });
}

function vars(apiPort) {
  return new Promise((resolve) => {
    http.get({ host: '127.0.0.1', port: apiPort, path: '/debug/vars' }, (res) => {
      let b = '';
      res.on('data', (d) => { b += d; });
      res.on('end', () => { try { resolve(JSON.parse(b)); } catch { resolve(null); } });
    }).on('error', () => resolve(null));
  });
}

/** Until the core's health check has judged every member of every group alive: true; false once `ms` have passed. */
async function waitAlive(apiPort, map, ms) {
  if (!map || !map.length) return true;
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const obs = ((await vars(apiPort)) || {}).observatory || {};
    if (map.every((g) => g.members.every((m, i) => obs[`${g.tag}~gm${i}`] && obs[`${g.tag}~gm${i}`].alive === true))) return true;
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
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-chaintail-'));
  const pages = [await page(P.page1, 'S1'), await page(P.page2, 'S2'), await page(P.page3, 'S3'), await probePage(P.probe)];
  const servers = { s1: P.page1, s2: P.page2, s3: P.page3, h: 0, s1b: 0, s2b: 0 };
  for (const [id, to] of Object.entries(servers)) {
    const f = path.join(work, id + '.json');
    fs.writeFileSync(f, JSON.stringify(serverConfig(P[id], to)));
    run(hopXray, f, id);
  }
  for (const id of Object.keys(servers)) if (!await waitPort(P[id])) { console.error('server ' + id + ' never came up'); killAll(); process.exit(1); }

  const byId = {};
  for (const id of Object.keys(servers)) byId[id] = record(id, P[id]);
  const live = groupRecord({ id: 'grp-live', name: 'S1+S2', members: [{ id: 's1' }, { id: 's2' }] }, byId);
  const hopGroup = groupRecord({ id: 'grp-hop', name: 'S1b+S2b', members: [{ id: 's1b' }, { id: 's2b' }] }, byId);
  const settings = { socksPort: P.socks, httpPort: P.socks + 1, apiPort: P.socks + 2, routingMode: 'global', blockAds: false,
    geoAssets: false, dnsManaged: false, logLevel: 'warning', enableSniffing: false, chainRelayPort: P.relay };
  const only = (...names) => (seen) => seen.every((x) => names.includes(x));
  const rounds = [
    ['a chain [H → S1]', { mode: 'chain', chain: [byId.h, byId.s1] }, only('S1')],
    ['a chain [H → group(S1, S2)]', { mode: 'chain', chain: [byId.h, live] }, (seen) => only('S1', 'S2')(seen) && seen.includes('S1') && seen.includes('S2')],
    ['a chain [group(S1b, S2b) → S3]', { mode: 'chain', chain: [hopGroup, byId.s3] }, only('S3')],
    ['a chain [H → S1] WITHOUT the relay (for the record — never fails the run)', { mode: 'chain', chain: [byId.h, byId.s1] }, null]
  ];

  let failed = 0;
  for (const [label, plan, good] of rounds) {
    const record = !good;
    const cfg = buildConfig(plan, record ? Object.assign({}, settings, { chainRelayPort: 0 }) : settings);
    const relayed = cfg.inbounds.some((i) => i.tag === 'chain-relay');
    if (!record && !relayed) { failed++; console.log(`✗ ${label}: the builder wrote no relay`); continue; }
    if (cfg.observatory) {
      cfg.observatory.probeUrl = `http://127.0.0.1:${P.probe}/`;
      cfg.observatory.probeInterval = '2s';
    }
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
      if (!await waitAlive(settings.apiPort, cfg.groupTags, 30000)) throw new Error('the health check judged no member alive within 30 s');
      const seen = [];
      for (let i = 0; i < N; i++) seen.push(await fetchOnce());
      const whole = seen.filter((x) => x.length === 2).length;
      const tally = {};
      for (const x of seen) { const k = x.startsWith('short ') ? 'cut short' : x; tally[k] = (tally[k] || 0) + 1; }
      const said = Object.entries(tally).map(([k, n]) => `${k} ×${n}`).join(', ');
      if (record) {
        note = `${N - whole}/${N} cut short by the core itself (${said})` +
          (whole === N ? ' — none: the core may be fixed; see configBuilder.relayHopDials' : '');
      } else {
        if (!good(seen)) throw new Error(`${whole}/${N} pages whole — ${said}`);
        const v = await vars(settings.apiPort);
        const inb = ((v && v.stats && v.stats.inbound) || {})['chain-relay'];
        if (!inb || !(inb.downlink > 0)) throw new Error('nothing went through the relay: ' + JSON.stringify(inb || null));
        const total = sumOutbounds(v);
        note = `${N}/${N} pages whole (${said}) — through the relay ${(inb.downlink / 1048576).toFixed(1)} MB, the meter saw ${(total.down / 1048576).toFixed(1)} MB`;
      }
    } catch (e) {
      failed++;
      note = 'FAILED — ' + e.message + '\n  ' + client.text().split('\n').filter(Boolean).slice(-6).join('\n  ');
    }
    try { client.proc.kill(); } catch { /* gone */ }
    await sleep(500);
    console.log(`${note.startsWith('FAILED') ? '✗' : record ? '–' : '✓'} ${label}: ${note}`);
  }

  killAll();
  for (const p of pages) p.close();
  await sleep(300);
  try { fs.rmSync(work, { recursive: true, force: true }); } catch { /* a core still closing */ }
  const gated = rounds.filter((r) => r[2]).length;
  console.log(`\n${gated - failed}/${gated} rounds passed (client ${path.basename(xray)}, servers ${path.basename(hopXray)})`);
  process.exit(failed ? 1 : 0);
}

process.on('exit', killAll);
process.on('SIGINT', () => { killAll(); process.exit(130); });
main().catch((e) => { killAll(); console.error(e); process.exit(1); });
