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
 *   4. a chain [H → group] — every member dials through H: S1 and S2 again.
 * Each round also reads the core's traffic counters as the app's meter does
 * (stats.sumOutbounds): a group's bytes must show — on its loopback, since the
 * members' `~` tags are left out of the total like a JSON server's helpers.
 * The health check asks a local page here instead of cp.cloudflare.com (the
 * only change made to what the builder wrote), so it needs no internet.
 *
 *   IRNF_XRAY_EXE     the client core (default bin/xray)
 *   IRNF_HOP_EXE      the core the servers run (default: the client core)
 *   IRNF_PROBE_PORT   base port, default 40400
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

const BASE = Number(process.env.IRNF_PROBE_PORT || 40400);
const P = { s1: BASE + 1, s2: BASE + 2, s3: BASE + 3, h: BASE + 4, s1b: BASE + 5, s2b: BASE + 6, dead: BASE + 9,
  page1: BASE + 11, page2: BASE + 12, page3: BASE + 13, probe: BASE + 14, socks: BASE + 20 };
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
const page = (port, text) => new Promise((r) => {
  const s = http.createServer((q, res) => { res.writeHead(200, { 'Content-Length': text.length }); res.end(text); });
  s.listen(port, '127.0.0.1', () => r(s));
});

/** GET / of TARGET:80 through the SOCKS port → the body. */
function fetchOnce() {
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
        buf = buf.subarray(10); st = 2; s.write(`GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n`);
      }
    });
    s.on('end', () => { clearTimeout(t); const i = buf.indexOf('\r\n\r\n'); return i < 0 ? reject(new Error('no HTTP answer')) : resolve(buf.subarray(i + 4).toString()); });
  });
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
  const servers = { s1: P.page1, s2: P.page2, s3: P.page3, h: 0, s1b: 0, s2b: 0 };
  for (const [id, to] of Object.entries(servers)) {
    const f = path.join(work, id + '.json');
    fs.writeFileSync(f, JSON.stringify(serverConfig(P[id], to)));
    run(hopXray, f, id);
  }
  for (const id of Object.keys(servers)) if (!await waitPort(P[id])) { console.error('server ' + id + ' never came up'); killAll(); process.exit(1); }

  const byId = {};
  for (const id of [...Object.keys(servers), 'dead']) byId[id] = record(id, P[id]);
  const live = groupRecord({ id: 'grp-live', name: 'S1+S2', members: [{ id: 's1' }, { id: 's2' }, { id: 'dead' }] }, byId);
  const plainGroup = groupRecord({ id: 'grp-hop', name: 'S1b+S2b', members: [{ id: 's1b' }, { id: 's2b' }, { id: 'dead' }] }, byId);
  const settings = { socksPort: P.socks, httpPort: P.socks + 1, apiPort: P.socks + 2, routingMode: 'global', blockAds: false,
    geoAssets: false, dnsManaged: false, logLevel: 'warning', enableSniffing: false };
  const rounds = [
    ['the group selected', { mode: 'single', server: live }, (seen) => seen.includes('S1') && seen.includes('S2') && seen.every((x) => x === 'S1' || x === 'S2')],
    ['advanced routing: 203.0.113.0/24 → the group', {
      mode: 'advanced', serversById: Object.assign({}, byId, { 'grp-live': live }), chainsById: {}, chain: [],
      rules: [{ type: 'ip', value: '203.0.113.0/24', target: 'grp-live' }], def: 's3'
    }, (seen) => seen.includes('S1') && seen.includes('S2') && seen.every((x) => x === 'S1' || x === 'S2')],
    ['a chain [group → S3]', { mode: 'chain', chain: [plainGroup, byId.s3] }, (seen) => seen.every((x) => x === 'S3')],
    ['a chain [H → group]', { mode: 'chain', chain: [byId.h, live] }, (seen) => seen.includes('S1') && seen.includes('S2') && seen.every((x) => x === 'S1' || x === 'S2')]
  ];

  let failed = 0;
  for (const [label, plan, good] of rounds) {
    const cfg = buildConfig(plan, settings);
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
      // the health check's first rounds: the dead member found dead (through a hop, H, its probe takes longer to fail)
      await sleep(9000);
      const seen = [];
      for (let i = 0; i < 9; i++) {
        try { seen.push(await fetchOnce()); } catch (e) { seen.push('ERR:' + e.message); }
      }
      if (!good(seen)) throw new Error('got ' + seen.join(' '));
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
