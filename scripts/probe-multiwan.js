#!/usr/bin/env node
'use strict';
/**
 * Two internets at once (settings.multiWan) on REAL links. The app's own
 * buildConfig binds proxy outbounds to interfaces (`sockopt.interface`, which
 * is SO_BINDTODEVICE on Linux): a copy of the server per link behind a
 * round-robin (balance), a primary and a fallback (failover), or XHTTP's
 * upload on one link and its download (`downloadSettings`) on another
 * (split). `xray run -test` says the config parses; only the bytes on each
 * link say the core did what it asks.
 *
 * Two network namespaces of their own, made here and removed whatever
 * happens — the runner's own network is never touched (no route, address or
 * sysctl of its own changes):
 *
 *        mwcli (the client)                              mwsrv (the server)
 *   this probe ─socks─▶ client core ─┬─ A  mwa0 10.10.1.1/30 ══ mwa1 10.10.1.2 ─┐
 *   (downloads,                      │     to 10.20.0.1 metric 100              ├─▶ 10.20.0.1 (on lo)
 *    uploads)                        └─ B  mwb0 10.10.2.1/30 ══ mwb1 10.10.2.2 ─┘   server core:
 *                                          to 10.20.0.1 metric 200                  VLESS/TCP, VLESS/XHTTP
 *                                                                                    freedom ─▶ the page
 *                                                                                    (127.0.0.1, a node of its own)
 *
 * A socket nobody bound leaves by A (the route the OS prefers); one bound to
 * mwb0 leaves by B. A reply from 10.20.0.1 on B is not on that preferred
 * route, so the reverse-path filter is off — inside the namespaces only. Each
 * link is limited to IRNF_MW_RATE each way (tc tbf, default 100mbit) so the
 * sum of two shows: printed, never gated — the gates are WHICH link carried
 * the bytes (/sys/class/net/<link>/statistics), not how fast.
 *
 * The client is the app's own: a vless:// link through parser.parseLink, the
 * config buildConfig({ mode: 'single', server }, settings) writes, settings
 * from tests/fixtures with `multiWan` (links A = mwa0, B = mwb0). Two things
 * differ from the app: the health check asks the page here instead of
 * cp.cloudflare.com (no internet in there; its 10 s interval is kept) and the
 * client logs at info (which member each connection took, printed on a
 * failure). The target is 198.51.100.7:80 — a documentation address, outside
 * the builder's private bypass; the server's freedom hands every flow to the
 * page. Plaintext VLESS is fine: the server's address is private.
 *
 * Gates, each from the links' byte counters before and after:
 *   multiWan off  the config is byte for byte the one without multiWan
 *   control       multiWan off: 8 parallel downloads ride A alone (≥ 95 % of
 *                 the payload in on A, ≤ 2 % on B) — the counters can tell
 *   balance       8 parallel downloads ride both links, each ≥ 20 % of the bytes
 *   failover      the primary is B — the link the OS would NOT pick, so riding
 *                 it is the binding's doing, not the routing table's:
 *                 (1) downloads ride B (≥ 90 %); (2) B down → within 40 s new
 *                 downloads succeed, on A; (3) B up again → within 40 s they
 *                 ride B again
 *   split         XHTTP, both ways round — the leg on B is the one the OS would
 *                 not pick, so up B proves the upload's binding and down B the
 *                 download's: a 20 MB upload leaves by `up` (≥ 90 % of it out on
 *                 that link, ≤ 10 % on the other), a 20 MB download arrives on
 *                 `down` (the same, in)
 * Every line prints the bytes per link; the core logs follow a failure. A
 * hard limit stops the whole run (HARD_LIMIT_MS) so CI never hangs.
 *
 * Runs only where it is meant to: Linux, root and IRNF_MW_PROBE=1 (CI).
 *   IRNF_XRAY_EXE    the core under test, client and server (default bin/xray)
 *   IRNF_HOP_EXE     the server's core (default: the core under test)
 *   IRNF_PROBE_PORT  base port, default 41200 (never the app's own)
 *   IRNF_MW_RATE     each link's rate each way, tc tbf (default 100mbit; 0 = none)
 */
const { spawn, spawnSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const net = require('net');
const os = require('os');
const path = require('path');

const NS_CLI = 'mwcli', NS_SRV = 'mwsrv';
/** The two links: the client's end, the server's end, and the route to the server over each. */
const A = { name: 'A', dev: 'mwa0', peer: 'mwa1', ip: '10.10.1.1', gw: '10.10.1.2', metric: 100, key: 'a' };
const B = { name: 'B', dev: 'mwb0', peer: 'mwb1', ip: '10.10.2.1', gw: '10.10.2.2', metric: 200, key: 'b' };
const SRV_IP = '10.20.0.1';
const TARGET = '198.51.100.7';
const PROBE_URL = `http://${TARGET}/ok`;
const UUID = '7d2f0c3b-1e4a-4b6d-9c8e-0a1b2c3d4e5f';
const BASE = Number(process.env.IRNF_PROBE_PORT || 41200);
const P = { tcp: BASE + 1, xhttp: BASE + 2, web: BASE + 3, socks: BASE + 10, http: BASE + 11, api: BASE + 12 };
/** The app's own ports (the owner's IRNetFree runs on them): never these. */
const APP_PORTS = [10808, 10809, 10085, 30808, 30809, 30085];
const RATE = process.env.IRNF_MW_RATE === undefined ? '100mbit' : String(process.env.IRNF_MW_RATE).trim();
const HARD_LIMIT_MS = 240000;
const INNER_LIMIT_MS = HARD_LIMIT_MS - 15000;   // the tests stop first, with the core logs; then the teardown
const MB = 1048576;
const PAR = 8, EACH = 4 * MB, SPLIT = 20 * MB, POLL = 1 * MB;
const VERDICT_WAIT_MS = 25000, FAILOVER_WAIT_MS = 40000;
const exeName = (n) => (process.platform === 'win32' ? n + '.exe' : n);
const XRAY = process.env.IRNF_XRAY_EXE || path.join(__dirname, '..', 'bin', exeName('xray'));
const SERVER_XRAY = process.env.IRNF_HOP_EXE || XRAY;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const run = (cmd, args, opts = {}) => {
  const r = spawnSync(cmd, args, Object.assign({ encoding: 'utf8', timeout: 20000 }, opts));
  if (r.status !== 0 && !opts.mayFail) throw new Error(`${cmd} ${args.join(' ')}: ${((r.stderr || r.stdout || '') + (r.error ? r.error.message : '')).toString().trim()}`);
  return r;
};
const inNs = (ns, args, opts) => run('ip', ['netns', 'exec', ns, ...args], opts);
const lastLine = (r) => ((r.stdout || '') + (r.stderr || '') + (r.error ? r.error.message : '')).trim().split(/\r?\n/).slice(-1)[0] || '(no output)';
const versionOf = (exe) => (spawnSync(exe, ['version'], { encoding: 'utf8', timeout: 20000 }).stdout || '').split(/\r?\n/)[0] || `(no version from ${exe})`;

/* ------------------------------ what the client gets: the app's own ------------------------------ */

/** A link as Settings stores it (the contract's shape), keyed by the interface it binds. */
const linkOf = (l) => ({ id: l.dev, iface: l.dev, name: l.name, role: 'use', weight: 1, quotaGb: 0, quotaPeriod: 'none' });
const NO_SPLIT = { up: '', down: '' };
/** settings.multiWan per line. Failover lists B first: the primary is the link the OS would not pick. */
const MW = {
  off: { enabled: false, mode: 'balance', links: [linkOf(A), linkOf(B)], split: NO_SPLIT },
  balance: { enabled: true, mode: 'balance', links: [linkOf(A), linkOf(B)], split: NO_SPLIT },
  failover: { enabled: true, mode: 'failover', links: [linkOf(B), linkOf(A)], split: NO_SPLIT },
  splitUpB: { enabled: true, mode: 'split', links: [linkOf(A), linkOf(B)], split: { up: B.dev, down: A.dev } },
  splitUpA: { enabled: true, mode: 'split', links: [linkOf(A), linkOf(B)], split: { up: A.dev, down: B.dev } }
};

/** The two servers, as the app keeps them: parsed from links like a user's. */
function probeServers() {
  const { parseLink } = require('../src/main/parser');
  return {
    tcp: parseLink(`vless://${UUID}@${SRV_IP}:${P.tcp}?type=tcp&security=none&encryption=none#mw-tcp`),
    xhttp: parseLink(`vless://${UUID}@${SRV_IP}:${P.xhttp}?type=xhttp&security=none&encryption=none&path=%2Fmw&mode=packet-up#mw-xhttp`)
  };
}

/** The settings main.js would pass (tests/fixtures), on this probe's ports; `multiWan` left out when undefined. */
function probeSettings(multiWan) {
  const F = require('../tests/fixtures');
  return F.settings(Object.assign({
    socksPort: P.socks, httpPort: P.http, apiPort: P.api,
    routingMode: 'global', blockAds: false, geoAssets: false, enableSniffing: false, dnsManaged: false, logLevel: 'info'
  }, multiWan === undefined ? {} : { multiWan }));
}

/** Every config the probe runs — buildConfig({ mode: 'single', server }, settings), nothing else. */
function buildProbeConfigs() {
  const { buildConfig } = require('../src/main/configBuilder');
  const sv = probeServers();
  const single = (server, mw) => buildConfig({ mode: 'single', server }, probeSettings(mw));
  return {
    servers: sv,
    none: single(sv.tcp, undefined),
    off: single(sv.tcp, MW.off),
    balance: single(sv.tcp, MW.balance),
    failover: single(sv.tcp, MW.failover),
    splitUpB: single(sv.xhttp, MW.splitUpB),
    splitUpA: single(sv.xhttp, MW.splitUpA)
  };
}

/** The far side: VLESS over TCP and over XHTTP on 10.20.0.1, every flow handed to the page. */
function serverConfig() {
  const users = { clients: [{ id: UUID }], decryption: 'none' };
  return {
    log: { loglevel: 'info' },
    inbounds: [
      { tag: 'vless-tcp', listen: SRV_IP, port: P.tcp, protocol: 'vless', settings: users, streamSettings: { network: 'tcp', security: 'none' } },
      { tag: 'vless-xhttp', listen: SRV_IP, port: P.xhttp, protocol: 'vless', settings: users, streamSettings: { network: 'xhttp', security: 'none', xhttpSettings: { path: '/mw' } } }
    ],
    outbounds: [{ tag: 'page', protocol: 'freedom', settings: { redirect: '127.0.0.1:' + P.web, finalRules: [{ action: 'allow' }] } }]
  };
}

/** What a config binds, in one line: each bound outbound's link (and XHTTP's download leg), each balancer. */
function bindings(cfg) {
  const out = [];
  for (const o of (cfg && cfg.outbounds) || []) {
    const ss = (o && o.streamSettings) || {};
    const iface = ss.sockopt && ss.sockopt.interface;
    const xs = ss.xhttpSettings || {};
    const ds = xs.downloadSettings || (xs.extra && xs.extra.downloadSettings);
    const down = ds && ds.sockopt && ds.sockopt.interface;
    if (iface || ds) out.push(`${o.tag} → ${iface || '(unbound)'}${ds ? ` (download → ${down || '(unbound)'})` : ''}`);
  }
  for (const b of ((cfg && cfg.routing) || {}).balancers || []) {
    out.push(`${b.tag}: ${(b.strategy && b.strategy.type) || '?'} over ${(b.selector || []).join(',')}, fallback ${b.fallbackTag || '-'}`);
  }
  return out.join('; ') || 'no outbound bound to a link, no balancer';
}

/* ------------------------------ the page (in mwsrv, a node of its own) ------------------------------ */

/** GET /big?n=<bytes>: that many bytes; POST /up: reads the body, answers {"got": n}; anything else: "ok". */
function serveMode() {
  const port = Number(process.argv[3]);
  const chunk = crypto.randomBytes(64 * 1024);
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://page');
    if (req.method === 'POST' && u.pathname === '/up') {
      let got = 0;
      req.on('data', (d) => { got += d.length; });
      req.on('end', () => {
        const body = JSON.stringify({ got });
        res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) });
        res.end(body);
      });
      return;
    }
    if (u.pathname === '/big') {
      let left = Math.max(0, Math.min(Number(u.searchParams.get('n')) || 0, 256 * MB));
      res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': left });
      const pump = () => {
        while (left > 0) {
          const k = Math.min(left, chunk.length);
          left -= k;
          if (!res.write(k === chunk.length ? chunk : chunk.subarray(0, k))) return void res.once('drain', pump);
        }
        res.end();
      };
      return pump();
    }
    res.writeHead(200, { 'Content-Type': 'text/plain', 'Content-Length': 2 });
    res.end('ok');
  });
  srv.listen(port, '127.0.0.1', () => console.log('ready ' + port));
}

/* ------------------------------ the namespaces (the parent, in the root namespace) ------------------------------ */

function preconditions() {
  if (process.env.IRNF_MW_PROBE !== '1' || process.platform !== 'linux' || !process.getuid || process.getuid() !== 0) {
    console.error('probe-multiwan: CI only — Linux, root and IRNF_MW_PROBE=1 (it makes network namespaces and links)');
    process.exit(2);
  }
  for (const [k, exe] of [['IRNF_XRAY_EXE', XRAY], ['IRNF_HOP_EXE', SERVER_XRAY]]) {
    if (!fs.existsSync(exe)) { console.error(`probe-multiwan: ${k}: no core at ${exe}`); process.exit(2); }
  }
  const own = Object.values(P).filter((p) => APP_PORTS.includes(p));
  if (own.length) { console.error(`probe-multiwan: IRNF_PROBE_PORT=${BASE} lands on the app's own port ${own.join(', ')}`); process.exit(2); }
}

/** Everything this probe made, gone: its processes, its namespaces (their links with them). Safe to repeat. */
function clearNet() {
  for (const ns of [NS_CLI, NS_SRV]) {
    const pids = String(run('ip', ['netns', 'pids', ns], { mayFail: true }).stdout || '').split(/\s+/).filter(Boolean);
    for (const pid of pids) { try { process.kill(Number(pid), 'SIGKILL'); } catch { /* gone */ } }
    run('ip', ['netns', 'del', ns], { mayFail: true });
  }
  // only there when a run died between making a pair the old way and moving it (netUp's fallback)
  for (const l of [A, B]) run('ip', ['link', 'del', l.dev], { mayFail: true });
}

function netUp() {
  for (const ns of [NS_CLI, NS_SRV]) {
    run('ip', ['netns', 'add', ns]);
    inNs(ns, ['ip', 'link', 'set', 'lo', 'up']);
    // inside the namespace only: no IPv6 chatter on the links (the counters stay the probe's), and no
    // reverse-path filter (B's replies come from 10.20.0.1, whose preferred route back is A)
    inNs(ns, ['sysctl', '-qw', 'net.ipv6.conf.all.disable_ipv6=1', 'net.ipv6.conf.default.disable_ipv6=1',
      'net.ipv4.conf.all.rp_filter=0', 'net.ipv4.conf.default.rp_filter=0'], { mayFail: true });
  }
  for (const l of [A, B]) {
    // each end made straight in its namespace; an older ip makes the pair here and moves it
    const made = run('ip', ['link', 'add', l.dev, 'netns', NS_CLI, 'type', 'veth', 'peer', 'name', l.peer, 'netns', NS_SRV], { mayFail: true });
    if (made.status !== 0) {
      run('ip', ['link', 'add', l.dev, 'type', 'veth', 'peer', 'name', l.peer]);
      run('ip', ['link', 'set', l.dev, 'netns', NS_CLI]);
      run('ip', ['link', 'set', l.peer, 'netns', NS_SRV]);
    }
    inNs(NS_CLI, ['sysctl', '-qw', `net.ipv4.conf.${l.dev}.rp_filter=0`, `net.ipv6.conf.${l.dev}.disable_ipv6=1`], { mayFail: true });
    inNs(NS_SRV, ['sysctl', '-qw', `net.ipv4.conf.${l.peer}.rp_filter=0`, `net.ipv6.conf.${l.peer}.disable_ipv6=1`], { mayFail: true });
    inNs(NS_CLI, ['ip', 'addr', 'add', l.ip + '/30', 'dev', l.dev]);
    inNs(NS_SRV, ['ip', 'addr', 'add', l.gw + '/30', 'dev', l.peer]);
    inNs(NS_SRV, ['ip', 'link', 'set', l.peer, 'up']);
    inNs(NS_CLI, ['ip', 'link', 'set', l.dev, 'up']);
  }
  inNs(NS_SRV, ['ip', 'addr', 'add', SRV_IP + '/32', 'dev', 'lo']);
  // one server address, a route over each link: A preferred (metric 100), B behind it (metric 200)
  for (const l of [A, B]) inNs(NS_CLI, ['ip', 'route', 'add', SRV_IP + '/32', 'via', l.gw, 'dev', l.dev, 'metric', String(l.metric)]);
}

/** Each link RATE each way (tbf on both ends' egress); a kernel without tbf runs unlimited — speed is never gated. */
function shape() {
  if (!RATE || RATE === '0') return 'no rate limit (IRNF_MW_RATE=0)';
  const ends = [[NS_CLI, A.dev], [NS_CLI, B.dev], [NS_SRV, A.peer], [NS_SRV, B.peer]];
  for (const [ns, dev] of ends) {
    const r = inNs(ns, ['tc', 'qdisc', 'replace', 'dev', dev, 'root', 'tbf', 'rate', RATE, 'burst', '256kb', 'latency', '100ms'], { mayFail: true });
    if (r.status !== 0) {
      for (const [n, d] of ends) inNs(n, ['tc', 'qdisc', 'del', 'dev', d, 'root'], { mayFail: true });
      return `no rate limit — tc refused tbf on ${dev}: ${lastLine(r)}`;
    }
  }
  return `each link ${RATE} each way (tc tbf)`;
}

let work = null;
let tornDown = false;
function teardown() {
  if (tornDown) return;
  tornDown = true;
  clearNet();
  if (work) { try { fs.rmSync(work, { recursive: true, force: true }); } catch { /* best effort */ } work = null; }
}

async function outside() {
  preconditions();
  clearNet();   // what a run that died left behind
  process.on('exit', teardown);
  process.on('SIGINT', () => { teardown(); process.exit(130); });
  process.on('SIGTERM', () => { teardown(); process.exit(143); });
  setTimeout(() => {
    console.log(`FAIL the probe ran out of time (${HARD_LIMIT_MS / 1000} s) — stopped`);
    teardown();
    process.exit(1);
  }, HARD_LIMIT_MS).unref();

  work = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-mw-'));
  netUp();
  const rateNote = shape();
  console.log(`client ${versionOf(XRAY)}${SERVER_XRAY !== XRAY ? ` · server ${versionOf(SERVER_XRAY)}` : ''}`);
  console.log(`links: A ${A.dev} ${A.ip} → ${SRV_IP} metric ${A.metric} (what the OS picks) · B ${B.dev} ${B.ip} → ${SRV_IP} metric ${B.metric} · ${rateNote}`);
  console.log(`ports ${BASE}+ · netns ${NS_CLI} (client) / ${NS_SRV} (server) · ${work}\n`);

  // the tests run INSIDE the client's namespace: its loopback is the client's SOCKS, its /sys its links' counters
  const child = spawn('ip', ['netns', 'exec', NS_CLI, process.execPath, __filename, '--inside'], {
    stdio: 'inherit', env: Object.assign({}, process.env, { IRNF_MW_WORK: work, IRNF_MW_RATE_NOTE: rateNote })
  });
  const code = await new Promise((resolve) => {
    child.on('error', (e) => { console.log(`FAIL could not start the tests in ${NS_CLI}: ${e.message}`); resolve(1); });
    child.on('exit', (c) => resolve(c === null ? 1 : c));
  });
  teardown();
  process.exit(code);
}

/* ------------------------------ the tests (a child, inside mwcli) ------------------------------ */

const kids = [];
let server = null;
function spawnKid(name, cmd, args) {
  const proc = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '';
  const take = (d) => { out += d; if (out.length > 400000) out = out.slice(-200000); };
  proc.stdout.on('data', take);
  proc.stderr.on('data', take);
  proc.on('error', (e) => { out += `\n(${name} did not start: ${e.message})`; });
  const kid = { name, proc, text: () => out, exited: new Promise((r) => proc.on('exit', r)) };
  kids.push(kid);
  return kid;
}
async function stopKid(kid) {
  if (!kid) return;
  const i = kids.indexOf(kid);
  if (i >= 0) kids.splice(i, 1);
  if (kid.proc.exitCode !== null || kid.proc.signalCode !== null) return;
  kid.proc.kill('SIGTERM');
  const gone = await Promise.race([kid.exited.then(() => true), sleep(3000).then(() => false)]);
  if (!gone) { kid.proc.kill('SIGKILL'); await Promise.race([kid.exited, sleep(2000)]); }
}
function killAll() { for (const k of kids.splice(0)) { try { k.proc.kill('SIGKILL'); } catch { /* gone */ } } }
const tail = (kid, n) => kid.text().split('\n').filter((l) => l.trim()).slice(-n).map((l) => `      [${kid.name}] ${l}`).join('\n') || `      [${kid.name}] (nothing logged)`;

async function waitPort(host, port, ms) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const ok = await new Promise((resolve) => {
      const s = net.connect(port, host);
      const t = setTimeout(() => { s.destroy(); resolve(false); }, 1000);
      s.once('connect', () => { clearTimeout(t); s.destroy(); resolve(true); });
      s.once('error', () => { clearTimeout(t); resolve(false); });
    });
    if (ok) return true;
    await sleep(150);
  }
  return false;
}
async function waitText(kid, re, ms) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (re.test(kid.text())) return true;
    if (kid.proc.exitCode !== null) return false;
    await sleep(100);
  }
  return false;
}

/** Both links' byte counters (rx: from the server, the download; tx: to it, the upload). */
function counters() {
  const read = (dev) => {
    try {
      const f = (k) => Number(fs.readFileSync(`/sys/class/net/${dev}/statistics/${k}_bytes`, 'utf8').trim());
      return { rx: f('rx'), tx: f('tx') };
    } catch {
      // a /sys that is not this namespace's: ask ip
      const j = JSON.parse(run('ip', ['-s', '-j', 'link', 'show', 'dev', dev]).stdout)[0];
      return { rx: Number(j.stats64.rx.bytes), tx: Number(j.stats64.tx.bytes) };
    }
  };
  return { a: read(A.dev), b: read(B.dev) };
}
function since(c0) {
  const c = counters();
  return { a: { rx: c.a.rx - c0.a.rx, tx: c.a.tx - c0.a.tx }, b: { rx: c.b.rx - c0.b.rx, tx: c.b.tx - c0.b.tx } };
}
const mb = (n) => (n / MB).toFixed(2) + ' MB';
const sec = (ms) => (ms / 1000).toFixed(2) + ' s';
const pct = (x) => (x * 100).toFixed(0) + ' %';
const mbit = (bytes, ms) => (ms > 0 ? (bytes * 8 / 1e6 / (ms / 1000)).toFixed(0) : '?') + ' Mbit/s';
const links = (d) => `A in ${mb(d.a.rx)} out ${mb(d.a.tx)} · B in ${mb(d.b.rx)} out ${mb(d.b.tx)}`;

const CHUNK = crypto.randomBytes(64 * 1024);
/**
 * One HTTP exchange with the page through the client's SOCKS port:
 * GET /big?n=<size> (counts the body) or POST /up with <size> bytes (the page
 * says how many it read). → { ok, ms, bytes, got?, error? }, never a throw.
 */
function through(method, size, timeoutMs) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    const s = net.connect(P.socks, '127.0.0.1');
    let stage = 0, buf = Buffer.alloc(0), want = -1, got = 0, text = '', done = false;
    const finish = (r) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      s.destroy();
      resolve(Object.assign({ ms: Date.now() - t0, bytes: got }, r));
    };
    const timer = setTimeout(() => finish({ ok: false, error: `timed out after ${timeoutMs / 1000} s` + (want >= 0 ? ` (${got} of ${want} bytes)` : '') }), timeoutMs);
    s.on('error', (e) => finish({ ok: false, error: e.code || e.message }));
    s.on('close', () => finish({ ok: false, error: want >= 0 ? `cut short: ${got} of ${want} bytes` : stage < 2 ? 'closed during the SOCKS handshake' : 'closed with no HTTP answer' }));
    s.on('connect', () => s.write(Buffer.from([5, 1, 0])));
    const body = (d) => {
      got += d.length;
      if (method === 'POST') text += d.toString('latin1');
      if (got < want) return;
      if (method === 'GET') return finish(got === want && want === size ? { ok: true } : { ok: false, error: `${got} bytes, asked for ${size}` });
      let j = null;
      try { j = JSON.parse(text); } catch { /* reported */ }
      finish(j && j.got === size ? { ok: true, got: j.got } : { ok: false, got: j && j.got, error: `the page read ${j ? j.got : JSON.stringify(text.slice(0, 40))} of ${size}` });
    };
    const send = () => {
      if (method === 'GET') return void s.write(`GET /big?n=${size} HTTP/1.1\r\nHost: ${TARGET}\r\nConnection: close\r\n\r\n`);
      s.write(`POST /up HTTP/1.1\r\nHost: ${TARGET}\r\nContent-Type: application/octet-stream\r\nContent-Length: ${size}\r\nConnection: close\r\n\r\n`);
      let left = size;
      const pump = () => {
        while (left > 0 && !done) {
          const k = Math.min(left, CHUNK.length);
          left -= k;
          if (!s.write(k === CHUNK.length ? CHUNK : CHUNK.subarray(0, k))) return void s.once('drain', pump);
        }
      };
      pump();
    };
    s.on('data', (d) => {
      if (stage === 3) return body(d);
      buf = Buffer.concat([buf, d]);
      if (stage === 0) {
        if (buf.length < 2) return;
        if (buf[0] !== 5 || buf[1] !== 0) return finish({ ok: false, error: 'SOCKS greeting refused' });
        buf = buf.subarray(2);
        stage = 1;
        s.write(Buffer.from([5, 1, 0, 1, ...TARGET.split('.').map(Number), 0, 80]));
      }
      if (stage === 1) {
        if (buf.length < 5) return;
        if (buf[1] !== 0) return finish({ ok: false, error: 'SOCKS connect refused (code ' + buf[1] + ')' });
        const len = buf[3] === 1 ? 10 : buf[3] === 4 ? 22 : 7 + buf[4];
        if (buf.length < len) return;
        buf = buf.subarray(len);
        stage = 2;
        send();
      }
      if (stage === 2) {
        const end = buf.indexOf('\r\n\r\n');
        if (end < 0) return;
        const head = buf.subarray(0, end).toString('latin1');
        const status = Number((/^HTTP\/1\.[01] (\d{3})/.exec(head) || [])[1]);
        const m = /\r\ncontent-length:\s*(\d+)/i.exec(head);
        if (status !== 200 || !m) return finish({ ok: false, error: `HTTP ${status || '?'}${m ? '' : ', no Content-Length'}` });
        want = Number(m[1]);
        stage = 3;
        const rest = buf.subarray(end + 4);
        buf = Buffer.alloc(0);
        body(rest);
      }
    });
  });
}

/** `n` downloads of `size` at once, with what the links carried meanwhile. */
async function parallelGets(n, size, timeoutMs) {
  const c0 = counters();
  const t0 = Date.now();
  const r = await Promise.all(Array.from({ length: n }, () => through('GET', size, timeoutMs)));
  const errors = [...new Set(r.filter((x) => !x.ok).map((x) => x.error))];
  return { ms: Date.now() - t0, d: since(c0), okN: r.filter((x) => x.ok).length, pay: n * size, errors };
}
const errs = (x) => (x.errors.length ? ` · ${x.errors.join('; ')}` : '');

/** The client core's /debug/vars (the health check's verdicts are under `observatory`). */
function debugVars() {
  return new Promise((resolve) => {
    const req = http.get({ host: '127.0.0.1', port: P.api, path: '/debug/vars', timeout: 2000 }, (res) => {
      let b = '';
      res.on('data', (d) => { b += d; });
      res.on('end', () => { try { resolve(JSON.parse(b)); } catch { resolve(null); } });
    });
    req.on('timeout', () => req.destroy());
    req.on('error', () => resolve(null));
  });
}
const memberTags = (map) => (map || []).flatMap((g) => g.members.map((m, i) => ({ tag: `${g.tag}~gm${i}`, who: m.name || m.id || '' })));
/** Until the health check has judged every member of every group alive (or `ms` passed). */
async function waitAlive(map, ms) {
  const end = Date.now() + ms;
  let obs = {};
  while (Date.now() < end) {
    const v = await debugVars();
    obs = (v && v.observatory) || {};
    if (memberTags(map).every((m) => obs[m.tag] && obs[m.tag].alive === true)) return { ok: true, obs };
    await sleep(500);
  }
  return { ok: false, obs };
}
const describeObs = (map, obs) => memberTags(map).map((m) => `${m.tag} (${m.who}) ${obs[m.tag] ? (obs[m.tag].alive ? 'alive' : 'dead') : 'not judged'}`).join(', ');

let failed = 0, passed = 0;
function gate(ok, label, note) {
  if (ok) passed++; else failed++;
  console.log(`${ok ? 'PASS' : 'FAIL'} ${label}${note ? ' — ' + note : ''}`);
}
const info = (label, note) => console.log(`  ·  ${label}${note ? ' — ' + note : ''}`);

function diag() {
  const show = (cmd) => String(run(cmd[0], cmd.slice(1), { mayFail: true }).stdout || '').trim().split('\n').map((l) => `      [${cmd.slice(0, 4).join(' ')}] ${l}`).join('\n');
  return [show(['ip', '-4', 'addr']), show(['ip', '-4', 'route']), show(['ip', 'netns', 'exec', NS_SRV, 'ip', '-4', 'addr'])].join('\n');
}
function dumpLogs(client) {
  console.log('    the core logs (last lines):');
  if (client) console.log(tail(client, 30));
  if (server) console.log(tail(server, 20));
}

async function startClient(file, cfg) {
  const f = path.join(process.env.IRNF_MW_WORK, file + '.json');
  fs.writeFileSync(f, JSON.stringify(cfg, null, 1));
  const t = spawnSync(XRAY, ['run', '-test', '-c', f], { encoding: 'utf8', timeout: 20000 });
  if (t.status !== 0) return { error: 'the core refused the config — ' + lastLine(t) };
  const kid = spawnKid('client', XRAY, ['run', '-c', f]);
  if (!await waitPort('127.0.0.1', P.socks, 10000)) return { error: 'the client never opened its SOCKS port', kid };
  return { kid };
}

/** One client core for one line: started, `body` run, the logs printed when a gate in it failed, stopped. */
async function withClient(label, file, cfg, body) {
  // the only change to what the builder wrote: the health check asks the page (cp.cloudflare.com is not in here)
  if (cfg.observatory) cfg.observatory.probeUrl = PROBE_URL;
  info(label, 'the config: ' + bindings(cfg));
  const before = failed;
  const c = await startClient(file, cfg);
  if (c.error) {
    gate(false, label, c.error);
    dumpLogs(c.kid);
    await stopKid(c.kid);
    return;
  }
  try { await body(cfg); } catch (e) { gate(false, label, 'stopped: ' + e.message); }
  if (failed > before) dumpLogs(c.kid);
  await stopKid(c.kid);
}

/** The health check's verdicts, waited for and printed (no group: nothing to judge — said, not failed). */
async function verdicts(cfg, label) {
  if (!cfg.groupTags) { info(label, 'no group in the config: nothing for a health check to judge'); return; }
  const v = await waitAlive(cfg.groupTags, VERDICT_WAIT_MS);
  info(label, `health check: ${describeObs(cfg.groupTags, v.obs)}${v.ok ? '' : ` — not every member alive within ${VERDICT_WAIT_MS / 1000} s`}`);
}

/** Downloads of 1 MB, one a second, until one arrives on `link` (or FAILOVER_WAIT_MS passed). */
async function pollUntil(link, t0) {
  let tries = 0, last = '';
  while (Date.now() - t0 < FAILOVER_WAIT_MS) {
    tries++;
    const c = counters();
    const r = await through('GET', POLL, 10000);
    const d = since(c);
    if (r.ok && d[link.key].rx >= 0.9 * POLL) return { ok: true, ms: Date.now() - t0, tries, d };
    last = r.ok ? `arrived on ${d.a.rx >= d.b.rx ? 'A' : 'B'}` : r.error;
    await sleep(1000);
  }
  return { ok: false, ms: Date.now() - t0, tries, last };
}
async function linkUp(l) {
  run('ip', ['link', 'set', l.dev, 'up']);
  // a link that went down took its routes with it: the one to the server comes back with the link
  for (let i = 0; i < 15; i++) {
    const r = run('ip', ['route', 'replace', SRV_IP + '/32', 'via', l.gw, 'dev', l.dev, 'metric', String(l.metric)], { mayFail: true });
    if (r.status === 0) return;
    await sleep(200);
  }
  throw new Error(`the route to ${SRV_IP} over ${l.dev} did not come back`);
}

const speeds = {};

async function control(cfgs) {
  const label = 'control · multiWan off';
  await withClient(label, 'control', cfgs.off, async () => {
    const x = await parallelGets(PAR, EACH, 30000);
    speeds.control = x;
    gate(x.okN === PAR && x.d.a.rx >= 0.95 * x.pay && x.d.b.rx <= 0.02 * x.pay,
      `${label}: ${PAR} parallel downloads ride A alone, the link the OS picks`,
      `${x.okN}/${PAR} × ${mb(EACH)} in ${sec(x.ms)} (${mbit(x.pay, x.ms)}) — ${links(x.d)}${errs(x)}`);
  });
}

async function balance(cfgs) {
  const label = 'balance';
  await withClient(label, 'balance', cfgs.balance, async (cfg) => {
    await verdicts(cfg, label);
    const x = await parallelGets(PAR, EACH, 30000);
    const sum = x.d.a.rx + x.d.b.rx;
    const sa = sum ? x.d.a.rx / sum : 0, sb = sum ? x.d.b.rx / sum : 0;
    gate(x.okN === PAR && sum >= 0.95 * x.pay && Math.min(sa, sb) >= 0.2,
      `${label}: ${PAR} parallel downloads ride both links, each ≥ 20 % of the bytes`,
      `${x.okN}/${PAR} × ${mb(EACH)} in ${sec(x.ms)} (${mbit(x.pay, x.ms)}) — A ${pct(sa)}, B ${pct(sb)} — ${links(x.d)}${errs(x)}`);
    const one = speeds.control;
    if (one && one.okN === PAR) info(`${label}: the sum`, `${mbit(x.pay, x.ms)} over both against ${mbit(one.pay, one.ms)} on A alone (the control) — ${process.env.IRNF_MW_RATE_NOTE || ''}; not gated`);
  });
}

async function failover(cfgs) {
  const label = 'failover · primary B';
  await withClient(label, 'failover', cfgs.failover, async (cfg) => {
    await verdicts(cfg, label);
    let x = await parallelGets(2, EACH, 30000);
    gate(x.okN === 2 && x.d.b.rx >= 0.9 * x.pay && x.d.a.rx <= 0.05 * x.pay,
      `${label}: downloads ride the primary B, though the OS would pick A`,
      `${x.okN}/2 × ${mb(EACH)} — ${links(x.d)}${errs(x)}`);

    try {
      run('ip', ['link', 'set', B.dev, 'down']);
      const moved = await pollUntil(A, Date.now());
      if (!moved.ok) {
        gate(false, `${label}: B down → downloads succeed on A within ${FAILOVER_WAIT_MS / 1000} s`, `none did in ${moved.tries} tries — the last: ${moved.last}`);
      } else {
        x = await parallelGets(2, EACH, 30000);
        gate(x.okN === 2 && x.d.a.rx >= 0.9 * x.pay,
          `${label}: B down → downloads succeed on A`,
          `the first after ${sec(moved.ms)} (${moved.tries} tries), then ${x.okN}/2 × ${mb(EACH)} — ${links(x.d)}${errs(x)}`);
      }
    } finally {
      await linkUp(B);
    }

    const back = await pollUntil(B, Date.now());
    gate(back.ok, `${label}: B up again → downloads return to B within ${FAILOVER_WAIT_MS / 1000} s`,
      back.ok ? `after ${sec(back.ms)} (${back.tries} tries) — ${links(back.d)}` : `not in ${back.tries} tries — the last: ${back.last}`);
  });
}

async function split(cfgs, key, up, down) {
  const label = `split · up ${up.name}, down ${down.name}`;
  const why = (l) => (l === B ? ' (the OS would pick A)' : '');
  await withClient(label, key, cfgs[key], async () => {
    const c0 = counters();
    const u = await through('POST', SPLIT, 60000);
    let d = since(c0);
    gate(u.ok && d[up.key].tx >= 0.9 * SPLIT && d[down.key].tx <= 0.1 * SPLIT,
      `${label}: a ${mb(SPLIT)} upload leaves by ${up.name}${why(up)}`,
      `${u.ok ? `the page read ${mb(u.got)}` : u.error} in ${sec(u.ms)} (${mbit(SPLIT, u.ms)}) — ${links(d)}`);
    const c1 = counters();
    const g = await through('GET', SPLIT, 60000);
    d = since(c1);
    gate(g.ok && d[down.key].rx >= 0.9 * SPLIT && d[up.key].rx <= 0.1 * SPLIT,
      `${label}: a ${mb(SPLIT)} download arrives on ${down.name}${why(down)}`,
      `${g.ok ? mb(g.bytes) : g.error} in ${sec(g.ms)} (${mbit(SPLIT, g.ms)}) — ${links(d)}`);
  });
}

async function inside() {
  if (process.env.IRNF_MW_PROBE !== '1' || process.platform !== 'linux' || !process.getuid || process.getuid() !== 0 || !process.env.IRNF_MW_WORK) {
    console.error('probe-multiwan --inside: only as a child of the probe, inside its namespace');
    process.exit(2);
  }
  process.on('exit', killAll);
  process.on('SIGINT', () => { killAll(); process.exit(130); });
  process.on('SIGTERM', () => { killAll(); process.exit(143); });
  setTimeout(() => {
    console.log(`FAIL the probe ran out of time (${INNER_LIMIT_MS / 1000} s) — stopped`);
    for (const k of kids) console.log(tail(k, 20));
    killAll();
    process.exit(1);
  }, INNER_LIMIT_MS).unref();

  try {
    // the far side: the page, then the server core, both in mwsrv
    const page = spawnKid('page', 'ip', ['netns', 'exec', NS_SRV, process.execPath, __filename, '--serve', String(P.web)]);
    if (!await waitText(page, /^ready/m, 10000)) throw new Error(`the page never listened in ${NS_SRV}\n${tail(page, 10)}`);
    const sFile = path.join(process.env.IRNF_MW_WORK, 'server.json');
    fs.writeFileSync(sFile, JSON.stringify(serverConfig(), null, 1));
    const st = spawnSync(SERVER_XRAY, ['run', '-test', '-c', sFile], { encoding: 'utf8', timeout: 20000 });
    if (st.status !== 0) throw new Error('the core refused the server config — ' + lastLine(st));
    server = spawnKid('server', 'ip', ['netns', 'exec', NS_SRV, SERVER_XRAY, 'run', '-c', sFile]);
    for (const port of [P.tcp, P.xhttp]) {
      if (!await waitPort(SRV_IP, port, 10000)) throw new Error(`the server never listened on ${SRV_IP}:${port}\n${tail(server, 20)}\n${diag()}`);
    }

    // the topology, for the record
    const routes = String(run('ip', ['-4', 'route', 'show', 'to', SRV_IP], { mayFail: true }).stdout || '').trim().split('\n').join('; ');
    info('routes to the server', routes || '(none?)');
    for (const l of [A, B]) {
      const r = run('ping', ['-c', '1', '-W', '2', '-I', l.dev, SRV_IP], { mayFail: true });
      info(`link ${l.name} (${l.dev})`, r.error ? `(no ping here: ${r.error.code || r.error.message})`
        : r.status === 0 ? `reaches ${SRV_IP}` : `does not reach ${SRV_IP}: ${lastLine(r)}\n${diag()}`);
    }

    const cfgs = buildProbeConfigs();
    const off = JSON.stringify(cfgs.off), none = JSON.stringify(cfgs.none);
    let at = 0;
    while (at < off.length && off[at] === none[at]) at++;
    gate(off === none, 'multiWan off writes the very config of before, byte for byte',
      off === none ? '' : `they part at ${at}: …${off.slice(Math.max(0, at - 40), at + 60)}… against …${none.slice(Math.max(0, at - 40), at + 60)}…`);

    await control(cfgs);
    await balance(cfgs);
    await failover(cfgs);
    await split(cfgs, 'splitUpB', B, A);
    await split(cfgs, 'splitUpA', A, B);
  } catch (e) {
    gate(false, 'the probe', e.message);
    dumpLogs(null);
  }
  console.log(`\n${passed}/${passed + failed} gates passed — client ${versionOf(XRAY)}`);
  killAll();
  process.exit(failed ? 1 : 0);
}

if (require.main === module) {
  if (process.argv[2] === '--serve') serveMode();
  else if (process.argv[2] === '--inside') inside().catch((e) => { console.error(e); killAll(); process.exit(1); });
  else outside().catch((e) => { console.log(`FAIL ${e.message}`); teardown(); process.exit(1); });
}

module.exports = { buildProbeConfigs, probeServers, probeSettings, serverConfig, bindings, MW, A, B, SRV_IP, TARGET, P, APP_PORTS };
