#!/usr/bin/env node
'use strict';
/**
 * Smooth speed limits on the ROUTER (module `lanUsers`, v1.40 — the shaper,
 * src/modules/lanUsers/router/shaper.js): a device's cap met by QUEUING (tc,
 * HTB on the LAN bridge for its download, ingress + an IFB for its upload)
 * instead of the table's policing drops, and a user's priority under the line
 * speed. Whether the rate is met, how evenly, and whether a 'high' device
 * beats a 'low' one: what no command listing can say. The gates are what the
 * devices measure.
 *
 * Four network namespaces of their own, made here and removed whatever
 * happens — the runner's own network is never touched:
 *
 *   lsdeva  device A  02:1b:00:00:00:a1  10.44.0.11  fd44::11 ─┐
 *   lsdevb  device B  02:1b:00:00:00:b2  10.44.0.12  fd44::12 ─┤ lsbr 10.44.0.1/24 fd44::1/64 (the LAN bridge)
 *   lsrtr   the router: the shaper's tree on lsbr and ifb-lu,       │
 *           for the comparison the app's nft table (its policing),  │ its own page on 10.44.0.1
 *           lsw0 10.45.0.1/30 fd45::1 ══ lsw1 10.45.0.2 fd45::2 ─┐
 *   lsnet   the internet: a page on 10.45.0.2 and on fd45::2        ┘ 20 ms each way (netem) — a real
 *                                                                     line's round trip, which TCP's
 *                                                                     sawtooth under a policer needs to show
 *
 * The shaper is the module's own: createShaper({ run, lanIf: 'lsbr' }) with
 * a `run` that executes every command inside the router's namespace — the
 * same commands, in the same order, the router runs. A "page" here is this
 * script serving a TCP stream: a device asks it for N bytes (download), hands
 * it N bytes (upload — the page measures), or reads for a while (the priority
 * gate). Rates are bytes over the time from the first byte to the last;
 * evenness is the coefficient of variation of the bytes per SAMPLE_MS.
 *
 * Gates (PASS/FAIL, each with what was measured):
 *   tc       apply({ no line, A: 2000 kbit down and up }) answers mode 'tc';
 *            lsbr carries htb 1f1e: and the ingress, ifb-lu its htb, A's class and filters are there
 *   down     A downloads SIZE from the internet: within ±25 % of 2000 kbit
 *   up       A uploads SIZE to the internet: within ±25 %
 *   v6       A downloads SIZE over IPv6: within ±25 %
 *   router   A downloads from the router's own page: at least 4× the cap (its own replies are never shaped)
 *   free     B (no class, no line) downloads: at least 4× the cap (unclassified traffic is direct)
 *   police   the shaper stopped (nothing of ours left), the app's own table with the same rate on A
 *            (router/nft.js rates, through openwrtNet.buildNftRuleset): A's download measured again —
 *            the shaped download was smoother (a lower coefficient of variation); both printed
 *   prio     line 4000 kbit, A 'high' and B 'low', no caps: downloading together for PRIO_MS, A gets at
 *            least 1.5× B's bytes, and together they get the line (60–130 % of it)
 *   busy     another shaper's root on lsbr: mode 'police', busy 'root', nothing of theirs touched
 *   missing  a router without tc (the runner told the shaper so): mode 'police', tc-tiny named,
 *            kmod-ifb not (the runner has it), nothing of ours left
 *   clean    stop(): no 1f1e: and no ingress on lsbr, no ifb-lu
 * A failure prints the router's qdiscs, classes, filters and table. A hard
 * limit stops the run (HARD_LIMIT_MS).
 *
 * Runs only where it is meant to: Linux, root and IRNF_LS_PROBE=1 (CI).
 *   IRNF_PROBE_PORT   base port, default 24400 (never the app's own)
 */
const { spawn, spawnSync, execFile } = require('child_process');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');

const NS = { rtr: 'lsrtr', inet: 'lsnet', a: 'lsdeva', b: 'lsdevb' };
const LAN_IF = 'lsbr';
const IFB = 'ifb-lu';
const LAN = { ip: '10.44.0.1', ip6: 'fd44::1', mask: 24, mask6: 64 };
/** The two devices: their namespace, their end of the link (and the bridge port), a fixed MAC, fixed addresses. */
const DEV = {
  a: { key: 'a', name: 'A', ns: NS.a, dev: 'lsa0', port: 'lsa1', mac: '02:1b:00:00:00:a1', ip: '10.44.0.11', ip6: 'fd44::11' },
  b: { key: 'b', name: 'B', ns: NS.b, dev: 'lsb0', port: 'lsb1', mac: '02:1b:00:00:00:b2', ip: '10.44.0.12', ip6: 'fd44::12' }
};
const WAN = { dev: 'lsw0', peer: 'lsw1', ip: '10.45.0.1', ip6: 'fd45::1', peerIp: '10.45.0.2', peerIp6: 'fd45::2' };
const BASE = Number(process.env.IRNF_PROBE_PORT || 24400);
const P = { inet: BASE + 1, inet6: BASE + 2, router: BASE + 3 };
/** The app's own ports (the owner's IRNetFree runs on them) and the users' defaults: never these. */
const APP_PORTS = [10808, 10809, 10085, 30808, 30809, 30085, 30820, 30821, 30822];
const MIB = 1048576;
/** The cap under test, kbps; what a device moves under it (≈ 10 s); the line of the priority gate. */
const CAP_KBPS = 2000, SIZE = Math.round(2.5 * MIB), FREE_SIZE = 4 * MIB, LINE_KBPS = 4000;
/** How far from the cap a measured rate may be. */
const TOL = 0.25;
/** The WAN link's delay each way (netem): 40 ms round trip. */
const RTT_HALF_MS = 20;
const SAMPLE_MS = 200;
const PRIO_MS = 8000;
const HARD_LIMIT_MS = 240000;
const INNER_LIMIT_MS = HARD_LIMIT_MS - 15000;   // the gates stop first, with the listings; then the teardown
const MEASURE_TIMEOUT_MS = 60000;
const CHUNK = Buffer.alloc(65536, 0x2e);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const run = (cmd, args, opts = {}) => {
  const r = spawnSync(cmd, args, Object.assign({ encoding: 'utf8', timeout: 20000 }, opts));
  if (r.status !== 0 && !opts.mayFail) throw new Error(`${cmd} ${args.join(' ')}: ${((r.stderr || r.stdout || '') + (r.error ? r.error.message : '')).toString().trim()}`);
  return r;
};
const inNs = (ns, args, opts) => run('ip', ['netns', 'exec', ns, ...args], opts);
const lastLine = (r) => ((r.stdout || '') + (r.stderr || '') + (r.error ? r.error.message : '')).trim().split(/\r?\n/).slice(-1)[0] || '(no output)';

/* ------------------------------ what the router is given: the module's own shapes ------------------------------ */

/** plan.decide's `shape` for the cap gates: no line, A capped both ways. */
function shapeDesc() {
  return { line: { down: 0, up: 0 }, classes: [{ mac: DEV.a.mac, ips: [DEV.a.ip, DEV.a.ip6], down: CAP_KBPS, up: CAP_KBPS, prio: 'normal' }] };
}

/** The priority gate: a line, A 'high' and B 'low', no caps. */
function prioDesc() {
  return {
    line: { down: LINE_KBPS, up: LINE_KBPS },
    classes: [
      { mac: DEV.a.mac, ips: [DEV.a.ip, DEV.a.ip6], down: 0, up: 0, prio: 'high' },
      { mac: DEV.b.mac, ips: [DEV.b.ip, DEV.b.ip6], down: 0, up: 0, prio: 'low' }
    ]
  };
}

/** The app's own table with A policed at the cap (v1.39's way), as the gateway would load it — the comparison. */
function policeTable() {
  const onet = require('../src/main/openwrtNet');
  return onet.buildNftRuleset({
    lanIf: LAN_IF, macs: [],
    lanUsers: {
      unassigned: 'allow', blocked: [], allowed: [DEV.a.mac], authorized: [], direct: [], ipmac: [], counters: [],
      rates: [{ mac: DEV.a.mac, ips: [DEV.a.ip, DEV.a.ip6], down: CAP_KBPS, up: CAP_KBPS }], portal: null
    }
  });
}

/** A measurement's numbers: the rate in kbit/s and the evenness of its samples (coefficient of variation, the partial first and last left out). */
function stats(m) {
  const kbit = m && m.ms > 0 ? Math.round(m.bytes * 8 / m.ms) : 0;
  const s = Array.isArray(m && m.samples) ? m.samples.slice(1, -1) : [];
  if (s.length < 4) return { kbit, cv: null, n: s.length };
  const mean = s.reduce((a, b) => a + b, 0) / s.length;
  if (!(mean > 0)) return { kbit, cv: null, n: s.length };
  const sd = Math.sqrt(s.reduce((a, b) => a + (b - mean) * (b - mean), 0) / s.length);
  return { kbit, cv: Math.round(sd / mean * 1000) / 1000, n: s.length };
}
const within = (kbit, target, tol = TOL) => kbit >= target * (1 - tol) && kbit <= target * (1 + tol);

/* ------------------------------ the page: a TCP stream, measured ------------------------------ */

/** Bytes per SAMPLE_MS while they arrive: { feed(n), done() → { bytes, ms, samples } }. */
function sampler() {
  let t0 = 0, bytes = 0, cur = 0, timer = null;
  const samples = [];
  return {
    feed(n) {
      if (!t0) { t0 = Date.now(); timer = setInterval(() => { samples.push(cur); cur = 0; }, SAMPLE_MS); }
      bytes += n; cur += n;
    },
    done() {
      clearInterval(timer);
      if (t0) samples.push(cur);
      return { bytes, ms: t0 ? Date.now() - t0 : 0, samples };
    }
  };
}

/** Writes `total` bytes (Infinity: until the socket goes) with back-pressure, then ends. */
function pump(sock, total) {
  let sent = 0, gone = false;
  sock.on('error', () => { gone = true; });
  sock.on('close', () => { gone = true; });
  const more = () => {
    while (!gone && sent < total) {
      const n = Math.min(CHUNK.length, total - sent);
      sent += n;
      if (!sock.write(n === CHUNK.length ? CHUNK : CHUNK.subarray(0, n))) return;   // drain first
    }
    if (!gone && sent >= total) sock.end();
  };
  sock.on('drain', more);
  more();
}

/** `--serve <host> <port>`: SEND n → n bytes; TIME → bytes until the client leaves; RECV n → reads n bytes, answers the measurement. */
function serveMode() {
  const host = process.argv[3], port = Number(process.argv[4]);
  const srv = net.createServer((sock) => {
    sock.setNoDelay(true);
    let header = '', rest = null;
    sock.on('error', () => {});
    sock.on('data', (buf) => {
      if (rest) return rest(buf);
      header += buf.toString('latin1');
      const i = header.indexOf('\n');
      if (i < 0) return;
      const [cmd, argS] = header.slice(0, i).split(' ');
      const arg = Number(argS);
      const extra = Buffer.from(header.slice(i + 1), 'latin1');
      if (cmd === 'SEND') { rest = () => {}; pump(sock, arg); return; }
      if (cmd === 'TIME') { rest = () => {}; pump(sock, Infinity); return; }
      if (cmd !== 'RECV') { sock.destroy(); return; }
      const s = sampler();
      let got = 0, answered = false;
      const answer = () => { if (answered) return; answered = true; sock.end(JSON.stringify(s.done()) + '\n'); };
      rest = (b) => { s.feed(b.length); got += b.length; if (got >= arg) answer(); };
      sock.on('end', answer);
      if (extra.length) rest(extra);
    });
  });
  srv.on('error', (e) => { console.log(`FAIL page ${host}:${port}: ${e.message}`); process.exit(1); });
  srv.listen(port, host, () => console.log('ready'));
}

/** `--fetch <host> <port> <SEND|TIME|RECV> <n>`: the device's side; prints the measurement as JSON. */
function fetchMode() {
  const host = process.argv[3], port = Number(process.argv[4]), mode = process.argv[5], arg = Number(process.argv[6]);
  let said = false;
  const out = (o) => { if (said) return; said = true; process.stdout.write(JSON.stringify(o) + '\n'); process.exit(o.error ? 1 : 0); };
  const sock = net.connect({ host, port });
  sock.setNoDelay(true);
  sock.on('error', (e) => out({ error: e.message }));
  sock.on('connect', () => {
    sock.write(`${mode} ${arg}\n`);
    if (mode === 'RECV') {
      let reply = '';
      sock.on('data', (b) => { reply += b.toString(); });
      const done = () => { try { out(JSON.parse(reply.trim())); } catch { out({ error: 'no measurement from the page: ' + reply.slice(0, 80) }); } };
      sock.on('end', done);
      sock.on('close', done);
      pump(sock, arg);
      return;
    }
    const s = sampler();
    sock.on('data', (b) => s.feed(b.length));
    if (mode === 'TIME') setTimeout(() => { sock.destroy(); out(s.done()); }, arg);
    else { sock.on('end', () => out(s.done())); sock.on('close', () => out(s.done())); }
  });
}

/* ------------------------------ the namespaces ------------------------------ */

function preconditions() {
  const root = typeof process.getuid === 'function' && process.getuid() === 0;
  if (process.platform !== 'linux' || !root || process.env.IRNF_LS_PROBE !== '1') {
    console.error('probe-lan-shape: CI only — Linux, root and IRNF_LS_PROBE=1 (it makes network namespaces, a bridge, tc qdiscs and an nft table)');
    process.exit(2);
  }
  for (const [name, port] of Object.entries(P)) {
    if (APP_PORTS.includes(port)) { console.error(`probe-lan-shape: port ${port} (${name}) is the app's own`); process.exit(2); }
  }
  for (const tool of ['ip', 'tc', 'nft', 'sysctl']) {
    if (spawnSync(tool, tool === 'nft' ? ['--version'] : ['-V'], { encoding: 'utf8' }).error) { console.error(`probe-lan-shape: ${tool} is not on this runner`); process.exit(2); }
  }
}

function clearNet() {
  for (const ns of Object.values(NS)) run('ip', ['netns', 'del', ns], { mayFail: true });
  // only there when a run died between making a pair the old way and moving it (netUp's fallback)
  for (const l of [DEV.a.port, DEV.b.port, WAN.dev]) run('ip', ['link', 'del', l], { mayFail: true });
}

/** A veth pair, each end straight in its namespace; an older ip makes the pair here and moves it. */
function pair(dev, ns, peer, peerNs) {
  const made = run('ip', ['link', 'add', dev, 'netns', ns, 'type', 'veth', 'peer', 'name', peer, 'netns', peerNs], { mayFail: true });
  if (made.status === 0) return;
  run('ip', ['link', 'add', dev, 'type', 'veth', 'peer', 'name', peer]);
  run('ip', ['link', 'set', dev, 'netns', ns]);
  run('ip', ['link', 'set', peer, 'netns', peerNs]);
}

function netUp() {
  for (const ns of Object.values(NS)) {
    run('ip', ['netns', 'add', ns]);
    inNs(ns, ['ip', 'link', 'set', 'lo', 'up']);
    inNs(ns, ['sysctl', '-qw', 'net.ipv4.conf.all.rp_filter=0', 'net.ipv4.conf.default.rp_filter=0'], { mayFail: true });
  }
  // the router: the LAN bridge, forwarding both ways
  inNs(NS.rtr, ['ip', 'link', 'add', LAN_IF, 'type', 'bridge']);
  inNs(NS.rtr, ['ip', 'addr', 'add', `${LAN.ip}/${LAN.mask}`, 'dev', LAN_IF]);
  inNs(NS.rtr, ['ip', '-6', 'addr', 'add', `${LAN.ip6}/${LAN.mask6}`, 'dev', LAN_IF, 'nodad']);
  inNs(NS.rtr, ['ip', 'link', 'set', LAN_IF, 'up']);
  inNs(NS.rtr, ['sysctl', '-qw', 'net.ipv4.ip_forward=1', 'net.ipv6.conf.all.forwarding=1', 'net.ipv6.conf.default.forwarding=1']);
  // the devices on the bridge
  for (const d of [DEV.a, DEV.b]) {
    pair(d.dev, d.ns, d.port, NS.rtr);
    inNs(NS.rtr, ['ip', 'link', 'set', d.port, 'master', LAN_IF]);
    inNs(NS.rtr, ['ip', 'link', 'set', d.port, 'up']);
    inNs(d.ns, ['ip', 'link', 'set', d.dev, 'address', d.mac]);
    inNs(d.ns, ['ip', 'addr', 'add', `${d.ip}/${LAN.mask}`, 'dev', d.dev]);
    inNs(d.ns, ['ip', '-6', 'addr', 'add', `${d.ip6}/${LAN.mask6}`, 'dev', d.dev, 'nodad']);
    inNs(d.ns, ['ip', 'link', 'set', d.dev, 'up']);
    inNs(d.ns, ['ip', 'route', 'add', 'default', 'via', LAN.ip]);
    inNs(d.ns, ['ip', '-6', 'route', 'add', 'default', 'via', LAN.ip6]);
  }
  // the WAN link to the internet
  pair(WAN.dev, NS.rtr, WAN.peer, NS.inet);
  inNs(NS.rtr, ['ip', 'addr', 'add', `${WAN.ip}/30`, 'dev', WAN.dev]);
  inNs(NS.rtr, ['ip', '-6', 'addr', 'add', `${WAN.ip6}/64`, 'dev', WAN.dev, 'nodad']);
  inNs(NS.rtr, ['ip', 'link', 'set', WAN.dev, 'up']);
  inNs(NS.inet, ['ip', 'addr', 'add', `${WAN.peerIp}/30`, 'dev', WAN.peer]);
  inNs(NS.inet, ['ip', '-6', 'addr', 'add', `${WAN.peerIp6}/64`, 'dev', WAN.peer, 'nodad']);
  inNs(NS.inet, ['ip', 'link', 'set', WAN.peer, 'up']);
  inNs(NS.inet, ['ip', 'route', 'add', 'default', 'via', WAN.ip]);
  inNs(NS.inet, ['ip', '-6', 'route', 'add', 'default', 'via', WAN.ip6]);
}

/** The WAN link's round trip (netem each way, on the WAN ends — never the LAN device the shaper owns). */
function delayWan() {
  const ends = [[NS.rtr, WAN.dev], [NS.inet, WAN.peer]];
  for (const [ns, dev] of ends) {
    const r = inNs(ns, ['tc', 'qdisc', 'add', 'dev', dev, 'root', 'netem', 'delay', `${RTT_HALF_MS}ms`], { mayFail: true });
    if (r.status !== 0) return `no delay on the WAN link — tc refused netem on ${dev}: ${lastLine(r)} (the policing comparison may be less telling)`;
  }
  return `WAN round trip ${2 * RTT_HALF_MS} ms (netem)`;
}

/* ------------------------------ the run ------------------------------ */

const kids = [];
const S = { pages: [], shaperLog: [] };
let passed = 0, failed = 0;
let tornDown = false;

function gate(ok, name, detail) {
  if (ok) passed++; else failed++;
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name.padEnd(8)} ${detail}`);
  if (!ok) listings();
}
const info = (name, detail) => console.log(`info ${name.padEnd(8)} ${detail}`);

function listings() {
  for (const args of [['tc', 'qdisc', 'show', 'dev', LAN_IF], ['tc', '-s', 'class', 'show', 'dev', LAN_IF], ['tc', 'filter', 'show', 'dev', LAN_IF],
    ['tc', 'filter', 'show', 'dev', LAN_IF, 'ingress'], ['tc', '-s', 'qdisc', 'show', 'dev', IFB], ['tc', '-s', 'class', 'show', 'dev', IFB], ['nft', 'list', 'ruleset']]) {
    const r = inNs(NS.rtr, args, { mayFail: true });
    console.log(`      $ ${args.join(' ')}\n` + ((r.stdout || '') + (r.stderr || '')).trim().split('\n').map((l) => '        ' + l).join('\n'));
  }
  for (const l of S.shaperLog.slice(-6)) console.log(`      [shaper] ${l}`);
}

function spawnKid(name, cmd, args) {
  const k = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'] });
  k.name = name; k.out = '';
  k.stdout.on('data', (b) => { k.out += b.toString(); });
  k.stderr.on('data', (b) => { k.out += b.toString(); });
  k.on('error', (e) => { k.out += `\n${e.message}`; });
  kids.push(k);
  return k;
}
async function waitText(k, re, ms) {
  const until = Date.now() + ms;
  while (Date.now() < until) { if (re.test(k.out)) return true; if (k.exitCode != null) return false; await sleep(100); }
  return false;
}
function killAll() { for (const k of kids) { try { k.kill('SIGKILL'); } catch { /* gone */ } } }

/** The command runner the shaper gets: everything inside the router's namespace, the shape of tunPlatform.run. */
const nsRun = (ns) => (cmd, args, options = {}) => new Promise((resolve, reject) => {
  execFile('ip', ['netns', 'exec', ns, cmd, ...args], { timeout: options.timeout || 20000, maxBuffer: 4 << 20 }, (err, stdout, stderr) => {
    if (err) return reject(new Error((stderr || err.message).toString().trim()));
    resolve((stdout || '').toString());
  });
});

/** One measurement from a device's namespace: → { bytes, ms, samples } or { error }. */
function measure(dev, host, port, mode, arg) {
  return new Promise((resolve) => {
    execFile('ip', ['netns', 'exec', dev.ns, process.execPath, __filename, '--fetch', host, String(port), mode, String(arg)],
      { timeout: MEASURE_TIMEOUT_MS, maxBuffer: 1 << 20, encoding: 'utf8' }, (err, stdout, stderr) => {
        const line = String(stdout || '').trim().split('\n').filter(Boolean).slice(-1)[0] || '';
        try { const j = JSON.parse(line); return resolve(j); } catch { /* no JSON */ }
        resolve({ error: (err ? err.message : '') + ' ' + String(stderr || '').trim() + ' ' + line });
      });
  });
}
const describe = (m, st) => (m.error ? `error: ${m.error}` : `${st.kbit} kbit/s (${(m.bytes / MIB).toFixed(2)} MiB in ${(m.ms / 1000).toFixed(1)} s${st.cv == null ? '' : `, cv ${st.cv} over ${st.n} samples`})`);

/** The router's qdiscs, classes and filters as text, for the tree gates. */
const routerText = (args) => ((inNs(NS.rtr, args, { mayFail: true }).stdout) || '');

async function outside() {
  preconditions();
  clearNet();
  process.on('exit', teardown);
  process.on('SIGINT', () => { teardown(); process.exit(130); });
  process.on('SIGTERM', () => { teardown(); process.exit(143); });
  setTimeout(() => {
    console.log(`FAIL the probe ran out of time (${INNER_LIMIT_MS / 1000} s) — stopped`);
    listings();
    teardown();
    process.exit(1);
  }, INNER_LIMIT_MS).unref();

  const { createShaper } = require('../src/modules/lanUsers/router/shaper');
  const rtr = nsRun(NS.rtr);
  const log = (m, lvl) => { S.shaperLog.push(`${lvl || 'info'}: ${m}`); console.log(`      [shaper ${lvl || 'info'}] ${m}`); };
  let shaper = null;
  let shapedCv = null;
  try {
    netUp();
    info('network', delayWan());
    // the pages: two on the internet (v4, v6), one the router's own
    for (const [ns, host, port] of [[NS.inet, WAN.peerIp, P.inet], [NS.inet, WAN.peerIp6, P.inet6], [NS.rtr, LAN.ip, P.router]]) {
      const pg = spawnKid(`page ${host}:${port}`, 'ip', ['netns', 'exec', ns, process.execPath, __filename, '--serve', host, String(port)]);
      if (!await waitText(pg, /^ready/m, 10000)) throw new Error(`the page ${host}:${port} never listened in ${ns}\n${pg.out}`);
    }
    // the plumbing before any shaping: A reaches the internet both ways (a sanity check, not a gate)
    const plain = await measure(DEV.a, WAN.peerIp, P.inet, 'SEND', MIB);
    if (plain.error) throw new Error(`A cannot reach the internet page: ${plain.error}`);
    info('plain', `A unshaped: ${describe(plain, stats(plain))}`);

    shaper = createShaper({ run: rtr, log, lanIf: LAN_IF, ifb: IFB });

    // --- tc: the tree
    let r = await shaper.apply(shapeDesc());
    const q = routerText(['tc', 'qdisc', 'show', 'dev', LAN_IF]);
    const c = routerText(['tc', 'class', 'show', 'dev', LAN_IF]);
    const f = routerText(['tc', 'filter', 'show', 'dev', LAN_IF]);
    const qi = routerText(['tc', 'qdisc', 'show', 'dev', IFB]);
    const fi = routerText(['tc', 'filter', 'show', 'dev', IFB]);
    // `tc filter show` prints a u32 match in hex (10.44.0.11 → 0a2c000b/ffffffff) and the direct queue's
    // class (minor 0) as `flowid 1f1e:` — read them the way it writes them
    const hexOf = (ip) => ip.split('.').map((n) => Number(n).toString(16).padStart(2, '0')).join('') + '/ffffffff';
    const treeOk = r.mode === 'tc' && /htb 1f1e: root/.test(q) && /ingress ffff:/.test(q) && /class htb 1f1e:101 root/.test(c) && /htb 1f1e: root/.test(qi)
      && f.includes(hexOf(DEV.a.ip)) && fi.includes(hexOf(DEV.a.ip)) && /flowid 1f1e:101\b/.test(f) && /flowid 1f1e:(0)?(\s|$)/m.test(f);
    gate(treeOk, 'tc', `mode ${r.mode}${r.missing.length ? ` missing ${r.missing.join(',')}` : ''}${r.why ? ` (${r.why})` : ''}; ${LAN_IF}: ${q.split('\n').filter(Boolean).length} qdiscs, ${c.split('\n').filter(Boolean).length} classes; the router's own → direct`);
    if (!treeOk) throw new Error('no tree: the measurements would say nothing');

    // --- down / up / v6 / router / free
    let m = await measure(DEV.a, WAN.peerIp, P.inet, 'SEND', SIZE);
    let st = stats(m);
    shapedCv = st.cv;
    gate(!m.error && within(st.kbit, CAP_KBPS), 'down', `A ← internet: ${describe(m, st)}; cap ${CAP_KBPS} ±${TOL * 100} %`);
    m = await measure(DEV.a, WAN.peerIp, P.inet, 'RECV', SIZE);
    st = stats(m);
    gate(!m.error && within(st.kbit, CAP_KBPS), 'up', `A → internet: ${describe(m, st)}; cap ${CAP_KBPS} ±${TOL * 100} %`);
    m = await measure(DEV.a, WAN.peerIp6, P.inet6, 'SEND', SIZE);
    st = stats(m);
    gate(!m.error && within(st.kbit, CAP_KBPS), 'v6', `A ← internet over IPv6: ${describe(m, st)}; cap ${CAP_KBPS} ±${TOL * 100} %`);
    m = await measure(DEV.a, LAN.ip, P.router, 'SEND', FREE_SIZE);
    st = stats(m);
    gate(!m.error && st.kbit >= 4 * CAP_KBPS, 'router', `A ← the router's own page: ${describe(m, st)}; at least ${4 * CAP_KBPS} (never shaped)`);
    m = await measure(DEV.b, WAN.peerIp, P.inet, 'SEND', FREE_SIZE);
    st = stats(m);
    gate(!m.error && st.kbit >= 4 * CAP_KBPS, 'free', `B ← internet (no class, no line): ${describe(m, st)}; at least ${4 * CAP_KBPS} (direct)`);

    // --- police: the app's table instead, the same rate
    await shaper.stop();
    const gone = !/1f1e:/.test(routerText(['tc', 'qdisc', 'show', 'dev', LAN_IF])) && inNs(NS.rtr, ['ip', 'link', 'show', 'dev', IFB], { mayFail: true }).status !== 0;
    const tableFile = path.join(os.tmpdir(), `irnf-ls-police-${process.pid}.nft`);
    fs.writeFileSync(tableFile, policeTable());
    inNs(NS.rtr, ['nft', '-f', tableFile]);
    m = await measure(DEV.a, WAN.peerIp, P.inet, 'SEND', SIZE);
    st = stats(m);
    inNs(NS.rtr, ['nft', 'delete', 'table', 'inet', 'irnetfree'], { mayFail: true });
    try { fs.unlinkSync(tableFile); } catch { /* gone */ }
    const smoother = gone && !m.error && shapedCv != null && st.cv != null && shapedCv < st.cv;
    gate(smoother, 'police', `${gone ? 'nothing of ours left; ' : 'OUR TREE OUTLIVED stop(); '}A ← internet policed in the table: ${describe(m, st)} — shaped cv ${shapedCv} vs policed cv ${st.cv} (lower is smoother)`);

    // --- prio: a line, A high and B low, together
    r = await shaper.apply(prioDesc());
    const both = await Promise.all([measure(DEV.a, WAN.peerIp, P.inet, 'TIME', PRIO_MS), measure(DEV.b, WAN.peerIp, P.inet, 'TIME', PRIO_MS)]);
    const sa = stats(both[0]), sb = stats(both[1]);
    const sum = sa.kbit + sb.kbit;
    gate(r.mode === 'tc' && r.prio.down && !both[0].error && !both[1].error && sa.kbit >= 1.5 * sb.kbit && sum >= 0.6 * LINE_KBPS && sum <= 1.3 * LINE_KBPS, 'prio',
      `line ${LINE_KBPS}: A (high) ${sa.kbit} kbit/s, B (low) ${sb.kbit} kbit/s over ${PRIO_MS / 1000} s together — A ≥ 1.5× B, sum ${sum} within 60–130 % of the line; mode ${r.mode}, prio.down ${r.prio.down}`);

    // --- busy: someone else's root
    await shaper.stop();
    inNs(NS.rtr, ['tc', 'qdisc', 'add', 'dev', LAN_IF, 'root', 'handle', '1:', 'fq_codel']);
    r = await shaper.apply(shapeDesc());
    const still = /fq_codel 1: root/.test(routerText(['tc', 'qdisc', 'show', 'dev', LAN_IF]));
    await shaper.stop();
    const stillAfter = /fq_codel 1: root/.test(routerText(['tc', 'qdisc', 'show', 'dev', LAN_IF]));
    inNs(NS.rtr, ['tc', 'qdisc', 'del', 'dev', LAN_IF, 'root', 'handle', '1:'], { mayFail: true });
    gate(r.mode === 'police' && r.busy === 'root' && r.missing.length === 0 && still && stillAfter, 'busy', `another root on ${LAN_IF}: mode ${r.mode}, busy ${r.busy}, missing [${r.missing.join(',')}], theirs untouched ${still && stillAfter}; ${r.why || ''}`);

    // --- missing: a router without tc
    const noTc = createShaper({ run: (cmd, args, o) => (cmd === 'tc' ? Promise.reject(new Error('spawn tc ENOENT')) : rtr(cmd, args, o)), log, lanIf: LAN_IF, ifb: IFB });
    r = await noTc.apply(shapeDesc());
    const noIfb = inNs(NS.rtr, ['ip', 'link', 'show', 'dev', IFB], { mayFail: true }).status !== 0;
    gate(r.mode === 'police' && r.missing.includes('tc-tiny') && !r.missing.includes('kmod-ifb') && noIfb, 'missing', `no tc: mode ${r.mode}, missing [${r.missing.join(', ')}], no ${IFB} left ${noIfb}`);

    // --- clean
    await shaper.apply(shapeDesc());
    await shaper.stop();
    const qq = routerText(['tc', 'qdisc', 'show', 'dev', LAN_IF]);
    const clean = !/1f1e:/.test(qq) && !/ingress/.test(qq) && inNs(NS.rtr, ['ip', 'link', 'show', 'dev', IFB], { mayFail: true }).status !== 0;
    gate(clean, 'clean', `after stop(): ${LAN_IF} carries ${qq.trim().split('\n').filter(Boolean).join(' | ') || 'nothing'}; ${IFB} ${clean ? 'gone' : 'STILL THERE'}`);
  } catch (e) {
    gate(false, 'the probe', e.message);
  }
  try { if (shaper) await shaper.stop(); } catch { /* down anyway */ }
  console.log(`\n${passed}/${passed + failed} gates passed — ${os.release()}, tc: ${(spawnSync('tc', ['-V'], { encoding: 'utf8' }).stdout || '').trim()}`);
  killAll();
  teardown();
  process.exit(failed ? 1 : 0);
}

function teardown() {
  if (tornDown) return;
  tornDown = true;
  killAll();
  clearNet();
}

if (require.main === module) {
  if (process.argv[2] === '--serve') serveMode();
  else if (process.argv[2] === '--fetch') fetchMode();
  else outside().catch((e) => { console.log(`FAIL ${e.message}`); teardown(); process.exit(1); });
}

module.exports = { shapeDesc, prioDesc, policeTable, stats, within, P, BASE, APP_PORTS, NS, DEV, LAN, LAN_IF, IFB, WAN, CAP_KBPS, LINE_KBPS, TOL, SIZE, SAMPLE_MS };
