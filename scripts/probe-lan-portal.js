#!/usr/bin/env node
'use strict';
/**
 * LAN users on the ROUTER, transparent mode (module `lanUsers`, the
 * contract's section B, "Router transparent mode"): every device behind the
 * router rides the config of the user it belongs to — no proxy settings on the
 * device. Which server a device's bytes reached, whether an unknown device
 * sees the login page and nothing else, whether a blocked or capped one gets
 * nothing: what no config check can say. The gates are what a device sees.
 *
 * Five network namespaces of their own, made here and removed whatever
 * happens — the runner's own network is never touched:
 *
 *   lpdeva  device A  02:1a:00:00:00:a1  192.168.77.11 ─┐
 *   lpdevb  device B  02:1a:00:00:00:b2  192.168.77.12 ─┤ br-lan 192.168.77.1/24
 *   lpdevc  device C  02:1a:00:00:00:c3  (no address  ─┤
 *           until it takes A's, in the spoof gates)     │
 *   lprtr   the router: the app's nft table, sing-box TUN (TunOpenwrt), Xray
 *           (buildConfig), the login portal on 192.168.77.1, a DNS on :53
 *           lpw0 10.31.0.1/30 ══ lpw1 10.31.0.2 ─┐
 *   lpnet   the internet: 10.32.0.1 (on lo)       ┘ S0, S1, S2 (VLESS/TCP), each
 *           handing every flow to a page that names it («S0», «S1», «S2»)
 *
 * A device asks http://198.51.100.7/ (port 80) and :8080 — a documentation
 * address, outside the builder's private bypass — and the page's answer says
 * which server carried it: S0 is the router's own connection (the default),
 * S1 alice's, S2 bob's.
 *
 * The router is the app's own, composed as the router service does it
 * (src/server/service.js): the Xray config from buildConfig({ mode: 'single',
 * server: S0 }, settings) with settings.tunMode, modules.lanUsers and
 * lanUsers (the store, contract B, as the service hands it to the build —
 * the users' target records and the transparent inbounds `tp` with it); the
 * gateway a TunOpenwrt (tunOpenwrt.js → openwrtNet.buildNftRuleset,
 * tunSingbox.buildTunConfig) started with the router's options plus
 * `lanUsers: { nft, singbox }`; the portal from router/portal.js. What the
 * service and the module's controller do around them — the devices on the LAN,
 * who each one is, a sign-in, a block, the meter and a user over its cap — is
 * this probe's ROUTER GLUE section, composed from the module's own exports:
 * the one place to keep in step with them (and with router/index.js, the
 * controller, once it is there). Nothing in what the builders wrote is changed.
 *
 * Gates (PASS/FAIL, each with what the device got):
 *   off       module off: the Xray config, the nft table and the sing-box
 *             config are those of before, byte for byte; A and B both ride S0
 *   assigned  A (→ alice) rides S1, on :80 and :8080
 *   captive   B (nobody's): http gets the login page, :8080 gets nothing, the
 *             router's DNS still answers; a wrong password leaves it there
 *   login     after POST /login as bob, B rides S2 (within 25 s)
 *   blocked   A blocked: nothing on :80 or :8080 (not even the login page),
 *             B untouched; unblocked, A rides S1 again (within 15 s)
 *   spoof     the kernel takes the module's pins of both families (nft -c);
 *             C — bob's own device, let through by its MAC — takes A's
 *             address while A is away: nothing it sends gets through (the
 *             pin rule's counter dropped it), not alice's S1, and the address
 *             is in no rule-set of bob's; A, back on its address, rides S1
 *             again (within 15 s)
 *   cap       A's per-device counter counts its 4 MiB download (≥ 90 %), the
 *             meter makes alice over her cap (≈ 2 MiB) → A rides no server:
 *             :8080 gets nothing, :80 nothing or the portal saying why; B untouched
 *   off again module off once more, with a device the portal bound and a
 *             user over its cap in the store: the same tables of before, and
 *             A and B ride S0, no login page
 * A piece of the module that is not there yet is named (and listed at the
 * end); the logs of the router's cores, the gateway, the nft table and the
 * rules follow a failure. A hard limit stops the run (HARD_LIMIT_MS).
 *
 * Runs only where it is meant to: Linux, root and IRNF_LP_PROBE=1 (CI).
 *   IRNF_XRAY_EXE     the router's core (default bin/xray)
 *   IRNF_HOP_EXE      the servers' core (default: the router's core)
 *   IRNF_SINGBOX_EXE  the gateway's sing-box (a file named sing-box)
 *   IRNF_PROBE_PORT   base port, default 23800 (never the app's own)
 */
const { spawn, spawnSync } = require('child_process');
const dgram = require('dgram');
const fs = require('fs');
const http = require('http');
const net = require('net');
const os = require('os');
const path = require('path');
const { normalizeMac } = require('../src/main/openwrtNet');

const NS = { rtr: 'lprtr', inet: 'lpnet', a: 'lpdeva', b: 'lpdevb', c: 'lpdevc' };
const LAN_IF = 'br-lan';
const LAN_IP = '192.168.77.1', LAN_MASK = 24;
/** The two devices: their namespace, their end of the link (and the router's), a fixed MAC, a fixed address. */
const DEV = {
  a: { key: 'a', name: 'A', ns: NS.a, dev: 'lpa0', port: 'lpa1', mac: '02:1a:00:00:00:a1', ip: '192.168.77.11', host: 'phone-a' },
  b: { key: 'b', name: 'B', ns: NS.b, dev: 'lpb0', port: 'lpb1', mac: '02:1a:00:00:00:b2', ip: '192.168.77.12', host: 'laptop-b' }
};
/**
 * The spoofer: on the bridge from the start with its own MAC but no address
 * and no lease (so no other gate meets it), until the spoof gates give it A's.
 */
const SPOOF = { key: 'c', name: 'C', ns: NS.c, dev: 'lpc0', port: 'lpc1', mac: '02:1a:00:00:00:c3', ip: DEV.a.ip, host: 'spoofer-c' };
const WAN = { dev: 'lpw0', peer: 'lpw1', ip: '10.31.0.1', gw: '10.31.0.2' };
const SRV_IP = '10.32.0.1';
const TARGET = '198.51.100.7';
const UUID = '7d2f0c3b-1e4a-4b6d-9c8e-0a1b2c3d4e5f';
const BASE = Number(process.env.IRNF_PROBE_PORT || 23800);
const P = {
  socks: BASE + 1, http: BASE + 2, api: BASE + 3, luSocks: BASE + 5, luHttp: BASE + 6, portal: BASE + 10,
  // free loopback ports for the per-target SOCKS inbounds (lu-tp-<n>), as the service would pick them
  tp: [20, 21, 22, 23, 24, 25, 26, 27].map((k) => BASE + k),
  s0: BASE + 31, s1: BASE + 32, s2: BASE + 33, page0: BASE + 41, page1: BASE + 42, page2: BASE + 43
};
/** The app's own ports (the owner's IRNetFree runs on them) and the users' defaults (contract B): never these. */
const APP_PORTS = [10808, 10809, 10085, 30808, 30809, 30085, 30820, 30821, 30822];
const MIB = 1048576;
/** alice's cap: 0.002 GB (≈ 2 MiB, the app's GB being binary); A then downloads PUSH. */
const CAP_GB = 0.002, PUSH = 4 * MIB;
const HARD_LIMIT_MS = 270000;
const INNER_LIMIT_MS = HARD_LIMIT_MS - 15000;   // the gates stop first, with the logs; then the teardown
const exeName = (n) => (process.platform === 'win32' ? n + '.exe' : n);
const XRAY = process.env.IRNF_XRAY_EXE || path.join(__dirname, '..', 'bin', exeName('xray'));
const SERVER_XRAY = process.env.IRNF_HOP_EXE || XRAY;
const SINGBOX = process.env.IRNF_SINGBOX_EXE || path.join(__dirname, '..', 'bin', exeName('sing-box'));
const LEASES = '/tmp/dhcp.leases';
const MOD = path.join(__dirname, '..', 'src', 'modules', 'lanUsers');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const run = (cmd, args, opts = {}) => {
  const r = spawnSync(cmd, args, Object.assign({ encoding: 'utf8', timeout: 20000 }, opts));
  if (r.status !== 0 && !opts.mayFail) throw new Error(`${cmd} ${args.join(' ')}: ${((r.stderr || r.stdout || '') + (r.error ? r.error.message : '')).toString().trim()}`);
  return r;
};
const inNs = (ns, args, opts) => run('ip', ['netns', 'exec', ns, ...args], opts);
const lastLine = (r) => ((r.stdout || '') + (r.stderr || '') + (r.error ? r.error.message : '')).trim().split(/\r?\n/).slice(-1)[0] || '(no output)';
const versionOf = (exe, re) => {
  const out = (spawnSync(exe, ['version'], { encoding: 'utf8', timeout: 20000 }).stdout || '');
  return re ? ((re.exec(out) || [])[1] || '') : (out.split(/\r?\n/)[0] || `(no version from ${exe})`);
};

/* ------------------------------ what the router is given: the app's own ------------------------------ */

/** The three servers as the app keeps them, parsed from links (ids fixed, so users can name them). */
function probeServers() {
  const { parseLink } = require('../src/main/parser');
  const one = (key, port) => Object.assign(parseLink(`vless://${UUID}@${SRV_IP}:${port}?type=tcp&security=none&encryption=none#${key.toUpperCase()}`), { id: 'srv-' + key });
  return { s0: one('s0', P.s0), s1: one('s1', P.s1), s2: one('s2', P.s2) };
}

/** One user, every key of the contract's shape. */
function user(id, username, password, target, over) {
  return Object.assign({ id, username, password, name: username, target, quotaGb: 0, quotaPeriod: 'none', expiresAt: 0, maxDevices: 0, enabled: true }, over || {});
}

/**
 * store.lanUsers (contract B): transparent mode on, unassigned devices get the
 * login page; the proxy accounts off (transparent mode must not need them).
 * alice owns device A and has a daily cap of CAP_GB; bob has no device yet.
 */
function probeLanUsers() {
  return {
    config: {
      proxy: { enabled: false, port: P.luSocks, httpPort: P.luHttp },
      transparent: { enabled: true, unassigned: 'login', sessionHours: 24, portalPort: P.portal }
    },
    users: [
      user('usr-alice', 'alice', 'alice-pw-1', 'srv-s1', { quotaGb: CAP_GB, quotaPeriod: 'day' }),
      user('usr-bob', 'bob', 'bob-pw-2', 'srv-s2')
    ],
    devices: [{ mac: DEV.a.mac, name: DEV.a.host, userId: 'usr-alice', blocked: false }]
  };
}

/** The connection plan main.js builds for a selected server: the router's own connection S0 (it carries no other record). */
function routerPlan(servers) {
  return { mode: 'single', server: servers.s0 };
}
const byIdOf = (servers) => Object.fromEntries(Object.values(servers).map((s) => [s.id, s]));

/**
 * settings.lanUsers as the service hands it to the build (USERS-CORE's
 * xray.js header, ipc.js forBuild): the store's record, who is over their cap,
 * the moment, the LAN address, the records the users' targets name (a single
 * plan carries none), and the router's transparent inbounds `tp`.
 */
function forBuild(lu, { tp = [], over = [], servers }) {
  return Object.assign({}, lu, {
    over, now: Date.now(), listen: LAN_IP, serversById: byIdOf(servers), chainsById: {},
    tp: tp.map(({ tag, port, target }) => ({ tag, port, target }))
  });
}

/** The settings service.js would pass on a router (tests/fixtures), on this probe's ports. */
function routerSettings(on, lu) {
  const F = require('../tests/fixtures');
  return F.settings({
    socksPort: P.socks, httpPort: P.http, apiPort: P.api, tunMode: true, directInterface: WAN.dev,
    routingMode: 'global', blockAds: false, geoAssets: false, enableSniffing: false, dnsManaged: false, logLevel: 'info',
    modules: { lanUsers: !!on }, lanUsers: lu
  });
}

/** The transparent inbounds for the probe's users, as plan.routedTargets numbers them (its targets, sorted). */
const pureTp = (lu) => [...new Set(lu.users.map((u) => u.target).filter((t) => !['', 'direct', 'block'].includes(t)))].sort()
  .map((target, n) => ({ tag: `lu-tp-${n}`, port: P.tp[n], target }));

/** The pure part, which `npm test` can build: the router's Xray config with the module on, off (the users' data all there), and as before. */
function buildPureConfigs() {
  const { buildConfig } = require('../src/main/configBuilder');
  const servers = probeServers();
  const lu = probeLanUsers();
  const fb = forBuild(lu, { tp: pureTp(lu), servers });
  const before = routerSettings(false, undefined);
  delete before.modules;
  delete before.lanUsers;
  return {
    servers, lu, fb,
    on: buildConfig(routerPlan(servers), routerSettings(true, fb)),
    off: buildConfig(routerPlan(servers), routerSettings(false, fb)),
    before: buildConfig(routerPlan(servers), before)
  };
}

/** The per-target SOCKS inbounds the builder wrote for transparent mode (`lu-tp-<n>`). */
const tpInbounds = (cfg) => ((cfg && cfg.inbounds) || []).filter((i) => i && /^lu-tp-/.test(String(i.tag || '')));
/** sing-box's per-device rules: by source MAC or address, or by a rule-set whose outbound is a transparent inbound. */
const deviceRules = (sb) => (((sb && sb.route) || {}).rules || []).filter((r) => r && (r.source_mac_address || r.source_ip_cidr || (r.rule_set && /^lu-tp-/.test(String(r.outbound || '')))));

/**
 * What the router's nft table counts per device: for each MAC, every counter
 * that names it or its address — a rule matching it (`ether saddr`, `ip daddr`
 * …) with a counter, a set element with its own counter, or a named counter
 * whose name or comment carries it (aa:bb:…, aa_bb_…, aabb…). From `nft -j
 * list table`. → { [mac]: { bytes, from: [where] } }
 */
function macBytes(j, devices) {
  const out = {};
  const forms = (d) => {
    const hex = d.mac.replace(/:/g, '');
    return [d.mac, d.mac.replace(/:/g, '_'), d.mac.replace(/:/g, '-'), hex];
  };
  const mentions = (text, d) => forms(d).some((f) => text.includes(f)) || new RegExp(`(^|[^0-9.])${d.ip.replace(/\./g, '\\.')}($|[^0-9])`).test(text);
  const add = (d, bytes, from) => {
    const o = out[d.mac] || (out[d.mac] = { bytes: 0, from: [] });
    o.bytes += bytes;
    o.from.push(`${from} ${bytes}`);
  };
  for (const item of (j && j.nftables) || []) {
    if (item.counter && typeof item.counter.bytes === 'number') {
      const text = `${item.counter.name || ''} ${item.counter.comment || ''}`.toLowerCase();
      for (const d of devices) if (mentions(text, d)) add(d, item.counter.bytes, `counter ${item.counter.name}`);
    }
    if (item.rule && Array.isArray(item.rule.expr)) {
      const ctr = item.rule.expr.find((e) => e && e.counter && typeof e.counter === 'object' && typeof e.counter.bytes === 'number');
      if (!ctr) continue;
      const text = JSON.stringify(item.rule.expr.filter((e) => e && e.match)).toLowerCase();
      for (const d of devices) if (mentions(text, d)) add(d, ctr.counter.bytes, `rule ${item.rule.chain}#${item.rule.handle}`);
    }
    if (item.set && Array.isArray(item.set.elem)) {
      for (const el of item.set.elem) {
        const e = el && el.elem;
        if (!e || !e.counter || typeof e.counter.bytes !== 'number') continue;
        const text = JSON.stringify(e.val).toLowerCase();
        for (const d of devices) if (mentions(text, d)) add(d, e.counter.bytes, `set ${item.set.name}`);
      }
    }
  }
  return out;
}

/** The table's sets, by name → their elements (as text). */
function nftSets(j) {
  const out = {};
  for (const item of (j && j.nftables) || []) {
    if (!item.set) continue;
    out[item.set.name] = (item.set.elem || []).map((el) => JSON.stringify(el && el.elem ? el.elem.val : el).replace(/"/g, ''));
  }
  return out;
}

/**
 * What the pin rules dropped — the rules that name `lu_ipmac4` / `lu_ipmac6`
 * (router/nft.js: a pinned address from a MAC that is not its own), from
 * `nft -j list table`: { packets, bytes, rules } (rules: how many were found).
 */
function pinDrops(j) {
  const out = { packets: 0, bytes: 0, rules: 0 };
  for (const item of (j && j.nftables) || []) {
    const r = item && item.rule;
    if (!r || !Array.isArray(r.expr) || !/@lu_ipmac[46]\b/.test(JSON.stringify(r.expr))) continue;
    out.rules++;
    const c = r.expr.find((e) => e && e.counter && typeof e.counter === 'object');
    if (c) { out.packets += Number(c.counter.packets) || 0; out.bytes += Number(c.counter.bytes) || 0; }
  }
  return out;
}

/* ------------------------------ the far side and the devices' tools (children) ------------------------------ */

/** --serve <port> <name>: a page that says its name; /big?n= sends n bytes. In lpnet. */
function serveMode() {
  const port = Number(process.argv[3]);
  const name = String(process.argv[4] || '?');
  const chunk = Buffer.alloc(64 * 1024, 0x61);
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://page');
    if (u.pathname === '/big') {
      let left = Math.max(0, Math.min(Number(u.searchParams.get('n')) || 0, 64 * MIB));
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
    res.writeHead(200, { 'Content-Type': 'text/plain', 'Content-Length': name.length });
    res.end(name);
  });
  srv.listen(port, '127.0.0.1', () => console.log('ready ' + port));
}

/**
 * --fetch <json>: one HTTP/1.1 request from a device — { host, port, path,
 * method, body, timeoutMs } — answered as one JSON line: { ok: an HTTP answer
 * came, status, location, body (up to 16 KB; none for /big), bytes, ms } or
 * { ok: false, error }.
 */
function fetchMode() {
  const q = JSON.parse(process.argv[3]);
  const t0 = Date.now();
  const keepBody = !String(q.path || '/').startsWith('/big');
  const s = net.connect({ host: q.host, port: q.port || 80 });
  let buf = Buffer.alloc(0), head = null, bytes = 0, body = '', done = false;
  const out = (r) => {
    if (done) return;
    done = true;
    clearTimeout(timer);
    s.destroy();
    process.stdout.write(JSON.stringify(Object.assign({ ms: Date.now() - t0 }, r)) + '\n');
  };
  const answer = () => out({ ok: true, status: head.status, location: head.location, body, bytes });
  const timer = setTimeout(() => out(head ? Object.assign({ ok: true, status: head.status, location: head.location, body, bytes, cut: 'timeout' }) : { ok: false, error: 'no answer in ' + (q.timeoutMs || 5000) + ' ms' }), q.timeoutMs || 5000);
  s.on('connect', () => {
    const b = Buffer.from(q.body || '');
    const port = q.port && q.port !== 80 ? ':' + q.port : '';
    s.write(`${q.method || 'GET'} ${q.path || '/'} HTTP/1.1\r\nHost: ${q.host}${port}\r\nUser-Agent: irnf-probe\r\nConnection: close\r\n` +
      (q.method === 'POST' ? `Content-Type: application/x-www-form-urlencoded\r\nContent-Length: ${b.length}\r\n` : '') + '\r\n');
    if (b.length) s.write(b);
  });
  const take = (d) => {
    bytes += d.length;
    if (keepBody && body.length < 16384) body += d.toString('utf8');
    if (head && head.length >= 0 && bytes >= head.length) answer();
  };
  s.on('data', (d) => {
    if (head) return take(d);
    buf = Buffer.concat([buf, d]);
    const i = buf.indexOf('\r\n\r\n');
    if (i < 0) return;
    const text = buf.subarray(0, i).toString('latin1');
    const len = /\r\ncontent-length:\s*(\d+)/i.exec(text);
    head = { status: Number((/^HTTP\/1\.[01] (\d{3})/.exec(text) || [])[1]) || 0, location: ((/\r\nlocation:\s*([^\r\n]+)/i.exec(text) || [])[1] || '').trim(), length: len ? Number(len[1]) : -1 };
    const rest = buf.subarray(i + 4);
    buf = Buffer.alloc(0);
    if (rest.length) take(rest);
    else if (head.length === 0) answer();
  });
  s.on('error', (e) => out({ ok: false, error: e.code || e.message }));
  s.on('close', () => (head ? answer() : out({ ok: false, error: 'closed with no HTTP answer' })));
}

/* ------------------------------ the namespaces (the parent, in the root namespace) ------------------------------ */

function preconditions() {
  if (process.env.IRNF_LP_PROBE !== '1' || process.platform !== 'linux' || !process.getuid || process.getuid() !== 0) {
    console.error('probe-lan-portal: CI only — Linux, root and IRNF_LP_PROBE=1 (it makes network namespaces, a bridge, a TUN and nft tables)');
    process.exit(2);
  }
  for (const [k, exe] of [['IRNF_XRAY_EXE', XRAY], ['IRNF_HOP_EXE', SERVER_XRAY], ['IRNF_SINGBOX_EXE', SINGBOX]]) {
    if (!fs.existsSync(exe)) { console.error(`probe-lan-portal: ${k}: no core at ${exe}`); process.exit(2); }
  }
  // TunSingbox finds its binary by name in the dirs it is given
  if (path.basename(SINGBOX) !== 'sing-box') { console.error(`probe-lan-portal: IRNF_SINGBOX_EXE must be a file named sing-box (${SINGBOX})`); process.exit(2); }
  for (const tool of ['ip', 'nft']) {
    if (run('sh', ['-c', `command -v ${tool}`], { mayFail: true }).status !== 0) { console.error(`probe-lan-portal: no ${tool} on this machine`); process.exit(2); }
  }
  const all = [].concat(...Object.values(P));
  const own = all.filter((p) => APP_PORTS.includes(p));
  if (own.length) { console.error(`probe-lan-portal: IRNF_PROBE_PORT=${BASE} lands on the app's own port ${own.join(', ')}`); process.exit(2); }
}

/** Everything this probe made, gone: the processes in its namespaces, the namespaces (their links with them). Safe to repeat. */
function clearNet() {
  for (const ns of Object.values(NS)) {
    const pids = String(run('ip', ['netns', 'pids', ns], { mayFail: true }).stdout || '').split(/\s+/).filter(Boolean);
    for (const pid of pids) { try { process.kill(Number(pid), 'SIGKILL'); } catch { /* gone */ } }
    run('ip', ['netns', 'del', ns], { mayFail: true });
  }
  // only there when a run died between making a pair the old way and moving it (pair()'s fallback)
  for (const l of [WAN.dev, DEV.a.dev, DEV.b.dev, SPOOF.dev]) run('ip', ['link', 'del', l], { mayFail: true });
}

/** A veth pair with one end in each namespace; an older ip makes it here and moves the ends. */
function pair(a, nsA, b, nsB) {
  const made = run('ip', ['link', 'add', a, 'netns', nsA, 'type', 'veth', 'peer', 'name', b, 'netns', nsB], { mayFail: true });
  if (made.status === 0) return;
  run('ip', ['link', 'add', a, 'type', 'veth', 'peer', 'name', b]);
  run('ip', ['link', 'set', a, 'netns', nsA]);
  run('ip', ['link', 'set', b, 'netns', nsB]);
}

function netUp() {
  for (const ns of Object.values(NS)) {
    run('ip', ['netns', 'add', ns]);
    inNs(ns, ['ip', 'link', 'set', 'lo', 'up']);
    // inside the namespaces only: no reverse-path filter (the TUN hands replies back from addresses
    // the main table routes elsewhere)
    inNs(ns, ['sysctl', '-qw', 'net.ipv4.conf.all.rp_filter=0', 'net.ipv4.conf.default.rp_filter=0'], { mayFail: true });
  }
  // no IPv6 chatter from the devices and the internet side (the router keeps it: sing-box's TUN has a v6 address)
  for (const ns of [NS.a, NS.b, NS.c, NS.inet]) inNs(ns, ['sysctl', '-qw', 'net.ipv6.conf.all.disable_ipv6=1', 'net.ipv6.conf.default.disable_ipv6=1'], { mayFail: true });
  inNs(NS.rtr, ['sysctl', '-qw', 'net.ipv4.ip_forward=1']);

  // the WAN: the router's default route, the internet's address on its loopback
  pair(WAN.dev, NS.rtr, WAN.peer, NS.inet);
  inNs(NS.rtr, ['ip', 'addr', 'add', WAN.ip + '/30', 'dev', WAN.dev]);
  inNs(NS.rtr, ['ip', 'link', 'set', WAN.dev, 'up']);
  inNs(NS.inet, ['ip', 'addr', 'add', WAN.gw + '/30', 'dev', WAN.peer]);
  inNs(NS.inet, ['ip', 'link', 'set', WAN.peer, 'up']);
  inNs(NS.inet, ['ip', 'addr', 'add', SRV_IP + '/32', 'dev', 'lo']);
  inNs(NS.rtr, ['ip', 'route', 'add', 'default', 'via', WAN.gw, 'dev', WAN.dev]);

  // the LAN: a bridge, a device on each port, with its fixed MAC and address
  if (inNs(NS.rtr, ['ip', 'link', 'add', LAN_IF, 'type', 'bridge', 'forward_delay', '0'], { mayFail: true }).status !== 0) {
    inNs(NS.rtr, ['ip', 'link', 'add', LAN_IF, 'type', 'bridge']);
  }
  inNs(NS.rtr, ['ip', 'addr', 'add', `${LAN_IP}/${LAN_MASK}`, 'dev', LAN_IF]);
  inNs(NS.rtr, ['ip', 'link', 'set', LAN_IF, 'up']);
  for (const d of Object.values(DEV)) {
    pair(d.dev, d.ns, d.port, NS.rtr);
    inNs(d.ns, ['ip', 'link', 'set', d.dev, 'address', d.mac]);
    inNs(d.ns, ['ip', 'addr', 'add', `${d.ip}/${LAN_MASK}`, 'dev', d.dev]);
    inNs(d.ns, ['ip', 'link', 'set', d.dev, 'up']);
    inNs(d.ns, ['ip', 'route', 'add', 'default', 'via', LAN_IP]);
    inNs(NS.rtr, ['ip', 'link', 'set', d.port, 'master', LAN_IF]);
    inNs(NS.rtr, ['ip', 'link', 'set', d.port, 'up']);
  }
  // the spoofer: on the bridge with its own MAC, silent — no address (and no v6) until the spoof gates
  pair(SPOOF.dev, SPOOF.ns, SPOOF.port, NS.rtr);
  inNs(SPOOF.ns, ['ip', 'link', 'set', SPOOF.dev, 'address', SPOOF.mac]);
  inNs(SPOOF.ns, ['ip', 'link', 'set', SPOOF.dev, 'up']);
  inNs(NS.rtr, ['ip', 'link', 'set', SPOOF.port, 'master', LAN_IF]);
  inNs(NS.rtr, ['ip', 'link', 'set', SPOOF.port, 'up']);
  // each device says hello, so the router's neighbour table knows its MAC (the portal reads it there)
  for (const d of Object.values(DEV)) {
    for (let i = 0; i < 10; i++) {
      if (inNs(d.ns, ['ping', '-c', '1', '-W', '1', LAN_IP], { mayFail: true }).status === 0) break;
    }
  }
}

/** dnsmasq's lease file, as OpenWrt keeps it, naming the two devices — only when none is there (then ours, and removed). */
let wroteLeases = false;
function writeLeases() {
  if (fs.existsSync(LEASES)) return `${LEASES} exists already — left as it is`;
  const until = Math.floor(Date.now() / 1000) + 86400;
  fs.writeFileSync(LEASES, Object.values(DEV).map((d) => `${until} ${d.mac} ${d.ip} ${d.host} 01:${d.mac}`).join('\n') + '\n');
  wroteLeases = true;
  return `${LEASES} written (the two devices)`;
}

let work = null;
let tornDown = false;
function teardown() {
  if (tornDown) return;
  tornDown = true;
  clearNet();
  if (wroteLeases) { try { fs.rmSync(LEASES, { force: true }); } catch { /* best effort */ } wroteLeases = false; }
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

  work = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-lp-'));
  netUp();
  const leaseNote = writeLeases();
  console.log(`router ${versionOf(XRAY)} · sing-box ${versionOf(SINGBOX, /(\d+\.\d+\.\d+\S*)/)}${SERVER_XRAY !== XRAY ? ` · servers ${versionOf(SERVER_XRAY)}` : ''}`);
  console.log(`LAN ${LAN_IF} ${LAN_IP}/${LAN_MASK}: A ${DEV.a.mac} ${DEV.a.ip} · B ${DEV.b.mac} ${DEV.b.ip} · C ${SPOOF.mac} (no address yet) · WAN ${WAN.dev} ${WAN.ip} → ${SRV_IP} (S0 :${P.s0}, S1 :${P.s1}, S2 :${P.s2}) · ${leaseNote}`);
  console.log(`ports ${BASE}+ · netns ${Object.values(NS).join(' / ')} · ${work}\n`);

  // the router runs INSIDE its namespace: its loopback is Xray's, its nft and rules the gateway's
  const child = spawn('ip', ['netns', 'exec', NS.rtr, process.execPath, __filename, '--inside'], {
    stdio: 'inherit', env: Object.assign({}, process.env, { IRNF_LP_WORK: work })
  });
  const code = await new Promise((resolve) => {
    child.on('error', (e) => { console.log(`FAIL could not start the router in ${NS.rtr}: ${e.message}`); resolve(1); });
    child.on('exit', (c) => resolve(c === null ? 1 : c));
  });
  teardown();
  process.exit(code);
}

/* ------------------------------ the router (a child, inside lprtr) ------------------------------ */

const kids = [];
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

/** A command, without blocking the router's own event loop (the portal and the DNS answer meanwhile). */
function runAsync(cmd, args, timeoutMs = 20000) {
  return new Promise((resolve) => {
    const p = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    const t = setTimeout(() => { try { p.kill('SIGKILL'); } catch { /* gone */ } }, timeoutMs);
    p.stdout.on('data', (d) => { stdout += d; });
    p.stderr.on('data', (d) => { stderr += d; });
    p.on('error', (e) => { clearTimeout(t); resolve({ status: null, stdout, stderr: stderr + e.message }); });
    p.on('close', (status) => { clearTimeout(t); resolve({ status, stdout, stderr }); });
  });
}
const lastJson = (r) => { try { return JSON.parse(String(r.stdout || '').trim().split('\n').pop()); } catch { return null; } };

/** One request from a device (fetchMode, in its namespace). */
async function devFetch(d, q) {
  const req = Object.assign({ host: TARGET, port: 80, path: '/', method: 'GET', timeoutMs: 5000 }, q);
  const r = await runAsync('ip', ['netns', 'exec', d.ns, process.execPath, __filename, '--fetch', JSON.stringify(req)], req.timeoutMs + 5000);
  return lastJson(r) || { ok: false, error: 'the fetch said nothing: ' + lastLine(r) };
}
/** The server whose page answered ('S0', 'S1', 'S2'), or null. */
const pageOf = (r) => (r && r.ok && r.status === 200 && /^S[0-2]$/.test(String(r.body)) ? r.body : null);
/** Is this answer the login page? A form with a password field. */
const isLogin = (r) => !!(r && r.ok && r.status === 200 && /<form/i.test(r.body || '') && /type\s*=\s*["']?password/i.test(r.body || ''));
/** Any page of the router's portal (the sign-in form, or a device's status: its account, its usage, why it is held). */
const isPortalPage = (r) => !!(r && r.ok && !pageOf(r) && /<html/i.test(r.body || ''));
const said = (r) => (!r ? 'nothing' : !r.ok ? r.error : pageOf(r) || (isLogin(r) ? 'the login page' : isPortalPage(r) ? `the portal's page (HTTP ${r.status}, no sign-in form)` : `HTTP ${r.status}${r.location ? ' → ' + r.location : ''} ${JSON.stringify(String(r.body || '').slice(0, 60))}`));

/** A device's plain request to TARGET on `port`, following one redirect (a portal may send it to its own address). */
async function devGet(d, port = 80, timeoutMs = 5000) {
  const r = await devFetch(d, { port, timeoutMs });
  if (r.ok && r.status >= 300 && r.status < 400 && r.location) {
    let u;
    try { u = new URL(r.location, `http://${TARGET}:${port}/`); } catch { return r; }
    const next = await devFetch(d, { host: u.hostname, port: Number(u.port) || 80, path: u.pathname + u.search, timeoutMs });
    return Object.assign(next, { via: u.toString() });
  }
  return Object.assign(r, { base: `http://${TARGET}${port !== 80 ? ':' + port : ''}/` });
}

/** What the device gets on :80 and :8080 — one line, and the pages. */
async function both(d) {
  const r80 = await devGet(d, 80), r8080 = await devGet(d, 8080);
  return { r80, r8080, line: `:80 ${said(r80)} · :8080 ${said(r8080)}` };
}

/** Until `fn` says yes (or `ms` passed): { ok, ms, last }. */
async function until(fn, ms, every = 1000) {
  const t0 = Date.now();
  let last = null;
  while (Date.now() - t0 < ms) {
    last = await fn();
    if (last && last.ok) return { ok: true, ms: Date.now() - t0, last };
    await sleep(every);
  }
  return { ok: false, ms: Date.now() - t0, last };
}

/* ------------------------------ ROUTER GLUE: what the router service does for this mode ------------------------------ */
/*
 * The service's part (src/server/service.js, and the module's controller
 * src/modules/lanUsers/router/index.js once it is there), composed here from
 * the module's own exports — the one section to keep in step with them:
 *   router/plan.js     readLanUsers, transparentWanted, routedTargets, decide,
 *                      bindingsOf, inactiveReason, judgeSignIn, ruleSetText
 *   router/devices.js  scanDevices, macOfIp
 *   router/portal.js   createPortal({ host, port, api, log }) → start(), stop()
 *   router/nft.js      parseCounters
 *   meter.js           createLanUsersMeter → tickDevices(), usage(), overIds()
 *   the build          settings.lanUsers.tp (xray.js) — or, when the builder
 *                      wrote no lu-tp-* inbound, router/xrayTargets.applyTransparentTargets
 *   the gateway        TunOpenwrt.start(…, { lanUsers: { nft, singbox: { targets } } }),
 *                      then setLanUsers(nft) for every change; each target's
 *                      rule-set file rewritten (sing-box reloads it by itself)
 * Every export goes through need(), which names a missing piece and what the
 * module does export.
 */

class Missing extends Error {}
const missing = new Set();
function need(file, name, who) {
  const full = path.join(MOD, file);
  const rel = 'src/modules/lanUsers/' + file;
  let why = null, m = null;
  if (!fs.existsSync(full)) why = `${rel} does not exist yet (${who})`;
  else {
    try { m = require(full); } catch (e) { why = `${rel} does not load: ${e.message}`; }
    if (m && typeof m[name] !== 'function') why = `${rel} exports no ${name}() (${who}) — it exports: ${Object.keys(m).join(', ') || 'nothing'}`;
  }
  if (why) { missing.add(why); throw new Missing(why); }
  return m[name];
}

/** Where each export the glue calls lives, and whose it is. */
const WHERE = {
  readLanUsers: 'router/plan.js', transparentWanted: 'router/plan.js', routedTargets: 'router/plan.js', decide: 'router/plan.js',
  bindingsOf: 'router/plan.js', inactiveReason: 'router/plan.js', judgeSignIn: 'router/plan.js', ruleSetText: 'router/plan.js',
  scanDevices: 'router/devices.js', macOfIp: 'router/devices.js', createPortal: 'router/portal.js', checkPassword: 'router/portal.js',
  parseCounters: 'router/nft.js', applyTransparentTargets: 'router/xrayTargets.js',
  createLanUsersMeter: 'meter.js', normalizeLanUsers: 'model.js'
};
const R = (name) => need(WHERE[name], name, WHERE[name].startsWith('router/') ? 'USERS-ROUTER' : 'USERS-CORE');

const S = {
  servers: null, lu: null, module: false,
  scan: [],            // the devices the last refresh saw (devices.scanDevices)
  sessions: {},        // the portal's sign-ins: { [mac]: { userId, until } } (plan.bindingsOf)
  usage: {},           // the meter's usage(): { [userId]: { bytes, period, since, until, quotaBytes, over } }
  meter: null, tp: [], decided: null, logins: [], tpBy: '',
  xray: null, xrayKid: null, tun: null, portal: null, dns: null,
  tunLog: [], portalLog: [], applied: []
};
const WORK = () => process.env.IRNF_LP_WORK;
const tunRun = (cmd, args) => require('../src/main/tunPlatform').run(cmd, args, { timeout: 10000 });

/** The store as the service reads it: through model.normalizeLanUsers when the module has one. */
function readStore(raw) {
  try { return R('normalizeLanUsers')(raw); } catch (e) {
    if (!(e instanceof Missing)) throw e;
    return JSON.parse(JSON.stringify(raw));
  }
}

/**
 * The controller's tick: the devices on the LAN now (devices.scanDevices —
 * the lease file and the neighbour table), who each one is and what the
 * gateway does with it (plan.decide), each target's rule-set file rewritten
 * (sing-box reloads it by itself) and the nft sets replaced under the live
 * tunnel (TunOpenwrt.setLanUsers). → plan.decide's answer.
 */
async function refresh(why) {
  const lu = R('readLanUsers')(S.lu);
  const scan = await R('scanDevices')({ run: tunRun, lanIf: LAN_IF });
  const d = R('decide')({ lu, sessions: S.sessions, scan, usage: S.usage, now: Date.now(), tp: S.tp, portal: { ip: LAN_IP, port: P.portal } });
  for (const t of S.tp) fs.writeFileSync(t.path, R('ruleSetText')(d.ruleSets[t.tag] || []));
  S.scan = scan;
  S.decided = d;
  if (S.tun && S.tun.active) {
    if (typeof S.tun.setLanUsers === 'function') {
      await S.tun.setLanUsers(d.nft);
      S.applied.push(`${why}: live`);
    } else {
      missing.add('TunOpenwrt has no setLanUsers() — every change took a whole reconnect here (USERS-ROUTER: the live nft path, modelled on setBypassMacs)');
      await disconnect();
      await connect(S.module);
      S.applied.push(`${why}: a reconnect (no live path)`);
    }
  }
  return d;
}

/** The router's connect: the Xray config (buildConfig), Xray, the gateway (TunOpenwrt) — as service.js connects. */
async function connect(on) {
  const { buildConfig } = require('../src/main/configBuilder');
  const { TunOpenwrt } = require('../src/main/tunOpenwrt');
  S.module = on;
  S.tp = [];
  S.tpBy = '';
  let lanUsersOpt = null;
  if (on) {
    // the service's gate: the module installed and transparent mode on
    const lu = R('readLanUsers')(S.lu);
    if (!R('transparentWanted')(routerSettings(true, null), lu)) throw new Error('plan.transparentWanted() says no, with modules.lanUsers and transparent.enabled both on');
    // one loopback inbound per config a user has, on the ports the service would pick
    S.tp = R('routedTargets')(lu).map((target, n) => ({ tag: `lu-tp-${n}`, port: P.tp[n], target, path: path.join(WORK(), `lu-tp-${n}.json`) }));
    const d = await refresh('connect');
    lanUsersOpt = { nft: d.nft, singbox: { targets: S.tp.map((t) => ({ tag: t.tag, port: t.port, path: t.path })) } };
  }
  const settings = routerSettings(on, forBuild(S.lu, { tp: S.tp, over: S.meter ? S.meter.overIds() : [], servers: S.servers }));
  S.xray = buildConfig(routerPlan(S.servers), settings);
  if (tpInbounds(S.xray).length) S.tpBy = 'buildConfig (settings.lanUsers.tp, xray.js)';
  else if (S.tp.length) {
    // the router's own writer of them, when the builder wrote none
    try {
      const r = R('applyTransparentTargets')(S.xray, S.tp.map((t) => ({ tag: t.tag, port: t.port, target: t.target })),
        { plan: routerPlan(S.servers), serverId: S.servers.s0.id, records: { serversById: byIdOf(S.servers), chainsById: {} }, directInterface: WAN.dev });
      if (tpInbounds(S.xray).length) S.tpBy = 'router/xrayTargets.applyTransparentTargets' + (r && r.skipped && r.skipped.length ? ` (skipped ${JSON.stringify(r.skipped)})` : '');
    } catch (e) { if (!(e instanceof Missing)) throw e; }
  }
  const file = path.join(WORK(), `xray-${on ? 'on' : 'off'}.json`);
  fs.writeFileSync(file, JSON.stringify(S.xray, null, 1));
  const t = spawnSync(XRAY, ['run', '-test', '-c', file], { encoding: 'utf8', timeout: 20000 });
  if (t.status !== 0) throw new Error('the core refused the router\'s config — ' + lastLine(t));
  S.xrayKid = spawnKid('xray', XRAY, ['run', '-c', file]);
  const ports = [P.socks, ...tpInbounds(S.xray).map((i) => i.port)];
  for (const port of ports) if (!await waitPort('127.0.0.1', port, 10000)) throw new Error(`the router's Xray never opened 127.0.0.1:${port}\n${tail(S.xrayKid, 15)}`);

  const sbDir = path.dirname(SINGBOX);
  S.tunLog = [];
  S.tun = new TunOpenwrt({
    binDir: sbDir, extraDirs: [sbDir], lang: 'en', tmpDir: process.env.IRNF_LP_WORK,
    onLog: (line, level) => { S.tunLog.push(`${level || 'log'}: ${line}`); if (S.tunLog.length > 300) S.tunLog.splice(0, 100); },
    // the LAN as netifd would report it (no ubus here); no dnsmasq of this service's user
    lanStatus: async () => ({ device: LAN_IF, address: LAN_IP, mask: LAN_MASK }),
    uid: 0, uidsOf: () => []
  });
  // service.js's call (myTun.start) — every server a user rides is dialled directly too: kept off the tunnel
  await S.tun.start(P.socks, [SRV_IP], [], {
    ipv6: false, strict: false, apps: null, bypassMacs: [], blockQuic: false, ownDirect: [], lanUsers: lanUsersOpt
  });
}

async function disconnect() {
  if (S.tun) { try { await S.tun.stop(); } catch (e) { S.tunLog.push('stop: ' + e.message); } S.tun = null; }
  await stopKid(S.xrayKid);
  S.xrayKid = null;
}

/**
 * What the portal asks of the controller (router/portal.js's `api`): the MAC
 * behind a client's address, a sign-in judged (plan.judgeSignIn — the
 * constant-time compare, the user active, its device limit) and, when it is
 * good, a session for the configured hours and the gateway told at once; a
 * device's status; a sign-out.
 */
const portalApi = {
  async macOf(ip) {
    return R('macOfIp')(await R('scanDevices')({ run: tunRun, lanIf: LAN_IF }), ip);
  },
  async signIn({ mac, username, password }) {
    const lu = R('readLanUsers')(S.lu);
    const v = R('judgeSignIn')({ lu, sessions: S.sessions, usage: S.usage, now: Date.now(), mac, username, password, checkPassword: R('checkPassword') });
    S.logins.push({ mac, username, ok: !!(v && v.ok), code: v && v.code });
    if (!v || !v.ok) return v;
    S.sessions[mac] = { userId: v.user.id, until: Date.now() + lu.transparent.sessionHours * 3600000 };
    await refresh('a sign-in');
    return { ok: true };
  },
  async statusOf(mac) {
    const lu = R('readLanUsers')(S.lu);
    const b = R('bindingsOf')(lu, S.sessions, Date.now())[mac];
    const u = b && lu.users.find((x) => x.id === b.userId);
    if (!u) return null;
    return { name: u.name, username: u.username, via: b.via, until: b.until, held: R('inactiveReason')(u, { now: Date.now(), usage: S.usage }), usage: S.usage[u.id] || null };
  },
  async signOut(mac) {
    delete S.sessions[mac];
    await refresh('a sign-out');
    return true;
  }
};

/** The portal, on the router's LAN address and its own port (never the admin UI's), as the service would start it. */
async function startPortal() {
  S.portalLog = [];
  S.portal = R('createPortal')({
    host: LAN_IP, port: P.portal, api: portalApi,
    log: (line, level) => { S.portalLog.push(`${level || 'log'}: ${line}`); if (S.portalLog.length > 200) S.portalLog.splice(0, 50); }
  });
  await S.portal.start();
}
async function stopPortal() {
  const p = S.portal;
  S.portal = null;
  if (p) { try { await Promise.race([p.stop(), sleep(3000)]); } catch { /* gone */ } }
}

/** The gateway's nft table: its JSON listing (text) and parsed (null when there is none). */
async function nftListing() {
  const r = await runAsync('nft', ['-j', 'list', 'table', 'inet', 'irnetfree'], 10000);
  let j = null;
  try { j = r.status === 0 ? JSON.parse(r.stdout) : null; } catch { /* reported as none */ }
  return { text: r.stdout || '', j };
}
async function nftTable() { return (await nftListing()).j; }
/** Each device's bytes both ways, as the module reads its own counters (nft.parseCounters): { [mac]: bytes }. */
async function deviceTotals() {
  const { text } = await nftListing();
  const out = {};
  for (const [mac, c] of Object.entries(R('parseCounters')(text) || {})) out[mac] = Number(c.up || 0) + Number(c.down || 0);
  return out;
}
/** The sing-box config the gateway is running (TunSingbox keeps it in its work dir while up). */
function runningSingbox() {
  const w = S.tun && S.tun.inner && S.tun.inner.work;
  try { return w ? JSON.parse(fs.readFileSync(path.join(w, 'sing-box.json'), 'utf8')) : null; } catch { return null; }
}
const NFT_FILE = () => path.join(WORK(), 'irnetfree-nft.conf');

/* ------------------------------ the gates ------------------------------ */

let failed = 0, passed = 0;
function gate(ok, label, note) {
  if (ok) passed++; else failed++;
  console.log(`${ok ? 'PASS' : 'FAIL'} ${label}${note ? ' — ' + note : ''}`);
  return ok;
}
const info = (label, note) => console.log(`  ·  ${label}${note ? ' — ' + note : ''}`);

async function dumpRouter(why) {
  console.log(`    the router (${why}):`);
  if (S.xrayKid) console.log(tail(S.xrayKid, 25));
  for (const l of S.tunLog.slice(-15)) console.log(`      [gateway] ${l}`);
  for (const l of S.portalLog.slice(-10)) console.log(`      [portal] ${l}`);
  for (const [cmd, args] of [['nft', ['list', 'table', 'inet', 'irnetfree']], ['ip', ['rule']], ['ip', ['neigh', 'show', 'dev', LAN_IF]]]) {
    const r = await runAsync(cmd, args, 5000);
    // the whole table: its sets, counters and maps come before the chains
    for (const l of String(r.stdout || r.stderr || '').trim().split('\n').slice(0, 160)) console.log(`      [${cmd} ${args[0]}] ${l}`);
  }
  const sb = runningSingbox();
  if (sb) console.log(`      [sing-box] route ${JSON.stringify(sb.route)}`);
}

/** Pure: module off writes the router's Xray config of before. */
function pureGates() {
  let c;
  try { c = buildPureConfigs(); } catch (e) { gate(false, 'the builder', 'buildConfig threw with settings.lanUsers: ' + (e && e.message)); return; }
  const a = JSON.stringify(c.off), b = JSON.stringify(c.before);
  let at = 0;
  while (at < a.length && a[at] === b[at]) at++;
  gate(a === b, 'module off: the router\'s Xray config is the config of before, byte for byte',
    a === b ? '' : `they part at ${at}: …${a.slice(Math.max(0, at - 40), at + 80)}… against …${b.slice(Math.max(0, at - 40), at + 80)}…`);
}

/** Phase "off": the gateway of today, with the users' data present but the module off. */
async function phaseOff(label) {
  const tunSb = require('../src/main/tunSingbox');
  const { buildNftRuleset, BYPASS_MARK } = require('../src/main/openwrtNet');
  const { ROUTER_UDP_TIMEOUT_S } = require('../src/main/tunOpenwrt');
  try { await connect(false); } catch (e) { gate(false, `${label}: the router connects`, e.message); await dumpRouter('connect failed'); await disconnect(); return; }
  const before = failed;
  try {
    // the users' data is all there (the second time: a device bound by the portal, one over its cap) — and inert
    let wrote = '';
    try { wrote = fs.readFileSync(NFT_FILE(), 'utf8'); } catch { /* reported */ }
    const of = buildNftRuleset({ lanIf: LAN_IF, macs: [], mark: BYPASS_MARK, blockQuic: false });
    gate(wrote === of, `${label}: the gateway's nft table is the table of before, byte for byte`, wrote === of ? '' : `wrote:\n${wrote}\nbefore:\n${of}`);
    const sb = runningSingbox();
    const want = tunSb.buildTunConfig({ socksPort: P.socks, excludeIps: S.tun.inner.excludeIps, ipv6: false, strict: false, interfaceName: tunSb.TUN_IF,
      apps: null, udpTimeout: ROUTER_UDP_TIMEOUT_S, dnsMode: tunSb.tunDnsModeFor(versionOf(SINGBOX, /(\d+\.\d+\.\d+\S*)/), 'app') });
    gate(!!sb && JSON.stringify(sb) === JSON.stringify(want), `${label}: the gateway's sing-box config is the config of before`, sb ? (JSON.stringify(sb) === JSON.stringify(want) ? '' : `running ${JSON.stringify(sb.route)} · before ${JSON.stringify(want.route)}`) : 'no sing-box config in the gateway\'s work dir');
    for (const d of [DEV.a, DEV.b]) {
      const x = await both(d);
      gate(pageOf(x.r80) === 'S0' && pageOf(x.r8080) === 'S0', `${label}: device ${d.name} rides the router's own connection, S0 — no login page`, x.line);
    }
  } catch (e) { gate(false, label, 'stopped: ' + e.message); }
  if (failed > before) await dumpRouter(label);
  await disconnect();
}

/** A command in a namespace, without blocking the router's event loop (runAsync). */
const nsRun = (ns, args, timeoutMs = 10000) => runAsync('ip', ['netns', 'exec', ns, ...args], timeoutMs);
/** A device's hello to the router, a few times over: its ARP tells the router's neighbour table who has its address now. */
async function hello(d, tries) {
  for (let i = 0; i < tries; i++) if ((await nsRun(d.ns, ['ping', '-c', '1', '-W', '1', LAN_IP])).status === 0) return true;
  return false;
}
/** A rule-set file the router wrote for a user's config, as one line (sing-box reads it from there). */
function ruleSetLine(target) {
  const t = S.tp.find((x) => x.target === target);
  try { return t ? fs.readFileSync(t.path, 'utf8').replace(/\s+/g, '') : '(no inbound for ' + target + ')'; } catch { return '(no file)'; }
}

/**
 * Spoof: sing-box picks a device's config by its source ADDRESS (a rule-set
 * cannot match a MAC), so the module pins every address of a user's device to
 * that device's MAC in the table (router/nft.js). C — bob's own device, which
 * the gate lets through by its MAC — takes A's address while A is away (its
 * link down: it answers for nothing) and says hello, so the router's replies
 * to that address reach C: without the pin C rides alice's S1, and her cap.
 * With it, the router drops what C sends from there — nothing gets through,
 * the pin rule's counter shows it was that rule, and A's address is in no
 * rule-set of bob's. Then C lets the address go, A comes back, and rides S1 as
 * before: the pin is A's own MAC's way through.
 */
async function spoofGates() {
  const A = DEV.a, C = SPOOF;
  // the kernel's word on a pin of each family: the probe's devices speak v4 only, so the live table's v6 pins stay empty
  const { buildNftRuleset, BYPASS_MARK } = require('../src/main/openwrtNet');
  const check = buildNftRuleset({ lanIf: LAN_IF, macs: [], mark: BYPASS_MARK, lanUsers: {
    unassigned: 'login', allowed: [A.mac], counters: [], portal: { ip: LAN_IP, port: P.portal },
    ipmac: [{ mac: A.mac, ips: [A.ip, '2001:db8:77::11'] }, { mac: DEV.b.mac, ips: [DEV.b.ip, '2001:db8:77::12', '2001:db8:77:0:a::12'] }]
  } });
  const checkFile = path.join(WORK(), 'pins-check.nft');
  fs.writeFileSync(checkFile, check);
  // -c: checked by the kernel, nothing applied (and the refresh below loads the real table anyway)
  const chk = await runAsync('nft', ['-c', '-f', checkFile], 10000);
  gate(chk.status === 0, 'the kernel takes the module\'s pins of both families (nft -c: v4 and v6 addresses of two devices)',
    chk.status === 0 ? '' : `${lastLine(chk)}\n    the text:\n${check}`);

  S.lu.devices.push({ mac: C.mac, name: C.host, userId: 'usr-bob', blocked: false });
  let reached = false, neigh = '', before = null, after = null, x = null;
  try {
    await nsRun(A.ns, ['ip', 'link', 'set', A.dev, 'down']);
    await nsRun(C.ns, ['ip', 'addr', 'add', `${C.ip}/${LAN_MASK}`, 'dev', C.dev]);
    await nsRun(C.ns, ['ip', 'route', 'replace', 'default', 'via', LAN_IP]);
    reached = await hello(C, 5);
    neigh = String((await runAsync('ip', ['neigh', 'show', C.ip, 'dev', LAN_IF], 5000)).stdout || '').trim() || '(none)';
    await refresh('C on A\'s address');
    before = pinDrops(await nftTable());
    x = await both(C);
    after = pinDrops(await nftTable());
  } catch (e) {
    gate(false, 'spoof: C takes A\'s address', 'stopped: ' + e.message);
  }
  if (x && before && after) {
    const pins = (S.decided && S.decided.nft && S.decided.nft.ipmac) || [];
    const aRow = S.scan.find((r) => r.mac === A.mac) || {};
    const leased = Array.isArray(aRow.leased) && aRow.leased.includes(A.ip);
    const pinnedToA = pins.some((p) => p.mac === A.mac && (p.ips || []).includes(A.ip));
    const bob = ruleSetLine('srv-s2');
    const rode = pageOf(x.r80) || pageOf(x.r8080);
    const dropped = after.packets - before.packets;
    const why = !reached ? `C never reached the router from ${C.ip} (no ping answer): with no replies coming back, C getting nothing proves nothing`
      : !leased ? `A's address has no running lease in the router's scan (${LEASES} is not this probe's?) — then it is whoever answers for it now`
      : rode === 'S1' ? 'C rode alice\'s S1 from A\'s address — the router routed it by address and nothing held the address to A\'s MAC'
      : rode ? `C rode ${rode} from A's address — it got through, as someone`
      : x.r80.ok || x.r8080.ok ? `C got an answer from A's address: ${x.line}`
      : !after.rules ? 'no pin rule in the table (nothing names lu_ipmac4 / lu_ipmac6)'
      : dropped <= 0 ? `C got nothing, but the pin rule dropped none of it (${before.packets} → ${after.packets} packets) — something else stopped it`
      : !pinnedToA ? `the decision pins ${A.ip} to no one or to another MAC: ${JSON.stringify(pins)}`
      : bob.includes(A.ip) ? `A's address went into bob's rule-set too: ${bob}`
      : '';
    gate(!why, `spoof: C (bob's device) on A's address gets nothing through — dropped by the pin, not alice's S1 (${S.applied.slice(-1)[0]})`,
      `${why ? why + ' · ' : ''}C ${x.line} · pin rule dropped ${dropped} packet(s) · pins ${JSON.stringify(pins)} · bob's rule-set ${bob} · the router's neighbour entry: ${neigh}`);
  }

  // C lets the address go; A comes back — its link, its route, and a hello so the router's entry says A again
  await nsRun(C.ns, ['ip', 'addr', 'flush', 'dev', C.dev]);
  await nsRun(A.ns, ['ip', 'link', 'set', A.dev, 'up']);
  await nsRun(A.ns, ['ip', 'route', 'replace', 'default', 'via', LAN_IP]);
  await runAsync('ip', ['neigh', 'del', A.ip, 'dev', LAN_IF], 5000);
  const aHello = await hello(A, 10);
  S.lu.devices = S.lu.devices.filter((d) => normalizeMac(d.mac) !== C.mac);
  await refresh('C gone, A back');
  const back = await until(async () => { const r = await devGet(A, 80, 4000); return { ok: pageOf(r) === 'S1', r }; }, 15000);
  gate(back.ok, `spoof: A, back on its own address, rides alice's S1 again — the pin is its own MAC's way through (${S.applied.slice(-1)[0]})`,
    back.ok ? `after ${(back.ms / 1000).toFixed(1)} s` : `:80 ${said(back.last && back.last.r)}${aHello ? '' : ' · A\'s hello to the router got no answer'} · pins ${JSON.stringify((S.decided && S.decided.nft && S.decided.nft.ipmac) || [])}`);
}

/** Phase "on": transparent mode, unassigned devices to the login page. */
async function phaseOn() {
  const label = 'module on';
  // the meter, as the service keeps one (usage file and reload are the service's: none here)
  try {
    S.meter = R('createLanUsersMeter')({ usage: {}, users: () => S.lu, canReload: () => false, pending: () => [], reload: async () => {},
      log: ({ line, level }) => { S.tunLog.push(`${level || 'log'}: ${line}`); } });
  } catch (e) { if (!(e instanceof Missing)) throw e; }
  try { await connect(true); } catch (e) {
    let nft = '';
    try { nft = fs.readFileSync(NFT_FILE(), 'utf8'); } catch { /* none written */ }
    gate(false, `${label}: the router connects`, `${e instanceof Missing ? 'missing piece: ' : ''}${e.message}${nft ? `\n    the nft text it was handed:\n${nft}` : ''}`);
    await dumpRouter('connect failed');
    await disconnect();
    return;
  }
  try { await startPortal(); } catch (e) {
    gate(false, `${label}: the portal listens on ${LAN_IP}:${P.portal}`, (e instanceof Missing ? 'missing piece: ' : '') + e.message);
  }
  const before = failed;
  try {
    // what the builders wrote for this mode — said, and the pieces that are not there named
    const tps = tpInbounds(S.xray);
    info('Xray', tps.length ? `${tps.map((i) => `${i.tag} 127.0.0.1:${i.port} → ${(S.xray.routing.rules.find((r) => (r.inboundTag || []).includes(i.tag)) || {}).outboundTag || '?'}`).join('; ')} — written by ${S.tpBy}` : 'no lu-tp-* inbound');
    if (!tps.length) missing.add('the router\'s Xray config has no lu-tp-* inbound — neither buildConfig (settings.lanUsers.tp, xray.js) nor router/xrayTargets.applyTransparentTargets wrote one');
    const sb = runningSingbox();
    const dr = deviceRules(sb);
    info('sing-box', dr.length ? dr.map((r) => JSON.stringify(r)).join('; ') + ` · rule-sets ${S.tp.map((t) => `${t.tag} ${(() => { try { return fs.readFileSync(t.path, 'utf8').replace(/\s+/g, ''); } catch { return '(no file)'; } })()}`).join(' · ')}` : `no per-device rule (route ${JSON.stringify(sb && sb.route)})`);
    if (!dr.length) missing.add('the gateway\'s sing-box config has no per-device rule — tunSingbox.buildTunConfig\'s lanRoutes, handed opts.lanUsers.singbox by TunOpenwrt.start (USERS-ROUTER)');
    const j = await nftTable();
    const sets = nftSets(j);
    let counted = '';
    try { counted = JSON.stringify(await deviceTotals()); } catch (e) { counted = e.message; }
    info('nft', `sets ${Object.entries(sets).map(([k, v]) => `${k} {${v.join(', ')}}`).join(' · ') || 'none'} · per-device bytes ${counted} (read by this probe: ${JSON.stringify(macBytes(j, Object.values(DEV)))})`);
    if (!Object.keys(sets).some((k) => k !== 'bypass_macs')) missing.add('the gateway\'s nft table has no set of the users\' part — openwrtNet.buildNftRuleset\'s lanUsers, handed opts.lanUsers.nft by TunOpenwrt.start (USERS-ROUTER)');

    // assigned: A → alice → S1
    let x = await both(DEV.a);
    gate(pageOf(x.r80) === 'S1' && pageOf(x.r8080) === 'S1', 'assigned device A (→ alice) rides alice\'s server S1', x.line);

    // captive: B is nobody's
    x = await both(DEV.b);
    gate(isLogin(x.r80), 'unassigned device B: its HTTP request gets the login page', `:80 ${said(x.r80)}${x.r80.via ? ` (redirected to ${x.r80.via})` : ''}`);
    gate(!x.r8080.ok, 'unassigned device B: its other traffic fails (:8080, nothing in 5 s)', `:8080 ${said(x.r8080)}`);
    const dns = await runAsync('ip', ['netns', 'exec', DEV.b.ns, process.execPath, path.join(__dirname, 'tun-dns-probe.js'), '--query', LAN_IP, 'portal.test', 'udp'], 10000);
    const dj = lastJson(dns) || {};
    gate(Array.isArray(dj.a) && dj.a.length > 0, 'unassigned device B: the router\'s DNS still answers it', dj.error || `portal.test → ${(dj.a || []).join(',') || 'rcode ' + dj.rcode}`);

    // the login form, as the page gives it
    const form = loginForm(x.r80);
    info('the login form', form ? `${form.method} ${form.url} (${form.user}, ${form.pass})` : 'no form found in the page');
    if (form) {
      const wrong = await post(DEV.b, form, 'bob', 'not-bob');
      const still = await devGet(DEV.b, 80);
      gate(isLogin(still) && !pageOf(still), 'a wrong password leaves B on the login page', `POST → ${said(wrong)}; then :80 ${said(still)}`);
      const right = await post(DEV.b, form, 'bob', 'bob-pw-2');
      const rode = await until(async () => { const r = await devGet(DEV.b, 80, 4000); return { ok: pageOf(r) === 'S2', r }; }, 25000);
      const after = rode.ok ? await devGet(DEV.b, 8080) : null;
      gate(rode.ok && pageOf(after) === 'S2', 'after POST /login as bob, B rides bob\'s server S2 (:80 and :8080, within 25 s)',
        `POST → ${said(right)}; sign-ins ${JSON.stringify(S.logins)}; ${rode.ok ? `S2 after ${(rode.ms / 1000).toFixed(1)} s, :8080 ${said(after)}` : `:80 still ${said(rode.last && rode.last.r)}`} · applied ${S.applied.slice(-2).join(', ') || 'nothing'}`);
    } else {
      gate(false, 'after POST /login as bob, B rides bob\'s server S2', 'no login form to post to');
    }

    // blocked: A gets nothing at all, B is untouched (what B got before — S2 once the sign-in worked)
    const devA = () => {
      const d = S.lu.devices.find((v) => normalizeMac(v.mac) === DEV.a.mac);
      if (!d) throw new Error(`device A is no longer in the store's devices (${JSON.stringify(S.lu.devices)}) — normalizeLanUsers dropped it?`);
      return d;
    };
    const bWas = said(await devGet(DEV.b, 80));
    devA().blocked = true;
    await refresh('block A');
    x = await both(DEV.a);
    let bx = await devGet(DEV.b, 80);
    gate(!x.r80.ok && !x.r8080.ok && said(bx) === bWas, `blocked device A gets nothing — not even the portal — while B is untouched (${S.applied.slice(-1)[0]})`, `A ${x.line} · B :80 ${said(bx)} (before: ${bWas})`);
    devA().blocked = false;
    await refresh('unblock A');
    const back = await until(async () => { const r = await devGet(DEV.a, 80, 4000); return { ok: pageOf(r) === 'S1', r }; }, 15000);
    gate(back.ok, `unblocked, A rides S1 again (${S.applied.slice(-1)[0]})`, back.ok ? `after ${(back.ms / 1000).toFixed(1)} s` : `:80 ${said(back.last && back.last.r)}`);

    // spoof: another device on A's address rides nothing — not alice's config, not her cap
    await spoofGates();

    // the cap: A's download on its own counter, the meter makes alice over her cap, A rides nothing
    if (!S.meter) throw new Missing([...missing].find((m) => m.includes('meter.js')) || 'src/modules/lanUsers/meter.js (USERS-CORE): no createLanUsersMeter');
    const alice = S.lu.users.find((u) => u.username === 'alice');
    const t0 = await deviceTotals();
    S.meter.tickDevices(t0);
    const big = await devFetch(DEV.a, { path: `/big?n=${PUSH}`, timeoutMs: 30000 });
    const t1 = await deviceTotals();
    S.meter.tickDevices(t1);
    const grew = (t1[DEV.a.mac] || 0) - (t0[DEV.a.mac] || 0);
    gate(big.ok && big.bytes >= PUSH && grew >= 0.9 * PUSH, `A's per-device counter counts its ${PUSH / MIB} MiB download (≥ 90 %)`,
      `${big.ok ? `${(big.bytes / MIB).toFixed(2)} MiB arrived` : big.error} · nft.parseCounters: A grew ${(grew / MIB).toFixed(2)} MiB (${JSON.stringify(t1)})`);
    S.usage = S.meter.usage();
    const au = S.usage[alice.id] || {};
    info('alice', `the meter's usage ${JSON.stringify(au)} · cap ${alice.quotaGb} GB${alice.quotaGb !== CAP_GB ? ` — the store said ${CAP_GB}: the model changed it` : ''}`);
    const bBefore = said(await devGet(DEV.b, 80));
    await refresh('alice over her cap');
    x = await both(DEV.a);
    bx = await devGet(DEV.b, 80);
    // in login mode a held device meets the gate: nothing past it, its http to the portal saying why
    const held = !pageOf(x.r80) && !pageOf(x.r8080) && !x.r8080.ok && (!x.r80.ok || isPortalPage(x.r80));
    gate(au.over === true && held && said(bx) === bBefore, `alice over her cap → A rides no server (:8080 nothing, :80 nothing or the portal); B is untouched (${S.applied.slice(-1)[0]})`,
      `over ${au.over} · held ${JSON.stringify(S.decided && S.decided.held)} · A ${x.line} · B :80 ${said(bx)} (before: ${bBefore})`);
  } catch (e) {
    gate(false, label, 'stopped: ' + (e instanceof Missing ? 'missing piece: ' : '') + e.message);
  }
  if (failed > before) await dumpRouter(label);
  await disconnect();
  await stopPortal();
}

/** What the users' meter makes of `bytes` this period for `user` (src/modules/lanUsers/meter.js capBytes). */
function usageOf(user, bytes) {
  const { capBytes } = require('../src/modules/lanUsers/meter');
  const quotaBytes = capBytes(user);
  return { bytes, quotaBytes, over: quotaBytes > 0 && bytes >= quotaBytes };
}

/** The login form in a page: where it posts, and its two fields (text and password). */
function loginForm(r) {
  if (!isLogin(r)) return null;
  const html = r.body;
  const f = /<form\b([^>]*)>/i.exec(html);
  const attr = (tag, name) => ((new RegExp(`\\b${name}\\s*=\\s*("([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i').exec(tag) || []).slice(2).find((v) => v !== undefined) || '');
  const action = attr(f[1], 'action') || '/login';
  const method = (attr(f[1], 'method') || 'POST').toUpperCase();
  const inputs = [...html.matchAll(/<input\b[^>]*>/gi)].map((m) => m[0]);
  const pass = inputs.find((i) => /type\s*=\s*["']?password/i.test(i));
  const text = inputs.find((i) => i !== pass && !/type\s*=\s*["']?(hidden|submit|button|checkbox|radio)/i.test(i));
  const hidden = inputs.filter((i) => /type\s*=\s*["']?hidden/i.test(i)).map((i) => [attr(i, 'name'), attr(i, 'value')]).filter(([n]) => n);
  let url;
  try { url = new URL(action, r.via || r.base || `http://${TARGET}/`); } catch { return null; }
  return { url: url.toString(), host: url.hostname, port: Number(url.port) || 80, path: url.pathname + url.search, method, user: (text && attr(text, 'name')) || 'username', pass: (pass && attr(pass, 'name')) || 'password', hidden };
}
async function post(d, form, username, password) {
  const body = new URLSearchParams([...form.hidden, [form.user, username], [form.pass, password]]).toString();
  return devFetch(d, { host: form.host, port: form.port, path: form.path, method: 'POST', body, timeoutMs: 8000 });
}

/** A DNS on the router's LAN address, standing in for dnsmasq: every A gets an answer (tun-dns-probe's codec). */
function startDns() {
  const { ispAnswer } = require('./tun-dns-probe');
  const sock = dgram.createSocket('udp4');
  sock.on('message', (msg, rinfo) => { try { sock.send(ispAnswer(msg).reply, rinfo.port, rinfo.address); } catch { /* a bad query */ } });
  return new Promise((resolve, reject) => { sock.once('error', reject); sock.bind(53, LAN_IP, () => resolve(sock)); });
}

async function inside() {
  if (process.env.IRNF_LP_PROBE !== '1' || process.platform !== 'linux' || !process.getuid || process.getuid() !== 0 || !process.env.IRNF_LP_WORK) {
    console.error('probe-lan-portal --inside: only as a child of the probe, inside its router namespace');
    process.exit(2);
  }
  const cleanup = () => { try { if (S.tun) S.tun.cleanupSync(); } catch { /* best effort */ } killAll(); };
  process.on('exit', cleanup);
  process.on('SIGINT', () => { cleanup(); process.exit(130); });
  process.on('SIGTERM', () => { cleanup(); process.exit(143); });
  setTimeout(() => {
    console.log(`FAIL the probe ran out of time (${INNER_LIMIT_MS / 1000} s) — stopped`);
    for (const k of kids) console.log(tail(k, 20));
    for (const l of S.tunLog.slice(-15)) console.log(`      [gateway] ${l}`);
    cleanup();
    process.exit(1);
  }, INNER_LIMIT_MS).unref();

  try {
    // the internet side: a page per server, then the servers, all in lpnet
    S.servers = probeServers();
    for (const [key, port] of [['S0', P.page0], ['S1', P.page1], ['S2', P.page2]]) {
      const pg = spawnKid('page ' + key, 'ip', ['netns', 'exec', NS.inet, process.execPath, __filename, '--serve', String(port), key]);
      if (!await waitText(pg, /^ready/m, 10000)) throw new Error(`the page of ${key} never listened in ${NS.inet}\n${tail(pg, 10)}`);
    }
    for (const [key, pg] of [['s0', P.page0], ['s1', P.page1], ['s2', P.page2]]) {
      const f = path.join(process.env.IRNF_LP_WORK, `server-${key}.json`);
      fs.writeFileSync(f, JSON.stringify({
        log: { loglevel: 'warning' },
        inbounds: [{ listen: SRV_IP, port: P[key], protocol: 'vless', settings: { clients: [{ id: UUID }], decryption: 'none' }, streamSettings: { network: 'tcp', security: 'none' } }],
        outbounds: [{ protocol: 'freedom', settings: { redirect: '127.0.0.1:' + pg, finalRules: [{ action: 'allow' }] } }]
      }));
      const srv = spawnKid('server ' + key, 'ip', ['netns', 'exec', NS.inet, SERVER_XRAY, 'run', '-c', f]);
      if (!await waitPort(SRV_IP, P[key], 10000)) throw new Error(`server ${key} never listened on ${SRV_IP}:${P[key]}\n${tail(srv, 10)}`);
    }
    S.dns = await startDns();
    S.lu = readStore(probeLanUsers());

    pureGates();
    await phaseOff('module off');
    await phaseOn();
    await phaseOff('module off again');
  } catch (e) {
    gate(false, 'the probe', (e instanceof Missing ? 'missing piece: ' : '') + e.message);
    for (const k of kids) console.log(tail(k, 8));
  }
  try { if (S.dns) S.dns.close(); } catch { /* closed */ }
  await disconnect();
  await stopPortal();
  if (S.applied.length) info('changes applied', S.applied.join(' · '));
  if (missing.size) {
    console.log('\nmissing pieces (the module, contract B):');
    for (const m of missing) console.log('  - ' + m);
  }
  console.log(`\n${passed}/${passed + failed} gates passed — router ${versionOf(XRAY)}, sing-box ${versionOf(SINGBOX, /(\d+\.\d+\.\d+\S*)/)}`);
  killAll();
  process.exit(failed ? 1 : 0);
}

if (require.main === module) {
  if (process.argv[2] === '--serve') serveMode();
  else if (process.argv[2] === '--fetch') fetchMode();
  else if (process.argv[2] === '--inside') inside().catch((e) => { console.log(`FAIL ${e && e.stack || e}`); killAll(); process.exit(1); });
  else outside().catch((e) => { console.log(`FAIL ${e.message}`); teardown(); process.exit(1); });
}

module.exports = { buildPureConfigs, probeLanUsers, probeServers, routerSettings, routerPlan, macBytes, nftSets, pinDrops, tpInbounds, deviceRules, loginForm, usageOf, P, APP_PORTS, NS, DEV, SPOOF, WAN, LAN_IP, LAN_IF, SRV_IP, TARGET, CAP_GB, PUSH, BASE };
