#!/usr/bin/env node
'use strict';
/**
 * LAN users (module `lanUsers`, the contract's section B) on a real core,
 * loopback only: people on the LAN reach the app's proxy with a username and a
 * password, and each one rides the config the admin gave them. `xray run
 * -test` says the inbounds parse; only a fetch through them says the core
 * routes each account to its own server, refuses the rest, and counts each
 * one's bytes — what the data caps (meter.js) are read from.
 *
 *   this probe ─SOCKS5 alice:pw─▶ ┐                         ┌─▶ S1 (VLESS) ─▶ page «S1»
 *              ─SOCKS5 bob:pw───▶ ├ lu-socks / lu-http ─────┼─▶ S2 (VLESS) ─▶ page «S2»
 *              ─HTTP  alice:pw──▶ ┘  (the client core)      └─▶ S0 (VLESS) ─▶ page «S0»
 *              ─SOCKS5 no auth──▶ socks-in (the app's own) ───▶ S0: the main connection
 *
 * The client config is the app's own: buildConfig({ mode: 'single', server:
 * S0, serversById }, settings) with settings.modules.lanUsers = true and
 * settings.lanUsers = the store's shape (contract B: config.proxy on, users),
 * the users' targets handed in the plan's serversById as the pool and advanced
 * plans carry them (main.js buildPlan). The servers are parsed from vless://
 * links like a user's (parser.parseLink). Two things differ from the app: the
 * users' inbounds (`lu-*`) are moved to 127.0.0.1 whatever listen the builder
 * gave them (a LAN address in the app — printed), and nothing else.
 *
 * Users (contract B's user shape, every key):
 *   alice → S1 · bob → S2 · dave → '' (the current connection, S0)
 *   erin  → 'block' · carol → S1 but disabled · gina → S1 but expired
 *
 * Gates:
 *   off       module off (settings.modules.lanUsers false), and module on with
 *             config.proxy.enabled false: the config of before, byte for byte
 *   built     the users' SOCKS and HTTP inbounds exist, with exactly the
 *             active users as accounts (not carol, not gina); the core takes
 *             the config
 *   main      the app's own SOCKS port (no auth) still rides S0, every fetch
 *   route     alice's 6 fetches all S1, bob's all S2, dave's all S0; erin's
 *             reach no server; the same over the users' HTTP proxy (alice, bob)
 *   refuse    a wrong password, carol, gina, a name nobody has, and no
 *             password at all: refused at the SOCKS handshake; over HTTP no
 *             credentials and a wrong password get 407
 *   bytes     /debug/vars shows a counter per user: alice's and bob's each at
 *             least what they fetched (256 KB and 512 KB more), none for carol
 *             — the key it is under is read from the core's answer and printed
 * A failure prints the client core's last lines. A piece of the module that
 * is not there yet (xray.js not in the builder) is named, and the rest stop.
 *
 * Runs only where it is meant to: IRNF_LU_PROBE=1 (CI's `cores` job).
 *   IRNF_XRAY_EXE    the core under test (default bin/xray)
 *   IRNF_HOP_EXE     the servers' core (default: the core under test)
 *   IRNF_PROBE_PORT  base port, default 23500 (never the app's own)
 */
const fs = require('fs');
const os = require('os');
const net = require('net');
const path = require('path');
const http = require('http');
const { spawn, spawnSync } = require('child_process');

const BASE = Number(process.env.IRNF_PROBE_PORT || 23500);
const P = {
  s0: BASE + 1, s1: BASE + 2, s2: BASE + 3,
  page0: BASE + 11, page1: BASE + 12, page2: BASE + 13,
  socks: BASE + 20, http: BASE + 21, api: BASE + 22,
  luSocks: BASE + 30, luHttp: BASE + 31, portal: BASE + 32
};
/**
 * The app's own ports (the owner's IRNetFree runs on them): never these.
 * 30820-30822 are the users' own defaults (contract B) — a running app may hold them too.
 */
const APP_PORTS = [10808, 10809, 10085, 30808, 30809, 30085, 30820, 30821, 30822];
const UUID = '7d2f0c3b-1e4a-4b6d-9c8e-0a1b2c3d4e5f';
const TARGET = '203.0.113.9';   // a documentation address: every server hands it to its own page
const ROUNDS = 6;
const KB = 1024;
const BIG = { alice: 256 * KB, bob: 512 * KB };
const exeName = (n) => (process.platform === 'win32' ? n + '.exe' : n);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const XRAY = process.env.IRNF_XRAY_EXE || path.join(__dirname, '..', 'bin', exeName('xray'));
const SERVER_XRAY = process.env.IRNF_HOP_EXE || XRAY;
const XRAY_JS = path.join(__dirname, '..', 'src', 'modules', 'lanUsers', 'xray.js');

/* ------------------------------ what the client gets: the app's own ------------------------------ */

/** The three servers as the app keeps them, parsed from links (ids fixed, so the users' targets can name them). */
function probeServers() {
  const { parseLink } = require('../src/main/parser');
  const one = (key, port) => Object.assign(parseLink(`vless://${UUID}@127.0.0.1:${port}?type=tcp&security=none&encryption=none#${key.toUpperCase()}`), { id: 'srv-' + key });
  return { s0: one('s0', P.s0), s1: one('s1', P.s1), s2: one('s2', P.s2) };
}

/** One user, every key of the contract's shape. */
function user(id, username, password, target, over) {
  return Object.assign({ id, username, password, name: username, target, quotaGb: 0, quotaPeriod: 'none', expiresAt: 0, maxDevices: 0, enabled: true }, over || {});
}

/** store.lanUsers (contract B): the proxy accounts on, on this probe's ports; transparent mode is the router's (off). */
function probeLanUsers(proxyEnabled = true) {
  return {
    config: {
      proxy: { enabled: proxyEnabled, port: P.luSocks, httpPort: P.luHttp },
      transparent: { enabled: false, unassigned: 'login', sessionHours: 24, portalPort: P.portal }
    },
    users: [
      user('usr-alice', 'alice', 'alice-pw-1', 'srv-s1'),
      user('usr-bob', 'bob', 'bob-pw-2', 'srv-s2'),
      user('usr-dave', 'dave', 'dave-pw-4', ''),
      user('usr-erin', 'erin', 'erin-pw-5', 'block'),
      user('usr-carol', 'carol', 'carol-pw-3', 'srv-s1', { enabled: false }),
      // expired long ago (2001-09-09): not active, so not an account
      user('usr-gina', 'gina', 'gina-pw-6', 'srv-s1', { expiresAt: 1000000000000 })
    ],
    devices: []
  };
}
/** Who must be an account, and who must not. */
const ACTIVE = ['alice', 'bob', 'dave', 'erin'];
const INACTIVE = ['carol', 'gina'];

/** The settings main.js would pass (tests/fixtures), on this probe's ports, plus `over`. */
function probeSettings(over) {
  const F = require('../tests/fixtures');
  return F.settings(Object.assign({
    socksPort: P.socks, httpPort: P.http, apiPort: P.api, allowLan: false,
    routingMode: 'global', blockAds: false, geoAssets: false, enableSniffing: false, dnsManaged: false, logLevel: 'warning'
  }, over || {}));
}

/**
 * Every config the probe uses — buildConfig(plan, settings), nothing else:
 *   on        modules.lanUsers true, lanUsers with the proxy accounts on
 *   none      no `modules`, no `lanUsers` at all (the config of before)
 *   off       modules.lanUsers false, the same lanUsers
 *   proxyOff  modules.lanUsers true, config.proxy.enabled false
 */
function buildProbeConfigs() {
  const { buildConfig } = require('../src/main/configBuilder');
  const servers = probeServers();
  const serversById = {};
  for (const s of Object.values(servers)) serversById[s.id] = s;
  const plan = () => ({ mode: 'single', server: servers.s0, serversById, chainsById: {} });
  const lu = probeLanUsers(true);
  return {
    servers, lu,
    on: buildConfig(plan(), probeSettings({ modules: { lanUsers: true }, lanUsers: lu })),
    none: buildConfig(plan(), probeSettings()),
    off: buildConfig(plan(), probeSettings({ modules: { lanUsers: false }, lanUsers: lu })),
    proxyOff: buildConfig(plan(), probeSettings({ modules: { lanUsers: true }, lanUsers: probeLanUsers(false) }))
  };
}

/** The users' inbounds the builder wrote (tag `lu-…`, SOCKS or HTTP). */
const luInbounds = (cfg) => ((cfg && cfg.inbounds) || []).filter((i) => i && /^lu-/.test(String(i.tag || '')) && (i.protocol === 'socks' || i.protocol === 'http'));
const accountsOf = (ib) => (((ib && ib.settings) || {}).accounts || []).map((a) => a && a.user).filter(Boolean);
/**
 * The inbound a user dials: the one whose accounts carry the name (one shared
 * inbound, or — the contract's fallback — one per user on its own port); for
 * someone in no account list, the shared one on config.proxy's port.
 */
function inboundFor(cfg, protocol, username, sharedPort) {
  const list = luInbounds(cfg).filter((i) => i.protocol === protocol);
  return list.find((i) => accountsOf(i).includes(username)) || list.find((i) => i.port === sharedPort) || list[0] || null;
}

/** What the users' part of a config is, in one line. */
function describeUsers(cfg) {
  const ib = luInbounds(cfg).map((i) => `${i.tag} ${i.protocol} ${i.listen || '(no listen)'}:${i.port} auth ${(i.settings && i.settings.auth) || (accountsOf(i).length ? 'accounts' : 'none')} [${accountsOf(i).join(',')}]${i.settings && i.settings.userLevel ? ` level ${i.settings.userLevel}` : ''}`);
  const rules = (((cfg && cfg.routing) || {}).rules || []).filter((r) => r && (Array.isArray(r.user) || (Array.isArray(r.inboundTag) && r.inboundTag.some((t) => /^lu-/.test(t)))))
    .map((r) => `${r.user ? 'user ' + r.user.join(',') : 'in ' + r.inboundTag.join(',')} → ${r.outboundTag || r.balancerTag}`);
  const outs = ((cfg && cfg.outbounds) || []).filter((o) => /^lu-/.test(String(o && o.tag))).map((o) => o.tag);
  const levels = Object.entries(((cfg && cfg.policy) || {}).levels || {}).map(([k, v]) => `${k}: ${Object.keys(v).filter((x) => /^statsUser/.test(x) && v[x]).join('+') || 'no user stats'}`);
  return `inbounds ${ib.join('; ') || 'none'} · rules ${rules.join('; ') || 'none'} · outbounds ${outs.join(', ') || 'none'} · policy levels ${levels.join(', ') || 'none'}`;
}

/* ------------------------------ the far side: servers and their pages ------------------------------ */

/** A VLESS/TCP server on 127.0.0.1:port; every flow handed to its page. */
function serverConfig(port, page) {
  return {
    log: { loglevel: 'warning' },
    inbounds: [{ listen: '127.0.0.1', port, protocol: 'vless', settings: { clients: [{ id: UUID }], decryption: 'none' }, streamSettings: { network: 'tcp', security: 'none' } }],
    outbounds: [{ protocol: 'freedom', settings: { redirect: '127.0.0.1:' + page, finalRules: [{ action: 'allow' }] } }]
  };
}
/** The page of a server: its name, or n bytes at /big?n=. */
function page(port, name) {
  const chunk = Buffer.alloc(64 * KB, 0x61);
  return new Promise((resolve) => {
    const srv = http.createServer((q, res) => {
      const u = new URL(q.url, 'http://page');
      if (u.pathname === '/big') {
        let left = Math.max(0, Math.min(Number(u.searchParams.get('n')) || 0, 64 * 1024 * KB));
        res.writeHead(200, { 'Content-Length': left });
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
      res.writeHead(200, { 'Content-Length': name.length });
      res.end(name);
    });
    srv.listen(port, '127.0.0.1', () => resolve(srv));
  });
}

/* ------------------------------ clients: SOCKS5 with RFC 1929, and an HTTP proxy ------------------------------ */

/**
 * One GET http://TARGET<pathname> through a SOCKS5 port — as `cred`
 * ({ user, pass }, RFC 1929) or offering no auth at all (cred null). Never
 * throws: { ok, body, bytes } or { ok: false, refused: 'greeting'|'auth'|'connect', error }.
 */
function socksGet(port, cred, pathname = '/', timeoutMs = 10000) {
  return new Promise((resolve) => {
    const s = net.connect(port, '127.0.0.1');
    let stage = 0, buf = Buffer.alloc(0), done = false, method = null;
    const finish = (r) => { if (done) return; done = true; clearTimeout(timer); s.destroy(); resolve(Object.assign({ method }, r)); };
    const timer = setTimeout(() => finish({ ok: false, error: `timed out at stage ${stage}` }), timeoutMs);
    s.on('error', (e) => finish({ ok: false, refused: stage < 2 ? 'greeting' : stage < 3 ? 'auth' : undefined, error: e.code || e.message }));
    s.on('connect', () => s.write(Buffer.from(cred ? [5, 1, 2] : [5, 1, 0])));
    const connect = () => { stage = 3; s.write(Buffer.from([5, 1, 0, 1, ...TARGET.split('.').map(Number), 0, 80])); };
    s.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      if (stage === 0) {
        if (buf.length < 2) return;
        method = buf[1];
        buf = buf.subarray(2);
        if (method === 0xff) return finish({ ok: false, refused: 'greeting', error: 'no acceptable auth method (0xFF)' });
        if (method === 2 && cred) {
          stage = 2;
          const u = Buffer.from(cred.user), p = Buffer.from(cred.pass);
          s.write(Buffer.concat([Buffer.from([1, u.length]), u, Buffer.from([p.length]), p]));
        } else if (method === 0) connect();
        else return finish({ ok: false, refused: 'greeting', error: 'method ' + method });
      }
      if (stage === 2) {
        if (buf.length < 2) return;
        const status = buf[1];
        buf = buf.subarray(2);
        if (status !== 0) return finish({ ok: false, refused: 'auth', error: 'auth status 0x' + status.toString(16) });
        connect();
      }
      if (stage === 3) {
        if (buf.length < 10) return;
        if (buf[1] !== 0) return finish({ ok: false, refused: 'connect', error: 'CONNECT refused (code ' + buf[1] + ')' });
        buf = buf.subarray(10);
        stage = 4;
        s.write(`GET ${pathname} HTTP/1.1\r\nHost: ${TARGET}\r\nConnection: close\r\n\r\n`);
      }
    });
    s.on('close', () => {
      if (stage < 4) return finish({ ok: false, refused: stage < 2 ? 'greeting' : stage < 3 ? 'auth' : 'connect', error: 'closed at stage ' + stage });
      const i = buf.indexOf('\r\n\r\n');
      if (i < 0) return finish({ ok: false, error: 'no HTTP answer' });
      const head = buf.subarray(0, i).toString('latin1');
      const status = Number((/^HTTP\/1\.[01] (\d{3})/.exec(head) || [])[1]);
      const body = buf.subarray(i + 4);
      finish(status === 200 ? { ok: true, body: pathname === '/' ? body.toString() : '', bytes: body.length } : { ok: false, error: 'HTTP ' + status, status });
    });
  });
}

/** One GET http://TARGET/ through an HTTP proxy port, with Basic credentials or none. → { ok, status, body }. */
function httpGet(port, cred, timeoutMs = 10000) {
  return new Promise((resolve) => {
    const headers = { Host: TARGET, Connection: 'close' };
    if (cred) headers['Proxy-Authorization'] = 'Basic ' + Buffer.from(`${cred.user}:${cred.pass}`).toString('base64');
    const req = http.request({ host: '127.0.0.1', port, method: 'GET', path: `http://${TARGET}/`, headers, timeout: timeoutMs, agent: false }, (res) => {
      let b = '';
      res.on('data', (d) => { b += d; });
      res.on('end', () => resolve({ ok: res.statusCode === 200, status: res.statusCode, body: b }));
    });
    req.on('timeout', () => req.destroy(new Error('timed out')));
    req.on('error', (e) => resolve({ ok: false, error: e.code || e.message }));
    req.end();
  });
}

/** The client core's /debug/vars. */
function debugVars() {
  return new Promise((resolve) => {
    const req = http.get({ host: '127.0.0.1', port: P.api, path: '/debug/vars', timeout: 3000 }, (res) => {
      let b = '';
      res.on('data', (d) => { b += d; });
      res.on('end', () => { try { resolve(JSON.parse(b)); } catch { resolve(null); } });
    });
    req.on('timeout', () => req.destroy());
    req.on('error', () => resolve(null));
  });
}

/**
 * A user's counter in /debug/vars, wherever the builder's per-user stats put
 * it: stats.user[<the account's name>] (SOCKS and HTTP accounts carry their
 * name as the user's email, Xray proxy/socks/protocol.go, proxy/http/server.go),
 * or stats.user[<a key carrying the user's id>]; with one inbound per user (the
 * contract's fallback), stats.inbound[<that inbound's tag>].
 */
function counterOf(vars, u, cfg) {
  const st = (vars && vars.stats) || {};
  const users = st.user || {};
  const sum = (c) => ({ up: Number((c && c.uplink) || 0), down: Number((c && c.downlink) || 0) });
  if (users[u.username]) return Object.assign({ key: `stats.user.${u.username}` }, sum(users[u.username]));
  const byId = Object.keys(users).find((k) => k.includes(u.id));
  if (byId) return Object.assign({ key: `stats.user.${byId}` }, sum(users[byId]));
  const own = luInbounds(cfg).filter((i) => accountsOf(i).length === 1 && accountsOf(i)[0] === u.username).map((i) => i.tag);
  const ib = own.find((t) => (st.inbound || {})[t]);
  if (ib) return Object.assign({ key: `stats.inbound.${ib}` }, sum(st.inbound[ib]));
  return null;
}

/* ------------------------------ the run ------------------------------ */

const procs = [];
function runCore(exe, file, tag) {
  const proc = spawn(exe, ['run', '-c', file], { windowsHide: true });
  let out = '';
  const take = (d) => { out += d; if (out.length > 200000) out = out.slice(-100000); };
  proc.stdout.on('data', take);
  proc.stderr.on('data', take);
  procs.push(proc);
  return { proc, tail: (n) => out.split('\n').filter((l) => l.trim()).slice(-n).map((l) => `      [${tag}] ${l}`).join('\n') || `      [${tag}] (nothing logged)` };
}
function killAll() { for (const p of procs.splice(0)) { try { p.kill('SIGKILL'); } catch { /* gone */ } } }
async function waitPort(port, ms = 10000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const ok = await new Promise((r) => { const s = net.connect(port, '127.0.0.1', () => { s.destroy(); r(true); }); s.on('error', () => r(false)); });
    if (ok) return true;
    await sleep(150);
  }
  return false;
}
const lastLine = (r) => ((r.stdout || '') + (r.stderr || '') + (r.error ? r.error.message : '')).trim().split(/\r?\n/).slice(-1)[0] || '(no output)';
const versionOf = (exe) => (spawnSync(exe, ['version'], { encoding: 'utf8', timeout: 20000 }).stdout || '').split(/\r?\n/)[0] || `(no version from ${exe})`;

let passed = 0, failed = 0;
function gate(ok, label, note) {
  if (ok) passed++; else failed++;
  console.log(`${ok ? 'PASS' : 'FAIL'} ${label}${note ? ' — ' + note : ''}`);
  return ok;
}
const info = (label, note) => console.log(`  ·  ${label}${note ? ' — ' + note : ''}`);

function preconditions() {
  if (process.env.IRNF_LU_PROBE !== '1') {
    console.error('probe-lan-users: CI only — IRNF_LU_PROBE=1 (it runs cores and binds loopback ports)');
    process.exit(2);
  }
  for (const [k, exe] of [['IRNF_XRAY_EXE', XRAY], ['IRNF_HOP_EXE', SERVER_XRAY]]) {
    if (!fs.existsSync(exe)) { console.error(`probe-lan-users: ${k}: no core at ${exe}`); process.exit(2); }
  }
  const own = Object.values(P).filter((p) => APP_PORTS.includes(p));
  if (own.length) { console.error(`probe-lan-users: IRNF_PROBE_PORT=${BASE} lands on the app's own port ${own.join(', ')}`); process.exit(2); }
}

/** N fetches as one client: what each answered ('S1', 'ERR:…'). */
async function seen(get, n = ROUNDS) {
  const out = [];
  for (let i = 0; i < n; i++) {
    const r = await get();
    out.push(r.ok ? String(r.body) : 'ERR:' + (r.error || r.status));
  }
  return out;
}
const all = (list, want) => list.length > 0 && list.every((x) => x === want);

async function main() {
  preconditions();
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-luprobe-'));
  console.log(`client ${versionOf(XRAY)}${SERVER_XRAY !== XRAY ? ` · servers ${versionOf(SERVER_XRAY)}` : ''} · ports ${BASE}+ · ${work}\n`);

  // the builder first — pure, before anything listens
  let cfgs;
  try { cfgs = buildProbeConfigs(); } catch (e) {
    gate(false, 'the builder', 'buildConfig threw with settings.lanUsers: ' + (e && e.stack || e));
    return finish(work);
  }
  const none = JSON.stringify(cfgs.none);
  for (const [k, label] of [['off', 'module off (settings.modules.lanUsers false)'], ['proxyOff', 'module on, config.proxy.enabled false']]) {
    const c = JSON.stringify(cfgs[k]);
    let at = 0;
    while (at < c.length && c[at] === none[at]) at++;
    gate(c === none, `${label}: the config of before, byte for byte`,
      c === none ? '' : `they part at ${at}: …${c.slice(Math.max(0, at - 40), at + 80)}… against …${none.slice(Math.max(0, at - 40), at + 80)}…`);
  }
  const cfg = cfgs.on;
  info('the users\' part of the config', describeUsers(cfg));
  const ibs = luInbounds(cfg);
  if (!ibs.length) {
    gate(false, 'the users\' inbounds', `buildConfig wrote no lu-* SOCKS/HTTP inbound with settings.modules.lanUsers=true and lanUsers.config.proxy.enabled=true — missing piece: ${fs.existsSync(XRAY_JS)
      ? 'src/modules/lanUsers/xray.js is there, but configBuilder.buildConfig does not call applyLanUsers (or it found no active user)'
      : 'src/modules/lanUsers/xray.js does not exist yet (USERS-CORE), and configBuilder.buildConfig calls no applyLanUsers'}`);
    return finish(work);
  }
  const socksIbs = ibs.filter((i) => i.protocol === 'socks'), httpIbs = ibs.filter((i) => i.protocol === 'http');
  const accounts = [...new Set(ibs.flatMap(accountsOf))].sort();
  gate(socksIbs.length > 0 && httpIbs.length > 0, 'the users\' SOCKS and HTTP inbounds are there', `${socksIbs.length} SOCKS, ${httpIbs.length} HTTP`);
  gate(socksIbs.every((i) => (i.settings || {}).auth === 'password') && socksIbs.every((i) => (i.settings || {}).udp === true),
    'every users\' SOCKS inbound asks a password and carries UDP', socksIbs.map((i) => `${i.tag}: auth ${(i.settings || {}).auth}, udp ${(i.settings || {}).udp}`).join('; '));
  gate(ACTIVE.every((u) => accounts.includes(u)) && INACTIVE.every((u) => !accounts.includes(u)),
    `the accounts are the active users (${ACTIVE.join(', ')}), never ${INACTIVE.join(' or ')}`, `accounts: ${accounts.join(', ') || 'none'}`);
  // the only change to what the builder wrote: the users' inbounds on loopback
  const listens = [...new Set(ibs.map((i) => i.listen || '(none)'))];
  for (const i of ibs) i.listen = '127.0.0.1';
  info('listen', `the builder gave the users' inbounds ${listens.join(', ')} — moved to 127.0.0.1 here`);
  const busy = ibs.map((i) => i.port).filter((p) => APP_PORTS.includes(p));
  if (busy.length) { gate(false, 'the users\' ports', `the builder put them on the app's own ${busy.join(', ')}, not on lanUsers.config.proxy's`); return finish(work); }

  // the far side
  const pages = [await page(P.page0, 'S0'), await page(P.page1, 'S1'), await page(P.page2, 'S2')];
  const servers = [];
  for (const [key, pg] of [['s0', P.page0], ['s1', P.page1], ['s2', P.page2]]) {
    const f = path.join(work, key + '.json');
    fs.writeFileSync(f, JSON.stringify(serverConfig(P[key], pg)));
    servers.push(runCore(SERVER_XRAY, f, key));
  }
  for (const key of ['s0', 's1', 's2']) {
    if (!await waitPort(P[key])) { gate(false, 'the servers', `${key} never listened on ${P[key]}\n${servers.map((s) => s.tail(5)).join('\n')}`); for (const p of pages) p.close(); return finish(work); }
  }

  // the client: the app's config
  const file = path.join(work, 'client.json');
  fs.writeFileSync(file, JSON.stringify(cfg, null, 1));
  const t = spawnSync(XRAY, ['run', '-test', '-c', file], { encoding: 'utf8', timeout: 20000 });
  if (!gate(t.status === 0, 'the core takes the config', t.status === 0 ? '' : lastLine(t))) { for (const p of pages) p.close(); return finish(work); }
  const client = runCore(XRAY, file, 'client');
  const before = failed;
  try {
    for (const port of [P.socks, ...ibs.map((i) => i.port)]) {
      if (!await waitPort(port)) throw new Error(`the client never opened 127.0.0.1:${port}`);
    }
    const byName = Object.fromEntries(cfgs.lu.users.map((u) => [u.username, u]));
    const cred = (name, pass) => ({ user: name, pass: pass == null ? byName[name].password : pass });
    const sIb = (name) => inboundFor(cfg, 'socks', name, P.luSocks);
    const hIb = (name) => inboundFor(cfg, 'http', name, P.luHttp);

    // the main connection: the app's own SOCKS, no auth
    let x = await seen(() => socksGet(P.socks, null));
    gate(all(x, 'S0'), 'the app\'s own SOCKS port (no auth) still rides the main connection, S0', x.join(' '));

    // each user's own server
    for (const [name, want] of [['alice', 'S1'], ['bob', 'S2'], ['dave', 'S0']]) {
      const ib = sIb(name);
      x = await seen(() => socksGet(ib.port, cred(name)));
      gate(all(x, want), `${name} (target ${JSON.stringify(byName[name].target)}) over SOCKS ${ib.tag}:${ib.port} rides ${want}, every fetch`, x.join(' '));
    }
    x = await seen(() => socksGet(sIb('erin').port, cred('erin')), 3);
    gate(x.every((v) => !['S0', 'S1', 'S2'].includes(v)), 'erin (target "block") reaches no server', x.join(' '));
    for (const [name, want] of [['alice', 'S1'], ['bob', 'S2']]) {
      const ib = hIb(name);
      const r = [];
      for (let i = 0; i < 3; i++) { const g = await httpGet(ib.port, cred(name)); r.push(g.ok ? g.body : 'ERR:' + (g.error || g.status)); }
      gate(all(r, want), `${name} over the users' HTTP proxy ${ib.tag}:${ib.port} rides ${want}`, r.join(' '));
    }

    // refused at the door
    const refusedAt = (r) => (r.ok ? 'GOT ' + r.body : `${r.refused || 'not refused'}: ${r.error}`);
    const tries = [
      ['a wrong password for alice', sIb('alice'), cred('alice', 'not-' + byName.alice.password)],
      ['carol (disabled)', sIb('carol'), cred('carol')],
      ['gina (expired)', sIb('gina'), cred('gina')],
      ['a name nobody has', sIb('alice'), { user: 'mallory', pass: 'mallory-pw' }],
      ['no password at all', sIb('alice'), null]
    ];
    for (const [label, ib, c] of tries) {
      const r = await socksGet(ib.port, c);
      gate(!r.ok && (r.refused === 'greeting' || r.refused === 'auth'), `${label} is refused at the SOCKS handshake (${ib.tag}:${ib.port})`, refusedAt(r));
    }
    for (const [label, c] of [['no credentials', null], ['a wrong password for bob', cred('bob', 'nope')], ['carol (disabled)', cred('carol')]]) {
      const ib = hIb(c ? c.user : 'alice');
      const r = await httpGet(ib.port, c);
      gate(r.status === 407, `${label} over HTTP gets 407 (${ib.tag}:${ib.port})`, r.ok ? 'GOT ' + r.body : String(r.status || r.error));
    }

    // per-user bytes
    const v0 = await debugVars();
    for (const name of ['alice', 'bob']) {
      const r = await socksGet(sIb(name).port, cred(name), `/big?n=${BIG[name]}`, 20000);
      if (!r.ok || r.bytes !== BIG[name]) gate(false, `${name}: ${BIG[name] / KB} KB through SOCKS`, r.ok ? `${r.bytes} bytes` : r.error);
    }
    await sleep(500);
    const v1 = await debugVars();
    if (!v1) throw new Error(`no /debug/vars on 127.0.0.1:${P.api}`);
    const st = v1.stats || {};
    info('/debug/vars', `stats.user keys: ${Object.keys(st.user || {}).join(', ') || 'none'} · stats.inbound keys: ${Object.keys(st.inbound || {}).join(', ') || 'none'}`);
    for (const name of ['alice', 'bob']) {
      const u = byName[name];
      const c1 = counterOf(v1, u, cfg), c0 = counterOf(v0, u, cfg) || { up: 0, down: 0 };
      const grew = c1 ? c1.down - c0.down : 0;
      gate(!!c1 && grew >= BIG[name], `${name}'s own counter grew by at least the ${BIG[name] / KB} KB fetched`,
        c1 ? `${c1.key}: down ${c1.down} (+${grew}), up ${c1.up}` : 'no counter for this user in /debug/vars — the builder\'s per-user stats (policy level statsUserUplink/Downlink, the account\'s user) are not on');
    }
    const cc = counterOf(v1, byName.carol, cfg);
    gate(!cc || (cc.down === 0 && cc.up === 0), 'carol (refused) has no bytes', cc ? `${cc.key}: down ${cc.down}, up ${cc.up}` : 'no counter');
  } catch (e) {
    gate(false, 'the probe', 'stopped: ' + e.message);
  }
  if (failed > before) {
    console.log('    the core logs (last lines):');
    console.log(client.tail(30));
    for (const s of servers) console.log(s.tail(5));
  }
  for (const p of pages) p.close();
  return finish(work);
}

function finish(work) {
  killAll();
  try { fs.rmSync(work, { recursive: true, force: true }); } catch { /* a core still closing */ }
  console.log(`\n${passed}/${passed + failed} gates passed — client ${path.basename(XRAY)}${SERVER_XRAY !== XRAY ? `, servers ${path.basename(SERVER_XRAY)}` : ''}`);
  process.exit(failed ? 1 : 0);
}

if (require.main === module) {
  process.on('exit', killAll);
  process.on('SIGINT', () => { killAll(); process.exit(130); });
  process.on('SIGTERM', () => { killAll(); process.exit(143); });
  // a hard limit: CI never hangs on a core that stopped answering
  setTimeout(() => { console.log('FAIL the probe ran out of time (120 s) — stopped'); killAll(); process.exit(1); }, 120000).unref();
  main().catch((e) => { console.log(`FAIL ${e && e.stack || e}`); killAll(); process.exit(1); });
}

module.exports = { buildProbeConfigs, probeLanUsers, probeServers, probeSettings, luInbounds, accountsOf, inboundFor, counterOf, P, APP_PORTS, ACTIVE, INACTIVE, BASE };
