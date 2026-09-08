'use strict';
/**
 * Where do the names actually go?
 *
 * `npm test` pins the JSON we emit and `npm run validate` proves the cores load
 * it. Neither says a word about the question the owner asked — "مقداری dns لیک
 * داریم" — because a leak is a *packet leaving somewhere it should not*, and no
 * amount of reading a config tells you that. This stands the resolver plan up on
 * loopback with two fake resolvers and watches which one every name lands on.
 *
 *   query ──socks──▶  client xray (the REAL buildConfig output)
 *                          │
 *                          ├── direct ────────────────▶  127.0.0.1:IR    "domestic"
 *                          │                                (in-country, cleartext UDP)
 *                          └── proxy ─socks─▶ hop xray ─▶  127.0.0.1:WORLD "remote"
 *                                              (redirect)
 *
 * Path attribution is by construction, not by guesswork: the domestic resolver
 * is a loopback address only a `direct` dial can reach, and the remote one is
 * 198.18.0.1 — an address that exists nowhere on this machine, so a query can
 * only arrive there by being carried through the exit, where the hop redirects
 * it to a socket we can read. A third socket, 127.0.0.9:53, is the *sink*:
 * nothing in the config names it, so a packet landing there is by definition a
 * query the core forwarded to its original destination instead of answering —
 * exactly the "non-IP query escapes" leak.
 *
 * Nothing here touches the machine's routes, adapters or firewall. Loopback and
 * two child processes, both killed on the way out.
 *
 *   IRNF_XRAY_EXE     extra core to run every scenario on (e.g. the PattN fork)
 *   IRNF_PROBE_PORT   base port, default 39800
 *   IRNF_PROBE_KEEP=1 keep the generated configs and print where they are
 *   IRNF_PROBE_BREAK   deliberately break the plan so the probe must FAIL:
 *                        scope    drop `domains`+`skipFallback` from the domestic server
 *                        nonip    drop the dns outbound's refuse rule
 *                      (a probe that cannot fail proves nothing — run these first)
 */
const fs = require('fs');
const os = require('os');
const net = require('net');
const path = require('path');
const dgram = require('dgram');
const { spawn } = require('child_process');
const { buildConfig } = require('../src/main/configBuilder');

const BASE = Number(process.env.IRNF_PROBE_PORT || 39800);
const P = { hop: BASE + 1, socks: BASE + 10, http: BASE + 11, api: BASE + 12, ir: BASE + 20, world: BASE + 21, corp: BASE + 22 };
const SINK_HOST = '127.0.0.9', SINK_PORT = 53;
const SINK6_HOST = '::1';
/** Reachable only through the exit: this address is on no interface here. */
const WORLD_HOST = '198.18.0.1';
const IR_ANSWER = '178.22.122.100';      // inside geoip:ir — survives expectedIPs
const WORLD_ANSWER = '93.184.216.34';
const BREAK = process.env.IRNF_PROBE_BREAK || '';

const exeName = (n) => (process.platform === 'win32' ? n + '.exe' : n);
const localXray = path.join(__dirname, '..', 'bin', exeName('xray'));
const cores = [];
for (const c of [localXray, process.env.IRNF_XRAY_EXE]) {
  if (c && fs.existsSync(c) && !cores.some(x => x.exe === c)) cores.push({ name: path.basename(c), exe: c });
}
if (!cores.length) {
  console.error('no core found — put xray in bin/ (npm run get-xray) or set IRNF_XRAY_EXE');
  process.exit(2);
}
/** geoip.dat/geosite.dat live next to whichever core we run. */
function assetDir(exe) { return path.dirname(exe); }
function hasGeo(exe) {
  const d = assetDir(exe);
  return fs.existsSync(path.join(d, 'geoip.dat')) && fs.existsSync(path.join(d, 'geosite.dat'));
}

/* ------------------------------ DNS wire bits ------------------------------ */

function encodeName(name) {
  const parts = String(name).split('.').filter(Boolean);
  const bufs = parts.map(p => Buffer.concat([Buffer.from([p.length]), Buffer.from(p, 'ascii')]));
  return Buffer.concat([...bufs, Buffer.from([0])]);
}

function encodeQuery(id, name, qtype) {
  const head = Buffer.alloc(12);
  head.writeUInt16BE(id, 0);
  head.writeUInt16BE(0x0100, 2);   // recursion desired
  head.writeUInt16BE(1, 4);        // QDCOUNT
  const tail = Buffer.alloc(4);
  tail.writeUInt16BE(qtype, 0);
  tail.writeUInt16BE(1, 2);        // IN
  return Buffer.concat([head, encodeName(name), tail]);
}

/** QNAME + QTYPE out of a query (no compression is legal in a question). */
function readQuestion(msg) {
  let i = 12; const parts = [];
  while (i < msg.length && msg[i]) {
    const len = msg[i];
    if (len > 63) return null;              // a pointer has no business here
    parts.push(msg.slice(i + 1, i + 1 + len).toString('ascii'));
    i += len + 1;
  }
  const qend = i + 1;
  if (qend + 4 > msg.length) return null;
  return { name: parts.join('.'), qtype: msg.readUInt16BE(qend), qend };
}

/** rcode + every A record, out of a response. */
function readAnswer(msg) {
  const rcode = msg.length >= 12 ? (msg.readUInt16BE(2) & 0x0f) : -1;
  const q = readQuestion(msg);
  const ips = [];
  if (q) {
    const an = msg.readUInt16BE(6);
    let i = q.qend + 4;
    for (let n = 0; n < an && i + 12 <= msg.length; n++) {
      if ((msg[i] & 0xc0) === 0xc0) i += 2;
      else { while (i < msg.length && msg[i]) i += msg[i] + 1; i += 1; }
      if (i + 10 > msg.length) break;
      const type = msg.readUInt16BE(i);
      const rdlen = msg.readUInt16BE(i + 8);
      const rd = msg.slice(i + 10, i + 10 + rdlen);
      if (type === 1 && rdlen === 4) ips.push(Array.from(rd).join('.'));
      i += 10 + rdlen;
    }
  }
  return { rcode, ips };
}

/**
 * A resolver that answers everything with one address and remembers every
 * question it was asked. UDP and TCP (the length-prefixed form), because the
 * domestic server is dialled over UDP and the remote one rides TCP through the
 * exit — the socks hop carries a stream far more reliably than a UDP associate,
 * and the server-selection logic under test does not know the difference.
 */
function fakeResolver(port, host, answerIp, label) {
  const seen = [];
  let muted = false;
  const reply = (msg) => {
    const q = readQuestion(msg);
    const head = Buffer.from(msg.slice(0, 12));
    head.writeUInt16BE(0x8180, 2);
    if (!q) { head.writeUInt16BE(0, 6); return head; }
    seen.push({ name: q.name, qtype: q.qtype });
    const body = msg.slice(12, q.qend + 4);
    const answers = q.qtype === 1
      ? Buffer.concat([Buffer.from([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4]), Buffer.from(answerIp.split('.').map(Number))])
      : Buffer.alloc(0);
    head.writeUInt16BE(1, 4);
    head.writeUInt16BE(q.qtype === 1 ? 1 : 0, 6);
    return Buffer.concat([head, body, answers]);
  };

  const u = dgram.createSocket('udp4');
  u.on('message', (msg, ri) => { const r = reply(msg); if (!muted) u.send(r, ri.port, ri.address); });
  const t = net.createServer((sock) => {
    let buf = Buffer.alloc(0);
    sock.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      while (buf.length >= 2 && buf.length >= 2 + buf.readUInt16BE(0)) {
        const len = buf.readUInt16BE(0);
        const msg = buf.slice(2, 2 + len);
        buf = buf.slice(2 + len);
        const r = reply(msg);
        if (muted) continue;              // heard the question, never answers
        const out = Buffer.alloc(2); out.writeUInt16BE(r.length, 0);
        sock.write(Buffer.concat([out, r]));
      }
    });
    sock.on('error', () => {});
  });
  return new Promise((res) => {
    u.bind(port, host, () => t.listen(port, host, () => res({
      label, seen,
      names: () => seen.map(x => x.name),
      reset: () => { seen.length = 0; muted = false; },
      mute: () => { muted = true; },
      close: () => { try { u.close(); } catch {} try { t.close(); } catch {} }
    })));
  });
}

/**
 * The sink. Nothing in any generated config names 127.0.0.9:53, so a packet
 * here is a query the core sent to its ORIGINAL destination — i.e. one that
 * escaped the internal resolver instead of being answered or refused.
 */
function sink(host, family) {
  const hits = [];
  const u = dgram.createSocket(family === 6 ? 'udp6' : 'udp4');
  u.on('message', (msg) => { const q = readQuestion(msg); hits.push({ proto: 'udp', name: q && q.name, qtype: q && q.qtype }); });
  const t = net.createServer((sock) => {
    hits.push({ proto: 'tcp-connect', name: null, qtype: null });
    sock.on('data', (d) => {
      if (d.length > 2) { const q = readQuestion(d.slice(2)); hits.push({ proto: 'tcp', name: q && q.name, qtype: q && q.qtype }); }
    });
    sock.on('error', () => {});
  });
  return new Promise((res) => {
    u.bind(SINK_PORT, host, () => t.listen(SINK_PORT, host, () => res({
      hits, reset: () => { hits.length = 0; },
      close: () => { try { u.close(); } catch {} try { t.close(); } catch {} }
    })));
  });
}

/* -------------------------------- the cores -------------------------------- */

const work = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-dnsprobe-'));
const children = [];

function startCore(exe, cfg, name) {
  const file = path.join(work, name + '.json');
  fs.writeFileSync(file, JSON.stringify(cfg, null, 2));
  const proc = spawn(exe, ['run', '-c', file], {
    cwd: assetDir(exe), windowsHide: true,
    env: Object.assign({}, process.env, { XRAY_LOCATION_ASSET: assetDir(exe), V2RAY_LOCATION_ASSET: assetDir(exe) })
  });
  const out = { proc, log: '', file };
  const grab = (d) => { out.log = (out.log + d.toString('utf8')).slice(-400000); };
  proc.stdout.on('data', grab);
  proc.stderr.on('data', grab);
  children.push(proc);
  return out;
}

function stopCore(c) {
  if (!c || !c.proc) return;
  try { c.proc.kill(); } catch {}
  const i = children.indexOf(c.proc);
  if (i >= 0) children.splice(i, 1);
}

function waitPort(port, host, ms) {
  const deadline = Date.now() + ms;
  return new Promise((resolve, reject) => {
    const tick = () => {
      const s = net.connect(port, host);
      s.on('connect', () => { s.destroy(); resolve(); });
      s.on('error', () => {
        s.destroy();
        if (Date.now() > deadline) return reject(new Error(`port ${host}:${port} never opened`));
        setTimeout(tick, 120);
      });
    };
    tick();
  });
}

/** The exit: everything that reaches it is redirected to the remote resolver. */
function hopConfig() {
  return {
    log: { loglevel: 'warning' },
    inbounds: [{ tag: 'in', port: P.hop, listen: '127.0.0.1', protocol: 'socks', settings: { auth: 'noauth', udp: true } }],
    outbounds: [{ tag: 'redir', protocol: 'freedom', settings: { redirect: `127.0.0.1:${P.world}` } }]
  };
}

/* ------------------------------ asking a name ------------------------------ */

/** SOCKS5 address block for a literal IPv4/IPv6 destination. */
function socksAddr(host, port) {
  const v6 = host.includes(':');
  const body = v6
    ? Buffer.concat([Buffer.from([4]), Buffer.from(expandV6(host))])
    : Buffer.concat([Buffer.from([1]), Buffer.from(host.split('.').map(Number))]);
  return Buffer.concat([body, Buffer.from([port >> 8, port & 0xff])]);
}

/** '::1' → the 16 bytes. Only the forms this file uses. */
function expandV6(host) {
  const [head, tail] = host.split('::');
  const h = head ? head.split(':') : [];
  const t = tail ? tail.split(':') : [];
  const mid = new Array(8 - h.length - t.length).fill('0');
  const parts = host.includes('::') ? [...h, ...mid, ...t] : host.split(':');
  const b = Buffer.alloc(16);
  parts.forEach((p, i) => b.writeUInt16BE(parseInt(p || '0', 16), i * 2));
  return b;
}

/**
 * A DNS query through the client's SOCKS inbound, aimed at a sink nothing in
 * the config names. `proto` picks the transport the OS would use: udp is what a
 * machine under TUN actually sends, tcp is the fallback every resolver library
 * has. `host` picks the address family.
 */
function ask(name, qtype, opts = {}) {
  const proto = opts.proto || 'tcp';
  const host = opts.host || SINK_HOST;
  return new Promise((resolve) => {
    const sock = net.connect(P.socks, '127.0.0.1');
    let stage = 0, buf = Buffer.alloc(0), udp = null;
    const done = (v) => { try { sock.destroy(); } catch {} if (udp) try { udp.close(); } catch {} resolve(v); };
    const timer = setTimeout(() => done({ error: 'timeout' }), opts.timeout || 8000);
    sock.on('error', (e) => { clearTimeout(timer); done({ error: e.code || e.message }); });
    sock.on('connect', () => sock.write(Buffer.from([5, 1, 0])));
    sock.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      if (stage === 0) {
        if (buf.length < 2) return;
        buf = buf.slice(2); stage = 1;
        // CMD 1 = CONNECT, 3 = UDP ASSOCIATE (with a 0.0.0.0:0 request address)
        sock.write(proto === 'udp'
          ? Buffer.concat([Buffer.from([5, 3, 0]), socksAddr('0.0.0.0', 0)])
          : Buffer.concat([Buffer.from([5, 1, 0]), socksAddr(host, SINK_PORT)]));
      }
      if (stage === 1) {
        // reply: VER REP RSV ATYP ADDR PORT — length depends on ATYP
        if (buf.length < 5) return;
        const atyp = buf[3];
        const n = atyp === 1 ? 10 : atyp === 4 ? 22 : 7 + buf[4];
        if (buf.length < n) return;
        const rep = buf[1];
        const bndPort = buf.readUInt16BE(n - 2);
        buf = buf.slice(n); stage = 2;
        if (rep !== 0) { clearTimeout(timer); return void done({ error: 'socks rep ' + rep }); }
        const q = encodeQuery(0x1234, name, qtype);
        if (proto === 'udp') {
          // The relay is always 127.0.0.1 — only the DESTINATION inside the
          // SOCKS header may be v6, so the socket that carries it is v4.
          udp = dgram.createSocket('udp4');
          udp.on('message', (msg) => {
            clearTimeout(timer);
            const hdrLen = msg[3] === 1 ? 10 : msg[3] === 4 ? 22 : 7 + msg[4];
            done(readAnswer(msg.slice(hdrLen)));
          });
          udp.send(Buffer.concat([Buffer.from([0, 0, 0]), socksAddr(host, SINK_PORT), q]), bndPort, '127.0.0.1');
          return;
        }
        const len = Buffer.alloc(2); len.writeUInt16BE(q.length, 0);
        sock.write(Buffer.concat([len, q]));
      }
      if (stage === 2 && proto !== 'udp') {
        if (buf.length < 2 || buf.length < 2 + buf.readUInt16BE(0)) return;
        clearTimeout(timer);
        done(readAnswer(buf.slice(2, 2 + buf.readUInt16BE(0))));
      }
    });
  });
}

/* --------------------------------- scenarios --------------------------------- */

const IR_NAMES = ['digikala.com', 'varzesh3.com', 'snapp.ir', 'bmi.ir'];
const WORLD_NAMES = ['example.com', 'www.google.com', 'github.com', 'facebook.com'];

/** The plan: one "server" that is a plain socks dial to the hop. */
const HOP_SERVER = {
  id: 'sv-hop', name: 'hop', protocol: 'socks', address: '127.0.0.1', port: P.hop,
  outbound: { protocol: 'socks', settings: { servers: [{ address: '127.0.0.1', port: P.hop }] } }
};
const PLAN = { mode: 'single', server: HOP_SERVER };

/**
 * A stand-in for the corporate WireGuard: the RECORD says wireguard (which is
 * all `isWgServer`/`wgResolvers` look at, so the resolver plan treats it exactly
 * as it treats a real `.conf` import) while the OUTBOUND is a plain freedom, so
 * the query it carries actually arrives somewhere we can read. Its resolver
 * knows only `corp.test`.
 */
const CORP_SERVER = {
  id: 'sv-corp', name: 'corp', protocol: 'wireguard', address: '127.0.0.1', port: 51820,
  dns: [`127.0.0.1:${P.corp}`], dnsDomains: ['corp.test'],
  outbound: { protocol: 'freedom', settings: {} }
};
const CORP_PLAN = {
  mode: 'advanced',
  serversById: { 'sv-hop': HOP_SERVER, 'sv-corp': CORP_SERVER }, chainsById: {}, chain: [],
  rules: [{ type: 'ip', value: '10.44.0.0/16', target: 'sv-corp' }],
  def: 'sv-hop'
};

function baseSettings(over) {
  return Object.assign({
    socksPort: P.socks, httpPort: P.http, apiPort: P.api,
    allowLan: false, blockAds: false, enableSniffing: true,
    dnsManaged: true,
    dnsRemote: [`tcp://${WORLD_HOST}:${P.world}`],
    dnsDirect: [`127.0.0.1:${P.ir}`],
    ipv6: false, logLevel: 'debug', customRules: [], geoAssets: true,
    routingMode: 'global'
  }, over || {});
}

/** IRNF_PROBE_BREAK: make the config leak on purpose, so the probe can fail. */
function sabotage(cfg) {
  if (BREAK === 'scope') {
    for (const s of cfg.dns.servers) {
      if (s && typeof s === 'object' && s.address === '127.0.0.1') { delete s.domains; delete s.skipFallback; delete s.expectedIPs; }
    }
  }
  if (BREAK === 'nonip') {
    // `skip` is the old behaviour the refuse rule replaced: a non-IP query is
    // forwarded to the address the client asked — which is the sink.
    const o = cfg.outbounds.find(x => x.protocol === 'dns');
    if (o) o.settings = { nonIPQuery: 'skip' };
  }
  return cfg;
}

const scenarios = [
  {
    id: 'bypass-ir',
    why: 'the domestic resolver must see Iranian names ONLY',
    settings: { routingMode: 'bypass-ir' },
    names: [...IR_NAMES, ...WORLD_NAMES],
    check(r) {
      const bad = r.ir.filter(n => !IR_NAMES.includes(n));
      return [
        [bad.length === 0, `domestic resolver saw only Iranian names (${r.ir.join(', ') || 'none'})`, `LEAK: domestic resolver saw ${bad.join(', ')}`],
        [r.world.some(n => WORLD_NAMES.includes(n)), 'world names went to the remote resolver', 'the remote resolver was never asked — rig broken'],
        [r.sink.length === 0, 'nothing escaped to the original destination', `LEAK: ${r.sink.length} packet(s) reached the sink`]
      ];
    }
  },
  {
    id: 'global',
    why: 'routingMode global must not build a domestic resolver at all',
    settings: { routingMode: 'global' },
    names: [...IR_NAMES, ...WORLD_NAMES],
    check(r) {
      return [
        [r.ir.length === 0, 'the domestic resolver was never contacted', `LEAK: domestic resolver saw ${r.ir.join(', ')}`],
        [r.sink.length === 0, 'nothing escaped to the original destination', `LEAK: ${r.sink.length} packet(s) reached the sink`]
      ];
    }
  },
  {
    id: 'bypass-ir-nogeo',
    why: 'without geo files bypass-ir routes EVERYTHING through the proxy — the domestic resolver should go with it',
    settings: { routingMode: 'bypass-ir', geoAssets: false },
    names: [...IR_NAMES, ...WORLD_NAMES],
    check(r) {
      return [
        [r.ir.length === 0, 'the domestic resolver was never contacted', `LEAK: domestic resolver saw ${r.ir.join(', ')} while every byte of traffic is proxied`],
        [r.sink.length === 0, 'nothing escaped to the original destination', `LEAK: ${r.sink.length} packet(s) reached the sink`]
      ];
    }
  },
  {
    id: 'remote-dead',
    why: 'when the DoH resolver stops answering, the domestic one must NOT inherit the world',
    settings: { routingMode: 'bypass-ir' },
    mute: 'remote',
    timeout: 25000,
    names: ['example.com', 'github.com'],
    check(r) {
      return [
        [r.ir.length === 0, 'the domestic resolver was not offered the names the DoH could not answer',
          `LEAK: with the remote resolver dead, the domestic one was asked about ${r.ir.join(', ')}`],
        [r.sink.length === 0, 'nothing escaped to the original destination', `LEAK: ${r.sink.length} packet(s) reached the sink`]
      ];
    }
  },
  {
    id: 'transports',
    why: 'the port-53 hijack must catch UDP and TCP, to a v4 and a v6 destination',
    settings: { routingMode: 'bypass-ir' },
    asks: [
      ['snapp.ir', 1, { proto: 'udp' }], ['example.com', 1, { proto: 'udp' }],
      ['snapp.ir', 1, { proto: 'tcp' }], ['example.com', 1, { proto: 'tcp' }],
      ['snapp.ir', 1, { proto: 'udp', host: SINK6_HOST }], ['example.com', 1, { proto: 'udp', host: SINK6_HOST }],
      ['snapp.ir', 1, { proto: 'tcp', host: SINK6_HOST }], ['example.com', 1, { proto: 'tcp', host: SINK6_HOST }]
    ],
    check(r) {
      const answered = r.answers.filter(a => a.rcode === 0 && a.ips && a.ips.length);
      return [
        [r.sink.length === 0 && r.sink6.length === 0, 'every transport was hijacked — nothing reached either sink',
          `LEAK: v4 sink ${r.sink.length}, v6 sink ${r.sink6.length} packet(s)`],
        [answered.length === r.answers.length, 'all 8 queries were answered by the core',
          'unanswered: ' + r.answers.filter(a => !(a.rcode === 0 && a.ips && a.ips.length)).map(a => `${a.name}/${a.opts.proto}/${a.opts.host || 'v4'}`).join(', ')]
      ];
    }
  },
  {
    id: 'nonip-types',
    why: 'PTR/TXT/HTTPS/SVCB queries must be refused, never forwarded',
    settings: { routingMode: 'bypass-ir' },
    asks: [['example.com', 16, {}], ['example.com', 65, {}], ['1.0.0.127.in-addr.arpa', 12, {}], ['example.com', 33, {}],
      ['example.com', 16, { proto: 'udp' }], ['example.com', 65, { proto: 'udp' }]],
    check(r) {
      return [
        [r.sink.length === 0, 'no non-IP query left the core', `LEAK: ${r.sink.map(h => h.proto + ' ' + h.name).join(', ')} reached the sink`],
        [r.answers.every(a => a.rcode === 5), 'every non-IP query was REFUSED', 'rcodes: ' + r.answers.map(a => a.rcode).join(',')]
      ];
    }
  },
  {
    id: 'corp-resolver',
    why: 'a routing target\'s own resolver must see its search domains, not the public web',
    plan: CORP_PLAN,
    settings: { routingMode: 'global' },
    names: ['git.corp.test', ...WORLD_NAMES],
    check(r) {
      const stray = r.corp.filter(n => !n.endsWith('corp.test'));
      return [
        [r.corp.includes('git.corp.test'), 'the corporate resolver answered its own search domain', 'the corporate resolver was never asked — rig broken'],
        [stray.length === 0, 'no public name went to the corporate resolver', `LEAK: the company was asked about ${stray.join(', ')}`],
        [r.sink.length === 0, 'nothing escaped to the original destination', `LEAK: ${r.sink.length} packet(s) reached the sink`]
      ];
    }
  },
  {
    id: 'aaaa-ipv4only',
    why: 'ipv6:false must not put an AAAA question on the wire',
    settings: { routingMode: 'bypass-ir' },
    asks: [['snapp.ir', 28, {}], ['example.com', 28, {}], ['snapp.ir', 28, { proto: 'udp' }], ['example.com', 28, { proto: 'udp' }]],
    check(r) {
      const v6 = [...r.irQ, ...r.worldQ].filter(q => q.qtype === 28);
      return [
        [v6.length === 0, 'no AAAA question reached any upstream resolver', `LEAK: AAAA asked upstream for ${v6.map(q => q.name).join(', ')}`],
        [r.sink.length === 0, 'nothing escaped to the original destination', `LEAK: ${r.sink.length} packet(s) reached the sink`]
      ];
    }
  }
];

/* ---------------------------------- driver ---------------------------------- */

async function run() {
  const ir = await fakeResolver(P.ir, '127.0.0.1', IR_ANSWER, 'domestic');
  const world = await fakeResolver(P.world, '127.0.0.1', WORLD_ANSWER, 'remote');
  const corp = await fakeResolver(P.corp, '127.0.0.1', '10.44.1.9', 'corporate');
  const sk = await sink(SINK_HOST, 4);
  const sk6 = await sink(SINK6_HOST, 6);
  let failures = 0, checks = 0;

  if (BREAK) console.log(`!! IRNF_PROBE_BREAK=${BREAK}: the config is sabotaged on purpose — the run below MUST fail\n`);

  for (const core of cores) {
    console.log(`\n=== ${core.name} ${hasGeo(core.exe) ? '' : '(no geo files next to it — geo scenarios are meaningless)'}`);
    const hop = startCore(core.exe, hopConfig(), 'hop-' + core.name);
    try {
      await waitPort(P.hop, '127.0.0.1', 8000);
    } catch (e) {
      console.log('  hop did not start: ' + e.message + '\n' + hop.log.slice(-500));
      stopCore(hop); failures++; continue;
    }

    for (const sc of scenarios) {
      ir.reset(); world.reset(); corp.reset(); sk.reset(); sk6.reset();
      const settings = baseSettings(sc.settings);
      const cfg = sabotage(buildConfig(sc.plan || PLAN, settings));
      const client = startCore(core.exe, cfg, `${sc.id}-${core.name}`);
      let up = true;
      try { await waitPort(P.socks, '127.0.0.1', 8000); } catch { up = false; }
      if (!up) {
        console.log(`\n  [${sc.id}] client core did not start:\n    ` + client.log.trim().split(/\r?\n/).slice(-4).join('\n    '));
        stopCore(client); failures++; continue;
      }

      if (sc.mute === 'remote') world.mute();
      const answers = [];
      const asks = (sc.asks || (sc.names || []).map(n => [n, 1, {}]))
        .map(([n, q, o]) => [n, q, Object.assign({}, o, sc.timeout ? { timeout: sc.timeout } : null)]);
      for (const [name, qtype, o] of asks) answers.push(Object.assign({ name, qtype, opts: o || {} }, await ask(name, qtype, o)));
      await new Promise(r => setTimeout(r, 300));

      const r = {
        ir: [...new Set(ir.names())], world: [...new Set(world.names())], corp: [...new Set(corp.names())],
        irQ: ir.seen.slice(), worldQ: world.seen.slice(), corpQ: corp.seen.slice(),
        sink: sk.hits.slice(), sink6: sk6.hits.slice(), answers
      };
      console.log(`\n  [${sc.id}] ${sc.why}`);
      console.log(`    domestic saw : ${r.ir.join(', ') || '(nothing)'}`);
      console.log(`    remote saw   : ${r.world.join(', ') || '(nothing)'}`);
      if (sc.plan === CORP_PLAN) console.log(`    corporate saw: ${r.corp.join(', ') || '(nothing)'}`);
      console.log(`    sink v4/v6   : ${r.sink.length ? r.sink.map(h => `${h.proto}:${h.name || '?'}`).join(', ') : '(nothing)'} / ${r.sink6.length ? r.sink6.map(h => `${h.proto}:${h.name || '?'}`).join(', ') : '(nothing)'}`);
      console.log(`    answers      : ${answers.map(a => `${a.name}/${a.qtype}${a.opts.proto === 'udp' ? '/udp' : ''}${a.opts.host ? '/v6' : ''}→${a.error || 'rcode' + a.rcode + (a.ips && a.ips.length ? ' ' + a.ips.join('+') : '')}`).join('  ')}`);
      const detours = [...new Set((client.log.match(/taking detour \[[^\]]*\] for \[[^\]]*\]/g) || []))];
      for (const d of detours.slice(0, 12)) console.log(`    router       : ${d}`);

      for (const [ok, good, bad] of sc.check(r)) {
        checks++;
        if (ok) console.log(`    PASS  ${good}`);
        else { failures++; console.log(`    FAIL  ${bad}`); }
      }
      stopCore(client);
    }
    stopCore(hop);
  }

  ir.close(); world.close(); corp.close(); sk.close(); sk6.close();
  console.log(`\n${checks - failures}/${checks} checks passed`);
  if (process.env.IRNF_PROBE_KEEP) console.log('configs kept in ' + work);
  else try { fs.rmSync(work, { recursive: true, force: true }); } catch {}
  process.exit(failures ? 1 : 0);
}

process.on('exit', () => { for (const c of children) { try { c.kill(); } catch {} } });
run().catch((e) => { console.error(e); for (const c of children) { try { c.kill(); } catch {} } process.exit(2); });
