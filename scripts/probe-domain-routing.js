#!/usr/bin/env node
'use strict';
/**
 * Which outbound does a real core choose, for a connection that arrives the way a
 * TUN hands it over: a bare address, with the name only in the first bytes? The
 * rules and the sniffing are the app's own (configBuilder, sniffRules.js). Loopback
 * only: every outbound is a freedom redirected to a local sink, the resolver a table.
 *
 *   this probe ─SOCKS5 to an address─▶ socks-in ─▶ the sink of the outbound it chose
 *
 * Gates, each a thing that was wrong with one setting or the other:
 *   corporate      an address in an IP rule goes to that rule's target, whatever name
 *                  it carries: its own, one that resolves elsewhere, one nobody knows
 *   wrong address  a public address with a corporate name still reaches the VPN
 *   LAN            a private address stays direct, whatever name it carries
 *   by name        a name in a domain rule, and under it, reaches its target, in each
 *                  way of writing it; a name that merely contains it does not
 *   poison         a poisoned address still has its name read
 *   QUIC           an Initial the core can read follows its name; one it cannot is
 *                  refused, so the browser falls back to TCP. Never the default
 *   a VPN behind   an address with someone else's name in its TLS, as a client behind
 *                  the router dials its server: with the router's setting the next hop
 *                  is asked for the address, with a desktop's for the name (the control)
 *
 *   IRNF_XRAY_EXE     the core under test
 *   IRNF_PROBE_PORT   base port
 */
const { spawn } = require('child_process');
const crypto = require('crypto');
const dgram = require('dgram');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { buildConfig } = require('../src/main/configBuilder');
const { parseLink } = require('../src/main/parser');

const XRAY = process.env.IRNF_XRAY_EXE || (process.platform === 'win32' ? 'bin/xray.exe' : 'bin/xray');
const BASE = Number(process.env.IRNF_PROBE_PORT || 24900);
const PORTS = { socks: BASE, http: BASE + 1, api: BASE + 2, target: BASE + 3, default: BASE + 4, wg: BASE + 5, direct: BASE + 6, nextHop: BASE + 7 };
const SINKS = ['target', 'default', 'wg', 'direct'];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let failed = 0;
function gate(ok, name, detail) {
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}${detail ? ' — ' + detail : ''}`);
  if (!ok) failed++;
}

/* ---------- the first bytes of a connection ---------- */

function ext(type, body) { const h = Buffer.alloc(4); h.writeUInt16BE(type, 0); h.writeUInt16BE(body.length, 2); return Buffer.concat([h, body]); }
function sniExt(name) {
  const n = Buffer.from(name);
  const b = Buffer.alloc(5 + n.length);
  b.writeUInt16BE(n.length + 3, 0); b[2] = 0; b.writeUInt16BE(n.length, 3); n.copy(b, 5);
  return ext(0, b);
}
function clientHello(name) {
  const e = Buffer.concat([sniExt(name), ext(43, Buffer.from([2, 3, 4]))]);
  const eLen = Buffer.alloc(2); eLen.writeUInt16BE(e.length);
  const body = Buffer.concat([
    Buffer.from([3, 3]), crypto.randomBytes(32), Buffer.from([32]), crypto.randomBytes(32),
    Buffer.from([0, 4, 0x13, 0x01, 0x13, 0x02]), Buffer.from([1, 0]), eLen, e
  ]);
  const h = Buffer.alloc(4); h[0] = 1; h.writeUIntBE(body.length, 1, 3);
  return Buffer.concat([h, body]);
}
function tlsRecord(name) {
  const ch = clientHello(name);
  const h = Buffer.from([22, 3, 1, 0, 0]); h.writeUInt16BE(ch.length, 3);
  return Buffer.concat([h, ch]);
}

function varint(n) {
  if (n < 64) return Buffer.from([n]);
  const b = Buffer.alloc(2); b.writeUInt16BE(n | 0x4000); return b;
}
function expand(prk, label, len) {
  const full = Buffer.from('tls13 ' + label);
  const info = Buffer.concat([Buffer.from([len >> 8, len & 255, full.length]), full, Buffer.from([0])]);
  let t = Buffer.alloc(0), out = Buffer.alloc(0), i = 1;
  while (out.length < len) { t = crypto.createHmac('sha256', prk).update(Buffer.concat([t, info, Buffer.from([i++])])).digest(); out = Buffer.concat([out, t]); }
  return out.subarray(0, len);
}
const cryptoFrame = (offset, data) => Buffer.concat([Buffer.from([6]), varint(offset), varint(data.length), data]);
/** A QUIC v1 Initial (RFC 9001): its keys derive from the connection id alone, so anyone can read it, the core too. */
function initialPacket(frames) {
  const dcid = crypto.randomBytes(8);
  const initial = crypto.createHmac('sha256', Buffer.from('38762cf7f55934b34d179ae6a4c80cadccbb7f0a', 'hex')).update(dcid).digest();
  const secret = expand(initial, 'client in', 32);
  const key = expand(secret, 'quic key', 16), iv = expand(secret, 'quic iv', 12), hp = expand(secret, 'quic hp', 16);
  let payload = Buffer.concat(frames);
  const minPayload = 1200 - (1 + 4 + 1 + dcid.length + 1 + 1 + 2 + 2) - 16;
  if (payload.length < minPayload) payload = Buffer.concat([payload, Buffer.alloc(minPayload - payload.length)]);
  const lenField = Buffer.alloc(2); lenField.writeUInt16BE((payload.length + 2 + 16) | 0x4000);
  const pn = Buffer.from([0, 0]);
  const header = Buffer.concat([Buffer.from([0xc1, 0, 0, 0, 1, dcid.length]), dcid, Buffer.from([0, 0]), lenField, pn]);
  const c = crypto.createCipheriv('aes-128-gcm', key, iv); c.setAAD(header);
  const ct = Buffer.concat([c.update(payload), c.final(), c.getAuthTag()]);
  const e = crypto.createCipheriv('aes-128-ecb', hp, null); e.setAutoPadding(false);
  const mask = e.update(ct.subarray(2, 18));
  const out = Buffer.concat([header, ct]);
  out[0] ^= mask[0] & 0x0f;
  out[header.length - 2] ^= mask[1];
  out[header.length - 1] ^= mask[2];
  return out;
}
const quicPlain = (name) => initialPacket([cryptoFrame(0, clientHello(name))]);
/** As Chrome sends it: the hello cut in CRYPTO frames, shuffled, with PING and PADDING between. */
function quicChrome(name) {
  const ch = clientHello(name);
  const cut = [0, 20, 61, 90, 130, ch.length];
  const f = [];
  for (let i = 0; i < cut.length - 1; i++) f.push(cryptoFrame(cut[i], ch.subarray(cut[i], cut[i + 1])));
  return initialPacket([f[3], Buffer.from([1]), f[0], Buffer.alloc(9), f[4], f[2], Buffer.from([1]), f[1]]);
}

/* ---------- the app's rules on a core with sinks for outbounds ---------- */

const server = (tag) => parseLink(`vless://11111111-1111-1111-1111-111111111111@192.0.2.1:443?type=tcp&security=none#${tag}`);
const BASE_SRV = Object.assign(server('base'), { id: 'sv-base' });
const TARGET_SRV = Object.assign(server('target'), { id: 'sv-target' });
const WG_SRV = {
  id: 'sv-wg', name: 'corp', protocol: 'wireguard', address: 'corp.example', port: 51820, dns: ['192.0.2.53'], dnsDomains: ['corp.example'],
  outbound: { protocol: 'wireguard', settings: { secretKey: 'cHJpdmF0ZS1rZXktZm9yLWEtcHJvYmUtb25seS1hYWE=', address: ['172.20.0.2/32'], peers: [{ publicKey: 'cHVibGljLWtleS1mb3ItYS1wcm9iZS1vbmx5LWFhYWE=', endpoint: '192.0.2.2:51820', allowedIPs: ['192.168.0.0/16', '10.0.0.0/8'] }] } }
};
const PLAN = {
  mode: 'advanced', serversById: { 'sv-base': BASE_SRV, 'sv-target': TARGET_SRV, 'sv-wg': WG_SRV }, chainsById: {}, chain: [], def: 'sv-base',
  rules: [
    { type: 'ip', value: '192.168.0.0/16, 10.0.0.0/8', target: 'sv-wg' },
    { type: 'domain', value: 'claude.ai, *anthropic.com, *.wild.example, x.com', target: 'sv-target' }
  ]
};
// what the corporate resolver and a public one would say, with no network
const HOSTS = {
  'host.corp.example': '10.20.30.40', 'public-name.example': '93.184.216.34', 'claude.ai': '160.79.104.10', 'www.claude.ai': '160.79.104.10',
  'api.anthropic.com': '160.79.104.10', 'a.wild.example': '93.184.216.34', 'x.com': '93.184.216.34', 'netflix.com': '93.184.216.34'
};

function coreConfig() {
  const c = buildConfig(PLAN, { socksPort: PORTS.socks, httpPort: PORTS.http, apiPort: PORTS.api, geoAssets: false, blockAds: false, enableSniffing: true, dnsManaged: true, logLevel: 'warning' });
  const rules = c.routing.rules;
  const tagOf = (pred) => (rules.find(pred) || {}).outboundTag;
  const roles = {
    [tagOf((r) => (r.ip || []).includes('10.0.0.0/8') && !(r.ip || []).includes('127.0.0.0/8'))]: 'wg',
    [tagOf((r) => (r.domain || []).includes('domain:claude.ai'))]: 'target',
    [rules.at(-1).outboundTag]: 'default',
    direct: 'direct'
  };
  c.outbounds = c.outbounds.map((o) => (roles[o.tag]
    ? { tag: o.tag, protocol: 'freedom', settings: { redirect: `127.0.0.1:${PORTS[roles[o.tag]]}` } }
    : { tag: o.tag, protocol: 'blackhole' }));
  c.dns = { hosts: HOSTS, servers: ['localhost'], queryStrategy: 'UseIPv4' };
  c.inbounds = c.inbounds.filter((i) => i.tag === 'socks-in');
  delete c.metrics; delete c.stats; delete c.policy;
  return c;
}

/* ---------- SOCKS5 ---------- */

function socksStep(onReply) {
  return new Promise((resolve, reject) => {
    const c = net.connect(PORTS.socks, '127.0.0.1');
    let stage = 0;
    c.on('error', reject);
    c.on('connect', () => c.write(Buffer.from([5, 1, 0])));
    c.on('data', (d) => {
      if (stage++ === 0) c.write(onReply());
      else if (stage === 2) { c.removeAllListeners('data'); resolve({ c, reply: d }); }
    });
  });
}
const v4 = (ip) => ip.split('.').map(Number);
const connectTo = (ip) => socksStep(() => Buffer.from([5, 1, 0, 1, ...v4(ip), 1, 187]));
const udpAssociate = () => socksStep(() => Buffer.from([5, 3, 0, 1, 0, 0, 0, 0, 0, 0]));

/** The app's config for one server, whose outbound is a SOCKS hop that says what it was asked for. */
async function askedOfNextHop(settings) {
  let asked = null;
  const hop = net.createServer((c) => {
    let stage = 0;
    c.on('error', () => {});
    c.on('data', (d) => {
      if (stage === 0) { stage = 1; c.write(Buffer.from([5, 0])); return; }
      if (stage === 1) {
        stage = 2;
        asked = d[3] === 1 ? [...d.subarray(4, 8)].join('.') : d.subarray(5, 5 + d[4]).toString();
        c.write(Buffer.from([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]));
      }
    });
  });
  await new Promise((r) => hop.listen(PORTS.nextHop, '127.0.0.1', r));
  const c = buildConfig({ mode: 'single', server: BASE_SRV }, Object.assign({ socksPort: PORTS.socks, httpPort: PORTS.http, apiPort: PORTS.api, geoAssets: false, blockAds: false, enableSniffing: true, dnsManaged: false, dnsRemote: ['127.0.0.1'], logLevel: 'warning' }, settings));
  c.outbounds = c.outbounds.map((o) => (o.tag === 'proxy' ? { tag: 'proxy', protocol: 'socks', settings: { servers: [{ address: '127.0.0.1', port: PORTS.nextHop }] } } : o));
  c.inbounds = c.inbounds.filter((i) => i.tag === 'socks-in');
  delete c.metrics; delete c.stats; delete c.policy;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'probe-hop-'));
  const file = path.join(dir, 'c.json');
  fs.writeFileSync(file, JSON.stringify(c));
  const core = spawn(XRAY, ['run', '-c', file], { stdio: 'ignore' });
  let up = false;
  for (let i = 0; i < 50 && !up; i++) {
    await sleep(100);
    up = await new Promise((r) => { const s = net.connect(PORTS.socks, '127.0.0.1', () => { s.destroy(); r(true); }); s.on('error', () => r(false)); });
  }
  const { c: conn } = await connectTo('203.0.113.9');
  conn.write(tlsRecord('www.google.com'));
  for (let i = 0; i < 100 && !asked; i++) await sleep(40);
  conn.destroy();
  core.kill();
  hop.close();
  await sleep(250);
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* still closing */ }
  return asked || 'nothing';
}

/* ---------- the run ---------- */

(async () => {
  const hits = [];
  const servers = [];
  for (const tag of SINKS) {
    const t = net.createServer((s) => { hits.push({ tag, net: 'tcp' }); s.on('data', () => {}); s.on('error', () => {}); });
    await new Promise((r) => t.listen(PORTS[tag], '127.0.0.1', r));
    const u = dgram.createSocket('udp4');
    u.on('message', () => hits.push({ tag, net: 'udp' }));
    await new Promise((r) => u.bind(PORTS[tag], '127.0.0.1', r));
    servers.push(t, u);
  }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'probe-domains-'));
  const file = path.join(dir, 'c.json');
  fs.writeFileSync(file, JSON.stringify(coreConfig()));
  const core = spawn(XRAY, ['run', '-c', file], { stdio: ['ignore', 'pipe', 'pipe'] });
  let said = '';
  core.stdout.on('data', (d) => { said += d; });
  core.stderr.on('data', (d) => { said += d; });
  let up = false;
  for (let i = 0; i < 50 && !up; i++) {
    await sleep(100);
    up = await new Promise((r) => { const c = net.connect(PORTS.socks, '127.0.0.1', () => { c.destroy(); r(true); }); c.on('error', () => r(false)); });
  }
  gate(up, 'the core runs the app\'s config', up ? '' : said.slice(-400));
  if (!up) { core.kill(); process.exit(1); }

  const tcp = async (name, ip) => {
    const before = hits.length;
    const { c } = await connectTo(ip);
    c.write(tlsRecord(name));
    let h = null;
    for (let i = 0; i < 100 && !h; i++) { await sleep(40); h = hits.slice(before).find((x) => x.net === 'tcp'); }
    c.destroy();
    return h ? h.tag : 'nothing';
  };
  const udp = async (datagram, ip) => {
    const before = hits.length;
    const { c, reply } = await udpAssociate();
    const port = reply.readUInt16BE(8);
    const u = dgram.createSocket('udp4');
    u.send(Buffer.concat([Buffer.from([0, 0, 0, 1, ...v4(ip), 1, 187]), datagram]), port, '127.0.0.1');
    await sleep(700);
    const got = [...new Set(hits.slice(before).filter((x) => x.net === 'udp').map((x) => x.tag))];
    u.close(); c.destroy();
    return got.join('+') || 'refused';
  };
  const expect = async (label, got, want) => {
    const value = await got;
    gate(value === want, label, `${value}${value === want ? '' : ', wanted ' + want}`);
  };

  await expect('corporate address, its own name', tcp('host.corp.example', '10.20.30.40'), 'wg');
  await expect('corporate address, a name that resolves elsewhere', tcp('public-name.example', '10.20.30.40'), 'wg');
  await expect('corporate address, a name nobody knows', tcp('nowhere.invalid', '10.20.30.40'), 'wg');
  await expect('a wrong public address, a corporate name', tcp('host.corp.example', '93.184.216.34'), 'wg');
  await expect('a LAN address, a name that resolves elsewhere', tcp('public-name.example', '172.16.5.5'), 'direct');
  await expect('a name in a domain rule', tcp('claude.ai', '160.79.104.10'), 'target');
  await expect('a name under it', tcp('www.claude.ai', '160.79.104.10'), 'target');
  await expect('*anthropic.com', tcp('api.anthropic.com', '160.79.104.10'), 'target');
  await expect('*.wild.example', tcp('a.wild.example', '93.184.216.34'), 'target');
  await expect('x.com itself', tcp('x.com', '93.184.216.34'), 'target');
  await expect('x.com does not catch netflix.com', tcp('netflix.com', '93.184.216.34'), 'default');
  await expect('no rule: the default', tcp('public-name.example', '93.184.216.34'), 'default');
  await expect('a poisoned address still has its name read', tcp('claude.ai', '10.10.34.35'), 'target');

  await expect('QUIC the core can read follows its name', udp(quicPlain('claude.ai'), '160.79.104.10'), 'target');
  await expect('QUIC the core can read, no rule: the default', udp(quicPlain('public-name.example'), '93.184.216.34'), 'default');
  await expect('QUIC to a corporate address goes by the address, its name readable', udp(quicPlain('public-name.example'), '10.20.30.40'), 'wg');
  const chrome = await udp(quicChrome('claude.ai'), '160.79.104.10');
  gate(chrome === 'refused' || chrome === 'target', 'Chrome-shaped QUIC never reaches the default', chrome);

  core.kill();
  for (const s of servers) { try { s.close(); } catch { /* closed */ } }
  await sleep(250);
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* still closing */ }

  // a VPN client behind the router: what is the next hop asked for?
  await expect('a VPN client behind a router keeps its address', askedOfNextHop({ sniffRouteOnly: true }), '203.0.113.9');
  await expect('the control: a desktop\'s sniffing replaces it', askedOfNextHop({}), 'www.google.com');

  console.log(failed ? `${failed} gate(s) failed` : 'all gates passed');
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
