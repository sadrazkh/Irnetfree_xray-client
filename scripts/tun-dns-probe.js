#!/usr/bin/env node
'use strict';
/**
 * Does a name asked through the REAL sing-box TUN reach Xray — or does sing-box
 * answer it itself and send it out past the tunnel?
 *
 * sing-box 1.14 added the TUN inbound's `dns_mode`, `hijack` by default under
 * auto_route: it answers queries to the TUN's peer address (172.19.0.2, the
 * resolver the app gives the adapter) with its own resolver. The app's config
 * carries no DNS of its own — Xray owns DNS — so on 1.14 a WireGuard target's
 * private names stopped resolving and the queries leaked to the system
 * resolver. tunSingbox.tunDnsModeFor writes `dns_mode: "disabled"` from 1.14 on.
 * `sing-box check` passing proves nothing about where a packet goes; this does.
 *
 * In a network namespace of its own (the runner's own network is never
 * touched), with root:
 *
 *   dig-like query ─▶ 172.19.0.2:53 ─▶ sing-box TUN (the app's config)
 *                                         │ socks
 *                                         ▼
 *                                Xray (the app's buildConfig: TUN, managed DNS,
 *                                a corporate WireGuard with private names; its
 *                                dns.hosts stands in for the WireGuard resolver)
 *
 *   the namespace's "physical" resolver: 10.200.0.1:53 on the host side — a
 *   fake ISP resolver that answers everything with 10.66.6.6 and writes down
 *   every name it is asked. A name it hears left the tunnel: a leak.
 *
 * Variants, each with a fresh sing-box:
 *   fixed    the config the app writes for this version (tunDnsModeFor)
 *   control  the config of v1.21.0 (no dns_mode). On 1.14+ it MUST reproduce
 *            the bug, or this probe cannot see it and its "ok" means nothing.
 * Plus `sing-box check` of a config with dns_mode on every version: 1.13 must
 * refuse it (why the key is written by version), 1.14 must take it.
 *
 * Runs only where it is meant to: Linux, root and IRNF_TUN_PROBE=1 (CI).
 *   IRNF_SINGBOX_EXE, IRNF_XRAY_EXE   the cores
 */
const { spawn, spawnSync } = require('child_process');
const dgram = require('dgram');
const fs = require('fs');
const os = require('os');
const path = require('path');

const NS = 'irnfprobe';
const HOST_IF = 'irnf-h', NS_IF = 'irnf-n';
const HOST_IP = '10.200.0.1', NS_IP = '10.200.0.2';
const PEER = '172.19.0.2';                 // tunSingbox TUN_PEER4: the adapter's resolver
const ISP_ANSWER = '10.66.6.6';
const SOCKS = 10808;
// the corporate WireGuard's private domain (tests/fixtures WG_CORP: tes.systems) and a plain one
const NAMES = { 'intranet.tes.systems': '10.77.0.5', 'leak-probe.example': '10.77.0.6' };

/* ------------------------------ a tiny DNS (A only) ------------------------------ */

function encodeName(name) {
  const parts = String(name).split('.').filter(Boolean);
  return Buffer.concat([...parts.map((p) => Buffer.concat([Buffer.from([p.length]), Buffer.from(p)])), Buffer.from([0])]);
}
function query(name, id) {
  const h = Buffer.alloc(12);
  h.writeUInt16BE(id, 0); h.writeUInt16BE(0x0100, 2); h.writeUInt16BE(1, 4);
  return Buffer.concat([h, encodeName(name), Buffer.from([0, 1, 0, 1])]);
}
function readName(buf, off) {
  const labels = [];
  let jumped = false, end = off;
  for (let guard = 0; guard < 64; guard++) {
    const len = buf[off];
    if (len === undefined) break;
    if ((len & 0xc0) === 0xc0) { if (!jumped) end = off + 2; off = ((len & 0x3f) << 8) | buf[off + 1]; jumped = true; continue; }
    if (len === 0) { if (!jumped) end = off + 1; break; }
    labels.push(buf.slice(off + 1, off + 1 + len).toString());
    off += 1 + len;
  }
  return { name: labels.join('.'), end };
}
/** { rcode, a: [ipv4…] } of an answer. */
function parseAnswer(buf) {
  const rcode = buf[3] & 0x0f;
  const qd = buf.readUInt16BE(4), an = buf.readUInt16BE(6);
  let off = 12;
  for (let i = 0; i < qd; i++) off = readName(buf, off).end + 4;
  const a = [];
  for (let i = 0; i < an; i++) {
    off = readName(buf, off).end;
    const type = buf.readUInt16BE(off), len = buf.readUInt16BE(off + 8);
    if (type === 1 && len === 4) a.push([...buf.slice(off + 10, off + 14)].join('.'));
    off += 10 + len;
  }
  return { rcode, a };
}

/* ------------------------------ the child mode: one query from inside the namespace ------------------------------ */

/** One A query to `server`, its answer as one JSON line (run inside the namespace by askInNs). */
function queryMode() {
  const [server, name, proto] = process.argv.slice(3);
  if (proto === 'tcp') {
    // DNS over TCP: a two-byte length before the message, both ways
    const msg = query(name, 4243);
    const len = Buffer.alloc(2); len.writeUInt16BE(msg.length, 0);
    let buf = Buffer.alloc(0);
    const s = require('net').connect({ host: server, port: 53 }, () => s.write(Buffer.concat([len, msg])));
    const timer = setTimeout(() => { console.log(JSON.stringify({ error: 'timeout' })); s.destroy(); }, 4000);
    s.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      if (buf.length >= 2 && buf.length >= 2 + buf.readUInt16BE(0)) { clearTimeout(timer); console.log(JSON.stringify(parseAnswer(buf.slice(2)))); s.destroy(); }
    });
    s.on('error', (e) => { clearTimeout(timer); console.log(JSON.stringify({ error: e.message })); });
    return;
  }
  const sock = dgram.createSocket('udp4');
  const timer = setTimeout(() => { console.log(JSON.stringify({ error: 'timeout' })); sock.close(); }, 4000);
  sock.on('message', (msg) => { clearTimeout(timer); console.log(JSON.stringify(parseAnswer(msg))); sock.close(); });
  sock.on('error', (e) => { clearTimeout(timer); console.log(JSON.stringify({ error: e.message })); });
  sock.send(query(name, 4242), 53, server);
}

/* ------------------------------ the probe ------------------------------ */

const log = (s) => console.log(s);
const run = (cmd, args, opts = {}) => {
  const r = spawnSync(cmd, args, Object.assign({ encoding: 'utf8', timeout: 20000 }, opts));
  if (r.status !== 0 && !opts.mayFail) throw new Error(`${cmd} ${args.join(' ')}: ${(r.stderr || r.stdout || r.error || '').toString().trim()}`);
  return r;
};
const inNs = (args, opts) => run('ip', ['netns', 'exec', NS, ...args], opts);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function preconditions() {
  if (process.env.IRNF_TUN_PROBE !== '1' || process.platform !== 'linux' || !process.getuid || process.getuid() !== 0) {
    console.error('tun-dns-probe: CI only — Linux, root and IRNF_TUN_PROBE=1 (it makes a network namespace and a TUN)');
    process.exit(2);
  }
  for (const k of ['IRNF_SINGBOX_EXE', 'IRNF_XRAY_EXE']) {
    if (!process.env[k] || !fs.existsSync(process.env[k])) { console.error(`tun-dns-probe: ${k} is not a file`); process.exit(2); }
  }
}

function netnsUp() {
  run('ip', ['netns', 'del', NS], { mayFail: true });
  run('ip', ['link', 'del', HOST_IF], { mayFail: true });
  run('ip', ['netns', 'add', NS]);
  run('ip', ['link', 'add', HOST_IF, 'type', 'veth', 'peer', 'name', NS_IF]);
  run('ip', ['link', 'set', NS_IF, 'netns', NS]);
  run('ip', ['addr', 'add', HOST_IP + '/24', 'dev', HOST_IF]);
  run('ip', ['link', 'set', HOST_IF, 'up']);
  inNs(['ip', 'link', 'set', 'lo', 'up']);
  inNs(['ip', 'addr', 'add', NS_IP + '/24', 'dev', NS_IF]);
  inNs(['ip', 'link', 'set', NS_IF, 'up']);
  inNs(['ip', 'route', 'add', 'default', 'via', HOST_IP]);
  // the namespace's own resolver is the "ISP" (ip netns exec bind-mounts this over /etc/resolv.conf)
  fs.mkdirSync(`/etc/netns/${NS}`, { recursive: true });
  fs.writeFileSync(`/etc/netns/${NS}/resolv.conf`, `nameserver ${HOST_IP}\n`);
}
function netnsDown() {
  run('ip', ['netns', 'del', NS], { mayFail: true });
  run('ip', ['link', 'del', HOST_IF], { mayFail: true });
  try { fs.rmSync(`/etc/netns/${NS}`, { recursive: true, force: true }); } catch { /* gone */ }
}

/** The fake ISP's reply to a query: an A gets ISP_ANSWER, anything else an empty answer. { name, reply }. */
function ispAnswer(msg) {
  const q = readName(msg, 12);
  const head = Buffer.from(msg.slice(0, 12));
  const type = msg.readUInt16BE(q.end);
  head.writeUInt16BE(0x8180, 2); head.writeUInt16BE(type === 1 ? 1 : 0, 6); head.writeUInt16BE(0, 8); head.writeUInt16BE(0, 10);
  const question = msg.slice(12, q.end + 4);
  const answer = type === 1 ? Buffer.concat([Buffer.from([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4]), Buffer.from(ISP_ANSWER.split('.').map(Number))]) : Buffer.alloc(0);
  return { name: q.name, reply: Buffer.concat([head, question, answer]) };
}

/** The fake ISP resolver on the host side: every A gets ISP_ANSWER; every name asked is written down. */
function fakeIsp() {
  const heard = [];
  const sock = dgram.createSocket('udp4');
  sock.on('message', (msg, rinfo) => {
    const { name, reply } = ispAnswer(msg);
    heard.push(name);
    sock.send(reply, rinfo.port, rinfo.address);
  });
  return new Promise((resolve, reject) => {
    sock.once('error', reject);
    sock.bind(53, HOST_IP, () => resolve({ heard, close: () => sock.close() }));
  });
}

function spawnInNs(exe, args, label) {
  const p = spawn('ip', ['netns', 'exec', NS, exe, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '';
  p.stdout.on('data', (d) => { out += d; });
  p.stderr.on('data', (d) => { out += d; });
  p.output = () => out.split('\n').slice(-40).map((l) => `      [${label}] ${l}`).join('\n');
  return p;
}
/** The namespace's addresses, routes and rules, for a variant that went wrong. */
function diag() {
  const show = (args) => (inNs(args, { mayFail: true }).stdout || '').trim().split('\n').map((l) => `      [${args.slice(1, 3).join(' ')}] ${l}`).join('\n');
  return [show(['ip', 'addr']), show(['ip', 'rule']), show(['ip', 'route', 'show', 'table', 'all'])].join('\n');
}
async function stop(p) {
  if (!p || p.exitCode !== null) return;
  p.kill('SIGTERM');
  for (let i = 0; i < 30 && p.exitCode === null; i++) await sleep(100);
  if (p.exitCode === null) p.kill('SIGKILL');
}
function askInNs(name, proto) {
  const r = inNs([process.execPath, __filename, '--query', PEER, name, proto || 'udp'], { mayFail: true });
  try { return JSON.parse(String(r.stdout || '').trim().split('\n').pop()); } catch { return { error: (r.stderr || 'no answer').toString().trim() }; }
}

/**
 * The probe's configs for a sing-box `version` — pure, so `npm test` checks
 * them: Xray is the app's own config for a corporate WireGuard under TUN with
 * managed DNS (no geo rule: no geo files here), whose dns.hosts stands in for
 * the WireGuard's private resolver; sing-box's are the app's TUN config with
 * the dns_mode this version gets (fixed), with none (control: v1.21.0), and
 * with "disabled" forced (for `sing-box check`).
 */
function buildProbeConfigs(version) {
  const { buildTunConfig, tunDnsModeFor } = require('../src/main/tunSingbox');
  const { buildConfig } = require('../src/main/configBuilder');
  const { settings, WG_CORP } = require('../tests/fixtures');
  const mode = tunDnsModeFor(version, 'app');
  const xray = buildConfig({ mode: 'single', server: WG_CORP }, settings({
    tunMode: true, blockAds: false, geoAssets: false, socksPort: SOCKS,
    dnsManaged: true, dnsRemote: ['https://1.1.1.1/dns-query'], dnsDirect: ['178.22.122.100']
  }));
  delete xray.metrics;   // its port is not this probe's business
  xray.dns = Object.assign({}, xray.dns, { hosts: Object.assign({}, xray.dns && xray.dns.hosts, NAMES) });
  return {
    mode,
    xray,
    sbFixed: buildTunConfig({ socksPort: SOCKS, excludeIps: [], dnsMode: mode }),
    sbControl: buildTunConfig({ socksPort: SOCKS, excludeIps: [] }),
    sbForced: buildTunConfig({ socksPort: SOCKS, dnsMode: 'disabled' })
  };
}

async function main() {
  preconditions();
  const sbExe = process.env.IRNF_SINGBOX_EXE, xrayExe = process.env.IRNF_XRAY_EXE;
  const version = (/(\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)/.exec(run(sbExe, ['version']).stdout) || [])[1] || '';
  const cfg = buildProbeConfigs(version);
  const mode = cfg.mode;
  const newer = !!mode;
  log(`sing-box ${version} → the app writes dns_mode: ${mode || '(none)'}`);

  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-tunprobe-'));
  // the cores say what they did with every packet: printed when a variant goes wrong
  const loud = (o, isXray) => Object.assign({}, o, { log: isXray ? Object.assign({}, o.log, { loglevel: 'debug' }) : { level: 'debug', timestamp: false } });
  fs.writeFileSync(path.join(work, 'xray.json'), JSON.stringify(loud(cfg.xray, true), null, 2));

  const results = [];
  const fail = (msg) => { results.push(['FAIL', msg]); };
  const ok = (msg) => { results.push(['ok', msg]); };

  // sing-box check: the dns_mode key by version
  const forced = path.join(work, 'sb-forced.json');
  fs.writeFileSync(forced, JSON.stringify(cfg.sbForced, null, 2));
  const chk = run(sbExe, ['check', '-c', forced], { mayFail: true });
  if (newer === (chk.status === 0)) ok(`sing-box check of dns_mode "disabled": ${chk.status === 0 ? 'accepted' : 'refused'} on ${version} — as the version rule expects`);
  else fail(`sing-box check of dns_mode "disabled" on ${version}: ${chk.status === 0 ? 'accepted' : 'refused'} — the version rule (since 1.14) is wrong: ${(chk.stderr || chk.stdout || '').trim().split('\n').pop()}`);

  netnsUp();
  const isp = await fakeIsp();
  let xray = null, sb = null;
  try {
    xray = spawnInNs(xrayExe, ['run', '-c', path.join(work, 'xray.json')], 'xray');
    await sleep(1500);
    if (xray.exitCode !== null) throw new Error('xray did not start\n' + xray.output());

    for (const variant of ['fixed', 'control']) {
      const dnsMode = variant === 'fixed' ? mode : null;
      const file = path.join(work, `sb-${variant}.json`);
      fs.writeFileSync(file, JSON.stringify(loud(variant === 'fixed' ? cfg.sbFixed : cfg.sbControl, false), null, 2));
      isp.heard.length = 0;
      sb = spawnInNs(sbExe, ['run', '-c', file], 'sing-box');
      let up = false;
      for (let i = 0; i < 50 && !up; i++) {
        await sleep(200);
        if (sb.exitCode !== null) break;
        up = /state UP|UP,LOWER_UP|,UP/.test(inNs(['ip', 'link', 'show', 'IRNetFree'], { mayFail: true }).stdout || '');
      }
      if (!up) { fail(`${variant}: the TUN did not come up\n${sb.output()}`); await stop(sb); continue; }
      await sleep(500);
      const got = {};
      // each name over UDP, and over TCP when UDP got nothing (a socks UDP relay is one more thing that can fail here)
      for (const name of Object.keys(NAMES)) {
        got[name] = askInNs(name, 'udp');
        if (got[name].error) { const t = askInNs(name, 'tcp'); got[name] = Object.assign(t, { via: 'tcp', udp: got[name].error }); }
      }
      const leaked = Object.keys(NAMES).filter((n) => isp.heard.includes(n));
      const byXray = Object.keys(NAMES).every((n) => (got[n].a || []).includes(NAMES[n]));
      const line = Object.keys(NAMES).map((n) => `${n} → ${got[n].error || (got[n].a || []).join(',') || 'rcode ' + got[n].rcode}${got[n].via ? ` (tcp; udp: ${got[n].udp})` : ''}`).join('; ');
      const clean = byXray && !leaked.length;
      // the bug's own signature: sing-box answered from the ISP resolver, or the ISP heard the name — not a mere timeout
      const ispAnswered = Object.keys(NAMES).some((n) => (got[n].a || []).includes(ISP_ANSWER));
      const why = () => `\n${sb.output()}\n${xray.output()}\n${diag()}`;
      if (variant === 'fixed') {
        if (clean) ok(`fixed (dns_mode ${dnsMode || 'none'}): every name answered by Xray, none reached the ISP resolver — ${line}`);
        else fail(`fixed (dns_mode ${dnsMode || 'none'}): ${line}${leaked.length ? ' · LEAKED to the ISP resolver: ' + leaked.join(', ') : ''}${why()}`);
      } else if (newer) {
        // the bug must show without the key, or this probe cannot tell it apart: the very names Xray
        // answered a moment ago (fixed) do not come from Xray now — sing-box took them (an ISP answer,
        // a name the ISP heard, or nothing at all: "name not resolved")
        const how = leaked.length ? 'leaked to the ISP resolver: ' + leaked.join(', ') : ispAnswered ? 'answered by the ISP resolver' : 'not resolved at all';
        if (!byXray) ok(`control (no dns_mode) on ${version}: the bug reproduces — Xray never saw the names, ${how} — ${line}`);
        else fail(`control (no dns_mode) on ${version}: Xray still answered — the probe does not reproduce what dns_mode fixes — ${line}${why()}`);
      } else if (clean) ok(`control on ${version}: the same config as fixed, clean — ${line}`);
      else fail(`control on ${version}: ${line}${leaked.length ? ' · leaked: ' + leaked.join(', ') : ''}${why()}`);
      await stop(sb);
      sb = null;
      await sleep(700);
    }
  } catch (e) {
    fail(e.message);
  } finally {
    await stop(sb);
    await stop(xray);
    isp.close();
    netnsDown();
  }
  log('');
  for (const [s, m] of results) log(`${s === 'ok' ? 'ok  ' : 'FAIL'} ${m}`);
  const bad = results.filter(([s]) => s !== 'ok').length;
  log(`\n${results.length - bad}/${results.length} — sing-box ${version}, ${path.basename(xrayExe)} (the app's config)`);
  process.exit(bad ? 1 : 0);
}

if (require.main === module) {
  if (process.argv[2] === '--query') queryMode();
  else main().catch((e) => { console.error(e); try { netnsDown(); } catch { /* best effort */ } process.exit(1); });
}

module.exports = { query, parseAnswer, readName, ispAnswer, buildProbeConfigs, ISP_ANSWER, NAMES, PEER };
