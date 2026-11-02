#!/usr/bin/env node
'use strict';
/**
 * Traffic by site on a router, device by device, through the real TUN: are the devices
 * behind the router told apart, and does each one's traffic land in its own rows?
 * `sing-box check` says the config parses; only packets forwarded from another
 * namespace into the TUN say what the API calls their source.
 *
 *   device A (netns) ─┐                                   ┌─▶ SOCKS, here ─▶ a TLS page, here
 *                     ├─▶ router (netns): the TUN ─▶ route ┤
 *   device B (netns) ─┘   the router's own config          └─ read by the app's own meter
 *
 * Device A asks a bare address under www.youtube.com, device B under files.aparat.com.
 * Gates:
 *   config    the router's TUN config: the sniff, the API, no process lookups
 *   apart     A's page is in A's rows and not B's, and the other way round
 *   house     the whole house has both
 *   names     the picker lists both devices, by the names their addresses resolve to
 *   router    the meter's limits: its read costs are reported, and it reads no faster than 5 s
 *
 * Runs only where it is meant to: Linux, root and IRNF_TUN_PROBE=1 (CI).
 *   IRNF_SINGBOX_EXE    the core under test
 */
const { spawn, spawnSync, execFileSync } = require('child_process');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const tls = require('tls');
const { buildTunConfig } = require('../src/main/tunSingbox');
const { createSiteUsage, deviceTable, deviceOfSource, ROUTER_LIMITS, ROUTER_DEVICE } = require('../src/main/siteUsage');

const BASE = Number(process.env.IRNF_PROBE_PORT || 24800);
const P = { tls: BASE + 0, socks: BASE + 1, api: BASE + 2 };
const NS = { rtr: 'irnfsu-r', a: 'irnfsu-a', b: 'irnfsu-b' };
const DEV = {
  a: { ns: NS.a, ip: '10.210.1.2', gw: '10.210.1.1', mac: 'aa:aa:aa:aa:aa:01', name: 'phone-a', sni: 'www.youtube.com', want: 3 * 1024 * 1024 },
  b: { ns: NS.b, ip: '10.210.2.2', gw: '10.210.2.1', mac: 'aa:aa:aa:aa:aa:02', name: 'laptop-b', sni: 'files.aparat.com', want: 1024 * 1024 }
};
const SITE = '203.0.113.50';
const WATCH = { port: P.api, secret: 'abcdef0123456789abcdef0123456789' };

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const run = (cmd, args, opts = {}) => {
  const r = spawnSync(cmd, args, Object.assign({ encoding: 'utf8', timeout: 20000 }, opts));
  if (r.status !== 0 && !opts.mayFail) throw new Error(`${cmd} ${args.join(' ')}: ${(r.stderr || r.stdout || r.error || '').toString().trim()}`);
  return r;
};
const inNs = (ns, args, opts) => run('ip', ['netns', 'exec', ns, ...args], opts);
let failed = 0;
function gate(ok, name, detail) {
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}${detail ? ' — ' + detail : ''}`);
  if (!ok) failed++;
}

function buildRouterConfig() {
  return buildTunConfig({ socksPort: P.socks, excludeIps: [], sniff: true, findProcess: false, watch: WATCH });
}

function netnsDown() {
  for (const ns of Object.values(NS)) run('ip', ['netns', 'del', ns], { mayFail: true });
}

function netnsUp() {
  netnsDown();
  for (const ns of Object.values(NS)) {
    run('ip', ['netns', 'add', ns]);
    inNs(ns, ['ip', 'link', 'set', 'lo', 'up']);
  }
  for (const [k, d] of Object.entries(DEV)) {
    const lan = `su-${k}0`, dev = `su-${k}1`;
    run('ip', ['link', 'add', lan, 'netns', NS.rtr, 'type', 'veth', 'peer', 'name', dev, 'netns', d.ns]);
    inNs(NS.rtr, ['ip', 'addr', 'add', d.gw + '/24', 'dev', lan]);
    inNs(NS.rtr, ['ip', 'link', 'set', lan, 'up']);
    inNs(d.ns, ['ip', 'addr', 'add', d.ip + '/24', 'dev', dev]);
    inNs(d.ns, ['ip', 'link', 'set', dev, 'up']);
    inNs(d.ns, ['ip', 'route', 'add', 'default', 'via', d.gw]);
  }
  // a default route for sing-box to detect: a WAN nothing answers on, as the page is served here
  inNs(NS.rtr, ['ip', 'link', 'add', 'su-wan', 'type', 'dummy']);
  inNs(NS.rtr, ['ip', 'addr', 'add', '10.210.9.1/24', 'dev', 'su-wan']);
  inNs(NS.rtr, ['ip', 'link', 'set', 'su-wan', 'up']);
  inNs(NS.rtr, ['ip', 'route', 'add', 'default', 'via', '10.210.9.2']);
  inNs(NS.rtr, ['sysctl', '-q', '-w', 'net.ipv4.ip_forward=1']);
}

/** Device mode: a TLS client to the bare address under its name; it reads its page and holds the connection a moment. */
function clientMode() {
  const [name, wantText] = process.argv.slice(3);
  const want = Number(wantText);
  const s = tls.connect({ host: SITE, port: 443, servername: name, rejectUnauthorized: false }, () => s.write(`GET ${want}\n`));
  let got = 0;
  const end = (code) => { console.log(got); process.exit(code); };
  s.on('data', (d) => { got += d.length; if (got >= want) setTimeout(() => end(0), 1500); });
  s.on('error', () => end(1));
  setTimeout(() => end(1), 25000);
}

/** A SOCKS5 server for socks-out: wherever it is asked, the page here answers. */
function forwarder() {
  return net.createServer((c) => {
    let buf = Buffer.alloc(0), stage = 0;
    c.on('error', () => {});
    c.on('data', function onData(d) {
      buf = Buffer.concat([buf, d]);
      if (stage === 0 && buf.length >= 2 + buf[1]) { buf = buf.subarray(2 + buf[1]); c.write(Buffer.from([5, 0])); stage = 1; }
      if (stage !== 1 || buf.length < 5) return;
      const hlen = buf[3] === 1 ? 4 : buf[3] === 4 ? 16 : 1 + buf[4];
      if (buf.length < 4 + hlen + 2) return;
      const rest = buf.subarray(4 + hlen + 2);
      stage = 2;
      c.removeListener('data', onData);
      c.pause();
      const up = net.connect(P.tls, '127.0.0.1', () => {
        c.write(Buffer.from([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]));
        if (rest.length) up.write(rest);
        c.pipe(up);
        up.pipe(c);
      });
      up.on('error', () => c.destroy());
      c.on('close', () => up.destroy());
    });
  });
}

function deviceClient(d) {
  return new Promise((resolve) => {
    const p = spawn('ip', ['netns', 'exec', d.ns, process.execPath, __filename, '--client', d.sni, String(d.want)], { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    p.stdout.on('data', (x) => { out += x; });
    p.stderr.on('data', (x) => { out += x; });
    const t = setTimeout(() => p.kill('SIGKILL'), 28000);
    p.on('close', (code) => { clearTimeout(t); resolve({ code, got: Number(out.trim().split('\n').pop()) || 0, out }); });
  });
}

/** Router mode, inside its namespace: the page, the SOCKS server, sing-box and the meter. */
async function routerMode() {
  const exe = process.env.IRNF_SINGBOX_EXE;
  const pair = execFileSync(exe, ['generate', 'tls-keypair', 'localhost'], { encoding: 'utf8' });
  const key = (/-----BEGIN PRIVATE KEY-----[\s\S]+?-----END PRIVATE KEY-----/.exec(pair) || [])[0];
  const cert = (/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/.exec(pair) || [])[0];
  const page = tls.createServer({ key, cert }, (c) => {
    c.on('error', () => {});
    c.once('data', (d) => {
      const want = Number((/GET (\d+)/.exec(d.toString()) || [])[1]) || 0;
      const chunk = Buffer.alloc(64 * 1024, 7);
      let left = want;
      const pump = () => {
        while (left > 0) {
          const n = Math.min(left, chunk.length);
          left -= n;
          if (!c.write(n === chunk.length ? chunk : chunk.subarray(0, n))) { c.once('drain', pump); return; }
        }
      };
      pump();
    });
  });
  const fwd = forwarder();
  await new Promise((r) => page.listen(P.tls, '127.0.0.1', r));
  await new Promise((r) => fwd.listen(P.socks, '127.0.0.1', r));

  const cfg = buildRouterConfig();
  gate(cfg.route.rules[0].action === 'sniff' && cfg.route.find_process === undefined && !!cfg.experimental.clash_api, 'config: the sniff and the API, no process lookups');
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-rsu-')), 'c.json');
  fs.writeFileSync(file, JSON.stringify(cfg));
  const core = spawn(exe, ['run', '-c', file], { stdio: ['ignore', 'pipe', 'pipe'] });
  let log = '';
  core.stdout.on('data', (d) => { log += d; });
  core.stderr.on('data', (d) => { log += d; });

  const table = deviceTable(Object.values(DEV).map((d) => ({ mac: d.mac, name: d.name, ips: [d.ip] })));
  const meter = createSiteUsage({
    enabled: () => true, connected: () => true, tun: () => ({ watch: WATCH, sniffs: true }), router: true,
    load: () => null, save: () => {}, limits: ROUTER_LIMITS,
    device: (m) => deviceOfSource(table, m.sourceIP)
  });
  try {
    let up = false;
    for (let i = 0; i < 50 && !up; i++) {
      await sleep(200);
      up = /UP/.test(run('ip', ['link', 'show', 'IRNetFree'], { mayFail: true }).stdout || '');
    }
    if (!up) { gate(false, 'the TUN came up', log.slice(-800)); return; }
    await sleep(500);
    await meter.tick();
    let done = false;
    const clients = Promise.all([deviceClient(DEV.a), deviceClient(DEV.b)]).then((r) => { done = true; return r; });
    while (!done) { await meter.tick(); await sleep(300); }
    const [ra, rb] = await clients;
    await meter.tick();
    gate(ra.got >= DEV.a.want && rb.got >= DEV.b.want, 'both devices got their pages through the TUN', `${ra.got} and ${rb.got} bytes${ra.got ? '' : ' ' + ra.out + log.slice(-800)}`);

    const house = meter.report('today');
    const a = meter.report({ range: 'today', device: DEV.a.mac });
    const b = meter.report({ range: 'today', device: DEV.b.mac });
    const row = (r, k) => r.rows.find((x) => x.key === k);
    console.log('     house: ' + house.rows.map((r) => `${r.key} ${r.down}`).join(', '));
    console.log('     devices: ' + house.devices.map((d) => `${d.id} ${d.name} ${d.total}`).join(', '));
    console.log('     A: ' + a.rows.map((r) => `${r.key} ${r.down}`).join(', ') + ' · B: ' + b.rows.map((r) => `${r.key} ${r.down}`).join(', '));
    gate(!!row(a, 's:youtube') && row(a, 's:youtube').down >= DEV.a.want * 0.9, 'apart: A\'s page is in A\'s rows', row(a, 's:youtube') ? `down ${row(a, 's:youtube').down}` : log.slice(-800));
    gate(!row(a, 'd:aparat.com'), 'apart: B\'s site is not in A\'s rows');
    gate(!!row(b, 'd:aparat.com') && row(b, 'd:aparat.com').down >= DEV.b.want * 0.9, 'apart: B\'s page is in B\'s rows', row(b, 'd:aparat.com') ? `down ${row(b, 'd:aparat.com').down}` : log.slice(-800));
    gate(!row(b, 's:youtube'), 'apart: A\'s site is not in B\'s rows');
    gate(!!row(house, 's:youtube') && !!row(house, 'd:aparat.com'), 'house: the whole house has both');
    const names = new Map(house.devices.map((d) => [d.id, d.name]));
    gate(names.get(DEV.a.mac) === DEV.a.name && names.get(DEV.b.mac) === DEV.b.name, 'names: the picker lists both devices by name', JSON.stringify([...names]));
    gate(!house.devices.some((d) => d.id === ROUTER_DEVICE && d.total > 1024), 'the devices\' traffic is not put on the router');
    gate(house.cost && house.cost.everyMs >= 5000 && house.cost.conns >= 0, 'router: the read\'s cost is reported, no read faster than 5 s', JSON.stringify(house.cost));
  } finally {
    core.kill();
    page.close();
    fwd.close();
  }
}

async function main() {
  if (process.env.IRNF_TUN_PROBE !== '1' || process.platform !== 'linux' || process.getuid() !== 0) {
    console.error('probe-router-site-usage: CI only — Linux, root and IRNF_TUN_PROBE=1');
    process.exit(2);
  }
  if (!process.env.IRNF_SINGBOX_EXE || !fs.existsSync(process.env.IRNF_SINGBOX_EXE)) { console.error('probe-router-site-usage: IRNF_SINGBOX_EXE is not a file'); process.exit(2); }
  netnsUp();
  const code = await new Promise((resolve) => {
    const p = spawn('ip', ['netns', 'exec', NS.rtr, process.execPath, __filename, '--router'], { stdio: 'inherit' });
    const t = setTimeout(() => p.kill('SIGKILL'), 100000);
    p.on('close', (c) => { clearTimeout(t); resolve(c); });
  });
  netnsDown();
  process.exit(code === 0 ? 0 : 1);
}

if (require.main === module) {
  if (process.argv[2] === '--client') clientMode();
  else if (process.argv[2] === '--router') routerMode().then(() => { console.log(failed ? `\n${failed} gate(s) failed` : '\nall gates passed'); process.exit(failed ? 1 : 0); }, (e) => { console.error(e); process.exit(1); });
  else main().catch((e) => { console.error(e); netnsDown(); process.exit(1); });
}

module.exports = { buildRouterConfig };
