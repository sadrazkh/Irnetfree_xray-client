#!/usr/bin/env node
'use strict';
/**
 * Traffic by site (src/main/siteUsage.js) on a real sing-box, loopback only: does the
 * app's own sniff name a connection in the API, and does the app's own meter put its
 * bytes in the right row? `sing-box check` says the rule parses, nothing about either.
 *
 *   this probe ─SOCKS5 to 127.0.0.1─▶ mixed inbound ─▶ route (the app's TUN rules)
 *                                                       │ socks-out
 *                                                       ▼
 *                                     a forwarder here ─▶ a TLS page here
 *
 * The config is buildTunConfig's with its TUN inbound swapped for a mixed one: only a
 * TUN needs root, and the sniff is the route's. A connection is held open a moment
 * after its page: on loopback it would end between two of the meter's reads, and a
 * connection the meter never saw is Other, which is the meter's known limit, not what
 * this asks. Gates:
 *   named     a TLS hello to a bare address under www.youtube.com lands in s:youtube,
 *             one under files.aparat.com in d:aparat.com, each with its page's bytes
 *   control   without the sniff the same request has no name: the rule is what names it
 *
 *   IRNF_SINGBOX_EXE    the core under test
 *   IRNF_PROBE_PORT     base port
 */
const { spawn, execFileSync } = require('child_process');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const tls = require('tls');
const { buildTunConfig } = require('../src/main/tunSingbox');
const { createSiteUsage } = require('../src/main/siteUsage');

const BASE = Number(process.env.IRNF_PROBE_PORT || 24700);
const P = { tls: BASE + 0, forward: BASE + 1, mixed: BASE + 2, api: BASE + 3 };
const SECRET = 'abcdef0123456789abcdef0123456789';
const WATCH = { port: P.api, secret: SECRET };
const BIG = 4 * 1024 * 1024, SMALL = 1024 * 1024;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let failed = 0;
function gate(ok, name, detail) {
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}${detail ? ' — ' + detail : ''}`);
  if (!ok) failed++;
}

/** The app's config for the TUN, on a mixed inbound. */
function buildProbeConfig(sniff) {
  const cfg = buildTunConfig({ socksPort: P.forward, excludeIps: [], sniff, watch: WATCH });
  cfg.inbounds = [{ type: 'mixed', tag: 'tun-in', listen: '127.0.0.1', listen_port: P.mixed }];
  delete cfg.route.auto_detect_interface;
  return cfg;
}

/** A SOCKS5 server that forwards to wherever it is asked: what stands for Xray here. */
function forwarder() {
  return net.createServer((c) => {
    let buf = Buffer.alloc(0), stage = 0;
    c.on('error', () => {});
    c.on('data', function onData(d) {
      buf = Buffer.concat([buf, d]);
      if (stage === 0 && buf.length >= 2 + buf[1]) { buf = buf.subarray(2 + buf[1]); c.write(Buffer.from([5, 0])); stage = 1; }
      if (stage !== 1 || buf.length < 5) return;
      const atyp = buf[3], hlen = atyp === 1 ? 4 : atyp === 4 ? 16 : 1 + buf[4];
      if (buf.length < 4 + hlen + 2) return;
      const host = atyp === 1 ? [...buf.subarray(4, 8)].join('.') : buf.subarray(5, 4 + hlen).toString();
      const port = buf.readUInt16BE(4 + hlen);
      const rest = buf.subarray(4 + hlen + 2);
      stage = 2;
      c.removeListener('data', onData);
      c.pause();
      const up = net.connect(port, host, () => {
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

/** A TLS client through the mixed port to the bare loopback address, under `name`; it reads `want` bytes and closes. */
function fetchUnder(name, want) {
  return new Promise((resolve) => {
    const raw = net.connect(P.mixed, '127.0.0.1');
    let stage = 0, buf = Buffer.alloc(0), done = false;
    const end = (v) => { if (done) return; done = true; clearTimeout(t); raw.destroy(); resolve(v); };
    const t = setTimeout(() => end(0), 15000);
    raw.on('error', () => end(0));
    raw.on('connect', () => raw.write(Buffer.from([5, 1, 0])));
    raw.on('data', function onData(d) {
      buf = Buffer.concat([buf, d]);
      if (stage === 0 && buf.length >= 2) {
        buf = buf.subarray(2);
        stage = 1;
        raw.write(Buffer.from([5, 1, 0, 1, 127, 0, 0, 1, P.tls >> 8, P.tls & 255]));
      }
      if (stage === 1 && buf.length >= 10) {
        stage = 2;
        raw.removeListener('data', onData);
        const s = tls.connect({ socket: raw, servername: name, rejectUnauthorized: false }, () => s.write(`GET ${want}\n`));
        let got = 0;
        s.on('data', (x) => { got += x.length; if (got >= want) setTimeout(() => { s.destroy(); end(got); }, 600); });
        s.on('error', () => end(got));
        s.on('close', () => end(got));
      }
    });
  });
}

async function runRound(exe, sniff) {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-su-')), 'c.json');
  fs.writeFileSync(file, JSON.stringify(buildProbeConfig(sniff)));
  const core = spawn(exe, ['run', '-c', file], { windowsHide: true });
  let log = '';
  core.stdout.on('data', (d) => { log += d; });
  core.stderr.on('data', (d) => { log += d; });
  const saved = { value: null };
  const meter = createSiteUsage({
    enabled: () => true, connected: () => true, tun: () => ({ watch: WATCH, sniffs: true }),
    load: () => null, save: (v) => { saved.value = v; }
  });
  try {
    await sleep(1500);
    await meter.tick();   // the baseline
    const a = fetchUnder('www.youtube.com', BIG);
    const b = fetchUnder('files.aparat.com', SMALL);
    // reads through the transfer, as the app's timer does; the last after both ended
    let done = false;
    const results = Promise.all([a, b]).then((r) => { done = true; return r; });
    while (!done) { await meter.tick(); await sleep(150); }
    const [gotA, gotB] = await results;
    await sleep(300);
    await meter.tick();
    return { gotA, gotB, report: meter.report('today'), log: log.slice(-1500) };
  } finally {
    core.kill();
    await sleep(400);
  }
}

async function main() {
  const exe = process.env.IRNF_SINGBOX_EXE;
  if (!exe || !fs.existsSync(exe)) { console.error('probe-site-usage: IRNF_SINGBOX_EXE is not a file'); process.exit(2); }
  const pair = execFileSync(exe, ['generate', 'tls-keypair', 'localhost'], { encoding: 'utf8', windowsHide: true });
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
  await new Promise((r) => fwd.listen(P.forward, '127.0.0.1', r));
  try {
    const on = await runRound(exe, true);
    gate(on.gotA >= BIG && on.gotB >= SMALL, 'both pages arrived through the app\'s route', `${on.gotA} and ${on.gotB} bytes`);
    const row = (k) => on.report.rows.find((r) => r.key === k);
    const yt = row('s:youtube'), ap = row('d:aparat.com');
    console.log('     rows: ' + on.report.rows.map((r) => `${r.key} ${r.down}`).join(', '));
    gate(!!yt && yt.down >= BIG * 0.9, 'named: the YouTube name landed in its row, with its bytes', yt ? `${yt.name}, down ${yt.down}` : on.log);
    gate(!!ap && ap.down >= SMALL * 0.9, 'named: another site landed under its domain, with its bytes', ap ? `${ap.name}, down ${ap.down}` : on.log);
    gate(on.report.total.down >= (BIG + SMALL) * 0.95, 'the totals account for what moved', `down ${on.report.total.down}`);

    const off = await runRound(exe, false);
    console.log('     rows without the sniff: ' + off.report.rows.map((r) => `${r.key} ${r.down}`).join(', '));
    gate(!off.report.rows.some((r) => r.key === 's:youtube' || r.key === 'd:aparat.com'), 'control: without the sniff neither has a name, so the rule is what names them');
  } finally {
    page.close();
    fwd.close();
  }
  console.log(failed ? `\n${failed} gate(s) failed` : '\nall gates passed');
  process.exit(failed ? 1 : 0);
}

if (require.main === module) main().catch((e) => { console.error(e); process.exit(1); });

module.exports = { buildProbeConfig };
