'use strict';
/**
 * An ECH outbound end to end, on the real network: the ECH key of
 * cloudflare-ech.com fetched the way patterniha published on 2026-10-20 —
 * `h2c://1.1.1.1/dns-query` through a `direct` outbound that carries the query
 * to 1.1.1.1:443 under TLS with another name (www.microsoft.com) and checks the
 * certificate against the resolver's own (`fromMitM`) — then a page of
 * cloudflare-ech.com fetched under that key, which says whether its SNI
 * arrived encrypted.
 *
 *   socks ─▶ core ── freedom + TLS (ECH) ══▶ cloudflare-ech.com:443  /cdn-cgi/trace
 *                        │ the ECH key: h2c://1.1.1.1/dns-query
 *                        └─▶ ech-1: direct + TLS (SNI www.microsoft.com) ══▶ 1.1.1.1:443
 *
 * The outbound is the editor's Example (serverFields.ECH_OUTBOUND_EXAMPLE) and
 * the config goes through the app's own step (configBuilder.applyEchOutbounds),
 * so this shows that what the app writes fetches the key on the cores it
 * suggests. Two lines, both gating:
 *  - with the ECH outbound: the trace says `sni=encrypted`;
 *  - the control, the same h2c query WITHOUT it: cleartext HTTP/2 to port 443
 *    gets no key, so the trace must not say `sni=encrypted` (or the page fails)
 *    — else this probe could not tell the outbound did anything.
 * A third line asks over plain UDP DNS for the record; it never gates (on a
 * runner abroad it works, in Iran it no longer does — the reason for all this).
 *
 *   IRNF_XRAY_EXE      the core under test (default bin/xray)
 *   IRNF_PROBE_PORT    base port, default 22800 (never the app's own)
 *   IRNF_PROBE_LOG     the core's log level, default warning (debug says why a key query failed)
 */
const fs = require('fs');
const os = require('os');
const net = require('net');
const path = require('path');
const { spawn, spawnSync } = require('child_process');
const { applyEchOutbounds } = require('../src/main/configBuilder');
const SF = require('../src/renderer/serverFields');

const BASE = Number(process.env.IRNF_PROBE_PORT || 22800);
const XRAY = process.env.IRNF_XRAY_EXE || path.join(__dirname, '..', 'bin', process.platform === 'win32' ? 'xray.exe' : 'xray');
const HOST = 'cloudflare-ech.com';
const HARD_LIMIT_MS = 120000;
const PAGE_TIMEOUT_MS = 25000;

const hard = setTimeout(() => { console.error('FAIL: the probe ran out of time'); process.exit(1); }, HARD_LIMIT_MS);
hard.unref();

/** The client config: a SOCKS inbound and a freedom outbound that speaks TLS with ECH to cloudflare-ech.com. */
function config(port, ech, withOutbound) {
  const tls = { serverName: HOST, alpn: ['http/1.1'], fingerprint: 'chrome', echConfigList: ech };
  if (withOutbound) tls.echOutbound = JSON.parse(JSON.stringify(SF.ECH_OUTBOUND_EXAMPLE));
  const outbounds = applyEchOutbounds([
    { tag: 'proxy', protocol: 'freedom', settings: { redirect: `${HOST}:443` }, streamSettings: { network: 'tcp', security: 'tls', tlsSettings: tls } }
  ]);
  return {
    log: { loglevel: process.env.IRNF_PROBE_LOG || 'warning' },
    inbounds: [{ tag: 'socks-in', port, listen: '127.0.0.1', protocol: 'socks', settings: { auth: 'noauth', udp: false } }],
    outbounds,
    routing: { rules: [{ type: 'field', inboundTag: ['socks-in'], outboundTag: 'proxy' }] }
  };
}

/** One HTTP/1.1 GET through SOCKS5 (the page is plain HTTP inside the outbound's TLS). */
function viaSocks(port, host, dport, request) {
  return new Promise((resolve) => {
    const s = net.connect(port, '127.0.0.1');
    let stage = 0, buf = Buffer.alloc(0), body = '';
    const done = (r) => { clearTimeout(t); s.destroy(); resolve(r); };
    const t = setTimeout(() => done({ ok: false, error: 'timed out' }), PAGE_TIMEOUT_MS);
    s.on('error', (e) => done({ ok: false, error: e.message }));
    s.on('connect', () => s.write(Buffer.from([5, 1, 0])));
    s.on('data', (d) => {
      if (stage === 2) { body += d.toString('utf8'); return; }
      buf = Buffer.concat([buf, d]);
      if (stage === 0 && buf.length >= 2) {
        if (buf[0] !== 5 || buf[1] !== 0) return done({ ok: false, error: 'socks greeting refused' });
        buf = buf.subarray(2);
        const h = Buffer.from(host);
        s.write(Buffer.concat([Buffer.from([5, 1, 0, 3, h.length]), h, Buffer.from([dport >> 8, dport & 255])]));
        stage = 1;
      }
      if (stage === 1 && buf.length >= 5) {
        if (buf[1] !== 0) return done({ ok: false, error: 'socks connect refused (' + buf[1] + ')' });
        const len = buf[3] === 1 ? 10 : buf[3] === 4 ? 22 : 7 + buf[4];
        if (buf.length < len) return;
        body = buf.subarray(len).toString('utf8');
        stage = 2;
        s.write(request);
      }
    });
    s.on('end', () => done(stage === 2 ? { ok: true, body } : { ok: false, error: 'closed before the page' }));
  });
}

function startCore(cfg, name) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-ech-'));
  const file = path.join(dir, 'config.json');
  fs.writeFileSync(file, JSON.stringify(cfg, null, 2));
  const t = spawnSync(XRAY, ['run', '-test', '-c', file], { encoding: 'utf8' });
  if (t.status !== 0) return { error: `${name}: -test refused the config:\n${(t.stdout || '') + (t.stderr || '')}`, file };
  const child = spawn(XRAY, ['run', '-c', file], { stdio: ['ignore', 'pipe', 'pipe'] });
  const log = [];
  child.stdout.on('data', (d) => log.push(String(d)));
  child.stderr.on('data', (d) => log.push(String(d)));
  return { child, log, file };
}

function waitPort(port, ms) {
  const end = Date.now() + ms;
  return new Promise((resolve) => {
    const tryOnce = () => {
      const s = net.connect(port, '127.0.0.1');
      s.on('connect', () => { s.destroy(); resolve(true); });
      s.on('error', () => { s.destroy(); if (Date.now() > end) resolve(false); else setTimeout(tryOnce, 150); });
    };
    tryOnce();
  });
}

async function line(name, port, ech, withOutbound) {
  const cfg = config(port, ech, withOutbound);
  const c = startCore(cfg, name);
  if (c.error) return { name, error: c.error };
  try {
    if (!await waitPort(port, 8000)) return { name, error: 'the core never listened', log: c.log.join('') };
    const t0 = Date.now();
    const r = await viaSocks(port, HOST, 80, `GET /cdn-cgi/trace HTTP/1.1\r\nHost: ${HOST}\r\nUser-Agent: irnf-probe\r\nConnection: close\r\n\r\n`);
    const sni = r.ok ? (/^sni=(\S+)/m.exec(r.body) || [])[1] || '?' : null;
    return { name, ms: Date.now() - t0, ok: r.ok, sni, error: r.error, log: c.log.join(''), outbounds: cfg.outbounds.map((o) => o.tag) };
  } finally {
    c.child.kill();
  }
}

(async () => {
  const v = spawnSync(XRAY, ['version'], { encoding: 'utf8' });
  console.log((v.stdout || '').split('\n')[0] || `(no version from ${XRAY})`);
  const h2c = `${HOST}+h2c://1.1.1.1/dns-query`;
  const withIt = await line('ECH outbound (h2c through ech-1)', BASE, h2c, true);
  const control = await line('control: the same h2c query, no ECH outbound', BASE + 1, h2c, false);
  const udp = await line('for the record: plain UDP DNS', BASE + 2, `${HOST}+udp://1.1.1.1`, false);
  let fail = false;
  for (const r of [withIt, control, udp]) {
    console.log(`${r.name}: ${r.error ? 'ERROR ' + r.error : `sni=${r.sni}`}${r.ms != null ? ` (${r.ms} ms)` : ''}${r.outbounds ? ` [${r.outbounds.join(', ')}]` : ''}`);
    if (process.env.IRNF_PROBE_LOG && r.log) console.log(r.log.split('\n').filter((l) => /ech|tls|error|fail/i.test(l)).slice(0, 12).join('\n'));
  }
  if (withIt.error || withIt.sni !== 'encrypted') {
    fail = true;
    console.error(`FAIL: with the ECH outbound the page must arrive under ECH (sni=encrypted)\n${withIt.log || ''}`);
  }
  if (!withIt.outbounds || !withIt.outbounds.includes('ech-1')) { fail = true; console.error('FAIL: applyEchOutbounds wrote no ech-1'); }
  if (control.sni === 'encrypted') {
    fail = true;
    console.error('FAIL: the control got the key without the ECH outbound — this probe cannot tell the outbound did anything');
  }
  console.log(fail ? 'RESULT: FAIL' : 'RESULT: OK');
  process.exit(fail ? 1 : 0);
})();
