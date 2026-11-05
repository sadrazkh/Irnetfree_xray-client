#!/usr/bin/env node
'use strict';
/**
 * Direct ports (src/main/directPorts.js) on a real core, loopback only: what
 * enters one leaves outside the VPN, whatever the main connection is doing. The
 * config is the app's own, with a server nothing listens on, so the main
 * connection is dead for the whole run.
 *
 *   this probe ─SOCKS5─▶ dp-<port> ┐
 *              ─HTTP───▶ dp-<port> ┴─▶ dp-direct ─▶ the page
 *              ─SOCKS5─▶ socks-in (sniffing on) ─▶ the dead server: the control
 *
 * Gates:
 *   socks, http  the page answers through each direct port
 *   bytes        /debug/vars: the bytes on dp-direct, none on the plan's exit
 *   no sniffing  a request whose Host names somewhere else still reaches the
 *                address it was sent to: nothing replaced it
 *   control      the same request through the app's own port (sniffing on) does
 *                NOT reach the page, or the gate above proves nothing
 *   sing-box     a TUIC config (sing-box runs it whole) opens the port too
 *   off          an empty list writes the very config of before
 *
 *   IRNF_XRAY_EXE       the core under test
 *   IRNF_SINGBOX_EXE    optional: the sing-box gate
 *   IRNF_PROBE_PORT     base port
 */
const { spawn } = require('child_process');
const fs = require('fs');
const http = require('http');
const net = require('net');
const os = require('os');
const path = require('path');
const { buildConfig } = require('../src/main/configBuilder');
const { buildSingboxConfig } = require('../src/main/singboxBuilder');
const { parseLink } = require('../src/main/parser');

const BASE = Number(process.env.IRNF_PROBE_PORT || 24600);
const PORTS = {
  page: BASE + 0, dead: BASE + 1, socks: BASE + 2, http: BASE + 3, api: BASE + 4, dpSocks: BASE + 5, dpHttp: BASE + 6,
  sbSocks: BASE + 7, sbHttp: BASE + 8, sbDp: BASE + 9
};
const PAGE = 'DIRECT-PORTS-OK';
const DEAD_LINK = `vless://11111111-1111-1111-1111-111111111111@127.0.0.1:${PORTS.dead}?type=tcp&security=none#dead`;
const TUIC_LINK = `tuic://11111111-1111-1111-1111-111111111111:pw@127.0.0.1:${PORTS.dead}?sni=x.example&alpn=h3&allow_insecure=1#t`;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let failed = 0;
function gate(ok, name, detail) {
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}${detail ? ' — ' + detail : ''}`);
  if (!ok) failed++;
}

/** The app's Xray config for the dead server, with or without direct ports. */
function buildProbeConfig(directPorts) {
  const c = buildConfig({ mode: 'single', server: parseLink(DEAD_LINK) }, {
    socksPort: PORTS.socks, httpPort: PORTS.http, apiPort: PORTS.api, geoAssets: false, blockAds: false, enableSniffing: true,
    dnsManaged: false, dnsRemote: ['127.0.0.1'], logLevel: 'warning', ...(directPorts ? { directPorts } : {})
  });
  // the control's page is on loopback, which sniffing leaves alone (sniffRules.js): here it must read the name
  for (const i of c.inbounds) { if (i.sniffing) delete i.sniffing.ipsExcluded; }
  return c;
}

const DIRECT = [{ port: PORTS.dpSocks, type: 'socks' }, { port: PORTS.dpHttp, type: 'http' }];

function runCore(exe, config, args) {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-dp-')), 'c.json');
  fs.writeFileSync(file, JSON.stringify(config));
  const p = spawn(exe, args(file), { windowsHide: true });
  let out = '';
  p.stdout.on('data', (d) => { out += d; });
  p.stderr.on('data', (d) => { out += d; });
  return { p, text: () => out.slice(-2000) };
}

async function waitPort(port, ms = 8000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const up = await new Promise((r) => { const s = net.connect(port, '127.0.0.1', () => { s.destroy(); r(true); }); s.on('error', () => r(false)); });
    if (up) return true;
    await sleep(150);
  }
  return false;
}

/** An HTTP GET of the page through a SOCKS5 port, Host as given → the body, or null when nothing came back in time. */
function getViaSocks(socksPort, hostHeader) {
  return new Promise((resolve) => {
    const s = net.connect(socksPort, '127.0.0.1');
    let stage = 0, buf = Buffer.alloc(0);
    const end = (v) => { clearTimeout(t); s.destroy(); resolve(v); };
    const t = setTimeout(() => end(null), 6000);
    s.on('connect', () => s.write(Buffer.from([5, 1, 0])));
    s.on('error', () => end(null));
    s.on('close', () => end(null));
    s.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      if (stage === 0 && buf.length >= 2) {
        buf = buf.subarray(2); stage = 1;
        s.write(Buffer.from([5, 1, 0, 1, 127, 0, 0, 1, PORTS.page >> 8, PORTS.page & 255]));
      }
      if (stage === 1 && buf.length >= 10) {
        buf = buf.subarray(10); stage = 2;
        s.write(`GET / HTTP/1.1\r\nHost: ${hostHeader}\r\nConnection: close\r\n\r\n`);
      }
      if (stage === 2 && buf.includes(PAGE)) end(PAGE);
    });
  });
}

/** The same through an HTTP proxy port. */
function getViaHttp(proxyPort) {
  return new Promise((resolve) => {
    const req = http.get({ host: '127.0.0.1', port: proxyPort, path: `http://127.0.0.1:${PORTS.page}/`, headers: { Host: `127.0.0.1:${PORTS.page}` }, timeout: 6000 }, (res) => {
      let b = '';
      res.on('data', (d) => { b += d; });
      res.on('end', () => resolve(b));
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
  });
}

function debugVars() {
  return new Promise((resolve) => {
    http.get({ host: '127.0.0.1', port: PORTS.api, path: '/debug/vars', timeout: 3000 }, (res) => {
      let b = '';
      res.on('data', (d) => { b += d; });
      res.on('end', () => { try { resolve(JSON.parse(b)); } catch { resolve(null); } });
    }).on('error', () => resolve(null));
  });
}

async function main() {
  const exe = process.env.IRNF_XRAY_EXE;
  if (!exe || !fs.existsSync(exe)) { console.error('probe-direct-ports: IRNF_XRAY_EXE is not a file'); process.exit(2); }
  const page = http.createServer((q, res) => res.end(PAGE));
  await new Promise((r) => page.listen(PORTS.page, '127.0.0.1', r));

  const cfg = buildProbeConfig(DIRECT);
  const core = runCore(exe, cfg, (f) => ['run', '-c', f]);
  const stops = [() => core.p.kill(), () => page.close()];
  try {
    gate(await waitPort(PORTS.dpSocks), 'the core opened the direct SOCKS port', core.text().slice(-300));
    gate(await waitPort(PORTS.dpHttp), 'the core opened the direct HTTP port');

    gate((await getViaSocks(PORTS.dpSocks, `127.0.0.1:${PORTS.page}`)) === PAGE, 'socks: the page answers with the main connection dead');
    gate((await getViaHttp(PORTS.dpHttp)) === PAGE, 'http: the page answers with the main connection dead');
    gate((await getViaSocks(PORTS.dpSocks, 'probe.invalid')) === PAGE, 'no sniffing: another name in Host does not replace the address');
    gate((await getViaSocks(PORTS.socks, 'probe.invalid')) !== PAGE, 'control: the app\'s own port (sniffing on) does replace it, so the gate above can tell');

    const vars = await debugVars();
    const out = (vars && vars.stats && vars.stats.outbound) || {};
    const dp = out['dp-direct'];
    gate(!!dp && dp.downlink >= PAGE.length, 'bytes: on dp-direct in /debug/vars', dp ? `down ${dp.downlink}, up ${dp.uplink}` : Object.keys(out).join(', '));
  } finally {
    for (const stop of stops) { try { stop(); } catch { /* gone */ } }
  }

  gate(JSON.stringify(buildProbeConfig([])) === JSON.stringify(buildProbeConfig(null)), 'off: an empty list writes the config of before');

  const sbExe = process.env.IRNF_SINGBOX_EXE;
  if (sbExe && fs.existsSync(sbExe)) {
    const page2 = http.createServer((q, res) => res.end(PAGE));
    await new Promise((r) => page2.listen(PORTS.page, '127.0.0.1', r));
    const conf = buildSingboxConfig(parseLink(TUIC_LINK), {
      socksPort: PORTS.sbSocks, httpPort: PORTS.sbHttp, dnsRemote: ['127.0.0.1'], logLevel: 'warning', directPorts: [{ port: PORTS.sbDp, type: 'socks' }]
    });
    const sb = runCore(sbExe, conf, (f) => ['run', '-c', f]);
    try {
      gate(await waitPort(PORTS.sbDp), 'sing-box: a TUIC config opened the direct port', sb.text().slice(-300));
      gate((await getViaSocks(PORTS.sbDp, 'probe.invalid')) === PAGE, 'sing-box: the page answers through it, the address as given');
    } finally {
      sb.p.kill();
      page2.close();
    }
  }

  console.log(failed ? `\n${failed} gate(s) failed — ${path.basename(exe)}` : `\nall gates passed — ${path.basename(exe)}`);
  process.exit(failed ? 1 : 0);
}

if (require.main === module) main().catch((e) => { console.error(e); process.exit(1); });

module.exports = { buildProbeConfig, DIRECT };
