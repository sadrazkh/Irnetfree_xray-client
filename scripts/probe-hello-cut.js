#!/usr/bin/env node
'use strict';
/*
 * A VPN client behind something that reads the name in a TLS hello and dials the name: a server with sniffing on and Route
 * Only off, at the far end of a VPN router's tunnel. Rebuilt on real cores, loopback only:
 *
 *   the app's core  ->  the reader (a real core, sniffing, Route Only off)  ->  the config's server at its address
 *                                                                          \->  the real site its name stands for
 *
 * The reader listens as a transparent proxy does: it is told the address, and swaps it if it can read a name. The cover name
 * resolves, inside the reader only, to a real TLS site at another loopback address on the same port.
 *
 * Gates, for a pinned TLS config and a Reality one, written by the app's own buildConfig:
 *   1. no reader: the config works, so the servers are right;
 *   2. the reader, hello whole: the config dies, and the real site was dialled, which is what the owner's path did;
 *   3. the reader, cutHello: the config works, its own server answered, the real site was not dialled.
 *
 * Then the same config as the SECOND hop of a chain whose first hop is a plain server (a real core, vless over TCP with
 * nothing on it) that itself sniffs with Route Only off — the hop in front reads the hello that comes out of its tunnel:
 *
 *   the app's core  ->  the first hop (sniffing)  ->  the config's server at its address
 *                                                \->  the real site its name stands for
 *
 *   4. the first hop not reading: the chain works, so the chain is right;
 *   5. the first hop reading, hello whole: the chain dies, with and without the chain relay (the relay alone cures nothing);
 *   6. the first hop reading, cutHello: the chain works, the real site was not dialled — without the chain relay, and with
 *      it, where the cut hop's dialer rides the relay (relayHopDials) and the config says so.
 *
 * With IRNF_SINGBOX_EXE set, the sing-box engine too: the app's own buildSingboxConfig, whose cut is sing-box's
 * `tls.record_fragment` (singboxBuilder.cutsHello), for a TLS config through the same reader — the same three gates. (Not
 * Reality: sing-box 1.14.4's Reality client does not authenticate against an Xray 26.10 Reality server even with nothing
 * in between — "authentication failed or validation criteria not met" — so there is nothing there for a reader to break.)
 *
 * Needs 127.0.0.2 (Linux, Windows; macOS has only 127.0.0.1 unless told otherwise).
 * IRNF_XRAY_EXE  the core; IRNF_SINGBOX_EXE  sing-box (optional); IRNF_PROBE_PORT  base port.
 */
const { spawn, spawnSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const net = require('net');
const os = require('os');
const path = require('path');
const tls = require('tls');
const { buildConfig } = require('../src/main/configBuilder');
const { buildSingboxConfig } = require('../src/main/singboxBuilder');
const { parseLink } = require('../src/main/parser');

const BASE = Number(process.env.IRNF_PROBE_PORT || 25000);
const PORTS = { socks: BASE, http: BASE + 1, api: BASE + 2, target: BASE + 3, tls: BASE + 4, reality: BASE + 5, readTls: BASE + 6, readReality: BASE + 7,
  hop: BASE + 8, hopQuiet: BASE + 9, relay: BASE + 10 };
const XRAY = process.env.IRNF_XRAY_EXE || 'xray';
const SINGBOX = process.env.IRNF_SINGBOX_EXE || '';
const OWN = '127.0.0.1', SITE = '127.0.0.2';
const COVER = 'cover.example.test', OWN_NAME = 'own.example.test', TARGET = '203.0.113.7';
const ID = '11111111-1111-1111-1111-111111111111';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let failed = 0;
function gate(ok, name, detail) {
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}${detail ? ' — ' + detail : ''}`);
  if (!ok) failed++;
}
function certFor(domain) {
  const made = spawnSync(XRAY, ['tls', 'cert', `--domain=${domain}`, '--json'], { encoding: 'utf8', timeout: 20000, windowsHide: true });
  const c = JSON.parse(made.stdout);
  const pem = c.certificate.join('\n') + '\n';
  return { certificate: c.certificate, key: c.key, pem, keyPem: c.key.join('\n').replace(/RSA PRIVATE KEY/g, 'PRIVATE KEY') + '\n', pin: new crypto.X509Certificate(pem).fingerprint256.replace(/:/g, '').toLowerCase() };
}
function realityKeys() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
  const raw = (k, type) => k.export({ format: 'der', type }).subarray(-32).toString('base64url');
  return { pub: raw(publicKey, 'spki'), priv: raw(privateKey, 'pkcs8') };
}
function listening(port, host = '127.0.0.1') {
  return new Promise((res) => { const s = net.connect(port, host, () => { s.destroy(); res(true); }); s.on('error', () => res(false)); });
}
const cores = new Set();
async function core(name, cfg, port, work, bin = XRAY) {
  const file = path.join(work, name + '.json');
  fs.writeFileSync(file, JSON.stringify(cfg));
  const p = spawn(bin, ['run', '-c', file], { stdio: ['ignore', 'ignore', 'pipe'], windowsHide: true });
  let err = '';
  p.stderr.on('data', (d) => { err = (err + d).slice(-400); });
  p.on('exit', () => cores.delete(p));
  cores.add(p);
  for (let i = 0; i < 80; i++) {
    await sleep(100);
    if (await listening(port)) return p;
    if (p.exitCode != null) break;
  }
  throw new Error(`${name} did not start: ${err}`);
}
const stop = async (p) => { if (p && p.exitCode == null) { p.kill(); await new Promise((r) => p.once('exit', r)); } };

/** One request through the client's SOCKS inbound, to an address only the server's redirect can reach: going direct cannot pass. */
function through(port) {
  return new Promise((res) => {
    const c = net.connect(port, '127.0.0.1');
    const address = Buffer.from(TARGET.split('.').map(Number));
    const portBytes = Buffer.alloc(2); portBytes.writeUInt16BE(PORTS.target);
    let stage = 0, body = '';
    const done = (v) => { clearTimeout(t); c.destroy(); res(v); };
    const t = setTimeout(() => done({ ok: false, why: 'no answer in 8 s' }), 8000);
    c.on('error', (e) => done({ ok: false, why: e.code }));
    c.on('connect', () => c.write(Buffer.from([5, 1, 0])));
    c.on('data', (d) => {
      if (stage === 0) { stage = 1; c.write(Buffer.concat([Buffer.from([5, 1, 0, 1]), address, portBytes])); return; }
      if (stage === 1) {
        stage = 2;
        if (d[1] !== 0) return done({ ok: false, why: 'refused ' + d[1] });
        c.write(`GET / HTTP/1.1\r\nHost: ${TARGET}\r\nConnection: close\r\n\r\n`);
        return;
      }
      body += d;
      if (body.includes('through-the-own-server')) done({ ok: true });
    });
    c.on('close', () => done({ ok: false, why: 'closed' }));
  });
}
const CLIENT = { socksPort: PORTS.socks, httpPort: PORTS.http, apiPort: PORTS.api, geoAssets: false, blockAds: false, enableSniffing: false, routingMode: 'global' };
function clientConfig(link, cutHello) {
  return buildConfig({ mode: 'single', server: parseLink(link) }, Object.assign({}, CLIENT, { cutHello }));
}
/** The config as the second hop of a chain behind a plain first hop at `hopPort`; `relay`: with the chain relay. */
function chainConfig(link, hopPort, cutHello, relay) {
  const hop = parseLink(`vless://${ID}@127.0.0.1:${hopPort}?type=tcp&security=none#hop`);
  return buildConfig({ mode: 'chain', chain: [hop, parseLink(link)], name: 'c' }, Object.assign({}, CLIENT, { cutHello, chainRelayPort: relay ? PORTS.relay : 0 }));
}

(async () => {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-hello-cut-'));
  console.log((spawnSync(XRAY, ['version'], { encoding: 'utf8', windowsHide: true }).stdout || '').split(/\r?\n/)[0]);
  const own = certFor(OWN_NAME);
  const site = certFor(COVER);
  const keys = realityKeys();

  // what the name really stands for: a TLS site of its own, on each server's port at another address
  let siteHits = 0;
  const sites = [PORTS.tls, PORTS.reality].map((port) => {
    const s = tls.createServer({ cert: site.pem, key: site.keyPem, ALPNProtocols: ['h2', 'http/1.1'], minVersion: 'TLSv1.3' }, (c) => { c.on('error', () => {}); c.end('HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nthe-real-site'); });
    s.on('connection', () => { siteHits++; });
    s.on('tlsClientError', () => {});
    s.listen(port, SITE);
    return s;
  });
  await sleep(200);
  const target = http.createServer((q, r) => r.end('through-the-own-server')).listen(PORTS.target, '127.0.0.1');

  const serverCfg = {
    log: { loglevel: 'none' },
    inbounds: [
      { tag: 'tls', listen: OWN, port: PORTS.tls, protocol: 'vless', settings: { clients: [{ id: ID }], decryption: 'none' },
        streamSettings: { network: 'tcp', security: 'tls', tlsSettings: { certificates: [{ certificate: own.certificate, key: own.key }] } } },
      { tag: 'reality', listen: OWN, port: PORTS.reality, protocol: 'vless', settings: { clients: [{ id: ID }], decryption: 'none' },
        streamSettings: { network: 'tcp', security: 'reality', realitySettings: { target: `${SITE}:${PORTS.reality}`, serverNames: [COVER], privateKey: keys.priv, shortIds: [''] } } }
    ],
    outbounds: [{ tag: 'out', protocol: 'freedom', settings: { redirect: `127.0.0.1:${PORTS.target}`, finalRules: [{ action: 'allow' }] } }]
  };
  const reading = { enabled: true, destOverride: ['tls'], routeOnly: false };   // a panel's usual setting
  const readerCfg = {
    log: { loglevel: 'none' },
    dns: { hosts: { [COVER]: SITE } },
    inbounds: [
      { tag: 'r-tls', listen: '127.0.0.1', port: PORTS.readTls, protocol: 'dokodemo-door', settings: { address: OWN, port: PORTS.tls, network: 'tcp' }, sniffing: reading },
      { tag: 'r-reality', listen: '127.0.0.1', port: PORTS.readReality, protocol: 'dokodemo-door', settings: { address: OWN, port: PORTS.reality, network: 'tcp' }, sniffing: reading }
    ],
    outbounds: [{ tag: 'out', protocol: 'freedom', settings: { domainStrategy: 'UseIPv4', finalRules: [{ action: 'allow' }] } }]
  };
  // a plain first hop: the same reading on its inbound (a panel's usual setting), and one that reads nothing
  const hopIn = (tag, port, sniffing) => Object.assign({ tag, listen: '127.0.0.1', port, protocol: 'vless', settings: { clients: [{ id: ID }], decryption: 'none' },
    streamSettings: { network: 'tcp', security: 'none' } }, sniffing ? { sniffing } : {});
  const hopCfg = {
    log: { loglevel: 'none' },
    dns: { hosts: { [COVER]: SITE } },
    inbounds: [hopIn('hop', PORTS.hop, reading), hopIn('hop-quiet', PORTS.hopQuiet, null)],
    outbounds: [{ tag: 'out', protocol: 'freedom', settings: { domainStrategy: 'UseIPv4', finalRules: [{ action: 'allow' }] } }]
  };
  await core('server', serverCfg, PORTS.tls, work);
  await core('reader', readerCfg, PORTS.readTls, work);
  await core('hop', hopCfg, PORTS.hop, work);

  const links = {
    'pinned TLS': (port) => `vless://${ID}@127.0.0.1:${port}?type=tcp&security=tls&sni=${COVER}&pcs=${own.pin}&fp=chrome#t`,
    Reality: (port) => `vless://${ID}@127.0.0.1:${port}?type=tcp&security=reality&sni=${COVER}&pbk=${keys.pub}&sid=&fp=chrome#t`
  };
  const direct = { 'pinned TLS': PORTS.tls, Reality: PORTS.reality };
  const viaReader = { 'pinned TLS': PORTS.readTls, Reality: PORTS.readReality };

  for (const kind of Object.keys(links)) {
    const run = async (port, cut) => {
      const hitsBefore = siteHits;
      const c = await core('client', clientConfig(links[kind](port), cut), PORTS.socks, work);
      await sleep(300);
      const r = await through(PORTS.socks);
      await stop(c);
      await sleep(150);
      return Object.assign(r, { dialled: siteHits - hitsBefore, cfg: cut });
    };
    const clean = await run(direct[kind], false);
    gate(clean.ok, `${kind}: with nothing reading, it works`, clean.why);
    const whole = await run(viaReader[kind], false);
    gate(!whole.ok, `${kind}: through a reader with a whole hello, it dies (what the owner saw)`, whole.ok ? 'it passed, so the reader read nothing' : whole.why);
    // a Reality server dials the real site itself on every connection, so only the pinned one can tell
    if (kind !== 'Reality') gate(whole.dialled > 0, `${kind}: the reader dialled the real site the name stands for`, `${whole.dialled} dial(s)`);
    const cut = await run(viaReader[kind], true);
    gate(cut.ok, `${kind}: through the same reader with a cut hello, it works`, cut.why);
    if (kind !== 'Reality') gate(cut.dialled === 0, `${kind}: and the real site was not dialled`, `${cut.dialled} dial(s)`);

    // the same config as the second hop of a chain: the hop in front reads the hello that comes out of its tunnel
    const chainRun = async (hopPort, cut, relay) => {
      const hitsBefore = siteHits;
      const cfg = chainConfig(links[kind](direct[kind]), hopPort, cut, relay);
      const exit = cfg.outbounds.find((o) => o.tag === 'proxy');
      const dialer = cfg.outbounds.find((o) => o.tag === exit.streamSettings.sockopt.dialerProxy);
      const c = await core('client', cfg, PORTS.socks, work);
      await sleep(300);
      const r = await through(PORTS.socks);
      await stop(c);
      await sleep(150);
      return Object.assign(r, { dialled: siteHits - hitsBefore, exitVia: exit.streamSettings.sockopt.dialerProxy, dialer, relayIn: cfg.inbounds.some((i) => i.tag === 'chain-relay') });
    };
    const quiet = await chainRun(PORTS.hopQuiet, false, false);
    gate(quiet.ok, `${kind}: behind a first hop that reads nothing, the chain works`, quiet.why);
    gate(quiet.exitVia === 'proxy-h0' && !quiet.relayIn, `${kind}: and the second hop dials the first, as always`, quiet.exitVia);
    for (const relay of [false, true]) {
      const where = relay ? 'with the chain relay' : 'without the chain relay';
      const whole = await chainRun(PORTS.hop, false, relay);
      gate(!whole.ok, `${kind}: behind a first hop that reads, with a whole hello, the chain dies (${where})`, whole.ok ? 'it passed, so the hop read nothing' : whole.why);
      if (kind !== 'Reality') gate(whole.dialled > 0, `${kind}: the first hop dialled the real site (${where})`, `${whole.dialled} dial(s)`);
      const cut = await chainRun(PORTS.hop, true, relay);
      gate(cut.ok, `${kind}: behind the same first hop with a cut hello, the chain works (${where})`, cut.why);
      if (kind !== 'Reality') gate(cut.dialled === 0, `${kind}: and the real site was not dialled (${where})`, `${cut.dialled} dial(s)`);
      const d = cut.dialer;
      const dialerOk = d && d.protocol === 'freedom' && /^dpi-/.test(d.tag) && d.settings.fragment && d.settings.fragment.interval === '0-0';
      const via = d && d.streamSettings && d.streamSettings.sockopt && d.streamSettings.sockopt.dialerProxy;
      gate(dialerOk && via === (relay ? 'chain-relay~proxy-h0' : 'proxy-h0') && cut.relayIn === relay,
        `${kind}: the second hop dials a cut dialer that dials the first hop ${relay ? 'over the relay' : 'itself'}`, `${cut.exitVia} -> ${via}`);
    }
  }

  // what is left alone stays as it was: a config with a fragment of its own keeps it, and off writes nothing at all
  const own2 = parseLink(`vless://${ID}@127.0.0.1:${PORTS.tls}?type=tcp&security=tls&sni=${COVER}&pcs=${own.pin}&fp=chrome&fragment=1-3,5-9,20-30#own`);
  const c1 = buildConfig({ mode: 'single', server: own2 }, { socksPort: PORTS.socks, httpPort: PORTS.http, apiPort: PORTS.api, geoAssets: false, blockAds: false, enableSniffing: false, routingMode: 'global', cutHello: true });
  const dialer = c1.outbounds.find((o) => /^dpi-/.test(o.tag));
  gate(dialer && dialer.settings.fragment.interval !== '0-0', 'a config with a fragment of its own keeps its own', dialer ? JSON.stringify(dialer.settings.fragment) : 'no dialer');

  // the sing-box engine: the same server, the same reader, the app's sing-box config — its cut is tls.record_fragment
  if (SINGBOX) {
    const sbVersion = (spawnSync(SINGBOX, ['version'], { encoding: 'utf8', windowsHide: true }).stdout || '').split(/\r?\n/)[0];
    console.log(sbVersion);
    // sing-box keeps no pin (it runs a pinned config on Xray), so its TLS config is the insecure one: the gates still
    // tell, since the real site's answer is no VLESS server's and the dial count is the real site's own
    const sbLink = (port) => `vless://${ID}@127.0.0.1:${port}?type=tcp&security=tls&sni=${COVER}&allowInsecure=1&fp=chrome#sb`;
    const sbRun = async (port, cut) => {
      const hitsBefore = siteHits;
      const cfg = buildSingboxConfig(parseLink(sbLink(port)), { socksPort: PORTS.socks, httpPort: 0, logLevel: 'error', cutHello: cut, singboxVersion: sbVersion });
      const c = await core('sb-client', cfg, PORTS.socks, work, SINGBOX);
      await sleep(300);
      const r = await through(PORTS.socks);
      await stop(c);
      await sleep(150);
      return Object.assign(r, { dialled: siteHits - hitsBefore, cfg });
    };
    const clean = await sbRun(PORTS.tls, false);
    gate(clean.ok, 'sing-box TLS: with nothing reading, it works', clean.why);
    gate(!clean.cfg.outbounds[0].tls.record_fragment, 'sing-box TLS: off, no record_fragment is written');
    const whole = await sbRun(PORTS.readTls, false);
    gate(!whole.ok, 'sing-box TLS: through a reader with a whole hello, it dies', whole.ok ? 'it passed, so the reader read nothing' : whole.why);
    gate(whole.dialled > 0, 'sing-box TLS: the reader dialled the real site the name stands for', `${whole.dialled} dial(s)`);
    const cut = await sbRun(PORTS.readTls, true);
    gate(cut.cfg.outbounds[0].tls.record_fragment === true, 'sing-box TLS: on, the config carries record_fragment');
    gate(cut.ok, 'sing-box TLS: through the same reader with the hello in records, it works', cut.why);
    gate(cut.dialled === 0, 'sing-box TLS: and the real site was not dialled', `${cut.dialled} dial(s)`);
  }

  for (const p of [...cores]) await stop(p);
  sites.forEach((s) => s.close());
  target.close();
  fs.rmSync(work, { recursive: true, force: true });
  console.log(failed ? `${failed} gate(s) failed` : 'every gate passed');
  process.exit(failed ? 1 : 0);
})().catch((e) => {
  console.error(String((e && e.stack) || e).slice(0, 600));
  for (const p of cores) p.kill();
  process.exit(1);
});
