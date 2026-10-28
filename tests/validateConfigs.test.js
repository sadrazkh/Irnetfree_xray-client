'use strict';
/**
 * The gate CI hands the suggested cores: scripts/validate-configs.js, run by
 * the `cores` job of .github/workflows/test.yml — the only place a core is run
 * on what this app writes, never the machine running this suite.
 *
 * Here the script runs dry (IRNF_VALIDATE_DRY=1: every config built, written
 * for the core's version and saved, no core run), so a link form the parser
 * stops taking, or a shape that stops carrying what it is there to check, is
 * found by `npm test` on every platform — not by a red `cores` job, or by a
 * green one that checked nothing.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { SUGGESTED } = require('../src/main/coreVersions');

const SCRIPT = path.join(__dirname, '..', 'scripts', 'validate-configs.js');

/**
 * The script, dry, into a fresh dir: its exit status and output, and its
 * configs by name. One run per environment for the whole file — the tests
 * only read what it wrote, and every run is a few hundred configs built on a
 * CI runner the timing-sensitive service tests share.
 */
const runs = new Map();
test.after(() => { for (const r of runs.values()) fs.rmSync(r.dir, { recursive: true, force: true }); });
function dryRun(t, env = {}) {
  const key = JSON.stringify(env);
  if (!runs.has(key)) runs.set(key, freshRun(env));
  return runs.get(key);
}
function freshRun(env) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-vc-'));
  const base = Object.assign({}, process.env);
  for (const k of ['IRNF_XRAY_EXE', 'IRNF_SINGBOX_EXE', 'IRNF_CORE_VERSION']) delete base[k];
  const r = spawnSync(process.execPath, [SCRIPT], {
    env: Object.assign(base, { IRNF_VALIDATE_DRY: '1', IRNF_VALIDATE_OUT: dir }, env),
    encoding: 'utf8', timeout: 60000, windowsHide: true
  });
  const read = (name) => JSON.parse(fs.readFileSync(path.join(dir, `${name}.json`), 'utf8'));
  return {
    status: r.status, out: `${r.stdout || ''}${r.stderr || ''}`, dir, read,
    proxy: (name) => read(name).outbounds.find((o) => o.tag === 'proxy'),
    built: `${r.stdout || ''}`.split(/\r?\n/).filter((l) => l.startsWith('built ')).map((l) => l.slice(6))
  };
}

const FORMS = ['ech-udp', 'ech-doh', 'ech-b64', 'pins', 'grpc-authority', 'kcp', 'hy2', 'ss-obfs', 'ss-v2ray', 'reality-pqv'];

test('the core gate builds every config without a core — the v1.18 link forms plain, under TUN and under the strict leak guard', { timeout: 60000 }, (t) => {
  const run = dryRun(t);
  assert.equal(run.status, 0, run.out);
  assert.equal(fs.readdirSync(run.dir).length, run.built.length, 'every config it names is on disk');
  assert.match(run.out, new RegExp(`^${run.built.length} configs built for xray ${SUGGESTED.xray.replace(/\./g, '\\.')} \\(15 of them sing-box TUN configs, \\d+ sing-box TUIC / AnyTLS configs\\)`, 'm'));
  // every desktop TUN's loopback API with find_process — alone, and beside the per-app split's process_name rule
  for (const name of ['tun-windows-watch', 'tun-watch-apps']) {
    const cfg = run.read(name);
    assert.deepEqual(cfg.experimental, { clash_api: { external_controller: '127.0.0.1:30860', secret: '0123456789abcdef0123456789abcdef' } }, name);
    assert.equal(cfg.route.find_process, true, name);
  }
  assert.equal(run.read('tun-watch-apps').route.rules[1].process_name[0], 'steam.exe');
  assert.equal(run.read('tun-v6false-strictfalse-exclude0').route.find_process, undefined, 'no API, no lookup: the output of before');
  assert.ok(run.built.length > 200, `the plans × DNS modes matrix and the shapes are still there: ${run.built.length}`);
  for (const form of FORMS) {
    for (const v of ['plain', 'tun', 'strict']) assert.ok(run.built.includes(`link-${form}-${v}.json`), `link-${form}-${v}`);
  }
  // ECH: as the link says; under TUN its DNS query bound to the NIC; under the strict guard asked over DoH
  const ech = (v) => run.proxy(`link-ech-udp-${v}`).streamSettings.tlsSettings;
  assert.deepEqual([ech('plain').echConfigList, ech('plain').echSockopt], ['cloudflare-ech.com+udp://1.1.1.1', undefined]);
  assert.deepEqual([ech('tun').echConfigList, ech('tun').echSockopt], ['cloudflare-ech.com+udp://1.1.1.1', { interface: 'eth0' }]);
  assert.deepEqual([ech('strict').echConfigList, ech('strict').echSockopt], ['cloudflare-ech.com+https://1.1.1.1/dns-query', { interface: 'eth0' }]);
  assert.equal(run.proxy('link-ech-doh-plain').streamSettings.tlsSettings.echConfigList, 'cloudflare-ech.com+https://1.1.1.1/dns-query');
  // …and the list itself (base64): nothing to ask, nothing to bind
  const b64 = run.proxy('link-ech-b64-tun').streamSettings.tlsSettings;
  assert.match(b64.echConfigList, /^[A-Za-z0-9+/]+=*$/);
  assert.equal(b64.echSockopt, undefined);
  // the certificate pins and the name to verify, gRPC's :authority, REALITY's ML-DSA-65 key
  const pins = run.proxy('link-pins-plain').streamSettings.tlsSettings;
  assert.deepEqual([pins.pinnedPeerCertSha256, pins.verifyPeerCertByName], ['ab'.repeat(32), 'real.example']);
  assert.equal(run.proxy('link-grpc-authority-plain').streamSettings.grpcSettings.authority, 'auth.example');
  assert.equal(Buffer.from(run.proxy('link-reality-pqv-plain').streamSettings.realitySettings.mldsa65Verify, 'base64url').length, 1952);
  // Hysteria2: salamander, the port hopping and the bandwidth
  const hy = run.proxy('link-hy2-plain').streamSettings.finalmask;
  assert.deepEqual(hy.udp.map((m) => m.type), ['salamander', 'udphop']);
  assert.deepEqual(hy.quicParams, { brutalUp: '50 mbps', brutalDown: '100 mbps' });
  // Shadowsocks' plugins as the transports the core has
  assert.equal(run.proxy('link-ss-obfs-plain').streamSettings.tcpSettings.header.type, 'http');
  const ws = run.proxy('link-ss-v2ray-plain').streamSettings;
  assert.deepEqual([ws.network, ws.security, ws.wsSettings.path], ['ws', 'tls', '/ws']);
});

test('the core gate hands the cores every mux shape (v1.18, spec §4): a single server, the anti-DPI dialer with pins under TUN, advanced, pool, the field report’s ECH-over-ws link, and the probe’s own test core', { timeout: 60000 }, (t) => {
  const { MUX } = require('../src/main/mux');
  const run = dryRun(t);
  assert.equal(run.status, 0, run.out);
  const muxed = (name) => run.read(name).outbounds.filter((o) => o.mux).map((o) => o.tag);
  assert.deepEqual(run.proxy('shape-single-mux').mux, MUX);
  assert.deepEqual(muxed('shape-single-mux-pinned-fragment-bound'), ['proxy']);
  const frag = run.proxy('shape-single-mux-pinned-fragment-bound').streamSettings.sockopt;
  assert.deepEqual([frag.dialerProxy, frag.domainStrategy], ['dpi-1', 'UseIPv4'], 'mux beside the dialer and the pin');
  assert.deepEqual(muxed('shape-advanced-mux').sort(), ['out-sv-vless'], 'the default; the chain’s VLESS hop never');
  assert.deepEqual(muxed('shape-pool-mux'), ['out-sv-vless']);
  for (const v of ['plain', 'tun', 'strict']) assert.deepEqual(run.proxy(`link-ech-udp-mux-${v}`).mux, MUX, v);
  assert.equal(run.proxy('link-ech-udp-mux-tun').streamSettings.tlsSettings.echConfigList, 'cloudflare-ech.com+udp://1.1.1.1');
  const probe = run.read('mux-probe');
  assert.deepEqual(probe.outbounds.find((o) => o.tag === 'proxy').mux, MUX);
  assert.deepEqual(probe.dns, { hosts: { 'a.example.com': ['203.0.113.10', '203.0.113.11'] } }, 'the probe dials the names its connect resolved');
  // and not one of the configs built without the setting carries mux — but a
  // JSON server's own: its main outbound is kept as written, its mux with it
  // (the "via a base" shapes carry mux under TUN on purpose, and JSON servers: their own test)
  // the editor's servers are set to Mux on, with their own numbers
  assert.deepEqual(run.proxy('editor-vless-ws-tls').mux, Object.assign({}, MUX, { concurrency: 4, xudpConcurrency: 16 }));
  for (const name of run.built.filter((n) => !/mux/.test(n) && !/^(json|via|editor)-/.test(n))) assert.equal(JSON.stringify(run.read(name.replace(/\.json$/, ''))).includes('"mux"'), false, name);
});

test('the core gate writes every config for the core’s own version: mKCP’s header and seed, Hysteria’s hopping — as the suggested Xray takes them, and as a January 2026 core did', { timeout: 60000 }, (t) => {
  const now = dryRun(t);
  assert.equal(now.status, 0, now.out);
  const kcp = now.proxy('link-kcp-plain').streamSettings;
  assert.deepEqual(kcp.kcpSettings, { mtu: 1350 });
  assert.deepEqual(kcp.finalmask.udp, [{ type: 'mkcp-legacy', settings: { value: 'S' } }, { type: 'mkcp-legacy', settings: { header: 'wechat' } }]);
  const old = dryRun(t, { IRNF_CORE_VERSION: '26.1.23' });
  assert.equal(old.status, 0, old.out);
  assert.match(old.out, /configs built for xray 26\.1\.23 /);
  const oldKcp = old.proxy('link-kcp-plain').streamSettings;
  assert.deepEqual(oldKcp.kcpSettings, { header: { type: 'wechat-video' }, seed: 'S', mtu: 1350 });
  assert.equal(oldKcp.finalmask, undefined);
  const oldHy = old.proxy('link-hy2-plain').streamSettings;
  assert.deepEqual(oldHy.hysteriaSettings, { version: 2, auth: 'pw', udphop: { ports: '20000-30000', interval: '30' }, up: '50 mbps', down: '100 mbps' });
  assert.deepEqual(oldHy.finalmask, { udp: [{ type: 'salamander', settings: { password: 'OB' } }] });
});

test('the core gate hands the cores every JSON shape: each fixture server in full mode (plain and under TUN), the Xray fixtures raw, JSON servers in a chain, advanced routing and a latency test', { timeout: 60000 }, (t) => {
  const { importJson } = require('../src/main/jsonImport');
  const run = dryRun(t);
  assert.equal(run.status, 0, run.out);
  const fixtures = ['xray-subscription', 'xray-fragment', 'xray-chain', 'xray-balancer', 'xray-wireguard', 'xray-masque', 'singbox'];
  let xrayServers = 0;
  for (const f of fixtures) {
    const servers = importJson(fs.readFileSync(path.join(__dirname, 'fixtures', 'json', `${f}.json`), 'utf8')).servers;
    assert.ok(servers.length > 0, f);
    servers.forEach((s, i) => {
      // the sing-box fixture's TUIC: no Xray takes it — sing-box checks it (singbox-json-singbox-<i>-…)
      if (s.protocol === 'tuic' || s.protocol === 'anytls') {
        assert.ok(run.built.includes(`singbox-json-${f}-${i}-connect.json`) && !run.built.includes(`json-${f}-${i}-full-plain.json`), `json-${f}-${i}: sing-box's`);
        return;
      }
      for (const v of ['plain', 'tun']) assert.ok(run.built.includes(`json-${f}-${i}-full-${v}.json`), `json-${f}-${i}-full-${v}`);
      for (const v of ['plain', 'tun']) {
        assert.equal(run.built.includes(`json-${f}-${i}-raw-${v}.json`), s.source === 'json', `json-${f}-${i}-raw-${v}: raw is for Xray JSON only`);
      }
      if (s.source === 'json') xrayServers++;
    });
  }
  // (xray-masque: its WARP and HTTP/2 servers are ordinary ones, its panel config the one JSON server)
  assert.equal(xrayServers, 5 + 1 + 1 + 2 + 1 + 1);
  // full mode: the helpers beside the main outbound, renamed; raw: the config as written, the app's inbounds
  const tags = (name) => run.read(name).outbounds.map((o) => o.tag);
  assert.deepEqual(tags('json-xray-fragment-0-full-plain').slice(0, 2), ['proxy', 'proxy~fragment']);
  assert.deepEqual(tags('json-xray-chain-0-full-plain').slice(0, 3), ['proxy', 'proxy~hop1', 'proxy~frag']);
  assert.equal(run.read('json-xray-chain-0-full-tun').outbounds[2].streamSettings.sockopt.interface, 'eth0');
  const raw = run.read('json-xray-balancer-0-raw-plain');
  const fx = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', 'json', 'xray-balancer.json'), 'utf8'));
  assert.deepEqual(raw.routing, fx.routing);
  assert.deepEqual(raw.observatory, fx.observatory);
  assert.deepEqual(raw.inbounds.map((i) => i.tag), ['socks-in', 'http-in']);
  assert.deepEqual(tags('json-xray-subscription-0-raw-plain'), ['proxy', 'direct', 'block']);
  // a JSON server as either hop of a chain, two of them under advanced routing, the latency test
  assert.deepEqual(tags('json-chain-later').slice(0, 2), ['proxy-h0', 'proxy']);
  assert.deepEqual(tags('json-chain-first').slice(0, 3), ['proxy-h0', 'proxy-h0~fragment', 'proxy']);
  assert.ok(tags('json-advanced').includes('out-jf~fragment') && tags('json-advanced').includes('out-jc~hop1'));
  assert.deepEqual(tags('json-test-chain'), ['proxy', 'proxy~hop1', 'proxy~frag', 'direct']);
  // what the cores refuse is never handed to them: allowInsecure, proxySettings
  for (const name of run.built.filter((n) => /^json-/.test(n))) {
    const text = JSON.stringify(run.read(name.replace(/\.json$/, '')));
    assert.equal(text.includes('allowInsecure'), false, name);
    assert.equal(text.includes('proxySettings'), false, name);
  }
  assert.equal(run.proxy('json-raw-pinned').streamSettings.tlsSettings.pinnedPeerCertSha256, 'ab11bf7ac877baa539294f5a3c864b8ed43e6fe3a9a8230fc2db7fff85c27fde');
  assert.equal(run.read('json-raw-wg-resolved').outbounds[0].settings.peers[0].endpoint, '198.51.100.7:51820');
  const pinned = run.read('json-chain-pinned');
  assert.deepEqual(pinned.dns.hosts['hop.example.com'], ['203.0.113.30']);
  assert.equal(pinned.outbounds.find((o) => o.tag === 'proxy~hop1').streamSettings.sockopt.domainStrategy, 'UseIPv4');
});

test('the core gate hands the cores every MASQUE shape: HTTP/3 and HTTP/2 with a user, a WARP account over both and behind a cover domain, noise before QUIC and a fragment of the TCP — never Mux, never allowInsecure', { timeout: 60000 }, (t) => {
  const run = dryRun(t);
  assert.equal(run.status, 0, run.out);
  const names = ['h3', 'h2', 'warp-h3', 'warp-h2', 'warp-cover', 'warp-h3-noise', 'warp-h2-fragment'];
  for (const n of names) for (const v of ['plain', 'tun', 'strict']) assert.ok(run.built.includes(`editor-masque-${n}-${v}.json`), `editor-masque-${n}-${v}`);
  const st = (name) => run.proxy(name).streamSettings;
  assert.deepEqual(st('editor-masque-h3-plain').masqueSettings, { user: 'irnf-ci', pass: 'irnf-ci-pass' });
  assert.equal(st('editor-masque-h3-plain').tlsSettings.alpn, undefined, 'HTTP/3: no ALPN');
  assert.deepEqual([st('editor-masque-h2-plain').tlsSettings.alpn, st('editor-masque-h2-plain').tlsSettings.fingerprint], [['h2'], 'chrome']);
  const w = st('editor-masque-warp-h3-plain').masqueSettings.warp;
  assert.match(w.privateKey, /^MIG/, 'the sign-up’s PEM, as the one line of base64 the record keeps');
  assert.deepEqual(w.address, ['172.16.0.2/32', '2606:4700:110:8a36::2/128']);
  assert.equal(run.proxy('editor-masque-warp-h2-plain').settings.address, '162.159.198.2');
  const cover = st('editor-masque-warp-cover-plain').tlsSettings;
  assert.deepEqual([cover.serverName, cover.verifyPeerCertByName], ['www.example.com', 'www.example.com']);
  // anti-DPI: a noise dialer for HTTP/3, a fragment one for HTTP/2 — bound to the NIC under TUN
  const dpi = (name) => run.read(name).outbounds.filter((o) => /^dpi-/.test(o.tag));
  assert.deepEqual(dpi('editor-masque-warp-h3-noise-plain').map((o) => [!!o.settings.noises, !!o.settings.fragment]), [[true, false]]);
  assert.deepEqual(dpi('editor-masque-warp-h2-fragment-plain').map((o) => [!!o.settings.noises, !!o.settings.fragment]), [[false, true]]);
  assert.equal(dpi('editor-masque-warp-h3-noise-tun')[0].streamSettings.sockopt.interface, 'eth0');
  assert.equal(st('editor-masque-warp-h3-noise-plain').sockopt.dialerProxy, 'dpi-1');
  // the table's generic MASQUE server: every field it has but WARP's
  const ed = run.proxy('editor-masque');
  assert.deepEqual(ed.settings.remoteDNS, ['1.1.1.1', '2606:4700:4700::1111']);
  assert.deepEqual(ed.streamSettings.masqueSettings.headers, { 'User-Agent': 'chrome' });
  assert.equal(ed.streamSettings.tlsSettings.useSystemCA, true);
  for (const name of run.built.filter((n) => /^editor-masque/.test(n))) {
    const text = JSON.stringify(run.read(name.replace(/\.json$/, '')));
    assert.equal(text.includes('"mux"'), false, name);
    assert.equal(text.includes('allowInsecure'), false, name);
  }
});

test('the core gate hands the cores every "via a base" shape (routing profiles): a server and a chain base, explicit / none, a WireGuard and JSON servers through a base and as one — plain, under TUN with pins and mux, under the strict guard', { timeout: 60000 }, (t) => {
  const run = dryRun(t);
  assert.equal(run.status, 0, run.out);
  const names = ['server-base', 'chain-base', 'explicit-and-none', 'wg-through-base', 'json-through-base', 'json-as-base'];
  for (const n of names) for (const v of ['managed', 'tun', 'strict']) assert.ok(run.built.includes(`via-${n}-${v}.json`), `via-${n}-${v}`);
  const outs = (name) => run.read(name).outbounds;
  const dialer = (name, tag) => {
    const o = outs(name).find((x) => x.tag === tag);
    assert.ok(o, `${name}: ${tag}`);
    return (o.streamSettings && o.streamSettings.sockopt && o.streamSettings.sockopt.dialerProxy) || null;
  };
  // one base, every target through it dialing its exit
  assert.deepEqual(outs('via-server-base-managed').map((o) => o.tag).filter((x) => /^(base-|out-)/.test(x)),
    ['base-sv-vless', 'out-sv-trojan@sv-vless', 'out-sv-ss@sv-vless', 'out-chain-c2@sv-vless-h0', 'out-chain-c2@sv-vless', 'out-sv-vless']);
  // a TCP dial through a base rides the chain relay to it (configBuilder.relayHopDials), routed there first
  assert.equal(dialer('via-server-base-managed', 'out-sv-trojan@sv-vless'), 'chain-relay~base-sv-vless');
  assert.equal(dialer('via-server-base-managed', 'out-chain-c2@sv-vless-h0'), 'base-sv-vless', 'a Shadowsocks hop keeps it: its UDP is UDP');
  assert.deepEqual(run.read('via-server-base-managed').routing.rules[0], { type: 'field', inboundTag: ['chain-relay'], user: ['base-sv-vless'], outboundTag: 'base-sv-vless' });
  assert.equal(dialer('via-chain-base-managed', 'base-chain-c1'), 'chain-relay~base-chain-c1-h0');
  assert.equal(dialer('via-chain-base-managed', 'out-sv-trojan@chain-c1'), 'chain-relay~base-chain-c1');
  assert.equal(dialer('via-explicit-and-none-managed', 'out-sv-trojan@chain-c1'), 'chain-relay~base-chain-c1');
  assert.equal(dialer('via-explicit-and-none-managed', 'out-sv-trojan'), null);
  assert.equal(dialer('via-wg-through-base-tun', 'out-sv-wgcorp@sv-vless'), 'base-sv-vless');
  assert.equal(dialer('via-json-through-base-managed', 'out-jf@sv-vless'), 'chain-relay~base-sv-vless');
  assert.equal(outs('via-json-through-base-managed').some((o) => o.tag.includes('~') && !o.tag.startsWith('chain-relay~')), false, 'a JSON server behind a base brings no helper');
  assert.equal(dialer('via-json-as-base-managed', 'base-jf'), 'base-jf~fragment');
  // under TUN: only what dials by itself is bound and pinned; mux only on the direct server target
  const tun = outs('via-server-base-tun');
  assert.equal(tun.find((o) => o.tag === 'base-sv-vless').streamSettings.sockopt.interface, 'Wi-Fi');
  assert.equal(tun.find((o) => o.tag === 'out-sv-trojan@sv-vless').streamSettings.sockopt.interface, undefined);
  assert.deepEqual(tun.filter((o) => o.mux).map((o) => o.tag), ['out-sv-vless']);
  assert.deepEqual(Object.keys(run.read('via-server-base-tun').dns.hosts).sort(), ['a.example.com']);
  // the app's mux never on a base or a target behind one (a JSON server's own, as written, is its own)
  const { MUX } = require('../src/main/mux');
  for (const n of names) for (const v of ['managed', 'tun', 'strict']) {
    for (const o of outs(`via-${n}-${v}`)) if (o.tag.includes('@') || o.tag.startsWith('base-')) assert.notDeepEqual(o.mux, MUX, `${n}-${v}: ${o.tag}`);
  }
  assert.deepEqual(outs('via-json-through-base-tun').find((o) => o.tag === 'out-jc@sv-vless').mux, { enabled: true, concurrency: 8 });
});

test('the core gate hands the cores every multi-internet shape (v1.32.0): balance with a backup link, failover, split over XHTTP TLS and REALITY, a group, the pool, advanced, the dialer per interface — plain and under TUN', { timeout: 60000 }, (t) => {
  const run = dryRun(t);
  assert.equal(run.status, 0, run.out);
  const names = ['balance', 'balance-fragment', 'failover', 'split-xhttp-tls', 'split-xhttp-reality', 'split-not-xhttp', 'group-balance', 'pool-balance', 'advanced-balance'];
  for (const n of names) for (const v of ['plain', 'tun']) assert.ok(run.built.includes(`multiwan-${n}-${v}.json`), `multiwan-${n}-${v}`);
  const outs = (name) => run.read(name).outbounds;
  const iface = (o) => ((o && o.streamSettings && o.streamSettings.sockopt) || {}).interface;
  const at = (name, tag) => outs(name).find((o) => o.tag === tag);
  // balance: a copy per link at its weight, the backup the fallback
  assert.deepEqual(outs('multiwan-balance-plain').filter((o) => /^proxy~(gm\d+|fb)$/.test(o.tag)).map((o) => [o.tag, iface(o)]),
    [['proxy~gm0', 'eth0'], ['proxy~gm1', 'eth1'], ['proxy~gm2', 'eth0'], ['proxy~fb', 'eth2']]);
  assert.equal(run.read('multiwan-balance-plain').routing.balancers[0].fallbackTag, 'proxy~fb');
  assert.deepEqual(outs('multiwan-failover-tun').filter((o) => /^proxy~/.test(o.tag)).map(iface), ['eth0', 'eth1']);
  // under TUN: the rest bound to the NIC, the links their own
  assert.equal(iface(at('multiwan-balance-tun', 'direct')), 'eth0');
  assert.equal(iface(at('multiwan-balance-tun', 'proxy~gm1')), 'eth1');
  // the dialer per interface
  assert.deepEqual(outs('multiwan-balance-fragment-tun').filter((o) => /^dpi-/.test(o.tag)).map(iface), ['eth0', 'eth1', 'eth2']);
  // split: one outbound, its two legs bound; the download leg answered from the config like the upload
  for (const [name, sec] of [['split-xhttp-tls', 'tls'], ['split-xhttp-reality', 'reality']]) {
    const p = run.proxy(`multiwan-${name}-tun`);
    const ds = p.streamSettings.xhttpSettings.extra.downloadSettings;
    assert.deepEqual([iface(p), ds.security, ds.sockopt.interface, ds.sockopt.domainStrategy], ['eth0', sec, 'eth1', 'UseIPv4'], name);
  }
  assert.equal(run.proxy('multiwan-split-not-xhttp-plain').protocol, 'loopback', 'not XHTTP: balanced over up and down');
  assert.equal(at('multiwan-pool-balance-plain', 'out-sv-trojan').protocol, 'loopback');
  assert.equal(at('multiwan-advanced-balance-plain', 'out-chain-c1-h0').protocol, 'vless', 'a chain hop stays');
  for (const n of names) for (const v of ['plain', 'tun']) assert.equal(JSON.stringify(run.read(`multiwan-${n}-${v}`)).includes('_mwSplit'), false);
});

test('the core gate hands sing-box every TUIC / AnyTLS config — links, the editor, the sing-box JSON fixture; the connect’s, a LAN’s and a latency test’s — and Xray none of them', { timeout: 60000 }, (t) => {
  const run = dryRun(t);
  const names = ['json-singbox-9', 'editor-tuic', 'editor-anytls', 'link-tuic-all', 'link-tuic-v6', 'link-tuic-ech-dns', 'link-anytls-all', 'link-anytls-ech-b64', 'link-anytls-fragment'];
  for (const n of names) for (const v of ['connect', 'lan', 'test']) assert.ok(run.built.includes(`singbox-${n}-${v}.json`), `singbox-${n}-${v}`);
  const out = (name) => run.read(name).outbounds.find((o) => o.tag === 'proxy');
  assert.deepEqual(out('singbox-editor-tuic-connect'), {
    type: 'tuic', tag: 'proxy', server: 'ed.example.com', server_port: 443, uuid: '2c0f0d9a-6b3a-4f0e-9a1f-8c2b4d6e7a10', password: 'irnf-ci-secret',
    congestion_control: 'bbr', udp_relay_mode: 'quic', zero_rtt_handshake: true, heartbeat: '10s',
    tls: { enabled: true, server_name: 'ed.example.com', insecure: true, alpn: ['h3'], disable_sni: true }
  });
  assert.equal(out('singbox-link-tuic-v6-connect').tls.alpn[0], 'h3', 'no ALPN in the link: h3');
  assert.equal(out('singbox-link-tuic-v6-connect').tls.utls, undefined, 'QUIC: no uTLS');
  assert.deepEqual(out('singbox-link-anytls-fragment-test').tls.utls, { enabled: true, fingerprint: 'firefox' });
  assert.equal(out('singbox-link-anytls-fragment-test').tls.fragment, true);
  assert.deepEqual(run.read('singbox-link-anytls-all-test').inbounds.map((i) => i.type), ['socks'], 'a test: SOCKS alone');
  // none of them ever reached an Xray config
  assert.equal(run.built.some((n) => /^(json-singbox-9|editor-(tuic|anytls)|link-(tuic|anytls))/.test(n)), false);
});

test('CI’s `cores` job hands the suggested Xray, Xray-PattN and sing-box every config — the versions read from coreVersions.js, the gate never dry', () => {
  const yml = fs.readFileSync(path.join(__dirname, '..', '.github', 'workflows', 'test.yml'), 'utf8').replace(/\r\n/g, '\n');
  const at = yml.indexOf('\n  cores:\n');
  assert.ok(at >= 0, 'test.yml has a cores job');
  const rest = yml.slice(at + 1);
  const end = rest.slice(1).search(/\n {2}[a-z][\w-]*:\n/);
  const job = end === -1 ? rest : rest.slice(0, end + 1);
  assert.match(job, /runs-on: ubuntu-latest/);
  for (const read of ['SUGGESTED.xray', "SUGGESTED['xray-pattn']", "SUGGESTED['sing-box']"]) {
    assert.ok(job.includes(`require('./src/main/coreVersions').${read}`), `the version is read from the table: ${read}`);
  }
  assert.match(job, /https:\/\/github\.com\/XTLS\/Xray-core\/releases\/download\/v\$XV\/Xray-linux-64\.zip/);
  assert.match(job, /https:\/\/github\.com\/patterniha\/Xray-core\/releases\/download\/v\$PV\/Xray-linux-64\.zip/);
  assert.match(job, /https:\/\/github\.com\/SagerNet\/sing-box\/releases\/download\/v\$SV\/sing-box-\$SV-linux-amd64\.tar\.gz/);
  assert.match(job, /IRNF_XRAY_EXE="\$RUNNER_TEMP\/x\/xray" IRNF_SINGBOX_EXE="\$RUNNER_TEMP\/s\/sing-box" node scripts\/validate-configs\.js/);
  assert.match(job, /IRNF_XRAY_EXE="\$RUNNER_TEMP\/p\/xray" node scripts\/validate-configs\.js/);
  assert.doesNotMatch(job, /IRNF_VALIDATE_DRY/, 'a dry run checks nothing');
});

test('the core gate carries the users’ configs (module lanUsers): their inbounds, accounts and per-user rules, on a router’s LAN address too', { timeout: 60000 }, (t) => {
  const run = dryRun(t);
  for (const name of ['single-desktop', 'single-router', 'single-socks-only', 'transparent-only', 'chain', 'advanced', 'pool']) {
    for (const v of ['plain', 'tun']) assert.ok(run.built.includes(`lanusers-${name}-${v}.json`), `lanusers-${name}-${v}`);
  }
  const router = run.read('lanusers-single-router-tun');
  const socks = router.inbounds.find((i) => i.tag === 'lu-socks');
  assert.deepEqual([socks.listen, socks.settings.auth, socks.settings.accounts.length], ['192.168.1.1', 'password', 6]);
  assert.ok(router.inbounds.some((i) => i.tag === 'lu-tp-0' && i.listen === '127.0.0.1'));
  assert.ok(router.routing.rules.some((r) => Array.isArray(r.user) && r.user[0] === 'mina' && r.outboundTag === 'lu-out-grp-lu'));
  assert.equal(router.outbounds.find((o) => o.tag === 'lu-out-sv-trojan').streamSettings.sockopt.interface, 'eth0', 'bound to the NIC under TUN');
});
