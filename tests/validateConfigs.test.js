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
  assert.match(run.out, new RegExp(`^${run.built.length} configs built for xray ${SUGGESTED.xray.replace(/\./g, '\\.')} \\(13 of them sing-box TUN configs\\)`, 'm'));
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
  for (const name of run.built.filter((n) => !/mux/.test(n) && !/^json-/.test(n))) assert.equal(JSON.stringify(run.read(name.replace(/\.json$/, ''))).includes('"mux"'), false, name);
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
  const fixtures = ['xray-subscription', 'xray-fragment', 'xray-chain', 'xray-balancer', 'xray-wireguard', 'singbox'];
  let xrayServers = 0;
  for (const f of fixtures) {
    const servers = importJson(fs.readFileSync(path.join(__dirname, 'fixtures', 'json', `${f}.json`), 'utf8')).servers;
    assert.ok(servers.length > 0, f);
    servers.forEach((s, i) => {
      for (const v of ['plain', 'tun']) assert.ok(run.built.includes(`json-${f}-${i}-full-${v}.json`), `json-${f}-${i}-full-${v}`);
      for (const v of ['plain', 'tun']) {
        assert.equal(run.built.includes(`json-${f}-${i}-raw-${v}.json`), s.source === 'json', `json-${f}-${i}-raw-${v}: raw is for Xray JSON only`);
      }
      if (s.source === 'json') xrayServers++;
    });
  }
  assert.equal(xrayServers, 5 + 1 + 1 + 2 + 1);
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
