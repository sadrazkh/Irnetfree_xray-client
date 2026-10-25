'use strict';
/**
 * Generate every plan shape × DNS mode × geo state and run `xray run -test` on
 * each. This is the only check that proves the CORE accepts what configBuilder
 * emits (dns.tag, the dns outbound, expectedIPs, DoH strings, inboundTag
 * rules) — the unit tests only pin our own output. Needs bin/xray(.exe)
 * (`npm run get-xray`), or IRNF_XRAY_EXE.
 *
 * Every config is first written for the core that runs it, as the app does
 * before it starts one (xrayManager.forCore): coreCompat.adaptForCore with the
 * core's own version (`<core> version`) — mKCP's header and seed and
 * Hysteria's port hopping moved between the 2026 releases. The v1.18 link
 * forms (ECH, pcs / vcn, pqv, gRPC's authority, mKCP, Hysteria2, Shadowsocks
 * plugins) are parsed from share links, as an import parses them, and built
 * plain, under TUN and under TUN with the strict leak guard.
 *
 * With IRNF_SINGBOX_EXE set, every TUN config tunSingbox.buildTunConfig can
 * emit is run through `sing-box check` as well (parse + build only — `check`
 * never creates an adapter) and counted into the same total.
 *
 * IRNF_VALIDATE_DRY=1 runs no core at all: every config is built, adapted (for
 * IRNF_CORE_VERSION, else the suggested Xray) and written — into
 * IRNF_VALIDATE_OUT when that is set — so the generation runs anywhere
 * (tests/validateConfigs.test.js). The suggested cores are handed them in CI:
 * the `cores` job of .github/workflows/test.yml.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { buildConfig, buildTestConfig, buildMultiTestConfig, buildRawConfig } = require('../src/main/configBuilder');
const { MUX } = require('../src/main/mux');
const { adaptForCore } = require('../src/main/coreCompat');
const { parseLink } = require('../src/main/parser');
const { SUGGESTED } = require('../src/main/coreVersions');
const F = require('../tests/fixtures');

const DRY = process.env.IRNF_VALIDATE_DRY === '1';
// IRNF_XRAY_EXE points the run at another core (e.g. the PattN fork in the
// app's userData bin) so both cores can be checked against the same shapes.
const exe = process.env.IRNF_XRAY_EXE || path.join(__dirname, '..', 'bin', process.platform === 'win32' ? 'xray.exe' : 'xray');
if (!DRY && !fs.existsSync(exe)) { console.error('no core at ' + exe + ' — run: npm run get-xray'); process.exit(2); }

/** The core's own version — the first x.y.z `<core> version` prints — which every config is written for. */
function coreVersion() {
  if (DRY) return process.env.IRNF_CORE_VERSION || SUGGESTED.xray;
  const r = spawnSync(exe, ['version'], { encoding: 'utf8', timeout: 15000, windowsHide: true });
  const said = `${r.stdout || ''}${r.stderr || ''}`;
  const m = /(\d+\.\d+\.\d+)/.exec(said);
  if (!m) {
    console.error(`${exe} did not say its version: ${JSON.stringify(said.trim().split(/\r?\n/)[0] || (r.error && r.error.message) || '')}`);
    process.exit(2);
  }
  return m[1];
}
const version = coreVersion();
console.log(`${path.basename(exe)} ${version}${DRY ? ' — dry run: every config is built and written, no core is run' : ''}`);

const single = { mode: 'single', server: F.VLESS_WS_TLS };
const chain = { mode: 'chain', chain: [F.VLESS_WS_TLS, F.TROJAN_TCP_TLS] };
const advanced = {
  mode: 'advanced', serversById: { 'sv-vless': F.VLESS_WS_TLS, 'sv-trojan': F.TROJAN_TCP_TLS },
  chainsById: { c1: [F.VLESS_WS_TLS, F.TROJAN_TCP_TLS] }, chain: [],
  rules: [{ type: 'domain', value: 'geosite:category-ir', target: 'direct' }, { type: 'ip', value: '10.20.0.0/16', target: 'chain:c1' }],
  def: 'sv-vless'
};
const pool = {
  mode: 'pool', entries: [{ id: 'e1', target: 'sv-trojan', socksPort: 60001, httpPort: 60002 }], primary: 'sv-vless',
  serversById: { 'sv-vless': F.VLESS_WS_TLS, 'sv-trojan': F.TROJAN_TCP_TLS }, chainsById: {}, chain: []
};

const plans = { single, chain, advanced, pool };
const dnsModes = {
  managed: { dnsManaged: true, dnsRemote: ['https://1.1.1.1/dns-query', 'https://8.8.8.8/dns-query'], dnsDirect: ['178.22.122.100', '185.51.200.2'] },
  managedDohDirect: { dnsManaged: true, dnsRemote: ['https://1.1.1.1/dns-query'], dnsDirect: ['https://178.22.122.100/dns-query'] },
  unmanaged: { dnsManaged: false, dnsRemote: ['1.1.1.1', '8.8.8.8'] }
};
const routing = ['global', 'bypass-ir', 'bypass-cn', 'direct'];

const work = process.env.IRNF_VALIDATE_OUT || fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-validate-'));
fs.mkdirSync(work, { recursive: true });
const assetDir = path.dirname(exe);
let failed = 0, total = 0;

/** One config: written for this core's version, then `run -test` — dry, only written. */
function check(name, cfg) {
  total++;
  const file = path.join(work, `${name}.json`);
  fs.writeFileSync(file, JSON.stringify(adaptForCore(cfg, version), null, 2));
  if (DRY) { console.log('built ' + path.basename(file)); return; }
  const r = spawnSync(exe, ['run', '-test', '-c', file], {
    env: Object.assign({}, process.env, { XRAY_LOCATION_ASSET: assetDir, V2RAY_LOCATION_ASSET: assetDir }),
    encoding: 'utf8', timeout: 15000, windowsHide: true
  });
  if (r.status === 0) { console.log('ok   ' + path.basename(file)); return; }
  failed++;
  console.log('FAIL ' + path.basename(file));
  console.log('     ' + ((r.stdout || '') + (r.stderr || '')).trim().split(/\r?\n/).slice(-3).join('\n     '));
}

for (const [pn, plan] of Object.entries(plans)) {
  for (const [dn, dns] of Object.entries(dnsModes)) {
    for (const geoAssets of [true, false]) {
      // The advanced plan gets every routing mode too now that it can apply one
      // under its own rules (`advancedUseMode`) — those geo rules have to be
      // accepted by the core like any other.
      for (const routingMode of (pn === 'pool' ? ['global'] : routing)) {
        const useMode = pn === 'advanced' && routingMode !== 'global';
        for (const ipv6 of [false, true]) {
          check(`${pn}-${dn}-${routingMode}${useMode ? '-usemode' : ''}-geo${geoAssets}-v6${ipv6}`,
            buildConfig(plan, F.settings(Object.assign({ routingMode, geoAssets, ipv6, advancedUseMode: useMode }, dns))));
        }
      }
    }
  }
}

// One-off shapes the matrix does not reach: entry forms the free-text inputs
// accept, every advanced default, the anti-DPI dialer next to dns-out, a
// WireGuard outbound, LAN listening with custom rules, a corporate WireGuard's
// resolver (a server object with plain-CIDR expectedIPs and `domain:` entries,
// routed through the chain / the exit by an inboundTag+ip rule).
const managed = dnsModes.managed;
const PINS = { 'a.example.com': ['203.0.113.10', '203.0.113.11'], 'b.example.com': ['203.0.113.20'] };
const advancedWgChain = {
  mode: 'advanced', serversById: { 'sv-vless': F.VLESS_WS_TLS, 'sv-wgcorp': F.WG_CORP },
  chainsById: { c1: [F.VLESS_WS_TLS, F.WG_CORP] }, chain: [],
  rules: [{ type: 'ip', value: '192.168.0.0/16', target: 'chain:c1' }],
  def: 'sv-vless'
};
const shapes = {
  'single-managed-udpRemote-bypass-ir': [single, { routingMode: 'bypass-ir', dnsManaged: true, dnsRemote: ['1.1.1.1', '8.8.8.8'] }],
  'single-managed-hostPort-bypass-ir': [single, { routingMode: 'bypass-ir', dnsManaged: true, dnsRemote: ['1.1.1.1:5353'], dnsDirect: ['178.22.122.100:5353'] }],
  'single-managed-hostnameDoh-bypass-ir': [single, { routingMode: 'bypass-ir', dnsManaged: true, dnsRemote: ['https://dns.google/dns-query'], dnsDirect: ['https://free.shecan.ir/dns-query'] }],
  'single-managed-lanRemote': [single, { dnsManaged: true, dnsRemote: ['192.168.1.1', 'https://1.1.1.1/dns-query'] }],
  'single-managed-v6-bypass-ir': [single, { routingMode: 'bypass-ir', ipv6: true, dnsManaged: true, dnsRemote: ['[2001:4860:4860::8888]:53', 'https://1.1.1.1/dns-query'], dnsDirect: ['2a00:1450::1'] }],
  'single-unmanaged-hostPort': [single, { dnsManaged: false, dnsRemote: ['1.1.1.1:5353'] }],
  'single-fragment-bypass-ir': [{ mode: 'single', server: F.vlessWithMarkers('sv-frag', { _fragment: 'tlshello,100-200,10-20' }) }, Object.assign({ routingMode: 'bypass-ir' }, managed)],
  'single-wireguard-bypass-ir': [{ mode: 'single', server: F.WG_BAD_MASK }, Object.assign({ routingMode: 'bypass-ir' }, managed)],
  'single-allowLan-customRules': [single, Object.assign({ allowLan: true, customRules: [{ domain: 'geosite:google', outboundTag: 'proxy' }, { ip: '1.2.3.0/24', outboundTag: 'direct' }] }, managed)],
  'chain-fragment': [{ mode: 'chain', chain: [F.vlessWithMarkers('sv-frag', { _fragment: 'tlshello' }), F.TROJAN_TCP_TLS] }, managed],
  'advanced-defDirect': [Object.assign({}, advanced, { def: 'direct' }), managed],
  'advanced-defBlock': [Object.assign({}, advanced, { def: 'block' }), managed],
  'advanced-defChain': [Object.assign({}, advanced, { def: 'chain:c1' }), managed],
  'advanced-cnDirect': [Object.assign({}, advanced, { rules: [{ type: 'domain', value: 'geosite:cn', target: 'direct' }] }), managed],
  'advanced-wgChainDns': [advancedWgChain, managed],
  'single-wgDns-domains': [{ mode: 'single', server: F.WG_CORP }, managed],
  'advanced-wgDefault': [Object.assign({}, advancedWgChain, { def: 'chain:c1' }), managed],
  'advanced-wgBlockDefault': [Object.assign({}, advancedWgChain, { def: 'block' }), managed],
  'pool-bypass-ir': [pool, Object.assign({ routingMode: 'bypass-ir' }, managed)],
  // a certificate pinned on first use (certPin.js) → tlsSettings.pinnedPeerCertSha256
  'single-certPin': [{ mode: 'single', server: Object.assign({}, F.VLESS_WS_TLS, { certPin: 'ab11bf7ac877baa539294f5a3c864b8ed43e6fe3a9a8230fc2db7fff85c27fde' }) }, managed],
  'chain-certPin-firstHop': [{ mode: 'chain', chain: [Object.assign({}, F.VLESS_WS_TLS, { certPin: 'AB:11:BF:7A:C8:77:BA:A5:39:29:4F:5A:3C:86:4B:8E:D4:3E:6F:E3:A9:A8:23:0F:C2:DB:7F:FF:85:C2:7F:DE' }), F.TROJAN_TCP_TLS] }, managed],
  // Under TUN every outbound that dials itself is bound to the physical NIC
  // (sockopt.interface — the core checks the field is well-formed, the NIC is
  // looked up at dial time; see configBuilder.bindDirectDials). One per plan
  // kind; the single carries the anti-DPI dialer so a bound dpi-* is covered.
  'single-bound-fragment': [{ mode: 'single', server: F.vlessWithMarkers('sv-frag', { _fragment: 'tlshello,100-200,10-20' }) }, Object.assign({ routingMode: 'bypass-ir', directInterface: 'Wi-Fi' }, managed)],
  'single-bound-wireguard': [{ mode: 'single', server: F.WG_BAD_MASK }, Object.assign({ directInterface: 'Wi-Fi' }, managed)],
  'chain-bound-wgExit': [{ mode: 'chain', chain: [F.VLESS_WS_TLS, F.WG_BAD_MASK] }, Object.assign({ directInterface: 'Wi-Fi' }, managed)],
  'advanced-bound-wgChain': [advancedWgChain, Object.assign({ directInterface: 'Wi-Fi' }, managed)],
  'pool-bound': [pool, Object.assign({ directInterface: 'Wi-Fi' }, managed)],
  // Entry servers answered from the config (configBuilder.pinEntryHosts):
  // dns.hosts + sockopt.domainStrategy beside the interface, the anti-DPI
  // dialer and chains, under both DNS modes and with IPv6 (UseIP, a v6 answer).
  'single-pinned-managed': [single, Object.assign({ entryHostIps: PINS }, managed)],
  'single-pinned-unmanaged': [single, Object.assign({ entryHostIps: PINS }, dnsModes.unmanaged)],
  'single-pinned-v6only': [single, Object.assign({ ipv6: true, entryHostIps: { 'a.example.com': ['2001:db8::10'] } }, managed)],
  'single-pinned-fragment-bound': [{ mode: 'single', server: F.vlessWithMarkers('sv-frag', { _fragment: 'tlshello,100-200,10-20' }) }, Object.assign({ routingMode: 'bypass-ir', directInterface: 'Wi-Fi', entryHostIps: PINS }, managed)],
  // the dpi dialer of a pinned outbound carries its strategy (UseIP with IPv6),
  // and one beside an unpinned outbound with the same settings is a dialer of its own
  'single-pinned-fragment-v6': [{ mode: 'single', server: F.vlessWithMarkers('sv-frag', { _fragment: 'tlshello,100-200,10-20', _noise: 'faketls' }) }, Object.assign({ ipv6: true, directInterface: 'Wi-Fi', entryHostIps: PINS }, managed)],
  'advanced-pinned-fragment-shared': [{
    mode: 'advanced', chain: [], chainsById: {},
    serversById: { 'sv-frag': F.vlessWithMarkers('sv-frag', { _fragment: 'tlshello,100-200,10-20' }), 'sv-trojan': Object.assign({}, F.TROJAN_TCP_TLS, { outbound: Object.assign({}, F.TROJAN_TCP_TLS.outbound, { _fragment: 'tlshello,100-200,10-20' }) }) },
    rules: [{ type: 'domain', value: 'a.com', target: 'sv-trojan' }], def: 'sv-frag'
  }, Object.assign({ routingMode: 'bypass-ir', directInterface: 'Wi-Fi', entryHostIps: { 'a.example.com': ['203.0.113.10'] } }, managed)],
  'chain-pinned-bound': [chain, Object.assign({ directInterface: 'Wi-Fi', entryHostIps: PINS }, managed)],
  'advanced-pinned-wgChain-unmanaged': [advancedWgChain, Object.assign({ directInterface: 'Wi-Fi', entryHostIps: PINS, wgEndpointIps: { 'cobra.example': '198.51.100.21' } }, dnsModes.unmanaged)],
  'advanced-pinned-wgChain-managed': [advancedWgChain, Object.assign({ routingMode: 'bypass-ir', directInterface: 'Wi-Fi', entryHostIps: PINS, wgEndpointIps: { 'cobra.example': '198.51.100.21' } }, managed)],
  'pool-pinned': [pool, Object.assign({ directInterface: 'Wi-Fi', entryHostIps: PINS }, managed)],
  // Mux on a server's own outbound (v1.18, spec §4 — src/main/mux.js): the
  // object the app writes, beside the anti-DPI dialer, the pin and the NIC
  // binding; an advanced default and a pool exit (a chain's hops never carry it).
  'single-mux': [single, Object.assign({ muxServerIds: ['sv-vless'] }, managed)],
  'single-mux-pinned-fragment-bound': [{ mode: 'single', server: F.vlessWithMarkers('sv-frag', { _fragment: 'tlshello,100-200,10-20' }) }, Object.assign({ routingMode: 'bypass-ir', directInterface: 'Wi-Fi', entryHostIps: PINS, muxServerIds: ['sv-frag'] }, managed)],
  'advanced-mux': [advanced, Object.assign({ muxServerIds: ['sv-vless', 'sv-trojan'] }, managed)],
  'pool-mux': [pool, Object.assign({ muxServerIds: ['sv-vless', 'sv-trojan'] }, managed)]
};
for (const [name, [plan, over]] of Object.entries(shapes)) check(`shape-${name}`, buildConfig(plan, F.settings(over)));

// The multi-target latency test (phase B): one core, an inbound per target
// routed by inboundTag — a server, a chain and an anti-DPI dialer together.
check('multi-test', buildMultiTestConfig(
  [F.VLESS_WS_TLS, [F.TROJAN_TCP_TLS, F.SS_TCP], F.vlessWithMarkers('sv-frag', { _fragment: 'tlshello,100-200,10-20' })],
  [41001, 41002, 41003]));

/**
 * An ECHConfigList (version 0xfe0d) naming `publicName`, base64 — the form a
 * link may carry instead of where to ask DNS for one: a config id, X25519
 * (HKDF-SHA256) with a public key, one suite (HKDF-SHA256 / AES-128-GCM), no
 * extensions.
 */
function echConfigListB64(publicName) {
  const u16 = (n) => Buffer.from([n >> 8, n & 0xff]);
  const name = Buffer.from(publicName);
  const contents = Buffer.concat([
    Buffer.from([7]), u16(0x0020), u16(32), Buffer.alloc(32, 5),
    u16(4), u16(0x0001), u16(0x0001),
    Buffer.from([0, name.length]), name, u16(0)
  ]);
  const config = Buffer.concat([u16(0xfe0d), u16(contents.length), contents]);
  return Buffer.concat([u16(config.length), config]).toString('base64');
}

// The link forms of v1.18, parsed from share links as an import parses them:
// ECH asked of DNS over UDP and over DoH (and given as the list itself),
// certificate pins with the name to verify, gRPC's :authority, mKCP's header
// and seed, Hysteria2 with salamander, port hopping and its bandwidth,
// Shadowsocks' obfs and v2ray plugins, REALITY with ML-DSA-65 (pqv). Each one
// plain, under TUN (every dial bound to the NIC — the ECH query too:
// echSockopt) and under TUN with the strict leak guard (an ECH query over UDP
// asked over DoH instead). And v1.31's ECH outbound (PattN's echOutbound, the
// editor's Example): the query over h2c through an outbound of its own.
const NEW_FORMS = [
  'vless://11111111-2222-3333-4444-555555555555@104.21.44.18:2087?encryption=none&type=ws&host=h.example&path=/&security=tls&fp=firefox&sni=h.example&ech=cloudflare-ech.com+udp://1.1.1.1#ech-udp',
  'vless://11111111-2222-3333-4444-555555555555@a.example:443?security=tls&sni=a.example&ech=cloudflare-ech.com%2Bhttps%3A%2F%2F1.1.1.1%2Fdns-query#ech-doh',
  'trojan://pw@a.example:443?security=tls&sni=a.example&pcs=' + 'ab'.repeat(32) + '&vcn=real.example#pins',
  'vless://11111111-2222-3333-4444-555555555555@g.example:443?type=grpc&serviceName=svc&authority=auth.example&security=tls&sni=g.example#grpc-authority',
  'vless://11111111-2222-3333-4444-555555555555@k.example:443?type=kcp&headerType=wechat-video&seed=S&mtu=1350#kcp',
  'hysteria2://pw@h.example:443/?sni=s.example&obfs=salamander&obfs-password=OB&mport=20000-30000&up=50&down=100&pinSHA256=' + 'cd'.repeat(32) + '#hy2',
  'ss://' + Buffer.from('chacha20-ietf-poly1305:pw').toString('base64') + '@s.example:8388?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dbing.com#ss-obfs',
  'ss://' + Buffer.from('chacha20-ietf-poly1305:pw').toString('base64') + '@s.example:443?plugin=v2ray-plugin%3Bmode%3Dwebsocket%3Btls%3Bhost%3Dws.example%3Bpath%3D%2Fws#ss-v2ray',
  'vless://11111111-2222-3333-4444-555555555555@r.example:443?encryption=none&flow=xtls-rprx-vision&type=tcp&security=reality&sni=www.example.com&fp=chrome' +
    '&pbk=' + Buffer.alloc(32, 9).toString('base64url') + '&sid=ab12&pqv=' + Buffer.alloc(1952, 7).toString('base64url') + '#reality-pqv',
  'vless://11111111-2222-3333-4444-555555555555@a.example:443?security=tls&sni=a.example&ech=' + encodeURIComponent(echConfigListB64('cloudflare-ech.com')) + '#ech-b64',
  'vless://11111111-2222-3333-4444-555555555555@104.21.44.18:2087?encryption=none&type=ws&host=h.example&path=/&security=tls&fp=chrome&sni=h.example' +
    '&ech=' + encodeURIComponent('cloudflare-ech.com+h2c://1.1.1.1/dns-query') +
    '&echOutbound=' + encodeURIComponent(JSON.stringify(require('../src/renderer/serverFields').ECH_OUTBOUND_EXAMPLE)) + '#ech-outbound'
];
const LINK_SETTINGS = {
  plain: {},
  tun: { tunMode: true, leakGuard: 'standard', directInterface: 'eth0' },
  strict: { tunMode: true, leakGuard: 'strict', directInterface: 'eth0' }
};
for (const link of NEW_FORMS) {
  const server = parseLink(link);
  for (const [variant, over] of Object.entries(LINK_SETTINGS)) check(`link-${server.name}-${variant}`, buildConfig({ mode: 'single', server }, F.settings(over)));
}

// The router's field report (spec §4): ECH over WebSocket, with mux on — plain,
// under TUN and under the strict guard. And the mux probe's own throwaway core:
// the test config with MUX on its proxy outbound and the connect's names
// answered from dns.hosts (what mux.probeMux starts).
const echWs = parseLink(NEW_FORMS[0]);
for (const [variant, over] of Object.entries(LINK_SETTINGS)) {
  check(`link-${echWs.name}-mux-${variant}`, buildConfig({ mode: 'single', server: echWs }, F.settings(Object.assign({ muxServerIds: [echWs.id] }, over))));
}
const probe = buildTestConfig(F.VLESS_WS_TLS, 41010, { entryHostIps: PINS, ipv6: false });
probe.outbounds.find((o) => o.tag === 'proxy').mux = Object.assign({}, MUX);
check('mux-probe', probe);

// JSON configs (docs/superpowers/specs/2026-10-08-json-configs-design.md), as
// an import reads the fixtures: every server in full mode — its helpers beside
// it, renamed — plain and under TUN; every Xray-JSON server raw too (its own
// config with the app's inbounds); a JSON server as either hop of a chain, two
// of them under advanced routing, and a latency test of one with helpers.
// (xray-masque: a WARP and an HTTP/2 MASQUE server read as ordinary ones, a
// panel's full config with a MASQUE outbound as a JSON server.)
const { importJson } = require('../src/main/jsonImport');
const JSON_FIXTURES = ['xray-subscription', 'xray-fragment', 'xray-chain', 'xray-balancer', 'xray-wireguard', 'xray-masque', 'singbox'];
const JSON_SETTINGS = { plain: managed, tun: Object.assign({}, managed, LINK_SETTINGS.tun) };
const jsonServers = {};
for (const f of JSON_FIXTURES) {
  jsonServers[f] = importJson(fs.readFileSync(path.join(__dirname, '..', 'tests', 'fixtures', 'json', `${f}.json`), 'utf8')).servers;
  jsonServers[f].forEach((server, i) => {
    for (const [variant, over] of Object.entries(JSON_SETTINGS)) {
      check(`json-${f}-${i}-full-${variant}`, buildConfig({ mode: 'single', server }, F.settings(over)));
      if (server.source === 'json') check(`json-${f}-${i}-raw-${variant}`, buildRawConfig(server, F.settings(over)));
    }
  });
}
const jf = Object.assign({}, jsonServers['xray-fragment'][0], { id: 'jf' });
const jc = Object.assign({}, jsonServers['xray-chain'][0], { id: 'jc' });
check('json-chain-later', buildConfig({ mode: 'chain', chain: [F.VLESS_WS_TLS, jc] }, F.settings(managed)));
check('json-chain-first', buildConfig({ mode: 'chain', chain: [jf, F.TROJAN_TCP_TLS] }, F.settings(JSON_SETTINGS.tun)));
check('json-advanced', buildConfig({
  mode: 'advanced', serversById: { jf, jc, 'sv-vless': F.VLESS_WS_TLS }, chainsById: {}, chain: [],
  rules: [{ type: 'domain', value: 'geosite:category-ir', target: 'direct' }, { type: 'ip', value: '10.20.0.0/16', target: 'jc' }], def: 'jf'
}, F.settings(Object.assign({ routingMode: 'bypass-ir' }, JSON_SETTINGS.tun))));
check('json-test-chain', buildTestConfig(jc, 41020));
// entered where it really dials (configBuilder.entryOutbounds): the chain
// fixture's hop answered from dns.hosts, its fragment dialer carrying the strategy
check('json-chain-pinned', buildConfig({ mode: 'single', server: jc }, F.settings(Object.assign({ entryHostIps: { 'hop.example.com': ['203.0.113.30'] } }, JSON_SETTINGS.tun))));
// raw, as the cores take it: a server that asked for allowInsecure, with the
// pin learnt for it; a WireGuard whose endpoint name the connect resolved
const insecure = JSON.parse(JSON.stringify(jsonServers['xray-subscription'][0]));
for (const o of [insecure.json.outbounds.find((x) => x.tag === 'proxy'), insecure.outbound]) o.streamSettings.tlsSettings.allowInsecure = true;
insecure.certPin = 'ab11bf7ac877baa539294f5a3c864b8ed43e6fe3a9a8230fc2db7fff85c27fde';
check('json-raw-pinned', buildRawConfig(insecure, F.settings(managed)));
check('json-raw-wg-resolved', buildRawConfig(jsonServers['xray-wireguard'][0], F.settings(Object.assign({ wgEndpointIps: { 'wg.example.com': '198.51.100.7' } }, JSON_SETTINGS.tun))));

// Routing profiles: "via a base" (docs/superpowers/specs/2026-10-09-routing-profiles-design.md §2).
// A base is one outbound group (`base-<id>`, a chain's `base-chain-<cid>` with
// its hops) shared by every target through it; a target through it is its own
// outbound (`out-<id>@<base>`, a chain's hops `…-h<i>`) dialing the base's exit
// by dialerProxy — a server and a chain through a server base and through a
// chain base, the default through it, a corporate WireGuard through it with its
// resolver, a JSON server through it and as the base, and all of it under TUN
// with the names pinned and mux on the one direct server target.
const VIA_SERVERS = { 'sv-vless': F.VLESS_WS_TLS, 'sv-trojan': F.TROJAN_TCP_TLS, 'sv-ss': F.SS_TCP, 'sv-wgcorp': F.WG_CORP, jf, jc };
const viaPlan = (over) => Object.assign({
  mode: 'advanced', profileId: 'rp-ci', serversById: VIA_SERVERS, chain: [],
  chainsById: { c1: [F.VLESS_WS_TLS, F.TROJAN_TCP_TLS], c2: [F.SS_TCP, F.TROJAN_TCP_TLS] },
  rules: [], def: 'direct', defVia: 'inherit', base: null, useMode: false
}, over);
const VIA_SHAPES = {
  'server-base': viaPlan({ base: 'sv-vless', rules: [{ type: 'domain', value: 'a.com', target: 'sv-trojan' }, { type: 'domain', value: 'b.com', target: 'sv-ss' }, { type: 'ip', value: '10.20.0.0/16', target: 'chain:c2' }], def: 'sv-vless', defVia: 'none' }),
  'chain-base': viaPlan({ base: 'chain:c1', rules: [{ type: 'domain', value: 'a.com', target: 'sv-ss' }, { type: 'ip', value: '10.20.0.0/16', target: 'chain:c2' }, { type: 'domain', value: 'geosite:category-ir', target: 'direct' }], def: 'sv-trojan' }),
  'explicit-and-none': viaPlan({ rules: [{ type: 'domain', value: 'a.com', target: 'sv-trojan', via: 'chain:c1' }, { type: 'domain', value: 'b.com', target: 'sv-trojan', via: 'none' }, { type: 'port', value: '5060', target: 'chain:c2', via: 'sv-vless' }], def: 'sv-ss', defVia: 'sv-vless' }),
  'wg-through-base': viaPlan({ base: 'sv-vless', rules: [{ type: 'ip', value: '192.168.0.0/16', target: 'sv-wgcorp' }], def: 'sv-vless', defVia: 'none' }),
  'json-through-base': viaPlan({ base: 'sv-vless', rules: [{ type: 'domain', value: 'a.com', target: 'jf' }, { type: 'domain', value: 'b.com', target: 'jc' }], def: 'sv-trojan', defVia: 'none' }),
  'json-as-base': viaPlan({ base: 'jf', rules: [{ type: 'domain', value: 'a.com', target: 'sv-trojan' }, { type: 'ip', value: '10.20.0.0/16', target: 'chain:c2' }], def: 'sv-ss' }),
  // a WireGuard base (a server, a chain ending in one) that is also "exit at the
  // base": its exit is a freedom dialling through the base's own outbound
  'wg-base-exit-at-base': viaPlan({ base: 'sv-wgcorp', rules: [{ type: 'ip', value: '192.168.0.0/16', target: 'sv-wgcorp', via: 'none' }, { type: 'domain', value: 'a.com', target: 'sv-trojan' }], def: 'sv-vless', defVia: 'none' }),
  'wg-chain-base-exit-at-base': viaPlan({ chainsById: { c3: [F.VLESS_WS_TLS, F.WG_CORP] }, base: 'chain:c3', rules: [{ type: 'ip', value: '192.168.0.0/16', target: 'chain:c3', via: 'none' }, { type: 'domain', value: 'a.com', target: 'sv-ss' }], def: 'chain:c3', defVia: 'none' })
};
const VIA_SETTINGS = {
  managed,
  tun: Object.assign({ routingMode: 'bypass-ir', tunMode: true, directInterface: 'Wi-Fi', entryHostIps: Object.assign({ 'edge1.example.com': ['203.0.113.40'] }, PINS), wgEndpointIps: { 'cobra.example': '198.51.100.21' }, muxServerIds: ['sv-vless', 'sv-trojan', 'sv-ss'] }, managed),
  strict: Object.assign({ tunMode: true, leakGuard: 'strict', directInterface: 'eth0' }, managed)
};
for (const [name, plan] of Object.entries(VIA_SHAPES)) {
  for (const [variant, over] of Object.entries(VIA_SETTINGS)) {
    // under the strict guard the profile applies the routing mode under its rules (its own useMode)
    const p = variant === 'strict' ? Object.assign({}, plan, { useMode: true }) : plan;
    check(`via-${name}-${variant}`, buildConfig(p, F.settings(Object.assign({ routingMode: 'bypass-ir' }, over))));
  }
}

// The full server editor (docs/superpowers/specs/2026-10-12-server-editor-design.md):
// a server made from the editor's fields (parser.createServer) for every
// protocol and every transport × security it takes, with EVERY field of the
// table that applies set — the values the form would write — so a core that
// refuses one of them says so here, not at a user's connect.
{
  const SFT = require('../src/renderer/serverFields');
  const { createServer } = require('../src/main/parser');
  const ENC = 'mlkem768x25519plus.native.0rtt.p7sTtcQlhzr21By6QMbFOEFjtHJa8dquXhK7pboK9GE';
  const DOWNLOAD = '{"address":"dl.example.com","port":443,"network":"xhttp","security":"tls","tlsSettings":{"serverName":"dl.example.com"},"xhttpSettings":{"path":"/dl"}}';
  const VALUES = {
    encryption: ENC, flow: '', vmessSecurity: 'chacha20-poly1305', alterId: '0', method: 'aes-256-gcm', uot: true,
    wgKeepAlive: '25', wgDomainStrategy: 'ForceIPv4', httpHeaders: '{"User-Agent":"irnf-ci"}',
    wsHeartbeat: '30', grpcUserAgent: 'irnf-ci', grpcIdleTimeout: '60', grpcHealthTimeout: '20', grpcInitialWindow: '65535',
    grpcPermitWithoutStream: true, xPaddingBytes: '100-1000', noGRPCHeader: true, scMaxEachPostBytes: '1000000',
    scMinPostsIntervalMs: '30', xmuxMaxConcurrency: '16-32', xmuxMaxConnections: '0', xmuxCMaxReuseTimes: '0',
    xmuxHMaxRequestTimes: '600-900', xmuxHMaxReusableSecs: '1800-3000', xmuxHKeepAlivePeriod: '0', downloadSettings: DOWNLOAD,
    kcpMtu: '1350', kcpTti: '50', kcpUplink: '5', kcpDownlink: '20', kcpCongestion: true, kcpReadBuffer: '2', kcpWriteBuffer: '2',
    echForceQuery: 'none', minVersion: '1.2', maxVersion: '1.3', curvePreferences: 'X25519MLKEM768, X25519', useSystemCA: true,
    mux: 'on', muxConcurrency: '4', xudpConcurrency: '16',
    tcpFastOpen: true, tcpMptcp: true, tcpKeepAliveInterval: '15', tcpKeepAliveIdle: '300', tcpCongestion: 'bbr',
    // MASQUE's, bar the WARP account (all-or-none: its own cases below)
    masqueUser: 'irnf-ci', masquePass: 'irnf-ci-pass', masqueHost: 'ed.example.com', masquePath: '/.well-known/masque/ip/{target}/{ipproto}/',
    masqueHeaders: '{"User-Agent":"chrome"}', remoteDNS: '1.1.1.1, 2606:4700:4700::1111'
  };
  const base = (protocol) => {
    const f = { protocol, name: 'editor-' + protocol, address: 'ed.example.com', port: '443' };
    if (protocol === 'vless' || protocol === 'vmess') f.uuid = '2c0f0d9a-6b3a-4f0e-9a1f-8c2b4d6e7a10';
    if (['trojan', 'shadowsocks', 'hysteria2'].includes(protocol)) f.password = 'irnf-ci-secret';
    if (protocol === 'wireguard') Object.assign(f, { privateKey: '2K2GILDj0FUWeLh2MhyzOfVm3cpC7evzkWZGRNL7yUA=', publicKey: 'HtCo1A5bqv1JjSdv4ynUqF1ZVCXDpPtd4292Md+AIko=' });
    if (protocol === 'hysteria2') Object.assign(f, { sni: 'ed.example.com', mport: '20000-30000', hopInterval: '45', up: '50 mbps', down: '200 mbps' });
    return f;
  };
  // REALITY: RAW, XHTTP and gRPC; TLS on every transport but mKCP; none where it makes sense
  const SECS = { tcp: ['tls', 'reality'], ws: ['tls', 'none'], grpc: ['tls', 'reality'], httpupgrade: ['tls'], xhttp: ['tls', 'reality'], kcp: ['none'] };
  const cases = [];
  for (const p of SFT.PROTOCOLS) {
    if (!SFT.hasTransport(p)) { cases.push([p, base(p)]); continue; }
    for (const net of SFT.NETWORKS) {
      for (const sec of SECS[net].filter((x) => SFT.securitiesOf(p).includes(x))) {
        const f = Object.assign(base(p), { network: net, security: sec, path: net === 'grpc' ? 'svc' : '/p', host: 'cdn.example.com', headerType: net === 'tcp' ? 'http' : undefined });
        if (sec === 'tls') Object.assign(f, { sni: 'cdn.example.com', fp: 'chrome', alpn: 'h2,http/1.1' });
        if (sec === 'reality') Object.assign(f, { sni: 'www.microsoft.com', fp: 'chrome', pbk: 'Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw', sid: '6ba85179', spx: '/start' });
        if (net === 'grpc') f.grpcMode = 'multi';
        if (net === 'xhttp') f.xhttpMode = 'packet-up';
        if (net === 'kcp') Object.assign(f, { kcpHeader: 'wechat-video', kcpSeed: 'irnf-seed' });
        if (p === 'vless' && net === 'tcp' && sec === 'reality') { f.flow = 'xtls-rprx-vision'; f.headerType = 'none'; }
        // Xray 26.9+ refuses Trojan without TLS to a public address ("prohibited unless the server address is a
        // private IP or domain"); a private one keeps the check on the fields rather than on that rule
        if (p === 'trojan' && sec === 'none') f.address = '10.0.0.2';
        cases.push([`${p}-${net}-${sec}`, f]);
      }
    }
  }
  let made = 0;
  for (const [name, f] of cases) {
    const fields = Object.assign({}, f);
    for (const fld of SFT.PATH_FIELDS) {
      if (!(fld.id in VALUES) || fields[fld.id] !== undefined) continue;
      // a flow belongs to RAW + TLS/REALITY only; VLESS Encryption with a flow on its own row above
      if (fld.id === 'flow') continue;
      fields[fld.id] = VALUES[fld.id];
    }
    const server = createServer(fields);
    made++;
    check(`editor-${name}`, buildConfig({ mode: 'single', server }, F.settings({ routingMode: 'bypass-ir', muxServerIds: [server.id] })));
  }
  if (made < 20) throw new Error('the editor’s configs: only ' + made);

  // MASQUE (.superpowers/sdd/masque/design.md §8), made by the editor as a
  // hand-made server and a WARP sign-up make it: HTTP/3 and HTTP/2 with a user
  // and password; a WARP account over both — a device key made here (PKCS#8
  // PEM, as the sign-up writes it) and the endpoint's real public key; WARP
  // behind a cover domain (the SNI, and the name its certificate is verified
  // as); and the anti-DPI each HTTP version takes — noise before QUIC, a
  // fragment of the TCP handshake. Plain, under TUN and under the strict guard.
  const DEVICE_KEY = require('crypto').generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey.export({ format: 'pem', type: 'pkcs8' });
  const WARP_PUB = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIaU7MToJm9NKp8YfGxR6r+/h4mcG7SxI8tsW8OR1A5tv/zCzVbCRRh2t87/kxnP6lAy0lkr7qYwu+ox+k3dr6w==';
  const own = { address: 'mq.example.com', sni: 'mq.example.com', masqueUser: 'irnf-ci', masquePass: 'irnf-ci-pass' };
  const warp = { address: '162.159.198.1', sni: 'consumer-masque.cloudflareclient.com',
    warpPrivateKey: DEVICE_KEY, warpPublicKey: WARP_PUB, warpAddress: '172.16.0.2, 2606:4700:110:8a36::2' };
  const H2 = { masqueHttp: 'h2', fp: 'chrome' };
  const MASQUE = {
    h3: own,
    h2: Object.assign({}, own, H2),
    'warp-h3': warp,
    'warp-h2': Object.assign({}, warp, H2, { address: '162.159.198.2' }),
    'warp-cover': Object.assign({}, warp, { sni: 'www.example.com', vcn: 'www.example.com' }),
    'warp-h3-noise': Object.assign({}, warp, { noise: 'rand:50-100:0;base64:FgMBAAA=:10-20' }),
    'warp-h2-fragment': Object.assign({}, warp, H2, { address: '162.159.198.2', fragment: 'tlshello,100-200,10-20' })
  };
  let masqueMade = 0;
  for (const [name, f] of Object.entries(MASQUE)) {
    const server = createServer(Object.assign({ protocol: 'masque', name: 'editor-masque-' + name, port: '443' }, f));
    masqueMade++;
    for (const [variant, over] of Object.entries(LINK_SETTINGS)) {
      check(`editor-masque-${name}-${variant}`, buildConfig({ mode: 'single', server }, F.settings(Object.assign({ routingMode: 'bypass-ir' }, over))));
    }
  }
  if (masqueMade < 7) throw new Error('the editor’s MASQUE configs: only ' + masqueMade);
}

// Multi-internet (v1.32.0, src/main/multiWan.js): a server over two links as
// a group — balance with a weight and a backup link (the fallback), failover —
// and split: an XHTTP server uploading on one link and downloading on the
// other, over TLS and over REALITY, the download leg written by the app
// (xhttpSettings.extra.downloadSettings with its own sockopt.interface). Also
// a group's members over the links, the pool and advanced routing, and the
// anti-DPI dialer bound per interface. Each plain and under TUN — everything
// else that dials itself bound to the NIC, the links keeping their own, the
// entry names answered from the config (the download leg's too).
{
  const { groupRecord } = require('../src/main/groups');
  const XH = '11111111-2222-3333-4444-555555555555';
  const xhTls = parseLink(`vless://${XH}@x.example.com:443?encryption=none&type=xhttp&security=tls&sni=x.example.com&fp=chrome&path=%2Fxh&host=x.example.com&mode=auto#mw-xhttp-tls`);
  const xhReality = parseLink(`vless://${XH}@r.example.com:443?encryption=none&type=xhttp&security=reality&sni=www.microsoft.com&fp=chrome&pbk=${Buffer.alloc(32, 9).toString('base64url')}&sid=ab12&path=%2Fxr&mode=auto#mw-xhttp-reality`);
  const MW_LINKS = [{ id: 'eth0', name: 'A', weight: 2 }, { id: 'eth1', name: 'B', weight: 1 }, { id: 'eth2', name: 'C', role: 'backup' }];
  const mwOf = (mode) => ({ enabled: true, mode, links: MW_LINKS, split: { up: 'eth0', down: 'eth1' } });
  const mwGroup = groupRecord({ id: 'grp-ci', name: 'CI', members: [{ id: 'sv-vless' }, { id: 'sv-trojan' }] }, { 'sv-vless': F.VLESS_WS_TLS, 'sv-trojan': F.TROJAN_TCP_TLS });
  const MW_SHAPES = {
    balance: [single, 'balance'],
    'balance-fragment': [{ mode: 'single', server: F.vlessWithMarkers('sv-frag', { _fragment: 'tlshello,100-200,10-20' }) }, 'balance'],
    failover: [single, 'failover'],
    'split-xhttp-tls': [{ mode: 'single', server: xhTls }, 'split'],
    'split-xhttp-reality': [{ mode: 'single', server: xhReality }, 'split'],
    'split-not-xhttp': [single, 'split'],
    'group-balance': [{ mode: 'single', server: mwGroup }, 'balance'],
    'pool-balance': [pool, 'balance'],
    'advanced-balance': [advanced, 'balance']
  };
  const MW_SETTINGS = {
    plain: managed,
    tun: Object.assign({ routingMode: 'bypass-ir', tunMode: true, leakGuard: 'standard', directInterface: 'eth0',
      entryHostIps: Object.assign({ 'x.example.com': ['203.0.113.50'], 'r.example.com': ['203.0.113.51'] }, PINS) }, managed)
  };
  for (const [name, [plan, mode]] of Object.entries(MW_SHAPES)) {
    for (const [variant, over] of Object.entries(MW_SETTINGS)) {
      check(`multiwan-${name}-${variant}`, buildConfig(plan, F.settings(Object.assign({ multiWan: mwOf(mode) }, over))));
    }
  }
}

// sing-box TUN configs (phase 3): ipv6 × strict × exclusions (a v4 and a v6
// entry → /32 and /128), plus the darwin shape — no interface_name, because
// sing-tun there only accepts utun<N> and names the device itself — plus the
// per-app split (task 10a): exclude, only, and exclude combined with
// strict+v6+excludeIps to prove `apps` and everything else are independent.
let sbTotal = 0, sbFailed = 0;
const sb = process.env.IRNF_SINGBOX_EXE;
if (sb || DRY) {
  if (!DRY && !fs.existsSync(sb)) { console.error('no sing-box at ' + sb); process.exit(2); }
  const { buildTunConfig } = require('../src/main/tunSingbox');
  const cases = [];
  for (const ipv6 of [false, true]) {
    for (const strict of [false, true]) {
      for (const excludeIps of [[], ['1.2.3.4', '2001:db8::1']]) {
        cases.push([`tun-v6${ipv6}-strict${strict}-exclude${excludeIps.length}`, { socksPort: 10808, ipv6, strict, excludeIps }]);
      }
    }
  }
  cases.push(['tun-darwin-noname', { socksPort: 10808, excludeIps: ['1.2.3.4'], interfaceName: null }]);
  cases.push(['tun-apps-exclude', { socksPort: 10808, apps: { mode: 'exclude', names: ['chrome.exe', 'Telegram.exe'] } }]);
  cases.push(['tun-apps-only', { socksPort: 10808, apps: { mode: 'only', names: ['chrome.exe'] } }]);
  cases.push(['tun-apps-exclude-strict-v6', { socksPort: 10808, ipv6: true, strict: true, excludeIps: ['1.2.3.4'], apps: { mode: 'exclude', names: ['steam.exe'] } }]);
  // the router's gateway (v1.16.2): the UDP session lifetime as whole seconds (TunOpenwrt's ROUTER_UDP_TIMEOUT_S)
  cases.push(['tun-openwrt-udp-timeout', { socksPort: 30808, excludeIps: ['104.16.7.70'], udpTimeout: require('../src/main/tunOpenwrt').ROUTER_UDP_TIMEOUT_S }]);
  // sing-box 1.14+: the dns_mode the app writes for this very core (tunSingbox.tunDnsModeFor), with the rest of a strict config
  const { tunDnsModeFor } = require('../src/main/tunSingbox');
  const sbVersion = DRY ? '' : ((/(\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)/.exec(String(spawnSync(sb, ['version'], { encoding: 'utf8', timeout: 15000, windowsHide: true }).stdout || '')) || [])[1] || '');
  const sbMode = tunDnsModeFor(sbVersion, 'app');
  if (sbMode) cases.push(['tun-dns-mode', { socksPort: 10808, strict: true, excludeIps: ['1.2.3.4'], apps: { mode: 'exclude', names: ['steam.exe'] }, dnsMode: sbMode }]);
  for (const [name, args] of cases) {
    total++; sbTotal++;
    const file = path.join(work, `${name}.json`);
    fs.writeFileSync(file, JSON.stringify(buildTunConfig(args), null, 2));
    if (DRY) { console.log('built ' + path.basename(file)); continue; }
    const r = spawnSync(sb, ['check', '-c', file], { encoding: 'utf8', timeout: 15000, windowsHide: true });
    if (r.status === 0) { console.log('ok   ' + path.basename(file)); continue; }
    failed++; sbFailed++;
    console.log('FAIL ' + path.basename(file));
    console.log('     ' + ((r.stdout || '') + (r.stderr || '')).trim().split(/\r?\n/).slice(-3).join('\n     '));
  }
}

if (DRY) {
  console.log(`\n${total} configs built for xray ${version} (${sbTotal} of them sing-box TUN configs) in ${work} — no core was run`);
  process.exit(0);
}
const by = `${path.basename(exe)} ${version}` + (sb ? ` + ${path.basename(sb)} (${sbTotal - sbFailed}/${sbTotal} TUN configs)` : '');
console.log(`\n${total - failed}/${total} configs accepted by ${by}`);
process.exit(failed ? 1 : 0);
