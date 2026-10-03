'use strict';
/**
 * The desktop's and the headless server's configs, byte for byte as v1.16.1
 * built them (v1.16.2 owner's rule: every change of the router round is
 * guarded to the OpenWrt build — the desktop, macOS, Linux and Android behave
 * exactly as before).
 *
 * The hashes below were taken from the v1.16.1 code (ff982b3) before the
 * round touched a line: sha256 of JSON.stringify(<config>). A change to any of
 * these outputs — a new key, a reordered one, a value — fails here; the
 * router's own additions (udp_timeout on the gateway's TUN, the DNS tuning in
 * service.js) enter only through options/paths a desktop never takes.
 * Android has its own builder (ConfigBuilder.kt), untouched by the round.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const { buildTunConfig } = require('../src/main/tunSingbox');
const { buildConfig } = require('../src/main/configBuilder');
const { buildSingboxConfig } = require('../src/main/singboxBuilder');
const { buildDnsPlan } = require('../src/main/dnsBuilder');
const { settings, VLESS_WS_TLS, TROJAN_TCP_TLS, WG_CORP } = require('./fixtures');

const sha = (o) => crypto.createHash('sha256').update(JSON.stringify(o)).digest('hex');

/** The desktop's TUN configs: Windows/Linux (named adapter), macOS (no name), strict, the per-app split. */
const TUN_CASES = {
  'default': { socksPort: 10808 },
  'strict + excludes': { socksPort: 10808, strict: true, excludeIps: ['203.0.113.7', '2001:db8::7', '198.51.100.0/24'] },
  'darwin (no interface name)': { socksPort: 20808, interfaceName: null },
  'apps exclude': { socksPort: 10808, apps: { mode: 'exclude', names: ['chrome.exe', ' chrome.exe ', 'Telegram.exe'] } },
  'apps only, ipv6': { socksPort: 10808, ipv6: true, apps: { mode: 'only', names: ['firefox'] } }
};

const MANAGED = { dnsManaged: true, dnsRemote: ['https://1.1.1.1/dns-query', 'https://8.8.8.8/dns-query'], dnsDirect: ['178.22.122.100', '185.51.200.2'] };
/** The desktop's xray configs: proxy mode, TUN with the NIC binding, bypass-ir, a chain, a corporate WireGuard, the legacy DNS list. */
const XRAY_CASES = {
  'single, global, managed DNS': [{ mode: 'single', server: VLESS_WS_TLS }, settings(MANAGED)],
  'single, bypass-ir, TUN bound to Wi-Fi': [{ mode: 'single', server: VLESS_WS_TLS }, settings(Object.assign({ routingMode: 'bypass-ir', tunMode: true, directInterface: 'Wi-Fi' }, MANAGED))],
  'chain, bypass-ir, strict': [{ mode: 'chain', chain: [TROJAN_TCP_TLS, VLESS_WS_TLS] }, settings(Object.assign({ routingMode: 'bypass-ir', tunMode: true, leakGuard: 'strict' }, MANAGED))],
  'corporate WireGuard, bypass-ir': [{ mode: 'single', server: WG_CORP }, settings(Object.assign({ routingMode: 'bypass-ir' }, MANAGED))],
  'managed DNS off (the legacy list)': [{ mode: 'single', server: VLESS_WS_TLS }, settings({ dnsManaged: false, dnsRemote: ['1.1.1.1', '8.8.8.8'] })]
};

const PINNED = {
  tun: {
    'default': '9420dd38c2581f35dc87cdd5edceb2769f419878c07bfa76e48926edb72e9190',
    'strict + excludes': 'c264b36c7ebc2dafdcec3e33f434032d46b6f82757377b2148cdb6bd7b8b7799',
    'darwin (no interface name)': 'c98fc225f8c8a325c5b08e11cacf2625ee994fd297a77cbe38bc6003beef79fa',
    'apps exclude': 'a5701a150bd32a8f74081c2afbaeb3532361ba85ff850795207d922b3cfbc5cf',
    'apps only, ipv6': 'b4a84a7635248a1f0a8a789de5c7a2c3bbb5b117508074f153d65d4b719b6b16'
  },
  xray: {
    'single, global, managed DNS': '156d20b1fc80f25a239780a9cbbdcd87439ab7c22fade2c637731dafe7e84ea3',
    'single, bypass-ir, TUN bound to Wi-Fi': 'e6c2718bd2bbfc22827bbc6f6081798728bc20710a4ad65209e885036d12c435',
    'chain, bypass-ir, strict': 'b0ea9a73726b9aa34b8178336621b944b93ba8f8c82f74a74f8bb1c83344c9ef',
    'corporate WireGuard, bypass-ir': '3c572ac9157373d60eefba94c19e30914e04575b0ec2630fa18abb77fcfe9bee',
    'managed DNS off (the legacy list)': '5f3c32ac62da3312fb73f8929e8cb25695032ff11c552226834298506e20ac58'
  },
  singbox: 'c18b0d2f8b9e478d816111995099f3808182acd2e571ca97ec60ecb07d52b221',
  dnsPlan: 'ae093d5d2a5cda0e56bc840eeb5e799a9cc913679c9c891fb2d20b80842566e0'
};

test('desktop TUN (sing-box) configs are byte-identical to v1.16.1 — no udp_timeout, no new key', () => {
  for (const [name, opts] of Object.entries(TUN_CASES)) {
    const cfg = buildTunConfig(opts);
    assert.equal('udp_timeout' in cfg.inbounds[0], false, `${name}: udp_timeout is the router's alone`);
    assert.equal(sha(cfg), PINNED.tun[name], `${name}: ${JSON.stringify(cfg)}`);
  }
});

test('desktop xray configs are byte-identical to v1.16.1 — no timeoutMs, parallel query or serve-stale in a desktop DNS block', () => {
  for (const [name, [plan, s]] of Object.entries(XRAY_CASES)) {
    const cfg = buildConfig(plan, s);
    for (const k of ['enableParallelQuery', 'serveStale', 'serveExpiredTTL']) assert.equal(k in (cfg.dns || {}), false, `${name}: ${k}`);
    assert.ok(!JSON.stringify(cfg).includes('timeoutMs'), `${name}: a per-server timeout`);
    assert.equal(sha(cfg), PINNED.xray[name], `${name}: ${JSON.stringify(cfg)}`);
  }
});

test('the desktop sing-box core config and the DNS plan are byte-identical to v1.16.1', () => {
  assert.equal(sha(buildSingboxConfig(VLESS_WS_TLS, Object.assign({ routingMode: 'bypass-ir' }, MANAGED))), PINNED.singbox);
  assert.equal(sha(buildDnsPlan(Object.assign({ routingMode: 'bypass-ir' }, MANAGED), { geoAssets: true })), PINNED.dnsPlan);
});

