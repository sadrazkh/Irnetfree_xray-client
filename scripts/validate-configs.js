'use strict';
/**
 * Generate every plan shape × DNS mode × geo state and run `xray run -test` on
 * each. This is the only check that proves the CORE accepts what configBuilder
 * emits (dns.tag, the dns outbound, expectedIPs, DoH strings, inboundTag
 * rules) — the unit tests only pin our own output. Needs bin/xray(.exe)
 * (`npm run get-xray`).
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { buildConfig } = require('../src/main/configBuilder');
const F = require('../tests/fixtures');

const exe = path.join(__dirname, '..', 'bin', process.platform === 'win32' ? 'xray.exe' : 'xray');
if (!fs.existsSync(exe)) { console.error('no core at ' + exe + ' — run: npm run get-xray'); process.exit(2); }

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

const work = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-validate-'));
const assetDir = path.dirname(exe);
let failed = 0, total = 0;
for (const [pn, plan] of Object.entries(plans)) {
  for (const [dn, dns] of Object.entries(dnsModes)) {
    for (const geoAssets of [true, false]) {
      for (const routingMode of (pn === 'advanced' || pn === 'pool' ? ['global'] : routing)) {
        for (const ipv6 of [false, true]) {
          total++;
          const cfg = buildConfig(plan, F.settings(Object.assign({ routingMode, geoAssets, ipv6 }, dns)));
          const file = path.join(work, `${pn}-${dn}-${routingMode}-geo${geoAssets}-v6${ipv6}.json`);
          fs.writeFileSync(file, JSON.stringify(cfg, null, 2));
          const r = spawnSync(exe, ['run', '-test', '-c', file], {
            env: Object.assign({}, process.env, { XRAY_LOCATION_ASSET: assetDir, V2RAY_LOCATION_ASSET: assetDir }),
            encoding: 'utf8', timeout: 15000, windowsHide: true
          });
          if (r.status === 0) { console.log('ok   ' + path.basename(file)); continue; }
          failed++;
          console.log('FAIL ' + path.basename(file));
          console.log('     ' + ((r.stdout || '') + (r.stderr || '')).trim().split(/\r?\n/).slice(-3).join('\n     '));
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
  'pool-bypass-ir': [pool, Object.assign({ routingMode: 'bypass-ir' }, managed)]
};
for (const [name, [plan, over]] of Object.entries(shapes)) {
  total++;
  const cfg = buildConfig(plan, F.settings(over));
  const file = path.join(work, `shape-${name}.json`);
  fs.writeFileSync(file, JSON.stringify(cfg, null, 2));
  const r = spawnSync(exe, ['run', '-test', '-c', file], {
    env: Object.assign({}, process.env, { XRAY_LOCATION_ASSET: assetDir, V2RAY_LOCATION_ASSET: assetDir }),
    encoding: 'utf8', timeout: 15000, windowsHide: true
  });
  if (r.status === 0) { console.log('ok   ' + path.basename(file)); continue; }
  failed++;
  console.log('FAIL ' + path.basename(file));
  console.log('     ' + ((r.stdout || '') + (r.stderr || '')).trim().split(/\r?\n/).slice(-3).join('\n     '));
}

console.log(`\n${total - failed}/${total} configs accepted by ${path.basename(exe)}`);
process.exit(failed ? 1 : 0);
