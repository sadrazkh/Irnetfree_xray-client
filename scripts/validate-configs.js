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
console.log(`\n${total - failed}/${total} configs accepted by ${path.basename(exe)}`);
process.exit(failed ? 1 : 0);
