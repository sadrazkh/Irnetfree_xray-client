'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { buildSingboxConfig } = require('../src/main/singboxBuilder');
const { VLESS_WS_TLS } = require('./fixtures');

test('a DoH remote resolver becomes an https DNS server', () => {
  const c = buildSingboxConfig(VLESS_WS_TLS, { dnsRemote: ['https://1.1.1.1/dns-query'] });
  assert.deepEqual(c.dns.servers[0], { type: 'https', tag: 'dns-direct', server: '1.1.1.1', path: '/dns-query' });
  assert.equal(c.dns.final, 'dns-direct');
});

test('a plain IP stays udp; the legacy dns list still works; nothing → 1.1.1.1', () => {
  assert.deepEqual(buildSingboxConfig(VLESS_WS_TLS, { dnsRemote: ['9.9.9.9'] }).dns.servers[0], { type: 'udp', tag: 'dns-direct', server: '9.9.9.9' });
  assert.equal(buildSingboxConfig(VLESS_WS_TLS, { dns: ['8.8.8.8'] }).dns.servers[0].server, '8.8.8.8');
  assert.equal(buildSingboxConfig(VLESS_WS_TLS, {}).dns.servers[0].server, '1.1.1.1');
});

/* ---------------- newer link features in sing-box's terms (each config passed `sing-box check`, 1.13.14) ---------------- */

const { parseLink } = require('../src/main/parser');
const outOf = (link, s) => buildSingboxConfig(parseLink(link), s || {}).outbounds[0];

test('ECH: the DNS form asks sing-box to look up the name before the +; a base64 list goes in as PEM', () => {
  const o = outOf('vless://u@104.21.44.18:2087?type=ws&host=h.example&path=/&security=tls&fp=firefox&sni=h.example&ech=cloudflare-ech.com+udp://1.1.1.1#x');
  assert.deepEqual(o.tls.ech, { enabled: true, query_server_name: 'cloudflare-ech.com' });
  assert.equal(o.tls.server_name, 'h.example');
  const b = outOf('trojan://pw@a.example.com:443?ech=AEXX');
  assert.deepEqual(b.tls.ech, { enabled: true, config: ['-----BEGIN ECH CONFIGS-----', 'AEXX', '-----END ECH CONFIGS-----'] });
  assert.equal(outOf('trojan://pw@a.example.com:443').tls.ech, undefined);
});

test('a pinned certificate is never "accept any" on sing-box: pcs, vcn or a pin learnt on first use → not sing-box\'s (the caller runs it on Xray, saying why)', () => {
  const { UnsupportedEngineConfig } = require('../src/main/singboxBuilder');
  const pinned = /certificate is pinned \(pcs, vcn or pinned on first use\), and sing-box could only check it by accepting any certificate/;
  const refused = (server) => assert.throws(() => buildSingboxConfig(server, {}), (e) => e instanceof UnsupportedEngineConfig && pinned.test(e.message));
  refused(parseLink('trojan://pw@a.example.com:443?pcs=' + 'ab'.repeat(32)));
  refused(parseLink('trojan://pw@a.example.com:443?vcn=real.example'));
  refused(parseLink('vless://u@w.example.com:443?type=ws&security=tls&pcs=' + 'cd'.repeat(32)));
  refused(parseLink('hysteria2://pw@h.example.com:443/?insecure=1&pinSHA256=' + 'ef'.repeat(32)));
  // the pin learnt on first use (certPin.js) — a link that asked for allowInsecure: on sing-box it was "insecure", the pin ignored
  refused(Object.assign(parseLink('trojan://pw@a.example.com:443?allowInsecure=1'), { certPin: 'aa'.repeat(32) }));
  refused(Object.assign(parseLink('hysteria2://pw@h.example.com:443/?insecure=1'), { certPin: 'aa'.repeat(32) }));
  // no pin: as before — the plain check, or the link's own allowInsecure (a Hysteria2's on purpose: needsInsecureCore)
  assert.equal(outOf('trojan://pw@a.example.com:443').tls.insecure, undefined);
  assert.equal(outOf('trojan://pw@a.example.com:443?allowInsecure=1').tls.insecure, true);
  assert.equal(outOf('hysteria2://pw@h.example.com:443/?insecure=1').tls.insecure, true);
  // REALITY has no certificate to pin: unchanged
  assert.equal(outOf('vless://u@r.example.com:443?security=reality&pbk=' + 'A'.repeat(43) + '&sid=ab&sni=www.example.com').tls.reality.enabled, true);
});

test('a pinned server set to sing-box is connected and pinged on Xray, the connect log saying why — desktop, headless service and Android', () => {
  const fs = require('node:fs');
  const path = require('node:path');
  const R = (...p) => fs.readFileSync(path.join(__dirname, '..', ...p), 'utf8');
  // (a TUIC / AnyTLS has no Xray: refused by name first — the one line before the fallback)
  const sbOnlyFirst = String.raw`(?:\/\/[^\n]*\n\s*if \(sbOnly\) throw new Error\(singboxOnlyError\(sbOnly, 'pin', settings\.lang\)\);\s*)?`;
  const fallback = new RegExp(String.raw`config = buildSingboxConfig\(plan\.server, settings\);\s*\} catch \(e\) \{\s*` + sbOnlyFirst +
    String.raw`send\('log', \{ line: ` + '`sing-box: \\$\\{e\\.message\\} — using Xray`' + String.raw`, level: 'warn' \}\);\s*engine = 'xray';`);
  for (const [file, re] of [
    ['src/main/main.js', fallback],
    ['src/server/service.js', fallback],
    ['src/main/latencyTest.js', /buildSingboxConfig\(target, [^\n]+\n[^\n]+\n\s*\} catch \{ \/\* a server sing-box cannot carry is measured on Xray \*\/ \}/],
    ['android/app/src/main/java/com/irnetfree/vpn/vpn/TunnelSetup.kt', /SingboxConfig\.build\(single\.server, s, auth, lan\)\.toString\(\)\)\s*\} catch \(t: Throwable\) \{\s*log\("sing-box: \$\{t\.message\} — using the in-process core"\)/]
  ]) assert.match(R(file), re, file);
  const kt = R('android/app/src/main/java/com/irnetfree/vpn/core/SingboxConfig.kt');
  assert.match(kt, /if \(security == "tls" && pinnedTls\(t, certPin\)\) \{\s*throw Unsupported\(/, 'Android: the same refusal');
  assert.equal((kt.match(/translateTls\(ss, server\.address, server\.certPin\)/g) || []).length, 2, 'Android: both translations pass the pin learnt on first use');
  assert.doesNotMatch(kt, /verifyPeerCertByName"\)\.isNotBlank\(\)\)\)\) tls\.put\("insecure", true\)/, 'Android: no pin turns into insecure');
});

test('hysteria2: password, salamander, hopping ranges, bandwidth, no uTLS', () => {
  const o = outOf('hysteria2://p%40ss@h.example.com:20000-30000/?sni=s.example&obfs=salamander&obfs-password=OB&insecure=1&up=50&down=100&mport=20000-30000,443');
  assert.deepEqual(o, {
    type: 'hysteria2', tag: 'proxy', server: 'h.example.com', password: 'p@ss',
    server_ports: ['20000:30000', '443:443'], hop_interval: '30s',
    obfs: { type: 'salamander', password: 'OB' }, up_mbps: 50, down_mbps: 100,
    tls: { enabled: true, server_name: 's.example', insecure: true }
  });
  const plain = outOf('hy2://pw@h.example.com:443');
  assert.deepEqual(plain, { type: 'hysteria2', tag: 'proxy', server: 'h.example.com', server_port: 443, password: 'pw', tls: { enabled: true, server_name: 'h.example.com' } });
});

test('ws early data, httpupgrade, a fragment, Shadowsocks plugins; RAW\'s HTTP header falls back to Xray', () => {
  const ws = outOf('vless://u@w.example.com:443?type=ws&security=tls&path=%2Fws%3Fed%3D2048&host=w.example.com');
  assert.deepEqual(ws.transport, { type: 'ws', path: '/ws', max_early_data: 2048, early_data_header_name: 'Sec-WebSocket-Protocol', headers: { Host: 'w.example.com' } });
  assert.deepEqual(outOf('vless://u@u.example.com:443?type=httpupgrade&security=tls&path=%2Fup&host=u.example.com').transport, { type: 'httpupgrade', host: 'u.example.com', path: '/up' });
  assert.equal(outOf('vless://u@u.example.com:443?security=tls&fragment=tlshello,100-200,10-20').tls.fragment, true);
  const b = Buffer.from('aes-256-gcm:pw').toString('base64');
  const v2 = outOf(`ss://${b}@v.example.com:443/?plugin=${encodeURIComponent('v2ray-plugin;tls;host=cdn.example.com;path=/ws')}`);
  assert.equal(v2.plugin, 'v2ray-plugin');
  assert.equal(v2.plugin_opts, 'mode=websocket;tls;host=cdn.example.com;path=/ws;mux=0');
  assert.equal(v2.tls, undefined);
  const obfs = outOf(`ss://${b}@o.example.com:8388/?plugin=${encodeURIComponent('obfs-local;obfs=http;obfs-host=www.bing.com')}`);
  assert.deepEqual([obfs.plugin, obfs.plugin_opts], ['obfs-local', 'obfs=http;obfs-host=www.bing.com']);
  assert.throws(() => outOf('vless://u@a.example.com:443?type=tcp&headerType=http&host=x.example'), /HTTP header/);
});

test('a latency test asks for the SOCKS port alone', () => {
  const c = buildSingboxConfig(parseLink('hy2://pw@h.example.com:443'), { socksPort: 20808, httpPort: 0 });
  assert.deepEqual(c.inbounds.map(i => [i.type, i.listen_port]), [['socks', 20808]]);
});

test('the TUN\'s sing-box never carries a server\'s TLS: every outbound it can write hands traffic to Xray (socks on 127.0.0.1) or goes direct', () => {
  const { buildTunConfig } = require('../src/main/tunSingbox');
  const shapes = [
    { socksPort: 10808 },
    { socksPort: 10808, ipv6: true, strict: true, excludeIps: ['1.2.3.4', '2001:db8::1'] },
    { socksPort: 10808, apps: { mode: 'exclude', names: ['chrome.exe'] } },
    { socksPort: 10808, apps: { mode: 'only', names: ['chrome.exe'] } },
    { socksPort: 10808, watch: { port: 30860, secret: '0123456789abcdef0123456789abcdef' } },
    { socksPort: 30808, lanRoutes: { targets: [{ tag: 'lu-tp-1', port: 41001, path: '/tmp/irnetfree-lu/lu-tp-1.json' }] } }
  ];
  for (const s of shapes) {
    for (const o of buildTunConfig(s).outbounds) {
      assert.ok(o.type === 'direct' || (o.type === 'socks' && o.server === '127.0.0.1'), JSON.stringify(o));
      assert.equal(o.tls, undefined, JSON.stringify(o));
    }
  }
});
