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

test('pcs / vcn: sing-box cannot express either check, so it skips verification as allowInsecure did', () => {
  assert.equal(outOf('trojan://pw@a.example.com:443?pcs=' + 'ab'.repeat(32)).tls.insecure, true);
  assert.equal(outOf('trojan://pw@a.example.com:443?vcn=real.example').tls.insecure, true);
  assert.equal(outOf('trojan://pw@a.example.com:443').tls.insecure, undefined);
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
