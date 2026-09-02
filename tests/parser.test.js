'use strict';
/**
 * Share-link parser tests.
 *
 * These pin down the exact outbound shape each link produces. The Android side
 * has its own port of this file (android/.../core/LinkParser.kt) that MUST agree
 * — when you change anything here, change it there too.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  parseLink, parseMany, b64decode,
  buildStreamSettings, buildWireguardOutbound,
  makeWireguardServer, makeProxyServer, applyServerEdits,
  parseWireguardConf, isWireguardConf,
  buildShareLink, isHttpProxyLink
} = require('../src/main/parser');

const b64 = (s) => Buffer.from(s, 'utf8').toString('base64');
const b64url = (s) => b64(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

/* ----------------------------- VLESS ----------------------------- */

test('vless: ws + tls', () => {
  const s = parseLink('vless://uuid-a@a.example.com:443?type=ws&security=tls&sni=cdn.example.com&host=cdn.example.com&path=%2Fws&fp=firefox#My%20Server');

  assert.equal(s.protocol, 'vless');
  assert.equal(s.name, 'My Server');
  assert.equal(s.address, 'a.example.com');
  assert.equal(s.port, 443);

  const vnext = s.outbound.settings.vnext[0];
  assert.equal(vnext.address, 'a.example.com');
  assert.equal(vnext.port, 443);
  assert.deepEqual(vnext.users[0], { id: 'uuid-a', encryption: 'none', flow: '' });

  const st = s.outbound.streamSettings;
  assert.equal(st.network, 'ws');
  assert.equal(st.security, 'tls');
  assert.deepEqual(st.wsSettings, { path: '/ws', headers: { Host: 'cdn.example.com' } });
  assert.deepEqual(st.tlsSettings, { serverName: 'cdn.example.com', allowInsecure: false, fingerprint: 'firefox' });
});

test('vless: reality keeps pbk/sid/spiderX and flow', () => {
  const s = parseLink('vless://uuid-b@1.2.3.4:8443?security=reality&pbk=PUBKEY&sid=ab12&spx=%2F&fp=chrome&flow=xtls-rprx-vision#Reality');

  assert.equal(s.outbound.settings.vnext[0].users[0].flow, 'xtls-rprx-vision');
  assert.deepEqual(s.outbound.streamSettings.realitySettings, {
    serverName: '', fingerprint: 'chrome', publicKey: 'PUBKEY', shortId: 'ab12', spiderX: '/'
  });
  // reality never emits tlsSettings
  assert.equal(s.outbound.streamSettings.tlsSettings, undefined);
});

test('vless: bare link falls back to tcp/none and port 443', () => {
  const s = parseLink('vless://uuid-c@plain.example.com');
  assert.equal(s.port, 443);
  assert.deepEqual(s.outbound.streamSettings, { network: 'tcp', security: 'none' });
  // no name in the link -> the address is used
  assert.equal(s.name, 'plain.example.com');
});

test('vless: IPv6 host is unbracketed', () => {
  const s = parseLink('vless://uuid-d@[2001:db8::1]:8443?security=tls#v6');
  assert.equal(s.address, '2001:db8::1');
  assert.equal(s.port, 8443);
});

test('vless: grpc / h2 / xhttp / kcp transports', () => {
  const grpc = parseLink('vless://u@g.example.com:443?type=grpc&serviceName=svc&mode=multi').outbound.streamSettings;
  assert.deepEqual(grpc.grpcSettings, { serviceName: 'svc', multiMode: true });

  const h2 = parseLink('vless://u@h.example.com:443?type=h2&path=%2Fp&host=a.com,b.com').outbound.streamSettings;
  assert.equal(h2.network, 'h2');
  assert.deepEqual(h2.httpSettings, { path: '/p', host: ['a.com', 'b.com'] });

  const xh = parseLink('vless://u@x.example.com:443?type=xhttp&path=%2Fx&host=x.com&mode=packet-up').outbound.streamSettings;
  assert.equal(xh.network, 'xhttp');
  assert.deepEqual(xh.xhttpSettings, { path: '/x', host: 'x.com', mode: 'packet-up' });

  const kcp = parseLink('vless://u@k.example.com:443?type=kcp&headerType=srtp&seed=s1').outbound.streamSettings;
  assert.equal(kcp.network, 'kcp');
  assert.deepEqual(kcp.kcpSettings, { header: { type: 'srtp' }, seed: 's1' });
});

test('vless: tcp with http header type', () => {
  const st = parseLink('vless://u@t.example.com:80?type=tcp&headerType=http&path=%2Fa&host=t.com').outbound.streamSettings;
  assert.deepEqual(st.tcpSettings, {
    header: { type: 'http', request: { path: ['/a'], headers: { Host: ['t.com'] } } }
  });
});

test('vless: anti-DPI markers are carried on the outbound', () => {
  const ob = parseLink('vless://u@f.example.com:443?fragment=tlshello,100-200,10-20&noise=faketls#frag').outbound;
  assert.equal(ob._fragment, 'tlshello,100-200,10-20');
  assert.equal(ob._noise, 'faketls');
});

test('vless: alpn is split on commas', () => {
  const st = parseLink('vless://u@a.example.com:443?security=tls&alpn=h2,http%2F1.1').outbound.streamSettings;
  assert.deepEqual(st.tlsSettings.alpn, ['h2', 'http/1.1']);
});

/* ----------------------------- VMess ----------------------------- */

test('vmess: base64 JSON payload', () => {
  const link = 'vmess://' + b64(JSON.stringify({
    v: '2', ps: 'VM Node', add: 'vm.example.com', port: '8080', id: 'uuid-vm',
    aid: '2', scy: 'zero', net: 'ws', type: 'none', host: 'vm.example.com',
    path: '/vm', tls: 'tls', sni: 'sni.example.com'
  }));
  const s = parseLink(link);

  assert.equal(s.protocol, 'vmess');
  assert.equal(s.name, 'VM Node');
  assert.equal(s.address, 'vm.example.com');
  assert.equal(s.port, 8080);
  assert.deepEqual(s.outbound.settings.vnext[0].users[0], { id: 'uuid-vm', alterId: 2, security: 'zero' });

  const st = s.outbound.streamSettings;
  assert.equal(st.network, 'ws');
  assert.deepEqual(st.wsSettings, { path: '/vm', headers: { Host: 'vm.example.com' } });
  assert.equal(st.tlsSettings.serverName, 'sni.example.com');
});

test('vmess: non-tls payload yields security none', () => {
  const link = 'vmess://' + b64(JSON.stringify({ add: 'p.example.com', port: '80', id: 'x', net: 'tcp' }));
  const st = parseLink(link).outbound.streamSettings;
  assert.equal(st.security, 'none');
  assert.equal(st.tlsSettings, undefined);
});

test('vmess: invalid payload throws', () => {
  assert.throws(() => parseLink('vmess://' + b64('not json')), /invalid base64\/JSON/);
});

/* ----------------------------- Trojan ----------------------------- */

test('trojan: defaults to tls and url-decodes the password', () => {
  const s = parseLink('trojan://p%40ss%3Aword@tr.example.com:443?sni=tr.example.com#Trojan');
  assert.equal(s.protocol, 'trojan');
  assert.deepEqual(s.outbound.settings.servers[0], {
    address: 'tr.example.com', port: 443, password: 'p@ss:word'
  });
  assert.equal(s.outbound.streamSettings.security, 'tls');
  assert.equal(s.outbound.streamSettings.tlsSettings.serverName, 'tr.example.com');
});

test('trojan: explicit security=none is respected', () => {
  const st = parseLink('trojan://pw@tr.example.com:80?security=none').outbound.streamSettings;
  assert.equal(st.security, 'none');
});

/* --------------------------- Shadowsocks --------------------------- */

test('ss: SIP002 form — base64(method:password)@host:port', () => {
  const s = parseLink('ss://' + b64url('aes-256-gcm:secret') + '@ss.example.com:8388#SS');
  assert.equal(s.name, 'SS');
  assert.deepEqual(s.outbound.settings.servers[0], {
    address: 'ss.example.com', port: 8388, method: 'aes-256-gcm', password: 'secret', uot: true
  });
});

test('ss: legacy form — base64(method:password@host:port)', () => {
  const s = parseLink('ss://' + b64('chacha20-ietf-poly1305:pw@ss2.example.com:9000') + '#SS%20legacy');
  assert.equal(s.name, 'SS legacy');
  assert.equal(s.address, 'ss2.example.com');
  assert.equal(s.port, 9000);
  assert.equal(s.outbound.settings.servers[0].method, 'chacha20-ietf-poly1305');
});

test('ss: plugin query is ignored', () => {
  const s = parseLink('ss://' + b64url('aes-128-gcm:pw') + '@ss3.example.com:1234?plugin=v2ray-plugin%3Btls#P');
  assert.equal(s.address, 'ss3.example.com');
  assert.equal(s.port, 1234);
});

/* ------------------------------ SOCKS ------------------------------ */

test('socks: host:port only, no credentials', () => {
  const s = parseLink('socks://1.2.3.4:1080#Open');
  assert.equal(s.protocol, 'socks');
  assert.deepEqual(s.outbound.settings.servers[0], { address: '1.2.3.4', port: 1080 });
  assert.equal(s.outbound.settings.servers[0].users, undefined);
});

test('socks: plain user:pass@host:port', () => {
  const s = parseLink('socks5://alice:s3cret@p.example.com:1081');
  assert.deepEqual(s.outbound.settings.servers[0].users, [{ user: 'alice', pass: 's3cret' }]);
  assert.equal(s.port, 1081);
});

test('socks: base64 credentials and fully base64 body', () => {
  const a = parseLink('socks://' + b64('bob:pw') + '@q.example.com:1082');
  assert.deepEqual(a.outbound.settings.servers[0].users, [{ user: 'bob', pass: 'pw' }]);

  const b = parseLink('socks://' + b64('carol:pw2@r.example.com:1083'));
  assert.equal(b.address, 'r.example.com');
  assert.equal(b.port, 1083);
  assert.deepEqual(b.outbound.settings.servers[0].users, [{ user: 'carol', pass: 'pw2' }]);
});

test('makeProxyServer: builds socks/http from form fields', () => {
  const http = makeProxyServer({ name: 'Corp', type: 'http', address: 'proxy.corp', port: '3128', username: 'u', password: 'p' });
  assert.equal(http.protocol, 'http');
  assert.equal(http.outbound.protocol, 'http');
  assert.deepEqual(http.outbound.settings.servers[0].users, [{ user: 'u', pass: 'p' }]);

  const socks = makeProxyServer({ type: 'socks', address: '10.0.0.9' });
  assert.equal(socks.port, 1080);                       // protocol default
  assert.equal(socks.outbound.settings.servers[0].users, undefined);
});

test('http proxy share link round-trips (v2rayN shape)', () => {
  const s = makeProxyServer({ name: 'Corp', type: 'http', address: 'proxy.corp', port: '3128', username: 'u', password: 'p' });
  const link = buildShareLink(s);
  assert.match(link, /^http:\/\/[A-Za-z0-9+/=]+@proxy\.corp:3128#Corp$/);
  const back = parseLink(link);
  assert.equal(back.protocol, 'http');
  assert.equal(back.name, 'Corp');
  assert.deepEqual(back.outbound.settings.servers[0], { address: 'proxy.corp', port: 3128, users: [{ user: 'u', pass: 'p' }] });

  const open = parseLink('http://10.0.0.9:8080#Open');
  assert.equal(open.outbound.protocol, 'http');
  assert.equal(open.outbound.settings.servers[0].users, undefined);
});

// Buffer.toString('base64') uses the STANDARD alphabet, so credentials can
// encode to a blob containing '/'. The link must still be recognised as a proxy
// link, otherwise smartImport files it as a subscription.
test('http proxy share link round-trips when the base64 credentials contain "/"', () => {
  const s = makeProxyServer({ name: 'Corp', type: 'http', address: 'proxy.corp', port: '3128', username: 'user', password: 'secret?' });
  const link = buildShareLink(s);
  assert.ok(link.includes('/@'), 'fixture must produce a base64 blob ending in "/": ' + link);
  assert.equal(isHttpProxyLink(link), true);

  const back = parseLink(link);
  assert.equal(back.protocol, 'http');
  assert.equal(back.name, 'Corp');
  assert.deepEqual(back.outbound.settings.servers[0], { address: 'proxy.corp', port: 3128, users: [{ user: 'user', pass: 'secret?' }] });

  // and it must reach parseMany as a server, not be skipped as a subscription
  const { servers, errors } = parseMany(link);
  assert.deepEqual(errors, []);
  assert.deepEqual(servers.map(x => x.protocol), ['http']);
});

test('isHttpProxyLink: only host:port shapes, never subscription URLs', () => {
  assert.equal(isHttpProxyLink('http://1.2.3.4:8080'), true);
  assert.equal(isHttpProxyLink('http://dXNlcjpwYXNz@1.2.3.4:8080#Corp'), true);
  assert.equal(isHttpProxyLink('http://dXNlcjpzZWNyZXQ/@proxy.corp:3128#Corp'), true);
  assert.equal(isHttpProxyLink('http://panel.example.com/sub/abc123'), false);
  assert.equal(isHttpProxyLink('http://panel.example.com/sub@x/y'), false);
  assert.equal(isHttpProxyLink('http://1.2.3.4:8080/?token=x'), false);
  assert.equal(isHttpProxyLink('https://1.2.3.4:8080'), false);
  assert.equal(isHttpProxyLink('http://1.2.3.4'), false);
});

// HTTP_PROXY_LINK is /i, so parseLink's scheme guard must be too — otherwise an
// uppercase link passes parseMany's filter and then throws instead of importing.
test('parseLink accepts an uppercase http:// scheme (matching the /i regex)', () => {
  assert.equal(isHttpProxyLink('HTTP://1.2.3.4:8080#Up'), true);

  const s = parseLink('HTTP://1.2.3.4:8080#Up');
  assert.equal(s.protocol, 'http');
  assert.equal(s.address, '1.2.3.4');
  assert.equal(s.port, 8080);

  const { servers, errors } = parseMany('HTTP://1.2.3.4:8080#Up');
  assert.deepEqual(errors, []);
  assert.deepEqual(servers.map(x => x.protocol), ['http']);
});

// HTTP_PROXY_LINK is deliberately duplicated: the renderer cannot require
// main-process modules. Nothing else guards the two copies against drifting
// apart, which would make the main process and the UI classify links
// differently with no failing test.
test('HTTP_PROXY_LINK is identical in src/main/parser.js and src/renderer/app.js', () => {
  const fs = require('node:fs');
  const path = require('node:path');

  const extract = (rel) => {
    const file = path.join(__dirname, '..', rel);
    const m = fs.readFileSync(file, 'utf8').match(/^const HTTP_PROXY_LINK = (\/.+\/[a-z]*);$/m);
    assert.ok(m, `no "const HTTP_PROXY_LINK = /…/;" literal found in ${rel}`);
    return m[1];
  };

  const mainCopy = extract('src/main/parser.js');
  const rendererCopy = extract('src/renderer/app.js');
  assert.equal(
    rendererCopy, mainCopy,
    'HTTP_PROXY_LINK drifted between src/main/parser.js and src/renderer/app.js — ' +
    `main: ${mainCopy} | renderer: ${rendererCopy}. Keep the two copies byte-identical.`
  );
});

test('parseMany imports http proxy links and skips subscription URLs', () => {
  const { servers } = parseMany([
    'http://dXNlcjpwYXNz@1.2.3.4:8080#Corp',
    'http://panel.example.com/sub/abc123',
    'vless://u1@a.example.com:443#A'
  ].join('\n'));
  assert.deepEqual(servers.map(s => s.protocol), ['http', 'vless']);
});

/* ---------------------------- WireGuard ---------------------------- */

test('wireguard: link parse coerces the interface address to /32', () => {
  const s = parseLink('wireguard://PRIVKEY@wg.example.com:51820?publickey=PUBKEY&address=10.13.13.2%2F24&mtu=1380&reserved=1,2,3#WG');

  assert.equal(s.protocol, 'wireguard');
  assert.equal(s.address, 'wg.example.com');
  assert.equal(s.port, 51820);

  const st = s.outbound.settings;
  assert.equal(st.secretKey, 'PRIVKEY');
  assert.deepEqual(st.address, ['10.13.13.2/32']);      // /24 -> /32, xray refuses otherwise
  assert.equal(st.mtu, 1380);
  assert.deepEqual(st.reserved, [1, 2, 3]);
  assert.deepEqual(st.peers[0], {
    publicKey: 'PUBKEY', endpoint: 'wg.example.com:51820', allowedIPs: ['0.0.0.0/0', '::/0']
  });
});

test('wireguard: IPv6 interface address becomes /128', () => {
  const ob = buildWireguardOutbound({ address: 'fd00::2/64', privateKey: 'k', publicKey: 'p', endpoint: 'h:1' });
  assert.deepEqual(ob.settings.address, ['fd00::2/128']);
});

test('wireguard: defaults when fields are missing', () => {
  const ob = buildWireguardOutbound({ privateKey: 'k', publicKey: 'p', endpoint: 'h:1' });
  assert.deepEqual(ob.settings.address, ['10.0.0.2/32']);
  assert.equal(ob.settings.mtu, 1420);
  assert.equal(ob.settings.reserved, undefined);
});

test('makeWireguardServer: derives host/port from the endpoint', () => {
  const s = makeWireguardServer({ name: 'WG Home', endpoint: 'wg.home.net:51821', privateKey: 'k', publicKey: 'p', address: '10.7.0.2/32' });
  assert.equal(s.address, 'wg.home.net');
  assert.equal(s.port, 51821);
  assert.equal(s.outbound.settings.peers[0].endpoint, 'wg.home.net:51821');
});

/* --------------------------- WireGuard .conf --------------------------- */

const WG_CONF = `[Interface]
PrivateKey = yYYF82v2u8vPXOsOokPZiEOZG664yNpHuXcmaVNMKvg=
Address = 10.1.142.13/32
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = FI/C4wFN+0e31jVk8sFJwxyMu7Hvav4vbWptZ//pnIE=
AllowedIPs = 10.0.0.1/32, 0.0.0.0/0, ::/0
Endpoint = ir.vrt-server.org:11040
PersistentKeepalive = 10`;

test('isWireguardConf recognises the INI form, not a link or a sub blob', () => {
  assert.equal(isWireguardConf(WG_CONF), true);
  assert.equal(isWireguardConf('  \n[interface]\nPrivateKey = k\n[Peer]\nPublicKey = p\nEndpoint = h:1'), true);
  assert.equal(isWireguardConf('wireguard://k@h:51820'), false);
  assert.equal(isWireguardConf('vless://u@a.com:443'), false);
  assert.equal(isWireguardConf('[Interface]\nPrivateKey = k'), false, 'a [Peer] section is required');
});

test('parseWireguardConf reads every field the form takes', () => {
  const f = parseWireguardConf(WG_CONF);
  assert.equal(f.privateKey, 'yYYF82v2u8vPXOsOokPZiEOZG664yNpHuXcmaVNMKvg=');
  assert.equal(f.publicKey, 'FI/C4wFN+0e31jVk8sFJwxyMu7Hvav4vbWptZ//pnIE=');
  assert.equal(f.endpoint, 'ir.vrt-server.org:11040');
  assert.equal(f.address, '10.1.142.13/32');
  assert.equal(f.allowedIPs, '10.0.0.1/32, 0.0.0.0/0, ::/0');
  assert.equal(f.name, 'ir.vrt-server.org');
});

test('parseWireguardConf: keys are case-insensitive, comments and CRLF tolerated', () => {
  const f = parseWireguardConf('[interface]\r\n# a comment\r\nprivatekey=K\r\naddress=10.0.0.2/32\r\nMTU = 1380\r\n\r\n[peer]\r\npublickey=P\r\nendpoint=h.example:51820\r\npresharedkey=PSK\r\n');
  assert.equal(f.privateKey, 'K');
  assert.equal(f.publicKey, 'P');
  assert.equal(f.mtu, '1380');
  assert.equal(f.presharedKey, 'PSK');
  assert.equal(f.allowedIPs, '', 'absent AllowedIPs stays empty so the builder applies its default');
});

test('parseWireguardConf rejects a config that cannot connect', () => {
  assert.throws(() => parseWireguardConf('[Interface]\nPrivateKey = K\n[Peer]\nPublicKey = P'), /Endpoint/);
  assert.throws(() => parseWireguardConf('[Interface]\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = P\nEndpoint = h:1'), /PrivateKey/);
  assert.throws(() => parseWireguardConf('[Interface]\nPrivateKey = K\n[Peer]\nEndpoint = h:1'), /PublicKey/);
});

test('parseMany imports a pasted .conf as one server', () => {
  const { servers, errors } = parseMany(WG_CONF);
  assert.equal(errors.length, 0);
  assert.equal(servers.length, 1);
  const s = servers[0];
  assert.equal(s.protocol, 'wireguard');
  assert.equal(s.address, 'ir.vrt-server.org');
  assert.equal(s.port, 11040);
  assert.deepEqual(s.outbound.settings.address, ['10.1.142.13/32']);
  assert.deepEqual(s.outbound.settings.peers[0].allowedIPs, ['10.0.0.1/32', '0.0.0.0/0', '::/0']);
});

test('a wireguard server exports a real share link, not its raw text', () => {
  const s = parseMany(WG_CONF).servers[0];
  const link = buildShareLink(s);
  assert.match(link, /^wireguard:\/\//);
  const back = parseLink(link);
  assert.equal(back.address, 'ir.vrt-server.org');
  assert.equal(back.port, 11040);
  assert.equal(back.outbound.settings.secretKey, s.outbound.settings.secretKey);
  assert.equal(back.outbound.settings.peers[0].publicKey, s.outbound.settings.peers[0].publicKey);
  assert.deepEqual(back.outbound.settings.peers[0].allowedIPs, ['10.0.0.1/32', '0.0.0.0/0', '::/0']);
});

/* ----------------------------- parseMany ----------------------------- */

test('parseMany: newline separated links', () => {
  const { servers, errors } = parseMany([
    'vless://u1@a.example.com:443#A',
    'trojan://pw@b.example.com:443#B'
  ].join('\n'));
  assert.equal(servers.length, 2);
  assert.equal(errors.length, 0);
  assert.deepEqual(servers.map(s => s.name), ['A', 'B']);
});

test('parseMany: base64 subscription blob', () => {
  const blob = b64('vless://u1@a.example.com:443#A\ntrojan://pw@b.example.com:443#B\n');
  const { servers } = parseMany(blob);
  assert.equal(servers.length, 2);
});

test('parseMany: skips junk lines and reports per-link failures', () => {
  const bad = 'vmess://' + b64('not json');
  const { servers, errors } = parseMany([
    'vless://u1@a.example.com:443#A',
    '# a comment line',
    '',
    bad
  ].join('\n'));
  assert.equal(servers.length, 1);
  assert.equal(errors.length, 1);
  assert.equal(errors[0].line, bad);
});

test('parseLink: unknown scheme throws', () => {
  assert.throws(() => parseLink('ftp://nope'), /Unsupported or invalid link/);
});

test('b64decode: tolerates url-safe alphabet and missing padding', () => {
  assert.equal(b64decode(b64url('hello world?')), 'hello world?');
});

/* --------------------------- applyServerEdits --------------------------- */

test('applyServerEdits: address/port propagate into the vless outbound', () => {
  const s = parseLink('vless://uuid-a@old.example.com:443?type=ws&security=tls&host=old.example.com&path=%2Fw');
  const out = applyServerEdits(s, { name: 'Renamed', address: 'new.example.com', port: '8443', uuid: 'uuid-z' });

  assert.equal(out.name, 'Renamed');
  assert.equal(out.address, 'new.example.com');
  assert.equal(out.port, 8443);
  const vnext = out.outbound.settings.vnext[0];
  assert.equal(vnext.address, 'new.example.com');
  assert.equal(vnext.port, 8443);
  assert.equal(vnext.users[0].id, 'uuid-z');
  // untouched transport fields are left alone
  assert.deepEqual(out.outbound.streamSettings.wsSettings, { path: '/w', headers: { Host: 'old.example.com' } });
});

test('applyServerEdits: does not mutate the original server', () => {
  const s = parseLink('trojan://pw@b.example.com:443');
  const before = JSON.stringify(s);
  applyServerEdits(s, { address: 'other.example.com', password: 'new' });
  assert.equal(JSON.stringify(s), before);
});

test('applyServerEdits: rebuilding the stream preserves fields the form omits', () => {
  const s = parseLink('vless://u@a.example.com:443?security=reality&pbk=PBK&sid=SID&spx=%2Fspider');
  // The edit form re-sends every transport field it exposes (see app.js), but it
  // has NO spiderX input — spiderX must survive the rebuild on its own.
  const out = applyServerEdits(s, { security: 'reality', sni: 'new.sni.com', pbk: 'PBK', sid: 'SID' });
  assert.deepEqual(out.outbound.streamSettings.realitySettings, {
    serverName: 'new.sni.com', fingerprint: 'chrome', publicKey: 'PBK', shortId: 'SID', spiderX: '/spider'
  });
});

test('applyServerEdits: kcp seed/headerType and grpc multiMode survive a rebuild', () => {
  // the form exposes neither kcp seed nor headerType — both are passthroughs
  const kcp = applyServerEdits(parseLink('vless://u@k.example.com:443?type=kcp&headerType=srtp&seed=SEED'), { sni: 'x.com' });
  assert.deepEqual(kcp.outbound.streamSettings.kcpSettings, { header: { type: 'srtp' }, seed: 'SEED' });

  // grpc multiMode has no form field either; serviceName is re-sent by the form
  const grpc = applyServerEdits(
    parseLink('vless://u@g.example.com:443?type=grpc&serviceName=svc&mode=multi'),
    { sni: 'x.com', serviceName: 'svc' }
  );
  assert.deepEqual(grpc.outbound.streamSettings.grpcSettings, { serviceName: 'svc', multiMode: true });
});

test('applyServerEdits: wireguard peer/interface fields', () => {
  const s = parseLink('wireguard://K@wg.example.com:51820?publickey=P&address=10.0.0.5%2F32');
  const out = applyServerEdits(s, {
    address: 'wg2.example.com', port: '51821',
    publicKey: 'P2', allowedIPs: '10.0.0.0/8, 192.168.0.0/16', mtu: '1280', reserved: '9,8,7'
  });
  assert.equal(out.outbound.settings.peers[0].endpoint, 'wg2.example.com:51821');
  assert.equal(out.outbound.settings.peers[0].publicKey, 'P2');
  assert.deepEqual(out.outbound.settings.peers[0].allowedIPs, ['10.0.0.0/8', '192.168.0.0/16']);
  assert.equal(out.outbound.settings.mtu, 1280);
  assert.deepEqual(out.outbound.settings.reserved, [9, 8, 7]);
});

test('applyServerEdits: anti-DPI markers set and clear', () => {
  const s = parseLink('vless://u@a.example.com:443');

  const on = applyServerEdits(s, { fragment: 'tlshello,10-20,5', noise: 'faketls' });
  assert.equal(on.outbound._fragment, 'tlshello,10-20,5');
  assert.equal(on.outbound._noise, 'faketls');

  const off = applyServerEdits(on, { fragment: '', noise: '  ' });
  assert.equal('_fragment' in off.outbound, false);
  assert.equal('_noise' in off.outbound, false);
});

test('applyServerEdits: per-config engine set and cleared', () => {
  const s = parseLink('vless://u@a.example.com:443');

  const singbox = applyServerEdits(s, { engine: 'sing-box' });
  assert.equal(singbox.engine, 'sing-box');

  // 'xray' is the default core — it is stored as "no engine", not as a value
  assert.equal('engine' in applyServerEdits(singbox, { engine: 'xray' }), false);
  assert.equal('engine' in applyServerEdits(singbox, { engine: '' }), false);
});

test('applyServerEdits: socks credentials are dropped when both fields are blank', () => {
  const s = parseLink('socks://alice:pw@p.example.com:1080');
  const cleared = applyServerEdits(s, { username: '', password: '' });
  assert.equal(cleared.outbound.settings.servers[0].users, undefined);

  const kept = applyServerEdits(s, { username: 'bob', password: '' });
  assert.deepEqual(kept.outbound.settings.servers[0].users, [{ user: 'bob', pass: '' }]);
});

/* --------------------------- buildStreamSettings --------------------------- */

test('buildStreamSettings: allowInsecure accepts "1" and "true"', () => {
  assert.equal(buildStreamSettings({ security: 'tls', allowInsecure: '1' }).tlsSettings.allowInsecure, true);
  assert.equal(buildStreamSettings({ security: 'tls', allowInsecure: 'true' }).tlsSettings.allowInsecure, true);
  assert.equal(buildStreamSettings({ security: 'tls', allowInsecure: '0' }).tlsSettings.allowInsecure, false);
});

test('buildStreamSettings: tls serverName falls back to host when sni is absent', () => {
  assert.equal(buildStreamSettings({ security: 'tls', host: 'h.example.com' }).tlsSettings.serverName, 'h.example.com');
});

/* --------------------------- finalmask / cs / fp --------------------------- */

const FM = '{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","lengths":["3-5","6-8"],"delays":["10-20"],"maxSplit":"3-6"}}]}';

test('vless: fm= is stored verbatim — no key rewriting', () => {
  const s = parseLink(`vless://u@a.example.com:443?security=tls&fm=${encodeURIComponent(FM)}#FM`);
  const fm = s.outbound.streamSettings.finalmask;
  assert.deepEqual(fm, JSON.parse(FM), 'the core takes plural lengths/delays; rewriting them breaks it');
});

test('vless: cs= and fp=unsafe are read into tlsSettings', () => {
  const s = parseLink('vless://u@a.example.com:443?security=tls&fp=unsafe&cs=TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256');
  assert.equal(s.outbound.streamSettings.tlsSettings.fingerprint, 'unsafe');
  assert.equal(s.outbound.streamSettings.tlsSettings.cipherSuites, 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256');
});

test('the legacy long parameter names still import', () => {
  const s = parseLink(`vless://u@a.example.com:443?security=tls&finalMask=${encodeURIComponent(FM)}&cipherSuites=X`);
  assert.deepEqual(s.outbound.streamSettings.finalmask, JSON.parse(FM));
  assert.equal(s.outbound.streamSettings.tlsSettings.cipherSuites, 'X');
});

test('invalid fm JSON is ignored rather than poisoning the config', () => {
  const s = parseLink('vless://u@a.example.com:443?security=tls&fm=%7Bnot-json');
  assert.equal(s.outbound.streamSettings.finalmask, undefined);
});

test('share links export fm= and cs=, never the legacy names', () => {
  const s = parseLink(`vless://u@a.example.com:443?security=tls&sni=a.com&fm=${encodeURIComponent(FM)}&cs=SUITE&fp=unsafe#N`);
  const link = buildShareLink(s);
  assert.match(link, /[?&]fm=/);
  assert.match(link, /[?&]cs=SUITE/);
  assert.match(link, /[?&]fp=unsafe/);
  assert.equal(/finalMask=|cipherSuites=/.test(link), false);
  assert.deepEqual(parseLink(link).outbound.streamSettings.finalmask, JSON.parse(FM));
});

test('vmess carries fm and cs through its base64 payload', () => {
  const link = 'vmess://' + Buffer.from(JSON.stringify({
    v: '2', ps: 'VM', add: 'vm.example.com', port: '443', id: 'uuid', net: 'ws',
    tls: 'tls', path: '/p', fm: FM, cs: 'SUITE', fp: 'unsafe'
  }), 'utf8').toString('base64');
  const s = parseLink(link);
  assert.deepEqual(s.outbound.streamSettings.finalmask, JSON.parse(FM));
  assert.equal(s.outbound.streamSettings.tlsSettings.cipherSuites, 'SUITE');
  const back = parseLink(buildShareLink(s));
  assert.deepEqual(back.outbound.streamSettings.finalmask, JSON.parse(FM));
});

test('applyServerEdits sets and clears finalMask and cipherSuites', () => {
  const s = parseLink('vless://u@a.example.com:443?security=tls&sni=a.com');
  const on = applyServerEdits(s, { security: 'tls', sni: 'a.com', finalMask: FM, cipherSuites: 'SUITE', fp: 'unsafe' });
  assert.deepEqual(on.outbound.streamSettings.finalmask, JSON.parse(FM));
  assert.equal(on.outbound.streamSettings.tlsSettings.cipherSuites, 'SUITE');
  const off = applyServerEdits(on, { security: 'tls', sni: 'a.com', finalMask: '', cipherSuites: '', fp: 'chrome' });
  assert.equal(off.outbound.streamSettings.finalmask, undefined);
  assert.equal(off.outbound.streamSettings.tlsSettings.cipherSuites, undefined);
});

test('the dead fakeSni marker is gone', () => {
  const s = parseLink('vless://u@a.example.com:443?security=tls&fakeSni=www.google.com');
  assert.equal(s.outbound._fakesni, undefined, 'freedom noises are UDP-only — this never worked on TLS');
  assert.equal(/fakeSni/.test(buildShareLink(s)), false);
});
