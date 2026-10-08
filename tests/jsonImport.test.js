'use strict';
/**
 * JSON configs as servers (spec: docs/superpowers/specs/2026-10-08-json-configs-design.md).
 *
 * A panel answers this app's User-Agent with an array of complete Xray configs;
 * v2rayN-style clients and sing-box get JSON too. Each Xray config becomes a
 * server whose main outbound is what the app dials everywhere, with the
 * outbounds it dials THROUGH (a fragment freedom, a chain's hops) kept beside
 * it; a sing-box config becomes ordinary servers, as if imported from their
 * links. The fixtures are shared with the Android JVM tests.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const J = require('../src/main/jsonImport');
const { parseMany, parseLink, applyServerEdits, editFields, buildShareLink } = require('../src/main/parser');

const fixture = (f) => fs.readFileSync(path.join(__dirname, 'fixtures/json', f), 'utf8');
const FIXTURES = ['xray-subscription.json', 'xray-fragment.json', 'xray-chain.json', 'xray-balancer.json', 'xray-wireguard.json', 'singbox.json'];
/** A record without its random id, for comparing two imports of the same text. */
const noId = (s) => Object.assign({}, s, { id: null });

/* ------------------------------ Xray JSON ------------------------------ */

test('a JSON subscription (an array of full Xray configs): five servers, the info rows are not servers and not errors', () => {
  const r = J.importJson(fixture('xray-subscription.json'));
  assert.deepEqual(r.errors, []);
  assert.deepEqual(r.servers.map((s) => s.name), ['🇩🇪 DE-1', '🇩🇪 DE-2', '🇳🇱 NL-1', '🇫🇮 FI-1', '🇺🇸 US-1']);
  for (const [i, s] of r.servers.entries()) {
    assert.equal(s.protocol, 'vless');
    assert.equal(s.outbound.protocol, 'vless');
    assert.equal(s.outbound.streamSettings.network, 'ws');
    assert.equal(s.outbound.streamSettings.security, 'tls');
    assert.equal(s.outbound.tag, undefined, 'the main outbound is stored without its tag');
    assert.equal(s.address, `edge${i + 1}.example.com`);
    assert.equal(s.port, 443);
    assert.equal(s.source, 'json');
    assert.equal(s.jsonMode, 'full');
    assert.deepEqual(s.extraOutbounds, []);
    assert.match(s.id, /^[0-9a-f]{16}$/);
  }
  // the record's `json` is that one config, `raw` its minified text, remarks included
  const cfg = JSON.parse(fixture('xray-subscription.json'))[2];
  assert.deepEqual(r.servers[0].json, cfg);
  assert.equal(r.servers[0].raw, JSON.stringify(cfg));
  assert.deepEqual(r.servers[0].jsonInfo, {
    rules: [{ match: 'geosite:private', to: 'direct' }, { match: 'geoip:ir', to: 'direct' }, { match: '*', to: 'proxy' }],
    dns: false, balancers: 0, observatory: false
  });
});

test('the same subscription base64-encoded gives the same five servers', () => {
  const text = fixture('xray-subscription.json');
  const plain = J.importJson(text);
  const b64 = J.importJson(Buffer.from(text, 'utf8').toString('base64'));
  assert.deepEqual(b64.errors, []);
  assert.deepEqual(b64.servers.map(noId), plain.servers.map(noId));
  // url-safe, unpadded, wrapped in lines — the shapes a subscription body comes in
  const wrapped = Buffer.from(text, 'utf8').toString('base64url').replace(/(.{76})/g, '$1\n');
  assert.deepEqual(J.importJson(wrapped).servers.map(noId), plain.servers.map(noId));
});

test('a fragment helper through dialerProxy is kept verbatim beside the main outbound; jsonInfo says what full mode does not use', () => {
  const r = J.importJson(fixture('xray-fragment.json'));
  assert.deepEqual(r.errors, []);
  assert.equal(r.servers.length, 1);
  const [s] = r.servers;
  const cfg = JSON.parse(fixture('xray-fragment.json'));
  assert.equal(s.name, '🇩🇪 frag');
  assert.deepEqual(s.extraOutbounds, [cfg.outbounds[1]]);
  assert.equal(s.extraOutbounds[0].tag, 'fragment');
  assert.equal(s.outbound.streamSettings.sockopt.dialerProxy, 'fragment');
  assert.equal(s.jsonInfo.rules.length, 3);
  assert.equal(s.jsonInfo.dns, true);
  assert.equal(s.jsonInfo.balancers, 0);
  assert.equal(s.jsonInfo.observatory, false);
});

test('a two-hop chain through proxySettings: the main outbound keeps its mux and proxySettings, the hops follow in order', () => {
  const r = J.importJson(fixture('xray-chain.json'));
  assert.deepEqual(r.errors, []);
  assert.equal(r.servers.length, 1);
  const [s] = r.servers;
  const cfg = JSON.parse(fixture('xray-chain.json'))[0];
  const main = Object.assign({}, cfg.outbounds[0]);
  delete main.tag;
  assert.deepEqual(s.outbound, main);
  assert.equal(s.outbound.protocol, 'vless');
  assert.equal(s.outbound.streamSettings.security, 'reality');
  assert.deepEqual(s.outbound.mux, { enabled: true, concurrency: 8 });
  assert.deepEqual(s.outbound.proxySettings, { tag: 'hop1' });
  assert.deepEqual(s.extraOutbounds.map((o) => o.tag), ['hop1', 'frag']);
  assert.equal(s.address, 'exit.example.com');
  assert.equal(J.mainOutboundTag(cfg), 'proxy');
  assert.deepEqual(J.helperClosure(cfg, 'proxy').map((o) => o.tag), ['hop1', 'frag']);
});

test('a balancer: one server per outbound its selector matches, named <remarks> · <tag>', () => {
  const r = J.importJson(fixture('xray-balancer.json'));
  assert.deepEqual(r.errors, []);
  assert.deepEqual(r.servers.map((s) => [s.name, s.protocol]), [['⚖ auto · proxy-1', 'vless'], ['⚖ auto · proxy-2', 'trojan']]);
  assert.deepEqual(r.servers.map((s) => s.address), ['edge1.example.com', 'edge2.example.com']);
  for (const s of r.servers) {
    assert.equal(s.jsonInfo.balancers, 1);
    assert.equal(s.jsonInfo.observatory, true);
    assert.deepEqual(s.jsonInfo.rules, [{ match: 'geoip:private', to: 'direct' }, { match: '*', to: 'balancer:auto' }]);
  }
  assert.deepEqual(J.mainOutboundTag(JSON.parse(fixture('xray-balancer.json'))), { balancer: ['proxy-1', 'proxy-2'] });
});

test('a single config object with no routing: its one proxy outbound — a WireGuard, read from the peer endpoint', () => {
  const r = J.importJson(fixture('xray-wireguard.json'));
  assert.deepEqual(r.errors, []);
  assert.equal(r.servers.length, 1);
  const [s] = r.servers;
  assert.deepEqual([s.name, s.protocol, s.address, s.port], ['🛡 wg', 'wireguard', 'wg.example.com', 51820]);
  assert.equal(s.outbound.protocol, 'wireguard');
  assert.deepEqual(s.jsonInfo, { rules: [], dns: false, balancers: 0, observatory: false });
});

test('the main outbound: the catch-all rule, else the one tagged proxy, else the first proxy protocol; none → no server', () => {
  const vless = (tag, address) => ({ tag, protocol: 'vless', settings: { vnext: [{ address, port: 443, users: [{ id: 'u', encryption: 'none' }] }] } });
  const catchAll = { outbounds: [vless('a', 'a.example'), vless('b', 'b.example'), { tag: 'direct', protocol: 'freedom' }],
    routing: { rules: [{ type: 'field', domain: ['x.com'], outboundTag: 'a' }, { type: 'field', outboundTag: 'b' }] } };
  assert.equal(J.mainOutboundTag(catchAll), 'b');
  const portRule = { outbounds: catchAll.outbounds, routing: { rules: [{ type: 'field', port: '443', outboundTag: 'b' }] } };
  assert.equal(J.mainOutboundTag(portRule), 'a', 'a rule with a matcher is no catch-all: the first proxy protocol');
  const tagged = { outbounds: [vless('x', 'x.example'), vless('proxy', 'p.example')] };
  assert.equal(J.mainOutboundTag(tagged), 'proxy');
  const toDirect = { outbounds: [vless('x', 'x.example'), { tag: 'direct', protocol: 'freedom' }], routing: { rules: [{ type: 'field', outboundTag: 'direct' }] } };
  assert.equal(J.mainOutboundTag(toDirect), 'x', 'a catch-all to a non-proxy outbound falls through');
  assert.equal(J.mainOutboundTag({ outbounds: [{ tag: 'direct', protocol: 'freedom' }, { tag: 'b', protocol: 'blackhole' }] }), null);
  assert.deepEqual(J.serversFromXray({ remarks: 'info', outbounds: [{ tag: 'direct', protocol: 'freedom' }] }), []);
  // name: remarks, else ps, else address:port
  assert.equal(J.serversFromXray({ ps: 'from ps', outbounds: [vless('proxy', 'p.example')] })[0].name, 'from ps');
  assert.equal(J.serversFromXray({ outbounds: [vless('proxy', 'p.example')] })[0].name, 'p.example:443');
});

test('helperClosure follows dialerProxy and proxySettings.tag recursively, each helper once, never the main outbound itself', () => {
  const cfg = { outbounds: [
    { tag: 'proxy', protocol: 'vless', settings: {}, streamSettings: { sockopt: { dialerProxy: 'a' } } },
    { tag: 'a', protocol: 'trojan', settings: {}, proxySettings: { tag: 'b' } },
    { tag: 'b', protocol: 'freedom', streamSettings: { sockopt: { dialerProxy: 'a' } } },
    { tag: 'unused', protocol: 'freedom' }
  ] };
  assert.deepEqual(J.helperClosure(cfg, 'proxy').map((o) => o.tag), ['a', 'b']);
  assert.deepEqual(J.helperClosure(cfg, 'unused'), []);
});

/* ------------------------------ sing-box JSON ------------------------------ */

test('a sing-box config: one ordinary server per supported outbound, the detour in the name, tuic reported by name', () => {
  const r = J.importJson(fixture('singbox.json'));
  assert.deepEqual(r.errors, [{ line: 'tuic', error: 'unsupported protocol: tuic' }]);
  assert.deepEqual(r.servers.map((s) => [s.name, s.protocol]), [
    ['vless-reality', 'vless'], ['vmess-ws', 'vmess'], ['trojan-grpc', 'trojan'], ['ss', 'shadowsocks'], ['hy2', 'hysteria2'],
    ['wg', 'wireguard'], ['socks-up', 'socks'], ['http-up', 'http'], ['vless-detour (via trojan-grpc)', 'vless']
  ]);
  for (const s of r.servers) {
    assert.equal(s.source, undefined, 'an ordinary server, not a JSON one');
    assert.deepEqual(parseLink(s.raw).outbound, s.outbound, `${s.name}: raw is the link it was imported as`);
  }
  assert.deepEqual(J.serversFromSingbox(JSON.parse(fixture('singbox.json'))).errors, r.errors);
});

test('each sing-box server is what its share link, written by hand, parses to', () => {
  const r = J.importJson(fixture('singbox.json'));
  const by = (name) => r.servers.find((s) => s.name === name);
  const links = {
    'vless-reality': 'vless://00000000-0000-4000-8000-0000000000c1@r.example.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.example.net&fp=chrome&pbk=AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKK&sid=0a1b&type=tcp#vless-reality',
    'trojan-grpc': 'trojan://tpw@t.example.com:443?security=tls&sni=t.example.com&type=grpc&serviceName=tg#trojan-grpc',
    hy2: 'hysteria2://hpw@h.example.com:443/?sni=h.example.com&obfs=salamander&obfs-password=ob&mport=20000-30000&up=50&down=100#hy2',
    'vmess-ws': 'vmess://' + Buffer.from(JSON.stringify({ v: '2', ps: 'vmess-ws', add: 'v.example.com', port: '8443', id: '00000000-0000-4000-8000-0000000000c2', aid: '0', scy: 'auto', net: 'ws', path: '/vm', host: 'v.example.com', tls: 'tls', sni: 'v.example.com' })).toString('base64'),
    wg: 'wireguard://SECRETKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D@w.example.com:51820?publickey=PUBKEYBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB%3D&address=10.8.0.2%2F32&mtu=1280#wg',
    ss: 'ss://' + Buffer.from('chacha20-ietf-poly1305:spw').toString('base64') + '@s.example.com:8388#ss'
  };
  for (const [name, link] of Object.entries(links)) {
    const s = by(name);
    assert.ok(s, name);
    assert.deepEqual(s.outbound, parseLink(link).outbound, name);
    assert.deepEqual([s.address, s.port], [parseLink(link).address, parseLink(link).port], name);
  }
  assert.deepEqual(by('socks-up').outbound.settings.servers[0], { address: 'p.example.com', port: 1080, users: [{ user: 'u', pass: 'p' }] });
  assert.deepEqual(by('http-up').outbound.settings.servers[0], { address: 'p.example.com', port: 3128 });
});

test('sing-box: a TLS ECH config goes as the link’s ech (echConfigList); one only fetched by name has no link form and is left out, nothing else changed', () => {
  const list = 'AEX+DQBBAQAgACBhbm90aGVyLWtleS1mb3ItdGVzdGluZy0xMjM0NTY3OA==';
  const tls = (ech) => Object.assign({ enabled: true, server_name: 'e.example.com' }, ech ? { ech } : {});
  const vless = (ech) => ({ type: 'vless', tag: 'v', server: 'e.example.com', server_port: 443, uuid: 'u', tls: tls(ech) });
  const one = (o) => J.serversFromSingbox({ outbounds: [o] }).servers[0];
  const plain = one(vless(null));
  // the PEM block sing-box writes, as lines or as one string
  const pem = ['-----BEGIN ECH CONFIGS-----', list, '-----END ECH CONFIGS-----'];
  for (const config of [pem, pem.join('\n'), [list]]) {
    const s = one(vless({ enabled: true, config }));
    assert.equal(s.outbound.streamSettings.tlsSettings.echConfigList, list, JSON.stringify(config));
    const { echConfigList, ...rest } = s.outbound.streamSettings.tlsSettings;
    assert.deepEqual(rest, plain.outbound.streamSettings.tlsSettings, 'only the ECH list is added');
  }
  // fetched by name (query_server_name) or switched off: no link carries it
  assert.deepEqual(one(vless({ enabled: true, query_server_name: 'cloudflare-ech.com' })).outbound, plain.outbound);
  assert.deepEqual(one(vless({ enabled: false, config: pem })).outbound, plain.outbound);
  // Hysteria2 and trojan the same way
  const hy = one({ type: 'hysteria2', tag: 'h', server: 'h.example.com', server_port: 443, password: 'p', tls: tls({ enabled: true, config: pem }) });
  assert.equal(hy.outbound.streamSettings.tlsSettings.echConfigList, list);
  const tr = one({ type: 'trojan', tag: 't', server: 't.example.com', server_port: 443, password: 'p', tls: tls({ enabled: true, config: pem }) });
  assert.equal(tr.outbound.streamSettings.tlsSettings.echConfigList, list);
});

test('sing-box: selector, urltest, direct, block and dns are skipped silently; an unsupported transport is an error by name', () => {
  const r = J.serversFromSingbox({ outbounds: [
    { type: 'selector', tag: 's', outbounds: [] }, { type: 'urltest', tag: 'u' }, { type: 'direct', tag: 'd' }, { type: 'block', tag: 'b' }, { type: 'dns', tag: 'x' },
    { type: 'vless', tag: 'q', server: 'q.example', server_port: 443, uuid: 'u', tls: { enabled: true, server_name: 'q.example' }, transport: { type: 'quic' } },
    { type: 'anytls', tag: 'any', server: 'a.example', server_port: 443 }
  ] });
  assert.deepEqual(r.servers, []);
  assert.deepEqual(r.errors.map((e) => e.line), ['q', 'any']);
  assert.match(r.errors[0].error, /quic/);
  assert.equal(r.errors[1].error, 'unsupported protocol: anytls');
});

/* ------------------------------ detection ------------------------------ */

test('Clash YAML is refused with the reason; a link, a WireGuard .conf and plain text are not JSON at all', () => {
  assert.deepEqual(J.importJson('proxies:\n  - name: a'), { servers: [], errors: [{ line: 'proxies:', error: 'Clash YAML is not supported — use the subscription link' }] });
  assert.equal(J.importJson('vless://u@a.example.com:443?security=tls#A'), null);
  assert.equal(J.importJson('[Interface]\nPrivateKey = k\n[Peer]\nPublicKey = p\nEndpoint = e.example:51820'), null);
  assert.equal(J.importJson('hello world'), null);
  assert.equal(J.importJson(''), null);
  assert.equal(J.looksLikeJson('  {"outbounds": []}'), true);
  assert.equal(J.looksLikeJson('[{"outbounds": []}]'), true);
  assert.equal(J.looksLikeJson('[Interface]'), false);
  assert.equal(J.looksLikeJson('vless://x'), false);
});

test('broken or foreign JSON is an error, not a silence', () => {
  const bad = J.importJson('{"outbounds": [');
  assert.equal(bad.servers.length, 0);
  assert.match(bad.errors[0].error, /^invalid JSON/);
  const foreign = J.importJson('{"hello": 1}');
  assert.equal(foreign.servers.length, 0);
  assert.match(foreign.errors[0].error, /no outbounds/);
  assert.deepEqual(J.importJson('[]'), { servers: [], errors: [] });
});

/* ------------------------------ parseMany ------------------------------ */

test('parseMany reads every fixture exactly as importJson does', () => {
  for (const f of FIXTURES) {
    const text = fixture(f);
    const a = parseMany(text), b = J.importJson(text);
    assert.deepEqual(a.errors, b.errors, f);
    assert.deepEqual(a.servers.map(noId), b.servers.map(noId), f);
    assert.ok(a.servers.length > 0, f);
  }
});

test('parseMany of links is what it was: links, base64 links and a .conf never meet the JSON reader', () => {
  const links = [
    'vless://11111111-2222-3333-4444-555555555555@a.example:443?encryption=none&type=ws&host=h.example&path=%2Fws&security=tls#ws',
    'trojan://pw@t.example:443?security=tls&sni=t.example&type=grpc&serviceName=svc#tg',
    'tuic://x@y:1#t'
  ].join('\n');
  const r = parseMany(links);
  assert.deepEqual(r.servers.map((s) => s.name), ['ws', 'tg']);
  assert.deepEqual(r.errors, [{ line: 'tuic://x@y:1#t', error: 'unsupported protocol: tuic' }]);
  assert.deepEqual(parseMany(Buffer.from(links).toString('base64')).servers.map(noId), r.servers.map(noId));
  for (const s of r.servers) assert.equal(s.source, undefined);
});

/* ------------------------------ editing ------------------------------ */

test('an edit of a JSON server re-derives everything from the new config, and records what the user changed', () => {
  const [s] = J.importJson(fixture('xray-fragment.json')).servers;
  const cfg = JSON.parse(fixture('xray-fragment.json'));
  cfg.outbounds[0].settings.vnext[0].address = 'moved.example.com';
  cfg.outbounds[1].settings.fragment.packets = '1-3';
  cfg.routing.rules.pop();
  const out = applyServerEdits(s, { name: s.name, jsonMode: 'raw', json: JSON.stringify(cfg, null, 2) });
  assert.equal(out.id, s.id);
  assert.equal(out.address, 'moved.example.com');
  assert.equal(out.outbound.settings.vnext[0].address, 'moved.example.com');
  assert.equal(out.extraOutbounds[0].settings.fragment.packets, '1-3');
  assert.deepEqual(out.json, cfg);
  assert.equal(out.raw, s.raw, 'raw stays the provider’s text, as a link keeps its link: the next refresh finds it by raw first');
  assert.equal(out.jsonMode, 'raw');
  assert.equal(out.jsonInfo.rules.length, 2);
  assert.deepEqual(out._edited, ['json', 'jsonMode']);
  assert.equal(s.jsonMode, 'full', 'the input is not changed');
  // an object is taken as well as text; a rename is recorded; full again is the default, released
  const again = applyServerEdits(out, { name: 'mine', jsonMode: 'full', json: cfg });
  assert.equal(again.name, 'mine');
  assert.deepEqual(again._edited, ['json', 'name']);
  // a Save with nothing changed records nothing
  assert.equal(applyServerEdits(s, { name: s.name, jsonMode: 'full', json: s.json })._edited, undefined);
});

test('a Save with nothing changed — the edit view sends the object it parsed, keys in any order — leaves the record exactly as it was', () => {
  const [s] = J.importJson(fixture('xray-chain.json')).servers;
  const reorder = (v) => (Array.isArray(v) ? v.map(reorder)
    : (v && typeof v === 'object' ? Object.keys(v).reverse().reduce((o, k) => { o[k] = reorder(v[k]); return o; }, {}) : v));
  const shuffled = reorder(JSON.parse(JSON.stringify(s.json)));
  assert.notEqual(JSON.stringify(shuffled), JSON.stringify(s.json), 'the keys really are in another order');
  for (const json of [shuffled, JSON.stringify(shuffled), JSON.parse(editFields(s).json), editFields(s).json]) {
    assert.deepEqual(applyServerEdits(s, { name: s.name, jsonMode: 'full', json }), s);
  }
  // an edited server keeps what it had recorded
  const raw = applyServerEdits(s, { name: s.name, jsonMode: 'raw', json: shuffled });
  assert.deepEqual(raw._edited, ['jsonMode']);
  assert.equal(raw.raw, s.raw, 'the same config: raw is not re-derived');
});

test('an edit that breaks the config is refused with the reason, and the record is left as it was', () => {
  const [s] = J.importJson(fixture('xray-fragment.json')).servers;
  assert.throws(() => applyServerEdits(s, { json: '{"outbounds": [' }), /invalid JSON/);
  assert.throws(() => applyServerEdits(s, { json: { outbounds: [{ tag: 'direct', protocol: 'freedom' }] } }), /no proxy outbound/);
  assert.throws(() => applyServerEdits(s, { json: '[1, 2]' }), /one Xray config/);
  assert.equal(s.address, 'edge1.example.com');
});

test('a balancer member stays the same member across an edit', () => {
  const servers = J.importJson(fixture('xray-balancer.json')).servers;
  const cfg = JSON.parse(fixture('xray-balancer.json'));
  cfg.outbounds[1].settings.servers[0].password = 'changed';
  const out = applyServerEdits(servers[1], { json: cfg });
  assert.equal(out.protocol, 'trojan');
  assert.equal(out.outbound.settings.servers[0].password, 'changed');
});

test('editFields and the share link of a JSON server are its JSON', () => {
  const [s] = J.importJson(fixture('xray-chain.json')).servers;
  assert.equal(buildShareLink(s), JSON.stringify(s.json, null, 2));
  assert.deepEqual(editFields(s), { name: s.name, jsonMode: 'full', json: JSON.stringify(s.json, null, 2) });
});
