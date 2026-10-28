'use strict';
/**
 * The full server editor, the record's side (parser.js through serverFields.js):
 * every field written, read back and kept; a server made from scratch; what a
 * share link carries; an edit surviving a subscription refresh.
 * docs/superpowers/specs/2026-10-12-server-editor-design.md.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const SF = require('../src/renderer/serverFields');
const { parseLink, applyServerEdits, editFields, createServer, buildShareLink } = require('../src/main/parser');
const { importJson } = require('../src/main/jsonImport');
const { reconcileServers } = require('../src/main/subscription');

const UUID = '2c0f0d9a-6b3a-4f0e-9a1f-8c2b4d6e7a10';
const ENC = 'mlkem768x25519plus.native.0rtt.p7sTtcQlhzr21By6QMbFOEFjtHJa8dquXhK7pboK9GE';
const WG_PRIV = 'aGVsbG8gd29ybGQgdGhpcyBpcyBhIGtleSAzMiBi';
const WG_PUB = 'cGVlciBrZXkgdGhpcyBpcyBhIGtleSAzMiBieXRlcw==';
const PBK = 'Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw';
/** A WARP account's key pair as the record keeps it: the base64 of each DER (a new pair per call). */
function warpKeys() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return {
    priv: privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64'),
    pub: publicKey.export({ format: 'der', type: 'spki' }).toString('base64')
  };
}
const WARP = warpKeys();

/** The fields a new server of this protocol cannot be made without. */
function baseFields(protocol, network, security) {
  const f = { protocol, name: 'T', address: 'de.example.com', port: '443' };
  if (protocol === 'vless' || protocol === 'vmess' || protocol === 'tuic') f.uuid = UUID;
  if (['trojan', 'shadowsocks', 'hysteria2', 'tuic', 'anytls'].includes(protocol)) f.password = 'secret-1';
  if (protocol === 'wireguard') Object.assign(f, { privateKey: WG_PRIV, publicKey: WG_PUB });
  // MASQUE needs nothing more: its user and password are optional (a WARP account: serverFor)
  if (SF.hasTransport(protocol)) {
    f.network = network || 'ws';
    f.security = security || 'none';
    if (f.security === 'reality') Object.assign(f, { sni: 'www.microsoft.com', pbk: PBK, sid: 'ab12' });
    if (f.security === 'tls') f.sni = 'de.example.com';
    if (f.network !== 'tcp' && f.network !== 'kcp') f.path = '/p';
  }
  return f;
}
/** A server where `field` applies. */
function serverFor(field) {
  const w = field.when || {};
  const protocol = (w.protocols || ['vless'])[0];
  const network = (w.networks || ['ws'])[0];
  const sec = (w.securities || [protocol === 'hysteria2' ? 'tls' : 'tls'])[0];
  const f = baseFields(protocol, network, SF.securitiesOf(protocol).includes(sec) ? sec : SF.securitiesOf(protocol)[0]);
  // a WARP account's fields are all-or-none: they are edited on a server that has them all
  if (field.group === 'warp') Object.assign(f, { warpPrivateKey: WARP.priv, warpPublicKey: WARP.pub, warpAddress: '172.16.0.2/32, 2606:4700:110:8a36::2/128' });
  return createServer(f);
}
/** A value the form could hold for this field, different from what a new server has. */
function sample(field) {
  // what only a real key, an address, a path or a header can be
  if (field.id === 'warpPrivateKey') return warpKeys().priv;
  if (field.id === 'warpPublicKey') return warpKeys().pub;
  if (field.id === 'warpAddress') return '172.16.0.9/32, 2606:4700:110:8f00::9/128';
  if (field.id === 'remoteDNS') return '9.9.9.9, 149.112.112.112';
  if (field.id === 'masquePath') return '/irnf-masquePath';
  if (field.id === 'tuicHeartbeat') return '15s';   // a duration, or sing-box refuses the config (parser.checkSingboxOnly)
  switch (field.kind) {
    case 'number': return '25';
    case 'range': return '16-32';
    case 'switch': return true;
    case 'json': return field.id === 'httpHeaders' || field.id === 'masqueHeaders' ? '{"User-Agent":"irnf-test"}' : '{"address":"dl.example.com","port":443}';
    case 'list': return 'X25519MLKEM768, X25519';
    case 'encryption': return ENC;
    case 'select': return field.options.find((o) => o && o !== 'none' && o !== 'auto' && o !== SF.SS_METHODS[0]) || field.options[1];
    default: return 'irnf-' + field.id;
  }
}

test('every path field: written by an edit, read back by the form, kept by a Simple-view edit that does not carry it', () => {
  for (const field of SF.PATH_FIELDS) {
    const s = serverFor(field);
    assert.ok(SF.fieldApplies(field, SF.contextOf(s)), field.id + ' applies to its sample server');
    const value = sample(field);
    const edited = applyServerEdits(s, { [field.id]: value });
    const shown = editFields(edited)[field.id];
    assert.equal(SF.toForm(field, SF.fromForm(field, value)), shown, field.id + ' read back');
    // a Simple-view save: its own fields as they were, a new name — the Pro value stays
    const simple = editFields(edited);
    for (const pf of SF.PATH_FIELDS) delete simple[pf.id];
    const renamed = applyServerEdits(edited, Object.assign(simple, { name: 'renamed' }));
    assert.equal(renamed.name, 'renamed');
    assert.deepEqual(SF.getPath(renamed, field.path), SF.getPath(edited, field.path), field.id + ' kept');
  }
});

test('an edit records the Pro fields it changed in _edited, and a field sent back unchanged is not an edit', () => {
  const s = createServer(baseFields('vless', 'ws', 'tls'));
  const a = applyServerEdits(s, { encryption: ENC, wsHeartbeat: '30' });
  assert.deepEqual([...(a._edited || [])].sort(), ['encryption', 'wsHeartbeat']);
  const b = applyServerEdits(a, editFields(a));
  assert.equal(JSON.stringify(b.outbound), JSON.stringify(a.outbound), 'everything sent back as shown changes nothing');
});

test('a transport change drops the old transport’s fields and keeps the socket options', () => {
  const s = applyServerEdits(createServer(baseFields('vless', 'ws', 'tls')), { wsHeartbeat: '30', tcpFastOpen: true, tcpCongestion: 'bbr' });
  const g = applyServerEdits(s, { network: 'grpc', path: 'svc', grpcIdleTimeout: '60', grpcMode: 'multi' });
  const st = g.outbound.streamSettings;
  assert.equal(st.network, 'grpc');
  assert.equal(st.wsSettings, undefined);
  assert.equal(st.grpcSettings.idle_timeout, 60);
  assert.equal(st.grpcSettings.multiMode, true);
  assert.deepEqual(st.sockopt, { tcpFastOpen: true, tcpCongestion: 'bbr' });
  assert.equal(editFields(g).wsHeartbeat, undefined, 'not a field of a gRPC server');
});

test('the transport fields the parser builds from: TCP’s HTTP header on and off, XHTTP mode, mKCP header and seed, REALITY’s spiderX', () => {
  const t = applyServerEdits(createServer(baseFields('vless', 'tcp', 'none')), { headerType: 'http', host: 'obfs.example', path: '/x' });
  assert.equal(t.outbound.streamSettings.tcpSettings.header.type, 'http');
  assert.equal(editFields(t).headerType, 'http');
  const off = applyServerEdits(t, { headerType: 'none' });
  assert.equal(off.outbound.streamSettings.tcpSettings, undefined);
  const x = applyServerEdits(createServer(baseFields('vless', 'xhttp', 'tls')), { xhttpMode: 'stream-one', xPaddingBytes: '100-1000', xmuxMaxConcurrency: '16-32' });
  assert.equal(x.outbound.streamSettings.xhttpSettings.mode, 'stream-one');
  assert.deepEqual(x.outbound.streamSettings.xhttpSettings.extra, { xPaddingBytes: '100-1000', xmux: { maxConcurrency: '16-32' } });
  const k = applyServerEdits(createServer(baseFields('vless', 'kcp', 'none')), { kcpHeader: 'wechat-video', kcpSeed: 'sd', kcpTti: '20' });
  assert.deepEqual(k.outbound.streamSettings.kcpSettings.header, { type: 'wechat-video' });
  assert.equal(k.outbound.streamSettings.kcpSettings.seed, 'sd');
  assert.equal(k.outbound.streamSettings.kcpSettings.tti, 20);
  const r = applyServerEdits(createServer(baseFields('vless', 'tcp', 'reality')), { spx: '/start' });
  assert.equal(r.outbound.streamSettings.realitySettings.spiderX, '/start');
});

test('createServer: every protocol, round-tripped through its own share link; what it cannot be made without, said', () => {
  for (const p of SF.PROTOCOLS) {
    // Shadowsocks travels plain here: over ws its link is a SIP003 plugin, whose Host is also its SNI
    const net = SF.hasTransport(p) && p !== 'shadowsocks' ? 'ws' : undefined;
    const sec = SF.securitiesOf(p).includes('tls') && p !== 'shadowsocks' ? 'tls' : undefined;
    const s = createServer(baseFields(p, net, sec));
    assert.equal(s.protocol, p);
    assert.equal(s.address, 'de.example.com');
    assert.equal(s.port, 443);
    assert.ok(s.id && s.raw, p + ' has an id and its link');
    // MASQUE has no link: its raw is the share JSON, which the JSON reader makes this server again
    const back = p === 'masque' ? importJson(s.raw).servers[0] : parseLink(s.raw);
    if (p === 'masque') assert.equal(back.source, undefined, 'an ordinary server, not a JSON one');
    const mine = editFields(s), theirs = editFields(back);
    for (const k of Object.keys(mine)) {
      const field = SF.FIELDS.find((x) => x.id === k);
      if (k === 'name' || (field && field.local)) continue;
      assert.equal(String(theirs[k] == null ? '' : theirs[k]), String(mine[k] == null ? '' : mine[k]), `${p}: ${k} through the link`);
    }
  }
  assert.throws(() => createServer({ protocol: 'vless', address: 'a.example', port: '443' }), /uuid is empty/);
  assert.throws(() => createServer({ protocol: 'vless', address: '', port: '443', uuid: UUID }), /address/);
  assert.throws(() => createServer({ protocol: 'vless', address: 'a.example', port: '70000', uuid: UUID }), /port/);
  assert.throws(() => createServer({ protocol: 'juicity', address: 'a.example', port: '443' }), /Unknown protocol/);
  // TUIC: a uuid (a real one: sing-box refuses anything else) and a password; AnyTLS: a password
  assert.throws(() => createServer({ protocol: 'tuic', address: 'a.example', port: '443', password: 'p' }), /uuid is empty/);
  assert.throws(() => createServer({ protocol: 'tuic', address: 'a.example', port: '443', uuid: UUID }), /password is empty/);
  assert.throws(() => createServer({ protocol: 'tuic', address: 'a.example', port: '443', uuid: 'not-one', password: 'p' }), /^Error: uuid: not a UUID/);
  assert.throws(() => createServer({ protocol: 'anytls', address: 'a.example', port: '443' }), /password is empty/);
});

test('a share link carries every field it can — VLESS Encryption and flow — and none marked "this device only"', () => {
  const s = applyServerEdits(createServer(baseFields('vless', 'tcp', 'reality')),
    { encryption: ENC, flow: 'xtls-rprx-vision', tcpFastOpen: true, mux: 'on', muxConcurrency: '4' });
  const link = buildShareLink(s);
  assert.match(link, new RegExp('encryption=' + ENC.replace(/\./g, '\\.')));
  assert.match(link, /flow=xtls-rprx-vision/);
  assert.doesNotMatch(link, /tcpFastOpen|mux|Concurrency/i);
  const back = parseLink(link);
  assert.equal(back.outbound.settings.vnext[0].users[0].encryption, ENC);
  assert.equal(back.outbound.streamSettings.sockopt, undefined);
  assert.equal(back.mux, undefined);
});

test('a subscription refresh keeps the Pro edits the user made, the provider’s values for the rest', () => {
  const link = 'vless://' + UUID + '@de.example.com:443?encryption=none&type=ws&path=%2Fw&host=h.example&security=tls&sni=h.example#DE';
  const old = applyServerEdits(parseLink(link), { encryption: ENC, wsHeartbeat: '30', tcpFastOpen: true, mux: 'off' });
  // the provider renames it (a traffic counter in the remark); the server is the same one
  const fresh = parseLink(link.replace('#DE', '#DE%20%7C%2011GB'));
  const [next] = reconcileServers([old], [fresh]);
  assert.equal(next.id, old.id);
  assert.equal(next.outbound.settings.vnext[0].users[0].encryption, ENC, 'the user’s Encryption');
  assert.equal(next.outbound.streamSettings.wsSettings.heartbeatPeriod, 30);
  assert.equal(next.outbound.streamSettings.sockopt.tcpFastOpen, true);
  assert.equal(next.mux, 'off');
  assert.equal(next.name, 'DE | 11GB', 'the provider’s new name');
});

test('Shadowsocks: the plugin becomes its transport; the Simple view’s values change nothing; the Pro view can set a transport', () => {
  const s = createServer(Object.assign(baseFields('shadowsocks'), { method: 'aes-256-gcm', network: undefined, security: undefined }));
  assert.equal(s.outbound.settings.servers[0].method, 'aes-256-gcm');
  const p = applyServerEdits(s, { plugin: 'obfs-local;obfs=http;obfs-host=bing.com' });
  assert.equal(p.outbound.streamSettings.tcpSettings.header.type, 'http');
  assert.equal(editFields(p).plugin, 'obfs-local;obfs=http;obfs-host=bing.com');
  const same = applyServerEdits(p, Object.assign(editFields(p), { name: 'x' }));
  assert.deepEqual(same.outbound.streamSettings, p.outbound.streamSettings);
  const ws = applyServerEdits(p, { plugin: editFields(p).plugin, network: 'ws', path: '/s', host: 'h.example', security: 'tls', sni: 'h.example' });
  assert.equal(ws.outbound.streamSettings.network, 'ws');
  assert.equal(editFields(ws).plugin, 'v2ray-plugin;mode=websocket;tls;host=h.example;path=/s;mux=0');
});

test('Hysteria2: hop interval and bandwidth from the form; a cleared bandwidth stays cleared', () => {
  const s = applyServerEdits(createServer(Object.assign(baseFields('hysteria2'), { mport: '20000-30000' })), { hopInterval: '45', up: '50 mbps', down: '200 mbps' });
  const fm = s.outbound.streamSettings.finalmask;
  assert.equal(fm.udp.find((m) => m.type === 'udphop').settings.interval, '45');
  assert.equal(fm.quicParams.brutalUp, '50 mbps');
  const cleared = applyServerEdits(s, { up: '', down: '' });
  assert.equal((cleared.outbound.streamSettings.finalmask || {}).quicParams, undefined);
});
