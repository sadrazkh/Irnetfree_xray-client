'use strict';
/**
 * TUIC and AnyTLS — sing-box's alone (neither Xray core has them): the link
 * and the record (parser.js), the sing-box outbound (singboxBuilder.js), the
 * core it runs on (engineChoice.js), the plans that cannot hold one and say so
 * (configBuilder.js), the latency test, the trust-on-first-use pin they never
 * get (certPin.js), the editor's rows (serverFields.js) and what a backup, a
 * subscription refresh and an address swap make of them. The real run — the
 * app's config against sing-box's own servers — is scripts/probe-tuic-anytls.js.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const SF = require('../src/renderer/serverFields');
const F = require('./fixtures');
const { parseLink, parseMany, buildShareLink, unreadLinkKeys, createServer, applyServerEdits, editFields } = require('../src/main/parser');
const { buildSingboxConfig, translateOutbound, UnsupportedEngineConfig } = require('../src/main/singboxBuilder');
const { chooseEngine, isSingboxOnly, singboxOnlyError } = require('../src/main/engineChoice');
const { buildConfig, buildTestConfig, buildMultiTestConfig } = require('../src/main/configBuilder');
const { latencyTest, testsAlone, udpOnly } = require('../src/main/latencyTest');
const { wantsPin, pinTargets } = require('../src/main/certPin');
const { groupRecord } = require('../src/main/groups');
const { withTarget } = require('../src/main/addressSwap');
const { serverIdentity } = require('../src/main/subscription');
const { importBundle } = require('../src/main/backup');

const U = '2c0f0d9a-6b3a-4f0e-9a1f-8c2b4d6e7a10';
const TUIC = `tuic://${U}:p%40ss:w@t.example.com:443?sni=s.example.com&alpn=h3&congestion_control=bbr&udp_relay_mode=quic&allow_insecure=1&reduce_rtt=1&heartbeat=15s&disable_sni=1#TU%20one`;
const ANYTLS = 'anytls://p%3Aw%40x@a.example.com:8443?sni=a.example.com&fp=firefox&alpn=h2,http/1.1&insecure=1#AT';
const R = (...p) => fs.readFileSync(path.join(__dirname, '..', ...p), 'utf8');
const sb = (link) => translateOutbound(parseLink(link), 'proxy');

/* ------------------------------ the link and the record ------------------------------ */

test('a TUIC link: the record in Xray’s shape, uuid:password split at the first colon, every knob in sing-box’s names', () => {
  const s = parseLink(TUIC);
  assert.deepEqual([s.protocol, s.name, s.address, s.port, s.raw], ['tuic', 'TU one', 't.example.com', 443, TUIC]);
  assert.deepEqual(s.outbound, {
    protocol: 'tuic',
    settings: { servers: [{ address: 't.example.com', port: 443, uuid: U, password: 'p@ss:w', congestionControl: 'bbr', udpRelayMode: 'quic', zeroRtt: true, heartbeat: '15s' }] },
    streamSettings: { network: 'udp', security: 'tls', tlsSettings: { serverName: 's.example.com', allowInsecure: true, alpn: ['h3'], disableSni: true } }
  });
  assert.equal(s.engine, undefined, 'no engine of its own: it is sing-box’s whatever a link says');
});

test('an AnyTLS link: the password is the whole userinfo, uTLS’s fingerprint (chrome when the link names none)', () => {
  const s = parseLink(ANYTLS);
  assert.deepEqual(s.outbound, {
    protocol: 'anytls',
    settings: { servers: [{ address: 'a.example.com', port: 8443, password: 'p:w@x' }] },
    streamSettings: { network: 'tcp', security: 'tls', tlsSettings: { serverName: 'a.example.com', allowInsecure: true, alpn: ['h2', 'http/1.1'], fingerprint: 'firefox' } }
  });
  assert.equal(parseLink('anytls://pw@1.2.3.4:443').outbound.streamSettings.tlsSettings.fingerprint, 'chrome');
  assert.equal(parseLink('anytls://pw@1.2.3.4:443').outbound.streamSettings.tlsSettings.serverName, '', 'an IP: no SNI of its own');
});

test('the edge forms: no password, an IPv6 host, a userinfo encoded whole, the other spellings of insecure and 0-RTT, a bare heartbeat, a scheme in capitals', () => {
  const noPw = parseLink(`tuic://${U}@[2001:db8::1]:8443#v6`);
  assert.deepEqual([noPw.address, noPw.port, noPw.outbound.settings.servers[0].password], ['2001:db8::1', 8443, '']);
  assert.equal(buildShareLink(noPw), `tuic://${U}@[2001:db8::1]:8443#v6`, 'no colon when there is no password');
  const whole = parseLink(`tuic://${encodeURIComponent(U + ':pa%ss:w')}@t.example.com:443`);
  assert.deepEqual([whole.outbound.settings.servers[0].uuid, whole.outbound.settings.servers[0].password], [U, 'pa%ss:w'], 'decoded once, then split');
  for (const k of ['insecure=1', 'allowInsecure=1', 'allow_insecure=true']) {
    assert.equal(parseLink(`tuic://${U}:p@t.example.com:443?${k}`).outbound.streamSettings.tlsSettings.allowInsecure, true, k);
    assert.equal(parseLink(`anytls://p@a.example.com:443?${k}`).outbound.streamSettings.tlsSettings.allowInsecure, true, k);
  }
  assert.equal(parseLink(`tuic://${U}:p@t.example.com:443?zero_rtt_handshake=1`).outbound.settings.servers[0].zeroRtt, true);
  const t = parseLink(`TUIC://${U}:p@t.example.com:443?congestion_control=NewReno&udp_relay_mode=bogus&heartbeat=20`).outbound.settings.servers[0];
  assert.deepEqual([t.congestionControl, t.udpRelayMode, t.heartbeat], ['new_reno', '', '20s']);
  assert.equal(parseLink(`tuic://${U}:p@t.example.com:443?heartbeat=soon`).outbound.settings.servers[0].heartbeat, '', 'no duration: left out, never handed to sing-box');
  assert.equal(parseLink('ANYTLS://pw@a.example.com:443').protocol, 'anytls');
  assert.equal(parseLink('anytls://@a.example.com:443').outbound.settings.servers[0].password, '');
  assert.throws(() => parseLink('tuic://not-a-uuid:p@t.example.com:443'), /TUIC: the uuid in the link is not a UUID/);
  assert.throws(() => parseLink('tuic://:p@t.example.com:443'), /TUIC: no uuid/);
  assert.throws(() => parseLink(`tuic://${U}:p@:443`), /no server address/);
});

test('the TLS extras every kind takes (tlsExtras): ECH, pcs, vcn and pcn read as vcn — never PattN’s Xray-only ECH outbound', () => {
  const pin = 'ab'.repeat(32);
  const tls = parseLink(`tuic://${U}:p@t.example.com:443?ech=cloudflare-ech.com%2Budp%3A%2F%2F1.1.1.1&pcs=${pin}&pcn=real.example&echOutbound=%7B%22protocol%22%3A%22direct%22%7D`).outbound.streamSettings.tlsSettings;
  assert.deepEqual([tls.echConfigList, tls.pinnedPeerCertSha256, tls.verifyPeerCertByName, tls.echOutbound], ['cloudflare-ech.com+udp://1.1.1.1', pin, 'real.example', undefined]);
});

test('share links round-trip: the link a record writes parses back to the very same record', () => {
  for (const link of [TUIC, ANYTLS, `tuic://${U}:pw@[2001:db8::1]:8443`, 'anytls://pw@1.2.3.4:443',
    `tuic://${U}:pw@t.example.com:443?pcs=${'cd'.repeat(32)}&vcn=v.example&ech=AEX%2BDQ`, 'anytls://p%2Bw@a.example.com:443?fp=safari&ech=AEX%2BDQ']) {
    const s = parseLink(link);
    const back = buildShareLink(s);
    assert.deepEqual(parseLink(back).outbound, s.outbound, link + ' → ' + back);
    assert.deepEqual(unreadLinkKeys(back), [], back + ': every key it writes is one the parser reads');
  }
  assert.match(buildShareLink(parseLink(TUIC)), /^tuic:\/\/2c0f0d9a-[^@]+:p%40ss%3Aw@t\.example\.com:443\?sni=s\.example\.com&alpn=h3&congestion_control=bbr&udp_relay_mode=quic&reduce_rtt=1&heartbeat=15s&allow_insecure=1&disable_sni=1#TU%20one$/);
  assert.equal(buildShareLink(parseLink(ANYTLS)), 'anytls://p%3Aw%40x@a.example.com:8443?sni=a.example.com&fp=firefox&alpn=h2%2Chttp%2F1.1&insecure=1#AT');
});

test('unreadLinkKeys knows every key TUIC and AnyTLS links are read for, and names the rest', () => {
  assert.deepEqual(unreadLinkKeys(TUIC), []);
  assert.deepEqual(unreadLinkKeys(ANYTLS), []);
  assert.deepEqual(unreadLinkKeys(`tuic://${U}:p@t.example.com:443?zero_rtt_handshake=1&insecure=1&peer=x&udp_over_stream=1#t`), ['peer', 'udp_over_stream']);
  assert.deepEqual(unreadLinkKeys('anytls://p@a.example.com:443?serverName=a&fingerprint=chrome&idleSessionTimeout=30#a'), ['idleSessionTimeout']);
  // a subscription of both imports them, and counts what it did not read
  const r = parseMany([TUIC, ANYTLS, 'anytls://p@b.example.com:443?foo=1#b'].join('\n'));
  assert.deepEqual(r.servers.map((s) => s.protocol), ['tuic', 'anytls', 'anytls']);
  assert.deepEqual(r.errors, []);
  assert.deepEqual(r.unread, { foo: 1 });
});

/* ------------------------------ sing-box ------------------------------ */

test('sing-box’s TUIC outbound: uuid, password, the knobs set, QUIC’s TLS with no uTLS, h3 when the link names no ALPN', () => {
  assert.deepEqual(sb(TUIC), {
    type: 'tuic', tag: 'proxy', server: 't.example.com', server_port: 443, uuid: U, password: 'p@ss:w',
    congestion_control: 'bbr', udp_relay_mode: 'quic', zero_rtt_handshake: true, heartbeat: '15s',
    tls: { enabled: true, server_name: 's.example.com', insecure: true, alpn: ['h3'], disable_sni: true }
  });
  assert.deepEqual(sb(`tuic://${U}:pw@t.example.com:443`), {
    type: 'tuic', tag: 'proxy', server: 't.example.com', server_port: 443, uuid: U, password: 'pw',
    tls: { enabled: true, server_name: 't.example.com', alpn: ['h3'] }
  }, 'sing-box’s defaults where the record says none');
});

test('sing-box’s AnyTLS outbound: the password, TLS with uTLS, the link’s fragment as sing-box’s own ClientHello split', () => {
  assert.deepEqual(sb(ANYTLS), {
    type: 'anytls', tag: 'proxy', server: 'a.example.com', server_port: 8443, password: 'p:w@x',
    tls: { enabled: true, server_name: 'a.example.com', insecure: true, alpn: ['h2', 'http/1.1'], utls: { enabled: true, fingerprint: 'firefox' } }
  });
  const frag = parseLink(ANYTLS);
  frag.outbound._fragment = 'tlshello,100-200,10-20';
  assert.equal(translateOutbound(frag, 'proxy').tls.fragment, true);
  const cfg = buildSingboxConfig(parseLink(ANYTLS), { socksPort: 24010, httpPort: 0 });
  assert.deepEqual(cfg.inbounds.map((i) => [i.type, i.listen, i.listen_port]), [['socks', '127.0.0.1', 24010]]);
  assert.equal(cfg.outbounds[0].type, 'anytls');
});

test('a pinned TUIC / AnyTLS (pcs, vcn, a pin learnt on first use) is refused on sing-box — never "accept any certificate"', () => {
  for (const link of [`tuic://${U}:p@t.example.com:443?pcs=${'ab'.repeat(32)}`, `anytls://p@a.example.com:443?vcn=real.example&insecure=1`]) {
    assert.throws(() => sb(link), UnsupportedEngineConfig, link);
  }
  assert.throws(() => translateOutbound(Object.assign(parseLink(ANYTLS), { certPin: 'aa'.repeat(32) }), 'proxy'), UnsupportedEngineConfig);
});

/* ------------------------------ which core, and what cannot run ------------------------------ */

test('engineChoice: a TUIC / AnyTLS alone runs on sing-box whatever its record or the default says; isSingboxOnly reads the outbound too', () => {
  for (const s of [parseLink(TUIC), parseLink(ANYTLS)]) {
    for (const def of ['xray', 'xray-pattn']) {
      assert.equal(chooseEngine({ mode: 'single', server: s }, def), 'sing-box');
      assert.equal(chooseEngine({ mode: 'single', server: Object.assign({}, s, { engine: 'xray-pattn' }) }, def), 'sing-box');
    }
    assert.equal(isSingboxOnly(s), true);
    assert.equal(isSingboxOnly({ outbound: s.outbound }), true, 'a record that lost its protocol');
  }
  assert.equal(isSingboxOnly(F.VLESS_WS_TLS), false);
  assert.equal(chooseEngine({ mode: 'single', server: F.VLESS_WS_TLS }), 'xray');
});

test('the Xray config refuses one by name: alone it needs the sing-box core; in a chain, a group, a rule or the pool it cannot be at all', () => {
  const t = Object.assign(parseLink(TUIC), { id: 'sv-tuic' });
  const a = Object.assign(parseLink(ANYTLS), { id: 'sv-any' });
  const s = (over) => F.settings(Object.assign({ lang: 'en' }, over));
  assert.throws(() => buildConfig({ mode: 'single', server: t }, s()), /"TU one" is a TUIC server: .*needs the sing-box core \(Settings → Required files\)/);
  assert.throws(() => buildConfig({ mode: 'single', server: a }, s({ lang: 'fa' })), /«AT» سرور AnyTLS است .*sing-box/);
  const NOT_IN = /is a (TUIC|AnyTLS) server: it runs only on its own, on sing-box — not inside a chain, group or routing rule/;
  assert.throws(() => buildConfig({ mode: 'chain', chain: [F.VLESS_WS_TLS, t] }, s()), NOT_IN);
  const grp = groupRecord({ id: 'grp-x', name: 'G', members: [{ id: 'sv-vless' }, { id: 'sv-any' }] }, { 'sv-vless': F.VLESS_WS_TLS, 'sv-any': a });
  assert.throws(() => buildConfig({ mode: 'single', server: grp }, s()), NOT_IN, 'a group is no lone server');
  const adv = { mode: 'advanced', serversById: { 'sv-vless': F.VLESS_WS_TLS, 'sv-tuic': t }, chainsById: {}, chain: [],
    rules: [{ type: 'domain', value: 'a.com', target: 'sv-tuic' }], def: 'sv-vless' };
  assert.throws(() => buildConfig(adv, s()), NOT_IN);
  const pool = { mode: 'pool', entries: [{ id: 'e1', target: 'sv-any', socksPort: 60001 }], primary: 'sv-any', serversById: { 'sv-any': a }, chainsById: {}, chain: [] };
  assert.throws(() => buildConfig(pool, s()), NOT_IN);
  // a latency test's Xray config of a chain / a batch: the same refusal, never an `xray run -test` "unknown protocol"
  assert.throws(() => buildTestConfig([F.VLESS_WS_TLS, t], 41000), NOT_IN);
  assert.throws(() => buildMultiTestConfig([F.VLESS_WS_TLS, a], [41001, 41002]), NOT_IN);
  // the plans without one are as they were
  assert.equal(buildConfig({ mode: 'single', server: F.VLESS_WS_TLS }, s()).outbounds[0].protocol, 'vless');
});

test('a LAN user whose config is a TUIC / AnyTLS is blocked, never the owner’s whole connection refused', () => {
  const t = Object.assign(parseLink(TUIC), { id: 'sv-tuic' });
  const users = [{ id: 'usr-a', username: 'ali', password: 'pw-ali', name: '', target: 'sv-tuic', quotaGb: 0, quotaPeriod: 'month', expiresAt: 0, maxDevices: 0, enabled: true }];
  const cfg = buildConfig({ mode: 'single', server: F.VLESS_WS_TLS }, F.settings({
    modules: { lanUsers: true },
    lanUsers: { config: { proxy: { enabled: true, port: 30820, httpPort: 30821 } }, users, devices: [], over: [], now: Date.now(), serversById: { 'sv-tuic': t } }
  }));
  const rule = cfg.routing.rules.find((r) => Array.isArray(r.user) && r.user.includes('ali'));
  assert.ok(rule, 'the user’s rule');
  assert.equal(rule.outboundTag, 'block');
  assert.equal(cfg.outbounds.some((o) => o.protocol === 'tuic'), false);
});

test('the connect (desktop and headless service): sing-box missing, the router, a pin — each said by name, never an Xray fallback', () => {
  for (const file of ['src/main/main.js', 'src/server/service.js']) {
    const src = R(file);
    const at = src.indexOf('function buildActive(');
    const body = src.slice(at, src.indexOf('return { plan, label, entryAddrs, config, geoWarn, engine };', at));
    assert.match(body, /const sbOnly = plan\.mode === 'single' && isSingboxOnly\(plan\.server\) \? plan\.server : null;/, file);
    assert.match(body, /if \(sbOnly && !xray\.resolveBin\('sing-box'\)\) throw new Error\(singboxOnlyError\(sbOnly, 'missing', settings\.lang\)\);/, file);
    assert.ok(body.indexOf("singboxOnlyError(sbOnly, 'missing'") < body.indexOf('xray.resolveEngine(chooseEngine('), file + ': before resolveEngine falls back to Xray');
    assert.match(body, /if \(sbOnly\) throw new Error\(singboxOnlyError\(sbOnly, 'pin', settings\.lang\)\);/, file);
  }
  const svc = R('src/server/service.js');
  assert.match(svc, /if \(sbOnly && OPENWRT\) throw new Error\(singboxOnlyError\(sbOnly, 'router', settings\.lang\)\);/);
  assert.ok(svc.indexOf("singboxOnlyError(sbOnly, 'router'") < svc.indexOf('running it on Xray instead'), 'refused before the router moves sing-box configs to Xray');
  assert.match(svc, /router: OPENWRT, lang: s\.lang/, 'the router’s latency test refuses it too');
  const t = parseLink(TUIC);
  assert.match(singboxOnlyError(t, 'router', 'en'), /cannot run on the router/);
  assert.match(singboxOnlyError(t, 'pin', 'en'), /pinned certificate .* remove the pin/);
  for (const why of ['missing', 'router', 'pin', 'plan']) assert.match(singboxOnlyError(t, why, 'fa'), /TUIC/);
});

test('a latency test: on sing-box, or refused saying why — sing-box missing, a router, a pin; alone in a batch; TUIC is UDP only', () => {
  const t = parseLink(TUIC), a = parseLink(ANYTLS);
  const r = latencyTest(t, 24020, { hasSingbox: true });
  assert.deepEqual([r.engine, r.single, r.config.outbounds[0].type, r.config.inbounds[0].listen_port], ['sing-box', true, 'tuic', 24020]);
  assert.equal(latencyTest(a, 24021, { hasSingbox: true, defaultEngine: 'xray-pattn' }).engine, 'sing-box');
  assert.throws(() => latencyTest(t, 1, { hasSingbox: false, lang: 'en' }), /needs the sing-box core \(Settings → Required files\)/);
  assert.throws(() => latencyTest(a, 1, { hasSingbox: true, router: true, lang: 'en' }), /cannot run on the router/);
  assert.throws(() => latencyTest(Object.assign(parseLink(ANYTLS), { certPin: 'aa'.repeat(32) }), 1, { hasSingbox: true, lang: 'en' }), /pinned certificate/);
  assert.throws(() => latencyTest([F.VLESS_WS_TLS, t], 1, { hasSingbox: true }), /not inside a chain/);
  // never batched: its refusal would take the batch's other targets down with it
  assert.equal(testsAlone(t, { hasSingbox: false }), true);
  assert.equal(testsAlone(a, { hasSingbox: true }), true);
  const grp = groupRecord({ id: 'grp-y', name: 'G', members: [{ id: 'sv-vless' }, { id: 'sv-tuic' }] }, { 'sv-vless': F.VLESS_WS_TLS, 'sv-tuic': Object.assign({}, t, { id: 'sv-tuic' }) });
  assert.equal(testsAlone(grp, { hasSingbox: false }), true, 'a group holding one');
  assert.equal(testsAlone(F.VLESS_WS_TLS, { hasSingbox: false }), false);
  assert.deepEqual([udpOnly(t), udpOnly(a)], [true, false], 'a TCP ping of TUIC says nothing; AnyTLS is TCP');
});

test('no pin is learnt on first use for TUIC / AnyTLS: their allow insecure is sing-box’s insecure, and a pin would leave them nothing to run on', () => {
  const t = parseLink(TUIC), a = parseLink(ANYTLS);
  assert.equal(t.outbound.streamSettings.tlsSettings.allowInsecure && a.outbound.streamSettings.tlsSettings.allowInsecure, true);
  assert.deepEqual([wantsPin(t), wantsPin(a)], [false, false]);
  assert.deepEqual(pinTargets({ mode: 'single', server: a }), { probe: [], behind: [] });
  assert.equal(wantsPin(parseLink('trojan://pw@a.example.com:443?allowInsecure=1')), true, 'Trojan as before');
  assert.equal(sb(ANYTLS).tls.insecure, true);
});

/* ------------------------------ the editor ------------------------------ */

test('the editor’s table: TUIC’s uuid, password and knobs (path fields), AnyTLS’s password and fingerprint; TLS only, no transport', () => {
  const ctx = (protocol) => SF.contextOf(createServer({ protocol, address: 'e.example.com', port: '443', uuid: U, password: 'pw' }));
  const shown = (protocol) => SF.FIELDS.filter((f) => SF.fieldApplies(f, ctx(protocol))).map((f) => f.id);
  const tuic = shown('tuic'), any = shown('anytls');
  for (const id of ['uuid', 'password', 'tuicCongestion', 'tuicUdpRelay', 'tuicZeroRtt', 'tuicHeartbeat', 'sni', 'tuicDisableSni', 'alpn', 'allowInsecure', 'pcs', 'vcn', 'ech', 'engine']) assert.ok(tuic.includes(id), 'tuic: ' + id);
  for (const id of ['password', 'sni', 'fp', 'alpn', 'allowInsecure', 'pcs', 'vcn', 'ech', 'engine']) assert.ok(any.includes(id), 'anytls: ' + id);
  for (const id of ['fp', 'network', 'security', 'echOutbound', 'useSystemCA', 'minVersion', 'mux', 'finalMask', 'cipherSuites']) assert.ok(!tuic.includes(id), 'not tuic: ' + id);
  for (const id of ['uuid', 'tuicCongestion', 'tuicDisableSni', 'network', 'echOutbound', 'mux']) assert.ok(!any.includes(id), 'not anytls: ' + id);
  assert.deepEqual([SF.securitiesOf('tuic'), SF.securitiesOf('anytls'), SF.hasTransport('tuic'), SF.singboxOnly('anytls'), SF.singboxOnly('hysteria2')], [['tls'], ['tls'], false, true, false]);
  assert.ok(SF.PROTOCOLS.includes('tuic') && SF.PROTOCOLS.includes('anytls'));
});

test('a TUIC made by hand: every field written in the record’s shape, read back as the form shows it, and a save of what it shows changes nothing', () => {
  const s = createServer({ protocol: 'tuic', name: 'hand', address: 't.example.com', port: '8443', uuid: U, password: 'pw', sni: 's.example.com', alpn: 'h3',
    allowInsecure: true, tuicCongestion: 'bbr', tuicUdpRelay: 'native', tuicZeroRtt: true, tuicHeartbeat: '20', tuicDisableSni: true, engine: 'xray', noise: 'faketls', fragment: 'tlshello,1-2,3-4' });
  assert.deepEqual(s.outbound.settings.servers[0], { address: 't.example.com', port: 8443, uuid: U, password: 'pw', congestionControl: 'bbr', udpRelayMode: 'native', zeroRtt: true, heartbeat: '20s' });
  assert.deepEqual(s.outbound.streamSettings, { network: 'udp', security: 'tls', tlsSettings: { serverName: 's.example.com', allowInsecure: true, alpn: ['h3'], disableSni: true } });
  assert.deepEqual([s.engine, s.outbound._noise, s.outbound._fragment], [undefined, undefined, undefined], 'no engine, no noise, no fragment for QUIC');
  assert.deepEqual(parseLink(s.raw).outbound, s.outbound, 'its raw is its own share link');
  const f = editFields(s);
  assert.deepEqual([f.uuid, f.password, f.sni, f.allowInsecure, f.alpn, f.tuicCongestion, f.tuicUdpRelay, f.tuicZeroRtt, f.tuicHeartbeat, f.tuicDisableSni],
    [U, 'pw', 's.example.com', true, 'h3', 'bbr', 'native', true, '20s', true]);
  const same = applyServerEdits(s, Object.assign({}, f, { engine: 'sing-box' }));
  assert.equal(JSON.stringify(same.outbound), JSON.stringify(s.outbound));
  assert.equal(same._edited, undefined, 'nothing the user changed');
  // the switches off: the record keeps every key, false — and "no SNI" is simply not there
  const off = applyServerEdits(s, { tuicZeroRtt: false, tuicDisableSni: false, tuicCongestion: '', tuicHeartbeat: '' });
  assert.deepEqual(off.outbound.settings.servers[0], { address: 't.example.com', port: 8443, uuid: U, password: 'pw', congestionControl: '', udpRelayMode: 'native', zeroRtt: false, heartbeat: '' });
  assert.equal(off.outbound.streamSettings.tlsSettings.disableSni, undefined);
  assert.throws(() => applyServerEdits(s, { tuicHeartbeat: 'soon' }), /^Error: tuicHeartbeat: a duration/);
  assert.throws(() => applyServerEdits(s, { uuid: 'nope' }), /^Error: uuid: not a UUID/);
  // an empty password keeps the one it had (as Trojan's); a new one replaces it; the SNI cleared is cleared
  assert.equal(applyServerEdits(s, { password: '' }).outbound.settings.servers[0].password, 'pw');
  const moved = applyServerEdits(s, { address: '203.0.113.5', port: '443', password: 'new', sni: '' });
  assert.deepEqual([moved.address, moved.outbound.settings.servers[0].address, moved.outbound.settings.servers[0].password, moved.outbound.streamSettings.tlsSettings.serverName],
    ['203.0.113.5', '203.0.113.5', 'new', '']);
});

test('an AnyTLS made by hand: its fingerprint and the TLS basics; its fragment kept (sing-box’s split), noise never', () => {
  const s = createServer({ protocol: 'anytls', address: 'a.example.com', port: '443', password: 'pw', fp: 'safari', ech: 'cloudflare-ech.com+udp://1.1.1.1', fragment: 'tlshello,100-200,10-20', noise: 'faketls' });
  assert.deepEqual(s.outbound.streamSettings.tlsSettings, { serverName: 'a.example.com', allowInsecure: false, fingerprint: 'safari', echConfigList: 'cloudflare-ech.com+udp://1.1.1.1' });
  assert.deepEqual([s.outbound._fragment, s.outbound._noise], ['tlshello,100-200,10-20', undefined]);
  assert.equal(translateOutbound(s, 'proxy').tls.fragment, true);
  assert.deepEqual(parseLink(s.raw).outbound.streamSettings, s.outbound.streamSettings);
  assert.equal(editFields(s).fp, 'safari');
});

test('every TUIC / AnyTLS string of the editor, in Persian and English', () => {
  const src = R('src', 'renderer', 'i18n.js');
  for (const k of ['sfp.tuic', 'sfp.anytls', 'sf.tuicCongestion', 'sfo.tuicCongestion._', 'sf.tuicUdpRelay', 'sfo.tuicUdpRelay._', 'sf.tuicUdpRelay.hint',
    'sf.tuicZeroRtt', 'sf.tuicZeroRtt.hint', 'sf.tuicHeartbeat', 'sf.tuicDisableSni', 'sf.engine.hint.tuic', 'sf.engine.hint.anytls',
    'sf.allowInsecure.hint.tuic', 'sf.allowInsecure.hint.anytls', 'sf.pcs.hint.tuic', 'sf.pcs.hint.anytls', 'edit.insecureHintSb']) {
    assert.equal(src.split(`'${k}':`).length - 1, 2, `${k} in both languages`);
  }
  const html = R('src', 'renderer', 'index.html');
  assert.match(html, /id="edEngineHintTuic" data-i18n="sf\.engine\.hint\.tuic" hidden/);
  assert.match(html, /id="edEngineHintAnytls" data-i18n="sf\.engine\.hint\.anytls" hidden/);
  const app = R('src', 'renderer', 'app.js');
  assert.match(app, /tuic: 'TUIC', anytls: 'AnyTLS'/);
  assert.match(app, /tuic: \['uuid', 'tuicCongestion', 'tuicUdpRelay', 'tuicZeroRtt'\], anytls: \['fp'\]/, 'the Simple view draws what its form lacks');
  assert.match(app, /tuic: \['uuid', 'password'\], anytls: \['password'\]/, 'a new one is refused without its credentials');
  assert.match(app.split('\n').find((l) => l.includes('const looksImportable = ')), /tuic:\\\/\\\/\|anytls:\\\/\\\//, 'a pasted link is taken');
});

/* ------------------------------ what else meets the record ------------------------------ */

test('a backup keeps them, a subscription refresh tells two apart by their credentials, an address swap moves them', () => {
  const t = Object.assign(parseLink(TUIC), { id: 'sv-tuic' });
  const a = Object.assign(parseLink(ANYTLS), { id: 'sv-any' });
  const r = importBundle({ app: 'IRNetFree', format: 1, servers: [t, a] }, { servers: [] });
  assert.deepEqual(r.next.servers.map((s) => s.protocol), ['tuic', 'anytls']);
  const other = parseLink(TUIC.replace('p%40ss', 'other'));
  assert.notEqual(serverIdentity(t), serverIdentity(other));
  assert.equal(serverIdentity(t), serverIdentity(parseLink(TUIC.replace('#TU%20one', '#renamed'))));
  const swapped = withTarget(a, { address: '203.0.113.7', port: 2053 });
  assert.deepEqual([swapped.address, swapped.port, swapped.outbound.settings.servers[0].address, swapped.outbound.settings.servers[0].port], ['203.0.113.7', 2053, '203.0.113.7', 2053]);
  assert.equal(swapped.outbound.streamSettings.tlsSettings.serverName, 'a.example.com', 'the SNI stays on the name');
  const bare = withTarget(parseLink(`tuic://${U}:p@t.example.com:443`), { address: '203.0.113.8' });
  assert.equal(bare.outbound.streamSettings.tlsSettings.serverName, 't.example.com');
});

test('CI runs the real thing: the probe in the cores job, sing-box handed to it, skipped where there is none', () => {
  const yml = R('.github', 'workflows', 'test.yml');
  assert.match(yml, /IRNF_SINGBOX_EXE="\$RUNNER_TEMP\/s\/sing-box" node scripts\/probe-tuic-anytls\.js/);
  const probe = R('scripts', 'probe-tuic-anytls.js');
  assert.match(probe, /parseLink\(LINKS\[kind\]\(pass\)\)/, 'the client is a server parsed from a link');
  assert.match(probe, /buildSingboxConfig\(server, /, 'and the app’s own config for it');
  assert.match(probe, /skipped: no sing-box/);
  assert.doesNotMatch(probe, /listen: '0\.0\.0\.0'|allowLan: true/, 'loopback only');
});
