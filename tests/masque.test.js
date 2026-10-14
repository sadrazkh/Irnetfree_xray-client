'use strict';
/**
 * MASQUE as a native protocol (.superpowers/sdd/masque/design.md §1-4): the
 * record the editor makes and edits (parser.js through serverFields.js), what
 * the core would refuse said at the save, the one-line share JSON and the JSON
 * reader that makes it this server again; then running it — never Mux, never
 * sing-box, never allowInsecure, anti-DPI by HTTP version, the pins and the
 * TCP ping that a QUIC server cannot have. The version gate is in
 * xrayManager.test.js and connectPath.test.js.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const SF = require('../src/renderer/serverFields');
const { createServer, applyServerEdits, editFields, buildShareLink, parseMany, masqueServer } = require('../src/main/parser');
const J = require('../src/main/jsonImport');
const { buildConfig, buildTestConfig, entryAddressesOf } = require('../src/main/configBuilder');
const { chooseEngine, needsInsecureCore, isMasque } = require('../src/main/engineChoice');
const { wantsPin, staleCertPins } = require('../src/main/certPin');
const { udpOnly, latencyTest } = require('../src/main/latencyTest');
const { buildSingboxConfig, UnsupportedEngineConfig } = require('../src/main/singboxBuilder');
const { muxEligible } = require('../src/main/mux');
const { exportBundle, importBundle } = require('../src/main/backup');
const { serverIdentity } = require('../src/main/subscription');
const { explainRoutes } = require('../src/main/connectionDiagnostics');
const F = require('./fixtures');

/** The WARP endpoint's public key (the same for every account today — research.md). */
const WARP_PUB = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIaU7MToJm9NKp8YfGxR6r+/h4mcG7SxI8tsW8OR1A5tv/zCzVbCRRh2t87/kxnP6lAy0lkr7qYwu+ox+k3dr6w==';
const { privateKey: DEVICE } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const PEM = DEVICE.export({ format: 'pem', type: 'pkcs8' });
const B64 = DEVICE.export({ format: 'der', type: 'pkcs8' }).toString('base64');
const PIN = 'ab'.repeat(32);
const noId = (s) => Object.assign({}, s, { id: null });

const plain = (more) => createServer(Object.assign({ protocol: 'masque', name: 'M', address: 'm.example.com', port: '443' }, more));
const warp = (more) => createServer(Object.assign({
  protocol: 'masque', name: '☁ WARP · H3', address: '162.159.198.1', port: '443', sni: 'consumer-masque.cloudflareclient.com',
  warpPrivateKey: PEM, warpPublicKey: WARP_PUB, warpAddress: '172.16.0.2, 2606:4700:110:8a36::2'
}, more));

/* ------------------------------ the record ------------------------------ */

test('a plain MASQUE server over HTTP/3: the core’s flat settings, MASQUE over TLS, no ALPN — the editor reads it back', () => {
  const s = plain({ masqueUser: 'ci', masquePass: 'ci-pass', sni: 'm.example.com', pcs: PIN.toUpperCase() });
  assert.deepEqual([s.protocol, s.address, s.port, s.name], ['masque', 'm.example.com', 443, 'M']);
  assert.deepEqual(s.outbound, {
    protocol: 'masque',
    settings: { address: 'm.example.com', port: 443 },
    streamSettings: {
      network: 'masque', security: 'tls',
      tlsSettings: { serverName: 'm.example.com', pinnedPeerCertSha256: PIN },
      masqueSettings: { user: 'ci', pass: 'ci-pass' }
    }
  });
  const f = editFields(s);
  assert.deepEqual([f.masqueHttp, f.masqueUser, f.masquePass, f.sni, f.pcs, f.fp], ['h3', 'ci', 'ci-pass', 'm.example.com', PIN, '']);
  assert.equal('allowInsecure' in f, false, 'never a MASQUE field');
  assert.deepEqual(SF.contextOf(s), { protocol: 'masque', network: 'masque', security: 'tls' });
  assert.equal(s._edited, undefined);
});

test('HTTP/2 is ALPN h2 (with the fingerprint, which only it uses); back to HTTP/3 drops the ALPN — one that already says the version is left alone', () => {
  const h2 = plain({ masqueHttp: 'h2', fp: 'firefox' });
  assert.deepEqual(h2.outbound.streamSettings.tlsSettings, { fingerprint: 'firefox', alpn: ['h2'] });
  assert.equal(editFields(h2).masqueHttp, 'h2');
  const h3 = applyServerEdits(h2, { masqueHttp: 'h3' });
  assert.equal(h3.outbound.streamSettings.tlsSettings.alpn, undefined);
  assert.deepEqual(h3._edited, ['masqueHttp']);
  // a JSON one's ["h3","h2"] is HTTP/3 already: a save that says h3 keeps it as written
  const both = masqueServer({ protocol: 'masque', settings: { address: 'b.example', port: 443 }, streamSettings: { network: 'masque', security: 'tls', tlsSettings: { alpn: ['h3', 'h2'] } } }, 'B');
  assert.deepEqual(applyServerEdits(both, { masqueHttp: 'h3' }).outbound.streamSettings.tlsSettings.alpn, ['h3', 'h2']);
  assert.equal(SF.masqueHttpOf({ alpn: ['h2', 'http/1.1'] }), 'h2');
  assert.equal(SF.masqueHttpOf({ alpn: 'h3,h2' }), 'h3');
  assert.equal(SF.masqueHttpOf(undefined), 'h3');
});

test('a WARP account: the key’s PEM made one line of base64, bare addresses /32 and /128, host and path left to the core’s WARP defaults', () => {
  const s = warp();
  const ms = s.outbound.streamSettings.masqueSettings;
  assert.deepEqual(ms, { warp: { privateKey: B64, publicKey: WARP_PUB, address: ['172.16.0.2/32', '2606:4700:110:8a36::2/128'] } });
  assert.equal(s.outbound.streamSettings.tlsSettings.serverName, 'consumer-masque.cloudflareclient.com');
  const f = editFields(s);
  assert.deepEqual([f.warpPrivateKey, f.warpPublicKey, f.warpAddress], [B64, WARP_PUB, '172.16.0.2/32, 2606:4700:110:8a36::2/128']);
  // a PEM flattened onto one line by a text box, and a SEC1 key, are read as well
  const flat = applyServerEdits(s, { warpPrivateKey: PEM.replace(/\n/g, '') });
  assert.equal(flat.outbound.streamSettings.masqueSettings.warp.privateKey, B64);
  const sec1 = DEVICE.export({ format: 'der', type: 'sec1' }).toString('base64');
  assert.equal(applyServerEdits(s, { warpPrivateKey: sec1 }).outbound.streamSettings.masqueSettings.warp.privateKey, sec1);
  // all three cleared: a plain server again, its user and password possible
  const off = applyServerEdits(s, { warpPrivateKey: '', warpPublicKey: '', warpAddress: '', masqueUser: 'u', masquePass: 'p' });
  assert.deepEqual(off.outbound.streamSettings.masqueSettings, { user: 'u', pass: 'p' });
});

test('what the core would refuse is refused at the save, naming the field', () => {
  const refuses = (more, re) => assert.throws(() => plain(more), re, JSON.stringify(more));
  refuses({ warpPrivateKey: PEM }, /^Error: warpPublicKey, warpAddress are empty/);
  refuses({ warpPrivateKey: PEM, warpPublicKey: WARP_PUB }, /^Error: warpAddress is empty/);
  refuses({ warpPrivateKey: PEM, warpPublicKey: WARP_PUB, warpAddress: '172.16.0.2', masqueUser: 'u' }, /masqueUser: a WARP account takes no user and password/);
  refuses({ warpPrivateKey: 'bm90IGEga2V5', warpPublicKey: WARP_PUB, warpAddress: '172.16.0.2' }, /warpPrivateKey: not a P-256 private key/);
  const ed = crypto.generateKeyPairSync('ed25519').privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64');
  refuses({ warpPrivateKey: ed, warpPublicKey: WARP_PUB, warpAddress: '172.16.0.2' }, /warpPrivateKey: not a P-256 private key/);
  refuses({ warpPrivateKey: PEM, warpPublicKey: 'bm8=', warpAddress: '172.16.0.2' }, /warpPublicKey: not a public key/);
  refuses({ warpPrivateKey: PEM, warpPublicKey: WARP_PUB, warpAddress: '172.16.0.2, 172.16.0.3' }, /warpAddress: at most one IPv4 and one IPv6/);
  refuses({ warpPrivateKey: PEM, warpPublicKey: WARP_PUB, warpAddress: 'warp.example' }, /warpAddress: "warp\.example" is not an IP address/);
  refuses({ warpPrivateKey: PEM, warpPublicKey: WARP_PUB, warpAddress: '172.16.0.2/33' }, /not an IP address/);
  refuses({ masqueUser: 'a:b' }, /masqueUser: a user name cannot contain ":"/);
  refuses({ masquePath: 'masque' }, /masquePath: the path starts with \//);
  refuses({ masqueHost: 'https://h.example/x' }, /masqueHost: a host name only/);
  refuses({ masqueHeaders: '{"Host":"h.example"}' }, /masqueHeaders: Host is the core's own/);
  refuses({ masqueHeaders: '{"capsule-protocol":"?1"}' }, /masqueHeaders: capsule-protocol is the core's own/);
  refuses({ masqueHeaders: '{"X-N":1}' }, /masqueHeaders: the value of X-N is not text/);
  refuses({ masqueHeaders: '{"Authorization":"Bearer x"}', masqueUser: 'u' }, /Authorization beside a user and password/);
  refuses({ remoteDNS: '1.1.1.1, dns.google' }, /remoteDNS: IP addresses only/);
  // what the core takes
  assert.doesNotThrow(() => plain({ masqueHeaders: '{"User-Agent":"chrome","Authorization":"Bearer x"}', masquePath: '/.well-known/masque/ip/{target}/{ipproto}/', masqueHost: 'm.example.com:8443', remoteDNS: '1.1.1.1, 2606:4700:4700::1111' }));
  // the record stays as it was when an edit is refused (applyServerEdits works on a copy)
  const s = plain();
  assert.throws(() => applyServerEdits(s, { masqueUser: 'a:b' }));
  assert.deepEqual(s.outbound.streamSettings.masqueSettings, {});
});

test('never allowInsecure, Mux or sing-box; a fragment only over HTTP/2, noise only over HTTP/3', () => {
  const s = plain({ allowInsecure: true, engine: 'sing-box', mux: 'on', fragment: 'tlshello,100-200,10-20', noise: 'rand:50-100:0' });
  assert.equal('allowInsecure' in s.outbound.streamSettings.tlsSettings, false);
  assert.equal(s.engine, undefined, 'sing-box has no MASQUE');
  assert.equal(s.mux, undefined, 'the Mux field is not MASQUE’s');
  assert.deepEqual([s.outbound._fragment, s.outbound._noise], [undefined, 'rand:50-100:0'], 'HTTP/3: noise');
  const h2 = applyServerEdits(s, { masqueHttp: 'h2', fragment: 'tlshello,100-200,10-20' });
  assert.deepEqual([h2.outbound._fragment, h2.outbound._noise], ['tlshello,100-200,10-20', undefined], 'HTTP/2: the fragment');
  assert.equal(applyServerEdits(s, { engine: 'xray-pattn' }).engine, 'xray-pattn');
  // a JSON outbound with Mux on: the core would refuse it
  const j = masqueServer({ protocol: 'masque', mux: { enabled: true }, settings: { address: 'j.example', port: 443 }, streamSettings: { network: 'masque', security: 'tls' } }, 'J');
  assert.equal(j.outbound.mux, undefined);
});

test('a Save with nothing changed changes nothing and records nothing; a changed field is recorded', () => {
  for (const s of [plain({ masqueUser: 'u', masquePass: 'p', masqueHttp: 'h2', fp: 'chrome', remoteDNS: '9.9.9.9', useSystemCA: true }), warp({ noise: 'random' })]) {
    const again = applyServerEdits(s, editFields(s));
    assert.equal(again._edited, undefined);
    assert.deepEqual(again.outbound, s.outbound);
  }
  const e = applyServerEdits(warp(), { sni: 'www.example.com', vcn: 'www.example.com' });
  assert.deepEqual(e._edited, ['sni', 'vcn']);
  assert.equal(e.outbound.streamSettings.tlsSettings.verifyPeerCertByName, 'www.example.com');
});

/* ------------------------------ sharing ------------------------------ */

test('the share JSON: one line, the remarks and the one outbound — without what is this device’s own', () => {
  const s = applyServerEdits(warp({ noise: 'random', engine: 'xray-pattn' }),
    { remoteDNS: '9.9.9.9', useSystemCA: true, echForceQuery: 'full', minVersion: '1.3', curvePreferences: 'X25519', pcs: PIN, finalMask: '{"quicParams":{"congestion":"reno"}}' });
  const link = buildShareLink(s);
  assert.equal(s.raw, buildShareLink(warp()).replace(/"remarks":"[^"]*"/, '"remarks":"☁ WARP · H3"'), 'raw is the share JSON of the server as made');
  assert.doesNotMatch(link, /\n/);
  const j = JSON.parse(link);
  assert.deepEqual(Object.keys(j), ['remarks', 'outbounds']);
  assert.equal(j.remarks, '☁ WARP · H3');
  assert.deepEqual(j.outbounds[0], {
    tag: 'proxy', protocol: 'masque',
    settings: { address: '162.159.198.1', port: 443 },
    streamSettings: {
      network: 'masque', security: 'tls',
      tlsSettings: { serverName: 'consumer-masque.cloudflareclient.com', pinnedPeerCertSha256: PIN },
      masqueSettings: { warp: { privateKey: B64, publicKey: WARP_PUB, address: ['172.16.0.2/32', '2606:4700:110:8a36::2/128'] } },
      finalmask: { quicParams: { congestion: 'reno' } }
    }
  });
  // every local field of the table, and the device's anti-DPI and core, stay here
  for (const f of SF.PATH_FIELDS.filter((x) => x.local && x.path[0] !== '@')) {
    assert.equal(SF.getPath({ outbound: j.outbounds[0] }, f.path), undefined, f.id);
  }
  assert.doesNotMatch(link, /_noise|_fragment|engine|xray-pattn/);
  const p = plain({ masqueHeaders: '{"User-Agent":"chrome"}', masqueUser: 'u', masquePass: 'p' });
  assert.deepEqual(JSON.parse(buildShareLink(p)).outbounds[0].streamSettings.masqueSettings, { user: 'u', pass: 'p' });
});

test('the share JSON pasted into another IRNetFree is this very server again — an ordinary one, every field editable', () => {
  for (const s of [warp(), plain({ masqueHttp: 'h2', masqueUser: 'u', masquePass: 'p', masquePath: '/m/', masqueHost: 'h.example', fp: 'safari', ech: 'AEXX', vcn: 'real.example' })]) {
    const r = parseMany(buildShareLink(s));
    assert.deepEqual(r.errors, []);
    assert.equal(r.servers.length, 1);
    const [back] = r.servers;
    assert.equal(back.source, undefined);
    assert.notEqual(back.id, s.id);
    assert.deepEqual(noId(back), noId(s));
  }
});

/* ------------------------------ the JSON reader ------------------------------ */

const fixture = () => fs.readFileSync(path.join(__dirname, 'fixtures', 'json', 'xray-masque.json'), 'utf8');

test('xray-masque.json: a WARP and an HTTP/2 server alone in their config become native servers, a panel’s full config stays a JSON server', () => {
  const r = J.importJson(fixture());
  assert.deepEqual(r.errors, []);
  assert.deepEqual(r.servers.map((s) => [s.name, s.protocol, s.address, s.port, s.source || 'native']), [
    ['☁ WARP · H3', 'masque', '162.159.198.1', 443, 'native'],
    ['Ⓜ MASQUE · H2', 'masque', 'masque.example.com', 8443, 'native'],
    ['🏛 panel MASQUE', 'masque', 'panel.example.com', 443, 'json']
  ]);
  const [w, h2, panel] = r.servers;
  assert.match(w.outbound.streamSettings.masqueSettings.warp.privateKey, /^MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg/, 'the PEM made one line');
  assert.equal(w.outbound.streamSettings.masqueSettings.warp.publicKey, WARP_PUB);
  assert.deepEqual(w.outbound.streamSettings.masqueSettings.warp.address, ['172.16.0.2/32', '2606:4700:110:8a36:4d2e:7c3a:9f11:5b20/128']);
  assert.equal(w.outbound.tag, undefined);
  assert.deepEqual(editFields(h2).masqueHttp, 'h2');
  assert.deepEqual(h2.outbound.settings.remoteDNS, ['1.1.1.1', '2606:4700:4700::1111']);
  assert.equal(h2.raw, buildShareLink(h2));
  // the panel's config: run whole if the user wants, its own routing kept
  assert.equal(panel.jsonMode, 'full');
  assert.equal(panel.outbound.protocol, 'masque');
  assert.deepEqual(panel.jsonInfo.rules.map((x) => x.to), ['direct', 'proxy']);
  assert.ok(J.PROXY_PROTOCOLS.has('masque'), 'a MASQUE JSON is never read as zero servers again');
});

test('only a config that is just one MASQUE server is read as one: a dialer, a second proxy, a key the editor refuses — a JSON server', () => {
  const ob = (more) => Object.assign({ tag: 'proxy', protocol: 'masque', settings: { address: 'a.example', port: 443 }, streamSettings: { network: 'masque', security: 'tls' } }, more);
  const one = (cfg) => J.serversFromXray(cfg)[0];
  assert.equal(one({ remarks: 'r', outbounds: [ob()] }).source, undefined);
  assert.equal(one({ remarks: 'r', outbounds: [ob(), { tag: 'd', protocol: 'freedom' }, { tag: 'b', protocol: 'blackhole' }, { tag: 'dns-out', protocol: 'dns' }] }).source, undefined);
  assert.equal(one({ outbounds: [ob()] }).name, 'a.example:443', 'no remarks: address:port, as for any JSON server');
  // through a fragment dialer: that dialer would be lost
  const viaFrag = { outbounds: [ob({ streamSettings: { network: 'masque', security: 'tls', sockopt: { dialerProxy: 'frag' } } }), { tag: 'frag', protocol: 'freedom', settings: { fragment: { packets: 'tlshello' } } }] };
  assert.equal(one(viaFrag).source, 'json');
  assert.equal(one(viaFrag).extraOutbounds.length, 1);
  // a second proxy, a loopback, its own inbounds or routing
  assert.equal(one({ outbounds: [ob(), { tag: 'v', protocol: 'vless', settings: { vnext: [{ address: 'v.example', port: 443, users: [{ id: 'u' }] }] } }] }).source, 'json');
  assert.equal(one({ outbounds: [ob(), { tag: 'l', protocol: 'loopback' }] }).source, 'json');
  assert.equal(one({ outbounds: [ob()], routing: { rules: [] } }).source, 'json');
  assert.equal(one({ outbounds: [ob()], inbounds: [] }).source, 'json');
  // a WARP account missing its addresses: the core will say so; the import keeps the config
  const bad = one({ outbounds: [ob({ streamSettings: { network: 'masque', security: 'tls', masqueSettings: { warp: { privateKey: B64, publicKey: WARP_PUB } } } })] });
  assert.equal(bad.source, 'json');
  assert.equal(bad.protocol, 'masque');
});

/* ------------------------------ running it ------------------------------ */

test('the config: the MASQUE outbound as the proxy, dialled directly, never Mux — even on the list of servers to mux', () => {
  const s = Object.assign(plain({ masqueUser: 'u', masquePass: 'p' }), { id: 'mq' });
  s.outbound.streamSettings.tlsSettings.allowInsecure = true;   // a hand-edited store
  const cfg = buildConfig({ mode: 'single', server: s }, F.settings({ muxServerIds: ['mq'] }));
  const proxy = F.outboundTagged(cfg, 'proxy');
  assert.equal(proxy.protocol, 'masque');
  assert.equal(proxy.mux, undefined);
  assert.equal('allowInsecure' in proxy.streamSettings.tlsSettings, false);
  assert.equal(muxEligible(s.outbound), false);
  assert.deepEqual(entryAddressesOf(s), ['m.example.com']);
  // a JSON one: its MASQUE outbound is an entry the bypass and the guard are cut for
  const panel = J.importJson(fixture()).servers[2];
  assert.deepEqual(entryAddressesOf(panel), ['panel.example.com']);
});

test('anti-DPI by HTTP version: HTTP/2 dials through a fragment, HTTP/3 through noise — and never the other, even from a record that kept it', () => {
  const dpi = (cfg) => cfg.outbounds.filter((o) => /^dpi-/.test(o.tag));
  const h2 = plain({ masqueHttp: 'h2', fragment: 'tlshello,100-200,10-20' });
  const c2 = buildConfig({ mode: 'single', server: h2 }, F.settings());
  assert.equal(F.outboundTagged(c2, 'proxy').streamSettings.sockopt.dialerProxy, 'dpi-1');
  assert.deepEqual(dpi(c2).map((o) => Object.keys(o.settings).sort()), [['domainStrategy', 'fragment']]);
  const h3 = warp({ noise: 'rand:50-100:0' });
  const c3 = buildConfig({ mode: 'single', server: h3 }, F.settings());
  assert.deepEqual(dpi(c3)[0].settings.noises, [{ type: 'rand', packet: '50-100', delay: '0' }]);
  assert.equal(dpi(c3)[0].settings.fragment, undefined);
  // a stored HTTP/3 record that still carries a fragment (hand-edited): no dialer at all
  const kept = plain();
  kept.outbound._fragment = 'tlshello,100-200,10-20';
  const ck = buildConfig({ mode: 'single', server: kept }, F.settings());
  assert.deepEqual(dpi(ck), []);
  assert.equal((F.outboundTagged(ck, 'proxy').streamSettings.sockopt || {}).dialerProxy, undefined);
  assert.equal(JSON.stringify(ck).includes('_fragment'), false);
  // the latency test's own config the same way
  assert.deepEqual(dpi(buildTestConfig(h3, 41000)).map((o) => !!o.settings.noises), [true]);
});

test('the core: Xray (or Xray-PattN when chosen), never sing-box — which refuses it outright', () => {
  const s = plain();
  assert.equal(isMasque(s), true);
  assert.equal(chooseEngine({ mode: 'single', server: Object.assign({}, s, { engine: 'sing-box' }) }), 'xray');
  assert.equal(chooseEngine({ mode: 'single', server: Object.assign({}, s, { engine: 'xray-pattn' }) }), 'xray-pattn');
  assert.equal(chooseEngine({ mode: 'single', server: s }, 'xray-pattn'), 'xray-pattn');
  assert.equal(needsInsecureCore(s), false);
  assert.throws(() => buildSingboxConfig(s, { socksPort: 1, httpPort: 0 }), UnsupportedEngineConfig);
  // a latency test with sing-box installed and asked for: still Xray
  const t = latencyTest(Object.assign({}, s, { engine: 'sing-box' }), 41001, { hasSingbox: true });
  assert.deepEqual([t.engine, t.single], ['xray', false]);
});

test('no certificate pin learnt for MASQUE, and a QUIC one’s pin is not re-checked over TCP; a TCP ping only over HTTP/2', async () => {
  const s = plain();
  s.outbound.streamSettings.tlsSettings.allowInsecure = true;
  assert.equal(wantsPin(s), false);
  const probed = [];
  const probe = async (o) => { probed.push(o.host); return 'cd'.repeat(32); };
  const h3 = Object.assign(plain(), { id: 'a', certPin: PIN });
  const h2 = Object.assign(plain({ masqueHttp: 'h2', address: 'h2.example.com' }), { id: 'b', certPin: PIN });
  assert.deepEqual((await staleCertPins([h3, h2], probe)).map((x) => x.id), ['b']);
  assert.deepEqual(probed, ['h2.example.com']);
  assert.equal(udpOnly(warp()), true);
  assert.equal(udpOnly(plain({ masqueHttp: 'h2' })), false);
  assert.equal(udpOnly({ protocol: 'masque' }), true);
});

test('a backup carries MASQUE servers; a subscription knows one by its account; the diagnostics name its hop', () => {
  const s = warp();
  const r = importBundle(exportBundle({ store: { servers: [s] } }), { servers: [] });
  assert.deepEqual(r.next.servers.map((x) => [x.id, x.protocol]), [[s.id, 'masque']]);
  const id = JSON.parse(serverIdentity(s));
  assert.deepEqual(id, ['masque', '162.159.198.1', 443, B64, 'masque', '', '']);
  assert.equal(JSON.parse(serverIdentity(plain({ masqueUser: 'u', masquePass: 'p', masquePath: '/m/' })))[3], 'u:p');
  assert.equal(JSON.parse(serverIdentity(plain({ masqueUser: 'u', masquePass: 'p', masquePath: '/m/' })))[5], '/m/');
  const cfg = buildConfig({ mode: 'single', server: s }, F.settings());
  assert.deepEqual(explainRoutes(cfg, { mode: 'single' }).paths.map((p) => p.hops), [['masque']]);
});
