'use strict';
/**
 * The server editor's field table (src/renderer/serverFields.js): its shape,
 * where each field applies, the generic path read/write, the form's
 * conversions and checks, and the VLESS Encryption read-back.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const SF = require('../src/renderer/serverFields');

const X25519_ENC = 'mlkem768x25519plus.native.0rtt.p7sTtcQlhzr21By6QMbFOEFjtHJa8dquXhK7pboK9GE';
const MLKEM_ENC = 'mlkem768x25519plus.native.0rtt.' + 'A'.repeat(1579);

test('the table: unique ids, a tab, a kind and a technical key each; a path or the parser’s own code, never both', () => {
  const ids = SF.FIELDS.map((f) => f.id);
  assert.equal(new Set(ids).size, ids.length, 'ids are unique');
  for (const f of SF.FIELDS) {
    assert.ok(SF.TABS.includes(f.tab), f.id + ' tab');
    assert.ok(f.kind, f.id + ' kind');
    assert.ok(f.key, f.id + ' key');
    assert.ok(!!f.path !== !!f.special, f.id + ': a path or special');
    if (f.kind === 'select' || f.kind === 'seg' || f.kind === 'chips') assert.ok(Array.isArray(f.options) && f.options.length, f.id + ' options');
    if (f.when && f.when.networks) for (const n of f.when.networks) assert.ok(SF.NETWORKS.includes(n), f.id + ' network ' + n);
  }
  // the app sets these itself — the editor never writes them
  for (const f of SF.PATH_FIELDS) {
    assert.doesNotMatch(f.path, /sockopt\.(interface|mark|domainStrategy|dialerProxy)$/, f.id);
  }
});

test('fieldApplies: protocol, transport and security decide; WireGuard has no transport, Hysteria2 is always TLS', () => {
  const by = (id) => SF.FIELDS.find((f) => f.id === id);
  const vlessWsTls = { protocol: 'vless', network: 'ws', security: 'tls' };
  assert.equal(SF.fieldApplies(by('wsHeartbeat'), vlessWsTls), true);
  assert.equal(SF.fieldApplies(by('grpcUserAgent'), vlessWsTls), false);
  assert.equal(SF.fieldApplies(by('encryption'), vlessWsTls), true);
  assert.equal(SF.fieldApplies(by('encryption'), Object.assign({}, vlessWsTls, { protocol: 'vmess' })), false);
  assert.equal(SF.fieldApplies(by('pbk'), vlessWsTls), false);
  assert.equal(SF.fieldApplies(by('pbk'), Object.assign({}, vlessWsTls, { security: 'reality' })), true);
  assert.equal(SF.fieldApplies(by('wsHeartbeat'), { protocol: 'wireguard', network: 'ws', security: 'none' }), false);
  assert.equal(SF.fieldApplies(by('alpn'), { protocol: 'hysteria2', network: 'hysteria', security: 'none' }), true);
  assert.deepEqual(SF.securitiesOf('vless'), ['none', 'tls', 'reality']);
  assert.deepEqual(SF.securitiesOf('wireguard'), []);
  assert.equal(SF.hasTransport('hysteria2'), false);
  assert.deepEqual(SF.contextOf({ protocol: 'vless', outbound: { streamSettings: { network: 'raw', security: 'reality' } } }),
    { protocol: 'vless', network: 'tcp', security: 'reality' });
});

test('getPath / setPath: dotted paths into the outbound, @ into the record, arrays by index; a delete prunes what it emptied deep down', () => {
  const s = { name: 'x', outbound: { settings: { vnext: [{ users: [{ id: 'u', flow: '' }] }] }, streamSettings: { sockopt: {} } } };
  assert.equal(SF.getPath(s, 'settings.vnext.0.users.0.id'), 'u');
  SF.setPath(s, 'settings.vnext.0.users.0.flow', 'xtls-rprx-vision');
  assert.equal(s.outbound.settings.vnext[0].users[0].flow, 'xtls-rprx-vision');
  SF.setPath(s, '@mux', 'on');
  assert.equal(s.mux, 'on');
  SF.setPath(s, '@mux', undefined);
  assert.equal('mux' in s, false);
  SF.setPath(s, 'streamSettings.xhttpSettings.extra.xmux.maxConcurrency', '16-32');
  assert.deepEqual(s.outbound.streamSettings.xhttpSettings, { extra: { xmux: { maxConcurrency: '16-32' } } });
  SF.setPath(s, 'streamSettings.xhttpSettings.extra.xmux.maxConcurrency', undefined);
  assert.deepEqual(s.outbound.streamSettings.xhttpSettings, {}, 'xmux and extra went; xhttpSettings stays');
  SF.setPath(s, 'streamSettings.sockopt.tcpFastOpen', true);
  SF.setPath(s, 'streamSettings.sockopt.tcpFastOpen', undefined);
  assert.deepEqual(s.outbound.streamSettings.sockopt, {}, 'sockopt itself stays');
  SF.setPath(s, 'settings.peers.0.keepAlive', undefined);
  assert.equal(s.outbound.settings.peers, undefined, 'deleting nothing makes nothing');
});

test('toForm / fromForm: numbers, ranges, JSON, lists, switches, and an empty value deletes — or is its emptyAs', () => {
  const k = (kind, more) => Object.assign({ id: 't', kind }, more);
  assert.equal(SF.fromForm(k('number'), ' 25 '), 25);
  assert.equal(SF.fromForm(k('number'), ''), undefined);
  assert.equal(SF.fromForm(k('range'), '16-32'), '16-32');
  assert.equal(SF.fromForm(k('range'), '30'), 30);
  assert.deepEqual(SF.fromForm(k('json'), '{"a":1}'), { a: 1 });
  assert.deepEqual(SF.fromForm(k('list'), 'X25519MLKEM768, X25519'), ['X25519MLKEM768', 'X25519']);
  assert.equal(SF.fromForm(k('switch'), true), true);
  assert.equal(SF.fromForm(k('switch'), false), undefined);
  assert.equal(SF.fromForm(k('encryption', { emptyAs: 'none' }), ''), 'none');
  assert.equal(SF.toForm(k('switch'), undefined), false);
  assert.equal(SF.toForm(k('list'), ['a', 'b']), 'a, b');
  assert.equal(SF.toForm(k('json'), { a: 1 }), '{"a":1}');
  assert.equal(SF.toForm(k('number'), 0), '0');
});

test('validate: what cannot be written says why', () => {
  const k = (kind) => ({ id: 't', kind });
  assert.equal(SF.validate(k('number'), '12'), null);
  assert.equal(SF.validate(k('number'), '1.5'), 'edit.err.number');
  assert.equal(SF.validate(k('range'), '100-1000'), null);
  assert.equal(SF.validate(k('range'), '100 to 1000'), 'edit.err.range');
  assert.equal(SF.validate(k('json'), '{"a":'), 'edit.err.json');
  assert.equal(SF.validate(k('json'), '[1]'), 'edit.err.json');
  assert.equal(SF.validate(k('encryption'), X25519_ENC), null);
  assert.equal(SF.validate(k('encryption'), 'aes.native.0rtt.' + 'k'.repeat(43)), 'edit.err.encPrefix');
  assert.equal(SF.validate(k('text'), ''), null);
});

test('readEncryption: the auth by the key’s length, the mode, 0-RTT or 1-RTT, padding — or why it is not one', () => {
  assert.equal(SF.readEncryption('none'), null);
  assert.equal(SF.readEncryption(''), null);
  assert.deepEqual(SF.readEncryption(X25519_ENC), { auth: 'X25519', mode: 'native', rtt: '0rtt', padded: false });
  assert.deepEqual(SF.readEncryption(MLKEM_ENC), { auth: 'ML-KEM-768', mode: 'native', rtt: '0rtt', padded: false });
  assert.equal(SF.readEncryption('mlkem768x25519plus.xorpub.1rtt.100-111-1111.75-0-111.' + 'k'.repeat(43)).padded, true);
  assert.deepEqual(SF.readEncryption('mlkem768x25519plus.plain.0rtt.' + 'k'.repeat(43)), { bad: 'edit.err.encMode' });
  assert.deepEqual(SF.readEncryption('mlkem768x25519plus.native.2rtt.' + 'k'.repeat(43)), { bad: 'edit.err.encRtt' });
  assert.deepEqual(SF.readEncryption('mlkem768x25519plus.native.0rtt.short'), { bad: 'edit.err.encKey' });
});

test('presets: PattNG’s, name for name and value for value — four finalmasks, two cipherSuites, dialMode’s oob — on those three fields only', () => {
  const by = (id) => SF.FIELDS.find((f) => f.id === id);
  assert.deepEqual(SF.FIELDS.filter((f) => f.presets).map((f) => f.id).sort(), ['cipherSuites', 'dialMode', 'finalMask']);
  for (const f of SF.FIELDS.filter((x) => x.presets)) {
    assert.ok(f.presets.length && f.presets.every((p) => p.name && typeof p.value === 'string' && p.value), f.id);
    assert.equal(new Set(f.presets.map((p) => p.name)).size, f.presets.length, f.id + ': one name each');
    // a preset is a value the field itself takes: no save refuses it
    for (const p of f.presets) assert.equal(SF.validate(f, p.value), null, `${f.id} ${p.name}`);
  }
  const fm = Object.fromEntries(by('finalMask').presets.map((p) => [p.name, JSON.parse(p.value)]));
  const split = (a, b, c) => ({ tcp: [
    { type: 'fragment', settings: { packets: 'tlshello', lengths: [a, b, c], delays: ['0'], maxSplit: '0' } },
    { type: 'fragment', settings: { packets: '1-1', lengths: ['114', '1'], delays: ['1'], maxSplit: '11' } }] });
  assert.deepEqual(fm, {
    'tlshello-0-len (0-104-1-0-0-114-1-1-11)': split('0', '104', '1'),
    'tlshello (6-98-1-0-0-114-1-1-11)': split('6', '98', '1'),
    'udp-noise (rnd-24-1200-1230)': { udp: [{ type: 'noise', settings: { reset: '28', noise: Array(24).fill({ rand: '1200-1230', delay: '10' }) } }] },
    merge: { tcp: [{ type: 'merge', settings: { times: 100, delayMs: 30, maxBytes: 16384 } }] }
  });
  // the form's own text: JSON as one line, as the field shows a record's
  for (const p of by('finalMask').presets) assert.equal(p.value, JSON.stringify(JSON.parse(p.value)));
  const cs = Object.fromEntries(by('cipherSuites').presets.map((p) => [p.name, p.value.split(':')]));
  assert.deepEqual(Object.keys(cs), ['semi-python-cipherSuites', 'real-firefox-cipherSuites']);
  assert.equal(cs['semi-python-cipherSuites'].length, 10);
  assert.deepEqual(cs['semi-python-cipherSuites'].slice(0, 2), ['TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384']);
  assert.equal(cs['semi-python-cipherSuites'][9], 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256');
  assert.equal(cs['real-firefox-cipherSuites'].length, 12);
  assert.deepEqual(cs['real-firefox-cipherSuites'].slice(-4), ['TLS_RSA_WITH_AES_128_GCM_SHA256', 'TLS_RSA_WITH_AES_256_GCM_SHA384', 'TLS_RSA_WITH_AES_128_CBC_SHA', 'TLS_RSA_WITH_AES_256_CBC_SHA']);
  assert.deepEqual(by('dialMode').presets, [{ name: 'oob', value: 'oob.0' }]);
});

test('presetOf: the preset the value equals — dialMode by its text, JSON by its canonical form, cipherSuites by its names in order — none for one’s own', () => {
  const by = (id) => SF.FIELDS.find((f) => f.id === id);
  assert.equal(SF.presetOf(by('dialMode'), 'oob.0'), 'oob');
  assert.equal(SF.presetOf(by('dialMode'), ' oob.0 '), 'oob');
  assert.equal(SF.presetOf(by('dialMode'), 'oob.0,32'), '');
  assert.equal(SF.presetOf(by('dialMode'), ''), '');
  const merge = SF.FINALMASK_PRESETS.find((p) => p.name === 'merge').value;
  assert.equal(SF.presetOf(by('finalMask'), merge), 'merge');
  // pretty-printed, keys in another order, or the record's own object: the same mask
  assert.equal(SF.presetOf(by('finalMask'), JSON.stringify(JSON.parse(merge), null, 2)), 'merge');
  assert.equal(SF.presetOf(by('finalMask'), '{"tcp":[{"settings":{"maxBytes":16384,"delayMs":30,"times":100},"type":"merge"}]}'), 'merge');
  assert.equal(SF.presetOf(by('finalMask'), JSON.parse(merge)), 'merge');
  // …but another number, a string for a number, an array order: not it
  assert.equal(SF.presetOf(by('finalMask'), merge.replace('"times":100', '"times":99')), '');
  assert.equal(SF.presetOf(by('finalMask'), merge.replace('"times":100', '"times":"100"')), '');
  assert.equal(SF.presetOf(by('finalMask'), '{"tcp":['), '', 'no JSON, no preset');
  assert.equal(SF.presetOf(by('finalMask'), SF.FINALMASK_PRESETS[1].value), 'tlshello (6-98-1-0-0-114-1-1-11)');
  const ff = SF.CIPHER_PRESETS.find((p) => p.name === 'real-firefox-cipherSuites').value;
  assert.equal(SF.presetOf(by('cipherSuites'), ff), 'real-firefox-cipherSuites');
  assert.equal(SF.presetOf(by('cipherSuites'), ' ' + ff.split(':').join(' : ') + ': '), 'real-firefox-cipherSuites', 'spaces around a name and an empty one are nothing');
  assert.equal(SF.presetOf(by('cipherSuites'), ff.split(':').reverse().join(':')), '', 'the order is the ClientHello’s: another order is another value');
  assert.equal(SF.presetOf(by('cipherSuites'), 'TLS_AES_256_GCM_SHA384'), '');
  assert.equal(SF.presetOf(by('sni'), 'oob.0'), '', 'a field with no presets has none');
});

test('dialMode: Xray-PattN’s OOB bytes in sockopt — the stream protocols’ advanced tab, the anti-DPI extension’s, this device only; oob.<byte>[,<byte>…] with every byte 0–255 or the save refuses', () => {
  const f = SF.FIELDS.find((x) => x.id === 'dialMode');
  assert.deepEqual([f.tab, f.group, f.kind, f.path, f.key, f.module, f.local, f.hint, f.placeholder],
    ['advanced', 'pattn', 'text', 'streamSettings.sockopt.dialMode', 'dialMode', 'antiDpi', true, true, 'oob.0']);
  assert.deepEqual(f.when.protocols, ['vless', 'vmess', 'trojan', 'shadowsocks']);
  // right after the other patterniha fields
  const ids = SF.FIELDS.map((x) => x.id);
  assert.equal(ids.indexOf('dialMode'), ids.indexOf('finalMask') + 1);
  for (const ok of ['oob.0', 'oob.255', 'oob.0,32,65', ' oob.7 ', '']) assert.equal(SF.validate(f, ok), null, JSON.stringify(ok));
  for (const bad of ['oob', 'oob.', 'oob.256', 'oob.0,', 'oob.0,,1', 'oob.0, 32', 'OOB.0', 'oob.-1', 'oob.1000', 'fragment', 'oob.0x20'])
    assert.equal(SF.validate(f, bad), 'edit.err.dialMode', JSON.stringify(bad));
  assert.deepEqual(SF.readDialMode('oob.0,32,65'), { bytes: [0, 32, 65] });
  assert.equal(SF.readDialMode(''), null);
  assert.deepEqual(SF.readDialMode('oob.300'), { bad: 'edit.err.dialMode' });
  assert.equal(SF.fieldApplies(f, { protocol: 'vless', network: 'xhttp', security: 'reality' }), true);
  for (const protocol of ['hysteria2', 'masque', 'wireguard', 'tuic', 'anytls', 'socks']) assert.equal(SF.fieldApplies(f, { protocol, network: 'tcp', security: 'tls' }), false, protocol);
  // written where the core reads it, beside the socket options the editor already writes
  const server = { protocol: 'vless', outbound: { settings: { vnext: [{ users: [{ id: 'u' }] }] }, streamSettings: { network: 'tcp', security: 'tls', sockopt: { tcpFastOpen: true } } } };
  SF.applyPathFields(server, { dialMode: 'oob.0' }, SF.readPathFields(server));
  assert.deepEqual(server.outbound.streamSettings.sockopt, { tcpFastOpen: true, dialMode: 'oob.0' });
});

test('fingerprints: hellochrome_120 (the official core’s too) right after chrome, in the table’s fingerprint field', () => {
  assert.deepEqual(SF.FINGERPRINTS.slice(0, 3), ['chrome', 'hellochrome_120', 'firefox']);
  assert.equal(new Set(SF.FINGERPRINTS).size, SF.FINGERPRINTS.length);
  assert.ok(SF.FIELDS.find((f) => f.id === 'fp').options.includes('hellochrome_120'));
});

test('applyPathFields: a submitted change wins, an unsent field keeps the record’s value, a field that stopped applying goes', () => {
  const server = {
    protocol: 'vless',
    outbound: {
      settings: { vnext: [{ users: [{ id: 'u', encryption: 'none', flow: '' }] }] },
      streamSettings: { network: 'ws', security: 'tls', wsSettings: { path: '/', heartbeatPeriod: 30 }, sockopt: { tcpFastOpen: true } }
    }
  };
  const kept = SF.readPathFields(server);
  // a rebuild that lost the heartbeat and the sockopt, then the fields applied
  server.outbound.streamSettings = { network: 'ws', security: 'tls', wsSettings: { path: '/' } };
  SF.applyPathFields(server, { encryption: X25519_ENC }, kept);
  const st = server.outbound.streamSettings;
  assert.equal(st.wsSettings.heartbeatPeriod, 30, 'kept');
  assert.equal(st.sockopt.tcpFastOpen, true, 'kept');
  assert.equal(server.outbound.settings.vnext[0].users[0].encryption, X25519_ENC, 'changed');
  // the transport changes to gRPC: the ws heartbeat no longer applies and is not written
  const kept2 = SF.readPathFields(server);
  server.outbound.streamSettings = { network: 'grpc', security: 'tls', grpcSettings: { serviceName: 's' } };
  SF.applyPathFields(server, { wsHeartbeat: '30', grpcIdleTimeout: '60' }, kept2);
  assert.equal(server.outbound.streamSettings.wsSettings, undefined);
  assert.equal(server.outbound.streamSettings.grpcSettings.idle_timeout, 60);
  assert.equal(server.outbound.streamSettings.sockopt.tcpFastOpen, true);
  // the same value sent back as text changes nothing (a number stays a number)
  const before = JSON.stringify(server);
  SF.applyPathFields(server, { grpcIdleTimeout: '60', encryption: X25519_ENC, tcpFastOpen: true }, SF.readPathFields(server));
  assert.equal(JSON.stringify(server), before);
});
